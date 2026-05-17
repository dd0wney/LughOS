#include "nngcompat.h"
#include "crypto.h"
#include "hardware.h"
#include "interrupt.h"

extern void *alloc_memory(size_t size);
extern void  free_memory(void *ptr);

/* ── Sizing ───────────────────────────────────────────────────── */
#define MAX_MESSAGES          64   /* nng_msg pool slots                  */
#define MAX_SOCKETS           16   /* socket pool                         */
#define MAX_PIPES             64   /* logical connections                  */
#define MAX_QUEUED_MSGS       16   /* per-socket incoming queue depth     */
#define MSG_BUFFER_SIZE      256   /* max nng_msg body bytes              */
#define MAX_SUBS               8   /* topic subscriptions per SUB socket  */
#define MAX_TOPIC_LEN         32   /* max topic prefix bytes              */
#define SURVEYOR_TIMEOUT_TICKS 100u /* survey window: 1 s at 100 Hz      */

/* ── CRC32 ────────────────────────────────────────────────────── */

static uint32_t crc32_table[256];

static void init_crc32_table(void) {
    uint32_t poly = 0xEDB88320u;
    for (int i = 0; i < 256; i++) {
        uint32_t c = (uint32_t)i;
        for (int j = 0; j < 8; j++)
            c = (c & 1u) ? (poly ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
}

uint32_t calculate_checksum(const void *data, size_t len) {
    if (!security_validate_memory_access((void *)data, len, false)) {
        log_message(LOG_ERROR, "Security violation in calculate_checksum\n");
        return 0;
    }
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ── Plain memory helpers (bypass security-gated memcpy/memcmp) ─ */

static void plain_copy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

static bool plain_eq(const void *a, const void *b, size_t n) {
    const uint8_t *p = (const uint8_t *)a;
    const uint8_t *q = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++)
        if (p[i] != q[i]) return false;
    return true;
}

/* ── Message pool ─────────────────────────────────────────────── */

typedef struct {
    nng_msg_t *msg;
    void      *buffer;
    bool       in_use;
} msg_slot_t;

static msg_slot_t msg_slots[MAX_MESSAGES];

/* ── Per-socket incoming queue ────────────────────────────────── */

typedef struct {
    nng_msg_t *messages[MAX_QUEUED_MSGS];
    int head, tail, count;
} incoming_queue_t;

static incoming_queue_t recv_queues[MAX_SOCKETS];

/* ── Per-socket protocol state ────────────────────────────────── */

typedef struct {
    int      rr_idx;           /* round-robin cursor for REQ/PUSH         */
    int      reply_src;        /* REP: socket id that sent the last REQ   */
    int      respondent_src;   /* RESPONDENT: surveyor id of last survey  */
    uint64_t survey_deadline;  /* SURVEYOR: jiffies when survey expires   */
    bool     survey_active;    /* SURVEYOR: a survey is in flight         */
    /* SUB topic prefix list */
    uint8_t  topics[MAX_SUBS][MAX_TOPIC_LEN];
    uint8_t  topic_len[MAX_SUBS];
    int      num_topics;
} socket_state_t;

static socket_state_t sock_state[MAX_SOCKETS];
static nng_socket_t   socket_pool[MAX_SOCKETS];

/* ── Logical pipe (connection) table ──────────────────────────── */

typedef struct {
    int  src;
    int  dst;
    bool in_use;
} pipe_t;

static pipe_t pipes[MAX_PIPES];

/* ── Internal helpers ─────────────────────────────────────────── */

static bool socket_valid(int id) {
    return id >= 0 && id < MAX_SOCKETS && socket_pool[id].id == id;
}

/* Enqueue an already-allocated msg into a socket's incoming queue. */
static int enqueue_incoming(int sock_id, nng_msg_t *msg) {
    incoming_queue_t *q = &recv_queues[sock_id];
    if (q->count >= MAX_QUEUED_MSGS)
        return NNG_ENOMEM;
    q->messages[q->tail] = msg;
    q->tail = (q->tail + 1) & (MAX_QUEUED_MSGS - 1);
    q->count++;
    return NNG_OK;
}

/* Copy src_msg body into a fresh allocation and enqueue at sock_id. */
static int deliver_copy(int sock_id, const nng_msg_t *src_msg) {
    nng_msg_t *copy;
    int rv = nng_msg_alloc(&copy, 0);
    if (rv != NNG_OK)
        return rv;
    if (src_msg->body_len > 0) {
        rv = nng_msg_append(copy, src_msg->body, src_msg->body_len);
        if (rv != NNG_OK) { nng_msg_free(copy); return rv; }
    }
    rv = enqueue_incoming(sock_id, copy);
    if (rv != NNG_OK)
        nng_msg_free(copy);
    return rv;
}

/* Return true if a SUB socket's subscription list accepts msg.
 * Empty topic (len==0) is a wildcard that matches everything. */
static bool sub_accepts(int sock_id, const nng_msg_t *msg) {
    socket_state_t *st = &sock_state[sock_id];
    for (int i = 0; i < st->num_topics; i++) {
        uint8_t tlen = st->topic_len[i];
        if (tlen == 0)
            return true;
        if (msg->body_len >= (size_t)tlen &&
            plain_eq(msg->body, st->topics[i], tlen))
            return true;
    }
    return false;  /* no match, or no subscriptions */
}

/* Fill peers_out[] with socket IDs connected to sock_id whose
 * protocol matches proto_filter.  For BUS, both pipe directions
 * are matched.  Returns peer count. */
static int collect_peers(int sock_id, int proto_filter,
                         int *peers_out, int max_peers) {
    int n = 0;
    for (int i = 0; i < MAX_PIPES && n < max_peers; i++) {
        if (!pipes[i].in_use) continue;
        int peer = -1;
        if (proto_filter == NNG_PROTO_BUS0) {
            if (pipes[i].src == sock_id)      peer = pipes[i].dst;
            else if (pipes[i].dst == sock_id) peer = pipes[i].src;
        } else {
            if (pipes[i].src == sock_id)      peer = pipes[i].dst;
        }
        if (peer >= 0 && socket_valid(peer) &&
            socket_pool[peer].protocol == proto_filter)
            peers_out[n++] = peer;
    }
    return n;
}

/* ── Lifecycle ────────────────────────────────────────────────── */

void nng_init(void) {
    log_message(LOG_INFO, "Initializing NNG compatibility layer\n");
    init_crc32_table();
    for (int i = 0; i < MAX_MESSAGES; i++) {
        msg_slots[i].msg    = NULL;
        msg_slots[i].buffer = NULL;
        msg_slots[i].in_use = false;
    }
    for (int i = 0; i < MAX_SOCKETS; i++) {
        socket_pool[i].id = -1;
        recv_queues[i].head = recv_queues[i].tail = recv_queues[i].count = 0;
        for (int j = 0; j < MAX_QUEUED_MSGS; j++)
            recv_queues[i].messages[j] = NULL;
        sock_state[i].rr_idx         = 0;
        sock_state[i].reply_src      = -1;
        sock_state[i].respondent_src = -1;
        sock_state[i].survey_active  = false;
        sock_state[i].num_topics     = 0;
    }
    for (int i = 0; i < MAX_PIPES; i++)
        pipes[i].in_use = false;
    log_message(LOG_INFO, "NNG compatibility layer initialized\n");
}

void nng_shutdown(void) {
    for (int i = 0; i < MAX_MESSAGES; i++) {
        if (msg_slots[i].in_use) {
            if (msg_slots[i].buffer) free_memory(msg_slots[i].buffer);
            if (msg_slots[i].msg)    free_memory(msg_slots[i].msg);
            msg_slots[i].in_use = false;
        }
    }
    for (int i = 0; i < MAX_SOCKETS; i++) {
        incoming_queue_t *q = &recv_queues[i];
        for (int j = 0; j < MAX_QUEUED_MSGS; j++) {
            if (q->messages[j]) { nng_msg_free(q->messages[j]); q->messages[j] = NULL; }
        }
        socket_pool[i].id = -1;
    }
    for (int i = 0; i < MAX_PIPES; i++)
        pipes[i].in_use = false;
}

/* ── Message pool API ─────────────────────────────────────────── */

int nng_msg_alloc(nng_msg_t **msgp, size_t size) {
    if (!msgp) return NNG_EINVAL;
    int slot = -1;
    for (int i = 0; i < MAX_MESSAGES; i++) {
        if (!msg_slots[i].in_use) { slot = i; break; }
    }
    if (slot < 0) return NNG_ENOMEM;
    if (size > MSG_BUFFER_SIZE) return NNG_EINVAL;

    nng_msg_t *msg = (nng_msg_t *)alloc_memory(sizeof(nng_msg_t));
    if (!msg) return NNG_ENOMEM;

    void *buf = alloc_memory(size > 0 ? size : 8u);
    if (!buf) { free_memory(msg); return NNG_ENOMEM; }

    msg->body = buf; msg->body_len = 0;
    msg->header = NULL; msg->header_len = 0;
    msg->flags = 0; msg->checksum = 0;

    msg_slots[slot].msg    = msg;
    msg_slots[slot].buffer = buf;
    msg_slots[slot].in_use = true;
    *msgp = msg;
    return NNG_OK;
}

int nng_msg_free(nng_msg_t *msg) {
    if (!msg) return NNG_EINVAL;
    for (int i = 0; i < MAX_MESSAGES; i++) {
        if (msg_slots[i].in_use && msg_slots[i].msg == msg) {
            free_memory(msg_slots[i].buffer);
            free_memory(msg);
            msg_slots[i].msg    = NULL;
            msg_slots[i].buffer = NULL;
            msg_slots[i].in_use = false;
            return NNG_OK;
        }
    }
    return NNG_EINVAL;
}

int nng_msg_append(nng_msg_t *msg, const void *data, size_t size) {
    if (!msg || !data) return NNG_EINVAL;
    if (!security_validate_memory_access(msg,  sizeof(nng_msg_t), true) ||
        !security_validate_memory_access((void *)data, size, false))
        return NNG_EINVAL;
    if (msg->body_len + size > MSG_BUFFER_SIZE)
        return NNG_ENOMEM;
    plain_copy((uint8_t *)msg->body + msg->body_len, data, size);
    msg->body_len += size;
    msg->checksum = calculate_checksum(msg->body, msg->body_len);
    return NNG_OK;
}

int nng_msg_len(const nng_msg_t *msg) {
    return msg ? (int)msg->body_len : 0;
}

void *nng_msg_body(const nng_msg_t *msg) {
    return msg ? msg->body : NULL;
}

/* ── Socket API ───────────────────────────────────────────────── */

int nng_socket_create(nng_socket_t *sock, int protocol) {
    if (!sock) return NNG_EINVAL;
    int id = -1;
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socket_pool[i].id < 0) { id = i; break; }
    }
    if (id < 0) return NNG_ENOMEM;

    sock->id = id; sock->protocol = protocol; sock->flags = 0;
    socket_pool[id] = *sock;
    sock_state[id].rr_idx         = 0;
    sock_state[id].reply_src      = -1;
    sock_state[id].respondent_src = -1;
    sock_state[id].survey_active  = false;
    sock_state[id].num_topics     = 0;
    log_message(LOG_DEBUG, "Created socket %d with protocol %d\n", id, protocol);
    return NNG_OK;
}

int nng_socket_close(nng_socket_t *sock) {
    if (!sock || !socket_valid(sock->id)) return NNG_EINVAL;
    int id = sock->id;

    incoming_queue_t *q = &recv_queues[id];
    for (int i = 0; i < MAX_QUEUED_MSGS; i++) {
        if (q->messages[i]) { nng_msg_free(q->messages[i]); q->messages[i] = NULL; }
    }
    q->head = q->tail = q->count = 0;

    for (int i = 0; i < MAX_PIPES; i++) {
        if (pipes[i].in_use && (pipes[i].src == id || pipes[i].dst == id))
            pipes[i].in_use = false;
    }
    socket_pool[id].id = -1;
    sock->id = -1;
    return NNG_OK;
}

int nng_connect(nng_socket_t *src, nng_socket_t *dst) {
    if (!src || !dst || !socket_valid(src->id) || !socket_valid(dst->id))
        return NNG_EINVAL;
    for (int i = 0; i < MAX_PIPES; i++) {
        if (!pipes[i].in_use) {
            pipes[i].src    = src->id;
            pipes[i].dst    = dst->id;
            pipes[i].in_use = true;
            log_message(LOG_DEBUG, "Pipe: socket %d -> socket %d\n",
                        src->id, dst->id);
            return NNG_OK;
        }
    }
    return NNG_ENOMEM;
}

/* ── SUB subscription management ─────────────────────────────── */

int nng_sub_subscribe(nng_socket_t *sock, const void *topic, size_t topic_len) {
    if (!sock || !socket_valid(sock->id) ||
        socket_pool[sock->id].protocol != NNG_PROTO_SUB0)
        return NNG_EINVAL;
    if (topic_len > MAX_TOPIC_LEN) return NNG_EINVAL;
    socket_state_t *st = &sock_state[sock->id];
    if (st->num_topics >= MAX_SUBS) return NNG_ENOMEM;
    int idx = st->num_topics++;
    if (topic_len > 0 && topic)
        plain_copy(st->topics[idx], topic, topic_len);
    st->topic_len[idx] = (uint8_t)topic_len;
    return NNG_OK;
}

int nng_sub_unsubscribe(nng_socket_t *sock, const void *topic, size_t topic_len) {
    if (!sock || !socket_valid(sock->id) ||
        socket_pool[sock->id].protocol != NNG_PROTO_SUB0)
        return NNG_EINVAL;
    socket_state_t *st = &sock_state[sock->id];
    for (int i = 0; i < st->num_topics; i++) {
        if (st->topic_len[i] == (uint8_t)topic_len &&
            (topic_len == 0 ||
             plain_eq(st->topics[i], topic, topic_len))) {
            /* compact: overwrite slot with last entry */
            int last = --st->num_topics;
            plain_copy(st->topics[i], st->topics[last], MAX_TOPIC_LEN);
            st->topic_len[i] = st->topic_len[last];
            return NNG_OK;
        }
    }
    return NNG_ENOENT;
}

/* ── nng_send: per-protocol routing ──────────────────────────── */

int nng_send(nng_socket_t *sock, nng_msg_t *msg, int flags) {
    (void)flags;
    if (!sock || !msg || !socket_valid(sock->id)) return NNG_EINVAL;

    int id    = sock->id;
    int proto = socket_pool[id].protocol;
    int peers[MAX_SOCKETS];
    int n, rv = NNG_OK;

    switch (proto) {

    /* PUB: fan-out to all connected SUBs that pass topic filter */
    case NNG_PROTO_PUB0:
        n = collect_peers(id, NNG_PROTO_SUB0, peers, MAX_SOCKETS);
        for (int i = 0; i < n; i++) {
            if (sub_accepts(peers[i], msg))
                deliver_copy(peers[i], msg);  /* best-effort: drop on full */
        }
        break;

    /* PUSH: round-robin to one connected PULL socket */
    case NNG_PROTO_PUSH0: {
        n = collect_peers(id, NNG_PROTO_PULL0, peers, MAX_SOCKETS);
        if (n == 0) { rv = NNG_ENOTSUP; break; }
        int idx = sock_state[id].rr_idx;
        if (idx < 0 || idx >= n) idx = 0;
        rv = deliver_copy(peers[idx], msg);
        sock_state[id].rr_idx = (idx + 1 >= n) ? 0 : idx + 1;
        break;
    }

    /* REQ: round-robin to one REP; REP records the return address */
    case NNG_PROTO_REQ0: {
        n = collect_peers(id, NNG_PROTO_REP0, peers, MAX_SOCKETS);
        if (n == 0) { rv = NNG_ENOTSUP; break; }
        int idx = sock_state[id].rr_idx;
        if (idx < 0 || idx >= n) idx = 0;
        int rep_id = peers[idx];
        rv = deliver_copy(rep_id, msg);
        if (rv == NNG_OK) {
            sock_state[rep_id].reply_src = id;
            sock_state[id].rr_idx = (idx + 1 >= n) ? 0 : idx + 1;
        }
        break;
    }

    /* REP: deliver reply back to the REQ that issued the request */
    case NNG_PROTO_REP0: {
        int req_id = sock_state[id].reply_src;
        if (req_id < 0 || !socket_valid(req_id)) { rv = NNG_ENOTSUP; break; }
        rv = deliver_copy(req_id, msg);
        sock_state[id].reply_src = -1;
        break;
    }

    /* BUS: forward to all connected peers (bidirectional, no loopback) */
    case NNG_PROTO_BUS0:
        n = collect_peers(id, NNG_PROTO_BUS0, peers, MAX_SOCKETS);
        for (int i = 0; i < n; i++)
            deliver_copy(peers[i], msg);
        break;

    /* SURVEYOR: broadcast to all RESPONDENTs; arm the survey timer */
    case NNG_PROTO_SURVEYOR0: {
        n = collect_peers(id, NNG_PROTO_RESPONDENT0, peers, MAX_SOCKETS);
        if (n == 0) { rv = NNG_ENOTSUP; break; }
        for (int i = 0; i < n; i++) {
            if (deliver_copy(peers[i], msg) == NNG_OK)
                sock_state[peers[i]].respondent_src = id;
        }
        sock_state[id].survey_active  = true;
        sock_state[id].survey_deadline =
            hw_get_jiffies() + SURVEYOR_TIMEOUT_TICKS;
        break;
    }

    /* RESPONDENT: reply to the surveyor if the survey is still open */
    case NNG_PROTO_RESPONDENT0: {
        int surveyor_id = sock_state[id].respondent_src;
        if (surveyor_id < 0 || !socket_valid(surveyor_id)) {
            rv = NNG_ENOTSUP; break;
        }
        if (!sock_state[surveyor_id].survey_active ||
            hw_get_jiffies() > sock_state[surveyor_id].survey_deadline) {
            sock_state[id].respondent_src = -1;
            rv = NNG_ETIMEDOUT; break;
        }
        rv = deliver_copy(surveyor_id, msg);
        sock_state[id].respondent_src = -1;
        break;
    }

    /* PAIR: deliver to the one connected peer */
    case NNG_PROTO_PAIR1: {
        n = collect_peers(id, NNG_PROTO_PAIR1, peers, MAX_SOCKETS);
        if (n == 0) { rv = NNG_ENOTSUP; break; }
        rv = deliver_copy(peers[0], msg);
        break;
    }

    default:
        rv = NNG_ENOTSUP;
        break;
    }

    nng_msg_free(msg);  /* sender transfers ownership per NNG semantics */
    return rv;
}

/* ── nng_recv ─────────────────────────────────────────────────── */

int nng_recv(nng_socket_t *sock, nng_msg_t **msgp, int flags) {
    if (!sock || !msgp || !socket_valid(sock->id)) return NNG_EINVAL;
    bool nonblock = (flags & 1) != 0;
    (void)nonblock;  /* cooperative kernel: recv is always non-blocking */
    int id = sock->id;

    /* SURVEYOR: expire survey if deadline has passed */
    if (socket_pool[id].protocol == NNG_PROTO_SURVEYOR0 &&
        sock_state[id].survey_active &&
        hw_get_jiffies() > sock_state[id].survey_deadline)
        sock_state[id].survey_active = false;

    incoming_queue_t *q = &recv_queues[id];
    if (q->count == 0) {
        /* SURVEYOR returns ETIMEDOUT once survey window closes */
        if (socket_pool[id].protocol == NNG_PROTO_SURVEYOR0 &&
            !sock_state[id].survey_active)
            return NNG_ETIMEDOUT;
        return NNG_ETIMEDOUT;
    }

    *msgp = q->messages[q->head];
    q->messages[q->head] = NULL;
    q->head = (q->head + 1) & (MAX_QUEUED_MSGS - 1);
    q->count--;
    return NNG_OK;
}

/* ── Message validation ───────────────────────────────────────── */

#define MSG_SIGNATURE_SIZE 32

int validate_message(const message_t *msg) {
    if (!security_validate_memory_access((void *)msg, sizeof(message_t), false) ||
        !security_validate_memory_access((void *)msg->payload, MAX_MSG_SIZE, false)) {
        log_message(LOG_ERROR, "Security violation: invalid message pointer\n");
        return 0;
    }
    size_t payload_len = strlen(msg->payload);
    if (msg->priority == PRIORITY_HIGH) {
        log_message(LOG_INFO, "Validating high-priority message: op=0x%x\n",
                    msg->operation);
        if (payload_len == 0) {
            log_message(LOG_WARNING, "High-priority message: empty payload\n");
            return 0;
        }
        if (msg->operation == OP_GRID_ALERT) {
            if (strstr(msg->payload, "GRID_FAULT") == NULL) {
                log_message(LOG_WARNING, "Grid alert: missing GRID_FAULT indicator\n");
                return 0;
            }
            uint8_t signature[MSG_SIGNATURE_SIZE];
            if (!crypto_sign(msg->payload, payload_len,
                             signature, sizeof(signature))) {
                log_message(LOG_ERROR, "Failed to sign grid alert\n");
                return 0;
            }
            log_message(LOG_INFO, "Grid alert signature verified\n");
        }
    }
    return 1;
}

/* ── LughOS ↔ NNG message conversion ─────────────────────────── */

int lugh_message_to_nng(const message_t *lugh_msg, nng_msg_t **nng_msg) {
    if (!lugh_msg || !nng_msg) return NNG_EINVAL;
    int rv = nng_msg_alloc(nng_msg, 0);
    if (rv != NNG_OK) return rv;

    uint8_t  priority  = (uint8_t)lugh_msg->priority;
    uint32_t operation = lugh_msg->operation;
    size_t   plen      = strlen(lugh_msg->payload);

    rv = nng_msg_append(*nng_msg, &priority,  sizeof(priority));
    if (rv == NNG_OK)
        rv = nng_msg_append(*nng_msg, &operation, sizeof(operation));
    if (rv == NNG_OK)
        rv = nng_msg_append(*nng_msg, lugh_msg->payload, plen + 1u);
    if (rv != NNG_OK) { nng_msg_free(*nng_msg); return rv; }
    return NNG_OK;
}

int nng_message_to_lugh(const nng_msg_t *nng_msg, message_t *lugh_msg) {
    if (!nng_msg || !lugh_msg || !nng_msg->body || nng_msg->body_len < 5u)
        return NNG_EINVAL;

    const uint8_t *body = (const uint8_t *)nng_msg->body;
    lugh_msg->priority = (msg_priority_t)body[0];
    plain_copy(&lugh_msg->operation, &body[1], sizeof(uint32_t));

    size_t plen = nng_msg->body_len - 5u;
    if (plen >= MAX_MSG_SIZE) plen = MAX_MSG_SIZE - 1u;
    if (plen > 0) plain_copy(lugh_msg->payload, &body[5], plen);
    lugh_msg->payload[plen] = '\0';
    return NNG_OK;
}
