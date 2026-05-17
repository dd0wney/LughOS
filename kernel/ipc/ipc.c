#include "lugh.h"
#include "nngcompat.h"
#include "security.h"
#include "crypto.h"
#include "watchdog.h"
#include "capabilities.h"

#define MAX_IPC_CHANNELS 16

typedef struct {
    int id;
    bool in_use;
    nng_socket_t socket;
    uint32_t security_level;
    uint32_t domain;
    uint32_t cap_mask;       /* CAP_* bitmask set at create time, immutable */
} ipc_channel_t;

static ipc_channel_t channels[MAX_IPC_CHANNELS];

/* ── Internal: fill deny info and emit via watchdog ─────────────── */

static void emit_deny(int src_id, int dst_id,
                      uint32_t op, uint8_t reason, uint8_t priority) {
    if (!watchdog_enabled)
        return;
    watchdog_deny_info_t d;
    d.src_domain   = (uint8_t)(channels[src_id].domain & 0xFFu);
    d.dst_domain   = (dst_id >= 0 && dst_id < MAX_IPC_CHANNELS)
                         ? (uint8_t)(channels[dst_id].domain & 0xFFu)
                         : 0xFFu;
    d.src_channel  = (uint8_t)((uint32_t)src_id & 0xFFu);
    d.dst_channel  = (dst_id >= 0 && dst_id < MAX_IPC_CHANNELS)
                         ? (uint8_t)((uint32_t)dst_id & 0xFFu)
                         : 0xFFu;
    d.protocol     = (uint8_t)((uint32_t)channels[src_id].socket.protocol & 0xFFu);
    d.reason       = reason;
    d.priority     = priority;
    d._pad         = 0;
    d.operation    = op;
    d.granted_caps = channels[src_id].cap_mask;
    d.required_caps = required_caps_for_op(op);
    watchdog_deny(&d);
}

/* ── Public API ──────────────────────────────────────────────────── */

int init_ipc(void) {
    log_message(LOG_INFO, "Initializing IPC subsystem\n");
    nng_init();
    for (int i = 0; i < MAX_IPC_CHANNELS; i++) {
        channels[i].id             = i;
        channels[i].in_use         = false;
        channels[i].security_level = 0;
        channels[i].domain         = 0;
        channels[i].cap_mask       = 0;
    }
    log_message(LOG_INFO,
        "IPC enforcement: cap_mask gates active, domain isolation active\n");
    return 0;
}

int ipc_create_channel(uint32_t security_level, uint32_t domain,
                       uint32_t cap_mask, int protocol) {
    int channel_id = -1;
    for (int i = 0; i < MAX_IPC_CHANNELS; i++) {
        if (!channels[i].in_use) { channel_id = i; break; }
    }
    if (channel_id < 0) {
        log_message(LOG_ERROR, "Failed to create IPC channel: no free slots\n");
        return -1;
    }
    int rv = nng_socket_create(&channels[channel_id].socket, protocol);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to create NNG socket: %d\n", rv);
        return -2;
    }
    channels[channel_id].in_use         = true;
    channels[channel_id].security_level = security_level;
    channels[channel_id].domain         = domain;
    channels[channel_id].cap_mask       = cap_mask;
    log_message(LOG_INFO,
        "Created IPC channel %d (domain: %u, caps: 0x%X)\n",
        channel_id, domain, cap_mask);
    return channel_id;
}

int ipc_close_channel(int channel_id) {
    if (channel_id < 0 || channel_id >= MAX_IPC_CHANNELS) {
        log_message(LOG_ERROR, "Invalid channel ID: %d\n", channel_id);
        return -1;
    }
    if (!channels[channel_id].in_use) {
        log_message(LOG_WARNING, "Channel %d already closed\n", channel_id);
        return -2;
    }
    int rv = nng_socket_close(&channels[channel_id].socket);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to close NNG socket: %d\n", rv);
        return -3;
    }
    channels[channel_id].in_use = false;
    log_message(LOG_INFO, "Closed IPC channel %d\n", channel_id);
    return 0;
}

/* Connect src channel to dst channel.
 * Enforces: same domain, OR src has CAP_CROSS_DOMAIN. */
int ipc_connect(int src_id, int dst_id) {
    if (src_id < 0 || src_id >= MAX_IPC_CHANNELS || !channels[src_id].in_use) {
        log_message(LOG_ERROR, "ipc_connect: invalid src channel %d\n", src_id);
        return -1;
    }
    if (dst_id < 0 || dst_id >= MAX_IPC_CHANNELS || !channels[dst_id].in_use) {
        log_message(LOG_ERROR, "ipc_connect: invalid dst channel %d\n", dst_id);
        return -1;
    }
    if (channels[src_id].domain != channels[dst_id].domain) {
        if (!(channels[src_id].cap_mask & CAP_CROSS_DOMAIN)) {
            log_message(LOG_ERROR,
                "ipc_connect: domain violation ch%d(dom=%u) -> ch%d(dom=%u)\n",
                src_id, channels[src_id].domain,
                dst_id, channels[dst_id].domain);
            emit_deny(src_id, dst_id, 0, DENY_DOMAIN, 0);
            return NNG_EACCESS;
        }
    }
    int rv = nng_connect(&channels[src_id].socket, &channels[dst_id].socket);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "ipc_connect: nng_connect failed: %d\n", rv);
        return rv;
    }
    log_message(LOG_DEBUG, "Connected ch%d(dom=%u) -> ch%d(dom=%u)\n",
        src_id, channels[src_id].domain, dst_id, channels[dst_id].domain);
    return 0;
}

int ipc_send(int channel_id, message_t *msg) {
    if (msg == NULL) {
        log_message(LOG_ERROR, "NULL message pointer in ipc_send\n");
        return -1;
    }
    if (channel_id < 0 || channel_id >= MAX_IPC_CHANNELS ||
        !channels[channel_id].in_use) {
        log_message(LOG_ERROR, "Invalid channel ID: %d\n", channel_id);
        return -2;
    }

    /* Capability check — before any side effects */
    uint32_t req = required_caps_for_op(msg->operation);
    uint32_t granted = channels[channel_id].cap_mask;
    if ((granted & req) != req) {
        uint8_t reason = (req & CAP_PRIVILEGED_OP) ? DENY_CAP_PRIV : DENY_CAP_SEND;
        log_message(LOG_ERROR,
            "ipc_send: cap denied ch%d op=0x%X granted=0x%X required=0x%X\n",
            channel_id, msg->operation, granted, req);
        emit_deny(channel_id, -1, msg->operation, reason,
                  (uint8_t)msg->priority);
        return -7;
    }

    msg->payload[MAX_MSG_SIZE - 1] = '\0';
    msg->checksum = calculate_checksum(msg->payload, strlen(msg->payload));

    nng_msg_t *nng_msg;
    int rv = lugh_message_to_nng(msg, &nng_msg);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to convert message: %d\n", rv);
        return -3;
    }

    /* Stamp channel context into _padding1 so the watchdog record carries
     * source identity (who/where/how) without resizing message_t. */
    if (watchdog_enabled) {
        msg->_padding1 = ((uint32_t)(channel_id & 0xFF))
                       | ((uint32_t)(channels[channel_id].domain & 0xFF) << 8)
                       | ((uint32_t)(channels[channel_id].socket.protocol & 0xFF) << 16);
        ring_push(&ipc_ring, msg);
    }

    rv = nng_send(&channels[channel_id].socket, nng_msg, 0);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to send message: %d\n", rv);
        return -4;
    }
    log_message(LOG_DEBUG, "Sent message on channel %d\n", channel_id);
    return 0;
}

int ipc_recv(int channel_id, message_t *msg, bool nonblock) {
    if (msg == NULL) {
        log_message(LOG_ERROR, "NULL message pointer in ipc_recv\n");
        return -1;
    }
    if (channel_id < 0 || channel_id >= MAX_IPC_CHANNELS ||
        !channels[channel_id].in_use) {
        log_message(LOG_ERROR, "Invalid channel ID: %d\n", channel_id);
        return -2;
    }

    /* Capability check */
    if (!(channels[channel_id].cap_mask & CAP_IPC_RECV)) {
        log_message(LOG_ERROR,
            "ipc_recv: cap denied ch%d (no CAP_IPC_RECV)\n", channel_id);
        emit_deny(channel_id, -1, 0, DENY_CAP_RECV, 0);
        return -7;
    }

    nng_msg_t *nng_msg;
    int rv = nng_recv(&channels[channel_id].socket, &nng_msg, nonblock ? 1 : 0);
    if (rv != NNG_OK) {
        if (rv == NNG_ETIMEDOUT && nonblock)
            return -3;
        log_message(LOG_ERROR, "Failed to receive message: %d\n", rv);
        return -4;
    }

    rv = nng_message_to_lugh(nng_msg, msg);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to convert message: %d\n", rv);
        nng_msg_free(nng_msg);
        return -5;
    }
    nng_msg_free(nng_msg);

    uint32_t verify_sum = calculate_checksum(msg->payload, strlen(msg->payload));
    if (verify_sum != msg->checksum) {
        log_message(LOG_ERROR, "Message checksum failed in ipc_recv\n");
        return -6;
    }
    log_message(LOG_DEBUG, "Received message on channel %d\n", channel_id);
    return 0;
}
