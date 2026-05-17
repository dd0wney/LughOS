#ifndef NNGCOMPAT_H
#define NNGCOMPAT_H

#include "lugh.h"
#include "security.h"

/* NNG-compatible messaging for LughOS bare-metal.
 * Implements all six ZeroMQ/NNG patterns over in-kernel logical pipes:
 *   PAIR, PUB/SUB, REQ/REP, PUSH/PULL, SURVEYOR/RESPONDENT, BUS
 *
 * Transport: logical connections between socket IDs (no network).
 * Use nng_connect(src, dst) instead of nng_dial/nng_listen.
 */

/* ── Message and socket types ─────────────────────────────────── */

typedef struct nng_msg {
    void    *body;
    size_t   body_len;
    void    *header;
    size_t   header_len;
    uint32_t flags;
    uint32_t checksum;
} nng_msg_t;

typedef struct nng_socket {
    int id;
    int protocol;
    uint32_t flags;
} nng_socket_t;

/* ── Error codes ──────────────────────────────────────────────── */
#define NNG_OK        0
#define NNG_ENOMEM    1
#define NNG_EINVAL    2
#define NNG_ECLOSED   3
#define NNG_ETIMEDOUT 4
#define NNG_ENOTSUP   5
#define NNG_ENOENT    6

/* ── Protocol types ───────────────────────────────────────────── */
#define NNG_PROTO_PAIR1       1   /* exclusive 1:1 bidirectional       */
#define NNG_PROTO_PUB0        2   /* publisher: fan-out to all SUBs    */
#define NNG_PROTO_SUB0        3   /* subscriber: topic-prefix filter   */
#define NNG_PROTO_REQ0        4   /* requester: round-robin to REPs    */
#define NNG_PROTO_REP0        5   /* replier: responds to one REQ      */
#define NNG_PROTO_PUSH0       6   /* pipeline source: round-robin push */
#define NNG_PROTO_PULL0       7   /* pipeline sink: receives work      */
#define NNG_PROTO_BUS0        8   /* mesh: all peers, no loopback      */
#define NNG_PROTO_SURVEYOR0   9   /* broadcast survey with timeout     */
#define NNG_PROTO_RESPONDENT0 10  /* responds to surveyor (optional)   */

/* ── Core lifecycle ───────────────────────────────────────────── */
void nng_init(void);
void nng_shutdown(void);

/* ── Socket API ───────────────────────────────────────────────── */
int nng_socket_create(nng_socket_t *sock, int protocol);
int nng_socket_close(nng_socket_t *sock);

/* Create a logical pipe from src to dst.
 * For BUS sockets, routing is bidirectional over a single pipe entry.
 * For all other protocols the pipe is directed: src sends, dst receives. */
int nng_connect(nng_socket_t *src, nng_socket_t *dst);

/* ── Message API ──────────────────────────────────────────────── */
int   nng_msg_alloc(nng_msg_t **msgp, size_t size);
int   nng_msg_free(nng_msg_t *msg);
int   nng_msg_append(nng_msg_t *msg, const void *data, size_t size);
int   nng_msg_len(const nng_msg_t *msg);
void *nng_msg_body(const nng_msg_t *msg);

/* ── Send / receive ───────────────────────────────────────────── */
int nng_send(nng_socket_t *sock, nng_msg_t *msg, int flags);
int nng_recv(nng_socket_t *sock, nng_msg_t **msgp, int flags);

/* ── SUB subscription management ─────────────────────────────── */
/* topic / topic_len: prefix bytes; topic_len == 0 subscribes to all. */
int nng_sub_subscribe(nng_socket_t *sock, const void *topic, size_t topic_len);
int nng_sub_unsubscribe(nng_socket_t *sock, const void *topic, size_t topic_len);

/* ── LughOS message conversion ────────────────────────────────── */
int lugh_message_to_nng(const message_t *lugh_msg, nng_msg_t **nng_msg);
int nng_message_to_lugh(const nng_msg_t *nng_msg, message_t *lugh_msg);

/* ── Validation ───────────────────────────────────────────────── */
int validate_message(const message_t *msg);
/* calculate_checksum is declared in lugh.h */

#endif /* NNGCOMPAT_H */
