#ifndef CAPABILITIES_H
#define CAPABILITIES_H

#include <stdint.h>

/* Per-channel capability bitmask (Capsicum-inspired).
 * Set at ipc_create_channel() time; immutable thereafter.
 * ipc_send / ipc_recv / ipc_connect check these before acting. */

#define CAP_IPC_SEND       (1u << 0)  /* may call ipc_send on this channel   */
#define CAP_IPC_RECV       (1u << 1)  /* may call ipc_recv on this channel   */
#define CAP_CROSS_DOMAIN   (1u << 2)  /* may ipc_connect to a different domain */
#define CAP_PRIVILEGED_OP  (1u << 3)  /* may send OP_UPDATE / OP_WRITE / OP_DELETE */
#define CAP_ALL             0x0Fu     /* convenience: every capability         */

/* Denial reason codes embedded in watchdog_deny_info_t.reason.
 * Values are stable — the JEPA encoder treats them as class labels. */
#define DENY_CAP_SEND      1u  /* ipc_send: CAP_IPC_SEND missing          */
#define DENY_CAP_RECV      2u  /* ipc_recv: CAP_IPC_RECV missing          */
#define DENY_CAP_PRIV      3u  /* ipc_send: CAP_PRIVILEGED_OP missing     */
#define DENY_DOMAIN        4u  /* ipc_connect: cross-domain, no CAP_CROSS_DOMAIN */

/* Return which CAP_* bits are required to send a given operation code.
 * Privileged ops (UPDATE / WRITE / DELETE) require CAP_PRIVILEGED_OP
 * in addition to the baseline CAP_IPC_SEND. */
static inline uint32_t required_caps_for_op(uint32_t op) {
    switch (op) {
        case 0x102u: /* OP_UPDATE */
        case 0x200u: /* OP_WRITE  */
        case 0x201u: /* OP_DELETE */
            return CAP_IPC_SEND | CAP_PRIVILEGED_OP;
        default:
            return CAP_IPC_SEND;
    }
}

#endif /* CAPABILITIES_H */
