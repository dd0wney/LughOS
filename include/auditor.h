#ifndef AUDITOR_H
#define AUDITOR_H

#include "lugh.h"
#include "ring_buffer.h"

#define AUDITOR_MAGIC             0x4C474849UL  /* "LGHI" = LughOS IPC */
/* Version bumps:
 *   v1 → MSG / OVERFLOW / HEARTBEAT / DENY only.
 *   v2 → adds structural events (CHAN_CREATE) so the encoder can
 *        reconstruct graph state from the event stream alone.
 *        Wire format unchanged (still 44 bytes packed) — only the
 *        record_type tag grows. Decoder must learn the new tags.
 */
#define AUDITOR_TELEMETRY_VERSION 2u

#define AUDITOR_REC_MSG          0u  /* normal IPC message event  */
#define AUDITOR_REC_OVERFLOW     1u  /* ring dropped N messages   */
#define AUDITOR_REC_HEARTBEAT    2u  /* 1-second keepalive        */
#define AUDITOR_REC_DENY         3u  /* capability/domain denied  */
#define AUDITOR_REC_CHAN_CREATE  5u  /* IPC channel created       */
#define AUDITOR_REC_CHAN_CONNECT 6u  /* IPC channel connected     */
#define AUDITOR_REC_DOMAIN_EDGE  8u  /* domain matrix mutation    */

/* Fixed-size telemetry record emitted on COM2.
 * 44 bytes packed. Python struct format: '<IHHQBBBBII16s'
 *
 * Field semantics by record type:
 *   MSG:         priority, src_domain, protocol, channel_id, operation, checksum, payload_hash
 *   OVERFLOW:    all context fields zero; operation = drop count
 *   HEARTBEAT:   all fields zero
 *   DENY:        priority=attempted, src_domain, protocol, channel_id,
 *                operation=attempted OP_*, checksum=[reason:8][dst_domain:8][dst_channel:8][rsvd:8],
 *                payload_hash[0..3]=granted_caps, [4..7]=required_caps,
 *                [8..11]=dst_channel_id (0xFFFFFFFF if none), [12..15]=zeros
 *   CHAN_CREATE: priority=0, src_domain=channel.domain (low 8),
 *                protocol=channel.protocol, channel_id=channel.id,
 *                operation=channel.cap_mask, checksum=channel.owner_task_id,
 *                payload_hash[0..3]=full channel.domain (uint32),
 *                payload_hash[4..7]=channel.security_level,
 *                payload_hash[8..15]=zeros.
 *                Re-uses existing 44-byte layout (no struct growth) — the
 *                python decoder unpacks owner_task_id from checksum and
 *                full-width domain from payload_hash[0..3].
 *   CHAN_CONNECT: priority=0, src_domain=src_channel.domain (low 8),
 *                protocol=src_channel.protocol, channel_id=src_channel.id,
 *                operation=dst_channel.id (full uint32 — survives table growth),
 *                checksum=dst_channel.domain (full uint32),
 *                payload_hash[0..3]=src_channel.cap_mask,
 *                payload_hash[4..7]=dst_channel.cap_mask,
 *                payload_hash[8..15]=zeros.
 *                Emitted on the success branch of ipc_connect only —
 *                denials use the existing DENY record. Together
 *                CREATE+CONNECT let the encoder reconstruct the channel
 *                graph (nodes + edges) from telemetry alone.
 *   DOMAIN_EDGE: priority=0, src_domain=src (low 8), protocol=0,
 *                channel_id=dst (low 8),
 *                operation=src (full uint32), checksum=dst (full uint32),
 *                payload_hash[0..3]=added (1 = edge added; reserved for
 *                future "removed" events), payload_hash[4..15]=zeros.
 *                Emitted by every successful domain_edge_set so the
 *                JEPA encoder sees policy mutations as first-class
 *                events.
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;           /* AUDITOR_MAGIC                        */
    uint16_t version;         /* AUDITOR_TELEMETRY_VERSION            */
    uint16_t record_type;     /* AUDITOR_REC_*                        */
    uint64_t jiffies;         /* hw_get_jiffies() at emit time        */
    uint8_t  priority;        /* msg.priority (MSG/DENY) or 0         */
    uint8_t  src_domain;      /* channels[ch].domain, low 8 bits      */
    uint8_t  protocol;        /* channels[ch].socket.protocol         */
    uint8_t  channel_id;      /* source channel index                 */
    uint32_t operation;       /* msg.operation or drop count          */
    uint32_t checksum;        /* msg.checksum (MSG) or deny context   */
    uint8_t  payload_hash[16];/* 4×FNV-1a-32 (MSG) or cap diag (DENY)*/
} auditor_record_t;           /* sizeof = 44 bytes, fixed              */

/* Context passed to auditor_deny() — assembled by ipc.c from channel table. */
typedef struct {
    uint8_t  src_domain;
    uint8_t  dst_domain;      /* 0xFF if no destination channel */
    uint8_t  src_channel;
    uint8_t  dst_channel;     /* 0xFF if no destination channel */
    uint8_t  protocol;
    uint8_t  reason;          /* DENY_CAP_SEND/RECV/PRIV/DOMAIN */
    uint8_t  priority;
    uint8_t  _pad;
    uint32_t operation;
    uint32_t granted_caps;
    uint32_t required_caps;
} auditor_deny_info_t;

/* Exported globals — defined in services/auditor/exporter.c */
extern ipc_ring_t        ipc_ring;
extern volatile uint8_t  auditor_enabled;

void auditor_init(void);
void auditor_tick(void);
void auditor_deny(const auditor_deny_info_t *info);

/* Structural events — emitted synchronously (no ring) because they are
 * rare and the encoder needs them to reconstruct the channel/task graph
 * at any timestamp. See auditor.c for field-reuse packing.
 *
 * channel_id     — index in the kernel channel table (0..MAX_IPC_CHANNELS-1)
 * owner_task_id  — current_task->task_id at create time (root of trust)
 * cap_mask       — channel's immutable CAP_* mask
 * domain         — full 32-bit security domain id
 * security_level — channel security level
 * protocol       — NNG protocol id (NNG_PROTO_*)
 */
void auditor_chan_create(uint32_t channel_id,
                         uint32_t owner_task_id,
                         uint32_t cap_mask,
                         uint32_t domain,
                         uint32_t security_level,
                         uint32_t protocol);

/* src/dst channel ids must reference existing channels; caller already
 * passed the connect's policy check by the time this fires. */
void auditor_chan_connect(uint32_t src_channel_id,
                          uint32_t src_domain,
                          uint32_t src_cap_mask,
                          uint32_t src_protocol,
                          uint32_t dst_channel_id,
                          uint32_t dst_domain,
                          uint32_t dst_cap_mask);

/* added=1 → edge inserted (current API). Reserved for a future
 * "removed" mutation if/when the policy gains a remove path. */
void auditor_domain_edge(uint32_t src_domain,
                         uint32_t dst_domain,
                         uint32_t added);

#endif /* AUDITOR_H */
