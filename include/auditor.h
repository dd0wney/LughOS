#ifndef AUDITOR_H
#define AUDITOR_H

#include "lugh.h"
#include "ring_buffer.h"

#define AUDITOR_MAGIC             0x4C474849UL  /* "LGHI" = LughOS IPC */
#define AUDITOR_TELEMETRY_VERSION 1u

#define AUDITOR_REC_MSG       0u  /* normal IPC message event  */
#define AUDITOR_REC_OVERFLOW  1u  /* ring dropped N messages   */
#define AUDITOR_REC_HEARTBEAT 2u  /* 1-second keepalive        */
#define AUDITOR_REC_DENY      3u  /* capability/domain denied  */

/* Fixed-size telemetry record emitted on COM2.
 * 44 bytes packed. Python struct format: '<IHHQBBBBII16s'
 *
 * Field semantics by record type:
 *   MSG:       priority, src_domain, protocol, channel_id, operation, checksum, payload_hash
 *   OVERFLOW:  all context fields zero; operation = drop count
 *   HEARTBEAT: all fields zero
 *   DENY:      priority=attempted, src_domain, protocol, channel_id,
 *              operation=attempted OP_*, checksum=[reason:8][dst_domain:8][dst_channel:8][rsvd:8],
 *              payload_hash[0..3]=granted_caps, [4..7]=required_caps,
 *              [8..11]=dst_channel_id (0xFFFFFFFF if none), [12..15]=zeros
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

#endif /* AUDITOR_H */
