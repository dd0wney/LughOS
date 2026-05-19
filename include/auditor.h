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
#define AUDITOR_REC_TASK_CREATE  4u  /* task spawned via create_task */
#define AUDITOR_REC_CHAN_CREATE  5u  /* IPC channel created       */
#define AUDITOR_REC_CHAN_CONNECT 6u  /* IPC channel connected     */
#define AUDITOR_REC_TASK_EXIT    7u  /* task terminated via SYS_EXIT */
#define AUDITOR_REC_DOMAIN_EDGE  8u  /* domain matrix mutation    */
#define AUDITOR_REC_FAULT        9u  /* ARM abort (prefetch/data) */

/* Fault subtypes — packed into the wire record's `protocol` byte.
 * The DFSR W-bit (bit 11) is decoded at the call site so Python
 * decoders need no ARM-specific bit manipulation. */
#define AUDITOR_FAULT_PABORT        0u  /* prefetch abort             */
#define AUDITOR_FAULT_DABORT_READ   1u  /* data abort, read access    */
#define AUDITOR_FAULT_DABORT_WRITE  2u  /* data abort, write access   */

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
 *                [8..11]=dst_channel_id (0xFFFFFFFF if none),
 *                [12..14]=parent_task_id (24-bit; sentinel 0xFFFFFF = ROOT/none) (J5),
 *                [15]=[depth:4 | sibling_count:4] (J6).
 *                Phase 3 J5 ate the first three bytes of the previously-zero
 *                [12..15] slot for parent_task_id; J6 reserves the final
 *                byte for the lineage depth + sibling count packed nibbles.
 *                MAX_TASKS=1024 fits in 24 bits with room to spare;
 *                depth/sibling_count are saturating-capped at 15.
 *   TASK_CREATE: priority=task.priority (clamped to uint8), src_domain=task.domain (low 8),
 *                protocol=0, channel_id=0,
 *                operation=task.task_id, checksum=task.parent_task_id,
 *                payload_hash[0..3]=task.cap_mask,
 *                payload_hash[4..7]=task.domain (full uint32 — handles >255 domains),
 *                payload_hash[8..11]=task.kernel_stack_top,
 *                payload_hash[12..15]=zeros.
 *                Emitted synchronously at the end of create_task on
 *                the success path. Together with TASK_EXIT this lets
 *                the encoder track task lifetimes without polling.
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
 *   FAULT:       priority=0, src_domain=task.domain & 0xFF (0 = no current_task),
 *                protocol=fault_subtype (AUDITOR_FAULT_PABORT/DABORT_READ/DABORT_WRITE),
 *                channel_id=0,
 *                operation=fault_pc (faulting instruction VA),
 *                checksum=dfar (Data Fault Address; 0 for prefetch),
 *                payload_hash[0..3]=dfsr (Data Fault Status; 0 for prefetch),
 *                payload_hash[4..7]=spsr (pre-fault CPSR snapshot),
 *                payload_hash[8..11]=task_id (0 if no current_task),
 *                payload_hash[12..15]=zeros.
 *                Emitted synchronously (no ring) from arm_pabort_diagnose /
 *                arm_dabort_diagnose so the record lands before the panic
 *                busy-loop. Accesses current_task directly (declared extern
 *                in lugh.h) — the abort site does not need to pass task
 *                context explicitly.
 *
 *   TASK_EXIT:   priority=0, src_domain=0, protocol=0, channel_id=0,
 *                operation=task_id, checksum=(uint32_t)exit_code,
 *                payload_hash[0..15]=zeros.
 *                Emitted synchronously from the SYS_EXIT syscall before
 *                the TASK_TERMINATED transition, so the caller's task_id
 *                is still queryable. Pairs with TASK_CREATE so the
 *                encoder can compute task lifetimes from telemetry alone.
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

/* Context passed to auditor_deny() — assembled by ipc.c from channel table.
 *
 * parent_task_id (J5) carries the caller's lineage at deny time so the
 * JEPA encoder can correlate denials with the task that spawned the
 * offender. Pass TASK_PARENT_NONE if current_task is NULL (eg auditor
 * tests calling the path before task_init).
 *
 * lineage_depth + sibling_count (J6) are computed by the emit site
 * before calling auditor_deny — bounded saturating walk of tasks[].
 * Each is clamped to 4 bits (max 15). */
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
    uint32_t parent_task_id;  /* TASK_PARENT_NONE if no parent (root or no current_task) */
    uint8_t  lineage_depth;   /* J6: 0..15, saturating; 0 = root */
    uint8_t  sibling_count;   /* J6: 0..15, saturating; tasks sharing parent_task_id */
    uint8_t  _pad2[2];
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

/* Task lifecycle events — emitted synchronously (no ring) so the JEPA
 * encoder sees TASK_CREATE strictly before any subsequent event that
 * references task_id, and TASK_EXIT strictly before the scheduler
 * transition that retires the task.
 *
 * task_id          — newly-allocated id (TASK_CREATE) or terminating id (TASK_EXIT)
 * parent_task_id   — current_task->task_id at create time
 * cap_mask         — effective caps after bounded-narrowing
 * domain           — full 32-bit security domain
 * priority         — task's scheduling priority (passed as int; clamped to uint8 on the wire)
 * kernel_stack_top — physical kernel stack TOP (0 if exceeded MAX_RUNNABLE)
 * exit_code        — caller-supplied SYS_EXIT argument
 */
void auditor_task_create(uint32_t task_id,
                         uint32_t parent_task_id,
                         uint32_t cap_mask,
                         uint32_t domain,
                         int      priority,
                         uint32_t kernel_stack_top);

void auditor_task_exit(uint32_t task_id, int exit_code);

/* Fault event — emitted synchronously from ARM abort handlers.
 * fault_type is one of AUDITOR_FAULT_PABORT / DABORT_READ / DABORT_WRITE.
 * dfar and dfsr should be 0 for prefetch aborts (no data address). */
void auditor_fault(uint32_t fault_pc,
                   uint32_t dfar,
                   uint32_t dfsr,
                   uint32_t spsr,
                   uint8_t  fault_type);

#endif /* AUDITOR_H */
