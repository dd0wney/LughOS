#include "lugh.h"
#include "auditor.h"
#include "hardware.h"
#include "interrupt.h"

/* COM2 serial port base address (0x2F8) for dedicated telemetry stream */
#define COM2_PORT  0x2F8u
#define COM2_LSR   (COM2_PORT + 5u)
#define COM2_THR_EMPTY 0x20u

#define DRAIN_BATCH 32u

ipc_ring_t       ipc_ring;
volatile uint8_t auditor_enabled = 0;

static uint64_t tick_count       = 0;
static uint32_t heartbeat_counter = 0;

/* ── COM2 helpers ────────────────────────────────────────────────── */

#ifdef __i386__
static void com2_init(void) {
    outb(COM2_PORT + 1, 0x00);
    outb(COM2_PORT + 3, 0x80);
    outb(COM2_PORT + 0, 0x03);
    outb(COM2_PORT + 1, 0x00);
    outb(COM2_PORT + 3, 0x03);
    outb(COM2_PORT + 2, 0xC7);
    outb(COM2_PORT + 4, 0x0B);
}

static void com2_write_bytes(const void *buf, uint32_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t i;
    for (i = 0; i < len; i++) {
        while (!(inb(COM2_LSR) & COM2_THR_EMPTY))
            ;
        outb(COM2_PORT, p[i]);
    }
}
#else
/* Non-x86: telemetry I/O sink not yet wired. The record-formatting paths
 * still run (so DENY / MSG / overflow construction is exercised on every
 * target), but the bytes are discarded. Phase 2 routes ARM telemetry to
 * PL011 UART1 on versatilepb and RISC-V to a second SBI console; keeping
 * the formatting paths live now makes that switch a one-function change.
 *
 * Crucially this avoids the inb()-returns-0-forever infinite spin that
 * the x86 path takes on any architecture where inb is a no-op stub. */
static void com2_init(void) { }
static void com2_write_bytes(const void *buf, uint32_t len) {
    (void)buf; (void)len;
}
#endif

/* ── Payload fingerprint: 4× FNV-1a-32 with distinct seeds ──────── */

static void payload_fingerprint(const char *payload, uint8_t out[16]) {
    static const uint32_t seeds[4] = {
        2166136261UL, 0xD3F81F4AUL, 0xA9035421UL, 0x5FA31B02UL
    };
    uint32_t i, j;
    for (i = 0; i < 4u; i++) {
        uint32_t h = seeds[i];
        for (j = 0; j < MAX_MSG_SIZE && payload[j] != '\0'; j++) {
            h ^= (uint8_t)payload[j];
            h *= 16777619UL;
        }
        out[i * 4u + 0u] = (uint8_t)(h);
        out[i * 4u + 1u] = (uint8_t)(h >> 8);
        out[i * 4u + 2u] = (uint8_t)(h >> 16);
        out[i * 4u + 3u] = (uint8_t)(h >> 24);
    }
}

/* ── Shared record header init ───────────────────────────────────── */

static void init_record(auditor_record_t *rec, uint16_t type) {
    rec->magic       = AUDITOR_MAGIC;
    rec->version     = AUDITOR_TELEMETRY_VERSION;
    rec->record_type = type;
    rec->jiffies     = hw_get_jiffies();
}

/* ── Record emission ─────────────────────────────────────────────── */

/* msg._padding1 was stamped in ipc_send with [channel_id:8][domain:8][protocol:8][0:8].
 * Unpack it here so MSG records carry source identity without resizing message_t. */
static void emit_msg_record(const message_t *msg) {
    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_MSG);
    rec.priority    = (uint8_t)msg->priority;
    rec.channel_id  = (uint8_t)( msg->_padding1        & 0xFFu);
    rec.src_domain  = (uint8_t)((msg->_padding1 >>  8) & 0xFFu);
    rec.protocol    = (uint8_t)((msg->_padding1 >> 16) & 0xFFu);
    rec.operation   = msg->operation;
    rec.checksum    = msg->checksum;
    payload_fingerprint(msg->payload, rec.payload_hash);
    com2_write_bytes(&rec, sizeof(rec));
}

static void emit_overflow_record(uint32_t dropped) {
    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_OVERFLOW);
    rec.priority   = 0;
    rec.src_domain = 0;
    rec.protocol   = 0;
    rec.channel_id = 0;
    rec.operation  = dropped;
    rec.checksum   = 0;
    uint32_t i;
    for (i = 0; i < 16u; i++) rec.payload_hash[i] = 0;
    com2_write_bytes(&rec, sizeof(rec));
}

static void emit_heartbeat_record(void) {
    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_HEARTBEAT);
    rec.priority   = 0;
    rec.src_domain = 0;
    rec.protocol   = 0;
    rec.channel_id = 0;
    rec.operation  = 0;
    rec.checksum   = 0;
    uint32_t i;
    for (i = 0; i < 16u; i++) rec.payload_hash[i] = 0;
    com2_write_bytes(&rec, sizeof(rec));
}

/* ── DENY record emission ────────────────────────────────────────── */

void auditor_deny(const auditor_deny_info_t *info) {
    if (!auditor_enabled || !info)
        return;

    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_DENY);

    rec.priority   = info->priority;
    rec.src_domain = info->src_domain;
    rec.protocol   = info->protocol;
    rec.channel_id = info->src_channel;
    rec.operation  = info->operation;

    /* Pack deny context into checksum field:
     * [reason:8][dst_domain:8][dst_channel:8][reserved:8] */
    rec.checksum = ((uint32_t)info->reason)
                 | ((uint32_t)info->dst_domain   << 8)
                 | ((uint32_t)info->dst_channel  << 16);

    /* payload_hash carries capability diagnostics:
     * [0..3] granted_caps  [4..7] required_caps
     * [8..11] dst_channel as full uint32  [12..15] zeros */
    uint32_t i;
    uint32_t vals[4];
    vals[0] = info->granted_caps;
    vals[1] = info->required_caps;
    vals[2] = (info->dst_channel == 0xFFu) ? 0xFFFFFFFFu
                                            : (uint32_t)info->dst_channel;
    vals[3] = 0u;
    for (i = 0; i < 4u; i++) {
        rec.payload_hash[i * 4u + 0u] = (uint8_t)(vals[i]);
        rec.payload_hash[i * 4u + 1u] = (uint8_t)(vals[i] >> 8);
        rec.payload_hash[i * 4u + 2u] = (uint8_t)(vals[i] >> 16);
        rec.payload_hash[i * 4u + 3u] = (uint8_t)(vals[i] >> 24);
    }
    com2_write_bytes(&rec, sizeof(rec));
}

/* ── Service entry points ────────────────────────────────────────── */

void auditor_init(void) {
    ring_init(&ipc_ring);
    com2_init();
    auditor_enabled = 1;
    log_message(LOG_INFO,
        "Auditor: armed (ring capacity=%u, record_size=%u)\n",
        IPC_RING_CAPACITY,
        (unsigned int)sizeof(auditor_record_t));
}

void auditor_tick(void) {
    if (!auditor_enabled)
        return;

    if (ipc_ring.overflow > 0) {
        emit_overflow_record(ipc_ring.overflow);
        ipc_ring.overflow = 0;
    }

    message_t msg;
    uint32_t drained = 0;
    while (drained < DRAIN_BATCH && ring_pop(&ipc_ring, &msg)) {
        emit_msg_record(&msg);
        drained++;
    }

    tick_count++;
    heartbeat_counter++;
    if (heartbeat_counter >= 100u) {
        emit_heartbeat_record();
        heartbeat_counter = 0;
    }
}
