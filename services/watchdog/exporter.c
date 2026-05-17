#include "lugh.h"
#include "watchdog.h"
#include "hardware.h"
#include "interrupt.h"

/* COM2 serial port base address (0x2F8) for dedicated telemetry stream */
#define COM2_PORT  0x2F8u
#define COM2_LSR   (COM2_PORT + 5u)   /* Line Status Register */
#define COM2_THR_EMPTY 0x20u          /* bit 5: transmit holding register empty */

/* Max messages drained per watchdog_tick() to avoid starving other events */
#define DRAIN_BATCH 32u

ipc_ring_t       ipc_ring;
volatile uint8_t watchdog_enabled = 0;

static uint64_t tick_count = 0;

/* ── COM2 helpers ────────────────────────────────────────────────── */

static void com2_init(void) {
    outb(COM2_PORT + 1, 0x00);   /* disable interrupts */
    outb(COM2_PORT + 3, 0x80);   /* enable DLAB (baud divisor) */
    outb(COM2_PORT + 0, 0x03);   /* divisor low  → 38400 baud */
    outb(COM2_PORT + 1, 0x00);   /* divisor high */
    outb(COM2_PORT + 3, 0x03);   /* 8N1, disable DLAB */
    outb(COM2_PORT + 2, 0xC7);   /* enable FIFO, clear, 14-byte threshold */
    outb(COM2_PORT + 4, 0x0B);   /* RTS/DSR set */
}

static void com2_write_bytes(const void *buf, uint32_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t i;
    for (i = 0; i < len; i++) {
        /* Spin until THR empty — QEMU always returns ready immediately */
        while (!(inb(COM2_LSR) & COM2_THR_EMPTY))
            ;
        outb(COM2_PORT, p[i]);
    }
}

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
            h *= 16777619UL;   /* FNV prime for 32-bit */
        }
        out[i * 4u + 0u] = (uint8_t)(h);
        out[i * 4u + 1u] = (uint8_t)(h >> 8);
        out[i * 4u + 2u] = (uint8_t)(h >> 16);
        out[i * 4u + 3u] = (uint8_t)(h >> 24);
    }
}

/* ── Record emission ─────────────────────────────────────────────── */

static void emit_msg_record(const message_t *msg) {
    watchdog_record_t rec;
    rec.magic       = WATCHDOG_MAGIC;
    rec.version     = WATCHDOG_TELEMETRY_VERSION;
    rec.record_type = WATCHDOG_REC_MSG;
    rec.jiffies     = hw_get_jiffies();
    rec.priority    = (uint8_t)msg->priority;
    rec._pad[0] = rec._pad[1] = rec._pad[2] = 0;
    rec.operation   = msg->operation;
    rec.checksum    = msg->checksum;
    payload_fingerprint(msg->payload, rec.payload_hash);
    com2_write_bytes(&rec, sizeof(rec));
}

static void emit_overflow_record(uint32_t dropped) {
    watchdog_record_t rec;
    rec.magic       = WATCHDOG_MAGIC;
    rec.version     = WATCHDOG_TELEMETRY_VERSION;
    rec.record_type = WATCHDOG_REC_OVERFLOW;
    rec.jiffies     = hw_get_jiffies();
    rec.priority    = 0;
    rec._pad[0] = rec._pad[1] = rec._pad[2] = 0;
    rec.operation   = dropped;   /* reuse field to carry drop count */
    rec.checksum    = 0;
    uint32_t i;
    for (i = 0; i < 16u; i++) rec.payload_hash[i] = 0;
    com2_write_bytes(&rec, sizeof(rec));
}

static void emit_heartbeat_record(void) {
    watchdog_record_t rec;
    rec.magic       = WATCHDOG_MAGIC;
    rec.version     = WATCHDOG_TELEMETRY_VERSION;
    rec.record_type = WATCHDOG_REC_HEARTBEAT;
    rec.jiffies     = hw_get_jiffies();
    rec.priority    = 0;
    rec._pad[0] = rec._pad[1] = rec._pad[2] = 0;
    rec.operation   = 0;
    rec.checksum    = 0;
    uint32_t i;
    for (i = 0; i < 16u; i++) rec.payload_hash[i] = 0;
    com2_write_bytes(&rec, sizeof(rec));
}

/* ── Service entry points ────────────────────────────────────────── */

void watchdog_init(void) {
    ring_init(&ipc_ring);
    com2_init();
    watchdog_enabled = 1;
    log_message(LOG_INFO,
        "Watchdog: armed (ring capacity=%u, record_size=%u)\n",
        IPC_RING_CAPACITY,
        (unsigned int)sizeof(watchdog_record_t));
}

void watchdog_tick(void) {
    if (!watchdog_enabled)
        return;

    /* Report and clear overflow from the previous tick window */
    if (ipc_ring.overflow > 0) {
        emit_overflow_record(ipc_ring.overflow);
        ipc_ring.overflow = 0;
    }

    /* Drain up to DRAIN_BATCH messages per tick */
    message_t msg;
    uint32_t drained = 0;
    while (drained < DRAIN_BATCH && ring_pop(&ipc_ring, &msg)) {
        emit_msg_record(&msg);
        drained++;
    }

    /* Heartbeat every 100 ticks (~1 s at 100 Hz) */
    tick_count++;
    if (((uint32_t)tick_count % 100u) == 0u)
        emit_heartbeat_record();
}
