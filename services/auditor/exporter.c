#include "lugh.h"
#include "auditor.h"
#include "hardware.h"
#include "interrupt.h"

#define DRAIN_BATCH 32u

ipc_ring_t       ipc_ring;
volatile uint8_t auditor_enabled = 0;

static uint64_t tick_count       = 0;
static uint32_t heartbeat_counter = 0;

/* ── Telemetry sink ────────────────────────────────────────────────
 * Per-arch backend writing fixed-size auditor_record_t records to a
 * dedicated serial port, separate from the kernel log console.
 *   x86 → COM2 (0x2F8) via 8250 I/O ports.
 *   ARM → PL011 UART1 (0x101F2000) on versatilepb via MMIO.
 * Capture from QEMU with a second -serial argument:
 *   x86:  -serial mon:stdio -serial file:/tmp/lugh_ipc.bin
 *   ARM:  -serial file:/tmp/lugh-arm.log -serial file:/tmp/lugh_ipc.bin
 * The wire format is identical across arches — scripts/read_telemetry.py
 * parses either capture identically. */

#ifdef __i386__
#define COM2_PORT      0x2F8u
#define COM2_LSR       (COM2_PORT + 5u)
#define COM2_THR_EMPTY 0x20u

static void tlm_init(void) {
    outb(COM2_PORT + 1, 0x00);
    outb(COM2_PORT + 3, 0x80);
    outb(COM2_PORT + 0, 0x03);
    outb(COM2_PORT + 1, 0x00);
    outb(COM2_PORT + 3, 0x03);
    outb(COM2_PORT + 2, 0xC7);
    outb(COM2_PORT + 4, 0x0B);
}

static void tlm_write_bytes(const void *buf, uint32_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t i;
    for (i = 0; i < len; i++) {
        while (!(inb(COM2_LSR) & COM2_THR_EMPTY))
            ;
        outb(COM2_PORT, p[i]);
    }
}

#elif defined(__arm__)
/* PL011 UART1 on versatilepb. QEMU's PL011 model is usable from reset,
 * so init is a no-op. DR at +0x00 (32-bit write, low byte to FIFO);
 * FR at +0x18, bit 5 = TXFF (FIFO full). */
#define PL011_U1_DR (*(volatile uint32_t *)(0x101F2000u + 0x00u))
#define PL011_U1_FR (*(volatile uint32_t *)(0x101F2000u + 0x18u))
#define PL011_FR_TXFF (1u << 5)

static void tlm_init(void) { }

static void tlm_write_bytes(const void *buf, uint32_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t i;
    for (i = 0; i < len; i++) {
        while ((PL011_U1_FR & PL011_FR_TXFF) != 0u) { }
        PL011_U1_DR = (uint32_t)p[i];
    }
}

#else
/* RISC-V and other targets: record formatting still runs so the paths
 * stay exercised on every build, but bytes are discarded until a real
 * sink is wired (likely a second SBI console). */
static void tlm_init(void) { }
static void tlm_write_bytes(const void *buf, uint32_t len) {
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
    tlm_write_bytes(&rec, sizeof(rec));
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
    tlm_write_bytes(&rec, sizeof(rec));
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
    tlm_write_bytes(&rec, sizeof(rec));
}

/* ── Structural event emission (sync — no ring) ──────────────────── */

/* CHAN_CREATE packs identity + policy into the existing 44-byte layout.
 * Field reuse mapping (mirrors auditor.h comment):
 *   priority      = 0
 *   src_domain    = low 8 bits of domain  (for fast filtering)
 *   protocol      = NNG protocol id
 *   channel_id    = channel table index
 *   operation     = cap_mask  (which CAP_* bits the channel holds)
 *   checksum      = owner_task_id  (root-of-trust binding)
 *   payload_hash  = [domain:32][security_level:32][zeros:64]
 *                   (full 32-bit domain lets us handle >255 domains later
 *                    without another version bump.)
 */
static void emit_chan_create_record(uint32_t channel_id,
                                    uint32_t owner_task_id,
                                    uint32_t cap_mask,
                                    uint32_t domain,
                                    uint32_t security_level,
                                    uint32_t protocol) {
    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_CHAN_CREATE);
    rec.priority   = 0;
    rec.src_domain = (uint8_t)(domain & 0xFFu);
    rec.protocol   = (uint8_t)(protocol & 0xFFu);
    rec.channel_id = (uint8_t)(channel_id & 0xFFu);
    rec.operation  = cap_mask;
    rec.checksum   = owner_task_id;

    uint32_t vals[4];
    vals[0] = domain;
    vals[1] = security_level;
    vals[2] = 0u;
    vals[3] = 0u;
    uint32_t i;
    for (i = 0; i < 4u; i++) {
        rec.payload_hash[i * 4u + 0u] = (uint8_t)(vals[i]);
        rec.payload_hash[i * 4u + 1u] = (uint8_t)(vals[i] >> 8);
        rec.payload_hash[i * 4u + 2u] = (uint8_t)(vals[i] >> 16);
        rec.payload_hash[i * 4u + 3u] = (uint8_t)(vals[i] >> 24);
    }
    tlm_write_bytes(&rec, sizeof(rec));
}

void auditor_chan_create(uint32_t channel_id,
                         uint32_t owner_task_id,
                         uint32_t cap_mask,
                         uint32_t domain,
                         uint32_t security_level,
                         uint32_t protocol) {
    if (!auditor_enabled)
        return;
    emit_chan_create_record(channel_id, owner_task_id, cap_mask,
                            domain, security_level, protocol);
}

/* CHAN_CONNECT: success-branch edge event. Packing (mirrors auditor.h):
 *   operation     = dst_channel_id  (full uint32 so future MAX_IPC_CHANNELS
 *                                    growth past 256 doesn't lose the dst)
 *   checksum      = dst_domain      (full uint32)
 *   payload_hash  = [src_cap_mask:32][dst_cap_mask:32][zeros:64]
 */
static void emit_chan_connect_record(uint32_t src_channel_id,
                                     uint32_t src_domain,
                                     uint32_t src_cap_mask,
                                     uint32_t src_protocol,
                                     uint32_t dst_channel_id,
                                     uint32_t dst_domain,
                                     uint32_t dst_cap_mask) {
    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_CHAN_CONNECT);
    rec.priority   = 0;
    rec.src_domain = (uint8_t)(src_domain & 0xFFu);
    rec.protocol   = (uint8_t)(src_protocol & 0xFFu);
    rec.channel_id = (uint8_t)(src_channel_id & 0xFFu);
    rec.operation  = dst_channel_id;
    rec.checksum   = dst_domain;

    uint32_t vals[4];
    vals[0] = src_cap_mask;
    vals[1] = dst_cap_mask;
    vals[2] = 0u;
    vals[3] = 0u;
    uint32_t i;
    for (i = 0; i < 4u; i++) {
        rec.payload_hash[i * 4u + 0u] = (uint8_t)(vals[i]);
        rec.payload_hash[i * 4u + 1u] = (uint8_t)(vals[i] >> 8);
        rec.payload_hash[i * 4u + 2u] = (uint8_t)(vals[i] >> 16);
        rec.payload_hash[i * 4u + 3u] = (uint8_t)(vals[i] >> 24);
    }
    tlm_write_bytes(&rec, sizeof(rec));
}

void auditor_chan_connect(uint32_t src_channel_id,
                          uint32_t src_domain,
                          uint32_t src_cap_mask,
                          uint32_t src_protocol,
                          uint32_t dst_channel_id,
                          uint32_t dst_domain,
                          uint32_t dst_cap_mask) {
    if (!auditor_enabled)
        return;
    emit_chan_connect_record(src_channel_id, src_domain, src_cap_mask,
                             src_protocol, dst_channel_id, dst_domain,
                             dst_cap_mask);
}

/* DOMAIN_EDGE: policy mutation event. The full uint32 src/dst are stored
 * in operation/checksum (current MAX_DOMAINS=8 fits in 8 bits, but this
 * leaves room to grow without another version bump). */
static void emit_domain_edge_record(uint32_t src_domain,
                                    uint32_t dst_domain,
                                    uint32_t added) {
    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_DOMAIN_EDGE);
    rec.priority   = 0;
    rec.src_domain = (uint8_t)(src_domain & 0xFFu);
    rec.protocol   = 0;
    rec.channel_id = (uint8_t)(dst_domain & 0xFFu);
    rec.operation  = src_domain;
    rec.checksum   = dst_domain;

    uint32_t vals[4];
    vals[0] = added;
    vals[1] = 0u;
    vals[2] = 0u;
    vals[3] = 0u;
    uint32_t i;
    for (i = 0; i < 4u; i++) {
        rec.payload_hash[i * 4u + 0u] = (uint8_t)(vals[i]);
        rec.payload_hash[i * 4u + 1u] = (uint8_t)(vals[i] >> 8);
        rec.payload_hash[i * 4u + 2u] = (uint8_t)(vals[i] >> 16);
        rec.payload_hash[i * 4u + 3u] = (uint8_t)(vals[i] >> 24);
    }
    tlm_write_bytes(&rec, sizeof(rec));
}

void auditor_domain_edge(uint32_t src_domain,
                         uint32_t dst_domain,
                         uint32_t added) {
    if (!auditor_enabled)
        return;
    emit_domain_edge_record(src_domain, dst_domain, added);
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
    tlm_write_bytes(&rec, sizeof(rec));
}

/* ── Service entry points ────────────────────────────────────────── */

void auditor_init(void) {
    ring_init(&ipc_ring);
    tlm_init();
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
