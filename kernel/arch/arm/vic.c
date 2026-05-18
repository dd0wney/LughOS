#include "lugh.h"
#include "interrupt.h"

/* PrimeCell PL190 Vector Interrupt Controller driver for QEMU
 * `versatilepb`. Non-vectored mode: on every IRQ, the C dispatcher
 * reads IRQStatus and calls the registered handler for each pending
 * source. Vectored mode is a possible later optimization once a
 * working baseline exists.
 *
 * Register map (offsets from VIC_BASE):
 *   0x000 IRQStatus    — final IRQ status after enable/select
 *   0x004 FIQStatus    — final FIQ status
 *   0x008 RawIntr      — raw interrupt status before select/enable
 *   0x00C IntSelect    — 1 bit/source: 0=IRQ, 1=FIQ
 *   0x010 IntEnable    — 1 bit/source: write 1 to enable
 *   0x014 IntEnClear   — 1 bit/source: write 1 to disable
 *   0x018 SoftInt      — write 1 to assert software interrupt
 *   0x01C SoftIntClear — write 1 to clear
 *
 * 32 IRQ sources on versatilepb. On IRQ4 the SP804 dual timer lives;
 * see kernel/arch/arm/timer.c. */

#define VIC_BASE         0x10140000u
#define VIC_IRQSTATUS    (*(volatile uint32_t *)(VIC_BASE + 0x000u))
#define VIC_INTSELECT    (*(volatile uint32_t *)(VIC_BASE + 0x00Cu))
#define VIC_INTENABLE    (*(volatile uint32_t *)(VIC_BASE + 0x010u))
#define VIC_INTENCLEAR   (*(volatile uint32_t *)(VIC_BASE + 0x014u))

#define VIC_NUM_IRQS 32u

/* Registered handlers — one slot per IRQ source. */
static irq_handler_t handlers[VIC_NUM_IRQS];
static void*         cookies [VIC_NUM_IRQS];

void vic_init(void) {
    /* Mask every source. The boot code starts with IRQs disabled at the
     * CPU; this clears any leftover enables in the VIC itself so we
     * don't take spurious interrupts the moment the CPU unmasks. */
    VIC_INTENCLEAR = 0xFFFFFFFFu;
    /* All sources route to IRQ (not FIQ). FIQ is reserved for future
     * latency-critical work; we treat any FIQ as a panic for now. */
    VIC_INTSELECT  = 0u;
    for (uint32_t i = 0u; i < VIC_NUM_IRQS; i++) {
        handlers[i] = NULL;
        cookies[i]  = NULL;
    }
    log_message(LOG_INFO,
        "VIC: PL190 initialised at 0x%X (%u sources, all masked)\n",
        VIC_BASE, VIC_NUM_IRQS);
}

int irq_register_handler(uint32_t irq, irq_handler_t fn, void *cookie) {
    if (irq >= VIC_NUM_IRQS || fn == NULL) return -1;
    if (handlers[irq] != NULL) {
        log_message(LOG_WARNING,
            "VIC: IRQ %u already registered; replacing\n", irq);
    }
    handlers[irq] = fn;
    cookies[irq]  = cookie;
    /* Enable the source. CPU-side I-bit is still set, so the IRQ
     * doesn't fire until enter_user_mode / explicit CPSR clear. */
    VIC_INTENABLE = (1u << irq);
    return 0;
}

int irq_unregister_handler(uint32_t irq) {
    if (irq >= VIC_NUM_IRQS) return -1;
    VIC_INTENCLEAR = (1u << irq);
    handlers[irq] = NULL;
    cookies[irq]  = NULL;
    return 0;
}

void irq_eoi(uint32_t irq) {
    /* PL190 has no explicit EOI for non-vectored sources — the device
     * driver is responsible for clearing the source-specific interrupt
     * (e.g. SP804 INTCLR). Reading IRQStatus has no side effect either.
     * We provide this entry point for the cross-arch HAL contract; on
     * x86 it writes the 8259 EOI register. */
    (void)irq;
}

/* Called from arm_irq_entry (exceptions.S) on every IRQ. Scans
 * IRQStatus and invokes every pending handler — there can be multiple
 * sources active simultaneously, so we walk the whole bitmap rather
 * than dispatching once and returning. */
void arm_irq_dispatch(void) {
    uint32_t status = VIC_IRQSTATUS;
    for (uint32_t i = 0u; i < VIC_NUM_IRQS && status != 0u; i++) {
        if ((status & (1u << i)) != 0u) {
            if (handlers[i] != NULL) {
                handlers[i](i, cookies[i]);
            }
            /* Don't clear status here — the source clears itself via
             * its own ack register (e.g. SP804 INTCLR). If a handler
             * leaves its source asserted, we'll re-enter on return. */
            status &= ~(1u << i);
        }
    }
}

/* ── IPL → CPSR.I mapping ─────────────────────────────────────────
 *
 * Coarse-grained: any non-NONE IPL sets CPSR.I (mask all IRQs at the
 * CPU). Future refinement: map IPL_TTY/CLOCK/HIGH to specific VIC
 * INTENABLE/INTENCLEAR patterns. The current implementation honors
 * the contract — splraise returns the prior I-bit, splx restores it
 * — which is what callers depend on; the fine-grained breakdown is
 * an optimization, not a correctness requirement.
 *
 * spl_t encodes the prior CPSR.I bit (0 = was enabled, 1 = was
 * masked). On ARMv5 we read/modify/write CPSR via mrs/msr; the
 * ARMv6+ `cpsie/cpsid i` mnemonic isn't available on ARM926EJ-S. */

static inline uint32_t cpsr_read(void) {
    uint32_t v;
    __asm__ volatile("mrs %0, cpsr" : "=r"(v));
    return v;
}

static inline void cpsr_write_c(uint32_t v) {
    __asm__ volatile("msr cpsr_c, %0" :: "r"(v) : "memory");
}

spl_t splraise(uint32_t ipl) {
    uint32_t cpsr = cpsr_read();
    spl_t prev = (spl_t)((cpsr >> 7) & 1u);
    if (ipl != IPL_NONE) {
        cpsr_write_c(cpsr | 0x80u);   /* mask IRQs */
    }
    return prev;
}

void splx(spl_t prev) {
    uint32_t cpsr = cpsr_read();
    if (prev != 0u) cpsr |=  0x80u;   /* was masked: keep masked */
    else            cpsr &= ~0x80u;   /* was enabled: unmask */
    cpsr_write_c(cpsr);
}

spl_t splhigh(void)  { return splraise(IPL_HIGH);  }
spl_t splclock(void) { return splraise(IPL_CLOCK); }

spl_t spl0(void) {
    /* Lower to IPL_NONE: unconditionally unmask. Returns prior I-bit
     * so the matching splx() can restore exactly. */
    uint32_t cpsr = cpsr_read();
    spl_t prev = (spl_t)((cpsr >> 7) & 1u);
    cpsr_write_c(cpsr & ~0x80u);
    return prev;
}
