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

/* ── IPL stubs — Phase 2 step 2 ────────────────────────────────────
 * The cross-arch interrupt.h declares spl* and hw_get_jiffies; we
 * keep no-op stubs here until the IPL → VIC mask mapping is wired.
 * hw_get_jiffies lives in timer.c once SP804 is online; until then
 * it returns 0 (the value most callers tolerate as "unset"). */
spl_t splraise(uint32_t ipl) { (void)ipl; return 0; }
void  splx(spl_t prev)       { (void)prev; }
spl_t splhigh(void)          { return 0; }
spl_t splclock(void)         { return 0; }
spl_t spl0(void)             { return 0; }
