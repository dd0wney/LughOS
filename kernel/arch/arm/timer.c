#include "lugh.h"
#include "interrupt.h"

/* SP804 dual-timer driver for QEMU `versatilepb`.
 *
 * Two timers (Timer0 at 0x101E2000, Timer1 at 0x101E2020) share VIC IRQ4.
 * That sharing is the well-known footgun: the ISR has to check RIS on
 * each timer and write INTCLR on the same one. Writing INTCLR on a
 * timer that isn't asserting leaves the IRQ line set and the handler
 * re-enters immediately — a tight loop that looks identical to "the
 * timer doesn't work."
 *
 * We use Timer0 for the system tick (100 Hz periodic) and leave Timer1
 * idle. The ISR still checks both so we're robust if Timer1 ever gets
 * enabled later.
 *
 * SP804 input clock on versatilepb is 1 MHz (TIMCLK at default
 * prescaler), so LOAD = 1_000_000 / hz. */

#define TIMER0_BASE    0x101E2000u
#define TIMER1_BASE    0x101E2020u
#define TIMER_VIC_IRQ  4u

#define T_LOAD     0x00u
#define T_VALUE    0x04u
#define T_CONTROL  0x08u
#define T_INTCLR   0x0Cu
#define T_RIS      0x10u
#define T_MIS      0x14u

#define T0_LOAD    (*(volatile uint32_t *)(TIMER0_BASE + T_LOAD))
#define T0_CONTROL (*(volatile uint32_t *)(TIMER0_BASE + T_CONTROL))
#define T0_INTCLR  (*(volatile uint32_t *)(TIMER0_BASE + T_INTCLR))
#define T0_RIS     (*(volatile uint32_t *)(TIMER0_BASE + T_RIS))
#define T1_RIS     (*(volatile uint32_t *)(TIMER1_BASE + T_RIS))
#define T1_INTCLR  (*(volatile uint32_t *)(TIMER1_BASE + T_INTCLR))

/* CONTROL register bits */
#define T_CTRL_ENABLE   (1u << 7)
#define T_CTRL_PERIODIC (1u << 6)
#define T_CTRL_INTEN    (1u << 5)
#define T_CTRL_32BIT    (1u << 1)

#define TIMCLK_HZ      1000000u
#define TICK_HZ        100u
/* LOAD = TIMCLK_HZ / TICK_HZ. Hardcoded because ARM926EJ-S has no
 * hardware divide and we build -nostdlib; a runtime divide here would
 * pull in __aeabi_uidiv from libgcc. If the tick rate ever needs to be
 * dynamic, link -lgcc instead of working around it. */
#define TIMER_LOAD_VAL 10000u

static volatile uint64_t arm_jiffies = 0u;

extern void log_tick(void); /* defined in kernel/log.c — drives [HHHHHHHH] */

static void timer_isr(uint32_t irq, void *cookie) {
    (void)irq; (void)cookie;
    /* Timer0 + Timer1 share IRQ4. Ack only the timer(s) actually asserting. */
    if ((T0_RIS & 1u) != 0u) {
        arm_jiffies++;
        log_tick();
        T0_INTCLR = 1u;
    }
    if ((T1_RIS & 1u) != 0u) {
        T1_INTCLR = 1u;
    }
}

void arm_timer_init(void) {
    T0_CONTROL = 0u;                 /* disable while configuring */
    T0_LOAD    = TIMER_LOAD_VAL;
    T0_CONTROL = T_CTRL_ENABLE | T_CTRL_PERIODIC
               | T_CTRL_INTEN  | T_CTRL_32BIT;
    irq_register_handler(TIMER_VIC_IRQ, timer_isr, NULL);
    log_message(LOG_INFO,
        "SP804: Timer0 enabled at %u Hz (LOAD=%u, VIC IRQ=%u)\n",
        (unsigned int)TICK_HZ, (unsigned int)TIMER_LOAD_VAL,
        (unsigned int)TIMER_VIC_IRQ);
}

uint64_t hw_get_jiffies(void) {
    return arm_jiffies;
}
