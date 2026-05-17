#include "lugh.h"
#include "interrupt.h"

/* 8253/8254 PIT port addresses */
#define PIT_CH0   0x40   /* Channel 0 data port (IRQ0)               */
#define PIT_CMD   0x43   /* Command / mode register                   */
/* PIT oscillator frequency in Hz */
#define PIT_BASE_HZ 1193182UL

static volatile uint64_t jiffies;

static void pit_tick(uint32_t irq, void *cookie) {
    (void)irq; (void)cookie;
    jiffies++;
    /* Log once per second (100 ticks at 100 Hz) to prove the IRQ path works.
     * Cast to uint32_t to avoid __umoddi3 (64-bit modulo) in -nostdlib builds. */
    if (((uint32_t)jiffies % 100u) == 0u)
        log_message(LOG_DEBUG, "[PIT] tick %llu\n", (unsigned long long)jiffies);
}

void pit_init(uint32_t hz) {
    uint32_t divisor = PIT_BASE_HZ / hz;

    /* Command: channel 0, lobyte/hibyte, mode 3 (square wave), binary */
    outb(PIT_CMD, 0x36);
    outb(PIT_CH0, (uint8_t)(divisor & 0xFF));
    outb(PIT_CH0, (uint8_t)((divisor >> 8) & 0xFF));

    irq_register_handler(0, pit_tick, NULL);
    log_message(LOG_INFO, "PIT initialised at %u Hz (divisor=%u)\n",
                (unsigned int)hz, (unsigned int)divisor);
}

uint64_t hw_get_jiffies(void) {
    return jiffies;
}
