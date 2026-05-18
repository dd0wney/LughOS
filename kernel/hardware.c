#include "console.h"
#include "lugh.h"
#include "hardware.h"
#include "watchdog.h"

extern scheduler_ops_t rr_scheduler;

/**
 * Output a byte to an I/O port
 * 
 * @param port Port number to write to
 * @param val Value to write
 */
#ifdef __i386__
void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
#else
/* Non-x86 has no port-I/O instruction; all device access is memory-mapped
 * and routed through arch-specific MMIO in log.c / console.c / exporter.c.
 * These stubs exist only so the linker can resolve cross-arch references
 * that are guarded by `#ifdef __i386__` at every actual call site.
 *
 * If execution ever reaches one of these, an unguarded x86-port caller
 * snuck in — trap loudly rather than silently returning 0, which on a
 * "while (!(inb(LSR) & THR_EMPTY))" loop would spin forever (the failure
 * mode that originally hung the ARM build inside watchdog_tick). */
__attribute__((noreturn))
void outb(uint16_t port, uint8_t val) {
    (void)port; (void)val;
    __builtin_trap();
}

__attribute__((noreturn))
uint8_t inb(uint16_t port) {
    (void)port;
    __builtin_trap();
}
#endif

/**
 * Halt the CPU completely (kernel panic / unrecoverable error).
 * cli prevents new interrupts; the hlt loop handles NMI wake-ups.
 */
void cpu_halt(void) {
#ifdef __i386__
    __asm__ volatile("cli");
    while (1) __asm__ volatile("hlt");
#else
    while (1) {}
#endif
}

/**
 * Detect and initialize hardware
 * 
 * @return int 1 if hardware initialization was successful, 0 otherwise
 */
int hw_detect(void) {
    // Placeholder - add actual hardware detection here
    log_message(LOG_INFO, "Performing hardware detection...\n");

    // Implementation would detect CPU type, memory, etc.
    return 1;
}

/**
 * Process any pending system events
 */
void process_events(void) {
    watchdog_tick();
    if (rr_scheduler.schedule) {
        uint32_t next_task_id = 0;
        rr_scheduler.schedule(NULL, 0, &next_task_id);
    }
}

/**
 * Put the CPU into a lower state until the next event.
 * sti; hlt is atomic on x86: interrupts are enabled for exactly the hlt
 * instruction, so we never miss a tick between the sti and the sleep.
 */
void cpu_idle(void) {
#ifdef __i386__
    __asm__ volatile("sti; hlt");
#endif
}