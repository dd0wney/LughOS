#include "console.h"
#include "lugh.h"
#include "hardware.h"

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
// On non-x86 architectures, these are not supported directly.
// For RISC-V and ARM, we'll use a memory-mapped approach implemented
// in the architecture-specific console files.
void outb(uint16_t port, uint8_t val) {
    (void)port; (void)val;
    // These are implemented architecture-specifically
}

uint8_t inb(uint16_t port) {
    (void)port;
    // These are implemented architecture-specifically
    return 0;
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
    // TODO: process interrupts, timers, etc.
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