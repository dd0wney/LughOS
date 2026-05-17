#include "lugh.h"
#include "interrupt.h"

extern void syscall_entry(void);

/* flags: 0xEE = Present(0x80) | DPL=3(0x60) | 32-bit interrupt gate(0x0E)
 * DPL=3 is required so user-space code can invoke via int $0x80.           */
void init_syscall(void) {
    log_message(LOG_INFO, "Initializing system call interface\n");
    idt_set_gate(0x80, (uint32_t)syscall_entry, 0x08, 0xEE);
    log_message(LOG_INFO, "System call interface initialized\n");
}
