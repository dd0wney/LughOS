#include "lugh.h"
#include "console.h"

// Hardware-specific console port (x86 serial port)
#define SERIAL_PORT 0x3F8

// Forward declarations for architecture-specific console functions
#ifdef __riscv
extern void riscv_console_init(void);
extern void riscv_console_putchar(char c);
extern void riscv_console_write(const char *str, size_t len);
#endif

/**
 * Initialize the console
 */
void console_init(void) {
    // For x86, initialize serial port
#ifdef __i386__
    // Initialize serial port COM1
    outb(SERIAL_PORT + 1, 0x00);    // Disable interrupts
    outb(SERIAL_PORT + 3, 0x80);    // Enable DLAB
    outb(SERIAL_PORT + 0, 0x03);    // Set divisor to 3 (38400 baud)
    outb(SERIAL_PORT + 1, 0x00);    // High byte
    outb(SERIAL_PORT + 3, 0x03);    // 8 bits, no parity, one stop bit
    outb(SERIAL_PORT + 2, 0xC7);    // Enable FIFO, clear them, 14-byte threshold
    outb(SERIAL_PORT + 4, 0x0B);    // IRQs enabled, RTS/DSR set
#elif defined(__riscv)
    // Initialize RISC-V UART
    riscv_console_init();
#endif
}

/**
 * Write a character to the console
 * 
 * @param c Character to write
 */
void console_putchar(char c) {
#ifdef __i386__
    // Wait for transmit buffer to be empty
    while ((inb(SERIAL_PORT + 5) & 0x20) == 0);
    
    // Send the character (cast to unsigned char to prevent sign conversion warnings)
    outb(SERIAL_PORT, (uint8_t)c);
#elif defined(__arm__)
    // ARM implementation would use UART
    // This is simplified - in a real system, we would 
    // write to the correct MMIO address for the UART
    volatile uint32_t *uart0 = (volatile uint32_t *)0x101f1000;
    *uart0 = c;
#elif defined(__riscv)
    // Use our RISC-V specific console implementation
    riscv_console_putchar(c);
#else
    // Fallback - print nothing
#endif
}

/**
 * Write a string to the console
 * 
 * @param str String to write
 */
void console_puts(const char *str) {
    // Validate parameters (SEI CERT EXP34-C, JPL Rule 15)
    if (str == NULL) {
        return;
    }
    
    for (int i = 0; str[i] != '\0'; i++) {
        console_putchar(str[i]);
    }
}

/**
 * Write a buffer to the console
 * 
 * @param buf Buffer to write
 * @param len Length of the buffer
 */
void console_write(const char *buf, size_t len) {
    // Validate parameters (SEI CERT EXP34-C, JPL Rule 15)
    if (buf == NULL) {
        return;
    }
    
#ifdef __riscv
    // Use optimized bulk write function for RISC-V
    riscv_console_write(buf, len);
#else
    // Security: Write at most len bytes (JPL Rule 6)
    for (size_t i = 0; i < len; i++) {
        console_putchar(buf[i]);
    }
#endif
}