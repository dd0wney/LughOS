#include "lugh.h"
#include "hardware.h"
#include <stdint.h>

// Include debug headers for early boot on RISC-V
#ifdef __riscv
#include "main_debug.h"
#endif

// Function prototypes
static void init_serial(void);
static void serial_write(uint8_t c);
static void kputchar(char c);
static void kprintf(const char* format, va_list args);

// Simple global tick counter for timestamps
static volatile uint32_t log_ticks = 0;

// Call this from your timer interrupt handler to increment
void log_tick(void) {
    log_ticks++;
}

/* Per-arch serial backend. Each arch must provide init_serial + serial_write.
 * Arch-specific MMIO addresses are declared here rather than in a header so
 * the log subsystem stays self-contained as the early-boot debug surface. */

#ifdef __i386__
/* x86: 16550-compatible UART at COM1 (0x3F8). */
static void init_serial(void) {
    outb(0x3F9, 0x00);    /* disable interrupts                       */
    outb(0x3FB, 0x80);    /* DLAB on                                  */
    outb(0x3F8, 0x03);    /* divisor low — 38400 baud                 */
    outb(0x3F9, 0x00);    /* divisor high                             */
    outb(0x3FB, 0x03);    /* 8N1, DLAB off                            */
    outb(0x3FA, 0xC7);    /* FIFO on, clear, 14-byte threshold        */
    outb(0x3FC, 0x0B);    /* DTR + RTS                                */
}

static void serial_write(uint8_t c) {
    while ((inb(0x3FD) & 0x20) == 0) { /* spin until LSR THRE         */ }
    outb(0x3F8, c);
}

#elif defined(__arm__)
/* ARM: PL011 UART0 on QEMU's `versatilepb` board.
 * Base 0x101F1000. DR at +0x00, FR at +0x18 (bit 5 = TXFF).
 * The QEMU PL011 model is usable from reset, so no init is required. */
#define PL011_DR (*(volatile uint32_t *)(0x101F1000u + 0x00u))
#define PL011_FR (*(volatile uint32_t *)(0x101F1000u + 0x18u))
#define PL011_FR_TXFF (1u << 5)

static void init_serial(void) {
    /* No-op: QEMU's PL011 model accepts writes from reset. A real board
     * would set IBRD/FBRD for baud and enable TX/RX via CR here. */
}

static void serial_write(uint8_t c) {
    while ((PL011_FR & PL011_FR_TXFF) != 0u) { /* spin while TX FIFO full */ }
    PL011_DR = (uint32_t)c;
}

#else
/* Fallback: no serial backend. Logs are silent. */
static void init_serial(void) { }
static void serial_write(uint8_t c) { (void)c; }
#endif

// Basic implementation of kernel console output 
// Outputs to both VGA and serial port
static void kputchar(char c) {
    // JPL Rule 15: Validate parameters at start of public functions (should check c is valid ASCII)
    // SEI CERT ARR30-C: Validate all array indices (bounds check for VGA buffer)
    // Initialize serial port if not done yet
    static int initialized = 0;
    if (!initialized) {
        init_serial();
        initialized = 1;
    }
    serial_write((uint8_t)c); // Explicit cast for sign-conversion
#ifdef __i386__
    /* VGA text mode at 0xB8000 — x86 PC-compatible only. On ARM/RISC-V
     * this address is DRAM, so writes would corrupt the kernel. */
    static volatile unsigned short* vga_buffer = (unsigned short*)0xB8000;
    static int position = 0;
    if (c == '\n') {
        position = ((position / 80) + 1) * 80;
        if (position >= 80 * 25) position = 0; // Bounds check
    } else {
        if (position < 80 * 25) {
            vga_buffer[position++] = (unsigned short)(((uint8_t)c) | 0x0700);
        } else {
            position = 0;
        }
    }
#endif
}

// Very basic printf-like functionality
static void kprintf(const char* format, va_list args) {
    // JPL Rule 15: Validate parameters at start of public functions (should check format != NULL)
    // SEI CERT STR31-C: Guarantee storage for strings has space for null terminator
    char c;
    while ((c = *format++)) {
        if (c != '%') {
            kputchar(c);
            continue;
        }
        c = *format++;
        if (!c) break;
        switch (c) {
            case 's': {
                const char* s = va_arg(args, const char*);
                if (s) {
                    for (size_t i = 0; s[i] != '\0'; i++) {
                        kputchar(s[i]);
                    }
                }
                break;
            }
            case 'd': {
                int value = va_arg(args, int);
                if (value < 0) {
                    kputchar('-');
                    value = -value;
                }
                char buffer[12];
                int i = 0;
                do {
                    int digit = value % 10;
                    buffer[i++] = (char)('0' + digit);
                    value /= 10;
                } while (value && i < 11);
                while (i > 0) {
                    kputchar(buffer[--i]);
                }
                break;
            }
            case 'u': {
                unsigned int value = va_arg(args, unsigned int);
                char buffer[12];
                int i = 0;
                do {
                    buffer[i++] = (char)('0' + (value % 10));
                    value /= 10;
                } while (value && i < 11);
                while (i > 0) {
                    kputchar(buffer[--i]);
                }
                break;
            }
            case 'x':
            case 'X': {
                /* Single handler, case selects the digit alphabet. The 'X'
                 * path matters because callers that use uppercase format
                 * specifiers would otherwise fall into the default branch,
                 * print "%X" literally, and shift every subsequent argument
                 * by one — a silent argument-misalignment bug. */
                char a = (c == 'X') ? 'A' : 'a';
                unsigned int value = va_arg(args, unsigned int);
                char buffer[8];
                int i = 0;
                do {
                    int digit = value & 0xF;
                    buffer[i++] = (char)((digit < 10) ? ('0' + digit) : (a + digit - 10));
                    value >>= 4;
                } while (i < 8); // Always print 8 hex digits
                while (i > 0) {
                    kputchar(buffer[--i]);
                }
                break;
            }
            case 'p': {
                unsigned int value = va_arg(args, unsigned int);
                kputchar('0'); kputchar('x');
                char buffer[8];
                int i = 0;
                do {
                    int digit = value & 0xF;
                    buffer[i++] = (char)((digit < 10) ? ('0' + digit) : ('a' + digit - 10));
                    value >>= 4;
                } while (i < 8); // Always print 8 hex digits for pointers
                while (i > 0) {
                    kputchar(buffer[--i]);
                }
                break;
            }
            case '%':
                kputchar('%');
                break;
            default:
                kputchar('%');
                kputchar(c);
        }
    }
}

void log_message(log_level_t level, const char* format, ...) {
    if ((unsigned)level >= (unsigned)LOG_LEVEL_COUNT) return;
    
#ifdef __riscv
    // For RISC-V, provide early debug output
    early_debug_print("[LOG] ");
#endif
    
    // Print timestamp prefix as 8 hex digits, zero-padded
    kputchar('[');
    unsigned int t = log_ticks;
    char buffer[8];
    int i = 0;
    do {
        int digit = t & 0xF;
        buffer[i++] = (char)((digit < 10) ? ('0' + digit) : ('a' + digit - 10));
        t >>= 4;
    } while (i < 8);
    while (i > 0) {
        kputchar(buffer[--i]);
    }
    kputchar(']');
    kputchar(' ');
    va_list args;
    va_start(args, format);
    kprintf(format, args);
    va_end(args);
    kputchar('\n'); // Always end log messages with a newline for clarity
    
#ifdef __riscv
    // Additional newline for RISC-V console readability
    early_debug_print("\r\n");
#endif
}