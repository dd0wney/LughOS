#include "lugh.h"
#include "hardware.h"
#include "interrupt.h"

/* Layout MUST match the push order in isr.S / irq_common:
 *   gs, fs, es, ds      — pushed last (gs at lowest address)
 *   edi..eax            — from pusha (edi at lowest)
 *   int_no, err_code    — pushed by stub
 *   eip, cs, eflags     — pushed by CPU
 */
struct regs {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp_d, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags;
};

static const char *exc_names[] = {
    "Divide-by-zero",        "Debug",                "NMI",
    "Breakpoint",            "Overflow",             "Bound Range Exceeded",
    "Invalid Opcode",        "Device Not Available", "Double Fault",
    "Coprocessor Seg Ovr",   "Invalid TSS",          "Segment Not Present",
    "Stack-Segment Fault",   "General Protection",   "Page Fault",
    "Reserved",              "x87 FP Exception",     "Alignment Check",
    "Machine Check",         "SIMD FP Exception",    "Virtualisation",
    "Control Protection",    "Reserved",             "Reserved",
    "Reserved",              "Reserved",             "Reserved",
    "Reserved",              "Reserved",             "Reserved",
    "Reserved",              "Reserved",
};

static struct {
    irq_handler_t fn;
    void         *cookie;
} irq_handlers[16];

/* ─── Public IRQ registration ─────────────────────────────────────────── */

int irq_register_handler(uint32_t irq, irq_handler_t fn, void *cookie) {
    if (irq >= 16) return -1;
    irq_handlers[irq].fn     = fn;
    irq_handlers[irq].cookie = cookie;
    return 0;
}

int irq_unregister_handler(uint32_t irq) {
    if (irq >= 16) return -1;
    irq_handlers[irq].fn     = NULL;
    irq_handlers[irq].cookie = NULL;
    return 0;
}

/* ─── Called from isr_common (assembly) ──────────────────────────────── */

void do_exception(struct regs *r) {
    const char *name = (r->int_no < 32) ? exc_names[r->int_no] : "Unknown";
    log_message(LOG_FATAL,
                "EXCEPTION %u (%s) err=0x%x eip=0x%x cs=0x%x\n",
                (unsigned int)r->int_no, name,
                (unsigned int)r->err_code,
                (unsigned int)r->eip,
                (unsigned int)r->cs);
    cpu_halt();
}

/* ─── Called from irq_common (assembly) ──────────────────────────────── */

static int is_spurious_irq7(void) {
    /* Read In-Service Register; if bit 7 clear the IRQ was spurious */
    outb(0x20, 0x0B);
    return !(inb(0x20) & 0x80);
}

static int is_spurious_irq15(void) {
    outb(0xA0, 0x0B);
    return !(inb(0xA0) & 0x80);
}

void do_irq(struct regs *r) {
    uint32_t irq = r->int_no;

    /* Spurious IRQ7: PIC raised it without a real request — no EOI */
    if (irq == 7 && is_spurious_irq7()) return;

    /* Spurious IRQ15: EOI master only, not slave */
    if (irq == 15 && is_spurious_irq15()) {
        outb(0x20, 0x20);
        return;
    }

    if (irq < 16 && irq_handlers[irq].fn)
        irq_handlers[irq].fn(irq, irq_handlers[irq].cookie);

    irq_eoi(irq);
}
