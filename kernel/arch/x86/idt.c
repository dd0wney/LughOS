#include "lugh.h"
#include "interrupt.h"

struct idt_entry {
    uint16_t base_lo;
    uint16_t sel;
    uint8_t  always0;
    uint8_t  flags;
    uint16_t base_hi;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

static struct idt_entry idt_entries[256] __attribute__((aligned(8)));
static struct idt_ptr   idt_ptr;

/* One declaration per ISR/IRQ stub defined in isr.S */
extern void isr0(void);  extern void isr1(void);  extern void isr2(void);
extern void isr3(void);  extern void isr4(void);  extern void isr5(void);
extern void isr6(void);  extern void isr7(void);  extern void isr8(void);
extern void isr9(void);  extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); extern void isr14(void);
extern void isr15(void); extern void isr16(void); extern void isr17(void);
extern void isr18(void); extern void isr19(void); extern void isr20(void);
extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void);
extern void isr27(void); extern void isr28(void); extern void isr29(void);
extern void isr30(void); extern void isr31(void);

extern void irq0(void);  extern void irq1(void);  extern void irq2(void);
extern void irq3(void);  extern void irq4(void);  extern void irq5(void);
extern void irq6(void);  extern void irq7(void);  extern void irq8(void);
extern void irq9(void);  extern void irq10(void); extern void irq11(void);
extern void irq12(void); extern void irq13(void); extern void irq14(void);
extern void irq15(void);

extern void syscall_entry(void);

void idt_set_gate(uint8_t num, uint32_t base, uint16_t sel, uint8_t flags) {
    idt_entries[num].base_lo = (uint16_t)(base & 0xFFFF);
    idt_entries[num].base_hi = (uint16_t)((base >> 16) & 0xFFFF);
    idt_entries[num].sel     = sel;
    idt_entries[num].always0 = 0;
    idt_entries[num].flags   = flags;
}

void idt_init(void) {
    idt_ptr.limit = (uint16_t)(sizeof(idt_entries) - 1);
    idt_ptr.base  = (uint32_t)&idt_entries;

    memset(&idt_entries, 0, sizeof(idt_entries));

    /* CPU exceptions (vectors 0-31): kernel-only interrupt gates (0x8E) */
#define ISR(n) idt_set_gate(n, (uint32_t)isr##n, 0x08, 0x8E)
    ISR(0);  ISR(1);  ISR(2);  ISR(3);  ISR(4);  ISR(5);  ISR(6);  ISR(7);
    ISR(8);  ISR(9);  ISR(10); ISR(11); ISR(12); ISR(13); ISR(14); ISR(15);
    ISR(16); ISR(17); ISR(18); ISR(19); ISR(20); ISR(21); ISR(22); ISR(23);
    ISR(24); ISR(25); ISR(26); ISR(27); ISR(28); ISR(29); ISR(30); ISR(31);
#undef ISR

    /* Hardware IRQs (vectors 0x20-0x2F): kernel-only interrupt gates */
#define IRQ(n) idt_set_gate(0x20 + (n), (uint32_t)irq##n, 0x08, 0x8E)
    IRQ(0);  IRQ(1);  IRQ(2);  IRQ(3);  IRQ(4);  IRQ(5);  IRQ(6);  IRQ(7);
    IRQ(8);  IRQ(9);  IRQ(10); IRQ(11); IRQ(12); IRQ(13); IRQ(14); IRQ(15);
#undef IRQ

    /* Syscall (vector 0x80): DPL=3 so user code can invoke via int $0x80
     * flags: 0xEE = Present(0x80) | DPL=3(0x60) | 32-bit interrupt gate(0x0E) */
    idt_set_gate(0x80, (uint32_t)syscall_entry, 0x08, 0xEE);

    __asm__ volatile("lidt (%0)" : : "r"(&idt_ptr));
    log_message(LOG_INFO, "IDT installed (%u entries)\n", 256u);
}
