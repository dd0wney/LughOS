#include "lugh.h"
#include "interrupt.h"

/* 8259 PIC port addresses */
#define PIC1_CMD  0x20
#define PIC1_DATA 0x21
#define PIC2_CMD  0xA0
#define PIC2_DATA 0xA1
#define PIC_EOI   0x20  /* End-of-interrupt command */

/* Short I/O delay for old hardware compatibility: write to an unused port */
static void io_wait(void) { outb(0x80, 0); }

/* ─── IPL state ──────────────────────────────────────────────────────── */
/*
 * enabled_mask: bit-per-IRQ mask of which IRQs software has enabled.
 *   Bit=1 means masked, bit=0 means enabled.
 *   Initial value after pic_remap(): all masked except cascade (IRQ2=bit2).
 *
 * ipl_mask: additional masking imposed by the current IPL level.
 *   IPL_HIGH = 0xFFFF (everything masked), IPL_NONE = 0x0000.
 *   Starts at 0xFFFF (boot is implicitly IPL_HIGH).
 *
 * Hardware mask written to the PICs = enabled_mask | ipl_mask.
 */
static uint16_t enabled_mask = 0xFFFB;  /* all masked except IRQ2 cascade */
static uint16_t ipl_mask     = 0xFFFF;  /* boot: IPL_HIGH                 */

/* ipl_to_mask[level] = bitmask of IRQs to additionally block at that IPL */
static const uint16_t ipl_to_mask[] = {
    [IPL_NONE]  = 0x0000,   /* no extra masking                            */
    [IPL_TTY]   = 0x00F0,   /* mask IRQ4-7 (serial COM2/COM1, ...)         */
    [IPL_CLOCK] = 0xFFFE,   /* mask all except IRQ0 (PIT timer)            */
    [IPL_HIGH]  = 0xFFFF,   /* mask everything                             */
};

static void apply_mask(void) {
    uint16_t m = enabled_mask | ipl_mask;
    outb(PIC1_DATA, (uint8_t)(m & 0xFF));
    outb(PIC2_DATA, (uint8_t)(m >> 8));
}

/* ─── IPL public API ─────────────────────────────────────────────────── */

spl_t splraise(uint32_t ipl) {
    uint32_t flags;
    __asm__ volatile("pushfl; popl %0; cli" : "=r"(flags));

    spl_t old = ipl_mask;
    if (ipl < 4) {
        uint16_t want = ipl_to_mask[ipl];
        if (want > ipl_mask) {   /* only raise, never lower */
            ipl_mask = want;
            apply_mask();
        }
    }

    if (flags & 0x200) __asm__ volatile("sti");
    return old;
}

void splx(spl_t prev) {
    uint32_t flags;
    __asm__ volatile("pushfl; popl %0; cli" : "=r"(flags));
    ipl_mask = prev;
    apply_mask();
    if (flags & 0x200) __asm__ volatile("sti");
}

spl_t splhigh(void)  { return splraise(IPL_HIGH);  }
spl_t splclock(void) { return splraise(IPL_CLOCK); }

spl_t spl0(void) {
    uint32_t flags;
    __asm__ volatile("pushfl; popl %0; cli" : "=r"(flags));
    spl_t old = ipl_mask;
    ipl_mask  = ipl_to_mask[IPL_NONE];
    apply_mask();
    if (flags & 0x200) __asm__ volatile("sti");
    return old;
}

/* ─── PIC initialisation ─────────────────────────────────────────────── */

void pic_remap(void) {
    /* Save existing masks (ICW1 resets the PIC state, masks will be re-applied) */

    outb(PIC1_CMD, 0x11); io_wait();  /* ICW1: init + ICW4 expected        */
    outb(PIC2_CMD, 0x11); io_wait();

    outb(PIC1_DATA, 0x20); io_wait(); /* ICW2 master: vectors 0x20-0x27    */
    outb(PIC2_DATA, 0x28); io_wait(); /* ICW2 slave:  vectors 0x28-0x2F    */

    outb(PIC1_DATA, 0x04); io_wait(); /* ICW3 master: slave on IRQ2 (bit2) */
    outb(PIC2_DATA, 0x02); io_wait(); /* ICW3 slave:  cascade identity = 2 */

    outb(PIC1_DATA, 0x01); io_wait(); /* ICW4: 8086 mode                   */
    outb(PIC2_DATA, 0x01); io_wait();

    /* Apply current enabled_mask | ipl_mask so everything stays masked     */
    apply_mask();

    log_message(LOG_INFO, "PIC remapped: master 0x20-0x27, slave 0x28-0x2F\n");
}

void pic_unmask(uint8_t irq) {
    if (irq >= 16) return;
    enabled_mask &= (uint16_t)~(1u << irq);
    apply_mask();
}

/* ─── EOI ────────────────────────────────────────────────────────────── */

void irq_eoi(uint32_t irq) {
    /* Slave IRQs (8-15) need EOI to both slave and master */
    if (irq >= 8)
        outb(PIC2_CMD, PIC_EOI);
    outb(PIC1_CMD, PIC_EOI);
}
