#ifndef INTERRUPT_H
#define INTERRUPT_H

#include "lugh.h"

/* ─── Cross-arch IRQ registration ──────────────────────────────────────── */

typedef void (*irq_handler_t)(uint32_t irq, void *cookie);

int  irq_register_handler(uint32_t irq, irq_handler_t fn, void *cookie);
int  irq_unregister_handler(uint32_t irq);
void irq_eoi(uint32_t irq);

/* ─── OpenBSD-style IPL system ─────────────────────────────────────────── */
/*
 * spl_t is an opaque snapshot of the prior PIC mask, returned by splraise()
 * so that splx() can restore it.  Kernel code should use spl* exclusively;
 * cli/sti are used internally to make mask updates atomic.
 */
typedef uint16_t spl_t;

#define IPL_NONE   0   /* baseline: only enabled IRQs deliverable           */
#define IPL_TTY    1   /* mask serial/kbd IRQs (4-7) and below              */
#define IPL_CLOCK  2   /* mask all except IRQ0 (PIT timer)                  */
#define IPL_HIGH   3   /* mask everything (cli-equivalent, tracked in PIC)  */

spl_t splraise(uint32_t ipl);   /* raise IPL; return prior spl_t             */
void  splx(spl_t prev);         /* restore prior IPL (may lower)             */
spl_t splhigh(void);            /* shorthand: splraise(IPL_HIGH)             */
spl_t splclock(void);           /* shorthand: splraise(IPL_CLOCK)            */
spl_t spl0(void);               /* lower to IPL_NONE; return prior           */

/* ─── Timing ─────────────────────────────────────────────────────────────  */

uint64_t hw_get_jiffies(void);

/* ─── x86-specific subsystem init (guarded) ───────────────────────────── */
#ifdef __i386__
void gdt_init(void);
void idt_init(void);
void idt_set_gate(uint8_t num, uint32_t base, uint16_t sel, uint8_t flags);
void pic_remap(void);
void pic_unmask(uint8_t irq);
void pit_init(uint32_t hz);
#endif

#endif /* INTERRUPT_H */
