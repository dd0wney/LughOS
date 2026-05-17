#include "lugh.h"
#include "interrupt.h"

/* ARM interrupt HAL stubs — implemented when ARM IRQ controller support lands */

int irq_register_handler(uint32_t irq, irq_handler_t fn, void *cookie) {
    (void)irq; (void)fn; (void)cookie;
    return -1;
}

int irq_unregister_handler(uint32_t irq) {
    (void)irq;
    return -1;
}

void     irq_eoi(uint32_t irq)       { (void)irq; }
spl_t    splraise(uint32_t ipl)      { (void)ipl; return 0; }
void     splx(spl_t prev)            { (void)prev; }
spl_t    splhigh(void)               { return 0; }
spl_t    splclock(void)              { return 0; }
spl_t    spl0(void)                  { return 0; }
uint64_t hw_get_jiffies(void)        { return 0; }
