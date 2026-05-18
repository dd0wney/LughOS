#include "lugh.h"
#include "interrupt.h"

/* Remaining ARM HAL stub. Everything else moved out:
 *   irq_*, spl*  → kernel/arch/arm/vic.c (PL190 driver + IPL stubs)
 *   hw_get_jiffies will move to kernel/arch/arm/timer.c when SP804 lands.
 *
 * Until then, jiffies is 0 — log_message timestamps stay at [00000000]
 * and DENY records get jiffies=0. Real timestamps arrive with the timer. */

uint64_t hw_get_jiffies(void) { return 0; }
