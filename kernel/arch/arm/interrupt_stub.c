/* ARM HAL is now split across kernel/arch/arm/vic.c (PL190 + spl* stubs)
 * and kernel/arch/arm/timer.c (SP804 + hw_get_jiffies). This file is
 * intentionally empty — kept so the Makefile's existing reference
 * doesn't need a coordinated removal until the next cleanup pass. */
