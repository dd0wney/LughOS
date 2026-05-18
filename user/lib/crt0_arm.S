/* ARM crt0 for LughOS user programs.
 *
 * Reset entry: clear FP, set up empty argc/argv, call main, then exit
 * via SYS_EXIT (syscall number 3). The kernel parks the task in a
 * "while(1) cpu_idle()" loop after SYS_EXIT today, so we should never
 * actually return; the trailing branch is defensive.
 *
 * Was previously assembled as Thumb (`.thumb`) which crashed
 * immediately on entry from the kernel's ARM-mode jump.
 */

.section .text
.global _start
.type _start, %function
.syntax unified
.arm

_start:
    mov r7, #0              @ clear frame pointer
    mov r0, #0              @ argc = 0
    mov r1, #0              @ argv = NULL
    bl  main
    @ main returned — exit with its return code.
    mov r1, r0              @ arg1 = exit code
    mov r2, #0
    mov r3, #0
    mov r0, #3              @ SYS_EXIT
    bl  syscall
    @ Should never reach here; busy-loop as a safety net. `wfi` isn't
    @ available on ARMv5 baseline so we don't use it.
1:  b   1b
