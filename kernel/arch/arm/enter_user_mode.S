/* ARM user-mode entry trampoline for LughOS.
 *
 * Inputs (AAPCS):
 *   r0 = user entry PC
 *   r1 = user stack pointer
 *
 * Performs the SVC→USR transition using the standard exception-return
 * idiom on ARMv5TE:
 *   1. Set USR-mode banked SP via SYS mode (SYS shares USR's register
 *      file but is privileged, so MSR cpsr_c can switch into it).
 *   2. Set SPSR_svc to the target user CPSR (USR mode, IRQs+FIQs on,
 *      ARM mode).
 *   3. Set LR_svc to the user PC.
 *   4. `movs pc, lr` atomically performs PC←LR_svc and CPSR←SPSR_svc,
 *      dropping the CPU into USR mode at the user entry point.
 *
 * Previously this file was assembled as Thumb (`.thumb` directive) while
 * the rest of the kernel runs in ARM mode. The kernel's `bl` jumped to
 * Thumb bytes that the CPU executed as ARM instructions, which produced
 * an Undefined Instruction trap — the EXC:U the panic handler caught.
 */

.section .text
.global enter_user_mode
.type enter_user_mode, %function
.syntax unified
.arm

enter_user_mode:
    @ Mask IRQs+FIQs during the transition so we can't be preempted
    @ between setting the USR SP and the exception return.
    msr cpsr_c, #0xD3              @ SVC mode, I=1, F=1

    @ Set the USR-banked SP via SYS mode (SYS and USR share R13).
    msr cpsr_c, #0xDF              @ SYS mode, I=1, F=1
    mov sp, r1                     @ R13_usr ← user_esp
    msr cpsr_c, #0xD3              @ back to SVC mode

    @ SPSR_svc = target user CPSR: USR mode, ARM (T=0), IRQs+FIQs on.
    mov r2, #0x10                  @ mode=USR(0x10), I=0, F=0, T=0
    msr spsr_cxsf, r2

    @ LR_svc = user entry PC.
    mov lr, r0

    @ Exception return: PC←LR_svc, CPSR←SPSR_svc → drops to USR mode.
    movs pc, lr
