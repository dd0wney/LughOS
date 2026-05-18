/* ARM SVC vector entry for LughOS.
 *
 * Called from the vector table at 0x00000008 (SVC vector) when user
 * code does `svc #0`. On entry:
 *   - CPSR has been saved to SPSR_svc (the user's CPSR).
 *   - Mode is SVC, I=1 (IRQs masked by SVC entry), F unchanged.
 *   - LR_svc = user PC + 4 (address of the instruction after `svc`).
 *   - User registers r0..r2 hold arg1..arg3; r7 holds syscall number
 *     (matches the user trampoline in user/lib/syscall_arm.S).
 *
 * We call into the C handler `syscall_handler(num, arg1, arg2, arg3)`
 * and return to user mode via `movs pc, lr` (PC←LR_svc, CPSR←SPSR_svc).
 * The previous version used `bx lr` which is a regular function
 * return — it would have jumped to the user PC while keeping CPSR in
 * SVC mode (privileged), defeating the user/kernel boundary.
 *
 * Also previously assembled as Thumb (`.thumb`); now ARM mode.
 */

.section .text
.global syscall_entry
.type syscall_entry, %function
.syntax unified
.arm

syscall_entry:
    push {r4-r11, lr}        @ save callee-saved + LR_svc (user return address)

    @ Shuffle args from (r7=num, r0..r2=args) → (r0=num, r1..r3=args).
    @ Move r2→r3 first so we don't clobber an arg before reading it.
    mov  r3, r2
    mov  r2, r1
    mov  r1, r0
    mov  r0, r7

    bl   syscall_handler

    pop  {r4-r11, lr}        @ restore + LR_svc
    movs pc, lr              @ exception return: PC←lr, CPSR←SPSR_svc

/* Dead-code trampoline: kernel doesn't make syscalls into itself. Kept
 * for compatibility with the build until a cleanup pass removes it. */
.global syscall
.type syscall, %function
syscall:
    push {r4-r7, lr}
    mov  r7, r0
    mov  r0, r1
    mov  r1, r2
    mov  r2, r3
    svc  #0
    pop  {r4-r7, pc}
