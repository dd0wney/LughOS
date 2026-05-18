/* ARM user-space syscall trampoline for LughOS.
 *
 * Convention (matching the kernel-side syscall_entry in
 * kernel/arch/arm/syscall.S):
 *   r0 = syscall number (on entry from C)
 *   r1 = arg1
 *   r2 = arg2
 *   r3 = arg3
 * After the shuffle below:
 *   r7 = syscall number   (kernel reads from here)
 *   r0 = arg1
 *   r1 = arg2
 *   r2 = arg3
 * Then `svc #0` traps into the kernel SVC vector.
 *
 * Was previously `.thumb` assembled, which would have crashed the user
 * program on first call. ARM mode now to match the rest of the build.
 */

.section .text
.global syscall
.type syscall, %function
.syntax unified
.arm

syscall:
    push {r4-r7, lr}
    mov  r7, r0              @ r7 = syscall number
    mov  r0, r1              @ r0 = arg1
    mov  r1, r2              @ r1 = arg2
    mov  r2, r3              @ r2 = arg3
    svc  #0
    pop  {r4-r7, pc}         @ r0 holds the kernel's return value
