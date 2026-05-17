/* 
 * x86 user mode entry trampoline for LughOS
 * Switches from kernel (ring 0) to user mode (ring 3) using iret
 * Arguments (stack-based):
 *   [esp+4]  = user_eip (user entry point, must be valid)
 *   [esp+8]  = user_esp (user stack pointer, must be valid)
 * Assumes GDT selectors:
 *   0x18 = user code segment (ring 3)
 *   0x20 = user data segment (ring 3)
 * Caller must validate arguments (SEI CERT EXP34-C, JPL Rule 15)
 */

    .section .text
    .global enter_user_mode
    .type enter_user_mode, @function

enter_user_mode:
    /* Load arguments — preserve user_esp in %eax before %ax is clobbered */
    mov 4(%esp), %edx        /* user_eip */
    mov 8(%esp), %eax        /* user_esp */

    /* Set user data segment selectors.
     * Use %cx (not %ax) so %eax (user_esp) is not clobbered.
     * Selectors need RPL=3 (bits [1:0]) so ring-0 segment loads succeed
     * and the post-IRET CPL=3 check on DS/ES/FS/GS passes. */
    mov $0x23, %cx           /* 0x20 | RPL=3 = user data selector */
    mov %cx, %ds
    mov %cx, %es
    mov %cx, %fs
    mov %cx, %gs

    /* Set up iret stack frame (JPL Rule 1: predictable execution).
     * CS and SS selectors must carry RPL=3 so IRET recognises this as
     * a privilege-level change from ring 0 → ring 3. */
    pushl $0x23              /* SS:  0x20 | RPL=3 */
    pushl %eax               /* ESP: user stack pointer (preserved above) */
    pushfl                   /* EFLAGS */
    popl %ecx                /* Modify EFLAGS */
    or $0x200, %ecx          /* Enable interrupts (IF=1) */
    pushl %ecx               /* Push modified EFLAGS */
    pushl $0x1B              /* CS:  0x18 | RPL=3 = user code selector */
    pushl %edx               /* EIP: user entry point */

    /* Transition to user mode (ring 3) */
    iret                     /* No instructions after iret (SEI CERT MSC15-C) */
