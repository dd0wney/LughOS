/* x86 (i686) kernel-mode context switch for LughOS (Phase 3 A4).
 *
 *   void x86_context_switch(task_t* prev, task_t* next)
 *     cdecl: arg0 (prev) at [esp+4], arg1 (next) at [esp+8]
 *
 * Saves callee-saved regs (ebx, esi, edi, ebp) onto prev's kernel stack,
 * writes the resulting ESP into prev->saved_sp, loads next->saved_sp into
 * ESP, restores next's callee-saved regs, and `ret` returns. Standard
 * kernel context switch — the call appears to return in next's context.
 *
 * Caller masks IRQs (cli) around the call so the swap is atomic against
 * a PIT tick that would re-enter the scheduler. The current_task swap
 * happens inside, between save and load.
 *
 * task_t layout matches include/lugh.h — saved_sp at offset 36.
 */

.section .text
.global x86_context_switch
.type x86_context_switch, @function

#define TASK_SAVED_SP_OFFSET 36

.extern current_task

x86_context_switch:
    /* Read args via cdecl */
    movl  4(%esp), %eax        /* eax = prev */
    movl  8(%esp), %edx        /* edx = next */

    /* Push callee-saved registers (i386 cdecl: ebx, esi, edi, ebp) */
    pushl %ebx
    pushl %esi
    pushl %edi
    pushl %ebp

    /* Save current ESP into prev->saved_sp */
    movl  %esp, TASK_SAVED_SP_OFFSET(%eax)

    /* Update current_task = next */
    movl  %edx, current_task

    /* Switch ESP to next's saved stack */
    movl  TASK_SAVED_SP_OFFSET(%edx), %esp

    /* Restore next's callee-saved regs (reverse order) */
    popl  %ebp
    popl  %edi
    popl  %esi
    popl  %ebx

    /* Return into next's context */
    ret
