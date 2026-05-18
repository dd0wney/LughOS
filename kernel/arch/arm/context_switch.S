/* ARM kernel-mode context switch for LughOS (Phase 3 A4).
 *
 *   void arm_context_switch(task_t* prev, task_t* next)
 *     r0 = prev, r1 = next
 *
 * Saves the callee-saved registers (r4-r11) and LR onto prev's kernel
 * stack, writes the resulting SP into prev->saved_sp, loads next->saved_sp
 * into SP, restores next's callee-saved regs + LR, and `bx lr` returns.
 * To the C caller, the call to arm_context_switch APPEARS to return —
 * but in next's execution context. This is the standard co-routine /
 * kernel context switch pattern.
 *
 * Caller must mask IRQs (set CPSR.I) around the call so the swap is
 * atomic against a timer tick that would otherwise re-enter the
 * scheduler. The current_task swap happens here, between the save and
 * load, so any state-change observation between the two register sets
 * cannot reach inconsistent task identity.
 *
 * task_t field offsets must match include/lugh.h:
 *   offset 0   task_id              (uint32_t)
 *   offset 4   priority             (int)
 *   offset 8   cap_mask             (uint32_t)
 *   offset 12  domain               (uint32_t)
 *   offset 16  state                (uint64_t)
 *   offset 24  deadline             (uint64_t)
 *   offset 32  kernel_stack_top     (uint32_t)
 *   offset 36  saved_sp             (uint32_t)   <-- the anchor
 */

.section .text
.global arm_context_switch
.type arm_context_switch, %function
.syntax unified
.arm

#define TASK_SAVED_SP_OFFSET 36

.extern current_task

arm_context_switch:
    @ Push callee-saved regs on prev's current SVC stack. AAPCS says
    @ r4-r11 must be preserved across calls; LR is the return address
    @ to the C caller of arm_context_switch.
    push  {r4-r11, lr}

    @ Save SP into prev->saved_sp
    str   sp, [r0, #TASK_SAVED_SP_OFFSET]

    @ Update current_task = next (the swap point — done with IRQs masked
    @ per the caller's contract).
    ldr   r2, =current_task
    str   r1, [r2]

    @ Switch SP to next's saved stack
    ldr   sp, [r1, #TASK_SAVED_SP_OFFSET]

    @ Restore next's callee-saved regs and LR
    pop   {r4-r11, lr}

    @ Return into next's context — the bx lr here lands at wherever
    @ arm_context_switch was originally called *from* in next's history.
    bx    lr
