/* ARM exception entry stubs.
 *
 * IRQ has a real save/restore/dispatch path. Everything else is a panic
 * stub that writes a single-letter code to PL011 UART0 (`EXC:X\n`) and
 * busy-loops. The panic path does direct MMIO with no function calls —
 * advisor caveat: a panic that re-enters the broken layer (log_message →
 * serial_write → fault) gives you nothing.
 *
 * Codes:
 *   U = Undefined instruction
 *   S = SVC / SWI (placeholder until init_syscall_arm wires a real path)
 *   P = Prefetch abort
 *   D = Data abort
 *   R = Reserved (vector 0x14)
 *   F = FIQ
 */

.section .text

#define PL011_DR 0x101F1000      @ UART0 data register on versatilepb

@ ── Panic stubs ───────────────────────────────────────────────────
.global arm_undef_panic
arm_undef_panic:
    mov r0, #'U'
    b   _arm_panic_print

.global arm_svc_panic
arm_svc_panic:
    mov r0, #'S'
    b   _arm_panic_print

@ Prefetch abort — capture fault PC + SPSR, dump via C helper, then loop.
@ Phase 4 F2 instrumentation: the EXC:P from the user_hello regression
@ now arrives with diagnostic info (faulting VA + pre-fault CPSR) so the
@ Phase 4 F3 graceful handler has the data it needs to decide who to
@ terminate. On ARMv5 the faulting instruction's address is LR_abt - 4.
.global arm_pabort_panic
arm_pabort_panic:
    sub  r0, lr, #4                 @ r0 = faulting instruction VA
    mrs  r1, spsr                   @ r1 = SPSR_abt (pre-fault CPSR)
    @ Make sure we have a usable abort-mode stack for the bl below.
    @ boot_arm.S set ABT SP at 0xE0000 with 64 KB headroom.
    bl   arm_pabort_diagnose        @ C: dumps "PABORT: pc=... cpsr=..."
    mov  r0, #'P'
    b    _arm_panic_print

@ Data abort — same idea but the fault VA is in DFAR (Data Fault
@ Address Register, CP15 c6,c0,0) and the status in DFSR (c5,c0,0).
@ LR_abt for data abort points past the faulting instruction +8 (ARMv5),
@ so the load-pair format is slightly different. Telemetry emission
@ (AUDITOR_REC_FAULT) added in Phase 4 F3. A graceful handler is
@ deferred to a later phase.
.global arm_dabort_panic
arm_dabort_panic:
    sub  r0, lr, #8                 @ r0 = faulting instruction VA
    mrc  p15, 0, r1, c6, c0, 0      @ r1 = DFAR (data fault address)
    mrc  p15, 0, r2, c5, c0, 0      @ r2 = DFSR (data fault status)
    mrs  r3, spsr                   @ r3 = SPSR_abt (pre-fault CPSR)
    bl   arm_dabort_diagnose        @ C: dumps full diagnosis
    mov  r0, #'D'
    b    _arm_panic_print

.global arm_reserved_panic
arm_reserved_panic:
    mov r0, #'R'
    b   _arm_panic_print

.global arm_fiq_panic
arm_fiq_panic:
    mov r0, #'F'
    b   _arm_panic_print

_arm_panic_print:
    @ Print "EXC:<code>\n" to PL011 UART0. 32-bit writes; the low byte
    @ goes to the FIFO. No FR.TXFF check — if bytes are dropped, fine.
    ldr r1, =PL011_DR
    mov r2, #'E'
    str r2, [r1]
    mov r2, #'X'
    str r2, [r1]
    mov r2, #'C'
    str r2, [r1]
    mov r2, #':'
    str r2, [r1]
    str r0, [r1]                 @ the single-letter code
    mov r2, #'\n'
    str r2, [r1]
1:  b   1b                       @ hang loudly

@ ── IRQ entry ─────────────────────────────────────────────────────
@ On IRQ entry the CPU saves CPSR→SPSR_irq, switches to IRQ mode with
@ I=1 (IRQs masked), and sets LR_irq = address-of-interrupted-instr + 4.
@ ARM convention requires the handler to subtract 4 before returning.
@
@ We save AAPCS volatile registers and the SPSR, then call into the
@ C dispatcher in vic.c. On return, restore SPSR + regs and pop into PC
@ with the `^` modifier — that atomically restores CPSR from SPSR.
.global arm_irq_entry
arm_irq_entry:
    sub   lr, lr, #4                  @ adjust IRQ return address
    stmfd sp!, {r0-r3, r12, lr}       @ save AAPCS volatile regs + LR
    mrs   r0, spsr                    @ save SPSR (interrupted CPSR)
    stmfd sp!, {r0}
    bl    arm_irq_dispatch            @ C dispatcher in vic.c
    ldmfd sp!, {r0}
    msr   spsr_cxsf, r0               @ restore SPSR
    ldmfd sp!, {r0-r3, r12, pc}^      @ ^ restores CPSR from SPSR
