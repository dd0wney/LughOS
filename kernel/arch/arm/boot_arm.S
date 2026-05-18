/* ARMv5TE boot stub for QEMU `versatilepb` (ARM926EJ-S).
 *
 * What this does, in order:
 *   1. Establish per-mode stacks (SVC, IRQ, ABT, UND) — each ARM mode has
 *      its own banked SP, and an exception entered without a valid SP for
 *      that mode is fatal in a way that's hard to debug.
 *   2. Install the exception vector table at address 0x00000000.
 *      ARMv5 expects the vectors there (low-vector mode, SCTLR.V=0); we
 *      explicitly clear V at boot so we don't inherit a stale state from
 *      the bootloader/firmware.
 *   3. Branch to kmain in SVC mode with IRQs+FIQs still masked. The C
 *      side enables IRQs after the VIC and timer are set up.
 *
 * The vector table uses `ldr pc, [pc, #24]` instructions that load
 * absolute handler addresses from a 32-byte literal pool placed
 * immediately after the 8 instructions. When the table is copied to
 * 0x00000000, the addresses in the literal pool stay correct because
 * they were resolved at link time (the handlers don't move).
 */

.section .text.boot
.global _start

@ ── CPSR values with IRQs+FIQs masked (I=1, F=1) ───────────────────
@ Layout: [I=0x80][F=0x40][T=0x20][MODE bits, 5]
@ The assembler doesn't accept `#(X|Y|Z)` immediates, so precompute.
#define CPSR_SVC_OFF 0xD3        @ 0x13 | 0x80 | 0x40
#define CPSR_IRQ_OFF 0xD2        @ 0x12 | 0x80 | 0x40
#define CPSR_ABT_OFF 0xD7        @ 0x17 | 0x80 | 0x40
#define CPSR_UND_OFF 0xDB        @ 0x1B | 0x80 | 0x40

@ ── Stack tops (grow down). Each gets 64 KB. ───────────────────────
@ Region layout:
@   0xC0000–0xD0000  UND stack
@   0xD0000–0xE0000  ABT stack
@   0xE0000–0xF0000  IRQ stack
@   0xF0000–0x100000 SVC stack (also pre-init stack; matches old code)
@ The kernel binary loads at 0x10000 and ends well below 0xC0000.
#define STACK_SVC_TOP 0x100000
#define STACK_IRQ_TOP 0x0F0000
#define STACK_ABT_TOP 0x0E0000
#define STACK_UND_TOP 0x0D0000

_start:
    @ ── Stage 1: clear SCTLR.V so vectors live at 0x00000000 ──────
    @ Reading SCTLR via CP15, clear bit 13 (V), write back.
    mrc p15, 0, r0, c1, c0, 0
    bic r0, r0, #(1 << 13)
    mcr p15, 0, r0, c1, c0, 0

    @ ── Stage 2: set up SVC stack (current mode) ──────────────────
    ldr sp, =STACK_SVC_TOP

    @ ── Stage 3: set up IRQ-mode stack ────────────────────────────
    msr cpsr_c, #CPSR_IRQ_OFF
    ldr sp, =STACK_IRQ_TOP

    @ ── Stage 4: set up ABT-mode stack ────────────────────────────
    msr cpsr_c, #CPSR_ABT_OFF
    ldr sp, =STACK_ABT_TOP

    @ ── Stage 5: set up UND-mode stack ────────────────────────────
    msr cpsr_c, #CPSR_UND_OFF
    ldr sp, =STACK_UND_TOP

    @ ── Stage 6: return to SVC, IRQs+FIQs still masked ────────────
    msr cpsr_c, #CPSR_SVC_OFF

    @ ── Stage 7: copy 64 bytes of vector table to 0x00000000 ──────
    @ 8 instructions + 8 literal-pool words = 64 bytes.
    ldr r0, =_vectors_start
    mov r1, #0
    ldr r2, =_vectors_end
1:  ldr r3, [r0], #4
    str r3, [r1], #4
    cmp r0, r2
    bne 1b

    @ ── Stage 8: hand off to C. IRQs still masked. ────────────────
    bl  kmain
    b   .                        @ kmain doesn't return; safety net

@ ── Exception vector table ────────────────────────────────────────
@ Each entry is `ldr pc, [pc, #24]`. PC at execution = instruction addr + 8
@ (ARM pipeline), so [pc, #24] = instruction addr + 32 = start of literal
@ pool below. Layout is identical whether running here or after the copy
@ to 0x00000000 because the offset is PC-relative.
.balign 32
_vectors_start:
    ldr pc, [pc, #24]            @ 0x00 reset           -> _reset_loop
    ldr pc, [pc, #24]            @ 0x04 undef inst      -> arm_undef_panic
    ldr pc, [pc, #24]            @ 0x08 SVC / SWI       -> arm_svc_panic (TODO: real)
    ldr pc, [pc, #24]            @ 0x0C prefetch abort  -> arm_pabort_panic
    ldr pc, [pc, #24]            @ 0x10 data abort      -> arm_dabort_panic
    ldr pc, [pc, #24]            @ 0x14 reserved        -> arm_reserved_panic
    ldr pc, [pc, #24]            @ 0x18 IRQ             -> arm_irq_entry
    ldr pc, [pc, #24]            @ 0x1C FIQ             -> arm_fiq_panic
    @ Literal pool: absolute handler addresses (resolved at link time).
    .word _reset_loop
    .word arm_undef_panic
    .word arm_svc_panic
    .word arm_pabort_panic
    .word arm_dabort_panic
    .word arm_reserved_panic
    .word arm_irq_entry
    .word arm_fiq_panic
_vectors_end:

@ ── Reset handler ─────────────────────────────────────────────────
@ Should never fire after boot. If it does, hang loudly.
_reset_loop:
    b   _reset_loop
