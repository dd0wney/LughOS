/* isr_stubs.S — ISR/IRQ stubs and common dispatchers for x86 LughOS.
 *
 * Each stub pushes a uniform (int_no, err_code) pair onto the stack so that
 * the common C handler receives a single `struct regs *` argument.
 *
 * Vectors with CPU-pushed error codes (Intel SDM Vol 3A §6.13):
 *   8 (DF), 10 (TS), 11 (NP), 12 (SS), 13 (GP), 14 (PF), 17 (AC), 21 (CP)
 * All others: stub pushes a dummy $0 so the layout is always uniform.
 */

    .section .text

/* ─── Macros ──────────────────────────────────────────────────────────── */

/* Exception WITHOUT a CPU-pushed error code */
.macro ISR_NOERR num
    .global isr\num
    isr\num:
        cli
        pushl $0            /* dummy error code */
        pushl $\num         /* vector number    */
        jmp isr_common
.endm

/* Exception WITH a CPU-pushed error code */
.macro ISR_ERR num
    .global isr\num
    isr\num:
        cli
        pushl $\num         /* vector number (error code already on stack) */
        jmp isr_common
.endm

/* Hardware IRQ stub: logical irq number pushed as int_no */
.macro IRQ_STUB n
    .global irq\n
    irq\n:
        cli
        pushl $0            /* dummy error code */
        pushl $\n           /* logical IRQ (0-15) */
        jmp irq_common
.endm

/* ─── Exception stubs (0-31) ──────────────────────────────────────────── */

ISR_NOERR 0     /* #DE Divide-by-zero           */
ISR_NOERR 1     /* #DB Debug                    */
ISR_NOERR 2     /* NMI                          */
ISR_NOERR 3     /* #BP Breakpoint               */
ISR_NOERR 4     /* #OF Overflow                 */
ISR_NOERR 5     /* #BR Bound Range Exceeded     */
ISR_NOERR 6     /* #UD Invalid Opcode           */
ISR_NOERR 7     /* #NM Device Not Available     */
ISR_ERR   8     /* #DF Double Fault (err=0)     */
ISR_NOERR 9     /* Coprocessor Segment Overrun  */
ISR_ERR   10    /* #TS Invalid TSS              */
ISR_ERR   11    /* #NP Segment Not Present      */
ISR_ERR   12    /* #SS Stack-Segment Fault      */
ISR_ERR   13    /* #GP General Protection       */
ISR_ERR   14    /* #PF Page Fault               */
ISR_NOERR 15    /* Reserved                     */
ISR_NOERR 16    /* #MF x87 FP Exception         */
ISR_ERR   17    /* #AC Alignment Check          */
ISR_NOERR 18    /* #MC Machine Check            */
ISR_NOERR 19    /* #XM/#XF SIMD FP Exception    */
ISR_NOERR 20    /* #VE Virtualisation           */
ISR_ERR   21    /* #CP Control Protection       */
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_NOERR 30
ISR_NOERR 31

/* ─── IRQ stubs (logical 0-15, mapped to vectors 0x20-0x2F) ──────────── */

IRQ_STUB 0
IRQ_STUB 1
IRQ_STUB 2
IRQ_STUB 3
IRQ_STUB 4
IRQ_STUB 5
IRQ_STUB 6
IRQ_STUB 7
IRQ_STUB 8
IRQ_STUB 9
IRQ_STUB 10
IRQ_STUB 11
IRQ_STUB 12
IRQ_STUB 13
IRQ_STUB 14
IRQ_STUB 15

/* ─── Common exception dispatcher ────────────────────────────────────── */
/*
 * Stack on entry (low → high):
 *   int_no, err_code, eip, cs, eflags  (no ss/esp: ring-0 kernel exception)
 *
 * After pusha + segment pushes, struct regs layout at %esp:
 *   gs, fs, es, ds, edi, esi, ebp, esp_d, ebx, edx, ecx, eax,
 *   int_no, err_code, eip, cs, eflags
 */
isr_common:
    pusha

    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs

    movl $0x10, %eax        /* kernel data selector */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    pushl %esp              /* arg0: struct regs * */
    call do_exception       /* never returns — calls cpu_halt() */
    addl $4, %esp           /* unreachable; keeps stack accounting correct */

    popl %gs
    popl %fs
    popl %es
    popl %ds
    popa
    addl $8, %esp           /* discard int_no and err_code */
    iret

/* ─── Common IRQ dispatcher ──────────────────────────────────────────── */

irq_common:
    pusha

    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs

    movl $0x10, %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    pushl %esp              /* arg0: struct regs * */
    call do_irq
    addl $4, %esp

    popl %gs
    popl %fs
    popl %es
    popl %ds
    popa
    addl $8, %esp
    iret
