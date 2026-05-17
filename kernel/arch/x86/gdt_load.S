/* gdt_flush - Load the GDT and reload all segment registers.
 *
 * void gdt_flush(struct gdt_ptr *ptr);
 *
 * Called from C with cdecl: arg at 4(%esp) after the return address.
 * After lgdt, a far-jump flushes the instruction pipeline and reloads CS
 * with the new kernel code selector (0x08).
 */
    .section .text
    .global gdt_flush
    .type gdt_flush, @function

gdt_flush:
    movl 4(%esp), %eax      /* arg0: pointer to gdt_ptr struct */
    lgdt (%eax)             /* load global descriptor table */

    /* Reload data segment registers with kernel data selector 0x10 */
    movl $0x10, %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Far-jump to flush CS with kernel code selector 0x08 */
    ljmp $0x08, $.flush
.flush:
    ret

    .size gdt_flush, . - gdt_flush
