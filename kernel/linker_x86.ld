/* filepath: /home/ddowney/Workspace/github.com/LughOS/kernel/linker_x86.ld */
OUTPUT_FORMAT("elf32-i386")
ENTRY(_start)

SECTIONS {
    /* Begin at 1MB - standard location for kernels to be loaded by GRUB */
    . = 1M;
    PROVIDE(_kernel_start = .);

    /* First put the multiboot header, as it needs to be within the first 8KB */
    /* The *.* wildcards are required, not decorative: COMMON_CFLAGS sets
     * -ffunction-sections -fdata-sections, so the compiler emits
     * .text.foo / .bss.bar rather than one .text / .bss. Without them
     * those become orphan sections that the linker places wherever it
     * likes — after _bss_end, in practice — which put 64 KB of BSS
     * outside the region the security validator derives from these
     * symbols. */
    .text BLOCK(4K) : ALIGN(4K) {
        PROVIDE(_text_start = .);
        *(.multiboot)
        *(.text)
        *(.text.*)
        PROVIDE(_text_end = .);
    }

    /* Read-only data */
    .rodata BLOCK(4K) : ALIGN(4K) {
        PROVIDE(_rodata_start = .);
        *(.rodata)
        *(.rodata.*)
        PROVIDE(_rodata_end = .);
    }

    /* Read-write data (initialized) */
    .data BLOCK(4K) : ALIGN(4K) {
        PROVIDE(_data_start = .);
        *(.data)
        *(.data.*)
        PROVIDE(_data_end = .);
    }

    /* Read-write data (uninitialized) and stack */
    .bss BLOCK(4K) : ALIGN(4K) {
        PROVIDE(_bss_start = .);
        *(COMMON)
        *(.bss)
        *(.bss.*)
        *(.bootstrap_stack)
        PROVIDE(_bss_end = .);
    }

    PROVIDE(_kernel_end = .);

    /* The compiler may produce other sections, put them in the proper place in
       in this file, if needed */
}