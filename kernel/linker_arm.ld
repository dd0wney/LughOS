OUTPUT_FORMAT("elf32-littlearm")
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);    /* R-X */
    rodata PT_LOAD FLAGS(4);  /* R-- */
    data PT_LOAD FLAGS(6);    /* RW- */
    bss PT_LOAD FLAGS(6);     /* RW- */
}

SECTIONS {
    /* Start at 0x10000 for ARM kernel */
    . = 0x10000;
    PROVIDE(_kernel_start = .);

    .text : {
        PROVIDE(_text_start = .);
        *(.text)
        *(.text.*)
        PROVIDE(_text_end = .);
    } :text

    .rodata : {
        PROVIDE(_rodata_start = .);
        *(.rodata)
        *(.rodata.*)
        PROVIDE(_rodata_end = .);
    } :rodata

    .data : {
        PROVIDE(_data_start = .);
        *(.data)
        *(.data.*)
        PROVIDE(_data_end = .);
    } :data

    .bss : {
        PROVIDE(_bss_start = .);
        *(COMMON)
        *(.bss)
        *(.bss.*)
        PROVIDE(_bss_end = .);
    } :bss

    PROVIDE(_kernel_end = .);
}