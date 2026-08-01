/* RISC-V Linker Script for LughOS */
OUTPUT_FORMAT("elf64-littleriscv", "elf64-littleriscv", "elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
	/* Start at 0x80100000 to avoid conflicting with OpenSBI firmware */
	. = 0x80100000;
	PROVIDE(_kernel_start = .);

	/* The *.* wildcards are required: COMMON_CFLAGS sets
	 * -ffunction-sections -fdata-sections, so without them the compiler's
	 * .text.foo / .bss.bar sections become orphans placed outside these
	 * output sections and outside the _bss_end boundary. */
	.text : ALIGN(4K)
	{
		PROVIDE(_text_start = .);
		*(.text.boot)
		*(.text)
		*(.text.*)
		PROVIDE(_text_end = .);
	}

	.rodata : ALIGN(4K)
	{
		PROVIDE(_rodata_start = .);
		*(.rodata)
		*(.rodata.*)
		PROVIDE(_rodata_end = .);
	}

	.data : ALIGN(4K)
	{
		PROVIDE(_data_start = .);
		*(.data)
		*(.data.*)
		PROVIDE(_data_end = .);
	}

	.bss : ALIGN(4K)
	{
		PROVIDE(__bss_start = .);
		PROVIDE(_bss_start = .);
		*(COMMON)
		*(.bss)
		*(.bss.*)
		PROVIDE(__bss_end = .);
		PROVIDE(_bss_end = .);
	}

	/* Add a section for stack to make sure it's properly aligned and sized */
	.stack : ALIGN(4K)
	{
		. = . + 0x4000; /* 16KB stack */
		PROVIDE(_stack_top = .);
	}

	PROVIDE(_kernel_end = .);
}
