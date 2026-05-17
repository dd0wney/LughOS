#include "lugh.h"
#include "interrupt.h"

struct gdt_entry {
    uint16_t limit_lo;
    uint16_t base_lo;
    uint8_t  base_mid;
    uint8_t  access;
    uint8_t  granularity;   /* high nibble: flags; low nibble: limit[19:16] */
    uint8_t  base_hi;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

static struct gdt_entry gdt_entries[5] __attribute__((aligned(8)));
static struct gdt_ptr   gdt_ptr;

/* Defined in gdt_load.S */
extern void gdt_flush(struct gdt_ptr *ptr);

static void gdt_set_entry(uint32_t idx, uint32_t base, uint32_t limit,
                           uint8_t access, uint8_t gran) {
    gdt_entries[idx].base_lo    = (uint16_t)(base  & 0xFFFF);
    gdt_entries[idx].base_mid   = (uint8_t)((base  >> 16) & 0xFF);
    gdt_entries[idx].base_hi    = (uint8_t)((base  >> 24) & 0xFF);
    gdt_entries[idx].limit_lo   = (uint16_t)(limit & 0xFFFF);
    gdt_entries[idx].granularity = (uint8_t)(((limit >> 16) & 0x0F) | (gran & 0xF0));
    gdt_entries[idx].access     = access;
}

static uint16_t read_cs(void) {
    uint16_t cs;
    __asm__ volatile("movw %%cs, %0" : "=r"(cs));
    return cs;
}

void gdt_init(void) {
    gdt_ptr.limit = (uint16_t)(sizeof(gdt_entries) - 1);
    gdt_ptr.base  = (uint32_t)&gdt_entries;

    /* access: P(1) DPL(xx) S(1) Type(xxxx)   gran: G(1) D/B(1) L(0) AVL(0) limit[19:16] */
    gdt_set_entry(0, 0, 0,        0x00, 0x00); /* 0x00: null descriptor   */
    gdt_set_entry(1, 0, 0xFFFFF,  0x9A, 0xCF); /* 0x08: kernel code       */
    gdt_set_entry(2, 0, 0xFFFFF,  0x92, 0xCF); /* 0x10: kernel data       */
    gdt_set_entry(3, 0, 0xFFFFF,  0xFA, 0xCF); /* 0x18: user code  DPL=3  */
    gdt_set_entry(4, 0, 0xFFFFF,  0xF2, 0xCF); /* 0x20: user data  DPL=3  */

    gdt_flush(&gdt_ptr);
    log_message(LOG_INFO, "GDT installed, CS=0x%x\n", (unsigned int)read_cs());
}
