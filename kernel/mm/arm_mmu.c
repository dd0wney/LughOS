#include "lugh.h"
#include "memory.h"

/* ARMv5TE MMU enable (Phase 3 B3) — atomic single-commit per advisor:
 * the kernel cannot run "half-MMU." Every region the kernel will touch
 * after enable MUST be mapped before SCTLR.M is set, and DACR must be
 * non-zero, and TLB+caches must be invalidated — anything missing and
 * the kernel takes a fault that can't be diagnosed without JTAG.
 *
 * ## Choices (and why)
 *
 * **1 MB sections, no L2 page tables.** A 4096-entry L1 table covers
 * the full 4 GB VA space in 1 MB chunks. For B3 we map the kernel + a
 * device window; user-page granularity (4 KB) is B4's job.
 *
 * **Identity mapping.** VA == PA for every entry. The kernel keeps
 * running on the same physical memory after MMU enable; we just buy
 * the protection that any unmapped address now faults. Higher-half
 * virtual layout is a multi-week side quest the advisor warned against.
 *
 * **DACR = all-Manager (0xFFFFFFFF).** AP bits are bypassed; mapped
 * addresses are accessible at any privilege. B4 will refine to Client
 * mode + proper AP bits when it introduces real user mappings. For B3
 * the goal is "MMU on, kernel keeps running" — protection is B4.
 *
 * **Caches stay OFF.** SCTLR.C and SCTLR.I remain 0. Avoids any cache-
 * coherency edge case during the enable transition. B4/Phase 4 can
 * turn caches on once the page tables are stable.
 *
 * **Static, 16 KB-aligned L1 table.** TTBR0 requires a 16 KB-aligned
 * base. A static array with __attribute__((aligned(16384))) gets us
 * that without dragging the frame allocator into the bootstrap path.
 * Table itself is 16 KB; this commit therefore burns 16 KB of BSS.
 *
 * ## Mapping plan
 *
 *   L1[0..7]   →  PA 0x00000000..0x007FFFFF (8 MB)
 *                vectors at 0, kernel image, BSS, per-mode stacks,
 *                frame allocator pool, user program load at 0x400000,
 *                user stack region around 0x700000.
 *   L1[0x101]  →  PA 0x10100000..0x101FFFFF (1 MB)
 *                contains VIC (0x10140000), SP804 (0x101E2000),
 *                PL011 UART0 (0x101F1000), PL011 UART1 (0x101F2000).
 *   all other  →  invalid (any access faults — that's the protection)
 *
 * ## Section descriptor format (ARMv5)
 *   [31:20] section base (1 MB aligned)
 *   [19:12] SBZ
 *   [11:10] AP (we use 0b11; doesn't matter when DACR is Manager)
 *   [9]     IMP / SBZ
 *   [8:5]   Domain (we use 0)
 *   [4]     IMP (was XN on later archs — must be 0 on v5)
 *   [3]     C (cacheable) — 0 since caches off
 *   [2]     B (bufferable) — 0
 *   [1:0]   type = 0b10 (section)
 *
 * Result: 0x00C02 base for each section, OR'd with the PA. */

#define SECTION_DESCRIPTOR(addr) \
    (((addr) & 0xFFF00000u) | (3u << 10) | (0u << 5) | 0x2u)

/* 4096 entries × 4 bytes = 16 KB. Alignment must match TTBR0's
 * 16 KB requirement on ARMv5. Lives in BSS, zero-initialised. */
static uint32_t l1_page_table[4096] __attribute__((aligned(16384)));

#ifdef __arm__

static inline void mmu_set_ttbr0(const uint32_t *table) {
    __asm__ volatile(
        "mcr p15, 0, %0, c2, c0, 0"
        : : "r"(table) : "memory");
}

static inline void mmu_set_dacr(uint32_t dacr) {
    __asm__ volatile(
        "mcr p15, 0, %0, c3, c0, 0"
        : : "r"(dacr) : "memory");
}

static inline void mmu_invalidate_tlb_and_caches(void) {
    uint32_t zero = 0u;
    /* Invalidate I-cache (entire) */
    __asm__ volatile("mcr p15, 0, %0, c7, c5, 0" : : "r"(zero) : "memory");
    /* Invalidate D-cache (entire). ARM926 supports this via c7,c6,0 */
    __asm__ volatile("mcr p15, 0, %0, c7, c6, 0" : : "r"(zero) : "memory");
    /* Invalidate unified TLB */
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(zero) : "memory");
}

static inline uint32_t sctlr_read(void) {
    uint32_t v;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(v));
    return v;
}

static inline void sctlr_write(uint32_t v) {
    __asm__ volatile(
        "mcr p15, 0, %0, c1, c0, 0\n\t"
        /* Pipeline-drain NOPs so the next fetched instruction sees
         * the new MMU state. ARMv5 has no DSB/ISB; three NOPs is the
         * canonical "wait for CP15 write to take effect" pattern. */
        "nop\n\t"
        "nop\n\t"
        "nop"
        : : "r"(v) : "memory");
}

#endif /* __arm__ */

void arm_mmu_init(void) {
#ifdef __arm__
    /* 1. Build the L1 page table. */
    uint32_t i;
    for (i = 0u; i < 4096u; i++) {
        l1_page_table[i] = 0u;
    }
    /* Map low 8 MB (kernel + stacks + frame pool + user load area). */
    for (i = 0u; i < 8u; i++) {
        l1_page_table[i] = SECTION_DESCRIPTOR(i * 0x100000u);
    }
    /* Map device window 0x10100000–0x101FFFFF (one section covers
     * VIC, SP804, PL011 UART0, PL011 UART1). */
    l1_page_table[0x101] = SECTION_DESCRIPTOR(0x10100000u);

    /* 2. Set TTBR0 first — before MMU is enabled, the CPU mustn't see
     * a stale base register. */
    mmu_set_ttbr0(l1_page_table);

    /* 3. DACR: all 16 domains in Manager mode. AP bits bypassed; the
     * only protection is "is this section mapped?". B4 narrows this. */
    mmu_set_dacr(0xFFFFFFFFu);

    /* 4. Flush stale TLB entries and any cache lines left from boot
     * (caches were never enabled, but be defensive). */
    mmu_invalidate_tlb_and_caches();

    /* 5. Enable MMU bit (SCTLR.M). Caches stay off (C, I bits clear).
     * V bit (high vectors) stays clear — we cleared it in boot_arm.S
     * and the vector table is identity-mapped at 0x00000000. */
    uint32_t sctlr = sctlr_read();
    sctlr |=  (1u << 0);   /* M = 1: MMU enable */
    sctlr &= ~(1u << 2);   /* C = 0: D-cache disabled */
    sctlr &= ~(1u << 12);  /* I = 0: I-cache disabled */
    sctlr &= ~(1u << 13);  /* V = 0: low vectors */
    sctlr_write(sctlr);

    /* From this point onward, every memory access is translated.
     * Identity mapping means the kernel sees the same addresses as
     * before, but unmapped accesses now fault into arm_dabort_panic
     * or arm_pabort_panic (boot_arm.S vector → exceptions.S). */
    log_message(LOG_INFO,
        "ARM MMU enabled: TTBR0=0x%X DACR=0xFFFFFFFF SCTLR.M=1 "
        "(9 sections identity-mapped, caches off)\n",
        (uint32_t)(uintptr_t)l1_page_table);
#else
    /* On non-ARM builds this is a no-op — the symbol exists so kmain
     * can call it unconditionally. Architecture-specific MMU enable
     * for x86 (B2) and RISC-V (B5) live in their own files. */
    log_message(LOG_DEBUG, "arm_mmu_init: not ARM, skipping\n");
#endif
}
