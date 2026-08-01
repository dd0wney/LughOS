#include "lugh.h"
#include "memory.h"

/* Cross-arch MMU surface (Phase 3 B3 + B4 + B5).
 *
 * Despite the file name, this is the central per-arch MMU dispatcher:
 *   __arm__  — real implementation (B3 enable + B4 AP enforcement).
 *   __i386__ — TBD (Phase 3 B2, on the Linux box where x86 builds).
 *   __riscv  — Sv32/Sv39 not implemented; the stubs below are the
 *              B5 deliverable so `make riscv` compiles. Runtime is
 *              no-op: kernel runs without MMU on RISC-V for now.
 *
 * All three architectures expose the same three public symbols
 * (arm_mmu_init, arm_section_set_ap, arm_tlb_invalidate_all) so
 * kmain doesn't need per-arch `#if` ladders around the call sites.
 *
 * The historical name `arm_mmu.c` predates B5; renaming to mm/mmu.c
 * would be cleaner but churns Makefile + git history without buying
 * anything functional. Deferred to Phase 4 cleanup.
 *
 * ─── original B3 design notes ───
 *
 */
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

/* AP encodings (ARMv5, with SCTLR.S = SCTLR.R = 0):
 *   0b00  no access (always faults)
 *   0b01  privileged RW, user no access  — kernel sections
 *   0b10  privileged RW, user RO         — read-only user data
 *   0b11  privileged RW, user RW         — user code/data/stack
 * Combined with DACR=Client per domain, these bits are enforced by
 * the MMU. With DACR=Manager (B3), they were bypassed. */
#define AP_KERNEL_ONLY  1u
#define AP_USER_RO      2u
#define AP_USER_RW      3u

#define SECTION_DESCRIPTOR(addr, ap) \
    (((addr) & 0xFFF00000u) | ((ap) << 10) | (0u << 5) | 0x2u)

/* 4096 entries × 4 bytes = 16 KB. Alignment must match TTBR0's
 * 16 KB requirement on ARMv5. Lives in BSS, zero-initialised.
 *
 * Guarded: every user of this table is inside an __arm__ block, so on
 * x86 and RISC-V it was an unused static and -Werror=unused-variable
 * failed the build for both targets. */
#ifdef __arm__
static uint32_t l1_page_table[4096] __attribute__((aligned(16384)));
#endif

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

/* TLB invalidate — call after any L1 table mutation so the CPU
 * doesn't keep using a stale translation. ARMv5's "invalidate all
 * TLB" is the simplest hammer; per-VA invalidation (`c8,c7,1`) is
 * a B4 optimization not yet worth its cost. */
#ifdef __arm__
void arm_tlb_invalidate_all(void) {
    uint32_t zero = 0u;
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(zero) : "memory");
}

/* Read a section's current AP bits. Returns -1 if the L1 entry is
 * invalid or not a section descriptor (i.e. nothing to inspect). */
int arm_section_get_ap(uint32_t va) {
    uint32_t idx = va >> 20;
    if (idx >= 4096u) return -1;
    if (l1_page_table[idx] == 0u) return -1;
    if ((l1_page_table[idx] & 0x3u) != 0x2u) return -1;
    return (int)((l1_page_table[idx] >> 10) & 0x3u);
}

/* Change the AP bits of a single 1 MB section. Used by map_user_space()
 * below to flip a section between kernel-only and user-RW (or vice
 * versa) — the only granularity available without L2 page tables.
 * Returns 0 on success, -1 on out-of-range VA. */
int arm_section_set_ap(uint32_t va, uint32_t ap) {
    uint32_t idx = va >> 20;
    if (idx >= 4096u) return -1;
    if (l1_page_table[idx] == 0u) return -1;        /* not mapped */
    if ((l1_page_table[idx] & 0x3u) != 0x2u) return -1;  /* not a section */
    /* Preserve base + C/B/Domain/IMP bits; replace AP. */
    l1_page_table[idx] =
        (l1_page_table[idx] & ~(0x3u << 10)) | ((ap & 0x3u) << 10);
    arm_tlb_invalidate_all();
    return 0;
}
#endif /* __arm__ */

void arm_mmu_init(void) {
#ifdef __arm__
    /* 1. Build the L1 page table. */
    uint32_t i;
    for (i = 0u; i < 4096u; i++) {
        l1_page_table[i] = 0u;
    }
    /* Sections 0–3 ([0x000000–0x400000)): kernel image, BSS, per-mode
     * stacks, frame allocator pool. Kernel-only — user mode faults. */
    for (i = 0u; i < 4u; i++) {
        l1_page_table[i] = SECTION_DESCRIPTOR(i * 0x100000u, AP_KERNEL_ONLY);
    }
    /* Sections 4–7 ([0x400000–0x800000)): user binary load area
     * (0x400000) and user stack (0x700000 grows down through 0x600000).
     * User RW so syscall return + user execution work. The frame pool
     * tail (0x500000–0x600000) physically overlaps user space, but no
     * frame is currently allocated there — Phase 4 will repartition. */
    for (i = 4u; i < 8u; i++) {
        l1_page_table[i] = SECTION_DESCRIPTOR(i * 0x100000u, AP_USER_RW);
    }
    /* Section 8 ([0x800000–0x8FFFFF)): the kernel heap that alloc_memory
     * carves blocks from. Kernel-only, so a user task cannot reach the
     * allocator's blocks — which it could when the heap sat inside the
     * user-RW sections 4–7. Bounds come from MM_HEAP_START/MM_HEAP_END
     * in include/memory.h; the loop below covers whatever range those
     * name, so moving the heap does not silently unmap it. */
    for (i = (MM_HEAP_START >> 20); i < ((MM_HEAP_END + 0xFFFFFu) >> 20); i++) {
        l1_page_table[i] = SECTION_DESCRIPTOR(i * 0x100000u, AP_KERNEL_ONLY);
    }

    /* Map device window 0x10100000–0x101FFFFF (one section covers
     * VIC, SP804, PL011 UART0, PL011 UART1). Kernel-only. */
    l1_page_table[0x101] = SECTION_DESCRIPTOR(0x10100000u, AP_KERNEL_ONLY);

    /* 2. Set TTBR0 first — before MMU is enabled, the CPU mustn't see
     * a stale base register. */
    mmu_set_ttbr0(l1_page_table);

    /* 3. DACR: all 16 domains in Client mode. AP bits ENFORCED.
     * Kernel sections (AP=01) trap on user access; user sections
     * (AP=11) trap if anything (no domain) is "No access". B3 used
     * Manager mode (0xFFFFFFFF, AP bypassed) — B4's switch to Client
     * mode is what makes user/kernel separation actually load-bearing. */
    mmu_set_dacr(0x55555555u);

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
        "ARM MMU enabled: TTBR0=0x%X DACR=0x55555555 SCTLR.M=1 "
        "(kernel sections 0-3+0x101 AP=01, user sections 4-7 AP=11)\n",
        (uint32_t)(uintptr_t)l1_page_table);
#else
    /* On non-ARM builds this is a no-op — the symbol exists so kmain
     * can call it unconditionally. Architecture-specific MMU enable
     * for x86 (B2) and RISC-V (B5) live in their own files. */
    log_message(LOG_DEBUG, "arm_mmu_init: not ARM, skipping\n");
#endif
}

#ifndef __arm__
/* Non-ARM stubs for the B4 helpers so memory.h's declarations can be
 * called unconditionally from arch-neutral code. */
int  arm_section_set_ap(uint32_t va, uint32_t ap) { (void)va; (void)ap; return 0; }
int  arm_section_get_ap(uint32_t va)              { (void)va; return -1; }
void arm_tlb_invalidate_all(void) { }
#endif
