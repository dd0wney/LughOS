#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stddef.h>

/**
 * Initialize the memory management subsystem.
 * 
 * This function sets up the memory allocation system, page tables,
 * and related data structures. Should be called early in the boot process.
 * 
 * Complies with:
 * - NASA Power of Ten Rule 3: All memory allocation done at initialization
 */
void memory_init(void);

/* allocate_page_dir() and map_user_space() are deliberately absent.
 * Both existed as stubs that returned success while doing nothing, which
 * made every caller's error check meaningless. See the note in
 * kernel/mm/memory.c. Use arm_section_set_ap() below for the one form of
 * mapping change LughOS can currently make. */

/**
 * Load a user program from binary data to memory.
 * 
 * @param binary_data Pointer to the binary data
 * @param size Size of the binary data in bytes
 * @param entry_point Pointer to store the program entry point
 * @param stack_pointer Pointer to store the stack pointer
 * @return 0 on success, -1 on failure
 */
int load_user_program(void* binary_data, size_t size, uint32_t* entry_point, uint32_t* stack_pointer);

/* ── Physical memory map (Phase 4 F5) ──────────────────────────────
 *
 * Every fixed region is named here, in one place, so an overlap shows up
 * as a compile-time failure rather than as corrupted memory at run time.
 * memory.c carries a _Static_assert that enforces the disjointness.
 *
 * This exists because the kernel heap used to start at MM_USER_LOAD_BASE.
 * The heap and the user program occupied the same addresses. The first
 * user IPC that got far enough to allocate an nng_msg_t overwrote the
 * user program's entry code, and the task then prefetch-aborted at pc=0.
 * Both constants were correct in isolation and fatal together, which is
 * exactly the failure a single named map prevents.
 */
#define MM_USER_LOAD_BASE   0x400000u   /* user binary load address       */
#define MM_USER_STACK_TOP   0x700000u   /* user stack top, grows downward */
#define MM_USER_REGION_END  0x800000u   /* end of user-accessible sections */

#if defined(__riscv)
/* RISC-V RAM begins at 0x80000000 and the kernel image at 0x80100000, so
 * a low heap address is not merely overlapping there, it is not RAM. */
#define MM_HEAP_START       0x80800000u
#define MM_HEAP_END         0x80900000u
#else
#define MM_HEAP_START       0x800000u
#define MM_HEAP_END         0x900000u
#endif

/* Fixed-size block allocator over [MM_HEAP_START, MM_HEAP_END).
 * Declared here rather than as an ad-hoc extern in each consumer.
 * Returns NULL when no block of a suitable size class is free. */
void* alloc_memory(size_t size);
void  free_memory(void* ptr);

/* Memory permission flags */
#define USER_READ       0x04
#define USER_WRITE      0x02
#define USER_EXEC       0x01
#define KERNEL_READ     0x40
#define KERNEL_WRITE    0x20
#define KERNEL_EXEC     0x10

/* ── Page frame allocator (Phase 3 B1) ─────────────────────────────
 *
 * 4 KB frames carved from a static physical pool. Foundation for the
 * MMU work in B2 (x86 paging), B3 (ARM MMU enable), and B4 (real
 * map_user_space). NASA Power of Ten rule 5: pool size fixed at
 * compile time, no runtime growth.
 *
 * alloc_frame returns the physical address of a free frame or 0 on
 * failure. free_frame returns a frame to the pool; defensive against
 * double-free / unaligned / out-of-range input (logs + returns).
 */
#define MM_FRAME_SIZE   4096u

void     frame_allocator_init(void);
uint32_t alloc_frame(void);
void     free_frame(uint32_t phys_addr);
uint32_t frame_count_free(void);

/* ── MMU enable (Phase 3 B3) ──────────────────────────────────────
 *
 * Identity-maps kernel + device window using 1 MB sections, sets DACR
 * and TTBR0, invalidates TLB and caches, then sets SCTLR.M. Must be
 * called AFTER any subsystem that touches a fixed physical address
 * (vectors, stacks, device drivers) has initialised — they're mapped
 * in the static table, but the MMU only starts enforcing translations
 * after this returns.
 *
 * Caches stay off in B3 (B4/Phase 4 enables them once page tables are
 * stable). Half-MMU is unbootable, so this is a single atomic op —
 * either everything is set up and the kernel survives the next
 * instruction fetch, or the kernel takes a fault that can't be
 * diagnosed without JTAG. On non-ARM builds it's a no-op stub. */
void arm_mmu_init(void);

/* ── User/kernel separation enforcement (Phase 3 B4) ──────────────
 *
 * After arm_mmu_init: sections 0–3 + 0x101 are AP=01 (kernel-only),
 * sections 4–7 are AP=11 (user RW). DACR=Client makes the CPU
 * enforce these. User mode accessing a kernel section now takes a
 * data abort instead of silently succeeding — B6's test exercises
 * this end to end.
 *
 * arm_section_set_ap flips a single 1 MB section's AP bits; useful
 * to toggle a region between user and kernel accessibility (the only
 * granularity available without L2 page tables, which are Phase 4).
 * Returns 0 / -1. TLB is invalidated automatically.
 *
 * arm_tlb_invalidate_all flushes the entire TLB — call after L1
 * mutations done by paths other than arm_section_set_ap. */
int  arm_section_set_ap(uint32_t va, uint32_t ap);
int  arm_section_get_ap(uint32_t va);    /* returns AP bits 0..3 or -1 if unmapped */
void arm_tlb_invalidate_all(void);

/* AP constants exposed for the B6 test and any caller that wants to
 * toggle a section between privileges. See arm_mmu.c for full encoding. */
#define MMU_AP_KERNEL_ONLY  1u
#define MMU_AP_USER_RO      2u
#define MMU_AP_USER_RW      3u

#endif /* MEMORY_H */