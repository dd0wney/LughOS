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

/**
 * Allocate a page directory for a new address space.
 * 
 * @return Pointer to the new page directory, or NULL on failure
 */
uint32_t* allocate_page_dir(void);

/**
 * Map a range of virtual addresses to physical memory with specified permissions.
 * 
 * @param page_dir Page directory to modify
 * @param start_addr Starting virtual address
 * @param end_addr Ending virtual address
 * @param permissions Permission flags (USER_READ, USER_WRITE, etc.)
 * @return 0 on success, -1 on failure
 */
int map_user_space(uint32_t* page_dir, uint32_t start_addr, uint32_t end_addr, uint32_t permissions);

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

#endif /* MEMORY_H */