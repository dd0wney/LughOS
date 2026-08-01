#include "lugh.h"
#include "security.h"
#include "memory.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * Memory region definitions
 * Per NASA Power of Ten rule 2 and SEI CERT DCL30-C, we use fixed-size allocations
 */
#define MEMORY_REGION_KERNEL     0x100000  // Kernel code (read-only)
#define MEMORY_REGION_DATA       0x300000  // Kernel data (read-write)

/* Heap bounds come from the single memory map in include/memory.h.
 *
 * They used to be defined here as [0x400000, 0x800000), which is the user
 * program's address range. The two definitions never appeared in the same
 * file, so nothing made the collision visible. The assertion below is what
 * makes a repeat a build failure instead of a corrupted user task. */
#define MEMORY_REGION_HEAP_START MM_HEAP_START
#define MEMORY_REGION_HEAP_END   MM_HEAP_END

_Static_assert(MEMORY_REGION_HEAP_END <= MM_USER_LOAD_BASE ||
               MEMORY_REGION_HEAP_START >= MM_USER_REGION_END,
               "kernel heap overlaps the user program region — the heap "
               "would hand out the user binary's own memory");

_Static_assert(MEMORY_REGION_HEAP_END > MEMORY_REGION_HEAP_START,
               "kernel heap bounds are inverted or empty");

/* Memory permission flags */
#define USER_READ       0x04
#define USER_WRITE      0x02
#define USER_EXEC       0x01
#define KERNEL_READ     0x40
#define KERNEL_WRITE    0x20
#define KERNEL_EXEC     0x10

/**
 * Static allocation metadata
 * Per NASA Power of Ten rule 3 (no dynamic memory after initialization)
 * we pre-allocate fixed-size memory blocks
 */
#define MEM_BLOCK_SIZES 4
#define MEM_BLOCKS_PER_SIZE 32
#define MEM_MAX_ALLOC_SIZE 4096

// Define block sizes (powers of 2 for efficiency)
static const size_t block_sizes[MEM_BLOCK_SIZES] = {
    64,    // For small structs
    256,   // For message headers and small buffers
    1024,  // For mid-sized buffers
    4096   // For large buffers
};

// Allocation metadata for each block
typedef struct {
    void* address;
    bool in_use;
    size_t size;
} mem_block_t;

// Memory allocation tracking
static mem_block_t memory_blocks[MEM_BLOCK_SIZES][MEM_BLOCKS_PER_SIZE];
static uintptr_t current_heap_ptr = MEMORY_REGION_HEAP_START;
static size_t remaining_heap = MEMORY_REGION_HEAP_END - MEMORY_REGION_HEAP_START;

/**
 * Initialize memory system 
 * Called during early boot to set up allocation structures
 */
void memory_init(void) {
    log_message(LOG_INFO, "Initializing memory system\n");
    
    // Initialize block tracking
    for (int size_class = 0; size_class < MEM_BLOCK_SIZES; size_class++) {
        // Pre-allocate blocks of this size class
        for (int i = 0; i < MEM_BLOCKS_PER_SIZE; i++) {
            // Calculate aligned block address
            size_t block_size = block_sizes[size_class];
            uintptr_t addr = current_heap_ptr;
            
            // Check for heap overflow
            if (remaining_heap < block_size) {
                log_message(LOG_ERROR, "Heap overflow during initialization\n");
                return;
            }
            
            // Initialize the block
            memory_blocks[size_class][i].address = (void*)addr;
            memory_blocks[size_class][i].in_use = false;
            memory_blocks[size_class][i].size = block_size;
            
            // Update heap pointers
            current_heap_ptr += block_size;
            remaining_heap -= block_size;
        }
    }
    
    log_message(LOG_INFO, "Memory system initialized: %u bytes allocated, %u remaining\n", 
               (unsigned int)((MEMORY_REGION_HEAP_END - MEMORY_REGION_HEAP_START) - remaining_heap),
               (unsigned int)remaining_heap);
}

// Function prototypes for static functions
static int find_size_class(size_t size);

/**
 * Find the appropriate size class for a request
 * 
 * @param size Requested allocation size
 * @return Index of the appropriate size class or -1 if too large
 */
static int find_size_class(size_t size) {
    // Bounded loop per NASA Power of Ten rule 2
    for (int i = 0; i < MEM_BLOCK_SIZES; i++) {
        if (size <= block_sizes[i]) {
            return i;
        }
    }
    
    // Request is too large
    return -1;
}

/**
 * Allocate memory from pre-allocated blocks
 * Per NASA Power of Ten rule 3 (no dynamic allocation after initialization)
 * 
 * @param size Size to allocate in bytes
 * @return Pointer to allocated memory or NULL if out of memory
 */
void* alloc_memory(size_t size) {
    // SEI CERT INT30-C: Ensure size is not zero
    if (size == 0) {
        log_message(LOG_ERROR, "Memory allocation failed: zero size requested\n");
        return NULL;
    }
    // NASA Power of Ten Rule 2: Check against maximum allowed size
    if (size > MEM_MAX_ALLOC_SIZE) {
        log_message(LOG_ERROR, "Memory allocation failed: requested %u bytes, maximum is %d\n", 
                    (unsigned int)size, MEM_MAX_ALLOC_SIZE);
        return NULL;
    }
    // NASA Power of Ten Rule 2: Use fixed-size allocation classes
    int size_class = find_size_class(size);
    if (size_class < 0) {
        log_message(LOG_ERROR, "Memory allocation failed: requested %u bytes exceeds maximum\n", (unsigned int)size);
        return NULL;
    }
    // NASA Power of Ten Rule 2: Bounded loop for block search
    for (int i = 0; i < MEM_BLOCKS_PER_SIZE; i++) {
        if (!memory_blocks[size_class][i].in_use) {
            memory_blocks[size_class][i].in_use = true;
            // SEI CERT MEM09-C: Clear memory before use
            void* ptr = memory_blocks[size_class][i].address;
            memset(ptr, 0, memory_blocks[size_class][i].size);
            log_message(LOG_DEBUG, "Allocated %u bytes at 0x%x (block %d of size class %d)\n", 
                        (unsigned int)memory_blocks[size_class][i].size, (unsigned int)(uintptr_t)ptr, i, size_class);
            return ptr;
        }
    }
    // NASA Power of Ten Rule 3: No dynamic allocation after init, so fail if no free block
    log_message(LOG_ERROR, "Memory allocation failed: no free blocks of size %u\n", 
                (unsigned int)block_sizes[size_class]);
    return NULL;
}

/**
 * Free memory by marking the block as available for reuse
 * Per SEI CERT MEM30-C, we ensure no access to freed memory
 * 
 * @param ptr Pointer to memory to free
 */
void free_memory(void* ptr) {
    // SEI CERT ARR30-C: Validate pointer before use
    if (ptr == NULL) {
        return; // Silently ignore NULL pointers
    }
    // SEI CERT ARR30-C: Validate pointer is within heap range
    if ((uintptr_t)ptr < MEMORY_REGION_HEAP_START || 
        (uintptr_t)ptr >= MEMORY_REGION_HEAP_END) {
        log_message(LOG_ERROR, "Security violation: attempt to free invalid memory at 0x%x\n", (unsigned int)(uintptr_t)ptr);
        return;
    }
    // NASA Power of Ten Rule 2: Bounded loops for block search
    for (int size_class = 0; size_class < MEM_BLOCK_SIZES; size_class++) {
        for (int i = 0; i < MEM_BLOCKS_PER_SIZE; i++) {
            if (memory_blocks[size_class][i].address == ptr && 
                memory_blocks[size_class][i].in_use) {
                size_t size = memory_blocks[size_class][i].size;
                // SEI CERT MEM03-C: Clear memory before releasing
                memset(ptr, 0, size);
                memory_blocks[size_class][i].in_use = false;
                log_message(LOG_DEBUG, "Freed %u bytes at 0x%x (block %d of size class %d)\n", 
                            (unsigned int)size, (unsigned int)(uintptr_t)ptr, i, size_class);
                return;
            }
        }
    }
    // NASA Power of Ten Rule 10: Log warning for attempt to free unallocated memory
    log_message(LOG_WARNING, "Attempted to free unallocated memory at 0x%x\n", (unsigned int)(uintptr_t)ptr);
}

/* allocate_page_dir() and map_user_space() were removed here.
 *
 * Both reported success without doing their job. map_user_space logged
 * "Mapped user space: 0x%x-0x%x" and returned 0 while creating no page
 * table entry at all, so its only caller copied into unmapped memory and
 * took a section translation fault. allocate_page_dir handed out a 4 KB
 * block that was never freed and never used as a page directory.
 *
 * A stub that returns an error is honest. A stub that returns success is
 * a defect with a comment attached, because every caller is written to
 * trust it. Real address-space construction needs the L2 page table work
 * that arm_section_set_ap() in kernel/mm/arm_mmu.c is the first step of;
 * these two will come back when there is something behind them.
 */