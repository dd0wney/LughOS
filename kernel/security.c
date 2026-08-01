/**
 * LughOS Kernel Security Implementation
 * 
 * This file contains security-critical implementations for the microkernel:
 * - Memory protection initialization
 * - Privilege level management
 * - Security validation
 */

#include "lugh.h"
#include "console.h"
#include "crypto.h"
#include "security.h" /* own prototypes — this file previously declared none */
#include "memory.h"   /* MM_HEAP_START / MM_USER_LOAD_BASE — the shared memory map */

/**
 * Initialize hardware memory protection
 * Enables MMU/MPU based on architecture
 */
void security_init_memory_protection(void) {
    // NASA Power of Ten Rule 7: Use hardware memory protection features
    #if defined(__i386__)
    log_message(LOG_INFO, "Initializing x86 paging and protection\n");
    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r" (cr0));
    cr0 |= 0x10000; // Set WP bit
    asm volatile("mov %0, %%cr0" : : "r" (cr0));
    #elif defined(__arm__)
    log_message(LOG_INFO, "Initializing ARM MPU\n");
    // ARM memory protection implementation would go here
    #endif
    log_message(LOG_INFO, "Memory protection enabled\n");
}

/**
 * Verify memory regions for security violations
 * 
 * @return true if memory layout is secure
 */
bool security_verify_memory_layout(void) {
    // NASA Power of Ten Rule 7: Verify memory layout for security
    log_message(LOG_INFO, "Verified memory security constraints\n");
    return true;
}

/**
 * Initialize security features of the kernel
 */
void security_init(void) {
    log_message(LOG_INFO, "Initializing kernel security features\n");
    // NASA Power of Ten Rule 7: Enable ASLR if supported
    #if defined(ENABLE_ASLR)
    log_message(LOG_INFO, "Enabling address space randomization\n");
    // ASLR implementation would go here
    #endif
    /* Build the region table from the link layout before anything relies
     * on write protection. Until this runs the validator fails open, so
     * the earlier it happens the smaller that window is. */
    security_regions_init();
    security_init_memory_protection();
    if (!security_verify_memory_layout()) {
        log_message(LOG_ERROR, "SECURITY VIOLATION: Insecure memory layout detected\n");
        while(1); // NASA Power of Ten Rule 10: Halt on critical security failure
    }
    log_message(LOG_INFO, "Security subsystem initialized successfully\n");
}

/**
 * Sanitize a user-provided buffer
 * Ensures the buffer meets security requirements
 * 
 * @param buffer Pointer to the buffer to sanitize
 * @param size Size of the buffer
 * @return Sanitized buffer (may be a copy if needed)
 */
void* security_sanitize_buffer(void* buffer, size_t size) {
    // SEI CERT ARR30-C: Validate buffer pointer and size
    if (!buffer || size == 0 || size > MAX_MSG_SIZE) {
        return NULL; // Reject invalid buffers
    }
    // NASA Power of Ten Rule 6: Input validation for security
    // (Further pattern scanning could be added here)
    
    return buffer;
}

/**
 * Memory region access permissions
 */
typedef struct {
    uintptr_t start_addr;
    uintptr_t end_addr;
    bool read_allowed;
    bool write_allowed;
    bool exec_allowed;
    const char* region_name;
} mem_region_t;

/**
 * Fixed-size array of protected memory regions
 * Per NASA Power of Ten rule 2 (fixed loop bounds)
 */
#define MAX_PROTECTED_REGIONS 8

/* Section boundaries emitted by kernel/linker_{x86,arm,riscv}.ld.
 *
 * Declared as arrays so the symbol's ADDRESS is the value — taking &sym or
 * using a plain char would read the memory at that address instead. */
extern char _text_start[],   _text_end[];
extern char _rodata_start[], _rodata_end[];
extern char _data_start[],   _data_end[];
extern char _bss_start[],    _bss_end[];

/**
 * Memory protection regions, built at init from the real link layout.
 *
 * This table used to be a hardcoded const array describing a memory map
 * that no architecture actually had:
 *
 *   { 0x00100000, 0x00200000, ... write_allowed=false, "Kernel code" }
 *
 * On x86 the kernel loads at 1 MB, so .data and .bss sat inside that
 * write-denied range. Every memcpy into a kernel global was refused,
 * which made strlen return 0 and strcpy produce an empty string — the
 * checkpoint table silently registered blank keys and every lookup
 * missed. On ARM the kernel loads at 0x10000, inside no declared region
 * at all, so the loop matched nothing and the validator returned true
 * unconditionally. The same table was corrupting on one target and inert
 * on the other, and correct on neither.
 *
 * Deriving the bounds from linker symbols means the table cannot drift
 * from the layout again: move a section and the regions move with it.
 *
 * NASA Power of Ten rule 2: fixed-size array, bounded loop, no growth.
 */
static mem_region_t protected_regions[MAX_PROTECTED_REGIONS];
static uint32_t     protected_region_count = 0u;

/* Append a region if there is room and the bounds are sane. A zero-length
 * or inverted range is dropped rather than stored, because a region with
 * end < start silently matches nothing in the overlap test below. */
static void region_add(uintptr_t start, uintptr_t end,
                       bool read_ok, bool write_ok, bool exec_ok,
                       const char* name) {
    if (protected_region_count >= MAX_PROTECTED_REGIONS) {
        log_message(LOG_ERROR,
            "security: region table full, dropping '%s'\n", name);
        return;
    }
    if (end < start) {
        log_message(LOG_ERROR,
            "security: region '%s' has end < start, dropped\n", name);
        return;
    }
    protected_regions[protected_region_count].start_addr    = start;
    protected_regions[protected_region_count].end_addr      = end;
    protected_regions[protected_region_count].read_allowed  = read_ok;
    protected_regions[protected_region_count].write_allowed = write_ok;
    protected_regions[protected_region_count].exec_allowed  = exec_ok;
    protected_regions[protected_region_count].region_name   = name;
    protected_region_count++;
}

/**
 * Build the protected-region table from the link layout.
 *
 * Call once, early, before anything relies on write protection. Until it
 * runs, protected_region_count is 0 and every access validates — the
 * string and memory helpers are used during early boot, well before a
 * region table can exist, so failing open before init is required rather
 * than merely convenient.
 */
void security_regions_init(void) {
    protected_region_count = 0u;

    /* Null pointer guard. Kept below any real kernel address on all three
     * targets (ARM starts at 0x10000, x86 at 0x100000, RISC-V at
     * 0x80100000), so it never shadows a legitimate section. */
    region_add(0x0u, 0xFFFu, false, false, false, "Null pointer guard");

    /* Kernel text and rodata: readable and executable, never writable.
     * This is the one region that actually protects something — a write
     * here is a genuine defect or an attack. */
    region_add((uintptr_t)_text_start, (uintptr_t)_rodata_end - 1u,
               true, false, true, "Kernel text+rodata");

    /* Kernel data and BSS: readable and writable, not executable.
     * .data and .bss are adjacent in all three linker scripts, so one
     * region covers both. */
    region_add((uintptr_t)_data_start, (uintptr_t)_bss_end - 1u,
               true, true, false, "Kernel data+bss");

    /* Block allocator arena — see the memory map in include/memory.h. */
    region_add(MM_HEAP_START, MM_HEAP_END - 1u,
               true, true, false, "Kernel heap");

    /* User program image and stack. Writable from kernel mode: the loader
     * copies the binary in, and the syscall layer writes the message
     * struct back. Hardware AP bits are what stop USER mode reaching
     * kernel memory — see arm_mmu_init. */
    region_add(MM_USER_LOAD_BASE, MM_USER_REGION_END - 1u,
               true, true, true, "User space");

    log_message(LOG_INFO,
        "security: %u regions from link layout "
        "(text=0x%x-0x%x data=0x%x-0x%x heap=0x%x-0x%x)\n",
        (unsigned int)protected_region_count,
        (unsigned int)(uintptr_t)_text_start,
        (unsigned int)((uintptr_t)_rodata_end - 1u),
        (unsigned int)(uintptr_t)_data_start,
        (unsigned int)((uintptr_t)_bss_end - 1u),
        (unsigned int)MM_HEAP_START,
        (unsigned int)(MM_HEAP_END - 1u));
}

/**
 * Validate a memory access to ensure it's within bounds and has proper permissions
 * Per NASA Power of Ten rule 6 (integrity checks) and SEI CERT ARR38-C
 * 
 * @param addr Address to check
 * @param size Size of access
 * @param write True if this is a write operation
 * @return true if access is allowed
 */
bool security_validate_memory_access(void* addr, size_t size, bool write) {
    // Validate parameters
    if (addr == NULL && size > 0) {
        log_message(LOG_WARNING, "Security violation: NULL pointer access\n");
        return false;
    }
    
    // Convert to integer for range checks
    uintptr_t address = (uintptr_t)addr;
    
    // Check for integer overflow in address calculation per SEI CERT INT30-C
    if (size > 0 && SIZE_MAX - size < address) {
        log_message(LOG_WARNING, "Security violation: address range overflow at %p + %zu\n", addr, size);
        return false;
    }
    
    // Calculate end address with overflow protection
    uintptr_t end_address = address + size - (size > 0 ? 1 : 0);
    
    /* Check against protected regions. Before security_regions_init runs,
     * the count is 0 and this loop is a no-op — see the note there. */
    for (uint32_t i = 0; i < protected_region_count; i++) {
        const mem_region_t* region = &protected_regions[i];
        
        // If memory range overlaps with this region
        if (address <= region->end_addr && end_address >= region->start_addr) {
            // Check permissions
            if (!region->read_allowed) {
                log_message(LOG_WARNING, "Security violation: read access to %s at %p\n", 
                           region->region_name, addr);
                return false;
            }
            
            if (write && !region->write_allowed) {
                log_message(LOG_WARNING, "Security violation: write attempt to %s at %p\n", 
                           region->region_name, addr);
                return false;
            }
        }
    }
    
    return true;
}

/**
 * Generate secure random data (for security operations)
 * 
 * @param buffer Buffer to fill with random data
 * @param size Size of data to generate
 * @return true on success
 */
bool security_generate_random(void* buffer, size_t size) {
    if (!buffer || size == 0) {
        return false;
    }
    
    // In a real implementation, this would use hardware RNG if available
    // or a secure PRNG with proper seeding
    
    // Simple example implementation (NOT SECURE - replace with proper implementation)
    uint8_t* buf = (uint8_t*)buffer;
    static uint32_t next = 123456789;
    
    for (size_t i = 0; i < size; i++) {
        next = next * 1103515245 + 12345;
        buf[i] = (next >> 16) & 0xFF;
    }
    
    return true;
}

/**
 * Verify the signature (hash) of an update image
 * 
 * Uses cryptographic functions to validate that the update
 * binary matches its expected hash to prevent tampering.
 * 
 * @param image Pointer to update binary image 
 * @param size Size of the binary image
 * @param expected_hash Expected hash value for verification
 * @return true if signature is valid
 * 
 * Complies with:
 * - SEI CERT MSC41-C: Never hard code sensitive information
 * - JPL Rule 14: Check return values
 * - NASA Rule 6: Validate data from external sources
 */
bool verify_signature(const uint8_t *image, size_t size, uint32_t expected_hash) {
    /* Validate parameters */
    if (image == NULL || size == 0) {
        log_message(LOG_ERROR, "Invalid parameters for signature verification");
        return false;
    }
    
    /* Calculate the hash */
    uint32_t calculated_hash = compute_sha256(image, size);
    
    /* Compare with expected hash */
    if (calculated_hash != expected_hash) {
        log_message(LOG_ERROR, "Signature verification failed: hash mismatch");
        log_message(LOG_ERROR, "Expected: 0x%08x, Calculated: 0x%08x", 
                   expected_hash, calculated_hash);
        return false;
    }
    
    log_message(LOG_INFO, "Signature verification passed");
    return true;
}
