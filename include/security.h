#ifndef SECURITY_H
#define SECURITY_H

#include "lugh.h"

/**
 * Initialize security features of the kernel
 */
void security_init(void);

/**
 * Initialize hardware memory protection
 */
void security_init_memory_protection(void);

/**
 * Build the protected-region table from the linker's section symbols.
 *
 * Called by security_init(). The regions describe the real link layout
 * (_text_start, _rodata_end, _data_start, _bss_end) plus the heap and
 * user bounds from memory.h, rather than a hardcoded map that no
 * architecture matched.
 *
 * Until this runs, security_validate_memory_access() allows everything —
 * the string and memory helpers run long before a region table can exist.
 */
void security_regions_init(void);

/**
 * Verify memory regions for security violations
 * 
 * @return true if memory layout is secure
 */
bool security_verify_memory_layout(void);

/**
 * Sanitize a user-provided buffer
 * Ensures the buffer meets security requirements
 * 
 * @param buffer Pointer to the buffer to sanitize
 * @param size Size of the buffer
 * @return Sanitized buffer (may be a copy if needed)
 */
void* security_sanitize_buffer(void* buffer, size_t size);

/**
 * Validate a memory access to ensure it's within bounds
 * 
 * @param addr Address to check
 * @param size Size of access
 * @param write True if this is a write operation
 * @return true if access is allowed
 */
bool security_validate_memory_access(void* addr, size_t size, bool write);

/**
 * Generate secure random data (for security operations)
 * 
 * @param buffer Buffer to fill with random data
 * @param size Size of data to generate
 * @return true on success
 */
bool security_generate_random(void* buffer, size_t size);

/**
 * Verify the signature (hash) of an update image
 * 
 * @param image Pointer to update binary image 
 * @param size Size of the binary image
 * @param expected_hash Expected hash value for verification
 * @return true if signature is valid
 */
bool verify_signature(const uint8_t *image, size_t size, uint32_t expected_hash);

#endif /* SECURITY_H */
