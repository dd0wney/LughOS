#ifndef SANDBOX_H
#define SANDBOX_H

/**
 * Sandbox Environment Header for LughOS
 *
 * Defines the interfaces for the sandbox testing environment
 * used to safely test updates before committing them.
 *
 * Complies with:
 * - SEI CERT ERR33-C: Detect errors and handle appropriately
 * - JPL Rule 14: Check return values
 * - NASA Rule 1: Simple control flow
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Size of the static staging area an update image is copied into.
 * An image larger than this is rejected rather than truncated.
 *
 * Bounded static storage, per NASA Power of Ten rule 3. This replaces the
 * two magic addresses (0x900000 code, 0xA00000 data) the sandbox used to
 * copy into. Those addresses were never mapped, so the copy faulted. */
#define SANDBOX_STAGE_SIZE  65536u

/**
 * Stage an update image in the sandbox area and validate its format.
 *
 * Copies the image into a static kernel staging buffer and checks the
 * ELF magic. It does NOT execute the image — LughOS has no mechanism to
 * run an untrusted binary under supervision yet, so the staging buffer
 * is kernel-only memory and nothing branches into it.
 *
 * @param image Pointer to the update binary
 * @param size Size of the update binary, at most SANDBOX_STAGE_SIZE
 * @return true when the image staged and its format validated
 */
bool sandbox_apply(const uint8_t *image, size_t size);

/**
 * Run validation tests on an updated component
 * 
 * @param path Path to the updated component
 * @return true if all tests passed
 */
bool run_tests(const char *path);

#endif /* SANDBOX_H */
