#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <stdint.h>
#include <stddef.h>

/* Hot-swappable storage backend interface. Mirrors scheduler_ops_t in
 * include/lugh.h — every backend is a vtable of named methods so the
 * kernel can hot-swap implementations under a quiesce-and-resume
 * protocol. For Phase 3 there is exactly one backend (memory_storage_ops);
 * the interface exists so the swap path is testable. */
typedef struct {
    const char* name;
    int  (*init)(void* context);
    int  (*create_checkpoint)(const char* src, const char* dst);
    int  (*restore_checkpoint)(const char* src, const char* dst);
    int  (*remove_checkpoint)(const char* checkpoint);
    int  (*get_state)(void* state_buffer, size_t* size);
    int  (*set_state)(void* state_buffer, size_t size);
    int  (*prepare_swap)(void);
    int  (*finalize_swap)(void);
} storage_ops_t;

/* Concrete in-memory storage backend. Defined in services/storage/storage.c. */
extern storage_ops_t memory_storage_ops;

/**
 * Generate a unique transaction ID.
 *
 * @return A unique 64-bit transaction identifier
 */
uint64_t generate_transaction_id(void);

/**
 * Create a checkpoint of a file for potential rollback.
 * 
 * @param src Source file path
 * @param dst Destination path for checkpoint
 * @return 0 on success, -1 on failure
 */
int create_checkpoint(const char *src, const char *dst);

/**
 * Restore a file from a checkpoint.
 * 
 * @param src Source checkpoint path
 * @param dst Destination path to restore to
 * @return 0 on success, -1 on failure
 */
int restore_checkpoint(const char *src, const char *dst);

/**
 * Remove a checkpoint file when it's no longer needed.
 * 
 * @param checkpoint Path to checkpoint file to remove
 * @return 0 on success, -1 on failure
 */
int remove_checkpoint(const char *checkpoint);

/**
 * Copy a file preserving all attributes and permissions.
 * 
 * @param src Source file path
 * @param dst Destination file path
 * @return 0 on success, -1 on failure
 */
int copy_file(const char *src, const char *dst);

/**
 * Log a transaction operation for audit trail.
 * 
 * @param operation Type of operation (e.g., "Checkpoint", "Rollback")
 * @param src Source path (if applicable)
 * @param dst Destination path (if applicable)
 */
void log_transaction(const char *operation, const char *src, const char *dst);

/**
 * Install an update to the system.
 * 
 * @param path Target path for the update
 * @param image Binary image data
 * @param size Size of the binary image
 * @return 0 on success, -1 on failure
 */
int install_update(const char *path, const uint8_t *image, size_t size);

#endif /* TRANSACTIONS_H */
