#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <stdint.h>
#include <stddef.h>
#include "lugh.h"  /* txn_log_entry_t */

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

/* Bounded sizing constants for the in-memory storage backend. */
#define MAX_CHECKPOINTS  16u
#define CHECKPOINT_SIZE  4096u

/**
 * Register a labeled in-memory buffer that create_checkpoint can read
 * from and restore_checkpoint can write back to. The buffer pointer is
 * stored — no copy is taken — so the lifetime of *data must outlive any
 * subsequent checkpoint operation referencing key.
 *
 * @param key   stable identifier (≤63 chars + NUL)
 * @param data  caller-owned buffer
 * @param size  byte length of *data (≤ CHECKPOINT_SIZE)
 * @return 0 on success, -1 on bad args / table full / size overflow
 */
int storage_register_buffer(const char *key, void *data, size_t size);

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
 * Append a transaction entry to the bounded global ring.
 *
 * Implementation in kernel/fs/storage.c. On overflow the oldest entry
 * is dropped, the local overflow counter is bumped, and
 * ipc_ring.overflow is bumped so the next auditor_tick() emits an
 * OVERFLOW telemetry record.
 *
 * @param entry caller-owned entry; task_id is stamped from
 *              current_task if entry->task_id == 0 on entry
 * @return 0 on success, -1 if entry == NULL
 */
int log_transaction(txn_log_entry_t* entry);

/* Read-only accessors for tests / introspection. */
uint32_t txn_log_get_overflow(void);
uint32_t txn_log_get_depth(void);

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
