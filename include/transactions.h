#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <stdint.h>
#include <stddef.h>
#include "lugh.h"  /* txn_log_entry_t */

/* Hot-swappable storage backend interface. Mirrors scheduler_ops_t in
 * include/lugh.h — every backend is a vtable of named methods so the
 * kernel can hot-swap implementations under a quiesce-and-resume
 * protocol.
 *
 * Until Phase 4 F6 this vtable was eight stubs that each returned 0
 * without doing anything, and nothing in the tree referred to it. Every
 * caller used the free functions below directly, so the "interface exists
 * so the swap path is testable" claim was not true — swapping the backend
 * changed nothing. The methods now carry the real implementations, and
 * callers dispatch through storage_backend(). */
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
 * Install memory_storage_ops as the active backend.
 *
 * Call once at boot, after memory_init() and before any subsystem starts
 * a workflow. storage_backend() returns NULL until this runs, and every
 * dispatching caller checks for that.
 */
void storage_init(void);

/**
 * Replace the active storage backend.
 *
 * Every checkpoint operation a caller performs through storage_backend()
 * goes to the new backend from the next call onward. There is no quiesce
 * here: a caller mid-workflow keeps whatever pointer it already read, so
 * swap between workflows, not during one.
 *
 * @param ops backend to install; NULL is rejected and leaves the current
 *            backend in place
 */
void storage_set_backend(storage_ops_t *ops);

/**
 * The active storage backend, or NULL before storage_init().
 *
 * Dispatch through this rather than calling create_checkpoint and friends
 * directly. A direct call always reaches the in-memory implementation,
 * whatever backend is installed, which is what made the seam decorative.
 */
storage_ops_t *storage_backend(void);

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
