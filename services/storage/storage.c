// JPL Rule 13: Limited scope for data and functions
// SEI CERT DCL30-C: Declare objects with appropriate storage duration

#include "lugh.h"
#include "transactions.h"

/* Concrete in-memory storage backend.
 *
 * Every method here used to be a stub returning 0. The vtable was
 * referenced by nothing, and every caller used the free functions in
 * services/storage/transactions.c directly, so a different backend could
 * not have changed any behaviour. A method that reports success without
 * doing its work is the same defect this tree removed from
 * map_user_space() and rollback_update().
 *
 * create_checkpoint, restore_checkpoint and remove_checkpoint now name the
 * real implementations in transactions.c. Their signatures match the
 * vtable exactly, so the vtable points straight at them with no wrapper.
 *
 * NASA Power of Ten rule 13: file-static linkage where possible.
 * The vtable itself is the only externally-visible symbol here.
 */

/* Genuine no-ops, and accurate as such. A synchronous in-RAM backend has
 * nothing to start, nothing to quiesce before a swap, and nothing to
 * resume after one. Returning 0 states that correctly. */
static int memstor_init(void* context) {
    (void)context;
    return 0;
}

static int memstor_prepare_swap(void) {
    return 0;
}

static int memstor_finalize_swap(void) {
    return 0;
}

/* Deliberately unsupported, and reported as such.
 *
 * get_state/set_state exist so a swap can hand a backend's state to its
 * replacement. This backend holds up to MAX_CHECKPOINTS × CHECKPOINT_SIZE
 * bytes of checkpoint data, which no caller-supplied state buffer is sized
 * for, and handing over the directory without the data would let a caller
 * believe its checkpoints survived a swap when they did not.
 *
 * Returning -1 loses nothing that a 0 would have preserved. It only stops
 * the caller believing otherwise. To change backends safely, finish or
 * roll back the outstanding workflows first, then swap. */
static int memstor_get_state(void* state_buffer, size_t* size) {
    (void)state_buffer; (void)size;
    log_message(LOG_WARNING,
        "storage(memory): get_state unsupported — a swap cannot carry "
        "checkpoint contents; quiesce and re-checkpoint instead\n");
    return -1;
}

static int memstor_set_state(void* state_buffer, size_t size) {
    (void)state_buffer; (void)size;
    log_message(LOG_WARNING,
        "storage(memory): set_state unsupported — see get_state\n");
    return -1;
}

storage_ops_t memory_storage_ops = {
    .name               = "memory",
    .init               = memstor_init,
    .create_checkpoint  = create_checkpoint,     /* transactions.c */
    .restore_checkpoint = restore_checkpoint,    /* transactions.c */
    .remove_checkpoint  = remove_checkpoint,     /* transactions.c */
    .get_state          = memstor_get_state,
    .set_state          = memstor_set_state,
    .prepare_swap       = memstor_prepare_swap,
    .finalize_swap      = memstor_finalize_swap,
};

/* ── Active backend ─────────────────────────────────────────────────
 *
 * NULL until storage_init() runs. Every dispatching caller checks for
 * NULL, so an operation attempted before init fails loudly rather than
 * reaching a half-built backend. */
static storage_ops_t *active_backend = NULL;

void storage_set_backend(storage_ops_t *ops) {
    if (ops == NULL) {
        log_message(LOG_ERROR,
            "storage: refusing to install a NULL backend\n");
        return;
    }
    active_backend = ops;
    log_message(LOG_INFO, "storage: backend '%s' active\n",
                (ops->name != NULL) ? ops->name : "(unnamed)");
}

storage_ops_t *storage_backend(void) {
    return active_backend;
}

void storage_init(void) {
    storage_set_backend(&memory_storage_ops);
    if (memory_storage_ops.init(NULL) != 0) {          /* JPL Rule 14 */
        log_message(LOG_ERROR, "storage: backend init failed\n");
    }
}
