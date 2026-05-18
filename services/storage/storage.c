// JPL Rule 13: Limited scope for data and functions
// SEI CERT DCL30-C: Declare objects with appropriate storage duration

#include "lugh.h"
#include "transactions.h"

/* Concrete in-memory storage backend.
 *
 * Phase 3 ships a single backend; the vtable shape exists so the
 * hot-swap protocol is testable end-to-end. Subsequent commits in this
 * track fill in the bodies (C2 wires the txn log, C4 the checkpoint
 * slots). For now every method is a stub returning 0.
 *
 * NASA Power of Ten rule 13: file-static linkage where possible.
 * The vtable itself is the only externally-visible symbol. */

static int memstor_init(void* context) {
    (void)context;
    return 0;
}

static int memstor_create_checkpoint(const char* src, const char* dst) {
    (void)src; (void)dst;
    return 0;
}

static int memstor_restore_checkpoint(const char* src, const char* dst) {
    (void)src; (void)dst;
    return 0;
}

static int memstor_remove_checkpoint(const char* checkpoint) {
    (void)checkpoint;
    return 0;
}

static int memstor_get_state(void* state_buffer, size_t* size) {
    (void)state_buffer; (void)size;
    return 0;
}

static int memstor_set_state(void* state_buffer, size_t size) {
    (void)state_buffer; (void)size;
    return 0;
}

static int memstor_prepare_swap(void) {
    return 0;
}

static int memstor_finalize_swap(void) {
    return 0;
}

storage_ops_t memory_storage_ops = {
    .name               = "memory",
    .init               = memstor_init,
    .create_checkpoint  = memstor_create_checkpoint,
    .restore_checkpoint = memstor_restore_checkpoint,
    .remove_checkpoint  = memstor_remove_checkpoint,
    .get_state          = memstor_get_state,
    .set_state          = memstor_set_state,
    .prepare_swap       = memstor_prepare_swap,
    .finalize_swap      = memstor_finalize_swap,
};
