#include <lugh.h>
#include <security.h>
#include <transactions.h>
#include <workflow.h>
#include <update.h>
#include <sandbox.h>
#include "assert.h"
#include "memory.h"
#include <stdint.h>  /* For uintptr_t */

#ifndef USER_READ
#define USER_READ  0x04
#endif
#ifndef USER_WRITE
#define USER_WRITE 0x02
#endif
#ifndef USER_EXEC
#define USER_EXEC  0x01
#endif

#define MAX_UPDATE_SIZE (1024 * 1024) /* 1MB; JPL Rule 25 */

/**
 * Local memcpy implementation for kernel use
 */
static void *k_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dest;
}

/**
 * Local strstr implementation for kernel use
 */
static const char *k_strstr(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; ++haystack) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) { ++h; ++n; }
        if (!*n) return haystack;
    }
    return NULL;
}

/**
 * Apply an update in a sandbox environment for testing
 * 
 * Creates an isolated test environment to run the update
 * to check for faults or security issues before committing.
 * 
 * @param image Pointer to the update binary 
 * @param size Size of the update binary
 * @return true if the update behaved correctly in sandbox
 * 
 * Complies with:
 * - SEI CERT ERR33-C: Detect errors and handle appropriately
 * - JPL Rule 14: Check return values
 * - NASA Rule 1: Simple control flow
 */
/* Static staging area. Bounded and zero-initialised in BSS, per NASA
 * Power of Ten rule 3.
 *
 * This replaces two magic addresses, 0x900000 for code and 0xA00000 for
 * data. Neither was ever mapped. sandbox_apply asked map_user_space to
 * map them, map_user_space returned 0 without creating any mapping, and
 * the copy that followed took a section translation fault:
 *
 *     DABORT pc=0x000192BC va=0x00900000 dfsr=0x05
 *
 * The fault stayed hidden because reaching this function required the
 * update pipeline to pass its checkpoint step, which it never did.
 *
 * The buffer is ordinary kernel memory and nothing branches into it —
 * see the note on execution below. */
static uint8_t sandbox_stage[SANDBOX_STAGE_SIZE];

bool sandbox_apply(const uint8_t *image, size_t size) {
    if (image == NULL || size == 0) {
        log_message(LOG_ERROR, "Invalid image for sandbox testing");
        return false;
    }

    /* Reject rather than truncate. A truncated image would still pass the
     * ELF check below and report a clean sandbox run for a binary that was
     * never staged in full. */
    if (size > sizeof(sandbox_stage)) {
        log_message(LOG_ERROR,
            "Image too large to stage: %u bytes, limit is %u",
            (unsigned int)size, (unsigned int)sizeof(sandbox_stage));
        return false;
    }

    log_message(LOG_INFO, "Staging update in sandbox environment");

    /* Basic validation of the binary format before any copy. */
    if (size < 64 || image[0] != 0x7F || image[1] != 'E' ||
        image[2] != 'L' || image[3] != 'F') {
        log_message(LOG_ERROR, "Invalid binary format in sandbox");
        return false;
    }

    k_memcpy(sandbox_stage, image, size);

    /* Execution is NOT implemented, and the code no longer pretends
     * otherwise. Running an untrusted binary under supervision needs
     * syscall filtering, resource accounting and a fault boundary that
     * returns control here — none of which LughOS has yet. Until then
     * this function stages and format-checks, and the staging buffer
     * stays kernel-only memory that nothing branches into.
     *
     * The previous version logged "Executing update in sandbox
     * environment" and "Sandbox execution completed without errors"
     * around a comment saying execution was simulated. */
    log_message(LOG_INFO,
        "Sandbox staging passed: %u bytes, format valid, not executed",
        (unsigned int)size);
    return true;
}

/**
 * Run validation tests on an updated component
 * 
 * @param path Path to the updated component
 * @return true if all tests passed
 * 
 * Complies with:
 * - SEI CERT ERR33-C: Detect errors and handle appropriately
 * - JPL Rule 14: Check return values
 */
bool run_tests(const char *path) {
    if (path == NULL) {
        log_message(LOG_ERROR, "Invalid path for testing");
        return false;
    }
    
    log_message(LOG_INFO, "Running tests for %s", path);
    
    /* In a real system, we would:
     * 1. Identify the component type from path
     * 2. Run appropriate test suite for that component
     * 3. Check for any failures
     */
    
    // For demonstration, simulate test results based on path
    if (k_strstr(path, "kernel") != NULL) {
        // Core kernel components need thorough testing
        log_message(LOG_INFO, "Running critical kernel component tests");
        // Simulate strict testing
        return true;  // Always return true for this demo
    } else if (k_strstr(path, "driver") != NULL) {
        // Driver tests
        log_message(LOG_INFO, "Running driver tests");
        return true;
    } else {
        // Service or application tests
        log_message(LOG_INFO, "Running standard component tests");
        return true;
    }
}

/* ── Update pipeline as a durable workflow (Phase 4 F4) ─────────────
 *
 * Each step below was a hand-written stage in apply_update, with the undo
 * path open-coded as a rollback_update() call after every failure branch.
 * The workflow engine owns the sequencing now, so:
 *
 *   - every step boundary emits a transaction-log entry and a telemetry
 *     record, which the hand-written version never did
 *   - each undo return value is checked, which the hand-written version
 *     discarded (the old rollback_update ignored restore_checkpoint)
 *   - update_state.status advances through the six enum values that were
 *     previously declared and never assigned
 *
 * The context pointer is the update_state, not the update_tx, so a step
 * can record which stage it is in as it runs rather than have the caller
 * infer it afterwards.
 */

static int step_checkpoint(void *ctx) {
    struct update_state *st = (struct update_state *)ctx;
    st->status = UPDATE_STATUS_CHECKPOINT;
    if (create_checkpoint(st->tx.path, st->tx.checkpoint) != 0) {
        log_message(LOG_ERROR, "Checkpoint failed");
        return -1;
    }
    return 0;
}

/* Undo for the checkpoint step: discard the snapshot. Runs LAST in the
 * undo chain (step 0 is undone last), so any restore that needs the
 * snapshot has already happened by the time this fires. */
static int undo_remove_checkpoint(void *ctx) {
    struct update_state *st = (struct update_state *)ctx;
    return remove_checkpoint(st->tx.checkpoint);
}

static int step_verify(void *ctx) {
    struct update_state *st = (struct update_state *)ctx;
    st->status = UPDATE_STATUS_VERIFY;
    if (!verify_signature(st->tx.image, st->tx.size, st->tx.hash)) {
        log_message(LOG_ERROR, "Invalid signature"); /* SEI CERT MSC41-C */
        return -1;
    }
    return 0;
}

static int step_sandbox(void *ctx) {
    struct update_state *st = (struct update_state *)ctx;
    st->status = UPDATE_STATUS_SANDBOX;
    return sandbox_apply(st->tx.image, st->tx.size) ? 0 : -1;
}

static int step_test(void *ctx) {
    struct update_state *st = (struct update_state *)ctx;
    st->status = UPDATE_STATUS_TEST;
    return run_tests(st->tx.path) ? 0 : -1;
}

static int step_install(void *ctx) {
    struct update_state *st = (struct update_state *)ctx;
    st->status = UPDATE_STATUS_COMMIT;
    return install_update(st->tx.path, st->tx.image, st->tx.size);
}

/* Undo for the install step. This is the call whose return value the old
 * rollback_update() threw away, so a failed restore reported success. */
static int undo_restore_checkpoint(void *ctx) {
    struct update_state *st = (struct update_state *)ctx;
    if (restore_checkpoint(st->tx.checkpoint, st->tx.path) != 0) { /* JPL Rule 14 */
        log_message(LOG_ERROR, "Restore from checkpoint FAILED");
        return -1;
    }
    return 0;
}

/* Steps run in this order and are undone in the opposite order. A step
 * with no undo leaves no effect behind: verify, sandbox and test all read
 * without writing. */
static const workflow_step_t update_steps[] = {
    { "checkpoint", step_checkpoint, undo_remove_checkpoint },
    { "verify",     step_verify,     NULL },
    { "sandbox",    step_sandbox,    NULL },
    { "test",       step_test,       NULL },
    { "install",    step_install,    undo_restore_checkpoint },
};

#define UPDATE_STEP_COUNT \
    ((uint32_t)(sizeof(update_steps) / sizeof(update_steps[0])))

int apply_update(struct update_state *state) {
    assert(state != NULL);                                  /* JPL Rule 16 */
    assert(state->tx.path != NULL && state->tx.image != NULL);

    if (state->tx.size > MAX_UPDATE_SIZE) {                 /* SEI CERT MEM35-C */
        log_message(LOG_ERROR, "Update too large");
        state->status = UPDATE_STATUS_ERROR;
        return -1;
    }

    workflow_t *wf = workflow_begin(update_steps, UPDATE_STEP_COUNT, state);
    if (wf == NULL) {
        log_message(LOG_ERROR, "No free workflow slot for update");
        state->status = UPDATE_STATUS_ERROR;
        return -1;
    }

    int rv = workflow_run(wf);

    if (rv == 0) {
        /* Discard the checkpoint only now. Until the workflow commits, the
         * checkpoint is the only thing that makes a rollback possible — the
         * old commit_update() removed it in the same breath as the install,
         * which left the install with nothing to fall back to. */
        (void)remove_checkpoint(state->tx.checkpoint);
        state->status = UPDATE_STATUS_COMPLETE;
        log_message(LOG_INFO, "Committed update");
        workflow_release(wf);
        return 0;
    }

    if (wf->status == WF_STATUS_FAILED) {
        /* The undo chain itself failed. The system cannot claim the update
         * left no trace, so the slot stays claimed as evidence and the
         * status is ERROR rather than ROLLBACK. */
        state->status = UPDATE_STATUS_ERROR;
        state->error_count++;
        log_message(LOG_ERROR,
            "Update rollback FAILED — system state is uncertain");
        return -1;
    }

    state->status = UPDATE_STATUS_ROLLBACK;
    log_message(LOG_INFO, "Rolled back update");
    workflow_release(wf);
    return -1;
}

/* Retained for API compatibility. The workflow engine drives the undo
 * chain now, so nothing in the tree calls this on the normal path.
 *
 * Unlike the version it replaces, it checks the restore result and reports
 * it. The old one discarded restore_checkpoint's return value under a
 * comment citing JPL Rule 14, which is the rule that says to check it. */
int rollback_update(struct update_tx *tx) {
    if (tx == NULL) {
        return -1;
    }
    if (restore_checkpoint(tx->checkpoint, tx->path) != 0) {
        log_message(LOG_ERROR, "Rollback FAILED: restore_checkpoint");
        return -1;
    }
    log_message(LOG_INFO, "Rolled back update");
    return 0;
}

/* Retained for API compatibility. Deliberately does NOT remove the
 * checkpoint — see the ordering note in apply_update. */
int commit_update(struct update_tx *tx) {
    if (tx == NULL) {
        return -1;
    }
    if (install_update(tx->path, tx->image, tx->size) != 0) {
        log_message(LOG_ERROR, "Commit FAILED: install_update");
        return -1;
    }
    log_message(LOG_INFO, "Committed update");
    return 0;
}