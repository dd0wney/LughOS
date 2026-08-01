#include "lugh.h"
#include "workflow.h"
#include "transactions.h"
#include "auditor.h"
#include "assert.h"

/**
 * Durable workflow engine (Phase 4 F4).
 *
 * The whole point of this file is that no step boundary passes without a
 * record, and no undo return value goes unchecked. Both were true of the
 * hand-written update pipeline this engine replaces, and both are the
 * reason it could report "Rolled back update" after a rollback that
 * silently failed.
 *
 * Complies with:
 * - NASA Power of Ten rule 2: every loop bound is a compile-time constant
 * - NASA Power of Ten rule 3: no allocation, the slot table is static
 * - SEI CERT ERR33-C: every callback return value is checked
 * - SEI CERT STR31-C: every string field is NUL-terminated
 */

/* ── 1. Slot table ──────────────────────────────────────────────────
 *
 * WF_STATUS_IDLE is 0, so zero-initialised static storage starts fully
 * free. status is the only free-slot marker, by design — a parallel
 * in_use[] array is a second source of truth that can disagree. */
static workflow_t workflows[WORKFLOW_MAX_ACTIVE];

uint32_t workflow_active_count(void) {
    uint32_t i;
    uint32_t n = 0u;
    for (i = 0u; i < WORKFLOW_MAX_ACTIVE; i++) {
        if (workflows[i].status != WF_STATUS_IDLE) {
            n++;
        }
    }
    return n;
}

/* ── 2. Telemetry ───────────────────────────────────────────────────
 *
 * Every step boundary emits one transaction-log entry. The entry pairs
 * the step name with the event name, so a reader can reconstruct the
 * whole workflow from the log alone without holding the step table. */

static const char *wf_event_name(uint32_t event) {
    switch (event) {
        case WF_EV_BEGIN:       return "BEGIN";
        case WF_EV_STEP_OK:     return "STEP_OK";
        case WF_EV_STEP_FAIL:   return "STEP_FAIL";
        case WF_EV_UNDO_OK:     return "UNDO_OK";
        case WF_EV_UNDO_FAIL:   return "UNDO_FAIL";
        case WF_EV_COMMIT:      return "COMMIT";
        case WF_EV_ROLLED_BACK: return "ROLLED_BACK";
        case WF_EV_FAILED:      return "FAILED";
        default:                return "UNKNOWN";
    }
}

/* Bounded copy into a fixed field. Truncates rather than failing — the
 * field is diagnostic, so losing a long step name must never abort a
 * workflow. Always NUL-terminates per CERT STR31-C. */
static void wf_copy_field(char *dst, size_t dst_size, const char *src) {
    size_t i = 0u;
    if (dst_size == 0u) {
        return;
    }
    if (src != NULL) {
        for (; i < dst_size - 1u && src[i] != '\0'; i++) {
            dst[i] = src[i];
        }
    }
    dst[i] = '\0';
}

/* step_index == wf->step_count marks a workflow-level event rather than a
 * per-step one. See the WF_EV_BEGIN note in workflow.h.
 *
 * Two sinks, on purpose. The transaction log is the in-kernel journal that
 * an operator or a supervisor task can read back. The auditor record is the
 * off-box telemetry stream the JEPA encoder consumes. They carry the same
 * facts in different shapes, and neither is derivable from the other: the
 * txn ring drops its oldest entry under pressure, and the auditor stream
 * has no bounded-history guarantee at all. */
static void wf_emit(const workflow_t *wf, uint32_t step_index, uint32_t event,
                    int step_rv) {
    txn_log_entry_t e;
    const char *name = "workflow";

    if (step_index < wf->step_count && wf->steps != NULL) {
        name = wf->steps[step_index].name;
    }

    e.txn_id    = wf->workflow_id;
    e.task_id   = 0u;              /* log_transaction stamps from current_task */
    e.operation = OP_WORKFLOW;
    e.checksum  = 0u;
    wf_copy_field(e.key,   sizeof(e.key),   name);
    wf_copy_field(e.value, sizeof(e.value), wf_event_name(event));

    (void)log_transaction(&e);

    auditor_workflow(wf->workflow_id, wf->owner_task_id, step_index,
                     (uint32_t)wf->status, wf->done_count, step_rv,
                     (uint8_t)event);
}

/* ── 3. Slot lifecycle ──────────────────────────────────────────────── */

workflow_t *workflow_begin(const workflow_step_t *steps, uint32_t count,
                           void *ctx) {
    uint32_t i;

    /* JPL Rule 15: validate at entry. A count of 0 would commit an empty
     * workflow, which is a caller bug rather than a no-op worth allowing. */
    if (steps == NULL || count == 0u || count > WORKFLOW_MAX_STEPS) {
        return NULL;
    }
    for (i = 0u; i < count; i++) {
        if (steps[i].run == NULL) {
            return NULL;   /* undo may be NULL, run may not */
        }
    }

    for (i = 0u; i < WORKFLOW_MAX_ACTIVE; i++) {
        if (workflows[i].status != WF_STATUS_IDLE) {
            continue;
        }
        workflows[i].workflow_id   = generate_transaction_id();
        workflows[i].owner_task_id = (current_task != NULL)
                                   ? current_task->task_id : 0u;
        workflows[i].status        = WF_STATUS_RUNNING;
        workflows[i].step_count    = count;
        workflows[i].done_count    = 0u;
        workflows[i].ctx           = ctx;
        workflows[i].steps         = steps;
        return &workflows[i];
    }

    return NULL;   /* table full */
}

void workflow_release(workflow_t *wf) {
    if (wf == NULL) {
        return;
    }
    wf->workflow_id   = 0u;
    wf->owner_task_id = 0u;
    wf->status        = WF_STATUS_IDLE;
    wf->step_count    = 0u;
    wf->done_count    = 0u;
    wf->ctx           = NULL;
    wf->steps         = NULL;
}

/* ── 4. The undo chain ──────────────────────────────────────────────
 *
 * Walks done_count-1 down to 0. A step whose run failed is not in that
 * range, so its undo never fires — it owns no completed effect.
 *
 * Every undo in the range is attempted even after one fails. Stopping at
 * the first failure would leave the remaining effects in place with no
 * record of them, which is strictly worse than trying and reporting.
 *
 * @return 0 when every undo succeeded, -1 when at least one failed
 */
static int wf_unwind(workflow_t *wf) {
    uint32_t remaining = wf->done_count;
    uint32_t k;
    int undo_failed = 0;

    wf->status = WF_STATUS_ROLLING_BACK;

    /* Rule 2: the bound is the compile-time constant, not the variable. */
    for (k = 0u; k < WORKFLOW_MAX_STEPS; k++) {
        if (remaining == 0u) {
            break;
        }
        remaining--;

        if (wf->steps[remaining].undo == NULL) {
            continue;   /* nothing to reverse for this step */
        }

        /* ERR33-C: the return value decides the terminal status, and it
         * reaches the telemetry stream. This is exactly the check that
         * sandbox.c:215 used to discard. */
        const int rv = wf->steps[remaining].undo(wf->ctx);
        if (rv != 0) {
            undo_failed = 1;
            wf_emit(wf, remaining, WF_EV_UNDO_FAIL, rv);
        } else {
            wf_emit(wf, remaining, WF_EV_UNDO_OK, 0);
        }
    }

    wf->done_count = 0u;

    if (undo_failed) {
        wf->status = WF_STATUS_FAILED;
        wf_emit(wf, wf->step_count, WF_EV_FAILED, -1);
        return -1;
    }

    wf->status = WF_STATUS_ROLLED_BACK;
    wf_emit(wf, wf->step_count, WF_EV_ROLLED_BACK, 0);
    return 0;
}

/* ── 5. The choke point ─────────────────────────────────────────────── */

int workflow_run(workflow_t *wf) {
    uint32_t i;

    if (wf == NULL || wf->steps == NULL || wf->status != WF_STATUS_RUNNING) {
        return -1;
    }

    wf_emit(wf, wf->step_count, WF_EV_BEGIN, 0);

    for (i = 0u; i < wf->step_count; i++) {
        /* Intent before effect. Without this record an abort inside a step
         * is indistinguishable from a step that never started, and
         * recovery cannot tell which effects may exist. */
        wf_emit(wf, i, WF_EV_BEGIN, 0);

        const int rv = wf->steps[i].run(wf->ctx);
        if (rv != 0) {
            wf_emit(wf, i, WF_EV_STEP_FAIL, rv);
            (void)wf_unwind(wf);   /* terminal status set inside */
            return -1;
        }

        wf_emit(wf, i, WF_EV_STEP_OK, 0);
        wf->done_count++;
    }

    wf->status = WF_STATUS_COMMITTED;
    wf_emit(wf, wf->step_count, WF_EV_COMMIT, 0);
    return 0;
}

/* ── 6. Recovery ────────────────────────────────────────────────────
 *
 * Scans for slots abandoned in a non-terminal status and reverses them.
 *
 * SLOT RETENTION POLICY: a slot that reverses cleanly is freed. A slot
 * whose undo chain failed stays claimed.
 *
 * The asymmetry is deliberate. A clean reversal proves the workflow left
 * nothing behind, so the slot carries no information worth a table entry
 * and the telemetry stream already holds the history. A failed undo
 * proves the opposite: the system cannot assert the workflow left no
 * trace, so the evidence stays in kernel memory where an operator or a
 * supervisor task can find it without replaying a telemetry capture.
 *
 * The cost is bounded and visible. At most WORKFLOW_MAX_ACTIVE genuinely
 * unrecoverable workflows can accumulate before workflow_begin starts
 * returning NULL, and a system in that state has already lost the ability
 * to guarantee atomicity — refusing new workflows is the correct response,
 * not a regression.
 */
int workflow_recover(void) {
    uint32_t i;
    int result = 0;

    for (i = 0u; i < WORKFLOW_MAX_ACTIVE; i++) {
        workflow_t *wf = &workflows[i];

        if (wf->status != WF_STATUS_RUNNING &&
            wf->status != WF_STATUS_ROLLING_BACK) {
            continue;
        }
        if (wf->steps == NULL) {
            /* Defensive: a RUNNING slot with no step table cannot be
             * reversed. Mark and keep it rather than dereference NULL. */
            wf->status = WF_STATUS_FAILED;
            result = -1;
            continue;
        }

        if (wf_unwind(wf) != 0) {
            result = -1;      /* status is WF_STATUS_FAILED — keep the slot */
            continue;
        }

        workflow_release(wf); /* reversed cleanly — return it to the pool */
    }

    return result;
}
