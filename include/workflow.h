#ifndef WORKFLOW_H
#define WORKFLOW_H

/**
 * Durable workflow engine for LughOS (Phase 4 F4)
 *
 * Runs an ordered list of steps as one unit. If a step fails, the engine
 * reverses every step that already completed, in the opposite order. The
 * three properties it provides, borrowed from DBOS:
 *
 *   transactional  every step boundary emits a transaction-log record
 *   durable        a completed step is recorded before the next one starts
 *   atomic         the workflow commits, or it looks like it never started
 *
 * SCOPE OF "DURABLE": the workflow table is static kernel memory, and the
 * checkpoint slots behind it live in RAM only (services/storage/transactions.c
 * — "No persistence, lives only across a kernel boot"). So workflow_recover()
 * reverses a workflow that a fault or a failed step abandoned WITHIN one
 * session. It is not crash recovery across a power cycle. It becomes crash
 * recovery unchanged once a persistent storage_ops_t backend exists.
 *
 * Complies with:
 * - NASA Power of Ten rule 2: every loop has a statically determinable bound
 * - NASA Power of Ten rule 3: no dynamic allocation
 * - SEI CERT ERR33-C: every undo return value is checked, never discarded
 */

#include <stdint.h>
#include <stddef.h>

/* Bounded sizing. Rule 2: both tables are fixed-length arrays. */
#define WORKFLOW_MAX_STEPS   8u
#define WORKFLOW_MAX_ACTIVE  4u

/* Terminal statuses are COMMITTED, ROLLED_BACK and FAILED.
 *
 * WF_STATUS_IDLE is 0 so a static workflow table starts out entirely free.
 * The status field is the single free-slot marker — there is deliberately
 * no parallel in_use[] array that could disagree with it.
 *
 * WF_STATUS_FAILED means the undo chain itself failed. The system cannot
 * assert that the workflow left no effect behind, so this status needs an
 * operator. It is not the same as ROLLED_BACK. */
typedef enum {
    WF_STATUS_IDLE = 0,
    WF_STATUS_RUNNING,
    WF_STATUS_COMMITTED,
    WF_STATUS_ROLLING_BACK,
    WF_STATUS_ROLLED_BACK,
    WF_STATUS_FAILED
} workflow_status_t;

/* Telemetry event subtypes. Packed into the auditor record's `protocol`
 * byte, and used as the transaction-log value string.
 *
 * WF_EV_BEGIN serves two roles, told apart by the step index that
 * accompanies it: an index inside [0, step_count) is a per-step intent
 * record written BEFORE that step runs. An index equal to step_count is
 * the workflow-level begin record. The intent record is what makes a
 * step recoverable — without it, an abort mid-step is indistinguishable
 * from a step that never started. */
#define WF_EV_BEGIN        0u
#define WF_EV_STEP_OK      1u
#define WF_EV_STEP_FAIL    2u
#define WF_EV_UNDO_OK      3u
#define WF_EV_UNDO_FAIL    4u
#define WF_EV_COMMIT       5u
#define WF_EV_ROLLED_BACK  6u
#define WF_EV_FAILED       7u

/* A step callback. Returns 0 on success and non-zero on failure. The
 * same signature serves for run and undo, so a step's undo can be
 * another step's run. */
typedef int (*workflow_fn)(void *ctx);

/* One step of a workflow.
 *
 * undo == NULL means the step leaves no effect to reverse. A pure check
 * such as a signature verification is the usual case. It is NOT a way to
 * say "this step cannot be undone" — a step with an irreversible effect
 * must not be placed after a step that may fail. */
typedef struct {
    const char  *name;   /* diagnostic label, copied into the txn-log key */
    workflow_fn  run;
    workflow_fn  undo;   /* NULL = no effect to reverse */
} workflow_step_t;

/* A workflow instance. The engine owns the storage — see workflow_begin.
 *
 * done_count is the undo cursor: the number of steps whose run returned 0.
 * A step whose run failed is NOT counted, because it owns no completed
 * effect, so the engine must not call its undo. */
typedef struct {
    uint64_t               workflow_id;    /* from generate_transaction_id() */
    uint32_t               owner_task_id;  /* current_task at begin, or 0 */
    workflow_status_t      status;
    uint32_t               step_count;
    uint32_t               done_count;     /* the undo cursor */
    void                  *ctx;
    const workflow_step_t *steps;          /* caller-owned, must be static */
} workflow_t;

/**
 * Claim a workflow slot and put it in WF_STATUS_RUNNING.
 *
 * The engine owns the returned storage, and it stays valid until
 * workflow_release(). A caller-owned descriptor would be lost when its
 * frame goes away, which would leave workflow_recover() nothing to find.
 *
 * @param steps  step table; the caller must keep it alive for the whole
 *               workflow, so static storage is required
 * @param count  number of steps, 1 to WORKFLOW_MAX_STEPS
 * @param ctx    opaque context passed to every run and undo callback
 * @return slot pointer, or NULL on bad arguments or a full table
 */
workflow_t *workflow_begin(const workflow_step_t *steps, uint32_t count,
                           void *ctx);

/**
 * Run every step in sequence. On the first failure, reverse every step
 * that completed, in the opposite order.
 *
 * Terminal status is one of:
 *   WF_STATUS_COMMITTED   every step succeeded
 *   WF_STATUS_ROLLED_BACK a step failed and every undo succeeded
 *   WF_STATUS_FAILED      a step failed and at least one undo also failed
 *
 * @param wf slot from workflow_begin, in WF_STATUS_RUNNING
 * @return 0 only when the workflow committed, -1 otherwise
 */
int workflow_run(workflow_t *wf);

/**
 * Reverse every workflow left in a non-terminal status.
 *
 * Call once at boot, after auditor_init(), so the reversal records reach
 * the telemetry stream. A slot is non-terminal when a fault or a reset
 * abandoned it between workflow_begin and a terminal status.
 *
 * Slot retention: a workflow that reverses cleanly has its slot freed. A
 * workflow whose undo chain failed keeps its slot, in WF_STATUS_FAILED,
 * because the system cannot assert that it left no trace. At most
 * WORKFLOW_MAX_ACTIVE such workflows can accumulate before
 * workflow_begin starts refusing new work, which is the correct response
 * from a system that has lost its atomicity guarantee.
 *
 * @return 0 when every abandoned workflow reversed cleanly, -1 when any
 *         undo failed and left a slot in WF_STATUS_FAILED
 */
int workflow_recover(void);

/**
 * Return a slot to the free pool. Safe to call with NULL.
 *
 * Releasing a WF_STATUS_FAILED slot discards the record that the system
 * could not undo a workflow. Prefer to leave such a slot claimed until an
 * operator has seen it.
 */
void workflow_release(workflow_t *wf);

/* Read-only accessor for tests and introspection. Counts non-IDLE slots. */
uint32_t workflow_active_count(void);

#endif /* WORKFLOW_H */
