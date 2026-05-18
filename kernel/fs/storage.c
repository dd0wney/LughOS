#include "lugh.h"
#include "auditor.h"

/* Bounded global transaction log — NASA Power of Ten rule 2 (statically
 * determinable upper bound) and rule 5 (no dynamic allocation after init).
 *
 * Ring buffer of fixed depth TXN_LOG_ENTRIES. On full-ring write the
 * oldest entry is dropped, the local overflow counter is bumped, and
 * ipc_ring.overflow is bumped so the next auditor_tick() emits an
 * OVERFLOW telemetry record — piggybacking on the existing exporter
 * path keeps the cross-subsystem coupling to a single shared word
 * (ipc_ring.overflow), no new auditor API.
 *
 * Power-of-2 capacity → index math is a bitwise AND, no modulo. */

#define TXN_LOG_ENTRIES 256u

static txn_log_entry_t txn_log[TXN_LOG_ENTRIES];
static volatile uint32_t txn_log_head     = 0u;  /* next write slot */
static volatile uint32_t txn_log_tail     = 0u;  /* oldest still live */
static uint32_t          txn_log_overflow = 0u;  /* drops since reset */

/* Read-only accessors used by tests in kernel/main.c. */
uint32_t txn_log_get_overflow(void) { return txn_log_overflow; }
uint32_t txn_log_get_depth(void)    { return txn_log_head - txn_log_tail; }

/* JPL Rule 13: Limited scope for data and functions
 * SEI CERT DCL30-C: Declare objects with appropriate storage duration */
int log_transaction(txn_log_entry_t* entry) {
    /* JPL Rule 15: validate parameters at entry. */
    if (entry == NULL) {
        return -1;
    }

    /* Full when (head - tail) == capacity. Drop oldest by advancing tail. */
    const uint32_t depth = txn_log_head - txn_log_tail;
    if (depth >= TXN_LOG_ENTRIES) {
        txn_log_tail++;          /* drop oldest */
        txn_log_overflow++;      /* bump local counter — test reads this */
        ipc_ring.overflow++;     /* surface to auditor — emits OVERFLOW on next tick */
    }

    /* Stamp owner if not already set. current_task may be NULL during
     * very early boot; 0 ("no task") is the documented sentinel. */
    if (entry->task_id == 0u && current_task != NULL) {
        entry->task_id = current_task->task_id;
    }

    txn_log[txn_log_head & (TXN_LOG_ENTRIES - 1u)] = *entry;
    txn_log_head++;
    return 0;
}
