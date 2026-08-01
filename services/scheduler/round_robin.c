#include "lugh.h"

/* Round-robin scheduler. Phase 3 A1: this used to maintain a private
 * `rr_tasks[RR_MAX_TASKS]` copy of the task data; that table was
 * disconnected from `kernel/sched/task.c`'s authoritative `tasks[]`,
 * which meant state changes by `create_task()` were invisible to the
 * scheduler and vice versa. Now we operate directly on the kernel
 * table via `task_table()` / `task_table_count()`. The only state
 * the scheduler still owns is the round-robin cursor. */

/* Upper bound check; not a storage backing. */
#define RR_MAX_TASKS 64

static int rr_cursor = 0;       /* index into task_table() of the last scheduled slot */

/* ── Internal helpers ─────────────────────────────────────────── */

static int rr_init(void *context) {
    (void)context;
    rr_cursor = 0;
    log_message(LOG_INFO,
        "Scheduler: round-robin initialised (operates on kernel task table, max=%d)\n",
        RR_MAX_TASKS);
    return 0;
}

/* Advance to the next READY task in round-robin order. If tasks/num_tasks
 * are non-NULL the caller's array is used (legacy callers); otherwise the
 * kernel task table is used. The previously RUNNING task is set back to
 * READY so it re-enters the rotation next tick. */
static int rr_schedule(task_t *tasks, int num_tasks, uint32_t *next_task_id) {
    if (!next_task_id) return -1;

    task_t *t = (tasks && num_tasks > 0) ? tasks : task_table();
    int     n = (tasks && num_tasks > 0) ? num_tasks : task_table_count();

    if (n <= 0) return -1;

    /* Yield: mark any RUNNING tasks back to READY */
    int i;
    for (i = 0; i < n; i++) {
        if (t[i].state == (uint64_t)TASK_RUNNING)
            t[i].state = TASK_READY;
    }

    /* Advance cursor, scanning up to n slots for the next READY task */
    int checked;
    for (checked = 0; checked < n; checked++) {
        rr_cursor = (rr_cursor + 1 >= n) ? 0 : rr_cursor + 1;
        if (t[rr_cursor].state == (uint64_t)TASK_READY) {
            t[rr_cursor].state = TASK_RUNNING;
            *next_task_id = t[rr_cursor].task_id;
            return 0;
        }
    }

    return -1;  /* no READY tasks */
}

/* The task is already in the kernel table (placed there by create_task);
 * the scheduler's only job here is to log and apply any policy decision
 * about whether the task should run. For now we accept everything that
 * fits within the RR_MAX_TASKS budget. */
static int rr_add_task(task_t *task) {
    if (!task) return -1;
    if (task_table_count() > RR_MAX_TASKS) {
        log_message(LOG_ERROR, "Scheduler: task table over budget (%d > %d)\n",
                    task_table_count(), RR_MAX_TASKS);
        return -1;
    }
    log_message(LOG_DEBUG, "Scheduler: added task %u (priority=%d)\n",
                task->task_id, task->priority);
    return 0;
}

/* Mark the task TERMINATED in the kernel table. The slot stays occupied
 * (kernel table is append-only by current design) but the scheduler
 * walker will skip it because TERMINATED != READY. */
static int rr_remove_task(uint32_t task_id) {
    task_t *t = task_find(task_id);
    if (!t) {
        log_message(LOG_WARNING, "Scheduler: task %u not found\n", task_id);
        return -1;
    }
    t->state = TASK_TERMINATED;
    /* Keep cursor in bounds if removal shrunk the schedulable set */
    int n = task_table_count();
    if (n > 0 && rr_cursor >= n) rr_cursor = n - 1;
    log_message(LOG_DEBUG, "Scheduler: removed task %u\n", task_id);
    return 0;
}

/* Serialise scheduler state for hot-swap handoff. The kernel task
 * table is owned by task.c and isn't dumped here — Phase 3 A1
 * narrowed `get_state` to just the round-robin cursor. */
static int rr_get_state(void *buf, size_t *size) {
    if (!buf || !size) return -1;
    size_t needed = sizeof(int);
    if (*size < needed) { *size = needed; return -1; }
    uint8_t *p = (uint8_t *)buf;
    int i;
    for (i = 0; i < (int)sizeof(int); i++)
        p[i] = ((uint8_t *)&rr_cursor)[i];
    *size = needed;
    return 0;
}

static int rr_set_state(void *buf, size_t size) {
    if (!buf || size < sizeof(int)) return -1;
    uint8_t *p = (uint8_t *)buf;
    /* Initialised even though the loop below writes every byte of it.
     * cppcheck cannot follow the byte-wise write through the cast and
     * reports uninitvar at the read on the next line. The initialiser
     * costs nothing, the loop overwrites it, and defensive
     * initialisation is what the JPL rules ask for anyway. */
    int cursor = 0;
    int i;
    for (i = 0; i < (int)sizeof(int); i++)
        ((uint8_t *)&cursor)[i] = p[i];
    rr_cursor = cursor;
    return 0;
}

static int rr_prepare_swap(void)  { return 0; }
static int rr_finalize_swap(void) { return 0; }

/* ── Public scheduler_ops_t instance ─────────────────────────── */

scheduler_ops_t rr_scheduler = {
    .name         = "Round Robin",
    .init         = rr_init,
    .schedule     = rr_schedule,
    .add_task     = rr_add_task,
    .remove_task  = rr_remove_task,
    .get_state    = rr_get_state,
    .set_state    = rr_set_state,
    .prepare_swap = rr_prepare_swap,
    .finalize_swap = rr_finalize_swap,
};
