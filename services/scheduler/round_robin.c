#include "lugh.h"

/* Fixed-size task table per NASA Power of Ten rule 3.
 * Smaller than MAX_TASKS (1024) — the scheduler only needs to track
 * runnable tasks, not every possible task ID in the system. */
#define RR_MAX_TASKS 64

static task_t rr_tasks[RR_MAX_TASKS];
static int    rr_task_count = 0;
static int    rr_cursor     = 0;   /* index of the last scheduled slot */

/* ── Internal helpers ─────────────────────────────────────────── */

static int rr_init(void *context) {
    (void)context;
    int i;
    for (i = 0; i < RR_MAX_TASKS; i++) {
        rr_tasks[i].task_id  = 0;
        rr_tasks[i].priority = 0;
        rr_tasks[i].state    = TASK_TERMINATED;
        rr_tasks[i].deadline = 0;
        rr_tasks[i]._padding1 = 0;
    }
    rr_task_count = 0;
    rr_cursor     = 0;
    log_message(LOG_INFO, "Scheduler: round-robin initialised (capacity=%d)\n",
                RR_MAX_TASKS);
    return 0;
}

/* Advance to the next READY task in round-robin order.
 * If tasks/num_tasks are non-NULL the caller's array is used; otherwise
 * the internal table is used.  The previously RUNNING task is set back
 * to READY so it re-enters the rotation next tick. */
static int rr_schedule(task_t *tasks, int num_tasks, uint32_t *next_task_id) {
    if (!next_task_id) return -1;

    task_t *t = (tasks && num_tasks > 0) ? tasks : rr_tasks;
    int     n = (tasks && num_tasks > 0) ? num_tasks : rr_task_count;

    if (n <= 0) return -1;

    /* Yield: mark the current RUNNING task back to READY */
    int i;
    for (i = 0; i < n; i++) {
        if (t[i].state == (uint64_t)TASK_RUNNING)
            t[i].state = TASK_READY;
    }

    /* Advance cursor, scanning up to n slots for the next READY task */
    int checked;
    for (checked = 0; checked < n; checked++) {
        rr_cursor = (rr_cursor + 1) % n;
        if (t[rr_cursor].state == (uint64_t)TASK_READY) {
            t[rr_cursor].state = TASK_RUNNING;
            *next_task_id = t[rr_cursor].task_id;
            return 0;
        }
    }

    return -1;  /* no READY tasks */
}

static int rr_add_task(task_t *task) {
    if (!task) return -1;
    if (rr_task_count >= RR_MAX_TASKS) {
        log_message(LOG_ERROR, "Scheduler: task table full (%d)\n", RR_MAX_TASKS);
        return -1;
    }
    /* Reject duplicate task_id */
    int i;
    for (i = 0; i < rr_task_count; i++) {
        if (rr_tasks[i].task_id == task->task_id) {
            log_message(LOG_WARNING, "Scheduler: task %u already registered\n",
                        task->task_id);
            return -1;
        }
    }
    rr_tasks[rr_task_count++] = *task;
    log_message(LOG_DEBUG, "Scheduler: added task %u (priority=%d)\n",
                task->task_id, task->priority);
    return 0;
}

static int rr_remove_task(uint32_t task_id) {
    int i;
    for (i = 0; i < rr_task_count; i++) {
        if (rr_tasks[i].task_id == task_id) {
            int last = --rr_task_count;
            rr_tasks[i] = rr_tasks[last];
            rr_tasks[last].state = TASK_TERMINATED;
            /* Keep cursor in bounds after compaction */
            if (rr_task_count > 0 && rr_cursor >= rr_task_count)
                rr_cursor = rr_task_count - 1;
            log_message(LOG_DEBUG, "Scheduler: removed task %u\n", task_id);
            return 0;
        }
    }
    log_message(LOG_WARNING, "Scheduler: task %u not found\n", task_id);
    return -1;
}

/* Serialise internal state into buf for hot-swap handoff.
 * Layout: [count:4][cursor:4][task_0..task_n] */
static int rr_get_state(void *buf, size_t *size) {
    if (!buf || !size) return -1;
    size_t needed = sizeof(int) * 2 + (size_t)rr_task_count * sizeof(task_t);
    if (*size < needed) { *size = needed; return -1; }

    uint8_t *p = (uint8_t *)buf;
    int i;

    /* write count */
    for (i = 0; i < (int)sizeof(int); i++)
        p[i] = ((uint8_t *)&rr_task_count)[i];
    p += sizeof(int);

    /* write cursor */
    for (i = 0; i < (int)sizeof(int); i++)
        p[i] = ((uint8_t *)&rr_cursor)[i];
    p += sizeof(int);

    /* write tasks */
    int j;
    for (j = 0; j < rr_task_count; j++) {
        for (i = 0; i < (int)sizeof(task_t); i++)
            p[i] = ((uint8_t *)&rr_tasks[j])[i];
        p += sizeof(task_t);
    }
    *size = needed;
    return 0;
}

static int rr_set_state(void *buf, size_t size) {
    if (!buf || size < sizeof(int) * 2) return -1;

    uint8_t *p = (uint8_t *)buf;
    int i;

    int count, cursor;
    for (i = 0; i < (int)sizeof(int); i++) ((uint8_t *)&count)[i]  = p[i];
    p += sizeof(int);
    for (i = 0; i < (int)sizeof(int); i++) ((uint8_t *)&cursor)[i] = p[i];
    p += sizeof(int);

    if (count < 0 || count > RR_MAX_TASKS) return -1;
    if (size < sizeof(int) * 2 + (size_t)count * sizeof(task_t)) return -1;

    rr_task_count = count;
    rr_cursor     = cursor;
    int j;
    for (j = 0; j < count; j++) {
        for (i = 0; i < (int)sizeof(task_t); i++)
            ((uint8_t *)&rr_tasks[j])[i] = p[i];
        p += sizeof(task_t);
    }
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
