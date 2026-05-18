#include "lugh.h"
#include "capabilities.h"

/* Static task table per NASA Power of Ten rule 5 (no dynamic allocation
 * after init) and rule 2 (statically determinable upper bound). */
static task_t tasks[MAX_TASKS];
static uint32_t task_count = 0;

/* Root-of-trust identity. Set by task_init() before init_ipc() so every
 * channel created during boot has a non-NULL owner. */
static task_t kernel_task;
task_t* current_task = NULL;

/* Monotonic task-id allocator. Task id 0 is reserved as "no task".
 * Wraps deterministically — the table is sized MAX_TASKS so id reuse
 * after a full cycle is acceptable for this MVP. */
static uint32_t next_task_id = 1u;
static uint32_t allocate_task_id(void) {
    uint32_t id = next_task_id;
    next_task_id = (next_task_id == 0xFFFFFFFFu) ? 1u : (next_task_id + 1u);
    return id;
}

void task_init(void) {
    /* Boot the root task: CAP_ALL in domain 0. Bootstrap IPC (auditor,
     * scheduler channels) runs under this identity. */
    kernel_task.task_id  = allocate_task_id();
    kernel_task.priority = 0;
    kernel_task.cap_mask = CAP_ALL;
    kernel_task.domain   = 0u;
    kernel_task.state    = TASK_RUNNING;
    kernel_task.deadline = 0u;
    current_task = &kernel_task;
    log_message(LOG_INFO,
        "Task subsystem: kernel_task ready (id=%u, caps=0x%X, domain=%u)\n",
        kernel_task.task_id, kernel_task.cap_mask, kernel_task.domain);
}

/* create_task: install a new task into the table.
 *
 * Capability inheritance is BOUNDED NARROWING — the new task receives
 * (spec->cap_mask & current_task->cap_mask). The caller can request
 * any subset of the parent's caps and will get exactly that, but
 * cannot widen beyond what the parent holds. This is the Capsicum
 * invariant: no descendant ever acquires a cap the root didn't grant.
 *
 * Cross-domain task creation additionally requires CAP_CROSS_DOMAIN
 * in the parent, mirroring the ipc_connect rule.
 *
 * spec is mutated on success: task_id, cap_mask, state are written back
 * so the caller can use spec as the live task descriptor. */
int create_task(task_t* spec) {
    if (spec == NULL) {
        log_message(LOG_ERROR, "create_task: NULL spec\n");
        return -1;
    }
    if (current_task == NULL) {
        log_message(LOG_ERROR, "create_task: task_init not called\n");
        return -2;
    }
    if (task_count >= MAX_TASKS) {
        log_message(LOG_ERROR, "create_task: table full (%u)\n",
            (unsigned int)MAX_TASKS);
        return -3;
    }
    if (spec->domain != current_task->domain &&
        !(current_task->cap_mask & CAP_CROSS_DOMAIN)) {
        log_message(LOG_ERROR,
            "create_task: cross-domain denied (parent_dom=%u, child_dom=%u)\n",
            current_task->domain, spec->domain);
        return -4;
    }

    uint32_t effective_caps = spec->cap_mask & current_task->cap_mask;
    if (effective_caps != spec->cap_mask) {
        log_message(LOG_WARNING,
            "create_task: caps narrowed 0x%X -> 0x%X (parent=0x%X)\n",
            spec->cap_mask, effective_caps, current_task->cap_mask);
    }

    task_t* t = &tasks[task_count++];
    t->task_id  = allocate_task_id();
    t->priority = spec->priority;
    t->cap_mask = effective_caps;
    t->domain   = spec->domain;
    t->state    = TASK_READY;
    t->deadline = spec->deadline;

    /* Mirror the assigned values back into spec so the caller can use
     * it as the task descriptor without re-fetching from the table. */
    spec->task_id  = t->task_id;
    spec->cap_mask = t->cap_mask;
    spec->state    = t->state;

    log_message(LOG_INFO,
        "Created task id=%u priority=%d caps=0x%X domain=%u\n",
        t->task_id, t->priority, t->cap_mask, t->domain);
    return 0;
}
