#include "lugh.h"
#include "capabilities.h"

/* Static task table per NASA Power of Ten rule 5 (no dynamic allocation
 * after init) and rule 2 (statically determinable upper bound). The
 * kernel task lives in slot 0 — Phase 3 A1 made this the single source
 * of truth so the scheduler doesn't maintain a parallel copy. */
static task_t tasks[MAX_TASKS];
static uint32_t task_count = 0;

/* Per-task kernel-mode stacks (Phase 3 A2). MAX_RUNNABLE caps how many
 * tasks can be concurrently schedulable; tasks created beyond that cap
 * get kernel_stack_top = 0 and are not eligible for context switching.
 * 8 × 16 KB = 128 KB static — comfortably bounded for an MVP, easy to
 * raise later if needed.
 *
 * 16-byte alignment matches AAPCS stack requirements on ARM (and is
 * over-aligned for x86, which is fine). */
#define MAX_RUNNABLE      8u
#define KERNEL_STACK_SIZE 16384u

static uint8_t kernel_stacks[MAX_RUNNABLE][KERNEL_STACK_SIZE]
    __attribute__((aligned(16)));

/* Assign the next available stack slot to a task. Returns the TOP
 * address (high end, since stacks grow down) or 0 if none free. */
static uint32_t assign_kernel_stack(uint32_t slot) {
    if (slot >= MAX_RUNNABLE) return 0u;
    return (uint32_t)(uintptr_t)&kernel_stacks[slot][KERNEL_STACK_SIZE];
}

/* current_task points into tasks[] above (NOT a free-standing static).
 * Same address as the scheduler walks, so context switches and cap
 * checks operate on identical state. */
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
    /* Boot the root task into tasks[0] with CAP_ALL in domain 0.
     * Everything subsequent (auditor, scheduler channels, user_init_task)
     * is created under this identity. The scheduler iterates tasks[]
     * including this slot, but kernel_task's state stays RUNNING so
     * the round-robin walker doesn't accidentally schedule it. */
    task_t* kt = &tasks[0];
    kt->task_id          = allocate_task_id();
    kt->priority         = 0;
    kt->cap_mask         = CAP_ALL;
    kt->domain           = 0u;
    kt->state            = TASK_RUNNING;
    kt->deadline         = 0u;
    kt->kernel_stack_top = assign_kernel_stack(0u);
    kt->_padding1        = 0u;
    task_count = 1u;
    current_task = kt;
    log_message(LOG_INFO,
        "Task subsystem: kernel_task ready (id=%u, caps=0x%X, domain=%u, stack_top=0x%X)\n",
        kt->task_id, kt->cap_mask, kt->domain, kt->kernel_stack_top);
}

/* ── Public accessors for the unified task table ──────────────────
 * The scheduler operates on this table directly (Phase 3 A1). */

task_t* task_table(void) {
    return tasks;
}

int task_table_count(void) {
    return (int)task_count;
}

task_t* task_find(uint32_t id) {
    if (id == 0u) return NULL;        /* 0 is reserved "no task" */
    for (uint32_t i = 0; i < task_count; i++) {
        if (tasks[i].task_id == id) return &tasks[i];
    }
    return NULL;
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

    uint32_t slot = task_count++;
    task_t* t = &tasks[slot];
    t->task_id          = allocate_task_id();
    t->priority         = spec->priority;
    t->cap_mask         = effective_caps;
    t->domain           = spec->domain;
    t->state            = TASK_READY;
    t->deadline         = spec->deadline;
    t->kernel_stack_top = assign_kernel_stack(slot);
    t->_padding1        = 0u;

    if (t->kernel_stack_top == 0u) {
        log_message(LOG_WARNING,
            "create_task: task %u exceeds MAX_RUNNABLE=%u; no kernel stack "
            "(task created but not schedulable until A4 lifecycle lands)\n",
            t->task_id, (unsigned int)MAX_RUNNABLE);
    }

    /* Mirror the assigned values back into spec so the caller can use
     * it as the task descriptor without re-fetching from the table. */
    spec->task_id          = t->task_id;
    spec->cap_mask         = t->cap_mask;
    spec->state            = t->state;
    spec->kernel_stack_top = t->kernel_stack_top;

    log_message(LOG_INFO,
        "Created task id=%u priority=%d caps=0x%X domain=%u stack_top=0x%X\n",
        t->task_id, t->priority, t->cap_mask, t->domain, t->kernel_stack_top);
    return 0;
}
