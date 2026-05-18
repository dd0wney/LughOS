#include "lugh.h"
#include "console.h"
#include "auditor.h"

/* Bootstrap IPC channel for user-mode SYS_IPC_SEND. Defined in main.c,
 * created at boot under user_init_task's identity with CAP_IPC_SEND.
 * Phase 3 routes every SYS_IPC_SEND through this single channel; the
 * channel-id is not in the syscall ABI yet. */
extern int user_bootstrap_channel;
int ipc_send(int channel_id, message_t *msg);

extern scheduler_ops_t rr_scheduler;


/**
 * System call handler for LughOS
 * 
 * Handles system calls from user mode programs.
 * 
 * @param num System call number
 * @param arg1 First argument 
 * @param arg2 Second argument
 * @param arg3 Third argument
 * 
 * Complies with:
 * - SEI CERT STR31-C: Guarantee null-terminated strings
 * - JPL Rule 6: Restrict length of data blocks
 * - NASA Rule 1: Simple control flow
 */
void syscall_handler(uint32_t num, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    /* Snapshot current_task at handler entry. Once Phase 3 A4 lands real
     * preemption, a PIT/SP804 tick can change current_task mid-handler.
     * Reading once into a local makes the handler's view of "who is
     * calling this syscall" stable for the duration of the call. */
    task_t* caller = current_task;
    (void)caller; /* used by SYS_EXIT / SYS_CREATE_TASK / SYS_YIELD below */
    switch (num) {
        case SYS_WRITE:
            // Console write system call
            // arg1 = buffer address, arg2 = length
            if (arg1 == 0) {
                log_message(LOG_ERROR, "SYS_WRITE: Null buffer pointer");
                return;
            }
            
            // Validate user pointer (should check if it's in user address space)
            if (arg1 < 0x400000 || arg1 > 0x7FFFFFFF) {
                log_message(LOG_ERROR, "SYS_WRITE: Buffer pointer outside user space");
                return;
            }
            
            // Limit length to prevent buffer overflows (JPL Rule 6)
            if (arg2 > 1024) {
                log_message(LOG_WARNING, "SYS_WRITE: Truncating large write request");
                arg2 = 1024;
            }
            
            // Write to console
#ifdef __riscv
            // Use uintptr_t for RISC-V (64-bit)
            console_write((const char*)(uintptr_t)arg1, arg2);
#else
            // Original 32-bit implementation
            console_write((const char*)arg1, arg2);
#endif
            break;
            
        case SYS_IPC_SEND: {
            // Route user IPC through the real subsystem so cap_mask
            // enforcement and auditor telemetry both fire.
            // arg1 = operation, arg2 = user-space message_t pointer.
            if (arg2 == 0) {
                log_message(LOG_ERROR, "SYS_IPC_SEND: Null message pointer");
                return;
            }
            if (arg2 < 0x400000 || arg2 > 0x7FFFFFFF) {
                log_message(LOG_ERROR, "SYS_IPC_SEND: Message pointer outside user space");
                return;
            }
            if (user_bootstrap_channel < 0) {
                log_message(LOG_ERROR, "SYS_IPC_SEND: bootstrap channel not initialized");
                return;
            }
#ifdef __riscv
            message_t* user_msg = (message_t*)(uintptr_t)arg2;
#else
            message_t* user_msg = (message_t*)arg2;
#endif
            user_msg->operation = arg1;
            user_msg->payload[MAX_MSG_SIZE - 1] = '\0';
            /* ipc_send computes checksum, stamps the channel context into
             * _padding1 for the auditor record, and gates on cap_mask. */
            int rv = ipc_send(user_bootstrap_channel, user_msg);
            if (rv == 0) {
                log_message(LOG_INFO,
                    "User IPC: op=0x%x sent on channel %d",
                    arg1, user_bootstrap_channel);
            } else {
                log_message(LOG_WARNING,
                    "User IPC: op=0x%x denied/failed (rv=%d)",
                    arg1, rv);
            }
            /* Drain the auditor ring so the MSG record we just pushed
             * reaches UART1 promptly. Without this, user IPC traffic
             * sits in the ring until process_events() runs from the
             * kernel idle loop — which on SYS_EXIT never happens
             * before QEMU terminates. Track A's preemptive scheduler
             * will drain on every tick; until then, drain inline. */
            auditor_tick();
            break;
        }
            
        case SYS_EXIT:
            /* Phase 3 A3 — mark the calling task TERMINATED and drop it
             * from the scheduler. The actual transition away from the
             * user-mode PC waits on A4's context switch; until then we
             * return from the syscall and the user code falls into
             * crt0's `b 1b` safety loop. */
            log_message(LOG_INFO,
                "SYS_EXIT: task=%u exit_code=%d",
                (caller != NULL) ? caller->task_id : 0u, (int)arg1);
            if (caller != NULL) {
                caller->state = TASK_TERMINATED;
                if (rr_scheduler.remove_task) {
                    rr_scheduler.remove_task(caller->task_id);
                }
            }
            break;

        case SYS_CREATE_TASK: {
            /* arg1 = user VA of a task_t spec. Bounds-check, copy into
             * kernel space, call create_task (bounded-narrowing applies),
             * log the assigned id. No return-value path yet — Phase 4
             * extends the syscall ABI to surface the new task_id. */
            if (arg1 == 0u ||
                arg1 < 0x400000u || arg1 > 0x7FFFFFFFu) {
                log_message(LOG_ERROR,
                    "SYS_CREATE_TASK: invalid user spec pointer 0x%x", arg1);
                return;
            }
            task_t spec;
            const task_t* user_spec = (const task_t*)(uintptr_t)arg1;
            spec = *user_spec;
            int rv = create_task(&spec);
            if (rv == 0) {
                log_message(LOG_INFO,
                    "SYS_CREATE_TASK: caller=%u -> new task id=%u caps=0x%X",
                    (caller != NULL) ? caller->task_id : 0u,
                    spec.task_id, spec.cap_mask);
            } else {
                log_message(LOG_WARNING,
                    "SYS_CREATE_TASK: caller=%u failed (rv=%d)",
                    (caller != NULL) ? caller->task_id : 0u, rv);
            }
            break;
        }

        case SYS_YIELD:
            /* Voluntary deschedule. Mark caller READY, invoke the
             * scheduler to pick the next runnable task. Without A4's
             * context switch the schedule decision isn't actuated —
             * the same task resumes — but the state transition is
             * structurally correct and observable in telemetry. */
            (void)arg1; (void)arg2; (void)arg3;
            if (caller != NULL && caller->state == (uint64_t)TASK_RUNNING) {
                caller->state = TASK_READY;
            }
            if (rr_scheduler.schedule) {
                uint32_t next_id = 0;
                int rv = rr_scheduler.schedule(NULL, 0, &next_id);
                if (rv == 0) {
                    log_message(LOG_DEBUG,
                        "SYS_YIELD: caller=%u -> next=%u",
                        (caller != NULL) ? caller->task_id : 0u, next_id);
                }
            }
            break;

        default:
            log_message(LOG_ERROR, "Unknown syscall: %d", num);
            break;
    }
}
