#include "lugh.h"
#include "console.h"
#include "auditor.h"

/* Bootstrap IPC channel for user-mode SYS_IPC_SEND. Defined in main.c,
 * created at boot under user_init_task's identity with CAP_IPC_SEND.
 * Phase 3 routes every SYS_IPC_SEND through this single channel; the
 * channel-id is not in the syscall ABI yet. */
extern int user_bootstrap_channel;
int ipc_send(int channel_id, message_t *msg);


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
            // Exit system call
            // arg1 = exit code
            log_message(LOG_INFO, "User program exited with code: %d", arg1);
            
            // In a real implementation, we would:
            // 1. Clean up resources
            // 2. Return to kernel mode
            // 3. Mark task as terminated
            
            // For now, just hang
            while(1) {
                cpu_idle();
            }
            break;
            
        default:
            log_message(LOG_ERROR, "Unknown syscall: %d", num);
            break;
    }
}
