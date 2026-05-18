#ifndef LUGHOS_SYSCALL_H
#define LUGHOS_SYSCALL_H

/* System call numbers */
#define SYS_WRITE       1    /* Write to console                              */
#define SYS_IPC_SEND    2    /* Send IPC message                              */
#define SYS_EXIT        3    /* Terminate current task                        */
#define SYS_CREATE_TASK 4    /* Spawn a new task; arg1 = user VA of task_t    */
#define SYS_YIELD       5    /* Voluntary deschedule; returns when resumed    */

/* Only for kernel use */
#if defined(__KERNEL__) || defined(__riscv)
void syscall_handler(uint32_t num, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif

#endif /* LUGHOS_SYSCALL_H */
