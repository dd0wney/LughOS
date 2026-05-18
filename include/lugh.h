#ifndef LUGHOS_H
#define LUGHOS_H

/* Use standard headers for types */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Define NULL if not already defined */
#ifndef NULL
#define NULL ((void*)0)
#endif

/* Variable arguments (for printf-like functions) */
typedef __builtin_va_list va_list;
#define va_start(v,l) __builtin_va_start(v,l)
#define va_end(v)     __builtin_va_end(v)
#define va_arg(v,l)   __builtin_va_arg(v,l)

/* System constants */
#define OS_NAME "LughOS"
#define OS_VERSION "0.0.1"
#define OS_AUTHOR "Darragh Downey"
#define MAX_TASKS 1024
#define MAX_MSG_SIZE 128
#define MAX_QUEUE_SIZE 1024
#define MAX_OPERATIONS 0x200

/* Architecture-specific constants */
#ifdef __i386__
#define KERNEL_PAGE_SIZE 4096
#elif defined(__arm__)
#define KERNEL_PAGE_SIZE 4096 /* Adjust for ARM if needed */
#else
#define KERNEL_PAGE_SIZE 4096
#endif

/* Task states */
#define TASK_READY 0
#define TASK_RUNNING 1
#define TASK_BLOCKED 2
#define TASK_TERMINATED 3

/* Message operations */
#define OP_ADD_TASK 0x01
#define OP_SCHEDULE 0x02
#define OP_GRID_ALERT 0x100 /* Critical infrastructure: energy grid fault */
#define OP_HEARTBEAT 0x101  /* Future: distributed operation */
#define OP_UPDATE 0x102     /* System update operation */
#define OP_WRITE 0x200
#define OP_DELETE 0x201

/* Logging levels */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL,
    LOG_LEVEL_COUNT
} log_level_t;

/* Task structure for scheduler.
 * cap_mask + domain are bound at create_task() and immutable thereafter,
 * making the task the root of trust for any channel it owns.
 *
 * kernel_stack_top is the top (high address) of the per-task kernel-mode
 * stack reserved in kernel/sched/task.c (Phase 3 A2). Phase 3 A4 uses
 * this as the save/restore anchor for context switches.
 *
 * Layout note (Phase 3 J0): struct size grew from 40 bytes (A2) to 44.
 * parent_task_id is APPENDED at the end so offsets 0..40 stay byte-for-byte
 * stable — kernel/arch/{arm,x86}/context_switch.S hardcodes
 * TASK_SAVED_SP_OFFSET=36 and any insertion in the middle would shift
 * saved_sp and break the context switch. Round-robin serialisation
 * through scheduler_ops.get_state was narrowed in A1 to just the cursor,
 * so neither the A2 nor the J0 size bump is load-bearing for any
 * persisted state today.
 *
 * parent_task_id semantics (Phase 3 J0):
 *   - TASK_PARENT_NONE = "no parent" (the kernel root task).
 *   - Otherwise: task_id of the task that called create_task() to spawn
 *     this one. The JEPA encoder uses this to reconstruct task lineage
 *     from telemetry alone — TASK_CREATE and DENY records carry it
 *     forward (see auditor.h for the wire layout). */
typedef struct {
    uint32_t task_id;          /* unique non-zero id; 0 reserved for "no task" */
    int priority;              /* 0 (highest) to 10 (lowest) */
    uint32_t cap_mask;         /* CAP_* bitmask; see include/capabilities.h */
    uint32_t domain;           /* security domain — IPC cross-domain rules apply */
    uint64_t state;            /* TASK_READY, TASK_RUNNING, TASK_BLOCKED, TASK_TERMINATED */
    uint64_t deadline;         /* For future real-time scheduling */
    uint32_t kernel_stack_top; /* per-task kernel stack TOP (grows down); 0 = no stack */
    uint32_t saved_sp;         /* SP when task is descheduled (Phase 3 A4); 0 = never run */
    uint32_t parent_task_id;   /* creator's task_id at create_task time; TASK_PARENT_NONE = root */
} task_t;

/* Sentinel for "no parent" — assigned to the kernel root task in
 * task_init() and to any synthesized task_t in tests that doesn't
 * have a real lineage. Any other value is the live task_id of the
 * creator at create_task time. */
#define TASK_PARENT_NONE 0xFFFFFFFFu

/* Context switch — arch-specific assembly. Saves callee-saved regs of prev
 * onto prev's kernel stack, writes the resulting SP into prev->saved_sp,
 * loads next->saved_sp into SP, restores next's regs, returns to the
 * instruction after arm_context_switch was originally called (now in
 * next's context). Caller must mask IRQs around the call. The current_task
 * swap happens inside the switch — see kernel/arch/<arch>/context_switch.S */
void arm_context_switch(task_t* prev, task_t* next);
void x86_context_switch(task_t* prev, task_t* next);

/* High-level scheduler helpers (Phase 3 A5). task_yield asks the scheduler
 * for the next runnable task and switches to it (arch-dispatched). It's
 * a no-op when the scheduler picks the same task. IRQs are masked across
 * the switch via splhigh/splx. */
typedef void (*task_entry_fn)(void);
void task_setup_initial_frame(task_t* t, task_entry_fn entry);
void task_yield(void);

/* Message priorities */
typedef enum {
    PRIORITY_HIGH = 0, /* Critical commands, interrupts, grid alerts */
    PRIORITY_MEDIUM,   /* Storage operations */
    PRIORITY_LOW       /* Logs, telemetry */
} msg_priority_t;

/* Message structure for prioritized IPC */
typedef struct {
    msg_priority_t priority;
    uint32_t operation;             /* OP_SCHEDULE, OP_GRID_ALERT, etc. */
    uint32_t checksum;              /* Integrity check per NASA Power of Ten rule 6 */
    uint32_t _padding1;             /* Explicit padding per CERT DCL39-C */
    char payload[MAX_MSG_SIZE];     /* Always terminated with '\0' per CERT STR31-C */
} message_t;

/* Priority queue for messages */
typedef struct {
    message_t messages[MAX_QUEUE_SIZE];
    int count;
} priority_queue_t;

/* Scheduler interface for hot-swappable schedulers */
typedef struct {
    const char* name;
    int (*init)(void* context);
    int (*schedule)(task_t* tasks, int num_tasks, uint32_t* next_task_id);
    int (*add_task)(task_t* task);
    int (*remove_task)(uint32_t task_id);
    int (*get_state)(void* state_buffer, size_t* size);
    int (*set_state)(void* state_buffer, size_t size);
    int (*prepare_swap)(void);
    int (*finalize_swap)(void);
} scheduler_ops_t;

/* Transaction log entry for updates.
 *
 * task_id records the owning task at txn-emit time so the JEPA encoder
 * can reconstruct cross-task causality without consulting the scheduler
 * (the auditor stream is the JEPA's only input). 0 = "no task" — same
 * sentinel as task_t.task_id.
 *
 * Layout (344 bytes, 8-byte aligned): txn_id, task_id, operation,
 * key[64], value[256], checksum. No trailing pad needed — the field
 * sequence already lands on an 8-byte boundary. */
typedef struct {
    uint64_t txn_id;
    uint32_t task_id;         /* current_task->task_id at emit, or 0 */
    int operation;            /* OP_WRITE, OP_DELETE, etc. */
    char key[64];             /* Always terminated with '\0' per CERT STR31-C */
    char value[256];          /* Always terminated with '\0' per CERT STR31-C */
    uint32_t checksum;        /* Integrity check per NASA Power of Ten rule 6 */
} txn_log_entry_t;

/* Memory safety functions */
void* memcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
void* memset(void* s, int c, size_t n);
size_t strlen(const char* s);
int strcmp(const char* s1, const char* s2);
char* strcpy(char* dest, const char* src);
char* strstr(const char* haystack, const char* needle);
void* kmalloc(size_t size);
void kfree(void* ptr);

/* IO port functions */
void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);

/* Function prototypes */
void queue_init(priority_queue_t* queue);
int queue_push(priority_queue_t* queue, message_t* msg);
int queue_pop(priority_queue_t* queue, message_t* msg);

/* Data integrity functions per NASA Power of Ten rule 6 */
uint32_t calculate_checksum(const void* data, size_t len);
// moved to transactions.h
// int log_message_transaction(message_t* msg);
// int log_transaction(txn_log_entry_t* entry);
// int commit_transaction(uint64_t txn_id);
// int rollback_transaction(uint64_t txn_id);
void scheduler_service(void* socket, scheduler_ops_t* ops);
void log_message(log_level_t level, const char* format, ...);
uint64_t generate_txn_id(void);
uint64_t generate_secure_id(void);

/* Task subsystem. task_init() must be called before init_ipc() so that
 * channel-creation cap checks have a valid current_task to compare against. */
void task_init(void);
int  create_task(task_t* spec);
extern task_t* current_task;

/* Accessors that let the scheduler operate on the kernel task table
 * (Phase 3 A1 — the kernel table is the single source of truth; the
 * scheduler no longer maintains a parallel rr_tasks[] copy).
 * task_find returns NULL when id is not present. */
task_t* task_table(void);
int     task_table_count(void);
task_t* task_find(uint32_t task_id);
void process_events(void);
void cpu_idle(void);
void enter_user_mode(uint32_t user_eip, uint32_t user_esp) __attribute__((noreturn));

/* User mode functions */
void switch_to_user_mode(uint32_t user_eip, uint32_t user_esp);

// moved to memory.h
// int load_user_program(const void* binary_ptr, size_t size, uint32_t* eip, uint32_t* esp);

/* Initialize system call mechanism */
void init_syscall(void);
void init_syscall_arm(void);
void init_syscall_riscv_c(void);

/* System call definitions */
#define SYS_WRITE       1    /* Write to console                              */
#define SYS_IPC_SEND    2    /* Send IPC message                              */
#define SYS_EXIT        3    /* Terminate current task                        */
#define SYS_CREATE_TASK 4    /* Spawn a new task; arg1 = user VA of task_t    */
#define SYS_YIELD       5    /* Voluntary deschedule; returns when resumed    */

#ifdef __KERNEL__
void syscall_handler(uint32_t num, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif

#endif /* LUGHOS_H */