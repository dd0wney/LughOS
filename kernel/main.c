#include "lugh.h"
#include "security.h"
#include "hardware.h"
#include "interrupt.h"
#include "nngcompat.h"
#include "console.h"
#include "crypto.h"
#include "auditor.h"
#include "capabilities.h"
#include "domain_graph.h"
#include "transactions.h"
#include "update.h"
#include "sandbox.h"
#include "memory.h"
#include "main_debug.h"

// Forward declarations
void test_nng(void);
void test_nng_patterns(void);
void test_energy_grid_alert(void);
void test_update_system(void);
void test_auditor(void);
void test_ipc_enforcement(void);
void test_task_caps(void);
void test_task_lifecycle(void);
void test_frame_allocator(void);
void test_mmu_protection(void);
void test_fault_telemetry(void);
int  init_ipc(void);
int  ipc_create_channel(uint32_t security_level, uint32_t domain,
                        uint32_t cap_mask, int protocol);
int  ipc_send(int channel_id, message_t *msg);
int  ipc_recv(int channel_id, message_t *msg, bool nonblock);
int  ipc_connect(int src_id, int dst_id);
int  ipc_close_channel(int channel_id);

extern scheduler_ops_t rr_scheduler;

/* The user-mode IPC bootstrap. user_init_task is the identity user
 * programs run as in Phase 3 — narrowed caps (CAP_IPC_SEND only) so
 * the existing escalation gate in ipc_create_channel actually bites
 * when user code asks for privileged ops. user_bootstrap_channel is
 * the single channel SYS_IPC_SEND routes through (channel-id is not
 * in the syscall ABI in Phase 3; extending it is Phase 4). */
static task_t user_init_task;
int user_bootstrap_channel = -1;

// Test NNG messaging functionality
void test_nng(void) {
    log_message(LOG_INFO, "Testing NNG messaging functionality...\n");
    // JPL Rule 14: Check return values of all non-void functions
    // SEI CERT EXP12-C: Do not ignore values returned by functions
    // JPL Rule 16: Use assertions for critical invariants (not shown here, but should be used in real tests)
    
    // Create a socket
    nng_socket_t socket;
    int rv = nng_socket_create(&socket, NNG_PROTO_PUB0);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to create socket: %d\n", rv);
        return;
    }
    
    // Test raw NNG messaging first
    nng_msg_t *raw_msg;
    rv = nng_msg_alloc(&raw_msg, 0);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to allocate message: %d\n", rv);
        nng_socket_close(&socket);
        return;
    }
    
    // Add data to message
    const char *data = "Hello from LughOS!";
    // JPL Rule 15: Validate parameters before use
    // SEI CERT STR31-C: Guarantee storage for strings has space for null terminator
    rv = nng_msg_append(raw_msg, data, strlen(data));
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to append data to message: %d\n", rv);
        nng_msg_free(raw_msg);
        nng_socket_close(&socket);
        return;
    }
    
    // Send the raw message
    rv = nng_send(&socket, raw_msg, 0);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to send message: %d\n", rv);
        nng_socket_close(&socket);
        return;
    }
    
    log_message(LOG_INFO, "Raw NNG test message sent successfully!\n");
    
    // Now test the LughOS message format conversion
    message_t lugh_msg;
    lugh_msg.priority = PRIORITY_HIGH;
    lugh_msg.operation = OP_GRID_ALERT;
    // SEI CERT STR31-C: Use safe string copy (ensure null-termination)
    strcpy(lugh_msg.payload, "GRID_ALERT: Testing NNG conversion");
    
    // Convert LughOS message to NNG message
    nng_msg_t *converted_msg;
    rv = lugh_message_to_nng(&lugh_msg, &converted_msg);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to convert LughOS message to NNG: %d\n", rv);
        nng_socket_close(&socket);
        return;
    }
    
    // Send the converted message
    rv = nng_send(&socket, converted_msg, 0);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to send converted message: %d\n", rv);
        nng_socket_close(&socket);
        return;
    }
    
    log_message(LOG_INFO, "Converted LughOS->NNG message sent successfully!\n");
    nng_socket_close(&socket);
}

// Test secure messaging for energy sector operations
void test_energy_grid_alert(void) {
    log_message(LOG_INFO, "Testing energy grid alert messaging...\n");
    
    // Create an energy grid alert message
    message_t alert;
    alert.priority = PRIORITY_HIGH;
    alert.operation = OP_GRID_ALERT;
    
    // Copy payload safely
    const char* payload = "GRID_FAULT: Voltage spike detected";
    size_t payload_len = strlen(payload);
    // JPL Rule 15: Validate parameters before use
    // SEI CERT ARR30-C: Validate all array indices
    if (payload_len >= MAX_MSG_SIZE) {
        log_message(LOG_ERROR, "Payload too large for message buffer\n");
        return;
    }
    // SEI CERT STR31-C: Guarantee storage for strings has space for null terminator
    memcpy(alert.payload, payload, payload_len + 1); // +1 for null terminator
    
    // Validate the message with our updated security validation
    log_message(LOG_INFO, "Grid Alert - Priority: %d, Operation: 0x%x, Payload: %s\n", 
               alert.priority, alert.operation, alert.payload);
    
    if (validate_message(&alert)) {
        log_message(LOG_INFO, "Grid alert message passed validation\n");
        
        // Test secure message transfer via NNG
        nng_socket_t socket;
        int rv = nng_socket_create(&socket, NNG_PROTO_PUB0);
        if (rv != NNG_OK) {
            log_message(LOG_ERROR, "Failed to create socket for grid alert: %d\n", rv);
            return;
        }
        
        // Convert to NNG message
        nng_msg_t *msg;
        rv = lugh_message_to_nng(&alert, &msg);
        if (rv != NNG_OK) {
            log_message(LOG_ERROR, "Failed to convert grid alert to NNG: %d\n", rv);
            nng_socket_close(&socket);
            return;
        }
        
        // Send the message
        rv = nng_send(&socket, msg, 0);
        if (rv != NNG_OK) {
            log_message(LOG_ERROR, "Failed to send grid alert: %d\n", rv);
            nng_socket_close(&socket);
            return;
        }
        
        log_message(LOG_INFO, "Grid alert sent successfully\n");
        
        // Try to receive the message back
        nng_msg_t *recv_msg;
        rv = nng_recv(&socket, &recv_msg, 0);
        if (rv == NNG_OK) {
            // Convert back to LughOS message
            message_t recv_alert;
            rv = nng_message_to_lugh(recv_msg, &recv_alert);
            if (rv == NNG_OK) {
                log_message(LOG_INFO, "Received grid alert: %s\n", recv_alert.payload);
            }
            nng_msg_free(recv_msg);
        } else {
            log_message(LOG_INFO, "No grid alerts in queue (expected for PUB socket)\n");
        }
        
        nng_socket_close(&socket);
    } else {
        log_message(LOG_ERROR, "Grid alert message failed validation\n");
    }
}

/**
 * Test the update system with a simulated update transaction
 * 
 * Creates a test update transaction and executes it to verify
 * that the update system works properly.
 * 
 * Complies with:
 * - SEI CERT ERR33-C: Detect errors and handle appropriately
 * - JPL Rule 14: Check return values
 */
void test_update_system(void) {
    log_message(LOG_INFO, "Testing update system...\n");
    
    // Create a sample binary for testing
    uint8_t test_binary[256];
    size_t test_size = sizeof(test_binary);
    
    // Initialize with ELF-like header
    test_binary[0] = 0x7F;
    test_binary[1] = 'E';
    test_binary[2] = 'L';
    test_binary[3] = 'F';
    
    // Fill rest with test pattern
    for (size_t i = 4; i < test_size; i++) {
        test_binary[i] = (uint8_t)(i & 0xFF);
    }
    
    // Calculate hash for later verification
    uint32_t hash = compute_sha256(test_binary, test_size);
    
    // Create update state
    struct update_state update;
    
    // Initialize the update transaction
    const char *test_path = "/services/test_update.bin";
    if (init_update_transaction(&update, UPDATE_TYPE_SERVICE, test_path, 
                              test_binary, test_size, hash) == 0) {
        
        // Execute the update
        int result = execute_update(&update);
        
        if (result == 0) {
            log_message(LOG_INFO, "Update test completed successfully\n");
        } else {
            log_message(LOG_ERROR, "Update test failed\n");
        }
        
        // Clean up
        cleanup_update_transaction(&update);
    } else {
        log_message(LOG_ERROR, "Failed to initialize update transaction\n");
    }
}

void test_auditor(void) {
    log_message(LOG_INFO, "Testing auditor telemetry path...\n");
    int ch = ipc_create_channel(0, 0, CAP_ALL, NNG_PROTO_PUB0);
    if (ch < 0) {
        log_message(LOG_ERROR, "Auditor test: failed to create IPC channel\n");
        return;
    }
    message_t msg;
    msg.priority  = PRIORITY_HIGH;
    msg.operation = 0xDEADBEEFu;
    msg.checksum  = 0;
    msg._padding1 = 0;
    memset(msg.payload, 0, MAX_MSG_SIZE);
    memcpy(msg.payload, "auditor-test", 13);
    ipc_send(ch, &msg);          /* triggers ring_push */
    auditor_tick();              /* drains ring → emits telemetry record on COM2 */
    log_message(LOG_INFO, "Auditor test: record emitted (check /tmp/lugh_ipc.bin)\n");
    ipc_close_channel(ch);
}

/* Direct call to auditor_fault() — exercises the emit path without
 * triggering a real hardware abort. The records land on COM2 / UART1
 * and are verifiable via scripts/validate_telemetry.py. */
void test_fault_telemetry(void) {
    log_message(LOG_INFO, "Testing auditor_fault() emit path...\n");

    /* Synthetic prefetch abort at a known VA from domain 0 task 1. */
    auditor_fault(0xDEAD0000u, 0u, 0u, 0x00000010u, AUDITOR_FAULT_PABORT);

    /* Synthetic data-write abort: VA=0xBAD00000, DFSR=0xF (permission L2),
     * SPSR=0x90 (IRQ disabled, ARM mode, SVC). */
    auditor_fault(0xCAFE0000u, 0xBAD00000u, 0x0000080Fu,
                  0x00000090u, AUDITOR_FAULT_DABORT_WRITE);

    log_message(LOG_INFO,
        "Fault telemetry test: 2 records emitted (pabort + dabort_write)\n");
}

/* Test IPC enforcement: 3 subtests covering cap_send, cap_priv, domain checks.
 * Each subtest expects a hard failure and a DENY record on the telemetry ring. */
void test_ipc_enforcement(void) {
    log_message(LOG_INFO, "Testing IPC enforcement...\n");
    int pass = 0;
    message_t msg;

    /* ── Subtest 1: ipc_send blocked by missing CAP_IPC_SEND ─────── */
    {
        /* Channel has only CAP_IPC_RECV — no send right */
        int ch = ipc_create_channel(0, 0, CAP_IPC_RECV, NNG_PROTO_PUB0);
        if (ch < 0) {
            log_message(LOG_ERROR, "Enforcement test 1: create failed\n");
            goto done;
        }
        msg.priority  = PRIORITY_HIGH;
        msg.operation = OP_HEARTBEAT;
        msg.checksum  = 0;
        msg._padding1 = 0;
        msg.payload[0] = '\0';
        int rv = ipc_send(ch, &msg);
        if (rv == -7) {
            log_message(LOG_INFO, "Enforcement test 1 PASS: send denied (CAP_SEND missing)\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Enforcement test 1 FAIL: expected -7, got %d\n", rv);
        }
        auditor_tick();  /* drain DENY record to COM2 */
        ipc_close_channel(ch);
    }

    /* ── Subtest 2: ipc_send blocked for privileged op (OP_DELETE) ─ */
    {
        /* Channel has send right but NOT CAP_PRIVILEGED_OP */
        int ch = ipc_create_channel(0, 0, CAP_IPC_SEND | CAP_IPC_RECV,
                                    NNG_PROTO_PUB0);
        if (ch < 0) {
            log_message(LOG_ERROR, "Enforcement test 2: create failed\n");
            goto done;
        }
        msg.priority  = PRIORITY_HIGH;
        msg.operation = OP_DELETE;
        msg.checksum  = 0;
        msg._padding1 = 0;
        msg.payload[0] = '\0';
        int rv = ipc_send(ch, &msg);
        if (rv == -7) {
            log_message(LOG_INFO,
                "Enforcement test 2 PASS: send denied (CAP_PRIV missing for OP_DELETE)\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Enforcement test 2 FAIL: expected -7, got %d\n", rv);
        }
        auditor_tick();
        ipc_close_channel(ch);
    }

    /* ── Subtest 3: ipc_connect blocked by domain mismatch ──────── */
    {
        /* ch_a in domain 0, ch_b in domain 1; ch_a has no CAP_CROSS_DOMAIN */
        int ch_a = ipc_create_channel(0, 0, CAP_IPC_SEND | CAP_IPC_RECV,
                                      NNG_PROTO_PUB0);
        int ch_b = ipc_create_channel(0, 1, CAP_IPC_SEND | CAP_IPC_RECV,
                                      NNG_PROTO_SUB0);
        if (ch_a < 0 || ch_b < 0) {
            log_message(LOG_ERROR, "Enforcement test 3: create failed\n");
            goto done;
        }
        int rv = ipc_connect(ch_a, ch_b);
        if (rv == NNG_EACCESS) {
            log_message(LOG_INFO,
                "Enforcement test 3 PASS: connect denied (domain mismatch, no CAP_CROSS_DOMAIN)\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Enforcement test 3 FAIL: expected NNG_EACCESS (%d), got %d\n",
                NNG_EACCESS, rv);
        }
        auditor_tick();
        ipc_close_channel(ch_a);
        ipc_close_channel(ch_b);
    }

    /* ── Subtest 4: same-domain ipc_connect succeeds — emits CHAN_CONNECT.
     * Doesn't disturb the deny-path assertions above; runs only after them
     * so a failure here can't mask an earlier deny failure. */
    {
        int ch_a = ipc_create_channel(0, 0, CAP_IPC_SEND | CAP_IPC_RECV,
                                      NNG_PROTO_PUSH0);
        int ch_b = ipc_create_channel(0, 0, CAP_IPC_SEND | CAP_IPC_RECV,
                                      NNG_PROTO_PULL0);
        if (ch_a < 0 || ch_b < 0) {
            log_message(LOG_ERROR, "Enforcement test 4: create failed\n");
            goto done;
        }
        int rv = ipc_connect(ch_a, ch_b);
        if (rv == 0) {
            log_message(LOG_INFO,
                "Enforcement test 4 PASS: same-domain connect allowed "
                "(CHAN_CONNECT record emitted)\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Enforcement test 4 FAIL: expected 0, got %d\n", rv);
        }
        auditor_tick();
        ipc_close_channel(ch_a);
        ipc_close_channel(ch_b);
    }

    /* ── Subtest 5: domain_edge_set(0, 1) emits AUDITOR_REC_DOMAIN_EDGE
     * and returns 0. The record is the audit trail for the policy change. */
    {
        int rv = domain_edge_set(0u, 1u);
        if (rv == 0) {
            log_message(LOG_INFO,
                "Enforcement test 5 PASS: domain edge 0->1 added "
                "(DOMAIN_EDGE record emitted)\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Enforcement test 5 FAIL: expected 0, got %d\n", rv);
        }
        auditor_tick();
    }

    /* ── Subtest 6: with edge 0->1 present, cross-domain ipc_connect
     * 0->1 now succeeds via the matrix (no CAP_CROSS_DOMAIN needed). */
    {
        int ch_a = ipc_create_channel(0, 0, CAP_IPC_SEND | CAP_IPC_RECV,
                                      NNG_PROTO_PUSH0);
        int ch_b = ipc_create_channel(0, 1, CAP_IPC_SEND | CAP_IPC_RECV,
                                      NNG_PROTO_PULL0);
        if (ch_a < 0 || ch_b < 0) {
            log_message(LOG_ERROR, "Enforcement test 6: create failed (a=%d b=%d)\n",
                        ch_a, ch_b);
            goto done;
        }
        int rv = ipc_connect(ch_a, ch_b);
        if (rv == 0) {
            log_message(LOG_INFO,
                "Enforcement test 6 PASS: cross-domain connect allowed via matrix\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Enforcement test 6 FAIL: expected 0, got %d\n", rv);
        }
        auditor_tick();
        ipc_close_channel(ch_a);
        ipc_close_channel(ch_b);
    }

    /* ── Subtest 7: CAP_CROSS_DOMAIN bypass — a channel holding the
     * capability may connect to a non-allowed domain (no edge 0->2). */
    {
        int ch_a = ipc_create_channel(0, 0,
                                      CAP_IPC_SEND | CAP_IPC_RECV | CAP_CROSS_DOMAIN,
                                      NNG_PROTO_PUSH0);
        int ch_b = ipc_create_channel(0, 2, CAP_IPC_SEND | CAP_IPC_RECV,
                                      NNG_PROTO_PULL0);
        if (ch_a < 0 || ch_b < 0) {
            log_message(LOG_ERROR,
                "Enforcement test 7: create failed (a=%d b=%d)\n", ch_a, ch_b);
            goto done;
        }
        int rv = ipc_connect(ch_a, ch_b);
        if (rv == 0) {
            log_message(LOG_INFO,
                "Enforcement test 7 PASS: CAP_CROSS_DOMAIN bypass to dom=2\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Enforcement test 7 FAIL: expected 0, got %d\n", rv);
        }
        auditor_tick();
        ipc_close_channel(ch_a);
        ipc_close_channel(ch_b);
    }

done:
    log_message(LOG_INFO, "IPC enforcement tests: %d/7 passed\n", pass);
}

/* Test task-bound capabilities: a child task cannot escalate beyond its
 * parent's caps, and a restricted task cannot mint a privileged channel.
 * Exercises both the bounded-narrowing rule in create_task and the
 * escalation gate in ipc_create_channel. */
void test_task_caps(void) {
    log_message(LOG_INFO, "Testing task-bound capabilities...\n");
    int pass = 0;
    task_t* saved = current_task;

    /* ── Subtest 1: bounded narrowing — child asking for CAP_ALL from a
     *    parent holding only CAP_IPC_SEND must be narrowed to CAP_IPC_SEND ── */
    {
        task_t restricted_parent;
        restricted_parent.task_id        = 0u;
        restricted_parent.priority       = 5;
        restricted_parent.cap_mask       = CAP_IPC_SEND;
        restricted_parent.domain         = 0u;
        restricted_parent.state          = TASK_RUNNING;
        restricted_parent.deadline       = 0u;
        restricted_parent.parent_task_id = TASK_PARENT_NONE; /* synthesized; no lineage */
        current_task = &restricted_parent;

        task_t spec;
        spec.task_id        = 0u;
        spec.priority       = 6;
        spec.cap_mask       = CAP_ALL;       /* tries to grab everything */
        spec.domain         = 0u;
        spec.state          = TASK_READY;
        spec.deadline       = 0u;
        spec.parent_task_id = TASK_PARENT_NONE; /* create_task overwrites it; init for determinism */
        int rv = create_task(&spec);
        if (rv == 0 && spec.cap_mask == CAP_IPC_SEND) {
            log_message(LOG_INFO,
                "Task caps test 1 PASS: child narrowed to 0x%X\n",
                spec.cap_mask);
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Task caps test 1 FAIL: rv=%d caps=0x%X (expected 0x%X)\n",
                rv, spec.cap_mask, CAP_IPC_SEND);
        }
        current_task = saved;
    }

    /* ── Subtest 2: a restricted task cannot mint a CAP_ALL channel ── */
    {
        task_t child;
        child.task_id        = 1000u;
        child.priority       = 5;
        child.cap_mask       = CAP_IPC_SEND | CAP_IPC_RECV;
        child.domain         = 0u;
        child.state          = TASK_RUNNING;
        child.deadline       = 0u;
        /* Pretend the synthesized child was spawned by kernel_task (id=1).
         * The upcoming CAP_ESCALATION DENY then carries non-zero depth
         * in the J6 lineage nibbles, exercising the depth-walk path
         * (one hop to TASK_PARENT_NONE = root). Without this, the synthesized
         * child would look like a root and depth would stay 0. */
        child.parent_task_id = 1u;
        current_task = &child;

        int ch = ipc_create_channel(0u, 0u, CAP_ALL, NNG_PROTO_PUB0);
        if (ch < 0) {
            log_message(LOG_INFO,
                "Task caps test 2 PASS: escalation denied (rv=%d)\n", ch);
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Task caps test 2 FAIL: escalation allowed (ch=%d)\n", ch);
            ipc_close_channel(ch);
        }
        current_task = saved;
    }

    /* ── Subtest 3: the same restricted task CAN create a within-caps channel ── */
    {
        task_t child;
        child.task_id        = 1001u;
        child.priority       = 5;
        child.cap_mask       = CAP_IPC_SEND | CAP_IPC_RECV;
        child.domain         = 0u;
        child.state          = TASK_RUNNING;
        child.deadline       = 0u;
        child.parent_task_id = TASK_PARENT_NONE; /* synthesized; no DENY here but be consistent */
        current_task = &child;

        int ch = ipc_create_channel(0u, 0u, CAP_IPC_SEND, NNG_PROTO_PUB0);
        if (ch >= 0) {
            log_message(LOG_INFO,
                "Task caps test 3 PASS: subset channel allowed (ch=%d)\n", ch);
            pass++;
            ipc_close_channel(ch);
        } else {
            log_message(LOG_ERROR,
                "Task caps test 3 FAIL: subset channel denied (rv=%d)\n", ch);
        }
        current_task = saved;
    }

    current_task = saved;
    log_message(LOG_INFO, "Task caps tests: %d/3 passed\n", pass);
}

/* ── test_task_lifecycle (Phase 3 A5) ─────────────────────────────────
 * Spawns two kernel-mode child tasks (t_a, t_b), each printing a
 * tagged line + yielding three times then "exiting". The test
 * verifies that:
 *   (1) arm_context_switch saves/restores callee-saved regs correctly,
 *   (2) the scheduler picks tasks in round-robin order,
 *   (3) TASK_TERMINATED tasks are skipped by the scheduler,
 *   (4) control returns to kernel_task after all children terminate.
 *
 * The test sweeps any stale READY tasks in tasks[] before yielding —
 * specifically the leaked task from test_task_caps subtest 1, which
 * has saved_sp = kernel_stack_top (an empty stack, never set up by
 * task_setup_initial_frame). Switching to such a task would `pop`
 * garbage and crash; parking it as TERMINATED is the defensive move.
 */
static volatile int task_a_runs = 0;
static volatile int task_b_runs = 0;

static void test_task_lifecycle_body_a(void) {
    while (task_a_runs < 3) {
        log_message(LOG_INFO, "[t=A] iteration %d", task_a_runs);
        task_a_runs++;
        task_yield();
    }
    current_task->state = TASK_TERMINATED;
    task_yield();
    /* Should never get here — TERMINATED tasks aren't picked. */
    for (;;) task_yield();
}

static void test_task_lifecycle_body_b(void) {
    while (task_b_runs < 3) {
        log_message(LOG_INFO, "[t=B] iteration %d", task_b_runs);
        task_b_runs++;
        task_yield();
    }
    current_task->state = TASK_TERMINATED;
    task_yield();
    for (;;) task_yield();
}

void test_task_lifecycle(void) {
    log_message(LOG_INFO, "Testing task lifecycle (context switch)...\n");
    task_a_runs = 0;
    task_b_runs = 0;

    /* Park stale tasks so the scheduler doesn't pick one with no
     * valid saved frame. */
    task_t* table = task_table();
    int n = task_table_count();
    for (int i = 0; i < n; i++) {
        if (table[i].task_id != current_task->task_id &&
            table[i].state != (uint64_t)TASK_TERMINATED) {
            table[i].state = TASK_TERMINATED;
        }
    }

    task_t spec_a = {0};
    spec_a.priority = 5;
    spec_a.cap_mask = CAP_IPC_SEND;
    spec_a.domain = 0;
    spec_a.state = TASK_READY;
    if (create_task(&spec_a) != 0) {
        log_message(LOG_ERROR, "test_task_lifecycle: create_task A failed\n");
        return;
    }
    task_t spec_b = {0};
    spec_b.priority = 5;
    spec_b.cap_mask = CAP_IPC_SEND;
    spec_b.domain = 0;
    spec_b.state = TASK_READY;
    if (create_task(&spec_b) != 0) {
        log_message(LOG_ERROR, "test_task_lifecycle: create_task B failed\n");
        return;
    }

    task_t* t_a = task_find(spec_a.task_id);
    task_t* t_b = task_find(spec_b.task_id);
    if (t_a == NULL || t_b == NULL) {
        log_message(LOG_ERROR, "test_task_lifecycle: task_find failed\n");
        return;
    }
    task_setup_initial_frame(t_a, test_task_lifecycle_body_a);
    task_setup_initial_frame(t_b, test_task_lifecycle_body_b);

    log_message(LOG_INFO, "test_task_lifecycle: yielding to children...\n");
    task_yield();
    /* Round-robin lands us back here between every child iteration too;
     * keep yielding until both children have hit TASK_TERMINATED.
     * Bounded loop: 64 iterations is far more than the 3*2 + bookkeeping
     * yields we expect; trips a defensive break if something stalls. */
    int safety = 0;
    while ((t_a->state != (uint64_t)TASK_TERMINATED ||
            t_b->state != (uint64_t)TASK_TERMINATED) &&
           safety < 64) {
        task_yield();
        safety++;
    }

    /* Children should both have terminated by the time we resume. */
    if (task_a_runs == 3 && task_b_runs == 3) {
        log_message(LOG_INFO,
            "Task lifecycle test PASS: A=%d B=%d (3 iterations each, "
            "context switches verified)\n", task_a_runs, task_b_runs);
    } else {
        log_message(LOG_ERROR,
            "Task lifecycle test FAIL: A=%d B=%d (expected 3/3)\n",
            task_a_runs, task_b_runs);
    }
}

/* ── test_frame_allocator (Phase 3 B1) ─────────────────────────────
 * Exercises alloc/free/reuse semantics and bookkeeping. The B2/B3 MMU
 * commits depend on these primitives behaving correctly under load. */
void test_frame_allocator(void) {
    log_message(LOG_INFO, "Testing page frame allocator...\n");
    int pass = 0;
    uint32_t before = frame_count_free();

    /* Subtest 1: three sequential allocs are contiguous and decrement free count */
    uint32_t f1 = alloc_frame();
    uint32_t f2 = alloc_frame();
    uint32_t f3 = alloc_frame();
    if (f1 != 0u && f2 != 0u && f3 != 0u &&
        (f2 - f1) == MM_FRAME_SIZE && (f3 - f2) == MM_FRAME_SIZE &&
        frame_count_free() == before - 3u) {
        log_message(LOG_INFO,
            "Frame test 1 PASS: 3 sequential frames at 0x%X / 0x%X / 0x%X "
            "(free %u -> %u)\n", f1, f2, f3, before, frame_count_free());
        pass++;
    } else {
        log_message(LOG_ERROR, "Frame test 1 FAIL: f1=0x%X f2=0x%X f3=0x%X free=%u\n",
            f1, f2, f3, frame_count_free());
    }

    /* Subtest 2: free middle frame, re-alloc should reuse the same slot */
    free_frame(f2);
    uint32_t f4 = alloc_frame();
    if (f4 == f2 && frame_count_free() == before - 3u) {
        log_message(LOG_INFO,
            "Frame test 2 PASS: freed 0x%X reused on next alloc\n", f2);
        pass++;
    } else {
        log_message(LOG_ERROR,
            "Frame test 2 FAIL: expected reuse of 0x%X, got 0x%X\n", f2, f4);
    }

    /* Subtest 3: defensive — double-free + misaligned + out-of-range tolerated */
    uint32_t saved_free = frame_count_free();
    free_frame(f1);
    free_frame(f1);                /* double-free, should be ignored */
    free_frame(0xDEADBEE0u);       /* out of pool */
    free_frame(0x00200001u);       /* misaligned */
    if (frame_count_free() == saved_free + 1u) {
        log_message(LOG_INFO,
            "Frame test 3 PASS: defensive free correctly ignored bad inputs\n");
        pass++;
    } else {
        log_message(LOG_ERROR,
            "Frame test 3 FAIL: free count diverged (got %u expected %u)\n",
            frame_count_free(), saved_free + 1u);
    }

    /* Clean up so subsequent code starts from a known free count */
    free_frame(f3);
    free_frame(f4);
    log_message(LOG_INFO, "Frame allocator tests: %d/3 passed\n", pass);
}

/* ── test_mmu_protection (Phase 3 B6) ─────────────────────────────
 *
 * The "real" B6 — trigger a deliberate access violation from user
 * mode and verify the kernel's data-abort handler logs the fault
 * and terminates the offending task — requires replacing the current
 * arm_dabort_panic stub (which busy-loops with "EXC:D") with a
 * graceful task-termination handler. That's a substantial piece of
 * assembly + C work and is filed as a Phase 4 follow-up.
 *
 * What this commit verifies instead: the AP-bit machinery B4 added
 * is observable and round-trips. If arm_section_set_ap doesn't
 * actually write the bits B4 thinks it writes, B6's runtime test
 * would silently never fire — so confirming the bit pattern at the
 * source is the right defensive layer to land first.
 *
 * Subtests:
 *   1. Boot mapping matches the B4 design (kernel/user/device).
 *   2. set_ap on a user section flips it kernel-only and back.
 *   3. set_ap on an unmapped VA returns -1 (doesn't corrupt L1).
 *   4. set_ap restores the original AP after the test mutations. */
void test_mmu_protection(void) {
    log_message(LOG_INFO, "Testing MMU protection (AP bits + DACR)...\n");
#ifdef __arm__
    int pass = 0;

    /* Subtest 1: boot mapping reads as designed.
     * Sections 0, 3 are kernel-only (AP=01). Section 4 is user
     * (AP=11). Section 0x101 (devices) is kernel-only. */
    int ap0    = arm_section_get_ap(0x00000000u);
    int ap3    = arm_section_get_ap(0x00300000u);
    int ap4    = arm_section_get_ap(0x00400000u);
    int ap_dev = arm_section_get_ap(0x10100000u);
    if (ap0 == (int)MMU_AP_KERNEL_ONLY && ap3 == (int)MMU_AP_KERNEL_ONLY &&
        ap4 == (int)MMU_AP_USER_RW && ap_dev == (int)MMU_AP_KERNEL_ONLY) {
        log_message(LOG_INFO,
            "MMU test 1 PASS: boot mapping correct "
            "(kernel sections AP=%d, user AP=%d, dev AP=%d)\n",
            ap0, ap4, ap_dev);
        pass++;
    } else {
        log_message(LOG_ERROR,
            "MMU test 1 FAIL: ap0=%d ap3=%d ap4=%d ap_dev=%d\n",
            ap0, ap3, ap4, ap_dev);
    }

    /* Subtest 2: round-trip set_ap on a USER section.
     * Flip section 4 (user code) to KERNEL_ONLY, verify, restore. */
    int orig4 = arm_section_get_ap(0x00400000u);
    int rv_set = arm_section_set_ap(0x00400000u, MMU_AP_KERNEL_ONLY);
    int read_back = arm_section_get_ap(0x00400000u);
    int rv_restore = arm_section_set_ap(0x00400000u, MMU_AP_USER_RW);
    int read_restored = arm_section_get_ap(0x00400000u);
    if (rv_set == 0 && read_back == (int)MMU_AP_KERNEL_ONLY &&
        rv_restore == 0 && read_restored == (int)MMU_AP_USER_RW &&
        orig4 == (int)MMU_AP_USER_RW) {
        log_message(LOG_INFO,
            "MMU test 2 PASS: set_ap round-trip on section 4 "
            "(%d -> %d -> %d)\n", orig4, read_back, read_restored);
        pass++;
    } else {
        log_message(LOG_ERROR,
            "MMU test 2 FAIL: orig=%d set_rv=%d read=%d restore_rv=%d final=%d\n",
            orig4, rv_set, read_back, rv_restore, read_restored);
    }

    /* Subtest 3: set_ap / get_ap reject unmapped VAs (defensive).
     * Section 0x42 (VA 0x04200000) is not in the boot mapping plan;
     * the L1 entry is 0 (invalid). Both helpers should return -1. */
    int rv_unmapped_get = arm_section_get_ap(0x04200000u);
    int rv_unmapped_set = arm_section_set_ap(0x04200000u, MMU_AP_USER_RW);
    int rv_unmapped_after = arm_section_get_ap(0x04200000u);
    if (rv_unmapped_get == -1 && rv_unmapped_set == -1 &&
        rv_unmapped_after == -1) {
        log_message(LOG_INFO,
            "MMU test 3 PASS: helpers reject unmapped VA 0x04200000 "
            "(get=%d set=%d post=%d)\n",
            rv_unmapped_get, rv_unmapped_set, rv_unmapped_after);
        pass++;
    } else {
        log_message(LOG_ERROR,
            "MMU test 3 FAIL: get=%d set=%d post=%d (expected -1, -1, -1)\n",
            rv_unmapped_get, rv_unmapped_set, rv_unmapped_after);
    }

    log_message(LOG_INFO, "MMU protection tests: %d/3 passed\n", pass);
#else
    log_message(LOG_INFO, "MMU protection tests: skipped (non-ARM build)\n");
#endif
}

/* Plain byte comparison — avoids pulling in a memcmp declaration. */
static int nng_test_body_eq(const nng_msg_t *m, const char *want, int len) {
    if (nng_msg_len(m) != len) return 0;
    const uint8_t *b = (const uint8_t *)nng_msg_body(m);
    const uint8_t *w = (const uint8_t *)want;
    for (int i = 0; i < len; i++)
        if (b[i] != w[i]) return 0;
    return 1;
}

/* Smoke-tests for all three core NNG patterns: PUB/SUB, PUSH/PULL, REQ/REP.
 * Each sub-test creates sockets, wires them with nng_connect, exercises the
 * routing behaviour, and asserts the outcome. Uses a simple EXPECT macro that
 * increments pass/fail counters and logs the label on failure. */
void test_nng_patterns(void) {
    log_message(LOG_INFO, "Testing NNG messaging patterns...\n");
    int pass = 0, fail = 0;

#define EXPECT(cond, label) \
    do { if (cond) { pass++; } \
         else { log_message(LOG_ERROR, "NNG FAIL: %s\n", (label)); fail++; } \
    } while (0)

    nng_msg_t *msg;
    nng_msg_t *rx;
    int rv;

    /* ── 1. PUB/SUB: topic prefix filtering ─────────────────────────── */
    {
        nng_socket_t pub, sub;
        EXPECT(nng_socket_create(&pub, NNG_PROTO_PUB0) == NNG_OK, "pub create");
        EXPECT(nng_socket_create(&sub, NNG_PROTO_SUB0) == NNG_OK, "sub create");
        EXPECT(nng_connect(&pub, &sub)               == NNG_OK, "pub->sub connect");
        EXPECT(nng_sub_subscribe(&sub, "GRID:", 5)   == NNG_OK, "sub subscribe GRID:");

        /* matching message — body starts with "GRID:" */
        rv = nng_msg_alloc(&msg, 0);
        if (rv == NNG_OK) {
            nng_msg_append(msg, "GRID:alert1", 11);
            EXPECT(nng_send(&pub, msg, 0) == NNG_OK, "pub send matching");
        }

        /* non-matching — should be filtered at the SUB socket */
        rv = nng_msg_alloc(&msg, 0);
        if (rv == NNG_OK) {
            nng_msg_append(msg, "OTHER:msg", 9);
            nng_send(&pub, msg, 0);
        }

        /* only the matching message arrives */
        rv = nng_recv(&sub, &rx, 1);
        EXPECT(rv == NNG_OK, "sub recv matching msg");
        if (rv == NNG_OK) {
            EXPECT(nng_test_body_eq(rx, "GRID:alert1", 11),
                   "sub body == GRID:alert1");
            nng_msg_free(rx);
        }

        /* second recv must time out — non-matching was filtered */
        EXPECT(nng_recv(&sub, &rx, 1) == NNG_ETIMEDOUT, "sub queue empty after filter");

        nng_socket_close(&pub);
        nng_socket_close(&sub);
    }

    /* ── 2. PUSH/PULL: round-robin across two pullers ────────────────── */
    {
        nng_socket_t push, pull0, pull1;
        EXPECT(nng_socket_create(&push,  NNG_PROTO_PUSH0) == NNG_OK, "push create");
        EXPECT(nng_socket_create(&pull0, NNG_PROTO_PULL0) == NNG_OK, "pull0 create");
        EXPECT(nng_socket_create(&pull1, NNG_PROTO_PULL0) == NNG_OK, "pull1 create");
        EXPECT(nng_connect(&push, &pull0) == NNG_OK, "push->pull0");
        EXPECT(nng_connect(&push, &pull1) == NNG_OK, "push->pull1");

        rv = nng_msg_alloc(&msg, 0);
        if (rv == NNG_OK) { nng_msg_append(msg, "work0", 5); nng_send(&push, msg, 0); }
        rv = nng_msg_alloc(&msg, 0);
        if (rv == NNG_OK) { nng_msg_append(msg, "work1", 5); nng_send(&push, msg, 0); }

        rv = nng_recv(&pull0, &rx, 1);
        EXPECT(rv == NNG_OK, "pull0 recv");
        if (rv == NNG_OK) {
            EXPECT(nng_test_body_eq(rx, "work0", 5),
                   "pull0 body == work0");
            nng_msg_free(rx);
        }

        rv = nng_recv(&pull1, &rx, 1);
        EXPECT(rv == NNG_OK, "pull1 recv");
        if (rv == NNG_OK) {
            EXPECT(nng_test_body_eq(rx, "work1", 5),
                   "pull1 body == work1");
            nng_msg_free(rx);
        }

        EXPECT(nng_recv(&pull0, &rx, 1) == NNG_ETIMEDOUT, "pull0 empty after rr");
        EXPECT(nng_recv(&pull1, &rx, 1) == NNG_ETIMEDOUT, "pull1 empty after rr");

        nng_socket_close(&push);
        nng_socket_close(&pull0);
        nng_socket_close(&pull1);
    }

    /* ── 3. REQ/REP: request-reply round-trip ────────────────────────── */
    {
        nng_socket_t req, rep;
        EXPECT(nng_socket_create(&req, NNG_PROTO_REQ0) == NNG_OK, "req create");
        EXPECT(nng_socket_create(&rep, NNG_PROTO_REP0) == NNG_OK, "rep create");
        EXPECT(nng_connect(&req, &rep) == NNG_OK, "req->rep connect");

        rv = nng_msg_alloc(&msg, 0);
        if (rv == NNG_OK) {
            nng_msg_append(msg, "ping", 4);
            EXPECT(nng_send(&req, msg, 0) == NNG_OK, "req send ping");
        }

        rv = nng_recv(&rep, &rx, 1);
        EXPECT(rv == NNG_OK, "rep recv ping");
        if (rv == NNG_OK) {
            EXPECT(nng_test_body_eq(rx, "ping", 4),
                   "rep body == ping");
            nng_msg_free(rx);
        }

        rv = nng_msg_alloc(&msg, 0);
        if (rv == NNG_OK) {
            nng_msg_append(msg, "pong", 4);
            EXPECT(nng_send(&rep, msg, 0) == NNG_OK, "rep send pong");
        }

        rv = nng_recv(&req, &rx, 1);
        EXPECT(rv == NNG_OK, "req recv pong");
        if (rv == NNG_OK) {
            EXPECT(nng_test_body_eq(rx, "pong", 4),
                   "req body == pong");
            nng_msg_free(rx);
        }

        nng_socket_close(&req);
        nng_socket_close(&rep);
    }

#undef EXPECT

    if (fail == 0)
        log_message(LOG_INFO,
                    "NNG pattern tests: PASS (%d/%d)\n", pass, pass);
    else
        log_message(LOG_ERROR,
                    "NNG pattern tests: %d FAILED (%d/%d passed)\n",
                    fail, pass, pass + fail);
}

/* Transactional-storage end-to-end test (storage track, C5).
 *
 * Subtest 1: 1000 generate_transaction_id() calls — verifies strict
 *            monotonicity and distinctness (IPL bracketing in C3).
 * Subtest 2: register a 4 KiB buffer with a known byte pattern,
 *            create_checkpoint, mutate the source, restore_checkpoint,
 *            assert byte-for-byte match (round-trip of C4).
 * Subtest 3: overflow the bounded txn log (1000 writes vs 256 slots)
 *            and assert ipc_ring.overflow is bumped — the cross-
 *            subsystem seam from C2 that the auditor exporter
 *            converts to an OVERFLOW telemetry record on its next
 *            tick. We drive auditor_tick() explicitly at the end so
 *            the record lands on COM2 / PL011 UART1 before the next
 *            test path runs. */
static void test_transactional_storage(void) {
    log_message(LOG_INFO, "Testing transactional storage...\n");
    int pass = 0;

    /* ── Subtest 1: 1000 distinct monotonic IDs ─────────────────── */
    {
        uint64_t prev = 0u;
        int ok = 1;
        int i;
        for (i = 0; i < 1000; i++) {
            uint64_t id = generate_transaction_id();
            if (id <= prev) { ok = 0; break; }
            prev = id;
        }
        if (ok) {
            log_message(LOG_INFO,
                "Storage test 1 PASS: 1000/1000 distinct monotonic ids\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Storage test 1 FAIL: monotonicity broke at i=%d\n", i);
        }
    }

    /* ── Subtest 2: 4 KiB round-trip via checkpoint/restore ─────── */
    {
        static uint8_t test_buf[CHECKPOINT_SIZE];
        size_t i;
        for (i = 0u; i < CHECKPOINT_SIZE; i++) {
            test_buf[i] = (uint8_t)(i & 0xFFu);   /* 0x00,0x01,...,0xFF,0x00,... */
        }

        int rv = storage_register_buffer("src_buf", test_buf, CHECKPOINT_SIZE);
        if (rv != 0) {
            log_message(LOG_ERROR,
                "Storage test 2 FAIL: register failed (rv=%d)\n", rv);
            goto subtest3;
        }

        if (create_checkpoint("src_buf", "ckpt_a") != 0) {
            log_message(LOG_ERROR, "Storage test 2 FAIL: create_checkpoint\n");
            goto subtest3;
        }

        /* Corrupt the source — restore must overwrite this. */
        for (i = 0u; i < CHECKPOINT_SIZE; i++) {
            test_buf[i] = 0xCCu;
        }

        if (restore_checkpoint("ckpt_a", "src_buf") != 0) {
            log_message(LOG_ERROR, "Storage test 2 FAIL: restore_checkpoint\n");
            goto subtest3;
        }

        size_t mismatches = 0u;
        for (i = 0u; i < CHECKPOINT_SIZE; i++) {
            if (test_buf[i] != (uint8_t)(i & 0xFFu)) mismatches++;
        }
        if (mismatches == 0u) {
            log_message(LOG_INFO,
                "Storage test 2 PASS: 4096/4096 bytes restored\n");
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Storage test 2 FAIL: %u byte mismatches\n",
                (unsigned int)mismatches);
        }
    }

subtest3:
    /* ── Subtest 3: deliberate txn-log overflow ─────────────────── */
    {
        /* Drain any pending overflow + entries from earlier subtests
         * (create_checkpoint and restore_checkpoint each emit one
         * txn_log entry) so we're measuring this subtest's delta
         * against a known baseline. The auditor exporter consumes
         * ring entries but not the txn_log itself, so we record the
         * current txn_log depth and recompute the expected drop count
         * from it. */
        auditor_tick();
        uint32_t baseline_overflow = ipc_ring.overflow;
        uint32_t baseline_local    = txn_log_get_overflow();
        uint32_t baseline_depth    = txn_log_get_depth();

        /* TXN_LOG_ENTRIES is 256; write 1000 — guarantees overflow.
         * Expected drops = max(0, 1000 - (256 - baseline_depth)). */
        const uint32_t writes = 1000u;
        const uint32_t capacity = 256u;
        const uint32_t free_slots = (baseline_depth < capacity)
            ? (capacity - baseline_depth) : 0u;
        const uint32_t expected_drops = (writes > free_slots)
            ? (writes - free_slots) : 0u;

        uint32_t i;
        for (i = 0u; i < writes; i++) {
            txn_log_entry_t e;
            e.txn_id    = generate_transaction_id();
            e.task_id   = 0u;
            e.operation = OP_WRITE;
            e.checksum  = 0u;
            e.key[0]    = 'k';
            e.key[1]    = '\0';
            e.value[0]  = 'v';
            e.value[1]  = '\0';
            (void)log_transaction(&e);
        }

        uint32_t local_delta    = txn_log_get_overflow() - baseline_local;
        uint32_t exporter_delta = ipc_ring.overflow      - baseline_overflow;

        /* Both counters must witness the same drop count, equal to
         * the expected_drops derived from baseline_depth. */
        if (local_delta == expected_drops &&
            exporter_delta == expected_drops &&
            expected_drops > 0u) {
            log_message(LOG_INFO,
                "Storage test 3 PASS: ring overflow=%u (local) / %u (exporter), expected=%u\n",
                (unsigned int)local_delta,
                (unsigned int)exporter_delta,
                (unsigned int)expected_drops);
            pass++;
        } else {
            log_message(LOG_ERROR,
                "Storage test 3 FAIL: expected=%u, got local=%u exporter=%u (baseline_depth=%u)\n",
                (unsigned int)expected_drops,
                (unsigned int)local_delta,
                (unsigned int)exporter_delta,
                (unsigned int)baseline_depth);
        }

        /* Flush — the auditor will emit an OVERFLOW record on COM2 /
         * PL011 UART1, captured by the QEMU -serial file binding. */
        auditor_tick();
    }

    log_message(LOG_INFO, "Storage tests: %d/3 passed\n", pass);
}

/**
 * @brief Initialize the kernel and its subsystems
 * 
 * This function is called on system boot to initialize all
 * essential kernel components, including hardware detection,
 * security, memory, and messaging systems.
 * 
 * Complies with:
 * - SEI CERT STR30-C: Ensure pointers are not null before dereferencing
 * - JPL Rule 15: Validate parameters before use
 */
void kmain(void) {
    // For RISC-V, provide more early debug output
#ifdef __riscv
    early_debug_print("[RISC-V] kmain() starting\r\n");
    early_debug_print("[RISC-V] About to call log_message...\r\n");
#endif

    // Initialize essential kernel subsystems
    log_message(LOG_INFO, "%s v%s booting...\n", OS_NAME, OS_VERSION);
    
    // Initialize hardware detection and security features
    if (!hw_detect()) {
        log_message(LOG_ERROR, "Hardware detection failed, halting system\n");
        return;
    }
    
    // Initialize console for output
    console_init();
    
    // Initialize security subsystem first (needed for validations)
    security_init();
    
    // Initialize memory subsystem (Per NASA Power of Ten rule 3: all allocation at init time)
    memory_init();

    // Page frame allocator (Phase 3 B1) — foundation for MMU work in B2/B3/B4.
    frame_allocator_init();

    // Initialize crypto subsystem (depends on memory and security)
    crypto_init();

    // Initialize x86 interrupt subsystem: GDT → IDT → PIC → PIT → enable IRQs
#if defined(__i386__)
    gdt_init();        /* load our GDT; fixes the latent user-selector bug       */
    idt_init();        /* install 32 exception + 16 IRQ + syscall gates           */
    pic_remap();       /* remap PICs to 0x20-0x2F (out of exception vector space) */
    pit_init(100);     /* 100 Hz timer on IRQ0; registers pit_tick handler        */
    pic_unmask(0);     /* enable IRQ0 (PIT) in the PIC mask                       */
    __asm__ volatile("sti");  /* IF=1: CPU accepts interrupts                     */
    (void)spl0();      /* lower IPL to IPL_NONE: PIC delivers enabled IRQs        */
#endif

#if defined(__arm__)
    // ARM interrupt subsystem: VIC → SP804 timer → MMU enable → CPU IRQ unmask.
    // Mirrors the x86 pic_remap → pit_init → paging → sti sequence above.
    extern void vic_init(void);
    extern void arm_timer_init(void);
    vic_init();
    arm_timer_init();
    /* Phase 3 B3: enable MMU (identity-mapped, DACR=Manager, caches off).
     * Order matters — vic_init / arm_timer_init have already poked the
     * device registers, but those addresses are in the identity-mapped
     * device window so subsequent accesses keep working. Done BEFORE the
     * CPSR.I clear so the first IRQ to fire runs with MMU on, matching
     * the post-B3 steady state. */
    arm_mmu_init();
    /* ARMv5 has no `cpsie` (ARMv6+ only). Clear CPSR.I longhand. */
    __asm__ volatile(
        "mrs r0, cpsr\n\t"
        "bic r0, r0, #0x80\n\t"
        "msr cpsr_c, r0"
        : : : "r0", "memory");
    // Initialize ARM system call interface
    init_syscall_arm();
#elif defined(__riscv)
    // Initialize RISC-V system call interface
    init_syscall_riscv_c();
#else
    // Initialize x86 system call interface
    init_syscall();
#endif
    
    // Establish root-of-trust task before IPC: ipc_create_channel checks
    // current_task->cap_mask, so it must point to a real task by this point.
    task_init();

    // Initialise the domain transition matrix BEFORE init_ipc() so any
    // cross-domain check inside IPC has a populated matrix to consult.
    // Default state is identity (each domain reaches only itself) — explicit
    // edges must be added via domain_edge_set() before domain_edges_seal().
    domain_edges_init();

    // Initialize IPC subsystem (includes NNG init) and arm auditor ring
    init_ipc();
    auditor_init();

    /* Phase 4 F1: backfill the kernel_task TASK_CREATE event the
     * auditor missed because task_init runs before auditor_init.
     * Without this, the audit stream has no record for task_id=1
     * even though every other task references it as parent. */
    task_emit_kernel_create_event();

    // Initialize scheduler
    rr_scheduler.init(NULL);

    // Run NNG tests
    test_nng();
    test_energy_grid_alert();
    test_auditor();
    test_ipc_enforcement();
    test_task_caps();
    test_task_lifecycle();
    test_frame_allocator();
    test_mmu_protection();
    test_fault_telemetry();
    test_transactional_storage();
    test_nng_patterns();

    // Test the update system
    test_update_system();

    // All policy mutations are done — seal the domain matrix so a
    // compromised user task cannot widen cross-domain reachability.
    domain_edges_seal();

    // Initialize user mode subsystem
    log_message(LOG_INFO, "Initializing user mode subsystem\n");

    // Establish the user identity before any user-mode code runs.
    // Bounded-narrowing inheritance in create_task means user_init_task
    // cannot widen caps beyond CAP_IPC_SEND. ipc_create_channel below
    // then runs as user_init_task, so the bootstrap channel inherits
    // the same narrow cap_mask — sending OP_DELETE / OP_WRITE through
    // it will produce a DENY_CAP_PRIV auditor record.
    user_init_task.task_id        = 0;
    user_init_task.priority       = 5;
    user_init_task.cap_mask       = CAP_IPC_SEND;
    user_init_task.domain         = 0;
    user_init_task.state          = TASK_READY;
    user_init_task.deadline       = 0;
    user_init_task.parent_task_id = TASK_PARENT_NONE; /* create_task overwrites it from current_task */
    if (create_task(&user_init_task) != 0) {
        log_message(LOG_ERROR, "Failed to create user_init_task\n");
    } else {
        /* current_task must point at the table-resident copy so the
         * scheduler and IPC paths see identical state (Phase 3 A1). */
        task_t* live = task_find(user_init_task.task_id);
        current_task = (live != NULL) ? live : &user_init_task;
        user_bootstrap_channel = ipc_create_channel(0u, 0u, CAP_IPC_SEND,
                                                    NNG_PROTO_PUB0);
        if (user_bootstrap_channel < 0) {
            log_message(LOG_ERROR,
                "Failed to create user bootstrap channel (rv=%d)\n",
                user_bootstrap_channel);
        } else {
            log_message(LOG_INFO,
                "user_init_task ready (id=%u caps=0x%X) on channel %d\n",
                user_init_task.task_id, user_init_task.cap_mask,
                user_bootstrap_channel);
        }
    }
    
    // The following would normally be loaded by a dynamic loader or initrd
    // For now, we'll just hardcode a test address
    uint32_t user_eip = 0x400000; // Entry point from linker script
    uint32_t user_esp = 0x700000; // Stack position
    
    // Check if we have a user program to load (would come from initrd or filesystem)
    // Using the symbols created by objcopy
    // Binary symbols created by ld (using -b binary)
#if defined(__i386__) || defined(__x86_64__)
    extern char _binary_build_x86_user_hello_bin_start[];
    extern char _binary_build_x86_user_hello_bin_end[];
    void* binary_start = (void*)_binary_build_x86_user_hello_bin_start;
    void* binary_end = (void*)_binary_build_x86_user_hello_bin_end;
#elif defined(__arm__)
    extern char _binary_build_arm_user_hello_bin_start[];
    extern char _binary_build_arm_user_hello_bin_end[];
    void* binary_start = (void*)_binary_build_arm_user_hello_bin_start;
    void* binary_end = (void*)_binary_build_arm_user_hello_bin_end;
#elif defined(__riscv)
    extern char _binary_build_riscv_user_hello_bin_start[];
    extern char _binary_build_riscv_user_hello_bin_end[];
    void* binary_start = (void*)_binary_build_riscv_user_hello_bin_start;
    void* binary_end = (void*)_binary_build_riscv_user_hello_bin_end;
#else
    #error "Unsupported architecture"
    void* binary_start = NULL;
    void* binary_end = NULL;
#endif
    
    if (binary_start != NULL && binary_end != NULL) {
        size_t size = (size_t)((uintptr_t)binary_end - (uintptr_t)binary_start);
        log_message(LOG_INFO, "Found user program: size=%u bytes\n", (unsigned int)size);
        
        // Load the user program
        if (load_user_program(binary_start, size, &user_eip, &user_esp) == 0) {
            log_message(LOG_INFO, "User program loaded: eip=0x%x, esp=0x%x\n", (unsigned int)user_eip, (unsigned int)user_esp);
            log_message(LOG_INFO, "User program loaded, switching to user mode\n");
            switch_to_user_mode(user_eip, user_esp); // No return
        } else {
            log_message(LOG_ERROR, "Failed to load user program\n");
        }
    }
    
    // If we reach here, either no user program was found or loading failed
    log_message(LOG_INFO, "No user program found or load failed, entering kernel main loop\n");
    
    // Simple microkernel main loop - for now, just idle
    while (1) {
        // Process any pending events
        process_events();
        // Idle the CPU to conserve power
        cpu_idle();
    }
}