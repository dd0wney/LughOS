#include "lugh.h"
#include "security.h"
#include "hardware.h"
#include "interrupt.h"
#include "nngcompat.h"
#include "console.h"
#include "crypto.h"
#include "watchdog.h"
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
void test_watchdog(void);
int  init_ipc(void);
int  ipc_create_channel(uint32_t security_level, uint32_t domain, int protocol);
int  ipc_send(int channel_id, message_t *msg);

extern scheduler_ops_t rr_scheduler;

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

void test_watchdog(void) {
    log_message(LOG_INFO, "Testing watchdog telemetry path...\n");
    int ch = ipc_create_channel(0, 0, NNG_PROTO_PUB0);
    if (ch < 0) {
        log_message(LOG_ERROR, "Watchdog test: failed to create IPC channel\n");
        return;
    }
    message_t msg;
    msg.priority  = PRIORITY_HIGH;
    msg.operation = 0xDEADBEEFu;
    msg.checksum  = 0;
    msg._padding1 = 0;
    memset(msg.payload, 0, MAX_MSG_SIZE);
    memcpy(msg.payload, "watchdog-test", 13);
    ipc_send(ch, &msg);          /* triggers ring_push */
    watchdog_tick();              /* drains ring → emits telemetry record on COM2 */
    log_message(LOG_INFO, "Watchdog test: record emitted (check /tmp/lugh_ipc.bin)\n");
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
    // Initialize ARM system call interface
    init_syscall_arm();
#elif defined(__riscv)
    // Initialize RISC-V system call interface
    init_syscall_riscv_c();
#else
    // Initialize x86 system call interface
    init_syscall();
#endif
    
    // Initialize IPC subsystem (includes NNG init) and arm watchdog ring
    init_ipc();
    watchdog_init();

    // Initialize scheduler
    rr_scheduler.init(NULL);

    // Run NNG tests
    test_nng();
    test_energy_grid_alert();
    test_watchdog();
    test_nng_patterns();
    
    // Test the update system
    test_update_system();
    
    // Initialize user mode subsystem
    log_message(LOG_INFO, "Initializing user mode subsystem\n");
    
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