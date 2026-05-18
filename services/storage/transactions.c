#include "lugh.h"
#include "assert.h"
#include "interrupt.h"
#include "hardware.h"
#include "transactions.h"

/* ── 1. Transaction-ID allocator ────────────────────────────────────
 *
 * IPL bracketing (splhigh/splx) makes the read-modify-write indivisible
 * against any kernel-mode preempter. On UP ARMv5 this is sufficient —
 * no other core can race once IRQs are masked. Same semantics on x86
 * via splhigh tracking the PIC mask. No LDREX/STREX needed.
 *
 * Defensive wrap check per NASA Power of Ten rule 5: at 2^64 IDs the
 * counter saturates. ~585 years at 1 GHz alloc but the invariant is
 * enforced rather than assumed. */
uint64_t generate_transaction_id(void) {
    static uint64_t next_id = 1u; /* 0 reserved as "no txn" */
    spl_t prev = splhigh();
    if (next_id == 0xFFFFFFFFFFFFFFFFull) {
        splx(prev); /* leave IPL consistent before halting */
        cpu_halt();
    }
    uint64_t id = next_id;
    next_id++;
    splx(prev);
    return id;
}

/* ── 2. Registered buffer table ─────────────────────────────────────
 *
 * The "labeled buffer keyed by src" referenced by create_checkpoint and
 * restore_checkpoint. There is no real filesystem in Phase 3 — buffers
 * are caller-owned regions registered by the test harness (or, later,
 * a service that wants snapshot/restore support).
 *
 * NASA Power of Ten rule 2: fixed-size table (no growth).
 * MAX_CHECKPOINTS is reused as the bound — the same scale fits both
 * sides of the operation. */
typedef struct {
    char    key[64];
    void   *data;
    size_t  size;
    bool    in_use;
} registered_buffer_t;

static registered_buffer_t registered_buffers[MAX_CHECKPOINTS];

/* Local memcmp — no libc and lugh.h doesn't expose one. */
static int key_equal(const char *a, const char *b) {
    size_t i;
    for (i = 0u; i < 64u; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

static registered_buffer_t* find_registered(const char *key) {
    uint32_t i;
    for (i = 0u; i < MAX_CHECKPOINTS; i++) {
        if (registered_buffers[i].in_use &&
            key_equal(registered_buffers[i].key, key)) {
            return &registered_buffers[i];
        }
    }
    return NULL;
}

int storage_register_buffer(const char *key, void *data, size_t size) {
    if (key == NULL || data == NULL || size == 0u || size > CHECKPOINT_SIZE) {
        return -1;
    }
    if (strlen(key) >= sizeof(registered_buffers[0].key)) {
        return -1;
    }
    /* Re-registration of an existing key updates the binding in place. */
    registered_buffer_t *existing = find_registered(key);
    if (existing != NULL) {
        existing->data = data;
        existing->size = size;
        return 0;
    }
    uint32_t i;
    for (i = 0u; i < MAX_CHECKPOINTS; i++) {
        if (!registered_buffers[i].in_use) {
            /* strcpy is safe here: the bound check above guarantees fit. */
            strcpy(registered_buffers[i].key, key);
            registered_buffers[i].data   = data;
            registered_buffers[i].size   = size;
            registered_buffers[i].in_use = true;
            return 0;
        }
    }
    return -1; /* table full */
}

/* ── 3. Checkpoint slots ────────────────────────────────────────────
 *
 * Each slot snapshots up to CHECKPOINT_SIZE bytes of a registered
 * buffer at a point in time, keyed by the dst string. No persistence —
 * lives only across a kernel boot. */
typedef struct {
    char    key[64];
    uint8_t data[CHECKPOINT_SIZE];
    size_t  size;
    bool    in_use;
} checkpoint_slot_t;

static checkpoint_slot_t checkpoint_slots[MAX_CHECKPOINTS];

static checkpoint_slot_t* find_slot(const char *key) {
    uint32_t i;
    for (i = 0u; i < MAX_CHECKPOINTS; i++) {
        if (checkpoint_slots[i].in_use &&
            key_equal(checkpoint_slots[i].key, key)) {
            return &checkpoint_slots[i];
        }
    }
    return NULL;
}

static checkpoint_slot_t* acquire_slot(const char *key) {
    /* Reuse an existing slot for the same key (overwrite semantics). */
    checkpoint_slot_t *s = find_slot(key);
    if (s != NULL) return s;
    uint32_t i;
    for (i = 0u; i < MAX_CHECKPOINTS; i++) {
        if (!checkpoint_slots[i].in_use) {
            if (strlen(key) >= sizeof(checkpoint_slots[i].key)) {
                return NULL;
            }
            strcpy(checkpoint_slots[i].key, key);
            checkpoint_slots[i].in_use = true;
            return &checkpoint_slots[i];
        }
    }
    return NULL;
}

/* ── 4. Public checkpoint API ───────────────────────────────────────
 *
 * Each operation:
 *   1. allocates a transaction ID via the atomic allocator
 *   2. performs the copy
 *   3. emits a txn_log_entry_t with op + key + value into the global
 *      transaction ring (kernel/fs/storage.c)
 * The log entry's task_id is stamped automatically by log_transaction
 * from current_task. */
static void emit_txn(uint64_t txn_id, int op, const char *src, const char *dst) {
    txn_log_entry_t e;
    e.txn_id    = txn_id;
    e.task_id   = 0u;          /* stamped by log_transaction from current_task */
    e.operation = op;
    e.checksum  = 0u;
    /* Best-effort key copy: truncate on overflow. STR31-C: always NUL-terminate. */
    size_t i;
    for (i = 0u; i < sizeof(e.key) - 1u && src[i] != '\0'; i++) e.key[i] = src[i];
    e.key[i] = '\0';
    for (i = 0u; i < sizeof(e.value) - 1u && dst[i] != '\0'; i++) e.value[i] = dst[i];
    e.value[i] = '\0';
    (void)log_transaction(&e);
}

int create_checkpoint(const char *src, const char *dst) {
    if (src == NULL || dst == NULL) return -1;
    registered_buffer_t *src_buf = find_registered(src);
    if (src_buf == NULL) return -1;

    checkpoint_slot_t *slot = acquire_slot(dst);
    if (slot == NULL) return -1;

    /* Copy under bound. src_buf->size is constrained ≤ CHECKPOINT_SIZE
     * at register time, so no truncation here in normal use. */
    memcpy(slot->data, src_buf->data, src_buf->size);
    slot->size = src_buf->size;

    emit_txn(generate_transaction_id(), OP_WRITE, src, dst);
    return 0;
}

int restore_checkpoint(const char *src, const char *dst) {
    if (src == NULL || dst == NULL) return -1;
    checkpoint_slot_t *slot = find_slot(src);
    if (slot == NULL) return -1;
    registered_buffer_t *dst_buf = find_registered(dst);
    if (dst_buf == NULL) return -1;
    if (slot->size > dst_buf->size) return -1;

    memcpy(dst_buf->data, slot->data, slot->size);

    emit_txn(generate_transaction_id(), OP_WRITE, src, dst);
    return 0;
}

int remove_checkpoint(const char *checkpoint) {
    if (checkpoint == NULL) return -1;
    checkpoint_slot_t *slot = find_slot(checkpoint);
    if (slot == NULL) return -1;
    slot->in_use = false;
    slot->size   = 0u;
    emit_txn(generate_transaction_id(), OP_DELETE, checkpoint, "");
    return 0;
}

/* ── 5. Legacy stubs preserved for the existing update.c consumer ──── */

int copy_file(const char *src, const char *dst) {
    assert(src != NULL && dst != NULL);
    /* No real filesystem in Phase 3 — treat as a logged no-op. */
    (void)src; (void)dst;
    return 0;
}

void log_transaction_file(const char *operation, const char *src, const char *dst) {
    if (operation == NULL) operation = "Unknown";
    if (src == NULL)       src       = "N/A";
    if (dst == NULL)       dst       = "N/A";
    log_message(LOG_INFO, "TRANSACTION: %s - From: %s, To: %s",
                operation, src, dst);
}

int install_update(const char *path, const uint8_t *image, size_t size) {
    assert(path != NULL && image != NULL && size > 0);
    log_message(LOG_INFO, "Installing update to %s (size: %u bytes)",
                path, (unsigned int)size);
    return 0;
}
