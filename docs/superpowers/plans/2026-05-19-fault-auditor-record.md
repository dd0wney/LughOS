# AUDITOR_REC_FAULT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire ARM abort handlers to emit a new `AUDITOR_REC_FAULT` (type 9) binary telemetry record so fault events appear in the auditor stream the JEPA encoder reads.

**Architecture:** Single record type with a `fault_subtype` field (pabort / dabort-read / dabort-write) packed into the `protocol` byte, following the established field-reuse-per-type pattern. The emitter (`emit_fault_record`) is synchronous and bypasses the ring buffer — identical to TASK_CREATE / CHAN_CREATE. Python scripts are updated to recognise type 9 without asserting its presence in CI.

**Tech Stack:** C (ARM cross-compiler `arm-none-eabi-gcc`), Python 3, GNU Make, QEMU `versatilepb`.

---

## File Map

| File | Role |
|------|------|
| `include/auditor.h` | Add `AUDITOR_REC_FAULT 9u`, three `AUDITOR_FAULT_*` subtype constants, wire-format comment, `auditor_fault()` declaration |
| `services/auditor/exporter.c` | Add `emit_fault_record()` (static) + `auditor_fault()` (public) |
| `kernel/arch/arm/abort_diag.c` | Call `auditor_fault()` from both diagnose functions |
| `scripts/validate_telemetry.py` | Register type 9 as `"FAULT"` in `REC_TYPE_NAME`; no presence assertion |
| `scripts/reconstruct_graph.py` | Add `REC_FAULT = 9` constant; add explicit no-op `elif` branch |
| `scripts/test_fault_record.py` | New: TDD test script for the Python-side changes |
| `kernel/main.c` | Add `test_fault_telemetry()` + wire into `kernel_main` call sequence |

---

### Task 1: Write the failing Python test

**Files:**
- Create: `scripts/test_fault_record.py`

- [ ] **Step 1: Create the test script**

```python
#!/usr/bin/env python3
"""TDD: FAULT record (type=9) must not trigger 'unknown record_type' in validate_telemetry.py
and must be a graph no-op in reconstruct_graph.py.

Run from the repo root:
    python3 scripts/test_fault_record.py
Exit 0 = all checks passed.
"""
import os
import struct
import subprocess
import sys
import tempfile

RECORD_FMT = "<IHHQBBBBII16s"
MAGIC = 0x4C474849
VERSION = 2

REC_MSG          = 0
REC_OVERFLOW     = 1
REC_DENY         = 3
REC_TASK_CREATE  = 4
REC_CHAN_CREATE  = 5
REC_CHAN_CONNECT = 6
REC_DOMAIN_EDGE  = 8
REC_FAULT        = 9

FAULT_PABORT       = 0
FAULT_DABORT_READ  = 1
FAULT_DABORT_WRITE = 2


def make_record(rec_type, jiffies=1000, priority=0, src_domain=0, protocol=0,
                channel_id=0, operation=0, checksum=0, payload_hash=None):
    if payload_hash is None:
        payload_hash = b"\x00" * 16
    return struct.pack(RECORD_FMT,
        MAGIC, VERSION, rec_type, jiffies,
        priority, src_domain, protocol, channel_id,
        operation, checksum, payload_hash)


def make_required_stream():
    """All categories in REQUIRED + two FAULT records (pabort and dabort_write)."""
    # MSG — payload_hash can be anything, just needs to be 16 bytes
    msg_payload = b"test" + b"\x00" * 12
    records = [
        make_record(REC_MSG,          operation=0xDEADBEEF, payload_hash=msg_payload),
        make_record(REC_OVERFLOW,     operation=1),
        make_record(REC_DENY,         src_domain=1, protocol=2, channel_id=0),
        make_record(REC_TASK_CREATE,  operation=1, checksum=0xFFFFFFFF),
        make_record(REC_CHAN_CREATE,   channel_id=1, operation=0xFF, checksum=1),
        make_record(REC_CHAN_CONNECT,  channel_id=1, operation=2),
        make_record(REC_DOMAIN_EDGE,  operation=0, checksum=1,
                    payload_hash=b"\x01" + b"\x00" * 15),
        # Two FAULT records: prefetch + data-write
        make_record(REC_FAULT, src_domain=0, protocol=FAULT_PABORT,
                    operation=0xDEAD0000, checksum=0,
                    payload_hash=b"\x00" * 8 + b"\x01\x00\x00\x00" + b"\x00" * 4),
        make_record(REC_FAULT, src_domain=2, protocol=FAULT_DABORT_WRITE,
                    operation=0xCAFE0000, checksum=0xBAD00000,
                    payload_hash=struct.pack("<IIII", 0x0000000F, 0x00000090, 2, 0)),
    ]
    return b"".join(records)


def run(cmd, input_path):
    result = subprocess.run(
        [sys.executable] + cmd + [input_path],
        capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    return result.returncode, result.stdout + result.stderr


def main():
    stream = make_required_stream()
    failures = []

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(stream)
        path = f.name

    try:
        # ── Check 1: validate_telemetry.py accepts FAULT records ─────────
        rc, out = run(["scripts/validate_telemetry.py"], path)
        if "unknown record_type 9" in out:
            failures.append("validate_telemetry.py: reports FAULT as unknown type")
        if rc != 0:
            failures.append(f"validate_telemetry.py: non-zero exit {rc}:\n{out}")

        # ── Check 2: reconstruct_graph.py runs without error ─────────────
        rc, out = run(["scripts/reconstruct_graph.py"], path)
        if rc != 0:
            failures.append(f"reconstruct_graph.py: non-zero exit {rc}:\n{out}")
        if "digraph" not in out:
            failures.append("reconstruct_graph.py: no 'digraph' in output — DOT not produced")

    finally:
        os.unlink(path)

    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

    print("PASS: all fault-record checks passed")
    sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run to verify it partially fails (proves the gap)**

```bash
python3 scripts/test_fault_record.py
```

Expected output:
```
FAIL:
  - validate_telemetry.py: reports FAULT as unknown type
```

Note: the reconstruct_graph.py check already passes — the existing unknown-type
fallthrough in `apply_record()` silently no-ops FAULT records. Task 4 adds the
explicit branch for documentation; it is not needed for correctness.

---

### Task 2: Add AUDITOR_REC_FAULT to auditor.h

**Files:**
- Modify: `include/auditor.h`

- [ ] **Step 1: Add the constant after AUDITOR_REC_DOMAIN_EDGE**

In `include/auditor.h`, find:
```c
#define AUDITOR_REC_DOMAIN_EDGE  8u  /* domain matrix mutation    */
```

Replace with:
```c
#define AUDITOR_REC_DOMAIN_EDGE  8u  /* domain matrix mutation    */
#define AUDITOR_REC_FAULT        9u  /* ARM abort (prefetch/data) */

/* Fault subtypes — packed into the wire record's `protocol` byte.
 * The DFSR W-bit (bit 11) is decoded at the call site so Python
 * decoders need no ARM-specific bit manipulation. */
#define AUDITOR_FAULT_PABORT        0u  /* prefetch abort             */
#define AUDITOR_FAULT_DABORT_READ   1u  /* data abort, read access    */
#define AUDITOR_FAULT_DABORT_WRITE  2u  /* data abort, write access   */
```

- [ ] **Step 2: Add wire-format comment for FAULT in the big field-semantics block**

In the `auditor_record_t` comment block in `include/auditor.h`, find the line:
```c
 *   TASK_EXIT:   priority=0, src_domain=0, protocol=0, channel_id=0,
```

Add before that line:
```c
 *   FAULT:       priority=0, src_domain=task.domain & 0xFF (0 = no current_task),
 *                protocol=fault_subtype (AUDITOR_FAULT_PABORT/DABORT_READ/DABORT_WRITE),
 *                channel_id=0,
 *                operation=fault_pc (faulting instruction VA),
 *                checksum=dfar (Data Fault Address; 0 for prefetch),
 *                payload_hash[0..3]=dfsr (Data Fault Status; 0 for prefetch),
 *                payload_hash[4..7]=spsr (pre-fault CPSR snapshot),
 *                payload_hash[8..11]=task_id (0 if no current_task),
 *                payload_hash[12..15]=zeros.
 *                Emitted synchronously (no ring) from arm_pabort_diagnose /
 *                arm_dabort_diagnose so the record lands before the panic
 *                busy-loop. Accesses current_task directly (declared extern
 *                in lugh.h) — the abort site does not need to pass task
 *                context explicitly.
 *
```

- [ ] **Step 3: Add auditor_fault() declaration at the bottom of auditor.h**

After `void auditor_task_exit(uint32_t task_id, int exit_code);`, add:

```c
/* Fault event — emitted synchronously from ARM abort handlers.
 * fault_type is one of AUDITOR_FAULT_PABORT / DABORT_READ / DABORT_WRITE.
 * dfar and dfsr should be 0 for prefetch aborts (no data address). */
void auditor_fault(uint32_t fault_pc,
                   uint32_t dfar,
                   uint32_t dfsr,
                   uint32_t spsr,
                   uint8_t  fault_type);
```

- [ ] **Step 4: Build ARM to verify the header compiles**

```bash
make arm 2>&1 | tail -5
```

Expected: build succeeds (no `auditor_fault` definition yet — the declaration alone doesn't cause a link error until abort_diag.c calls it).

---

### Task 3: Update validate_telemetry.py

**Files:**
- Modify: `scripts/validate_telemetry.py`

- [ ] **Step 1: Add FAULT to REC_TYPE_NAME**

In `scripts/validate_telemetry.py`, find:
```python
REC_TYPE_NAME = {
    0: "MSG",
    1: "OVERFLOW",
    2: "HEARTBEAT",
    3: "DENY",
    4: "TASK_CREATE",
    5: "CHAN_CREATE",
    6: "CHAN_CONNECT",
    7: "TASK_EXIT",
    8: "DOMAIN_EDGE",
}
```

Replace with:
```python
REC_TYPE_NAME = {
    0: "MSG",
    1: "OVERFLOW",
    2: "HEARTBEAT",
    3: "DENY",
    4: "TASK_CREATE",
    5: "CHAN_CREATE",
    6: "CHAN_CONNECT",
    7: "TASK_EXIT",
    8: "DOMAIN_EDGE",
    9: "FAULT",
}
```

Do NOT add `"FAULT"` to `REQUIRED` — fault absence on a clean boot is correct.

- [ ] **Step 2: Run the Python test — it should now fully pass**

```bash
python3 scripts/test_fault_record.py
```

Expected:
```
PASS: all fault-record checks passed
```

Both checks pass: validate_telemetry.py now accepts type 9, and reconstruct_graph.py
already handled unknown types as no-ops before Task 4.

---

### Task 4: Update reconstruct_graph.py

**Files:**
- Modify: `scripts/reconstruct_graph.py`

- [ ] **Step 1: Add REC_FAULT constant**

In `scripts/reconstruct_graph.py`, find:
```python
REC_DOMAIN_EDGE = 8
```

Replace with:
```python
REC_DOMAIN_EDGE = 8
REC_FAULT       = 9  # prefetch/data abort — no-op for graph topology
```

- [ ] **Step 2: Add no-op branch in apply_record()**

In `scripts/reconstruct_graph.py`, find:
```python
    elif t == REC_DOMAIN_EDGE:
        # J7: src in operation, dst in checksum.
        src = rec["operation"]
        dst = rec["checksum"]
        state.domain_edges.add((src, dst))
```

Replace with:
```python
    elif t == REC_DOMAIN_EDGE:
        # J7: src in operation, dst in checksum.
        src = rec["operation"]
        dst = rec["checksum"]
        state.domain_edges.add((src, dst))

    elif t == REC_FAULT:
        # F3: fault records annotate task nodes but don't mutate graph topology.
        # Graph-level fault annotation (e.g. marking a task node "faulted") is
        # deferred to Phase 5. Explicit branch documents the intent.
        pass
```

- [ ] **Step 3: Confirm the Python test still passes**

```bash
python3 scripts/test_fault_record.py
```

Expected:
```
PASS: all fault-record checks passed
```

- [ ] **Step 4: Commit Python-side changes**

```bash
git add scripts/test_fault_record.py scripts/validate_telemetry.py scripts/reconstruct_graph.py
git commit -m "feat(jepa-prep): AUDITOR_REC_FAULT Python decoder support (Phase 4 F3)"
```

---

### Task 5: Implement auditor_fault() in exporter.c

**Files:**
- Modify: `services/auditor/exporter.c`

- [ ] **Step 1: Add emit_fault_record() static function**

In `services/auditor/exporter.c`, find:
```c
void auditor_task_exit(uint32_t task_id, int exit_code) {
```

Add before it:

```c
/* FAULT: synchronous panic-path event. Reads current_task directly
 * (extern task_t* current_task declared in lugh.h) — the abort handler
 * does not pass task context explicitly.
 *
 * Wire packing (mirrors auditor.h FAULT comment):
 *   protocol      = fault_type  (AUDITOR_FAULT_PABORT/DABORT_READ/DABORT_WRITE)
 *   operation     = fault_pc
 *   checksum      = dfar        (0 for prefetch aborts)
 *   payload_hash  = [dfsr:32][spsr:32][task_id:32][zeros:32]
 */
static void emit_fault_record(uint32_t fault_pc,
                               uint32_t dfar,
                               uint32_t dfsr,
                               uint32_t spsr,
                               uint8_t  fault_type) {
    auditor_record_t rec;
    init_record(&rec, AUDITOR_REC_FAULT);
    rec.priority   = 0;
    rec.src_domain = (current_task != NULL)
                     ? (uint8_t)(current_task->domain & 0xFFu)
                     : 0u;
    rec.protocol   = fault_type;
    rec.channel_id = 0;
    rec.operation  = fault_pc;
    rec.checksum   = dfar;

    uint32_t vals[4];
    vals[0] = dfsr;
    vals[1] = spsr;
    vals[2] = (current_task != NULL) ? current_task->task_id : 0u;
    vals[3] = 0u;
    uint32_t i;
    for (i = 0; i < 4u; i++) {
        rec.payload_hash[i * 4u + 0u] = (uint8_t)(vals[i]);
        rec.payload_hash[i * 4u + 1u] = (uint8_t)(vals[i] >> 8);
        rec.payload_hash[i * 4u + 2u] = (uint8_t)(vals[i] >> 16);
        rec.payload_hash[i * 4u + 3u] = (uint8_t)(vals[i] >> 24);
    }
    tlm_write_bytes(&rec, sizeof(rec));
}

void auditor_fault(uint32_t fault_pc,
                   uint32_t dfar,
                   uint32_t dfsr,
                   uint32_t spsr,
                   uint8_t  fault_type) {
    if (!auditor_enabled)
        return;
    emit_fault_record(fault_pc, dfar, dfsr, spsr, fault_type);
}

```

- [ ] **Step 2: Build ARM to verify it compiles**

```bash
make arm 2>&1 | tail -5
```

Expected: build succeeds. `auditor_fault` is now defined but the abort-diag call sites aren't wired yet — no linker warnings at this stage.

---

### Task 6: Wire abort_diag.c call sites

**Files:**
- Modify: `kernel/arch/arm/abort_diag.c`

- [ ] **Step 1: Add the auditor.h include**

In `kernel/arch/arm/abort_diag.c`, find:
```c
#include "lugh.h"
```

Replace with:
```c
#include "lugh.h"
#include "auditor.h"
```

- [ ] **Step 2: Call auditor_fault() in arm_pabort_diagnose()**

Find:
```c
    log_message(LOG_FATAL,
        "PABORT: pc=0x%X spsr=0x%X mode=0x%X task=%u\n",
        fault_pc, spsr, mode, current_task_id);
}
```

Replace with:
```c
    log_message(LOG_FATAL,
        "PABORT: pc=0x%X spsr=0x%X mode=0x%X task=%u\n",
        fault_pc, spsr, mode, current_task_id);
    auditor_fault(fault_pc, 0u, 0u, spsr, AUDITOR_FAULT_PABORT);
}
```

- [ ] **Step 3: Call auditor_fault() in arm_dabort_diagnose()**

Find:
```c
    log_message(LOG_FATAL,
        "DABORT: pc=0x%X va=0x%X dfsr=0x%X status=0x%X dom=%u %s "
        "spsr=0x%X mode=0x%X task=%u\n",
        fault_pc, dfar, dfsr, status, domain,
        is_write ? "write" : "read", spsr, mode, current_task_id);
}
```

Replace with:
```c
    log_message(LOG_FATAL,
        "DABORT: pc=0x%X va=0x%X dfsr=0x%X status=0x%X dom=%u %s "
        "spsr=0x%X mode=0x%X task=%u\n",
        fault_pc, dfar, dfsr, status, domain,
        is_write ? "write" : "read", spsr, mode, current_task_id);
    {
        uint8_t ft = is_write ? AUDITOR_FAULT_DABORT_WRITE : AUDITOR_FAULT_DABORT_READ;
        auditor_fault(fault_pc, dfar, dfsr, spsr, ft);
    }
}
```

- [ ] **Step 4: Build ARM**

```bash
make arm 2>&1 | tail -5
```

Expected: clean build, no warnings.

- [ ] **Step 5: Commit C implementation**

```bash
git add include/auditor.h services/auditor/exporter.c kernel/arch/arm/abort_diag.c
git commit -m "feat(jepa-prep): emit AUDITOR_REC_FAULT from ARM abort handlers (Phase 4 F3)"
```

---

### Task 7: Add test_fault_telemetry() and verify end-to-end

**Files:**
- Modify: `kernel/main.c`

- [ ] **Step 1: Add test_fault_telemetry() declaration near the other test declarations**

In `kernel/main.c`, find:
```c
void test_mmu_protection(void);
```

Add after it:
```c
void test_fault_telemetry(void);
```

- [ ] **Step 2: Add test_fault_telemetry() implementation**

In `kernel/main.c`, find the closing brace of `test_auditor()` (around line 270). Add after it:

```c
/* Direct call to auditor_fault() — exercises the emit path without
 * triggering a real hardware abort. The records land on COM2 / UART1
 * and are verifiable via scripts/validate_telemetry.py. */
void test_fault_telemetry(void) {
    log_message(LOG_INFO, "Testing auditor_fault() emit path...\n");

    /* Synthetic prefetch abort at a known VA from domain 0 task 1. */
    auditor_fault(0xDEAD0000u, 0u, 0u, 0x00000010u, AUDITOR_FAULT_PABORT);

    /* Synthetic data-write abort: VA=0xBAD00000, DFSR=0xF (permission L1),
     * SPSR=0x90 (IRQ disabled, ARM mode, SVC). */
    auditor_fault(0xCAFE0000u, 0xBAD00000u, 0x0000080Fu,
                  0x00000090u, AUDITOR_FAULT_DABORT_WRITE);

    log_message(LOG_INFO,
        "Fault telemetry test: 2 records emitted (pabort + dabort_write)\n");
}
```

- [ ] **Step 3: Wire the call into kernel_main**

Find in `kernel/main.c`:
```c
    test_mmu_protection();
```

Add after it:
```c
    test_fault_telemetry();
```

- [ ] **Step 4: Build ARM**

```bash
make arm 2>&1 | tail -5
```

Expected: clean build.

- [ ] **Step 5: Run ARM in QEMU and capture the telemetry stream**

```bash
timeout 15s qemu-system-arm \
  -M versatilepb -cpu arm926 \
  -kernel build/arm/lughos.bin \
  -initrd build/arm/user_hello \
  -nographic -no-reboot \
  -serial file:/tmp/lugh-arm.log \
  -serial file:/tmp/lugh_ipc.bin 2>/dev/null || true
```

- [ ] **Step 6: Validate the stream**

```bash
python3 scripts/validate_telemetry.py /tmp/lugh_ipc.bin
```

Expected output includes:
```
=== telemetry validation: N records ===
...
FAULT            2
...
```
Exit code: 0

- [ ] **Step 7: Check the FAULT records decode correctly**

```bash
python3 scripts/validate_telemetry.py -v /tmp/lugh_ipc.bin | grep FAULT
```

Expected: two lines containing `FAULT`.

- [ ] **Step 8: Verify reconstruct_graph.py handles the live stream**

```bash
python3 scripts/reconstruct_graph.py /tmp/lugh_ipc.bin | head -5
```

Expected: begins with `digraph lughos {` — no crash, no error.

- [ ] **Step 9: Run full test suite**

```bash
make test 2>&1 | tail -10
```

Expected: passes (existing tests unaffected).

- [ ] **Step 10: Run Python test**

```bash
python3 scripts/test_fault_record.py
```

Expected:
```
PASS: all fault-record checks passed
```

- [ ] **Step 11: Commit**

```bash
git add kernel/main.c
git commit -m "test(jepa-prep): test_fault_telemetry() exercises auditor_fault() emit path (Phase 4 F3)"
```
