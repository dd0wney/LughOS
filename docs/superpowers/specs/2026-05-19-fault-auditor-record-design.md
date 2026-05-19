# AUDITOR_REC_FAULT — Design Spec

**Date:** 2026-05-19
**Phase:** 4 F3 (JEPA-prep instrumentation track)
**Status:** Approved, pending implementation

## Problem

Phase 4 F2 wired ARM prefetch and data abort handlers to `arm_pabort_diagnose()` /
`arm_dabort_diagnose()` in `kernel/arch/arm/abort_diag.c`. Those functions call
`log_message()` — the human-readable serial console — but never write to the binary
auditor telemetry stream that the JEPA encoder reads. Fault events are therefore
invisible to `scripts/reconstruct_graph.py` and any downstream model training.

## Goal

Emit a single new record type, `AUDITOR_REC_FAULT` (type 9), from both abort diagnose
functions. The record carries enough context for the JEPA encoder to identify the
faulting task, fault address, fault class (prefetch / data-read / data-write), and
CPU mode at fault time — without consulting the kernel's in-memory state.

## Non-goals

- No struct layout change; wire format stays at 44 bytes.
- No `AUDITOR_TELEMETRY_VERSION` bump; the new type tag is additive and existing
  decoders treat unknown types as no-ops.
- No graph topology mutation; fault records annotate existing task nodes, they do not
  introduce new nodes or edges. Graph-level fault annotation is deferred to Phase 5.
- No x86 / RISC-V call sites in this phase; the only abort diagnose functions are ARM.

## Design

### New constants

```c
#define AUDITOR_REC_FAULT           9u

#define AUDITOR_FAULT_PABORT        0u  /* prefetch abort             */
#define AUDITOR_FAULT_DABORT_READ   1u  /* data abort, read access    */
#define AUDITOR_FAULT_DABORT_WRITE  2u  /* data abort, write access   */
```

### Wire format (`AUDITOR_REC_FAULT`)

All values little-endian, consistent with the existing `<IHHQBBBBII16s` struct layout.

| Field          | Bytes | Value |
|----------------|-------|-------|
| `magic`        | 4     | `AUDITOR_MAGIC` (0x4C474849) |
| `version`      | 2     | `AUDITOR_TELEMETRY_VERSION` (2) |
| `record_type`  | 2     | 9 |
| `jiffies`      | 8     | `hw_get_jiffies()` at emit time |
| `priority`     | 1     | 0 |
| `src_domain`   | 1     | `current_task->domain & 0xFF`; 0 if no task |
| `protocol`     | 1     | fault subtype: 0=pabort, 1=dabort_read, 2=dabort_write |
| `channel_id`   | 1     | 0 |
| `operation`    | 4     | `fault_pc` — faulting instruction VA |
| `checksum`     | 4     | `dfar` — Data Fault Address Register; 0 for pabort |
| `payload_hash[0..3]`  | 4  | `dfsr` — Data Fault Status Register; 0 for pabort |
| `payload_hash[4..7]`  | 4  | `spsr` — pre-fault CPSR snapshot |
| `payload_hash[8..11]` | 4  | `task_id`; 0 if no `current_task` |
| `payload_hash[12..15]`| 4  | zeros |

The `protocol` field carries `fault_subtype` — the same field-reuse-per-type pattern
established by DENY (IPC protocol), TASK_CREATE (0), and DOMAIN_EDGE (0). The DFSR
W-bit (bit 11) that distinguishes read vs. write is decoded in C at the call site and
collapsed into the 2-value subtype so Python decoders need no ARM-specific bit manipulation.

### API

```c
/* include/auditor.h */
void auditor_fault(uint32_t fault_pc,
                   uint32_t dfar,       /* 0 for pabort               */
                   uint32_t dfsr,       /* 0 for pabort               */
                   uint32_t spsr,
                   uint8_t  fault_type);/* AUDITOR_FAULT_*            */
```

### Emit path

`auditor_fault()` → `emit_fault_record()` → `tlm_write_bytes()` directly.

No ring buffer. Same synchronous UART polling path used by TASK_CREATE, CHAN_CREATE,
and DOMAIN_EDGE. Safe from abort-mode context: no dynamic allocation, bounded loop,
no interrupt dependency.

The `auditor_enabled` guard is kept — consistent with all structural emitters.
Pre-`auditor_init()` faults are unrecoverable panics already captured by `log_message`;
the binary telemetry record adds nothing in that window.

### Call sites (`kernel/arch/arm/abort_diag.c`)

**`arm_pabort_diagnose()`** — after existing `log_message`:
```c
auditor_fault(fault_pc, 0u, 0u, spsr, AUDITOR_FAULT_PABORT);
```

**`arm_dabort_diagnose()`** — `is_write` is already decoded from DFSR bit 11:
```c
uint8_t ft = is_write ? AUDITOR_FAULT_DABORT_WRITE : AUDITOR_FAULT_DABORT_READ;
auditor_fault(fault_pc, dfar, dfsr, spsr, ft);
```

### Python decoder updates

**`scripts/validate_telemetry.py`:**
- Add `REC_FAULT = 9` to the known-types mapping.
- Do **not** add to the "must be present" assertion set. Fault absence on a clean boot
  is correct; asserting presence would require deliberately triggering aborts in CI.

**`scripts/reconstruct_graph.py`:**
- Add `REC_FAULT = 9` constant.
- Add explicit no-op branch: `elif rec_type == REC_FAULT: pass`.
- Rationale: explicit branch is documentation and forward-compatibility hygiene; the
  existing unknown-type fallthrough already handles it correctly.

## Files changed

| File | Nature of change |
|------|-----------------|
| `include/auditor.h` | New constant, 3 subtype defines, wire-format doc comment, declaration |
| `services/auditor/exporter.c` | `emit_fault_record()` (static) + `auditor_fault()` (public) |
| `kernel/arch/arm/abort_diag.c` | Two `auditor_fault()` call sites |
| `scripts/validate_telemetry.py` | Register `REC_FAULT=9` as known type |
| `scripts/reconstruct_graph.py` | `REC_FAULT=9` constant + no-op branch |

## Testing

- Existing `make test` suite must pass unchanged (no new abort scenarios required).
- `scripts/validate_telemetry.py` must accept a stream that contains FAULT records
  without asserting their presence.
- `scripts/reconstruct_graph.py` must parse a stream with FAULT records and produce
  identical DOT output to a stream without them (fault records are no-ops for topology).
- Manual: trigger a deliberate fault in QEMU (e.g. branch to an unmapped VA), capture
  `/tmp/lugh_ipc.bin`, verify a type-9 record appears with the expected `fault_pc`.
