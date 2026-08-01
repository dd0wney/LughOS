#!/usr/bin/env python3
"""TDD: WORKFLOW record (type=10) must decode correctly across all three
telemetry consumers.

Checks:
  1. validate_telemetry.py does not report it as an unknown record_type
  2. reconstruct_graph.py stays a graph no-op and still emits DOT
  3. read_telemetry.py --json round-trips every packed field

Check 3 is the one that matters. Checks 1 and 2 pass for any tag that is
merely *listed*; only a field-level round-trip proves the packing in
services/auditor/exporter.c and the unpacking in read_telemetry.py agree.

Run from the repo root:
    python3 scripts/test_workflow_record.py
Exit 0 = all checks passed.
"""
import json
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
REC_WORKFLOW     = 10

# Mirrors WF_EV_* in include/workflow.h
WF_EV_BEGIN       = 0
WF_EV_STEP_OK     = 1
WF_EV_STEP_FAIL   = 2
WF_EV_UNDO_OK     = 3
WF_EV_ROLLED_BACK = 6

# Mirrors workflow_status_t in include/workflow.h
WF_STATUS_RUNNING      = 1
WF_STATUS_ROLLING_BACK = 3
WF_STATUS_ROLLED_BACK  = 4


def make_record(rec_type, jiffies=1000, priority=0, src_domain=0, protocol=0,
                channel_id=0, operation=0, checksum=0, payload_hash=None):
    if payload_hash is None:
        payload_hash = b"\x00" * 16
    return struct.pack(RECORD_FMT,
        MAGIC, VERSION, rec_type, jiffies,
        priority, src_domain, protocol, channel_id,
        operation, checksum, payload_hash)


def make_workflow_record(workflow_id, event, step_index, status,
                         owner_task=1, done_count=0, step_rv=0, src_domain=0):
    """Pack a WORKFLOW record exactly as emit_workflow_record() does."""
    return make_record(
        REC_WORKFLOW,
        src_domain=src_domain,
        protocol=event,
        channel_id=step_index & 0xFF,
        operation=workflow_id & 0xFFFFFFFF,
        checksum=(workflow_id >> 32) & 0xFFFFFFFF,
        payload_hash=struct.pack("<IIIi", owner_task, status, done_count,
                                 step_rv),
    )


# A workflow that fails at step 1 and rolls step 0 back. The 64-bit id uses
# both halves so a decoder that drops the high word is caught.
WF_ID = 0x00000007_DEADBEEF

WORKFLOW_SEQUENCE = [
    # (event, step_index, status, done_count, step_rv)
    (WF_EV_BEGIN,       2, WF_STATUS_RUNNING,      0,  0),   # workflow begin
    (WF_EV_BEGIN,       0, WF_STATUS_RUNNING,      0,  0),   # step 0 intent
    (WF_EV_STEP_OK,     0, WF_STATUS_RUNNING,      0,  0),
    (WF_EV_BEGIN,       1, WF_STATUS_RUNNING,      1,  0),   # step 1 intent
    (WF_EV_STEP_FAIL,   1, WF_STATUS_RUNNING,      1, -1),   # negative rv
    (WF_EV_UNDO_OK,     0, WF_STATUS_ROLLING_BACK, 1,  0),
    (WF_EV_ROLLED_BACK, 2, WF_STATUS_ROLLED_BACK,  0,  0),
]


def make_required_stream():
    """Every category a healthy boot exercises, plus the workflow sequence."""
    msg_payload = b"test" + b"\x00" * 12
    records = [
        make_record(REC_MSG,          operation=0xDEADBEEF, payload_hash=msg_payload),
        make_record(REC_OVERFLOW,     operation=1),
        make_record(REC_DENY,         src_domain=1, protocol=2, channel_id=0),
        make_record(REC_TASK_CREATE,  operation=1, checksum=0xFFFFFFFF),
        make_record(REC_CHAN_CREATE,  channel_id=1, operation=0xFF, checksum=1),
        make_record(REC_CHAN_CONNECT, channel_id=1, operation=2),
        make_record(REC_DOMAIN_EDGE,  operation=0, checksum=1,
                    payload_hash=b"\x01" + b"\x00" * 15),
        make_record(REC_FAULT, src_domain=0, protocol=0,
                    operation=0xDEAD0000, checksum=0,
                    payload_hash=b"\x00" * 8 + b"\x01\x00\x00\x00" + b"\x00" * 4),
    ]
    for event, step, status, done, rv in WORKFLOW_SEQUENCE:
        records.append(make_workflow_record(WF_ID, event, step, status,
                                            done_count=done, step_rv=rv))
    return b"".join(records)


def run(cmd, input_path, extra=None):
    argv = [sys.executable] + cmd + [input_path] + (extra or [])
    result = subprocess.run(
        argv, capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    return result.returncode, result.stdout + result.stderr


def check_json_roundtrip(path, failures):
    """Every packed field must survive the trip back out of read_telemetry.py."""
    rc, out = run(["scripts/read_telemetry.py"], path,
                  ["--window", "1", "--workflow", "--once"])
    if rc != 0:
        failures.append(f"read_telemetry.py: non-zero exit {rc}:\n{out}")
        return

    decoded = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            decoded.extend(json.loads(line))
        except json.JSONDecodeError:
            continue

    got = [e for e in decoded if e.get("type") == "WORKFLOW"]
    if len(got) != len(WORKFLOW_SEQUENCE):
        failures.append(
            f"read_telemetry.py: expected {len(WORKFLOW_SEQUENCE)} "
            f"WORKFLOW entries, got {len(got)}")
        return

    ev_name = {0: "BEGIN", 1: "STEP_OK", 2: "STEP_FAIL", 3: "UNDO_OK",
               4: "UNDO_FAIL", 5: "COMMIT", 6: "ROLLED_BACK", 7: "FAILED"}
    st_name = {0: "IDLE", 1: "RUNNING", 2: "COMMITTED", 3: "ROLLING_BACK",
               4: "ROLLED_BACK", 5: "FAILED"}

    for i, (event, step, status, done, rv) in enumerate(WORKFLOW_SEQUENCE):
        e = got[i]
        for field, want in (
            ("workflow_id", WF_ID),
            ("wf_event",    ev_name[event]),
            ("step_index",  step),
            ("wf_status",   st_name[status]),
            ("done_count",  done),
            ("step_rv",     rv),
        ):
            if e.get(field) != want:
                failures.append(
                    f"record {i}: {field} = {e.get(field)!r}, expected {want!r}")


def main():
    stream = make_required_stream()
    failures = []

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(stream)
        path = f.name

    try:
        # ── Check 1: validate_telemetry.py accepts WORKFLOW records ──────
        rc, out = run(["scripts/validate_telemetry.py"], path)
        if "unknown record_type 10" in out:
            failures.append("validate_telemetry.py: reports WORKFLOW as unknown type")
        if rc != 0:
            failures.append(f"validate_telemetry.py: non-zero exit {rc}:\n{out}")

        # ── Check 2: reconstruct_graph.py stays a graph no-op ────────────
        rc, out = run(["scripts/reconstruct_graph.py"], path)
        if rc != 0:
            failures.append(f"reconstruct_graph.py: non-zero exit {rc}:\n{out}")
        if "digraph" not in out:
            failures.append("reconstruct_graph.py: no 'digraph' in output")

        # ── Check 3: field-level round-trip ──────────────────────────────
        check_json_roundtrip(path, failures)

    finally:
        os.unlink(path)

    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

    print(f"PASS: all workflow-record checks passed "
          f"({len(WORKFLOW_SEQUENCE)} records round-tripped)")
    sys.exit(0)


if __name__ == "__main__":
    main()
