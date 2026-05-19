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
