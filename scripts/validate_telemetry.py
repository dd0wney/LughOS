#!/usr/bin/env python3
"""
LughOS auditor telemetry stream validator (Phase 3 J8).

Reads /tmp/lugh_ipc.bin (or argv[1]) and verifies:
  - Every 44-byte record has the LughOS magic (0x4C474849 "LGHI").
  - Every record's version is the current AUDITOR_TELEMETRY_VERSION (2).
  - Every record_type is a known type (no UNKNOWN(N) leaks).
  - At least one record of every category we expect a healthy boot
    sequence to produce. Missing categories indicate a broken or
    masked emission path (e.g. an ifdef regression on TASK_CREATE).
  - Stream length is a clean multiple of 44 — no torn records.

Exit code 0 if everything passes, 1 otherwise. Designed to be run
from CI or shell scripts:

    qemu-system-arm ... -serial file:/tmp/lugh_ipc.bin
    python3 scripts/validate_telemetry.py && echo OK

Categories asserted present (relative — "at least one of each"
rather than exact counts, because counts depend on the test suite
mix and would drift each time we add a test):

  MSG           - normal IPC traffic
  DENY          - capability or domain denials
  CHAN_CREATE   - channel lifecycle event
  CHAN_CONNECT  - channel connection event
  DOMAIN_EDGE   - policy mutation event
  TASK_CREATE   - task lineage event
  OVERFLOW      - ring overflow (test_transactional_storage deliberately overflows)

Not asserted: HEARTBEAT (only fires on long runs), TASK_EXIT (only
fires after a clean SYS_EXIT, currently gated by user_hello-hang).
"""

from __future__ import annotations
import argparse
import struct
import sys
from collections import Counter

RECORD_FMT  = "<IHHQBBBBII16s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)
MAGIC       = 0x4C474849
VERSION     = 2

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
    10: "WORKFLOW",
}

# Categories a healthy boot exercises (test_auditor, test_ipc_enforcement,
# test_task_caps, test_transactional_storage, user_init_task setup).
REQUIRED = {
    "MSG", "DENY", "CHAN_CREATE", "CHAN_CONNECT",
    "DOMAIN_EDGE", "TASK_CREATE", "OVERFLOW",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", default="/tmp/lugh_ipc.bin",
                    help="binary telemetry capture (default: /tmp/lugh_ipc.bin)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="print per-record info as it's parsed")
    args = ap.parse_args()

    try:
        with open(args.file, "rb") as f:
            blob = f.read()
    except OSError as e:
        print(f"validate_telemetry: cannot open {args.file}: {e}", file=sys.stderr)
        return 1

    if len(blob) == 0:
        print(f"validate_telemetry: empty file {args.file}", file=sys.stderr)
        return 1

    if len(blob) % RECORD_SIZE != 0:
        print(f"validate_telemetry: torn stream — {len(blob)} bytes is not a "
              f"multiple of {RECORD_SIZE}", file=sys.stderr)
        return 1

    failures = []
    counter: Counter[str] = Counter()

    n_records = len(blob) // RECORD_SIZE
    for i in range(n_records):
        chunk = blob[i * RECORD_SIZE : (i + 1) * RECORD_SIZE]
        magic, version, rec_type, jiffies, *_rest = struct.unpack(RECORD_FMT, chunk)

        if magic != MAGIC:
            failures.append(f"record {i}: bad magic 0x{magic:08X} (expected 0x{MAGIC:08X})")
        if version != VERSION:
            failures.append(f"record {i}: bad version {version} (expected {VERSION})")
        if rec_type not in REC_TYPE_NAME:
            failures.append(f"record {i}: unknown record_type {rec_type}")
            counter[f"UNKNOWN({rec_type})"] += 1
        else:
            counter[REC_TYPE_NAME[rec_type]] += 1
            if args.verbose:
                print(f"  [{i:3d}] j={jiffies:>7} {REC_TYPE_NAME[rec_type]}")

    missing = REQUIRED - set(counter.keys())
    if missing:
        failures.append(f"missing required categories: {sorted(missing)}")

    # Always print the histogram so operators see what landed.
    print(f"=== telemetry validation: {n_records} records ===")
    for name in sorted(counter.keys()):
        marker = "  required" if name in REQUIRED else ""
        print(f"  {name:14s} {counter[name]:>4}{marker}")

    if failures:
        print("\nFAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"\nOK — every required category present, {n_records} records parsed clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
