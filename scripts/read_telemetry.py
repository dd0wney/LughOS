#!/usr/bin/env python3
"""
LughOS IPC telemetry reader.

Reads 44-byte watchdog_record_t records written by the LughOS watchdog
service on COM2 and prints a human-readable stream.

Usage:
    python3 read_telemetry.py [FILE]
    python3 read_telemetry.py [FILE] --window N

FILE defaults to /tmp/lugh_ipc.bin (QEMU -serial file:/tmp/lugh_ipc.bin).

--window N groups MSG records into tumbling windows of N entries and
emits each window as a JSON array suitable for JEPA encoder input.
Pipe to `jq '.'` for pretty printing or `jq length` to verify window size.
"""

import argparse
import json
import struct
import sys
import time

# Must match watchdog_record_t in include/watchdog.h
MAGIC       = 0x4C474849  # "LGHI"
RECORD_FMT  = "<IHHQBxxxII16s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)

assert RECORD_SIZE == 44, f"Format mismatch: expected 44 bytes, got {RECORD_SIZE}"

REC_TYPE_NAME = {0: "MSG", 1: "OVERFLOW", 2: "HEARTBEAT"}
PRIO_NAME     = {0: "HIGH", 1: "MED", 2: "LOW"}


def parse_record(raw: bytes) -> dict:
    magic, version, rec_type, jiffies, priority, operation, checksum, payload_hash = \
        struct.unpack(RECORD_FMT, raw)
    return {
        "magic":        magic,
        "version":      version,
        "type":         rec_type,
        "jiffies":      jiffies,
        "priority":     priority,
        "operation":    operation,
        "checksum":     checksum,
        "payload_hash": payload_hash.hex(),
    }


def format_record(r: dict) -> str:
    rtype = REC_TYPE_NAME.get(r["type"], f"UNK({r['type']})")
    prio  = PRIO_NAME.get(r["priority"], str(r["priority"]))
    j     = r["jiffies"]
    if r["type"] == 0:  # MSG
        return (
            f"[j={j:>7}]  MSG       prio={prio:<4}  "
            f"op=0x{r['operation']:08X}  csum=0x{r['checksum']:08X}  "
            f"hash={r['payload_hash'][:16]}..."
        )
    if r["type"] == 1:  # OVERFLOW
        return f"[j={j:>7}]  OVERFLOW  dropped={r['operation']}"
    if r["type"] == 2:  # HEARTBEAT
        return f"[j={j:>7}]  HEARTBEAT"
    return f"[j={j:>7}]  UNKNOWN   type={r['type']}"


def tail_records(path: str):
    """Yield one 44-byte aligned record at a time, blocking until data arrives."""
    with open(path, "rb") as f:
        buf = b""
        while True:
            chunk = f.read(RECORD_SIZE - len(buf))
            if chunk:
                buf += chunk
            else:
                time.sleep(0.01)
                continue
            while len(buf) >= RECORD_SIZE:
                yield buf[:RECORD_SIZE]
                buf = buf[RECORD_SIZE:]


def main() -> None:
    ap = argparse.ArgumentParser(
        description="LughOS IPC telemetry reader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "file",
        nargs="?",
        default="/tmp/lugh_ipc.bin",
        help="binary telemetry file (default: /tmp/lugh_ipc.bin)",
    )
    ap.add_argument(
        "--window",
        type=int,
        metavar="N",
        default=0,
        help="emit tumbling windows of N MSG records as JSON arrays",
    )
    args = ap.parse_args()

    if args.window < 0:
        ap.error("--window must be a positive integer")

    window_buf: list = []

    for raw in tail_records(args.file):
        r = parse_record(raw)

        if r["magic"] != MAGIC:
            # Lost sync — report and try to recover on next 44-byte boundary.
            sys.stderr.write(
                f"sync error: magic=0x{r['magic']:08X} (expected 0x{MAGIC:08X})\n"
            )
            continue

        if args.window > 0:
            if r["type"] == 0:  # MSG records only
                window_buf.append({
                    "jiffies":      r["jiffies"],
                    "priority":     r["priority"],
                    "operation":    r["operation"],
                    "checksum":     r["checksum"],
                    "payload_hash": r["payload_hash"],
                })
                if len(window_buf) >= args.window:
                    print(json.dumps(window_buf))
                    sys.stdout.flush()
                    window_buf = []
        else:
            print(format_record(r))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
