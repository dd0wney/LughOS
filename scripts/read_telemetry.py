#!/usr/bin/env python3
"""
LughOS IPC telemetry reader.

Reads 44-byte auditor_record_t records written by the LughOS auditor
service on COM2 and prints a human-readable stream.

Usage:
    python3 read_telemetry.py [FILE]
    python3 read_telemetry.py [FILE] --window N

FILE defaults to /tmp/lugh_ipc.bin (QEMU -serial file:/tmp/lugh_ipc.bin).

--window N groups MSG records into tumbling windows of N entries and
emits each window as a JSON array suitable for JEPA encoder input.
Pipe to `jq '.'` for pretty printing or `jq length` to verify window size.

Record schema (44 bytes packed, '<IHHQBBBBII16s'):
  magic(4) version(2) rec_type(2) jiffies(8)
  priority(1) src_domain(1) protocol(1) channel_id(1)
  operation(4) checksum(4) payload_hash(16)

For DENY records (type=3), checksum encodes:
  [reason:8][dst_domain:8][dst_channel:8][reserved:8]
  and payload_hash encodes:
  [granted_caps:32][required_caps:32][dst_channel_id:32][zeros:32]

For CHAN_CREATE records (type=5, v2+), the layout is:
  operation     = cap_mask
  checksum      = owner_task_id
  payload_hash  = [domain:32][security_level:32][zeros:64]
  src_domain/protocol/channel_id mirror the channel's policy.
"""

import argparse
import json
import struct
import sys
import time

# Must match auditor_record_t in include/auditor.h
MAGIC       = 0x4C474849  # "LGHI"
RECORD_FMT  = "<IHHQBBBBII16s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)

assert RECORD_SIZE == 44, f"Format mismatch: expected 44 bytes, got {RECORD_SIZE}"

REC_TYPE_NAME = {0: "MSG", 1: "OVERFLOW", 2: "HEARTBEAT", 3: "DENY",
                 5: "CHAN_CREATE"}
PRIO_NAME     = {0: "HIGH", 1: "MED", 2: "LOW"}
PROTO_NAME    = {1: "PAIR", 2: "PUB", 3: "SUB", 4: "REQ", 5: "REP",
                 6: "PUSH", 7: "PULL", 8: "BUS", 9: "SURV", 10: "RESP"}
DENY_REASON   = {
    1: "CAP_SEND",        2: "CAP_RECV",       3: "CAP_PRIV",
    4: "DOMAIN",          5: "CAP_ESCALATION", 6: "DOMAIN_CREATE",
}

CAP_NAMES = {0x01: "SEND", 0x02: "RECV", 0x04: "CROSS_DOM", 0x08: "PRIV_OP"}


def caps_str(mask: int) -> str:
    parts = [name for bit, name in sorted(CAP_NAMES.items()) if mask & bit]
    return "|".join(parts) if parts else "NONE"


def parse_record(raw: bytes) -> dict:
    magic, version, rec_type, jiffies, priority, src_domain, protocol, \
        channel_id, operation, checksum, payload_hash = \
        struct.unpack(RECORD_FMT, raw)
    return {
        "magic":       magic,
        "version":     version,
        "type":        rec_type,
        "jiffies":     jiffies,
        "priority":    priority,
        "src_domain":  src_domain,
        "protocol":    protocol,
        "channel_id":  channel_id,
        "operation":   operation,
        "checksum":    checksum,
        "payload_hash": payload_hash.hex(),
    }


def _unpack_le32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def format_record(r: dict) -> str:
    rtype = REC_TYPE_NAME.get(r["type"], f"UNK({r['type']})")
    prio  = PRIO_NAME.get(r["priority"], str(r["priority"]))
    proto = PROTO_NAME.get(r["protocol"], str(r["protocol"]))
    j     = r["jiffies"]
    ch    = r["channel_id"]
    dom   = r["src_domain"]

    if r["type"] == 0:  # MSG
        return (
            f"[j={j:>7}]  MSG       "
            f"ch={ch} dom={dom} proto={proto:<4} prio={prio:<4}  "
            f"op=0x{r['operation']:08X}  csum=0x{r['checksum']:08X}  "
            f"hash={r['payload_hash'][:16]}..."
        )

    if r["type"] == 1:  # OVERFLOW
        return f"[j={j:>7}]  OVERFLOW  dropped={r['operation']}"

    if r["type"] == 2:  # HEARTBEAT
        return f"[j={j:>7}]  HEARTBEAT"

    if r["type"] == 5:  # CHAN_CREATE — structural event (v2+)
        raw_hash = bytes.fromhex(r["payload_hash"])
        full_domain  = _unpack_le32(raw_hash, 0)
        sec_level    = _unpack_le32(raw_hash, 4)
        owner_task   = r["checksum"]
        cap_mask     = r["operation"]
        return (
            f"[j={j:>7}]  CHAN_CREATE "
            f"ch={ch} owner_task={owner_task} "
            f"caps=0x{cap_mask:X}[{caps_str(cap_mask)}] "
            f"domain={full_domain} sec_lvl={sec_level} "
            f"proto={proto}"
        )

    if r["type"] == 3:  # DENY — unpack structured fields
        reason_code = r["checksum"] & 0xFF
        dst_domain  = (r["checksum"] >> 8)  & 0xFF
        dst_channel = (r["checksum"] >> 16) & 0xFF

        raw_hash = bytes.fromhex(r["payload_hash"])
        granted  = _unpack_le32(raw_hash, 0)
        required = _unpack_le32(raw_hash, 4)
        dst_ch32 = _unpack_le32(raw_hash, 8)

        reason_name = DENY_REASON.get(reason_code, f"UNKNOWN({reason_code})")
        dst_str = "none" if dst_ch32 == 0xFFFFFFFF else str(dst_ch32)

        return (
            f"[j={j:>7}]  DENY      "
            f"ch={ch}(dom={dom},proto={proto})  "
            f"reason={reason_name}  "
            f"op=0x{r['operation']:08X}  "
            f"granted=[{caps_str(granted)}]  "
            f"required=[{caps_str(required)}]  "
            f"dst=ch{dst_str}(dom={dst_domain})"
        )

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
    ap.add_argument(
        "--deny",
        action="store_true",
        help="include DENY records in --window JSON output",
    )
    args = ap.parse_args()

    if args.window < 0:
        ap.error("--window must be a positive integer")

    window_buf: list = []

    for raw in tail_records(args.file):
        r = parse_record(raw)

        if r["magic"] != MAGIC:
            sys.stderr.write(
                f"sync error: magic=0x{r['magic']:08X} (expected 0x{MAGIC:08X})\n"
            )
            continue

        if args.window > 0:
            include = (r["type"] == 0) or (args.deny and r["type"] == 3)
            if include:
                entry: dict = {
                    "type":       REC_TYPE_NAME.get(r["type"], r["type"]),
                    "jiffies":    r["jiffies"],
                    "src_domain": r["src_domain"],
                    "protocol":   r["protocol"],
                    "channel_id": r["channel_id"],
                    "priority":   r["priority"],
                    "operation":  r["operation"],
                }
                if r["type"] == 0:
                    entry["checksum"]     = r["checksum"]
                    entry["payload_hash"] = r["payload_hash"]
                elif r["type"] == 3:
                    raw_hash = bytes.fromhex(r["payload_hash"])
                    entry["deny_reason"]  = r["checksum"] & 0xFF
                    entry["dst_domain"]   = (r["checksum"] >> 8)  & 0xFF
                    entry["granted_caps"] = _unpack_le32(raw_hash, 0)
                    entry["required_caps"]= _unpack_le32(raw_hash, 4)
                window_buf.append(entry)
                if len(window_buf) >= args.window:
                    print(json.dumps(window_buf))
                    sys.stdout.flush()
                    window_buf = []
        else:
            print(format_record(r))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
