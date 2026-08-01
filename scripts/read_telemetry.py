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
  [granted_caps:32][required_caps:32][dst_channel_id:32]
  [parent_task_id:24 (J5)][depth:4 | sibling_count:4 (J6)]

The parent_task_id field is the caller's task_t.parent_task_id at deny
time. 0xFFFFFF is the truncated form of TASK_PARENT_NONE (the kernel
root, or "no current_task" in early-boot self-tests). depth and
sibling_count are saturating-capped at 15.

For CHAN_CREATE records (type=5, v2+), the layout is:
  operation     = cap_mask
  checksum      = owner_task_id
  payload_hash  = [domain:32][security_level:32][zeros:64]
  src_domain/protocol/channel_id mirror the channel's policy.

For CHAN_CONNECT records (type=6, v2+), the layout is:
  channel_id    = src_channel_id (low 8)
  src_domain    = src_channel_domain (low 8)
  protocol      = src_channel_protocol (low 8)
  operation     = dst_channel_id (full uint32)
  checksum      = dst_channel_domain (full uint32)
  payload_hash  = [src_cap_mask:32][dst_cap_mask:32][zeros:64]

For DOMAIN_EDGE records (type=8, v2+), the layout is:
  src_domain    = src_domain (low 8)
  channel_id    = dst_domain (low 8, repurposed as 'dst slot')
  operation     = src_domain (full uint32)
  checksum      = dst_domain (full uint32)
  payload_hash  = [added:32][zeros:96]   (added=1 means edge inserted)

For TASK_CREATE records (type=4, v2+ J1), the layout is:
  priority      = task.priority (clamped to uint8)
  src_domain    = task.domain (low 8)
  operation     = task.task_id (full uint32)
  checksum      = task.parent_task_id (0xFFFFFFFF = ROOT)
  payload_hash  = [cap_mask:32][domain:32][stack_top:32][zeros:32]

For TASK_EXIT records (type=7, v2+ J4), the layout is:
  operation     = task_id (full uint32)
  checksum      = (uint32_t)exit_code   (display as signed int32)
  payload_hash  = [zeros:128]
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
                 4: "TASK_CREATE",
                 5: "CHAN_CREATE", 6: "CHAN_CONNECT",
                 7: "TASK_EXIT",
                 8: "DOMAIN_EDGE",
                 9: "FAULT",
                 10: "WORKFLOW"}

# WORKFLOW record subtypes, carried in the `protocol` byte.
# Mirrors the WF_EV_* constants in include/workflow.h.
WF_EVENT_NAME = {0: "BEGIN", 1: "STEP_OK", 2: "STEP_FAIL", 3: "UNDO_OK",
                 4: "UNDO_FAIL", 5: "COMMIT", 6: "ROLLED_BACK", 7: "FAILED"}

# Mirrors workflow_status_t in include/workflow.h.
WF_STATUS_NAME = {0: "IDLE", 1: "RUNNING", 2: "COMMITTED",
                  3: "ROLLING_BACK", 4: "ROLLED_BACK", 5: "FAILED"}

# Mirrors include/lugh.h TASK_PARENT_NONE — kernel root task.
TASK_PARENT_NONE = 0xFFFFFFFF
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

    if r["type"] == 8:  # DOMAIN_EDGE — policy mutation event (v2+)
        raw_hash = bytes.fromhex(r["payload_hash"])
        added    = _unpack_le32(raw_hash, 0)
        src_dom  = r["operation"]
        dst_dom  = r["checksum"]
        verb     = "added" if added == 1 else f"op={added}"
        return (
            f"[j={j:>7}]  DOMAIN_EDGE "
            f"src_dom={src_dom} -> dst_dom={dst_dom} ({verb})"
        )

    if r["type"] == 4:  # TASK_CREATE — lineage event (v2+ J1)
        raw_hash = bytes.fromhex(r["payload_hash"])
        cap_mask    = _unpack_le32(raw_hash, 0)
        full_domain = _unpack_le32(raw_hash, 4)
        stack_top   = _unpack_le32(raw_hash, 8)
        task_id     = r["operation"]
        parent_id   = r["checksum"]
        parent_str  = "ROOT" if parent_id == TASK_PARENT_NONE else str(parent_id)
        return (
            f"[j={j:>7}]  TASK_CREATE "
            f"task={task_id} parent={parent_str} "
            f"caps=0x{cap_mask:X}[{caps_str(cap_mask)}] "
            f"domain={full_domain} prio={r['priority']} stack_top=0x{stack_top:X}"
        )

    if r["type"] == 7:  # TASK_EXIT — lifecycle event (v2+ J4)
        task_id   = r["operation"]
        exit_code = r["checksum"]
        # Exit code is conceptually int32; display signed for readability.
        if exit_code & 0x80000000:
            exit_code -= 0x100000000
        return (
            f"[j={j:>7}]  TASK_EXIT   "
            f"task={task_id} exit_code={exit_code}"
        )

    if r["type"] == 6:  # CHAN_CONNECT — edge between two channels (v2+)
        raw_hash = bytes.fromhex(r["payload_hash"])
        src_caps = _unpack_le32(raw_hash, 0)
        dst_caps = _unpack_le32(raw_hash, 4)
        dst_ch   = r["operation"]
        dst_dom  = r["checksum"]
        return (
            f"[j={j:>7}]  CHAN_CONNECT "
            f"src=ch{ch}(dom={dom},proto={proto},caps=[{caps_str(src_caps)}]) "
            f"-> dst=ch{dst_ch}(dom={dst_dom},caps=[{caps_str(dst_caps)}])"
        )

    if r["type"] == 3:  # DENY — unpack structured fields
        reason_code = r["checksum"] & 0xFF
        dst_domain  = (r["checksum"] >> 8)  & 0xFF
        dst_channel = (r["checksum"] >> 16) & 0xFF

        raw_hash = bytes.fromhex(r["payload_hash"])
        granted  = _unpack_le32(raw_hash, 0)
        required = _unpack_le32(raw_hash, 4)
        dst_ch32 = _unpack_le32(raw_hash, 8)

        # J5: 24-bit parent_task_id packed at [12..14], byte 15 reserved
        # for J6's depth+siblings nibbles. Lift the all-ones truncation
        # back to the full TASK_PARENT_NONE sentinel for display.
        parent24    = raw_hash[12] | (raw_hash[13] << 8) | (raw_hash[14] << 16)
        parent_id   = TASK_PARENT_NONE if parent24 == 0xFFFFFF else parent24
        parent_str  = "ROOT" if parent_id == TASK_PARENT_NONE else str(parent_id)
        # J6: nibbles in byte 15 — depth in high nibble, sibs in low.
        depth_byte    = raw_hash[15]
        lineage_depth = (depth_byte >> 4) & 0x0F
        sibling_count = depth_byte & 0x0F

        reason_name = DENY_REASON.get(reason_code, f"UNKNOWN({reason_code})")
        dst_str = "none" if dst_ch32 == 0xFFFFFFFF else str(dst_ch32)

        return (
            f"[j={j:>7}]  DENY      "
            f"ch={ch}(dom={dom},proto={proto})  "
            f"reason={reason_name}  "
            f"op=0x{r['operation']:08X}  "
            f"granted=[{caps_str(granted)}]  "
            f"required=[{caps_str(required)}]  "
            f"dst=ch{dst_str}(dom={dst_domain})  "
            f"parent={parent_str}  depth={lineage_depth} sibs={sibling_count}"
        )

    if r["type"] == 10:  # WORKFLOW (Phase 4 F4)
        raw_hash = bytes.fromhex(r["payload_hash"])
        # The full 64-bit workflow_id is split across operation (low) and
        # checksum (high) — see the field map in include/auditor.h.
        wf_id  = (r["checksum"] << 32) | r["operation"]
        owner  = _unpack_le32(raw_hash, 0)
        status = _unpack_le32(raw_hash, 4)
        done   = _unpack_le32(raw_hash, 8)
        rv_raw = _unpack_le32(raw_hash, 12)
        rv     = rv_raw - (1 << 32) if rv_raw >= (1 << 31) else rv_raw

        ev_name     = WF_EVENT_NAME.get(r["protocol"], f"UNKNOWN({r['protocol']})")
        status_name = WF_STATUS_NAME.get(status, f"UNKNOWN({status})")

        return (
            f"[j={j:>7}]  WORKFLOW  "
            f"wf=0x{wf_id:016X}  "
            f"event={ev_name:<12} step={ch}  "
            f"status={status_name:<12} done={done}  "
            f"owner_task={owner}  rv={rv}"
        )

    return f"[j={j:>7}]  UNKNOWN   type={r['type']}"


def tail_records(path: str, follow: bool = True):
    """Yield one 44-byte aligned record at a time.

    follow=True blocks at EOF waiting for more data, which is what a live
    QEMU serial capture needs. follow=False stops at EOF, which is what
    reading an already-captured file needs — without it this generator
    never returns and any batch consumer hangs.
    """
    with open(path, "rb") as f:
        buf = b""
        while True:
            chunk = f.read(RECORD_SIZE - len(buf))
            if chunk:
                buf += chunk
            elif follow:
                time.sleep(0.01)
                continue
            else:
                return   # EOF, and a partial trailing record is not a record
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
    ap.add_argument(
        "--workflow",
        action="store_true",
        help="include WORKFLOW records in --window JSON output",
    )
    ap.add_argument(
        "--once",
        action="store_true",
        help="stop at EOF instead of following the file for new records",
    )
    args = ap.parse_args()

    if args.window < 0:
        ap.error("--window must be a positive integer")

    window_buf: list = []

    for raw in tail_records(args.file, follow=not args.once):
        r = parse_record(raw)

        if r["magic"] != MAGIC:
            sys.stderr.write(
                f"sync error: magic=0x{r['magic']:08X} (expected 0x{MAGIC:08X})\n"
            )
            continue

        if args.window > 0:
            include = ((r["type"] == 0)
                       or (args.deny and r["type"] == 3)
                       or (args.workflow and r["type"] == 10))
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
                elif r["type"] == 10:
                    raw_hash = bytes.fromhex(r["payload_hash"])
                    rv_raw = _unpack_le32(raw_hash, 12)
                    entry["workflow_id"]  = (r["checksum"] << 32) | r["operation"]
                    entry["wf_event"]     = WF_EVENT_NAME.get(
                        r["protocol"], r["protocol"])
                    entry["step_index"]   = r["channel_id"]
                    entry["owner_task"]   = _unpack_le32(raw_hash, 0)
                    entry["wf_status"]    = WF_STATUS_NAME.get(
                        _unpack_le32(raw_hash, 4), _unpack_le32(raw_hash, 4))
                    entry["done_count"]   = _unpack_le32(raw_hash, 8)
                    entry["step_rv"]      = (rv_raw - (1 << 32)
                                             if rv_raw >= (1 << 31) else rv_raw)
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
