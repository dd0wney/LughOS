#!/usr/bin/env python3
"""
LughOS auditor stream → graph reconstruction (Phase 3 J9).

Replays the structural events (TASK_CREATE, CHAN_CREATE, CHAN_CONNECT,
DOMAIN_EDGE, TASK_EXIT) from the auditor binary stream and emits a
graphviz DOT representation of the system state at the requested
timestamp (or end-of-stream by default).

This is the "the JEPA encoder can reconstruct the world from events
alone" property made operational: if J0–J7's record formats are
expressive enough, this script can rebuild the task lineage tree,
channel ownership, channel connections, and domain transition
matrix without ever consulting the kernel's in-memory state.

Usage:

    python3 scripts/reconstruct_graph.py [FILE] [--at JIFFIES] > graph.dot
    dot -Tpng graph.dot -o graph.png

If `--at JIFFIES` is omitted, the final state is rendered. With a
specific jiffies value, events past that timestamp are ignored —
useful for tracing how the graph evolves.

Field-reuse decoding mirrors the J2/J3/J7 packing choices in
include/auditor.h. See `read_telemetry.py` for the per-record
field semantics; this tool only consumes what's needed to build the
graph and treats unknown record types as a no-op (forward-compatible).
"""

from __future__ import annotations
import argparse
import struct
import sys
from dataclasses import dataclass, field

RECORD_FMT  = "<IHHQBBBBII16s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)
MAGIC       = 0x4C474849

REC_MSG          = 0
REC_OVERFLOW     = 1
REC_HEARTBEAT    = 2
REC_DENY         = 3
REC_TASK_CREATE  = 4
REC_CHAN_CREATE  = 5
REC_CHAN_CONNECT = 6
REC_TASK_EXIT    = 7
REC_DOMAIN_EDGE  = 8
REC_FAULT        = 9  # prefetch/data abort — no-op for graph topology


@dataclass
class Task:
    task_id: int
    parent_task_id: int
    cap_mask: int
    domain: int
    alive: bool = True


@dataclass
class Channel:
    channel_id: int
    owner_task_id: int
    cap_mask: int
    domain: int


@dataclass
class GraphState:
    tasks: dict[int, Task] = field(default_factory=dict)
    channels: dict[int, Channel] = field(default_factory=dict)
    # (src_channel_id, dst_channel_id) pairs
    chan_edges: set[tuple[int, int]] = field(default_factory=set)
    # (src_domain, dst_domain) pairs allowed by the matrix
    domain_edges: set[tuple[int, int]] = field(default_factory=set)


def _unpack_le32(hash_field: bytes, offset: int) -> int:
    return struct.unpack_from("<I", hash_field, offset)[0]


def apply_record(state: GraphState, rec: dict) -> None:
    """Mutate `state` based on one decoded record. Unknown types ignored."""
    t = rec["type"]
    if t == REC_TASK_CREATE:
        # J1 packing (see emit_task_create_record in services/auditor/exporter.c):
        #   rec.operation   = task_id  (full uint32)
        #   rec.checksum    = parent_task_id  (full uint32)
        #   payload_hash[0..3] = cap_mask
        #   payload_hash[4..7] = domain  (full uint32)
        #   payload_hash[8..11] = kernel_stack_top  (informational)
        hash_bytes  = bytes.fromhex(rec["payload_hash"])
        task_id     = rec["operation"]
        parent      = rec["checksum"]
        cap_mask    = _unpack_le32(hash_bytes, 0)
        domain      = _unpack_le32(hash_bytes, 4)
        state.tasks[task_id] = Task(task_id, parent, cap_mask, domain)

    elif t == REC_TASK_EXIT:
        # exit_code in checksum, task_id in operation per J4.
        task_id = rec["operation"]
        if task_id in state.tasks:
            state.tasks[task_id].alive = False

    elif t == REC_CHAN_CREATE:
        # J2: channel_id, owner_task_id=checksum, cap_mask=operation,
        # full domain in payload_hash[0..3].
        hash_bytes = bytes.fromhex(rec["payload_hash"])
        ch_id      = rec["channel_id"]
        owner      = rec["checksum"]
        cap_mask   = rec["operation"]
        domain     = _unpack_le32(hash_bytes, 0)
        state.channels[ch_id] = Channel(ch_id, owner, cap_mask, domain)

    elif t == REC_CHAN_CONNECT:
        # J3: src in channel_id, dst in operation (full uint32).
        src = rec["channel_id"]
        dst = rec["operation"]
        state.chan_edges.add((src, dst))

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


def parse_record(raw: bytes) -> dict:
    magic, version, rec_type, jiffies, priority, src_domain, protocol, \
        channel_id, operation, checksum, payload_hash = \
        struct.unpack(RECORD_FMT, raw)
    return {
        "magic":        magic,
        "version":      version,
        "type":         rec_type,
        "jiffies":      jiffies,
        "priority":     priority,
        "src_domain":   src_domain,
        "protocol":     protocol,
        "channel_id":   channel_id,
        "operation":    operation,
        "checksum":     checksum,
        "payload_hash": payload_hash.hex(),
    }


def emit_dot(state: GraphState) -> str:
    out = []
    out.append("digraph lughos_state {")
    out.append("  rankdir=LR;")
    out.append("  node [fontname=\"Menlo\", fontsize=10];")
    out.append("  edge [fontname=\"Menlo\", fontsize=9];")
    out.append("")
    out.append("  // ── tasks ──")
    for tid, t in sorted(state.tasks.items()):
        style = "" if t.alive else ", style=dashed, color=gray"
        label = (f"task {tid}\\n"
                 f"parent={t.parent_task_id:#x}\\n"
                 f"caps=0x{t.cap_mask:X} dom={t.domain}")
        out.append(f'  task_{tid} [shape=box, label="{label}"{style}];')
    out.append("")
    out.append("  // ── lineage (parent → child) ──")
    for tid, t in sorted(state.tasks.items()):
        if t.parent_task_id != 0xFFFFFFFF and t.parent_task_id in state.tasks:
            out.append(f'  task_{t.parent_task_id} -> task_{tid} '
                       f'[style=dashed, label="spawns"];')
    out.append("")
    out.append("  // ── channels ──")
    for ch_id, c in sorted(state.channels.items()):
        label = (f"ch {ch_id}\\n"
                 f"caps=0x{c.cap_mask:X} dom={c.domain}")
        out.append(f'  chan_{ch_id} [shape=ellipse, label="{label}"];')
    out.append("")
    out.append("  // ── ownership (task → channel) ──")
    for ch_id, c in sorted(state.channels.items()):
        if c.owner_task_id in state.tasks:
            out.append(f'  task_{c.owner_task_id} -> chan_{ch_id} [label="owns"];')
    out.append("")
    out.append("  // ── channel connections ──")
    for src, dst in sorted(state.chan_edges):
        out.append(f'  chan_{src} -> chan_{dst} [color=blue, label="connect"];')
    out.append("")
    out.append("  // ── domain policy edges ──")
    for src, dst in sorted(state.domain_edges):
        out.append(f'  dom_{src} [shape=diamond, label="dom {src}"];')
        out.append(f'  dom_{dst} [shape=diamond, label="dom {dst}"];')
        out.append(f'  dom_{src} -> dom_{dst} [color=red, label="allow"];')
    out.append("}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", default="/tmp/lugh_ipc.bin")
    ap.add_argument("--at", type=int, default=None, metavar="JIFFIES",
                    help="rebuild state at this jiffies value (default: end-of-stream)")
    ap.add_argument("--summary", action="store_true",
                    help="print a text summary instead of DOT")
    args = ap.parse_args()

    try:
        with open(args.file, "rb") as f:
            blob = f.read()
    except OSError as e:
        print(f"reconstruct_graph: cannot open {args.file}: {e}", file=sys.stderr)
        return 1

    if len(blob) % RECORD_SIZE != 0:
        print(f"reconstruct_graph: torn stream ({len(blob)} bytes)", file=sys.stderr)
        return 1

    state = GraphState()
    processed = 0
    for i in range(len(blob) // RECORD_SIZE):
        chunk = blob[i * RECORD_SIZE : (i + 1) * RECORD_SIZE]
        rec = parse_record(chunk)
        if rec["magic"] != MAGIC:
            continue
        if args.at is not None and rec["jiffies"] > args.at:
            break
        apply_record(state, rec)
        processed += 1

    if args.summary:
        print(f"# graph state @ "
              f"{'jiffies=' + str(args.at) if args.at is not None else 'end-of-stream'}", )
        print(f"# {processed} events applied")
        print(f"tasks:           {len(state.tasks)}")
        print(f"  live:          {sum(1 for t in state.tasks.values() if t.alive)}")
        print(f"  exited:        {sum(1 for t in state.tasks.values() if not t.alive)}")
        print(f"channels:        {len(state.channels)}")
        print(f"chan_connects:   {len(state.chan_edges)}")
        print(f"domain_edges:    {len(state.domain_edges)}")
        return 0

    print(emit_dot(state))
    return 0


if __name__ == "__main__":
    sys.exit(main())
