"""Static reachability closure of 6502 code via pyghidra-mcp's `disassemble` (grm-haj3).

Follows every DIRECT control-flow target (JSR/JMP abs, branches, fall-through) from the roots
itself, rather than trusting Ghidra's existing flow refs, and prints the first path found to the
target. It walks EXISTING listing instructions only (`disassemble` does not decode raw bytes): a
target Ghidra never disassembled is flagged as a blind spot, never walked. Also flags what
could hide control flow (indirect JMP, PHA;RTS push-dispatch), writes to the given zero-page
slot, indirect stores, and banked-window targets (< $C000, not followed: which bank runs there
is not a static fact).

usage: closure6502.py <binary> <slot-zp-hex> <target-hex> <root-hex>...
  STOP="f270 ..."  treat the instructions at these addresses as non-returning exits (e.g. a
                   restart JMP), so the walk does not continue through them

Worked example (blmaster, the e953 question in docs/human-research-todo.md's Answered table):
  closure6502.py blmaster.nes d3 e692 ea3a eb51 e953
"""
import asyncio
import json
import os
import re
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = f"http://127.0.0.1:{os.environ.get('GRM_MCP_PORT', '8765')}/mcp"
STOP = {int(a, 16) for a in os.environ.get("STOP", "").split()}
BRANCH = {"BPL", "BMI", "BVC", "BVS", "BCC", "BCS", "BNE", "BEQ"}


async def disasm(s, binary, addr):
    r = await s.call_tool("disassemble", {"binary_name": binary, "address": f"{addr:04x}", "count": 40})
    listing = json.loads(r.content[0].text)["listing"]
    out = []
    for line in listing.splitlines():
        m = re.match(r"([0-9a-f]+)\s+(\w+)\s*(.*)", line.strip())
        if m:
            out.append((int(m.group(1), 16), m.group(2).upper(), m.group(3)))
    return out


def path(parent, b):
    chain = []
    while parent.get(b):
        blk, site, mn = parent[b]
        chain.append(f"{site:04x} {mn} {b:04x}")
        b = blk
    chain.append(f"root {b:04x}")
    return " <- ".join(chain)


def target(ops):
    m = re.match(r"0x([0-9a-f]+)$", ops.strip())
    return int(m.group(1), 16) if m else None


async def main(binary, slot, goal, roots):
    flags, seen_blocks, edges = [], set(), []
    parent = {r: None for r in roots}
    work = list(roots)
    async with streamablehttp_client(URL) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            while work:
                start = work.pop()
                if start in seen_blocks:
                    continue
                seen_blocks.add(start)
                if start == goal:
                    flags.append(f"REACHES target {goal:04x} via " + path(parent, start))
                if start < 0xC000:
                    flags.append(f"banked-window target {start:04x} (not followed)")
                    continue
                prev = None
                rows = await disasm(s, binary, start)
                # `disassemble` lists EXISTING instructions from `start` forward; when `start` itself
                # is not an instruction it silently returns the NEXT one. Never walk from that.
                if not rows or rows[0][0] != start:
                    flags.append(f"target {start:04x} is not disassembled in Ghidra's listing (blind spot)")
                    continue
                for addr, mn, ops in rows:
                    if addr != start and addr in seen_blocks:
                        break
                    if addr == goal:
                        flags.append(f"REACHES target {goal:04x} (fall-through in block {start:04x}) via " + path(parent, start))
                    if mn in ("STA", "STX", "STY") and re.search(rf"0x0*{slot:x}\b", ops) and "(" not in ops:
                        flags.append(f"{addr:04x} {mn} {ops}  <- writes the slot")
                    if mn in ("STA", "STX", "STY") and "(" in ops:
                        flags.append(f"{addr:04x} {mn} {ops}  <- indirect store (could alias slot)")
                    if mn == "JMP" and "(" in ops:
                        flags.append(f"{addr:04x} JMP {ops}  <- INDIRECT jump")
                    if mn in ("RTS", "RTI") and prev == "PHA":
                        flags.append(f"{addr:04x} {mn} right after PHA  <- possible push-dispatch")
                    if addr in STOP:
                        flags.append(f"{addr:04x} {mn} {ops}  <- treated as non-returning exit (STOP)")
                        break
                    t = target(ops)
                    if mn in ("JSR", "JMP") and t is not None and "(" not in ops:
                        edges.append((addr, mn, t))
                        parent.setdefault(t, (start, addr, mn))
                        work.append(t)
                    if mn in BRANCH and t is not None:
                        parent.setdefault(t, (start, addr, mn))
                        work.append(t)
                    if mn in ("JMP", "RTS", "RTI", "BRK"):
                        break
                    prev = mn
                else:
                    flags.append(f"block {start:04x}: 40-instruction window ended without a terminator")
    print(f"blocks walked: {len(seen_blocks)}")
    print("calls/jumps:", " ".join(f"{a:04x}:{m}->{t:04x}" for a, m, t in sorted(set(edges))))
    print("FLAGS:" if flags else "FLAGS: none")
    for f in flags:
        print("  " + f)


h = lambda x: int(x, 16)
asyncio.run(main(sys.argv[1], h(sys.argv[2]), h(sys.argv[3]), [h(a) for a in sys.argv[4:]]))
