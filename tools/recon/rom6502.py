"""Shared helpers for the tools/recon scripts: byte-level 6502 decoding (iNES parsing and ROM finding live in tools/banktest/romlib.py and are re-exported here).

The opcode table is NOT defined here: it is tools/banktest/dis6502.py's (`OPS`, `MODES`, `fmt`),
imported by path so that there is exactly one 6502 decode table in the repo (see AGENTS.md,
"Analysis scripts: look in tools/ first"). Addressing-mode names are dis6502's (izx/izy for
(zp,X)/(zp),Y). Official NMOS opcodes only; undocumented opcodes decode to None.

Not a CLI. Import it from a sibling script (which must put its own directory on sys.path first,
because `python -I` drops the script directory):

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import rom6502
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'banktest'))
import dis6502  # noqa: E402  (path set up just above)
import romlib  # noqa: E402
from romlib import cpu_of, parse_ines  # noqa: E402,F401  (moved to romlib; re-exported for importers)

OPS = dis6502.OPS
LEN = dis6502.MODES            # mode -> instruction length

_REV = {v: k for k, v in OPS.items()}   # (mnemonic, mode) -> opcode

TERM = {'RTS', 'RTI', 'JMP', 'BRK'}


def decode(d, i):
    """Decode one instruction at d[i]: (mnemonic, mode, length, operand bytes) or None."""
    if i < 0 or i >= len(d):
        return None
    o = OPS.get(d[i])
    if o is None:
        return None
    n = LEN[o[1]]
    if i + n > len(d):
        return None
    return (o[0], o[1], n, d[i + 1:i + n])


def operand(ins):
    """The raw operand value (16-bit for 3-byte forms, 8-bit for 2-byte forms), else None."""
    n, b = ins[2], ins[3]
    if n == 3:
        return b[0] | b[1] << 8
    if n == 2:
        return b[0]
    return None


def chain_back(d, p, maxback, lo):
    """Earliest start s in [p-maxback, p) (>= lo) whose forward decode lands exactly on p.

    Returns the list of (offset, ins) from s up to p, or [] if none. Heuristic: a decode that
    happens to resync is accepted, and the earliest start wins.
    """
    for s in range(max(lo, p - maxback), p):
        i = s
        out = []
        while i < p:
            ins = decode(d, i)
            if ins is None:
                out = None
                break
            out.append((i, ins))
            i += ins[2]
        if out is not None and i == p and out:
            return out
    return []


class _View:
    """Makes dis6502.fmt (which indexes a 32K view by addr-$8000) read from a few raw bytes."""

    def __init__(self, buf, pc):
        self.buf, self.base = buf, pc - 0x8000

    def __getitem__(self, j):
        return self.buf[j - self.base]


def fmt_ins(ins, pc):
    """Format a decode() result as 'MNEMONIC operand' using dis6502's own formatter."""
    buf = bytes([_REV[(ins[0], ins[1])]]) + bytes(ins[3])
    return dis6502.fmt(_View(buf + b'\0\0', pc), pc)[1]


def find_rom(row_id):
    """Resolve a manifest row id to a ROM path (romlib.find_path; SystemExit if missing)."""
    return romlib.find_path(row_id)
