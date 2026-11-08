"""Shared helpers for the tools/recon scripts: iNES parsing and byte-level 6502 decoding.

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


def parse_ines(path):
    """Return (mapper, prg_bytes) for an iNES file, or None if it is not one."""
    raw = open(path, 'rb').read()
    if raw[:4] != b'NES\x1a':
        return None
    prg16, f6, f7 = raw[4], raw[6], raw[7]
    mapper = (f6 >> 4) | (f7 & 0xF0)
    if (f7 & 0x0C) == 0x08:
        mapper |= (raw[8] & 0x0F) << 8
    elif raw[12:16] != b'\0\0\0\0':
        mapper &= 0x0F  # DiskDude header garbage
    off = 16 + (512 if f6 & 4 else 0)
    return mapper, raw[off: off + prg16 * 0x4000]


def cpu_of(prgsize, off):
    """CPU address of PRG offset `off` when the last 16K bank sits at $C000."""
    return 0xC000 + (off - (prgsize - 0x4000))


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
    """Resolve a manifest row id to a ROM path via dis6502's --find logic (prints, so capture it)."""
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        dis6502.find(row_id)
    return buf.getvalue().strip()
