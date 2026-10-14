"""Helpers shared by the tools/banktest/mk*test.py fixture generators.

Each generator puts its own directory on sys.path before `import bankgen`, so the import also
works under `python -I` (isolated mode does not add the script directory):

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import bankgen  # noqa: E402

Only behaviour that was byte-for-byte identical across the copies lives here; anything that
drifted between generators stays in that generator.
"""

import os
import sys


def outdir_arg(script_file):
    """The generators' `<script> <output-dir>` preamble: check argv, create and return the dir."""
    if len(sys.argv) != 2:
        sys.exit("usage: %s <output-dir>" % os.path.basename(script_file))
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    return outdir


def prg(load_addr, code_bytes):
    """Prefix code with the 2-byte little-endian load address header of a .prg file."""
    return bytes([load_addr & 0xFF, load_addr >> 8]) + bytes(code_bytes)


def write_bytes(outdir, name, data):
    """Write `data` to outdir/name; return the path."""
    path = os.path.join(outdir, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def write_prg(outdir, name, load_addr, payload):
    """Write a .prg (load address header + payload) to outdir/name; return the path."""
    return write_bytes(outdir, name, prg(load_addr, payload))


def ines_header(prg_banks, chr_banks, mapper, nes2_prg_exponent=False):
    # nes2_prg_exponent switches the PRG size field to NES 2.0's EXPONENT form, where h[9]'s
    # low nibble is 0xF and `prg_banks` is not a unit count at all but EEEEEEMM, for a size of
    # 2^E * (2M+1) BYTES. It is the only way to declare a PRG smaller than one 16 KiB unit --
    # see make_prg_nromsub() and InesHeader.nes2RomSize. The CHR field stays linear (h[9]'s
    # high nibble 0), so chr_banks keeps its ordinary meaning.
    h = bytearray(16)
    h[0:4] = b"NES\x1a"
    h[4] = prg_banks
    h[5] = chr_banks
    h[6] = (mapper & 0x0F) << 4  # low mapper nibble, no trainer/mirroring flags
    h[7] = mapper & 0xF0         # high mapper nibble; NES 2.0 bits (h[7] & 0x0C) left 0
    # bytes 8-15 stay zero: plain iNES 1.0, no DiskDude tail
    if nes2_prg_exponent:
        h[7] |= 0x08             # flags7 bits 2-3 == 0b10: this is a NES 2.0 header
        h[9] = 0x0F              # PRG size nibble 0xF -> h[4] is an exponent, not a count
    return bytes(h)
