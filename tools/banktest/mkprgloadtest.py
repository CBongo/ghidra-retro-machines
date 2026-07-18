#!/usr/bin/env python3
"""Generate C64 PRGs that exercise arbitrary-address and wrapping loads.

Usage: mkprgloadtest.py <output-dir>

The fixtures deliberately contain conspicuous marker bytes rather than useful
programs, except for c000emutest, which is a small in-place decrypt loop used to
prove that base-space code loaded at $C000 is visible to EmulationRecovery.
"""

import os
import sys


def write_prg(outdir, name, load_address, payload):
    path = os.path.join(outdir, name)
    with open(path, "wb") as stream:
        stream.write(bytes((load_address & 0xff, load_address >> 8)))
        stream.write(payload)
    print("wrote %s (%d payload bytes at $%04X)" %
          (path, len(payload), load_address))


def placement_payload():
    """$A000-$FFFF, crossing every banked window and base RAM $C000."""
    payload = bytearray([0x5a] * 0x6000)
    for address, marker in (
            (0xA000, b"A000"),
            (0xBFFC, b"BEND"),
            (0xC000, b"C000"),
            (0xCFFC, b"CEND"),
            (0xD000, b"D000"),
            (0xDFFC, b"DEND"),
            (0xE000, b"E000"),
            (0xFFFC, b"EEND")):
        offset = address - 0xA000
        payload[offset:offset + len(marker)] = marker
    return payload


def wrapping_payload():
    """$FFFC-$FFFF then $0000-$0303, including P6510 and low-RAM vectors."""
    payload = bytearray([0x77] * (4 + 0x304))
    payload[0:4] = bytes((0xfc, 0xfd, 0xfe, 0xff))
    payload[4:8] = bytes((0xd0, 0xd1, 0x02, 0x03))  # $0000-$0003
    payload[4 + 0x300:4 + 0x304] = b"VECT"          # $0300-$0303
    return payload


def c000_emu_payload():
    key = 0xaa
    plaintext = bytes(range(1, 9))
    code = bytes((
        0xa2, 0x07,             # LDX #$07
        0xbd, 0x10, 0xc0,       # LDA $C010,X
        0x49, key,              # EOR #$AA
        0x9d, 0x10, 0xc0,       # STA $C010,X
        0xca,                   # DEX
        0x10, 0xf5,             # BPL $C002
        0x4c, 0x0d, 0xc0,       # JMP $C00D
    ))
    assert len(code) == 0x10
    return code + bytes(value ^ key for value in plaintext)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkprgloadtest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    write_prg(outdir, "prgplacementtest.prg", 0xa000, placement_payload())
    write_prg(outdir, "prgwraptest.prg", 0xfffc, wrapping_payload())
    write_prg(outdir, "c000emutest.prg", 0xc000, c000_emu_payload())


if __name__ == "__main__":
    main()
