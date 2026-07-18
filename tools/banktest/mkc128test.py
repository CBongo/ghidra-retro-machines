#!/usr/bin/env python3
"""Generate the deterministic C128 native-BASIC loader fixture.

Usage: mkc128test.py <output-dir>

The PRG starts at the C128 native-mode BASIC text address ($1C01).  Its linked
BASIC-line chain reaches $FEFE and its first line contains raw BASIC 7 two-byte
token prefixes ($CE/$02 and $FE/$03); the loader only needs to preserve them,
while BASIC 7 token interpretation belongs to a future analyzer.  The
accompanying files are exact-size, synthetic (non-copyrighted) ROM images for
the fixed C128 power-up map slots.
"""

import os
import sys


LOAD_ADDR = 0x1C01
MAX_PRG_END_EXCLUSIVE = 0xFF00


def write_rom(path, size, seed):
    with open(path, "wb") as stream:
        stream.write(bytes((seed + i) & 0xff for i in range(size)))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkc128test.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    # 10 REM <raw BASIC 7 CE/FE prefixed token pairs>.  A REM token keeps the
    # fixture harmless to an eventual BASIC 7 parser while retaining the raw
    # bytes that prove PRG placement does not alter them.  Continue with short,
    # valid linked REM lines up to the $FEFE master $0000 link, proving the
    # large payload is a real BASIC chain rather than arbitrary padding.
    payload = bytearray()
    cursor = LOAD_ADDR
    line_number = 10
    master_link = MAX_PRG_END_EXCLUSIVE - 2

    def append_line(text):
        nonlocal cursor, line_number
        next_addr = cursor + 5 + len(text)
        payload.extend((next_addr & 0xff, next_addr >> 8,
                        line_number & 0xff, line_number >> 8))
        payload.extend(text)
        payload.append(0)
        cursor = next_addr
        line_number = (line_number + 10) & 0xffff

    append_line(bytes([0x8F, 0xCE, 0x02, 0xFE, 0x03]))
    while cursor < master_link:
        # Five bytes are the link, line number, and terminator.  Keep every
        # record at most 160 bytes so the generated chain remains easy to
        # inspect while its final line reaches the exact boundary.
        text_size = min(155, master_link - cursor - 5)
        append_line(bytes([0x8F]) * text_size)
    assert cursor == master_link
    payload.extend((0, 0))
    with open(os.path.join(outdir, "c128nativebasic7test.prg"), "wb") as stream:
        stream.write(bytes([LOAD_ADDR & 0xff, LOAD_ADDR >> 8]) + payload)

    # Exact-slot images with distinct position-dependent patterns.  These are
    # intentionally synthetic; they exercise loader paths without distributing
    # Commodore ROM contents.
    for name, size, seed in (
            ("c128-basic-lo.bin", 0x4000, 0x10),
            ("c128-basic-hi.bin", 0x4000, 0x20),
            ("c128-editor.bin", 0x1000, 0x30),
            ("c128-kernal.bin", 0x2000, 0x40)):
        write_rom(os.path.join(outdir, name), size, seed)

    print("wrote C128 native BASIC PRG and synthetic BASIC/editor/KERNAL ROMs to " + outdir)


if __name__ == "__main__":
    main()
