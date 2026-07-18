#!/usr/bin/env python3
"""Generate the deterministic PET 4032 descriptor/loader headless fixture."""

import os
import sys

LOAD_ADDR = 0x0401


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkpettest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    # 10 PRINT"PET" followed by the master $0000 link. The first line's link must
    # point exactly one byte past its own text terminator for the structural sniff.
    text = bytes([0x99, 0x22, ord("P"), ord("E"), ord("T"), 0x22])
    line_size = 2 + 2 + len(text) + 1
    next_addr = LOAD_ADDR + line_size
    payload = bytes([
        next_addr & 0xff, next_addr >> 8,
        10, 0,
    ]) + text + bytes([0, 0, 0])
    with open(os.path.join(outdir, "pet4032test.prg"), "wb") as f:
        f.write(bytes([LOAD_ADDR & 0xff, LOAD_ADDR >> 8]) + payload)

    # Exact-size, non-copyrighted synthetic images exercise fixed-region ROM slots.
    for name, size, seed in (
            ("pet-basic.bin", 0x3000, 0x40),
            ("pet-editor.bin", 0x0800, 0x60),
            ("pet-kernal.bin", 0x1000, 0x80)):
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(bytes((seed + i) & 0xff for i in range(size)))

    print("wrote PET 4032 PRG and synthetic BASIC/editor/KERNAL ROMs to " + outdir)


if __name__ == "__main__":
    main()
