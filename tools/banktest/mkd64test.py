#!/usr/bin/env python3
"""Generate a tiny synthetic 1541 .d64 for the D64FileSystem headless fixture (bead grm-t3n.2).

Usage: mkd64test.py <output-dir>

Writes d64fstest.d64: a 35-track image holding one PRG member (D64FSTEST, exposed as
D64FSTEST.prg and imported by C64PrgLoader) that spans two sectors, plus a SEQ member (NOTES,
exposed as NOTES.seq) that must NOT be imported as a program. Entirely synthetic; no real disk
content.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402

SECTORS = [21] * 17 + [19] * 7 + [18] * 6 + [17] * 5


def offset(track, sector):
    return (sum(SECTORS[:track - 1]) + sector) * 256


def build():
    img = bytearray(sum(SECTORS) * 256)
    bam = offset(18, 0)
    img[bam:bam + 3] = bytes((18, 1, 0x41))
    img[offset(18, 1) + 1] = 0xFF
    alloc = iter([(1, s) for s in range(21)])

    def write_chain(data):
        chunks = [data[i:i + 254] for i in range(0, len(data), 254)] or [b""]
        secs = [next(alloc) for _ in chunks]
        for i, chunk in enumerate(chunks):
            base = offset(*secs[i])
            if i + 1 < len(chunks):
                img[base:base + 2] = bytes(secs[i + 1])
            else:
                img[base:base + 2] = bytes((0, len(chunk) + 1))
            img[base + 2:base + 2 + len(chunk)] = chunk
        return secs[0]

    def entry(index, ftype, name, first):
        base = offset(18, 1) + index * 32
        img[base + 2] = ftype
        img[base + 3:base + 5] = bytes(first)
        img[base + 5:base + 21] = name.ljust(16, "\xa0").encode("latin-1")

    # $C000 load address, 300 payload bytes: crosses a sector boundary (254 data bytes each).
    payload = bytearray(b"D64F" + bytes(range(256)) + bytes(40))
    prg = bytes((0x00, 0xC0)) + bytes(payload)
    entry(0, 0x82, "D64FSTEST", write_chain(prg))
    entry(1, 0x81, "NOTES", write_chain(b"THIS IS A SEQ FILE, NOT A PROGRAM\r"))
    return bytes(img)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    path = bankgen.write_bytes(out, "d64fstest.d64", build())
    print("wrote %s" % path)


if __name__ == "__main__":
    main()
