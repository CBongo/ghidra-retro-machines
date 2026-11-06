#!/usr/bin/env python3
"""Generate a tiny synthetic EA-style boot disk for the EA boot-image fixture (bead grm-t3n.6).

Usage: mkeabootd64test.py <output-dir>

Writes eabootd64test.d64: a 35-track image holding a synthetic 2562-byte "EA loader" (a USR file
so the PRG loader does not import it; the real one is a PRG) and, in raw sectors T1 S0.., a
5-page boot image encrypted with the key the loader's own bytes imply. D64FileSystem must expose
it as the synthetic member "EA_BOOT_IMAGE.prg" at $0800. Entirely synthetic; the loader carries
only the few machine-code anchor bytes the recognizer keys on.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402
from mkd64test import SECTORS, offset  # noqa: E402

START_PAGE = 0x08
END_PAGE = 0x0D


def put(prg, addr, *vals):
    for i, v in enumerate(vals):
        prg[2 + addr - 0xC000 + i] = v


def rot_sum(mem, start, count):
    a = 0
    for i in range(count):
        carry = (a >> 7) & 1
        a = (((a << 1) & 0xFF) + mem[start + i] + carry) & 0xFF
    return a


def plain_image():
    return bytes((i * 13 + (i >> 8) + 5) & 0xFF for i in range((END_PAGE - START_PAGE) * 256))


def make_loader(checksum):
    prg = bytearray(2562)
    prg[1] = 0xC0
    for i in range(2, len(prg)):
        prg[i] = (i * 31 + 7) & 0xFF
    prg[5], prg[6], prg[7] = START_PAGE, END_PAGE, checksum
    put(prg, 0xC293, 0xA9, 0x00, 0x85, 0x2C, 0xAD, 0x03, 0xC0)
    put(prg, 0xC4D3, 0xEE, 0xBF, 0xC6, 0xAD, 0xBF, 0xC6)
    put(prg, 0xC4E0, 0xFF)
    put(prg, 0xC4EB, 0xA0, 0x00, 0x98, 0x0A, 0x71, 0x2C)
    return bytes(prg)


def derive_key(loader):
    mem = bytearray(loader[2:])
    mem[0xC4D3 - 0xC000] = 0xCE
    mem[0xC4E0 - 0xC000] = 0xF1
    return (rot_sum(mem, 0x08, 0x2E6) + mem[4]) & 0xFF, rot_sum(mem, 0x309, 0x227)


def crypt(data, load_addr, c6bf, c6c0):
    out = bytearray(data)
    idx = 0
    while True:
        c6bf = (c6bf - 1) & 0xFF
        if c6bf == c6c0:
            c6bf = 0xF1
            c6c0 = (c6c0 + 1) & 0xFF
            key = c6c0
        else:
            key = c6bf
        for _ in range(4):
            for _ in range(2):
                if idx < len(out):
                    out[idx] ^= key
                idx += 1
            key = (((load_addr + idx) >> 8) & 0xFF) ^ 0x7F
        if key == 0 or idx >= len(out):
            return bytes(out)


def build():
    img = bytearray(sum(SECTORS) * 256)
    bam = offset(18, 0)
    img[bam:bam + 3] = bytes((18, 1, 0x41))
    img[offset(18, 1) + 1] = 0xFF
    plain = plain_image()
    loader = make_loader(sum(plain) & 0xFF)
    c6bf, c6c0 = derive_key(loader)
    enc = crypt(plain, START_PAGE << 8, c6bf, c6c0)
    track, sector = 1, 0
    for p in range(len(enc) // 256):
        base = offset(track, sector)
        img[base:base + 256] = enc[p * 256:(p + 1) * 256]
        sector += 1
        if sector == 20:
            sector, track = 0, track + 1
    # Loader file on track 5 onward (clear of the raw boot sectors on tracks 1-2).
    chunks = [loader[i:i + 254] for i in range(0, len(loader), 254)]
    secs = [(5 + i // 21, i % 21) for i in range(len(chunks))]
    for i, chunk in enumerate(chunks):
        base = offset(*secs[i])
        if i + 1 < len(chunks):
            img[base:base + 2] = bytes(secs[i + 1])
        else:
            img[base:base + 2] = bytes((0, len(chunk) + 1))
        img[base + 2:base + 2 + len(chunk)] = chunk
    entry = offset(18, 1)
    img[entry + 2] = 0x83  # closed USR
    img[entry + 3:entry + 5] = bytes(secs[0])
    img[entry + 5:entry + 21] = b"EA2".ljust(16, b"\xa0")
    return bytes(img)


def main():
    outdir = bankgen.outdir_arg(__file__)
    path = bankgen.write_bytes(outdir, "eabootd64test.d64", build())
    print("wrote %s" % path)


if __name__ == "__main__":
    main()
