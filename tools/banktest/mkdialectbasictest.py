#!/usr/bin/env python3
"""Generate small, byte-exact CBM BASIC dialect analyzer fixtures.

Usage: mkdialectbasictest.py <output-dir>

The fixtures deliberately retain token bytes rather than source text.  They
exercise the $CC+ dialect fork, C128's CE/FE two-byte pages (including invalid
pairs that still consume their second byte), quote/REM raw PETSCII behavior,
and a simple decimal SYS target where that dialect supports the analyzer's
common function-marking behavior.
"""

import os
import sys


def write(path, load_addr, payload):
    with open(path, "wb") as stream:
        stream.write(bytes([load_addr & 0xff, load_addr >> 8]) + payload)


def make_c64():
    # BASIC 2 owns neither $CC+ nor the C128 CE/FE token pages.  The text is
    # structurally valid but intentionally not executable; it is a decoder-only
    # collision guard, while mkbasictest.py remains the executable C64 fixture.
    return bytes([
        0x0f, 0x08, 0x0a, 0x00, 0xcc, 0x20, 0xd5, 0x20, 0xce, 0x02, 0x20, 0xfe, 0x02,
        0x00,
        # An in-range expression is not a simple SYS literal: it must not create
        # a function at its decimal prefix ($0810, or 2064).
        0x1c, 0x08, 0x14, 0x00, 0x9e, 0x20, 0x32, 0x30, 0x36, 0x34, 0x2b, 0x31, 0x00,
        0x00, 0x00,
    ])


def make_c64_overflow():
    # Keep this in a separate program: the analyzer deliberately handles only the
    # first SYS per PRG, and this pure overflow must independently take its Note path.
    return bytes([
        0x0d, 0x08, 0x0a, 0x00, 0x9e, 0x20, 0x36, 0x35, 0x35, 0x33, 0x36, 0x00,
        0x00, 0x00,
    ])


def make_pet4():
    # The master link is $042a and the trailing RTS is at $042c (decimal 1068).
    return bytes([
        0x0b, 0x04, 0x0a, 0x00, 0xcc, 0x20, 0xcd, 0x20, 0xda, 0x00,
        0x16, 0x04, 0x14, 0x00, 0x99, 0x22, 0xcc, 0xcd, 0xda, 0x22, 0x00,
        0x1f, 0x04, 0x1e, 0x00, 0x8f, 0xcc, 0x22, 0xce, 0x00,
        0x2a, 0x04, 0x28, 0x00, 0x9e, 0x20, 0x31, 0x30, 0x36, 0x38, 0x00,
        0x00, 0x00, 0x60,
    ])


def make_c128():
    # The master link is $1c4d and the trailing RTS is at $1c4f (decimal 7247).
    return bytes([
        0x0b, 0x1c, 0x0a, 0x00, 0xcc, 0x20, 0xd5, 0x20, 0xef, 0x00,
        0x12, 0x1c, 0x14, 0x00, 0xce, 0x02, 0x00,
        0x19, 0x1c, 0x1e, 0x00, 0xfe, 0x02, 0x00,
        # CE99 and FE99 are invalid extension tokens.  Each prefix must consume
        # its $99 second byte as raw PETSCII rather than allowing a PRINT token.
        0x23, 0x1c, 0x23, 0x00, 0xce, 0x99, 0x20, 0xfe, 0x99, 0x00,
        # A configured prefix at the final text byte has no selector to consume.
        0x29, 0x1c, 0x25, 0x00, 0xce, 0x00,
        0x36, 0x1c, 0x28, 0x00, 0x99, 0x22, 0xce, 0x02, 0xfe, 0x02, 0xcc, 0x22, 0x00,
        0x42, 0x1c, 0x32, 0x00, 0x8f, 0xce, 0x02, 0xfe, 0x02, 0xcc, 0x22, 0x00,
        0x4d, 0x1c, 0x3c, 0x00, 0x9e, 0x20, 0x37, 0x32, 0x34, 0x37, 0x00,
        0x00, 0x00, 0x60,
    ])


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkdialectbasictest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    write(os.path.join(outdir, "c64basic2tokentest.prg"), 0x0801, make_c64())
    write(os.path.join(outdir, "c64basicoverflowtest.prg"), 0x0801, make_c64_overflow())
    write(os.path.join(outdir, "petbasic4test.prg"), 0x0401, make_pet4())
    write(os.path.join(outdir, "c128basic7test.prg"), 0x1c01, make_c128())
    print("wrote C64 BASIC 2, PET BASIC 4, and C128 BASIC 7 dialect fixtures to " + outdir)


if __name__ == "__main__":
    main()
