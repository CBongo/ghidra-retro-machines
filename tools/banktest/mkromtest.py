#!/usr/bin/env python3
"""Generates the ROM-loading regression fixture set (bead grm-mbm).

Usage: mkromtest.py <output-dir>

Writes into <output-dir>:
  - romload.prg    : a trivial C64 PRG (just enough to import)
  - kernal.bin     : 8192-byte synthetic "KERNAL" ROM, byte[i] = i & 0xFF
  - basic.bin      : 8192-byte synthetic "BASIC"  ROM, byte[i] = (i & 0xFF) ^ 0x55
  - chargen.bin    : 4096-byte synthetic "CHARGEN" ROM, byte[i] = (i & 0xFF) ^ 0xAA

These are NOT real ROMs (copyrighted) -- just known-pattern files the exact size
the loader expects, so run-banktest can pass their paths as loader options
(-loader-kernalRom etc.) and VerifyBankTest can assert the KERNAL/BASIC/CHARGEN
blocks came back INITIALIZED with those bytes. The distinct per-file patterns
prove each path lands in the right block; the KERNAL pattern makes byte $E3A2
equal $A2 (offset 0x3A2), mirroring where CHRGET really lives (grm-1.7.1).
No dependencies beyond Python 3.
"""

import sys
import os

LOAD_ADDR = 0x2000


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkromtest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    # Trivial PRG: load $2000, body = LDA #$00 ; RTS.
    prg = bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8, 0xA9, 0x00, 0x60])
    with open(os.path.join(outdir, "romload.prg"), "wb") as f:
        f.write(prg)

    kernal = bytes(i & 0xFF for i in range(0x2000))
    basic = bytes((i & 0xFF) ^ 0x55 for i in range(0x2000))
    chargen = bytes((i & 0xFF) ^ 0xAA for i in range(0x1000))
    for name, data in (("kernal.bin", kernal), ("basic.bin", basic),
                       ("chargen.bin", chargen)):
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)

    print("wrote romload.prg + kernal.bin(%d)/basic.bin(%d)/chargen.bin(%d) to %s" %
          (len(kernal), len(basic), len(chargen), outdir))


if __name__ == "__main__":
    main()
