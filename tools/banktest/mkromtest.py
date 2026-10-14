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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402

LOAD_ADDR = 0x2000


def main():
    outdir = bankgen.outdir_arg(__file__)

    # Trivial PRG: load $2000, body = LDA #$00 ; RTS.
    bankgen.write_prg(outdir, "romload.prg", LOAD_ADDR, [0xA9, 0x00, 0x60])

    kernal = bytes(i & 0xFF for i in range(0x2000))
    basic = bytes((i & 0xFF) ^ 0x55 for i in range(0x2000))
    chargen = bytes((i & 0xFF) ^ 0xAA for i in range(0x1000))
    for name, data in (("kernal.bin", kernal), ("basic.bin", basic),
                       ("chargen.bin", chargen)):
        bankgen.write_bytes(outdir, name, data)

    print("wrote romload.prg + kernal.bin(%d)/basic.bin(%d)/chargen.bin(%d) to %s" %
          (len(kernal), len(basic), len(chargen), outdir))


if __name__ == "__main__":
    main()
