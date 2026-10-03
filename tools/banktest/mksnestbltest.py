#!/usr/bin/env python3
"""Synthesize snestbltest.smc (bead grm-s3wo): a 64 KiB LoROM cartridge carrying the same
invented-table strings as mknestbltest.py (imported from it, so the two cannot drift), for
SnesRomLoader -loader-tblFile + TblStringAnalyzer. The matching snestbltest.tbl is the NES
fixture's table verbatim.

LoROM maps ROM offset $1000 at $00:9000, so every string address matches the NES fixture
($9000..$90E0). Bank $00 is also mirrored byte-mapped at $80:8000, which pins grm-a6n0 on a
second platform: the strings must be annotated at $00:9xxx only, never at $80:9xxx.
Padding is $00, unmapped in the table, as in the NES fixture.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mknestbltest as nes   # noqa: E402

HEADER_AT = 0x7FC0
BANK = 0x8000
RESET = 0x8000


def cartridge():
    image = bytearray(BANK * 2)
    # the shared string layout (CPU $8000-based offsets == LoROM bank-0 offsets)
    prg = nes.make_prg(BANK)
    image[0:BANK] = prg
    image[0:0x1000] = bytes(0x1000)     # drop the NES reset stub/vectors; SNES has its own
    image[BANK - 6:BANK] = bytes(6)
    # reset code: SEI; CLC; XCE; BRA *   (parked)
    image[0:5] = bytes([0x78, 0x18, 0xFB, 0x80, 0xFE])

    at = HEADER_AT
    image[at:at + 21] = "SNESTBLTEST".ljust(21).encode("ascii")
    image[at + 0x15] = 0x20     # LoROM, slow
    image[at + 0x16] = 0x00     # ROM only
    image[at + 0x17] = 0x06     # 64 KiB
    image[at + 0x18] = 0x00
    checksum = 0x1234
    image[at + 0x1C] = (checksum ^ 0xFFFF) & 0xFF
    image[at + 0x1D] = ((checksum ^ 0xFFFF) >> 8) & 0xFF
    image[at + 0x1E] = checksum & 0xFF
    image[at + 0x1F] = (checksum >> 8) & 0xFF
    image[at + 0x20 + 0x1C] = RESET & 0xFF
    image[at + 0x20 + 0x1D] = RESET >> 8
    return bytes(image)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mksnestbltest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    img = cartridge()
    # self-check: strings landed where the criteria expect (LoROM $00:9000 == offset $1000)
    assert img[0x1000] == 0x87 and img[0x100C] == 0xFF
    assert img[0x10E4] == 0xFF
    with open(os.path.join(outdir, "snestbltest.smc"), "wb") as f:
        f.write(img)
    with open(os.path.join(outdir, "snestbltest.tbl"), "w", newline="") as f:
        f.write(nes.make_tbl())
    print("wrote snestbltest.smc (%d bytes) and snestbltest.tbl" % len(img))


if __name__ == "__main__":
    main()
