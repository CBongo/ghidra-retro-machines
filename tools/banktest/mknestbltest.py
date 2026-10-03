#!/usr/bin/env python3
"""Synthesize nestbltest.nes + nestbltest.tbl (bead grm-pqk): a 32 KiB NROM image carrying
a handful of strings encoded with a made-up per-game "tile table", and the matching .tbl.

Nothing here is copyrighted: the table is invented (tiles $80+ are A-Z, a few punctuation
tiles, one two-byte "DTE" entry), and the strings are generic.

The ROM exercises TblStringAnalyzer end to end. PRG offset == CPU address - $8000 (NROM-256,
no mirroring), $00 is deliberately UNMAPPED in the table and is the padding between strings,
so every string is bounded by an undecodable byte on the left.

  $8000  4C 00 80      JMP $8000   (RESET: idle loop)
  $8003  40            RTI         (NMI/IRQ)
  $9000  S1  "HELLO WORLD!" FF                  -> annotated (plain run, end token FF)
  $9020  S2  F0 01 "ITE" -> "QUITE" FF         -> annotated (4 entries), via the two-byte entry F001=QU
                                                   (longest match must beat F0=Q)
  $9040  S3  "GAME" FE                          -> annotated, a SECOND end token
  $9060  S4  "AB" FF                            -> NOT annotated: below min length (4)
  $9080  S5  "SCORE" 00                         -> NOT annotated: no end token (unmapped $00)
  $90A0  S6  "A" FD "BCD" FF                    -> annotated; FD is a legacy *FD=<br> entry,
                                                   decoded as text and not as a terminator
  $90C0  S7  "NOW" FF                           -> NOT annotated: 3 entries, one under the minimum
  $90E0  S8  "ABCD" FF                          -> annotated: exactly the minimum length (4)
"""
import os
import sys

PRG_SIZE = 0x8000
BASE = 0x8000

# tile -> text; the TBL below is generated from this so the two cannot drift.
LETTERS = {0x80 + i: chr(ord("A") + i) for i in range(26)}
PUNCT = {0xA0: " ", 0xA1: "!", 0xA2: ","}
END_TOKENS = {0xFF: "<end>", 0xFE: "<end2>"}
LINEBREAK = {0xFD: "<br>"}
TWO_BYTE = {(0xF0, 0x01): "QU"}
SINGLE_Q = {0xF0: "Q"}


def enc(text):
    inv = {v: k for k, v in {**LETTERS, **PUNCT}.items()}
    return bytes(inv[c] for c in text)


def make_tbl():
    lines = [
        "# nestbltest.tbl -- invented table for the grm-pqk fixture (no real game)",
        "# tiles 80-99 are A-Z",
    ]
    for k, v in sorted(LETTERS.items()):
        lines.append("%02X=%s" % (k, v))
    lines.append("")
    for k, v in sorted(PUNCT.items()):
        lines.append("%02X=%s" % (k, v))
    lines.append("# a one-byte Q and a two-byte QU that must win longest-match")
    for k, v in SINGLE_Q.items():
        lines.append("%02X=%s" % (k, v))
    for k, v in TWO_BYTE.items():
        lines.append("%02X%02X=%s" % (k[0], k[1], v))
    lines.append("# end-of-string tokens")
    for k, v in sorted(END_TOKENS.items(), reverse=True):
        lines.append("/%02X=%s" % (k, v))
    lines.append("# legacy linebreak entry")
    for k, v in LINEBREAK.items():
        lines.append("*%02X=%s" % (k, v))
    return "\r\n".join(lines) + "\r\n"   # CRLF on purpose: real .tbl files often are


def make_prg(size=PRG_SIZE):
    prg = bytearray(size)

    def put(cpu, data):
        off = cpu - BASE
        prg[off:off + len(data)] = data

    put(0x8000, bytes([0x4C, 0x00, 0x80]))
    put(0x8003, bytes([0x40]))
    put(0x9000, enc("HELLO WORLD!") + b"\xFF")
    put(0x9020, b"\xF0\x01" + enc("ITE") +b"\xFF")
    put(0x9040, enc("GAME") + b"\xFE")
    put(0x9060, enc("AB") + b"\xFF")
    put(0x9080, enc("SCORE") + b"\x00")
    put(0x90A0, enc("A") + b"\xFD" + enc("BCD") + b"\xFF")
    put(0x90C0, enc("NOW") + b"\xFF")
    put(0x90E0, enc("ABCD") + b"\xFF")
    put(BASE + size - 6, bytes([0x03, 0x80, 0x00, 0x80, 0x03, 0x80]))
    return bytes(prg)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mknestbltest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    prg = make_prg()
    assert len(prg) == PRG_SIZE

    def at(cpu):
        return prg[cpu - BASE]

    # byte-level self-check of every string and the vectors (a typo here would otherwise
    # produce a valid-but-wrong ROM that gets blessed into the golden)
    assert prg[0x0000:0x0003] == bytes([0x4C, 0x00, 0x80]) and at(0x8003) == 0x40
    assert at(0x9000) == 0x87 and at(0x900B) == 0xA1 and at(0x900C) == 0xFF   # H ... ! <end>
    assert prg[0x1020:0x1022] == b"\xF0\x01" and at(0x9025) == 0xFF            # DTE, I, T, E, end
    assert at(0x9044) == 0xFE
    assert at(0x9062) == 0xFF and at(0x9063) == 0x00
    assert at(0x9085) == 0x00
    assert at(0x90A1) == 0xFD and at(0x90A5) == 0xFF
    assert at(0x90C3) == 0xFF
    assert at(0x90E4) == 0xFF
    assert prg[0x7FFA] | (prg[0x7FFB] << 8) == 0x8003    # NMI
    assert prg[0x7FFC] | (prg[0x7FFD] << 8) == 0x8000    # RESET
    assert prg[0x7FFE] | (prg[0x7FFF] << 8) == 0x8003    # IRQ

    write_rom(outdir, "nestbltest", prg)
    # grm-a6n0: the same strings in a 16 KiB NROM-128 image. The loader mirrors PRG at
    # $C000 as a byte-mapped block, and the analyzer must annotate $9000.. only, not $D000..
    write_rom(outdir, "nestbltest16", make_prg(0x4000))
    with open(os.path.join(outdir, "nestbltest.tbl"), "w", newline="") as f:
        f.write(make_tbl())


def write_rom(outdir, stem, prg):
    header = bytearray(16)
    header[0:4] = b"NES\x1a"
    header[4] = len(prg) // 0x4000   # 1 or 2 x 16 KiB, mapper 0 (NROM-128/256)
    header[5] = 0
    rom = bytes(header) + prg
    with open(os.path.join(outdir, stem + ".nes"), "wb") as f:
        f.write(rom)
    print("wrote %s (%d bytes)" % (os.path.join(outdir, stem + ".nes"), len(rom)))


if __name__ == "__main__":
    main()
