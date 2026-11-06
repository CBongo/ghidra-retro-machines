#!/usr/bin/env python3
"""Hand-assembles the rolling-key decrypt regression PRG (bead grm-yxn).

Usage: mkrollingtest.py <output-dir>

Writes rollingdecrypt.prg into <output-dir>. No dependencies beyond Python 3.

This exercises C64DecryptLoopAnalyzer's TIER 2 path: the key is not a constant
but a per-byte rolling key read from a table (EOR keytab,X), so the analyzer
cannot decrypt inline -- it hands the loop to the grm-edg EmulationRecovery
harness, which runs it and reads back the plaintext, then materializes the
DECRYPTED_2019 overlay. Because both the key table and the ciphertext live in
initialized PRG memory (no IO / uninitialized reads), the recovery is trusted:
a NOTE bookmark, not a SUSPECT/WARNING one.

Load address $2000 (inside RAM_MAIN, marked a function so it disassembles).

  $2000  A2 07        LDX #$07          ; index 7..0 -> 8 bytes
  $2002  BD 19 20     LDA $2019,X       ; load ciphertext byte      (loop top)
  $2005  5D 11 20     EOR $2011,X       ; XOR with rolling key table $2011,X
  $2008  9D 19 20     STA $2019,X       ; store back in place
  $200B  CA           DEX
  $200C  10 F4        BPL $2002         ; loop while X >= 0
  $200E  4C 19 20     JMP $2019         ; JUMP INTO the decrypted range -> AUTO
  $2011  <8 bytes>    rolling key table
  $2019  <8 bytes>    ciphertext = plaintext EOR keytab

Plaintext is $01..$08.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402

LOAD_ADDR = 0x2000
KEYTAB_ADDR = 0x2011
PAYLOAD_ADDR = 0x2019
PLAINTEXT = bytes(range(1, 9))                              # $01..$08
KEYTAB = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])


def build():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x19, 0x20,       # LDA $2019,X   (ciphertext)
        0x5D, 0x11, 0x20,       # EOR $2011,X   (rolling key table)
        0x9D, 0x19, 0x20,       # STA $2019,X
        0xCA,                   # DEX
        0x10, 0xF4,             # BPL $2002
        0x4C, 0x19, 0x20,       # JMP $2019   (into the decrypted range)
    ])
    assert LOAD_ADDR + len(code) == KEYTAB_ADDR, "code must end exactly at the key table"
    assert KEYTAB_ADDR + len(KEYTAB) == PAYLOAD_ADDR, "key table must end at the payload"
    ciphertext = bytes(p ^ k for p, k in zip(PLAINTEXT, KEYTAB, strict=True))
    return code + KEYTAB + ciphertext


# grm-430b: the Summer Games loader shape -- UP-counting rolling key (key = previous, already
# decrypted byte) whose own back-branch operand ($200F) is inside the decrypted range and is
# patched by the loop; it exits by FALLING THROUGH into the range (no JMP).
#   $2000  A0 0E        LDY #$0E
#   $2002  B9 01 20     LDA $2001,Y
#   $2005  59 00 20     EOR $2000,Y
#   $2008  99 01 20     STA $2001,Y
#   $200B  C8           INY
#   $200C  C0 20        CPY #$20
#   $200E  D0 22        BNE ..       ; operand $22 ^ $D0 = $F2 -> BNE $2002 once decrypted
#   $2010  <17 bytes>   encrypted; range = $200F..$2020
SP_CODE = bytes([0xA9, 0x11, 0xA2, 0x22, 0xA0, 0x33, 0x85, 0xFB] + [0xEA] * 8 + [0x60])
SP_PLAIN = bytes([0xF2]) + SP_CODE                     # $200F..$2020 (18 bytes)


def build_selfpatched():
    code = bytes([
        0xA0, 0x0E, 0xB9, 0x01, 0x20, 0x59, 0x00, 0x20, 0x99, 0x01, 0x20,
        0xC8, 0xC0, 0x20, 0xD0,
    ])
    prev = 0xD0                                        # byte at $200E, the opcode
    enc = bytearray()
    for p in SP_PLAIN:
        enc.append(p ^ prev)
        prev = p
    assert enc[0] == 0x22
    return code + bytes(enc)


def main():
    outdir = bankgen.outdir_arg(__file__)
    sp = bankgen.write_prg(outdir, "selfpatchdecrypt.prg", LOAD_ADDR, build_selfpatched())
    print("wrote %s; range $200F-$2020" % sp)

    body = build()
    path = bankgen.write_prg(outdir, "rollingdecrypt.prg", LOAD_ADDR, body)
    print("wrote %s (%d bytes); entry $%04X, keytab $%04X, payload $%04X-$%04X" %
          (path, 2 + len(body), LOAD_ADDR, KEYTAB_ADDR, PAYLOAD_ADDR,
           PAYLOAD_ADDR + len(PLAINTEXT) - 1))


if __name__ == "__main__":
    main()
