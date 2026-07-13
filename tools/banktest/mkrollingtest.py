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
    ciphertext = bytes(p ^ k for p, k in zip(PLAINTEXT, KEYTAB))
    return code + KEYTAB + ciphertext


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkrollingtest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    body = build()
    header = bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8])
    path = os.path.join(outdir, "rollingdecrypt.prg")
    with open(path, "wb") as f:
        f.write(header + body)
    print("wrote %s (%d bytes); entry $%04X, keytab $%04X, payload $%04X-$%04X" %
          (path, len(header) + len(body), LOAD_ADDR, KEYTAB_ADDR, PAYLOAD_ADDR,
           PAYLOAD_ADDR + len(PLAINTEXT) - 1))


if __name__ == "__main__":
    main()
