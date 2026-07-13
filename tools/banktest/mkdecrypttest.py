#!/usr/bin/env python3
"""Hand-assembles the C64DecryptLoopAnalyzer regression PRG (bead grm-1.7.2).

Usage: mkdecrypttest.py <output-dir>

Writes decryptloop.prg into <output-dir>. No dependencies beyond Python 3.

Like mkemutest.py this is a constant-EOR in-place decrypt loop, but it ends with
a JMP INTO the decrypted range ($2010), which is the "executed as code" signal
(invariant 4) that makes the analyzer auto-apply the recovery: it decrypts the
range inline and exposes the plaintext as a DECRYPTED_2010 overlay block with a
NOTE provenance bookmark. (mkemutest.py's loop instead spins with JMP $200D, so
the analyzer would only mark it a candidate -- that fixture is for the raw
EmulationRecovery harness, this one for the decrypt analyzer.)

Load address is $2000 (inside RAM_MAIN) so the loader carves the PRG into the
base address space; the loader also marks $2000 as a function, so auto-analysis
disassembles the loop for the INSTRUCTION_ANALYZER to see.

  $2000  A2 07        LDX #$07          ; index 7..0 -> 8 bytes
  $2002  BD 10 20     LDA $2010,X       ; load encrypted byte      (loop top)
  $2005  49 AA        EOR #$AA          ; decrypt with constant key $AA
  $2007  9D 10 20     STA $2010,X       ; store back in place
  $200A  CA           DEX
  $200B  10 F5        BPL $2002         ; loop while X >= 0
  $200D  4C 10 20     JMP $2010         ; JUMP INTO the decrypted range -> AUTO
  $2010  <8 bytes>    encrypted payload = plaintext EOR $AA

Plaintext is $01..$08.
"""

import sys
import os

LOAD_ADDR = 0x2000
KEY = 0xAA
PLAINTEXT = bytes(range(1, 9))          # $01..$08
PAYLOAD_ADDR = 0x2010


def build():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x10, 0x20,       # LDA $2010,X
        0x49, KEY,              # EOR #$AA
        0x9D, 0x10, 0x20,       # STA $2010,X
        0xCA,                   # DEX
        0x10, 0xF5,             # BPL $2002
        0x4C, 0x10, 0x20,       # JMP $2010   (into the decrypted range)
    ])
    assert LOAD_ADDR + len(code) == PAYLOAD_ADDR, \
        "code length must place payload exactly at $2010"
    encrypted = bytes(b ^ KEY for b in PLAINTEXT)
    return code + encrypted


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkdecrypttest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    body = build()
    header = bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8])
    path = os.path.join(outdir, "decryptloop.prg")
    with open(path, "wb") as f:
        f.write(header + body)
    print("wrote %s (%d bytes); entry $%04X, payload $%04X-$%04X, key $%02X" %
          (path, len(header) + len(body), LOAD_ADDR, PAYLOAD_ADDR,
           PAYLOAD_ADDR + len(PLAINTEXT) - 1, KEY))


if __name__ == "__main__":
    main()
