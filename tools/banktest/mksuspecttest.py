#!/usr/bin/env python3
"""Hand-assembles the SUSPECT (hardware-keyed) decrypt regression PRG (bead grm-yxn).

Usage: mksuspecttest.py <output-dir>

Writes suspectdecrypt.prg into <output-dir>. No dependencies beyond Python 3.

This is the tier-2 SUSPECT case: the rolling key is read from a CIA hardware
register (EOR $DC00,X) rather than a data table. On real hardware that byte is a
timer/latch value the p-code emulator cannot know, so EmulationRecovery answers
the read with a policy value (0) and records an IO read in the provenance log.
C64DecryptLoopAnalyzer therefore still recovers bytes and creates the
DECRYPTED_2011 overlay, but flags the result suspect with a WARNING bookmark
(not a trusted NOTE) -- the "detect and downgrade" behavior for hardware-tainted
recovery.

Because the emulator reads the key as 0, the recovered bytes equal the
ciphertext (plaintext = ciphertext EOR 0). The point of the fixture is the
WARNING, not the byte values, so the ciphertext is a distinctive $C1..$C8.

Load address $2000 (inside RAM_MAIN, marked a function so it disassembles).

  $2000  A2 07        LDX #$07          ; index 7..0 -> 8 bytes
  $2002  BD 11 20     LDA $2011,X       ; load ciphertext byte      (loop top)
  $2005  5D 00 DC     EOR $DC00,X       ; XOR with CIA1 register -> hardware key
  $2008  9D 11 20     STA $2011,X       ; store back in place
  $200B  CA           DEX
  $200C  10 F4        BPL $2002         ; loop while X >= 0
  $200E  4C 11 20     JMP $2011         ; JUMP INTO the range -> AUTO
  $2011  <8 bytes>    ciphertext ($C1..$C8)
"""

import sys
import os

LOAD_ADDR = 0x2000
PAYLOAD_ADDR = 0x2011
CIPHERTEXT = bytes([0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8])


def build():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x11, 0x20,       # LDA $2011,X   (ciphertext)
        0x5D, 0x00, 0xDC,       # EOR $DC00,X   (CIA1 register -- hardware key)
        0x9D, 0x11, 0x20,       # STA $2011,X
        0xCA,                   # DEX
        0x10, 0xF4,             # BPL $2002
        0x4C, 0x11, 0x20,       # JMP $2011   (into the range)
    ])
    assert LOAD_ADDR + len(code) == PAYLOAD_ADDR, "code must end exactly at the ciphertext"
    return code + CIPHERTEXT


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mksuspecttest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    body = build()
    header = bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8])
    path = os.path.join(outdir, "suspectdecrypt.prg")
    with open(path, "wb") as f:
        f.write(header + body)
    print("wrote %s (%d bytes); entry $%04X, payload $%04X-$%04X, key from $DC00 (CIA1)" %
          (path, len(header) + len(body), LOAD_ADDR, PAYLOAD_ADDR,
           PAYLOAD_ADDR + len(CIPHERTEXT) - 1))


if __name__ == "__main__":
    main()
