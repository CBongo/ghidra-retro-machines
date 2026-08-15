#!/usr/bin/env python3
"""Hand-assembles the EmulationRecovery regression PRG (bead grm-edg).

Usage: mkemutest.py <output-dir>

Writes emurecoverytest.prg (2-byte little-endian load-address header, then a
6502 constant-key EOR in-place decrypt loop, then the encrypted payload) into
<output-dir>. No dependencies beyond Python 3.

The fixture is a minimal decrypt-on-the-fly routine: it EORs an 8-byte range in
place with a constant key, exactly the tier-1 shape the SMC decrypt work
(grm-1.7.2) recovers. VerifyBankTest.java loads it, runs
retromachines.EmulationRecovery from the loop entry with a dirty-watch on the
payload range, and checks that the harness stops on DIRTY_WATCH with the
correctly decrypted bytes and a clean (non-suspect) provenance log.

The load address ($2000) must lie inside the descriptor's load_target region
(RAM_MAIN, $0800-$9FFF) so the loader carves the PRG into the *base* address
space; a load address outside it (e.g. $C000) collides with another base block
and the loader falls back to an overlay space, which the emulator's base-space
image would not see.

Memory layout (load address $2000, inside RAM_MAIN):

  $2000  A2 07        LDX #$07          ; index 7..0 -> 8 bytes
  $2002  BD 10 20     LDA $2010,X       ; load encrypted byte      (loop top)
  $2005  49 AA        EOR #$AA          ; decrypt with constant key $AA
  $2007  9D 10 20     STA $2010,X       ; store back in place (in-place decrypt)
  $200A  CA           DEX
  $200B  10 F5        BPL $2002         ; loop while X >= 0
  $200D  4C 0D 20     JMP $200D         ; spin (safety net; dirty-watch stops first)
  $2010  <8 bytes>    encrypted payload = plaintext EOR $AA

Plaintext is $01..$08, so the recovered bytes are trivially checkable.
"""

import sys
import os

LOAD_ADDR = 0x2000
KEY = 0xAA
PLAINTEXT = bytes(range(1, 9))          # $01..$08
PAYLOAD_ADDR = 0x2010


def build(load_addr=LOAD_ADDR):
    """Build the constant-EOR decrypt loop loaded at load_addr, encrypting an
    8-byte payload at load_addr+$10 (bead grm-w8a: shared by mkemutest.py's own
    $2000 fixture and mkprgloadtest.py's $C000 one -- the two were previously
    byte-identical except these load-address-dependent operand bytes).

    The BPL branch offset ($F5 = -11) is relative displacement within the loop
    body, so it is the same literal regardless of load_addr; only the LDA/STA
    absolute operand (payload_addr) and the trailing JMP's spin-target operand
    (load_addr+$0D) vary with the load address.
    """
    payload_addr = load_addr + 0x10
    payload_lo, payload_hi = payload_addr & 0xFF, payload_addr >> 8
    spin_addr = load_addr + 0x0D
    spin_lo, spin_hi = spin_addr & 0xFF, spin_addr >> 8
    code = bytes([
        0xA2, 0x07,                        # LDX #$07
        0xBD, payload_lo, payload_hi,      # LDA payload_addr,X
        0x49, KEY,                         # EOR #$AA
        0x9D, payload_lo, payload_hi,      # STA payload_addr,X
        0xCA,                              # DEX
        0x10, 0xF5,                        # BPL loop-top (-11, layout-invariant)
        0x4C, spin_lo, spin_hi,            # JMP spin_addr (spin)
    ])
    assert load_addr + len(code) == payload_addr, \
        "code length must place payload exactly at load_addr+$10"
    encrypted = bytes(b ^ KEY for b in PLAINTEXT)
    return code + encrypted


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkemutest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    body = build()
    header = bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8])
    path = os.path.join(outdir, "emurecoverytest.prg")
    with open(path, "wb") as f:
        f.write(header + body)
    print("wrote %s (%d bytes); entry $%04X, payload $%04X-$%04X, key $%02X" %
          (path, len(header) + len(body), LOAD_ADDR, PAYLOAD_ADDR,
           PAYLOAD_ADDR + len(PLAINTEXT) - 1, KEY))


if __name__ == "__main__":
    main()
