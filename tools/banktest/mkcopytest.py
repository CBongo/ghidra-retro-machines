#!/usr/bin/env python3
"""Hand-assembles the C64CopyLoopAnalyzer regression PRGs (bead grm-1.7.1).

Usage: mkcopytest.py <output-dir>

Writes two PRGs that exercise the two branches of the run-from-elsewhere
recognizer's materialize/disassemble split:

  copyloop.prg  -- a verbatim indexed copy loop that ENDS WITH A JUMP into the
                   destination, proving the copied bytes run as code. The
                   analyzer materializes a dual-home byte-mapped overlay
                   COPY_c000 (mapped 1:1 back to the source at $200E) AND
                   disassembles it.

  copydata.prg  -- the SAME copy loop but with NO jump into the destination (it
                   just RTSes). Insufficient evidence the bytes are code, so the
                   analyzer materializes the overlay COPY_c100 (mapped to $200C)
                   but leaves it as DATA -- not disassembled.

Load address is $2000 (inside RAM_MAIN) so the loader carves each PRG into the
base address space; the loader marks $2000 as a function, so auto-analysis
disassembles the loop for the INSTRUCTION_ANALYZER to see. The source payload
lives inside the loaded PRG, so it is initialized (real bytes) with no ROM
dependency -- the byte-mapped overlay reads those bytes through the 1:1 map.

copyloop.prg ($01..$08 payload copied to $C000):

  $2000  A2 07        LDX #$07          ; index 7..0 -> 8 bytes
  $2002  BD 0E 20     LDA $200E,X       ; load source byte      (loop top)
  $2005  9D 00 C0     STA $C000,X       ; store to destination (DIFFERENT base)
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  4C 00 C0     JMP $C000         ; JUMP INTO the copy -> AUTO (code)
  $200E  01..08       source payload

copydata.prg ($11..$18 payload copied to $C100):

  $2000  A2 07        LDX #$07
  $2002  BD 0C 20     LDA $200C,X       ; source                (loop top)
  $2005  9D 00 C1     STA $C100,X       ; destination (DIFFERENT base)
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  60           RTS               ; no jump into range -> CANDIDATE (data)
  $200C  11..18       source payload
"""

import sys
import os

LOAD_ADDR = 0x2000


def build_copyloop():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x0E, 0x20,       # LDA $200E,X   (source)
        0x9D, 0x00, 0xC0,       # STA $C000,X   (destination)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2002
        0x4C, 0x00, 0xC0,       # JMP $C000     (into the copy -> AUTO)
    ])
    payload = bytes(range(1, 9))            # $01..$08
    assert LOAD_ADDR + len(code) == 0x200E, "payload must sit exactly at $200E"
    return code + payload


def build_copydata():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x0C, 0x20,       # LDA $200C,X   (source)
        0x9D, 0x00, 0xC1,       # STA $C100,X   (destination)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2002
        0x60,                   # RTS           (no jump into range -> CANDIDATE)
    ])
    payload = bytes(range(0x11, 0x19))      # $11..$18
    assert LOAD_ADDR + len(code) == 0x200C, "payload must sit exactly at $200C"
    return code + payload


def write_prg(outdir, name, body):
    header = bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8])
    path = os.path.join(outdir, name)
    with open(path, "wb") as f:
        f.write(header + body)
    print("wrote %s (%d bytes); load $%04X" % (path, len(header) + len(body), LOAD_ADDR))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkcopytest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    write_prg(outdir, "copyloop.prg", build_copyloop())
    write_prg(outdir, "copydata.prg", build_copydata())


if __name__ == "__main__":
    main()
