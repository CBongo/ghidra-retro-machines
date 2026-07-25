#!/usr/bin/env python3
"""Hand-assembles the C64CopyLoopAnalyzer regression PRGs (bead grm-1.7.1, extended by grm-chu).

Usage: mkcopytest.py <output-dir>

Writes three PRGs that exercise the run-from-elsewhere recognizer's materialize/disassemble
split AND the grm-chu placement policy (carve the destination in place vs. fall back to a
byte-mapped overlay):

  copyloop.prg    -- a verbatim indexed copy loop into the free, uninitialized RAM_C000
                      block, ENDING WITH A JUMP into the destination, proving the copied
                      bytes run as code. The destination is wholly carvable, so the
                      materializer carves it IN PLACE (COPY_c000, C000-C007) and
                      disassembles it -- a base-space JSR/JMP into $C000 now resolves
                      directly, no bridging.

  copydata.prg    -- the SAME shape but with NO jump into the destination (it just
                      RTSes). Insufficient evidence the bytes are code, so the destination
                      is still carved in place (COPY_c100, interior of RAM_C000) but left
                      as DATA -- not disassembled.

  copyoverlay.prg -- the destination lands INSIDE the loaded PRG image itself (already
                      initialized real file bytes), so the grm-chu in-place precondition
                      ("destination block is uninitialized") fails and the materializer
                      falls back to the pre-grm-chu representation: a dual-home
                      byte-mapped overlay (COPY_200e) mapped 1:1 back to the source. A
                      JMP into the destination immediately follows the loop, same as
                      copyloop.prg -- this is the only regression coverage
                      TransferMaterializer.bridgeJump has ever had, since bridging is
                      needed only when the copy could NOT be carved in place.

Load address is $2000 (inside RAM_MAIN) so the loader carves each PRG into the base
address space; the loader marks $2000 as a function, so auto-analysis disassembles the
loop for the INSTRUCTION_ANALYZER to see. Every source payload lives inside the loaded
PRG, so it is initialized (real bytes) with no ROM dependency.

copyloop.prg ($01..$08 payload copied to $C000, RAM_C000 wholly uninitialized -> carved
in place at the block's own start):

  $2000  A2 07        LDX #$07          ; index 7..0 -> 8 bytes
  $2002  BD 0E 20     LDA $200E,X       ; load source byte      (loop top)
  $2005  9D 00 C0     STA $C000,X       ; store to destination (DIFFERENT base)
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  4C 00 C0     JMP $C000         ; JUMP INTO the copy -> AUTO (code)
  $200E  01..08       source payload

copydata.prg ($11..$18 payload copied to $C100, interior of RAM_C000 -> carved in place
with a leftover fragment on each side):

  $2000  A2 07        LDX #$07
  $2002  BD 0C 20     LDA $200C,X       ; source                (loop top)
  $2005  9D 00 C1     STA $C100,X       ; destination (DIFFERENT base)
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  60           RTS               ; no jump into range -> CANDIDATE (data)
  $200C  11..18       source payload

copyoverlay.prg ($91..$98 payload copied to $200E, which sits inside this very PRG's own
already-initialized image -> the in-place precondition fails, so it falls back to a
COPY_200e byte-mapped overlay onto $2016):

  $2000  A2 07        LDX #$07
  $2002  BD 16 20     LDA $2016,X       ; load source byte      (loop top)
  $2005  9D 0E 20     STA $200E,X       ; store to destination (DIFFERENT base, but
                                        ; still inside THIS PRG's own initialized image)
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  4C 0E 20     JMP $200E         ; JUMP INTO the copy -> AUTO (code)
  $200E  EE*8         destination placeholder bytes (pre-copy; distinguishable from the
                       source payload so a COPIED check that read the wrong side would
                       be caught)
  $2016  91..98       source payload
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


def build_copyoverlay():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x16, 0x20,       # LDA $2016,X   (source)
        0x9D, 0x0E, 0x20,       # STA $200E,X   (destination -- inside this PRG's image)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2002
        0x4C, 0x0E, 0x20,       # JMP $200E     (into the copy -> AUTO)
    ])
    dest_placeholder = bytes([0xEE] * 8)    # pre-copy filler, distinguishable from source
    payload = bytes(range(0x91, 0x99))      # $91..$98
    assert LOAD_ADDR + len(code) == 0x200E, "destination placeholder must sit at $200E"
    assert LOAD_ADDR + len(code) + len(dest_placeholder) == 0x2016, \
        "payload must sit exactly at $2016"
    return code + dest_placeholder + payload


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
    write_prg(outdir, "copyoverlay.prg", build_copyoverlay())


if __name__ == "__main__":
    main()
