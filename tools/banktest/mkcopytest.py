#!/usr/bin/env python3
"""Hand-assembles the CopyLoopAnalyzer regression PRGs (bead grm-1.7.1, extended by grm-chu,
grm-bqs and grm-9a0).

Usage: mkcopytest.py <output-dir>

Writes five PRGs that exercise the run-from-elsewhere recognizer's EVIDENCE GATE (does a
jump into the destination prove the payload is code?) AND the grm-chu placement policy
(carve the destination in place vs. fall back to a byte-mapped overlay):

  copyloop.prg    -- a verbatim indexed copy loop into the free, uninitialized RAM_C000
                      block, ENDING WITH A JUMP into the destination, proving the copied
                      bytes run as code. The destination is wholly carvable, so the
                      materializer carves it IN PLACE (COPY_c000, C000-C007) and
                      disassembles it -- a base-space JSR/JMP into $C000 now resolves
                      directly, no bridging.

  copydata.prg    -- the SAME shape but with NO jump into the destination (it just
                      RTSes). No evidence the bytes are code, so NOTHING is materialized:
                      the loop gets a NOTE bookmark explaining the refusal and RAM_C000 is
                      left whole and uninitialized. (Until grm-1.7.6 this case carved
                      COPY_c100 anyway and merely withheld disassembly; real NES cartridges
                      showed that snapshots ordinary runtime buffers -- this idiom is how
                      6502 moves DATA, not just code. A copy whose payload really is code
                      but has no nearby jump, like CHRGET, is now the descriptor
                      copied_from directive's job, or the manual script's.)

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

copybanked.prg ($A1..$A8 payload copied to $E000 -- UNDER the KERNAL window, which is the
real idiom this models: games run code from the RAM the KERNAL ROM normally covers). The
base-space block at $E000 is the HIROM window's home occupant, KERNAL, so before grm-bqs
the carve fired on it and shredded a ROM image into KERNAL / COPY_e000 / KERNAL_E008. The
write actually lands in the RAM_E000 occupant, and BoardBankAnalyzer has already re-homed
this store's write reference there, so the copy is carved inside the RAM_E000 overlay and
KERNAL is left whole:

  $2000  A2 07        LDX #$07
  $2002  BD 0E 20     LDA $200E,X       ; load source byte      (loop top)
  $2005  9D 00 E0     STA $E000,X       ; store UNDER the KERNAL ROM
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  4C 00 E0     JMP $E000         ; JUMP INTO the copy -> AUTO (code)
  $200E  A1..A8       source payload

Run TWICE by the harness, as copybanked (no ROM) and copybankedrom (-loader-kernalRom),
because the placement must come out identical either way: which occupant a write reaches is
a hardware fact, not a fallback for an uninitialized ROM block. Before grm-bqs the two runs
disagreed -- with a dump supplied KERNAL was initialized, so the carve was refused and the
bug hid.

copybankedsrc.prg is the mirror image of copybanked.prg: it isolates the SOURCE half of
banked-window resolution (grm-9a0), which copybanked.prg cannot see because its source is an
ordinary base-space payload inside the PRG. Here the source is the C64 CHARACTER ROM -- a
NON-HOME occupant of the CHARIO window ($D000-$DFFF, whose home occupant is IO, because the
descriptor's initial_state has CHAREN=1) -- and the destination is deliberately an ORDINARY
base-space RAM destination ($C000, outside every window), so the only banked thing in the
fixture is the read. Copying the character ROM down into RAM is the canonical real-world C64
idiom for this shape.

The fixture DELIBERATELY PINS the bank state first, because in the default state every C64
window's live occupant IS its home occupant and there would be nothing to resolve:

  $2000  A9 33        LDA #$33          ; LORAM=1, HIRAM=1, CHAREN=0
  $2002  85 01        STA $01           ; mechanism write: banks CHARGEN in over $D000
  $2004  A2 07        LDX #$07          ; index 7..0 -> 8 bytes
  $2006  BD 00 D0     LDA $D000,X       ; SOURCE: reads CHARGEN, a NON-HOME occupant (loop top)
  $2009  9D 00 C0     STA $C000,X       ; destination: free uninitialized RAM_C000, base space
  $200C  CA           DEX
  $200D  10 F7        BPL $2006
  $200F  4C 00 C0     JMP $C000         ; JUMP INTO the copy -> AUTO (code)

Run TWICE by the harness, as copybankedsrc (no ROM) and copybankedsrcrom
(-loader-chargenRom), and here the two runs must DIFFER -- that split is the point of the
fixture. Without a dump the CHARGEN occupant is uninitialized, so TransferMaterializer's
gate 0 ("an unreadable source materializes nothing") must refuse and place nothing; with the
dump supplied the copy materializes carrying the character ROM's own bytes, which
mkromtest.py generates as byte[i] = (i & 0xFF) ^ 0xAA, i.e. AA AB A8 A9 AE AF AC AD at $C000.
Before grm-9a0 the recognizer named the base-space $D000 -- the IO home occupant -- in BOTH
runs, so supplying the character ROM changed nothing at all and its bytes were never reached.
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


def build_copybanked():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x0E, 0x20,       # LDA $200E,X   (source)
        0x9D, 0x00, 0xE0,       # STA $E000,X   (destination -- UNDER the KERNAL window)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2002
        0x4C, 0x00, 0xE0,       # JMP $E000     (into the copy -> AUTO)
    ])
    payload = bytes(range(0xA1, 0xA9))      # $A1..$A8, distinct from copyloop's $01..$08
    assert LOAD_ADDR + len(code) == 0x200E, "payload must sit exactly at $200E"
    return code + payload


def build_copybankedsrc():
    code = bytes([
        0xA9, 0x33,             # LDA #$33      (LORAM=1, HIRAM=1, CHAREN=0)
        0x85, 0x01,             # STA $01       (bank CHARGEN in over $D000)
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x00, 0xD0,       # LDA $D000,X   (SOURCE -- the CHARGEN occupant, not IO)
        0x9D, 0x00, 0xC0,       # STA $C000,X   (destination -- ordinary base-space RAM)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2006
        0x4C, 0x00, 0xC0,       # JMP $C000     (into the copy -> AUTO)
    ])
    # The loop top is the LDA, and BPL is a signed 8-bit displacement from the byte AFTER
    # its operand: $2006 - $200F = -9 = $F7.
    assert LOAD_ADDR + 6 == 0x2006, "loop top (the LDA) must sit at $2006"
    assert (0x2006 - (LOAD_ADDR + 15)) & 0xFF == 0xF7, "BPL displacement must reach the LDA"
    assert LOAD_ADDR + len(code) == 0x2012, "code must end at $2012 (no payload follows)"
    return code


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
    write_prg(outdir, "copybanked.prg", build_copybanked())
    write_prg(outdir, "copybankedsrc.prg", build_copybankedsrc())


if __name__ == "__main__":
    main()
