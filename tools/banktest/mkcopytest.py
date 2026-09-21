#!/usr/bin/env python3
"""Hand-assembles the CopyLoopAnalyzer regression PRGs (bead grm-1.7.1, extended by grm-chu,
grm-bqs and grm-9a0).

Usage: mkcopytest.py <output-dir>

Writes eight PRGs that exercise the run-from-elsewhere recognizer's EVIDENCE GATE (does a
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

copybankedinplace.prg is the SAME-BASE cross-occupant copy (grm-cpj): the canonical C64 boot
idiom LDA $A000,X / STA $A000,X, which READS the BASIC ROM (the LOROM window's home occupant
in the default bank state, LORAM=1) and WRITES the RAM underneath it (RAM_A000 -- a write can
never land in ROM, so the window's on_write routes it there). Before grm-cpj
CopyLoopAnalyzer.tryRecognize rejected any loop whose load and store shared a base address
as an in-place transform, so this copy was silently discarded; now the same-base case is
admitted iff the two sides resolve to DIFFERENT occupants, which BoardBankAnalyzer's re-homed
references decide. The source and destination are DELIBERATELY the same base address, so the
only thing that distinguishes this from an in-place decrypt is occupancy:

  $2000  A2 07        LDX #$07
  $2002  BD 00 A0     LDA $A000,X       ; SOURCE: BASIC ROM, the home occupant (loop top)
  $2005  9D 00 A0     STA $A000,X       ; DESTINATION: RAM_A000, under the ROM (same base!)
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  4C 00 A0     JMP $A000         ; JUMP INTO the copy -> AUTO (code)

Run TWICE by the harness, as copybankedinplace (no ROM) and copybankedinplacerom
(-loader-basicRom), and like copybankedsrc the two runs must DIFFER: with no dump the BASIC
occupant is uninitialized and TransferMaterializer's gate 0 refuses; with the dump the copy is
carved inside the RAM_A000 overlay carrying the BASIC ROM's own bytes, which mkromtest.py
generates as byte[i] = (i & 0xFF) ^ 0x55, i.e. 55 54 57 56 51 50 53 52 at RAM_A000::a000.
Before grm-cpj neither run recognized the loop at all. The in-place decrypt fixtures
(mkdecrypttest.py) are the counter-witness: they must NOT start being claimed as copies.

copyfar.prg and copychain.prg pin the PROGRAM-WIDE half of the evidence gate (grm-k5m). The
original gate looked only a few instructions past the loop for the JMP into the destination,
which is the CHRGET shape; the shape real cartridges actually use is a boot routine that
copies several stubs into RAM and RETURNS, after which the game calls them at their RAM
addresses from arbitrarily far away (Wizards & Warriors copies three AxROM bank-switch
routines to $0300/$032d/$033d and calls them from four different banks). Those calls are the
same evidence, found through the reference manager instead of by lookahead.

copyfar.prg -- the caller precedes the loop and is disassembled BEFORE the loop is judged, so
the reference already exists when the recognizer first looks (the simple case):

  $2000  20 07 20     JSR $2007         ; run the copy routine
  $2003  20 00 C0     JSR $C000         ; then CALL the copy -- far from the loop, before it
  $2006  60           RTS
  $2007  A2 07        LDX #$07
  $2009  BD 15 20     LDA $2015,X       ; source                (loop top)
  $200C  9D 00 C0     STA $C000,X       ; destination (DIFFERENT base)
  $200F  CA           DEX
  $2010  10 F7        BPL $2009
  $2012  60           RTS               ; no jump NEAR the loop; the lookahead finds nothing
  $2013  EA EA        NOP NOP           ; padding so the payload is not within the lookahead
                                        ; either way (it is data; the walk stops at the RTS)
  $2015  A9 42 60 EA EA EA EA EA        ; payload: LDA #$42 / RTS / NOPs -- real code at $C000

copychain.prg -- the evidence arrives LATER, in a later analysis round: loop B (into $C100) is
declined on first sight because nothing yet flows into $C100; loop A (into $C000) is proven by
the usual adjacent JMP and materialized; A's copied code is a JSR $C102, which is only
disassembled once A is materialized -- and THAT reference is what re-admits B on the
analyzer's next round. Address order puts B first so it is judged (and declined) before A.
B's payload deliberately starts with two zero bytes (a two-byte table ahead of the routine),
so the third evidence leg -- "the payload decodes as a subroutine from its first byte" -- FAILS
on it and only the late call can admit it; the call lands mid-range, at $C102, which is also
where the materializer must then disassemble from (entryPoint), leaving $C100-$C101 as data:

  $2000  A2 07        LDX #$07
  $2002  BD 21 20     LDA $2021,X       ; srcB                  (loop B top)
  $2005  9D 00 C1     STA $C100,X       ; -> $C100, nothing flows there YET
  $2008  CA           DEX
  $2009  10 F7        BPL $2002
  $200B  A2 07        LDX #$07          ; falls straight into loop A (no RTS between)
  $200D  BD 19 20     LDA $2019,X       ; srcA                  (loop A top)
  $2010  9D 00 C0     STA $C000,X       ; -> $C000
  $2013  CA           DEX
  $2014  10 F7        BPL $200D
  $2016  4C 00 C0     JMP $C000         ; adjacent jump proves A; NOT in B's range, so B's own
                                        ; lookahead (LDX/LDA/STA/DEX/BPL/JMP) finds nothing
  $2019  20 02 C1 60 EA EA EA EA        ; srcA: JSR $C102 / RTS / NOPs -- the late evidence
  $2021  00 00 A9 42 60 EA EA EA        ; srcB: two table bytes, then LDA #$42 / RTS / NOPs
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


def build_copybankedinplace():
    code = bytes([
        0xA2, 0x07,             # LDX #$07
        0xBD, 0x00, 0xA0,       # LDA $A000,X   (SOURCE -- the BASIC ROM, home occupant)
        0x9D, 0x00, 0xA0,       # STA $A000,X   (DESTINATION -- RAM_A000 under it, SAME base)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2002
        0x4C, 0x00, 0xA0,       # JMP $A000     (into the copy -> AUTO)
    ])
    assert code[3:5] == code[6:8] == bytes([0x00, 0xA0]), "load and store must share a base"
    assert (0x2002 - (LOAD_ADDR + 11)) & 0xFF == 0xF7, "BPL displacement must reach the LDA"
    assert LOAD_ADDR + len(code) == 0x200E, "code must end at $200E (no payload follows)"
    return code


def build_copyfar():
    code = bytes([
        0x20, 0x07, 0x20,       # JSR $2007     (the copy routine)
        0x20, 0x00, 0xC0,       # JSR $C000     (CALL the copy -- far from the loop, before it)
        0x60,                   # RTS
        0xA2, 0x07,             # LDX #$07                                      ($2007)
        0xBD, 0x15, 0x20,       # LDA $2015,X   (source)                        ($2009)
        0x9D, 0x00, 0xC0,       # STA $C000,X   (destination)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2009
        0x60,                   # RTS           (no jump near the loop)
        0xEA, 0xEA,             # NOP NOP       (padding)
    ])
    payload = bytes([0xA9, 0x42, 0x60, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA])  # LDA #$42 / RTS / NOPs
    assert LOAD_ADDR + 7 == 0x2007, "loop routine must sit at $2007"
    assert (0x2009 - (LOAD_ADDR + 0x12)) & 0xFF == 0xF7, "BPL displacement must reach the LDA"
    assert LOAD_ADDR + len(code) == 0x2015, "payload must sit exactly at $2015"
    return code + payload


def build_copychain():
    code = bytes([
        0xA2, 0x07,             # LDX #$07                                      ($2000)
        0xBD, 0x21, 0x20,       # LDA $2021,X   (srcB)                          ($2002)
        0x9D, 0x00, 0xC1,       # STA $C100,X   (-> $C100; nothing flows there yet)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $2002
        0xA2, 0x07,             # LDX #$07                                      ($200B)
        0xBD, 0x19, 0x20,       # LDA $2019,X   (srcA)                          ($200D)
        0x9D, 0x00, 0xC0,       # STA $C000,X   (-> $C000)
        0xCA,                   # DEX
        0x10, 0xF7,             # BPL $200D
        0x4C, 0x00, 0xC0,       # JMP $C000     (adjacent jump proves A)        ($2016)
    ])
    src_a = bytes([0x20, 0x02, 0xC1, 0x60, 0xEA, 0xEA, 0xEA, 0xEA])  # JSR $C102 / RTS / NOPs
    src_b = bytes([0x00, 0x00, 0xA9, 0x42, 0x60, 0xEA, 0xEA, 0xEA])  # 2 table bytes, LDA #$42 / RTS
    assert (0x2002 - (LOAD_ADDR + 0x0B)) & 0xFF == 0xF7, "loop B's BPL must reach its LDA"
    assert (0x200D - (LOAD_ADDR + 0x16)) & 0xFF == 0xF7, "loop A's BPL must reach its LDA"
    assert LOAD_ADDR + len(code) == 0x2019, "srcA must sit exactly at $2019"
    assert LOAD_ADDR + len(code) + len(src_a) == 0x2021, "srcB must sit exactly at $2021"
    return code + src_a + src_b


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
    write_prg(outdir, "copybankedinplace.prg", build_copybankedinplace())
    write_prg(outdir, "copyfar.prg", build_copyfar())
    write_prg(outdir, "copychain.prg", build_copychain())


if __name__ == "__main__":
    main()
