#!/usr/bin/env python3
"""Generate the deterministic SPC700 .spc snapshot loader fixtures (bead grm-c9d.4).

Four tiny synthetic snapshots (no real music data, no Sony IPL bytes):

  spcsnaptest.spc      IPL disabled (CONTROL bit 7 clear). Header PC $0410 -- deliberately the
                       middle of the driver, as a real snapshot's PC is -- while the driver's
                       real entry is $0400. RAM holds a ten-instruction program at $0400, a
                       callee at $0420, and an idle loop at $0410. The "extra RAM" area differs
                       from the RAM image at $FFC0, so the loader must keep both.
  spcsnapentry.spc     The same bytes under another name; run with -loader-entry 0400 to
                       exercise the entry override.
  spcsnapipl.spc       CONTROL bit 7 set (IPL mapped in) but the file does NOT carry the stock
                       IPL at $FFC0, so the loader must make an uninitialized IPL_ROM block
                       (the project redistributes no IPL) and keep the file's bytes in an overlay.

  spcsnapstack.spc     Stack-chain recovery (grm-c9d.9). The header PC ($FF21) is a bare RET inside
                       routine C ($FF20), like FF2 Town/Battle. The stack page holds the live chain:
                       main loop $0403 CALL !$0440 -> A; A $0442 TCALL 3 (table word $0460) -> B;
                       B $0461 PCALL $20 (= $FF20) -> C; plus a DECOY return address $0415 above the
                       outermost frame whose preceding bytes are a CALL to $9000 (a target that
                       cannot contain the main loop), which the walk must refuse. Run once as-is
                       (3 frames) and once with -loader-stack false (0 frames, the "before").

The DSP block carries recognisable values in registers whose names the loader must get right
(V0VOLL, V0PITCH, V3SRCN, MVOLL, KON, FLG, DIR, ESA, EDL, COEF7), and the I/O page carries
distinct values in $F0-$FF so the timer target/output registers are distinguishable.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402

ENTRY = 0x0400
HEADER_PC = 0x0410
CALLEE = 0x0420


def text(s, n):
    return s.encode("ascii").ljust(n, b"\x00")


def program():
    """The driver at $0400: set the stack, program two DSP registers through DSPADDR/DSPDATA,
    clear CONTROL, call a routine that reads timer 2's output, then idle."""
    return bytes([
        0xCD, 0xEF,                  # $0400 MOV X,#$EF
        0xBD,                        # $0402 MOV SP,X
        0x8F, 0x6C, 0xF2,            # $0403 MOV $F2,#$6C   ; DSPADDR = FLG
        0x8F, 0x20, 0xF3,            # $0406 MOV $F3,#$20   ; DSPDATA
        0xE8, 0x00,                  # $0409 MOV A,#$00
        0xC4, 0xF1,                  # $040B MOV $F1,A      ; CONTROL
        0x3F, CALLEE & 0xFF, CALLEE >> 8,   # $040D CALL !$0420
        # $0410 idle loop (the header PC)
        0x2F, 0xFE,                  # $0410 BRA $0410
    ])


def callee():
    return bytes([
        0xE4, 0xFF,                  # $0420 MOV A,$FF      ; T2OUT, timer 2's counter
        0xC4, 0x10,                  # $0422 MOV $10,A
        0x6F,                        # $0424 RET
    ])


def stack_driver(ram):
    """Plant the call chain of spcsnapstack and return (pc, sp)."""
    def put(at, *b):
        ram[at:at + len(b)] = bytes(b)

    put(0x0400, 0xCD, 0xCF, 0xBD)            # MOV X,#$CF ; MOV SP,X
    put(0x0403, 0x3F, 0x40, 0x04)            # CALL !$0440   (ret $0406)
    put(0x0406, 0x2F, 0xFB)                  # BRA $0403     (the main loop)
    put(0x0440, 0xE8, 0x01)                  # A: MOV A,#1
    put(0x0442, 0x31)                        #    TCALL 3    (ret $0443)
    put(0x0443, 0x6F)                        #    RET
    put(0x0460, 0x00)                        # B: NOP
    put(0x0461, 0x4F, 0x20)                  #    PCALL $20  (-> $FF20, ret $0463)
    put(0x0463, 0x6F)                        #    RET
    put(0xFF20, 0x00, 0x6F)                  # C: NOP ; RET   (the header PC is the RET)
    put(0xFFD8, 0x60, 0x04)                  # TCALL 3 table entry -> $0460
    put(0x0412, 0x3F, 0x00, 0x90)            # decoy: CALL !$9000 (ret $0415)
    sp = 0xCF
    for ret in (0x0415, 0x0406, 0x0443, 0x0463):   # decoy outermost, then main, A, B
        ram[0x100 + sp] = ret >> 8
        ram[0x100 + sp - 1] = ret & 0xFF
        sp -= 2
    return 0xFF21, sp


def snapshot(control, stack=False):
    ram = bytearray(0x10000)
    if not stack:
        ram[ENTRY:ENTRY + len(program())] = program()
        ram[CALLEE:CALLEE + len(callee())] = callee()
    # The I/O page as captured: a distinct byte per register.
    for i in range(16):
        ram[0xF0 + i] = 0xA0 + i
    ram[0xF1] = control
    # A recognisable, non-IPL pattern at $FFC0-$FFFF.
    for i in range(0x40):
        ram[0xFFC0 + i] = (0x30 + i) & 0xFF
    extra = bytes((0xC0 - i) & 0xFF for i in range(0x40))

    pc, sp = HEADER_PC, 0xEF
    if stack:
        pc, sp = stack_driver(ram)

    dsp = bytearray(0x80)
    dsp[0x00] = 0x7F                 # V0VOLL
    dsp[0x02], dsp[0x03] = 0x00, 0x10   # V0PITCH = $1000
    dsp[0x34] = 0x05                 # V3SRCN
    dsp[0x0C] = 0x60                 # MVOLL
    dsp[0x4C] = 0x01                 # KON
    dsp[0x6C] = 0x20                 # FLG
    dsp[0x5D] = 0x10                 # DIR
    dsp[0x6D] = 0x40                 # ESA
    dsp[0x7F] = 0x7E                 # COEF7

    hdr = bytearray(0x100)
    hdr[0:33] = b"SNES-SPC700 Sound File Data v0.30"
    hdr[0x21:0x23] = b"\x1a\x1a"
    hdr[0x23] = 26                   # ID666 tag present
    hdr[0x24] = 30
    hdr[0x25:0x27] = bytes([pc & 0xFF, pc >> 8])
    hdr[0x27] = 0x12                 # A
    hdr[0x28] = 0x34                 # X
    hdr[0x29] = 0x56                 # Y
    hdr[0x2A] = 0x02                 # PSW
    hdr[0x2B] = sp                   # SP
    hdr[0x2E:0x4E] = text("Test Song", 32)
    hdr[0x4E:0x6E] = text("Test Game", 32)
    hdr[0x6E:0x7E] = text("grm", 16)
    hdr[0x7E:0x9E] = text("synthetic fixture", 32)
    hdr[0x9E:0xA9] = text("11/06/2026", 11)
    hdr[0xA9:0xAC] = b"123"
    hdr[0xAC:0xB1] = b"01000"
    hdr[0xB1:0xD1] = text("Nobody", 32)
    hdr[0xD1] = 0
    hdr[0xD2] = ord("0")
    data = bytes(hdr) + bytes(ram) + bytes(dsp) + bytes(0x40) + extra
    assert len(data) == 0x10200, hex(len(data))
    return data


def main():
    outdir = bankgen.outdir_arg(__file__)
    plain = snapshot(0x00)
    bankgen.write_bytes(outdir, "spcsnaptest.spc", plain)
    bankgen.write_bytes(outdir, "spcsnapentry.spc", plain)
    bankgen.write_bytes(outdir, "spcsnapipl.spc", snapshot(0x80))
    stack = snapshot(0x00, stack=True)
    bankgen.write_bytes(outdir, "spcsnapstack.spc", stack)
    bankgen.write_bytes(outdir, "spcsnapnostack.spc", stack)
    print("wrote SPC700 snapshot fixtures to " + outdir)


if __name__ == "__main__":
    main()
