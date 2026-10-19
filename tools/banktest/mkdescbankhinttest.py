#!/usr/bin/env python3
"""Synthesize the switch_sites bank: VALUE hint fixtures (beads grm-hb6.23, grm-hb6.22).

Two images, each imported with an overlay game descriptor planted by run-banktest.sh under
<settings dir>/retro-machines/games/, so the hints reach BoardBankAnalyzer end to end
(GameCompiler -> NesRomLoader -> Retro Machines.Switch Sites -> BankDataflowEngine ->
BankAnnotationAdapter / SwitchSiteHints.reportValueHints):

  descbankhinttest.nes      UxROM (mapper 2), 8 x 16 KiB PRG, single-field latch
  descbankhinttest.yaml       three hinted stores, see the listing below
  descbankhintmmc3test.nes  MMC3 (mapper 4), 8 x 8 KiB PRG, the multi-field mechanism
  descbankhintmmc3test.yaml   one hinted $8001 data write after a select of 6 (grm-hb6.22)

UxROM listing (fixed bank 7 at $C000):
  $C000  A5 10      LDA $10      bank from RAM: dataflow recovers nothing
  $C002  8D F0 FF   STA $FFF0    H1: hint bank 2 -> applied, comment suffix, no warning
  $C005  20 00 80   JSR $8000    -> PRG_LO_B2::8000
  $C008  A9 01      LDA #1
  $C00A  8D F0 FF   STA $FFF0    H2: hint bank 5, dataflow says 1 -> hint WINS and warns
  $C00D  20 00 80   JSR $8000    -> PRG_LO_B5::8000 (not B1)
  $C010  A9 03      LDA #3
  $C012  8D F0 FF   STA $FFF0    H3: hint bank 9 of 8 -> NOT applied, warns; dataflow's 3 stays
  $C015  4C 15 C0   JMP $C015
  $C018  40         RTI          (NMI / IRQ)
$FFF0 holds $FF so the latch's bus-conflict AND launders nothing. Every switchable bank starts
with RTS at $8000 (and carries its bank number at $8001, so the images differ per bank).

MMC3 listing (fixed last bank at $E000, PRG mode 0 so $8000 is R6):
  $E000  A9 06      LDA #6
  $E002  8D 00 80   STA $8000    select R6
  $E005  A5 10      LDA $10      bank from RAM
  $E007  8D 01 80   STA $8001    M1: hint bank 5 -> applied to R6 alone (grm-hb6.22)
  $E00A  20 00 80   JSR $8000    -> R6's bank-5 overlay
  $E00D  4C 0D E0   JMP $E00D
  $E010  40         RTI
"""
import hashlib
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402

UX_BANK = 0x4000
UX_BANKS = 8
MMC3_BANK = 0x2000
MMC3_BANKS = 8

UX_CODE = bytes([
    0xA5, 0x10, 0x8D, 0xF0, 0xFF, 0x20, 0x00, 0x80,   # c000
    0xA9, 0x01, 0x8D, 0xF0, 0xFF, 0x20, 0x00, 0x80,   # c008
    0xA9, 0x03, 0x8D, 0xF0, 0xFF, 0x4C, 0x15, 0xC0,   # c010
    0x40,                                             # c018
])

MMC3_CODE = bytes([
    0xA9, 0x06, 0x8D, 0x00, 0x80, 0xA5, 0x10, 0x8D, 0x01, 0x80,   # e000
    0x20, 0x00, 0x80, 0x4C, 0x0D, 0xE0,                           # e00a
    0x40,                                                         # e010
])


def _vectors(prg, reset, irq):
    for vec, target in ((len(prg) - 6, irq), (len(prg) - 4, reset), (len(prg) - 2, irq)):
        prg[vec] = target & 0xFF
        prg[vec + 1] = target >> 8


def make_uxrom():
    prg = bytearray(UX_BANK * UX_BANKS)
    for bank in range(UX_BANKS - 1):
        prg[bank * UX_BANK] = 0x60          # RTS at $8000
        prg[bank * UX_BANK + 1] = bank
    fixed = (UX_BANKS - 1) * UX_BANK
    prg[fixed:fixed + len(UX_CODE)] = UX_CODE
    prg[fixed + 0x3FF0] = 0xFF              # the latch target: no bus-conflict masking
    _vectors(prg, 0xC000, 0xC018)
    return bankgen.ines_header(len(prg) // 0x4000, 0, 2) + bytes(prg), bytes(prg)


def make_mmc3():
    prg = bytearray(MMC3_BANK * MMC3_BANKS)
    for bank in range(MMC3_BANKS - 1):
        prg[bank * MMC3_BANK] = 0x60
        prg[bank * MMC3_BANK + 1] = bank
    fixed = (MMC3_BANKS - 1) * MMC3_BANK
    prg[fixed:fixed + len(MMC3_CODE)] = MMC3_CODE
    _vectors(prg, 0xE000, 0xE010)
    return bankgen.ines_header(len(prg) // 0x4000, 0, 4) + bytes(prg), bytes(prg)


HEAD = """\
# Planted by run-banktest.sh for the {id} fixture (beads grm-hb6.23, grm-hb6.22). Synthetic.
schema: 2

game:
  id: {id}
  title: "switch_sites bank: value hint fixture (synthetic)"
  board: {board}
  identity:
    prg_sha256: "{prg}"
    file_sha256: "{file}"
  provenance: "synthetic: tools/banktest/mkdescbankhinttest.py"

banking:
  switch_sites:
"""

UX_SITES = """\
    - addr: 0xC002
      bank: 2
      provenance: "synthetic H1: RAM-fed store, hint fills it"
    - addr: 0xC00A
      bank: 5
      provenance: "synthetic H2: contradicts the recovered 1, must win and warn"
    - addr: 0xC012
      bank: 9
      provenance: "synthetic H3: bank 9 of 8, must not apply"
"""

MMC3_SITES = """\
    - addr: 0xE007
      bank: 5
      provenance: "synthetic M1: R6 data write after select 6"
"""


def _write(outdir, name, board, rom, prg, sites):
    bankgen.write_bytes(outdir, name + ".nes", rom)
    with open(os.path.join(outdir, name + ".yaml"), "w", newline="\n") as f:
        f.write(HEAD.format(id=name, board=board, prg=hashlib.sha256(prg).hexdigest(),
                            file=hashlib.sha256(rom).hexdigest()) + sites)


def main():
    outdir = bankgen.outdir_arg(__file__)
    ux, ux_prg = make_uxrom()
    mmc3, mmc3_prg = make_mmc3()

    # Self-check: the bytes the verifier's criteria name (bead fixture-dispatch-two-sided).
    fixed = (UX_BANKS - 1) * UX_BANK
    assert ux_prg[fixed + 0x02:fixed + 0x05] == bytes([0x8D, 0xF0, 0xFF])
    assert ux_prg[fixed + 0x0A:fixed + 0x0D] == bytes([0x8D, 0xF0, 0xFF])
    assert ux_prg[fixed + 0x12:fixed + 0x15] == bytes([0x8D, 0xF0, 0xFF])
    assert ux_prg[fixed + 0x08:fixed + 0x0A] == bytes([0xA9, 0x01])
    assert ux_prg[fixed + 0x3FF0] == 0xFF
    assert ux_prg[-4] | (ux_prg[-3] << 8) == 0xC000
    assert all(ux_prg[b * UX_BANK] == 0x60 for b in (2, 5))
    mfixed = (MMC3_BANKS - 1) * MMC3_BANK
    assert mmc3_prg[mfixed + 0x07:mfixed + 0x0A] == bytes([0x8D, 0x01, 0x80])
    assert mmc3_prg[mfixed + 0x00:mfixed + 0x02] == bytes([0xA9, 0x06])
    assert mmc3_prg[-4] | (mmc3_prg[-3] << 8) == 0xE000
    assert mmc3_prg[5 * MMC3_BANK] == 0x60

    _write(outdir, "descbankhinttest", "nes_uxrom", ux, ux_prg, UX_SITES)
    _write(outdir, "descbankhintmmc3test", "nes_mmc3", mmc3, mmc3_prg, MMC3_SITES)
    print("wrote bank-hint fixtures to %s" % outdir)


if __name__ == "__main__":
    main()
