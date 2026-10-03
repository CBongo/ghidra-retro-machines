#!/usr/bin/env python3
"""Synthesize the descriptor-tier fixtures (beads grm-hb6.15, grm-hb6.16).

One tiny MMC1 image (iNES mapper 1, 2 x 16 KiB PRG, no CHR), copied under three names so each
fixture is its own headless import:

  descoverlaytest.nes      imported WITH the planted overlay descriptor -> the overlay must win
  descoverlayctltest.nes   byte-identical, imported with NOTHING planted -> negative control
                           (and leak check: proves the overlay did not outlive its fixture)
  descannotationtest.nes   byte-identical, imported normally; AssertDescriptorReanalysis.java
                           then mutates labels and re-runs DescriptorAnnotationAnalyzer one-shot

Also writes, for run-banktest.sh to plant under <settings dir>/retro-machines/games/:

  descoverlaytest.yaml     a valid overlay keyed on this image's identity, hinting
                           banking.initial_state { prg_mode: 0 } (MMC1 32 KiB mode). With no
                           hint the board's home layout is mode 3 (W8000 8000-bfff + WC000),
                           so the hint is visible in the block map.
  descoverlaybad.yaml      deliberately malformed (no identity); must be skipped with a
                           logged error and cost only itself.

PRG layout (last bank fixed at $C000):
  $C000  4C 00 C0   JMP $C000   (RESET: idle loop)
  $C003  40         RTI         (NMI / IRQ)
"""
import hashlib
import os
import sys

PRG_SIZE = 0x8000
HEADER = 16


def make_rom():
    prg = bytearray(PRG_SIZE)
    prg[0x4000:0x4003] = bytes([0x4C, 0x00, 0xC0])
    prg[0x4003] = 0x40
    for vec, target in ((0x7FFA, 0xC003), (0x7FFC, 0xC000), (0x7FFE, 0xC003)):
        prg[vec] = target & 0xFF
        prg[vec + 1] = target >> 8
    header = bytearray(16)
    header[0:4] = b"NES\x1a"
    header[4] = PRG_SIZE // 0x4000
    header[5] = 0
    header[6] = 0x10          # mapper 1 (low nibble in flags 6 bits 4-7)
    return bytes(header) + bytes(prg), bytes(prg)


OVERLAY = """\
# Planted by run-banktest.sh for the descoverlaytest fixture (bead grm-hb6.15). Synthetic.
schema: 2

game:
  id: descoverlaytest
  title: "Overlay descriptor fixture (synthetic)"
  board: nes_mmc1
  identity:
    prg_sha256: "{prg}"
    file_sha256: "{file}"
  provenance: "synthetic: tools/banktest/mkdescoverlaytest.py"

banking:
  initial_state: {{ prg_mode: 0 }}
"""

BAD_OVERLAY = """\
# Deliberately malformed overlay (no game.identity): must be skipped, loudly, without
# affecting the valid overlay next to it (design section 5.4).
schema: 2

game:
  id: descoverlaybad
  title: "Malformed overlay (synthetic)"
  board: nes_mmc1
  provenance: "synthetic"
"""


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkdescoverlaytest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    rom, prg = make_rom()
    assert len(rom) == HEADER + PRG_SIZE
    assert prg[0x7FFC] | (prg[0x7FFD] << 8) == 0xC000
    for name in ("descoverlaytest", "descoverlayctltest", "descannotationtest"):
        with open(os.path.join(outdir, name + ".nes"), "wb") as f:
            f.write(rom)
    prg_sha = hashlib.sha256(prg).hexdigest()
    file_sha = hashlib.sha256(rom).hexdigest()
    with open(os.path.join(outdir, "descoverlaytest.yaml"), "w", newline="\n") as f:
        f.write(OVERLAY.format(prg=prg_sha, file=file_sha))
    with open(os.path.join(outdir, "descoverlaybad.yaml"), "w", newline="\n") as f:
        f.write(BAD_OVERLAY)
    print("wrote descriptor fixtures to %s (prg %s)" % (outdir, prg_sha))


if __name__ == "__main__":
    main()
