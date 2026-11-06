#!/usr/bin/env python3
"""Synthesize the C64 game-descriptor fixtures (bead grm-hb6.30).

One tiny PRG, loaded at $C000, whose load address is NOT a useful entry (zeros -> BRK), with
real code only at $C010 and $C030 and a data table at $C020:

  $C000  00 x16         padding (BRK)
  $C010  A9 01 8D 20 D0 60     LDA #1 / STA $D020 / RTS        (hinted function)
  $C016  00 x10
  $C020  01 02 03 04            data table                      (hinted label)
  $C024  00 x12
  $C030  A2 00 E8 60            LDX #0 / INX / RTS              (member-level hinted function)

Written under three names so each is its own headless import:

  c64hintentrytest.prg     imported WITH the planted overlay -> the hints must apply
  c64hintentryctltest.prg  byte-identical, NOTHING planted    -> negative control (and leak check)
  c64hintd64test.d64       a .d64 holding the same bytes as member HINTD64, imported WITH the
                           overlay -> proves the identity (member content sha256) is container-free

and, for run-banktest.sh to plant under <settings dir>/retro-machines/games/:

  c64hintentrytest.yaml    game-level entries (C010 game_init, C020 hint_table label), a member
                           whose own entries override C010 (member_init) and add C030 (member_fn),
                           and a reserved forth: section carried through verbatim (grm-arbi.3).
"""
import hashlib
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402
import mkd64test  # noqa: E402

LOAD = 0xC000


def make_prg():
    body = bytearray(0x34)
    body[0x10:0x16] = bytes((0xA9, 0x01, 0x8D, 0x20, 0xD0, 0x60))
    body[0x20:0x24] = bytes((0x01, 0x02, 0x03, 0x04))
    body[0x30:0x34] = bytes((0xA2, 0x00, 0xE8, 0x60))
    return bankgen.prg(LOAD, body)


OVERLAY = """\
# Planted by run-banktest.sh for the c64hintentrytest fixtures (bead grm-hb6.30). Synthetic.
schema: 2

game:
  id: c64hintentrytest
  title: "C64 entry-hint fixture (synthetic)"
  platform: c64
  provenance: "synthetic: tools/banktest/mkc64descrtest.py"

entries:
  - {{ addr: 0xC010, name: game_init, comment: "game-level, overridden by the member" }}
  - {{ addr: 0xC020, name: hint_table, kind: label, comment: "data table" }}

forth:
  ip: 0x7E
  handlers:
    0x08F9: DOCON

members:
  - sha256: "{sha}"
    name: HINT.PRG
    entries:
      - {{ addr: 0xC010, name: member_init }}
      - {{ addr: 0xC030, name: member_fn, kind: function }}
    forth:
      names:
        0x0B2E: {{ name: EXIT }}
"""


def main():
    outdir = bankgen.outdir_arg(__file__)
    prg = make_prg()
    for name in ("c64hintentrytest.prg", "c64hintentryctltest.prg"):
        bankgen.write_bytes(outdir, name, prg)
    bankgen.write_bytes(outdir, "c64hintd64test.d64", mkd64test.build([("HINTD64", prg)], base=False))
    sha = hashlib.sha256(prg).hexdigest()
    with open(os.path.join(outdir, "c64hintentrytest.yaml"), "w", newline="\n") as f:
        f.write(OVERLAY.format(sha=sha))
    print("wrote C64 descriptor fixtures to %s (member sha256 %s)" % (outdir, sha))


if __name__ == "__main__":
    main()
