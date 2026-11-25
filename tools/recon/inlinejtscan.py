#!/usr/bin/env python3
"""Find JSR-inline-jump-table dispatchers in a 6502 image by their byte shape.

Usage:
  python -I tools/recon/inlinejtscan.py <rom.nes> [...]
  python -I tools/recon/inlinejtscan.py --row <row-id> [...]   (resolves via romlib, like dis6502.py --find)

Written for grm-gipk.26 (metroid_u's ChooseRoutine at $C27C parks the entry's low byte in X).
Prints every PRG offset where the dispatcher's double indirect load appears, labelled by where
the low byte waits between the two loads -- the three variants InlineJumpTableDispatch accepts:

  zp   LDA (p),Y / STA q / INY / LDA (p),Y        (smb JumpEngine)
  pha  LDA (p),Y / PHA   / INY / LDA (p),Y        (megaman3 8023, grm-gipk.4)
  tax  LDA (p),Y / TAX   / INY / LDA (p),Y        (metroid_u c27c, grm-gipk.26)

The routine's entry sits a few bytes before the reported offset and varies, so read it with
dis6502.py. A raw byte match is a lead, not proof: the `zp` shape also matches ordinary
pointer-copy loops, and ultimaav's `tax` hits at $C36E/$C392 are a table search, not a
dispatcher (its real one is $F449).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'banktest'))
import romlib  # noqa: E402

SHAPES = (
    ('tax', lambda d, i: d[i + 2] == 0xAA and d[i + 3] == 0xC8 and d[i + 4] == 0xB1 and
     d[i + 5] == d[i + 1]),
    ('pha', lambda d, i: d[i + 2] == 0x48 and d[i + 3] == 0xC8 and d[i + 4] == 0xB1 and
     d[i + 5] == d[i + 1]),
    ('zp', lambda d, i: d[i + 2] == 0x85 and d[i + 4] == 0xC8 and d[i + 5] == 0xB1 and
     d[i + 6] == d[i + 1]),
)


def scan(path):
    data = open(path, 'rb').read()
    prg = data[16:16 + data[4] * 0x4000]
    hits = []
    for i in range(len(prg) - 8):
        if prg[i] != 0xB1:
            continue
        for name, test in SHAPES:
            if test(prg, i):
                hits.append((i, name))
    return hits


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    paths = []
    if args[0] == '--row':
        for row in args[1:]:
            paths.append((row, romlib.find_path(row)))
    else:
        paths = [(p, p) for p in args]
    for label, path in paths:
        for off, name in scan(path):
            bank, within = divmod(off, 0x4000)
            print('%-14s %-4s prg+%05x  bank %2d +%04x' % (label, name, off, bank, within))


if __name__ == '__main__':
    main()
