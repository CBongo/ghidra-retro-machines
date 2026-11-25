"""Corpus byte-pattern scanner with wildcards and captures (bead grm-2a2a.8).

Replaces the scratch scanners re-written per bead (grm-6m24 dodge_*scan.py, grm-gcwb, grm-5tl.20.1,
grm-mej.19): "find this byte shape in every pinned ROM, tell me where and what the operands were".

PATTERN SYNTAX (whitespace-separated tokens, compiled to a Python bytes regex, DOTALL)
    a9 8d         literal hex bytes
    ??            any one byte
    [a9|a2]       alternation of bytes; ranges allowed: [a9|b0-b7|c0]
    {lo} {hi}     capture one byte under that name, printed per hit. Reusing a name requires the
                  same byte again (backreference): `85 {z} 68 85 {z}`
    {hi=80-9f}    capture restricted to a byte list (same list syntax as [..])
    *N  *N-M      up to N (or N..M) any bytes, lazy: `4c *32 60`
Hits may overlap (every offset is tried). A hit never spans a 16K bank boundary unless --span.
Examples:
    --pat '0a aa 68 85 {zp} 68 85 {zp1}'     grm-gcwb: JumpEngine-shaped pointer parking, TAX form
    --pat '0a a8 68 85 {lo} 68 85 {hi}'      same, TAY form
    --pat '[20|4c] {lo} {hi=80-9f}'          grm-6m24: JSR/JMP refs into $8000-$9FFF
    --pat '20 {lo} {hi} *16 60'              a JSR followed within 16 bytes by an RTS byte

USAGE (run from the repo root; ROM dirs come from $GRM_ROM_DIR / $GRM_SNES_ROM_DIR, never hardcoded)
    python -I tools/recon/romscan.py --pat '0a aa 68 85 {zp} 68 85 {zp1}'          # every NES row
    python -I tools/recon/romscan.py --pat '8d {lo} {hi}' --row smb3 dodge --dis 3
    python -I tools/recon/romscan.py --pat 'a9 ?? 8d 00 e0' --count                  # per-row counts
    python -I tools/recon/romscan.py --pat '...' --set manifest.tsv                  # manifest glob
    python -I tools/recon/romscan.py --pat '...' --corpus                            # every image in the dirs
    python -I tools/recon/romscan.py --pat '...' --file path/to/game.nes             # bare images
    python -I tools/recon/romscan.py --pat '...' --platform snes                     # raw offsets
Per hit (tab-separated): row id, PRG file offset (PRG start = 0), 16K bank, CPU address (the last
bank at $C000 via romlib.cpu_of; any other bank as bank:addr in the $8000 window), captures.
--dis N disassembles N instructions at the hit (rom6502/dis6502 tables, 6502 only). --max-hits N
caps hits per row. Default row set: manifest.tsv rows with a numeric mapper (the NES corpus).

Limits: static byte matches, so operand and data bytes match too (the false-positive class every
recon tool has); a switchable bank's address is the $8000-window guess, not the live mapping.
SNES: raw file offsets only (no header or LoROM/HiROM mapping yet; the seam is PLATFORMS).
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rom6502  # noqa: E402
import romlib  # noqa: E402  (rom6502 put tools/banktest on sys.path)

# platform -> (env var, image extensions, default manifest glob, row filter)
PLATFORMS = {
    'nes': ('GRM_ROM_DIR', ('.nes',), 'manifest.tsv', lambda f: f[3].isdigit()),
    'snes': ('GRM_SNES_ROM_DIR', ('.sfc', '.smc'), 'manifest-snes.tsv', lambda f: True),
}

_BYTE = r'[0-9a-fA-F]{2}'


def _alt_class(spec):
    """'a9|b0-b7' -> a regex byte class of those values."""
    vals = set()
    for part in spec.split('|'):
        if '-' in part:
            lo, hi = (int(x, 16) for x in part.split('-'))
            vals.update(range(lo, hi + 1))
        else:
            vals.add(int(part, 16))
    return '[' + ''.join('\\x%02x' % v for v in sorted(vals)) + ']'


def compile_pattern(pat):
    """Compile the romscan syntax to (body regex, capture names in order)."""
    out, names = [], []
    for t in pat.split():
        if re.fullmatch(_BYTE, t):
            out.append('\\x%02x' % int(t, 16))
        elif t == '??':
            out.append('.')
        elif re.fullmatch(r'\[[0-9a-fA-F|-]+\]', t):
            out.append(_alt_class(t[1:-1]))
        elif re.fullmatch(r'\*\d+(-\d+)?', t):
            lo, _, hi = t[1:].partition('-')
            out.append('.{%d,%d}?' % (int(lo) if hi else 0, int(hi or lo)))
        else:
            m = re.fullmatch(r'\{([A-Za-z_]\w*)(?:=([0-9a-fA-F|-]+))?\}', t)
            if not m:
                sys.exit('bad pattern token %r' % t)
            n, spec = m.groups()
            if n in names:
                out.append('(?P=%s)' % n)
            else:
                names.append(n)
                out.append('(?P<%s>%s)' % (n, _alt_class(spec) if spec else '.'))
    if not out:
        sys.exit('empty pattern')
    return ''.join(out), names


def addr_of(prgsize, off):
    """(cpu, label): last bank at $C000, any other bank in the $8000 window as bank:addr."""
    if off >= prgsize - 0x4000:
        c = romlib.cpu_of(prgsize, off)
        return c, '%04x' % c
    a = 0x8000 + off % 0x4000
    return a, '%02x:%04x' % (off // 0x4000, a)


def load_image(path, platform):
    """PRG bytes (iNES-parsed for NES, the raw file otherwise), or None for a non-iNES NES file."""
    if platform == 'nes':
        r = romlib.parse_ines(path)
        return None if r is None else r[1]
    with open(path, 'rb') as f:
        return f.read()


def scan(prg, body, names, span=False, max_hits=0):
    """[(offset, {name: byte})] for every (overlapping) match of the compiled body."""
    rx = re.compile(b'(?=(' + body + b'))', re.DOTALL)   # lookahead: overlapping hits
    hits = []
    for m in rx.finditer(prg):
        o = m.start()
        if not span and o // 0x4000 != (m.end(1) - 1) // 0x4000:
            continue
        hits.append((o, {k: prg[m.start(k)] for k in names}))
        if max_hits and len(hits) >= max_hits:
            break
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--pat', required=True, help='pattern (see module docstring)')
    ap.add_argument('--platform', choices=sorted(PLATFORMS), default='nes')
    ap.add_argument('--row', nargs='+', help='manifest row ids')
    ap.add_argument('--set', help='manifest glob under tools/banktest/realrom (default per platform)')
    ap.add_argument('--file', nargs='+', help='scan these image files instead of manifest rows')
    ap.add_argument('--corpus', action='store_true',
                    help='scan every image at depth 1 of the env dirs (the whole collection, not just pinned rows)')
    ap.add_argument('--dis', type=int, default=0, metavar='N', help='disassemble N instructions per hit (6502)')
    ap.add_argument('--count', action='store_true', help='per-row hit counts only')
    ap.add_argument('--max-hits', type=int, default=0, help='cap hits per row (0 = none)')
    ap.add_argument('--span', action='store_true', help='allow hits across 16K bank boundaries')
    a = ap.parse_args()

    env, exts, default_set, keep = PLATFORMS[a.platform]
    body, names = compile_pattern(a.pat)
    body = body.encode('ascii')

    if a.corpus:
        targets = [(os.path.basename(p), p) for p in romlib.rom_files(env, exts)]
    elif a.file:
        targets = [(os.path.basename(p), p) for p in a.file]
    else:
        if a.row:
            ids = a.row
        else:
            ids = []
            for f in romlib.manifest_rows([a.set or default_set]):
                if len(f) > 3 and keep(f) and f[0] not in ids:
                    ids.append(f[0])
        found = romlib.find_many(ids, env=env, exts=exts)
        targets = [(r, found[r]) for r in ids if r in found]
        missing = [r for r in ids if r not in found]
        if missing:
            print('# not found under $%s: %s' % (env, ' '.join(missing)), file=sys.stderr)

    total = 0
    for label, path in targets:
        prg = load_image(path, a.platform)
        if prg is None:
            print('# %s: not an iNES image, skipped' % label, file=sys.stderr)
            continue
        hits = scan(prg, body, names, a.span, a.max_hits)
        total += len(hits)
        if a.count:
            if hits:
                print('%-24s %d' % (label, len(hits)))
            continue
        for o, caps in hits:
            cpu, lab = addr_of(len(prg), o) if a.platform == 'nes' else (o, '-')
            cs = ' '.join('%s=%02x' % kv for kv in caps.items())
            print('%s\tprg=%05x\tbank=%d\tcpu=%s\t%s' % (label, o, o // 0x4000, lab, cs))
            if a.dis and a.platform == 'nes':
                i, pc = o, cpu
                for _ in range(a.dis):
                    ins = rom6502.decode(prg, i)
                    if ins is None:
                        print('\t\t.byte $%02x' % prg[i])
                        break
                    print('\t\t%04x  %s' % (pc, rom6502.fmt_ins(ins, pc)))
                    i += ins[2]
                    pc += ins[2]
    print('# %d hits in %d images' % (total, len(targets)), file=sys.stderr)


if __name__ == '__main__':
    main()
