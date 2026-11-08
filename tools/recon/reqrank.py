#!/usr/bin/env python3
"""reqrank.py -- rank reqscan.py's JSON output for "request RAM cell fulfilled later" bank switching.

Written for bead grm-5tl.20.2 (the corpus survey that followed Metroid's request/fulfil switch).

usage:  python -I tools/recon/reqrank.py MODE SCAN.json [options]
  adj       SCAN.json [MAXFRAC [MAXROWS]]
            Cells the helper window (or a call site) loads, ranked by the fraction of their writers
            sitting right before a JSR/JMP to the helper (low fraction = the cell is written
            elsewhere and consumed later = "request" style).  Defaults MAXFRAC 0.3, MAXROWS 60.
  callargs  SCAN.json
            Helpers with >= 2 call sites where at most half the calls pass an immediate in A, and
            that either load a RAM cell in the window or take RAM-sourced arguments.
  readclear SCAN.json
            Cells that call sites read and that a call site / the window then zeroes (consume-and-
            clear handshake).  One row per (title family, helper, cell).
  asrc      SCAN.json
            The cell that is the direct A source of the helper's first mapper store, with writer
            count (2..30, shift ops excluded), readers outside the helper and adjacency.
            (Needs a SCAN.json made by the current reqscan.py: uses aSrc / aSrcWriters.)

Mapper filters are fixed: MMC1 (1) rows need a shift (LSR) and >= 4 stores to registers; MMC1 and
MMC3 (4) rows must store only to that mapper's register addresses.  Rows are de-duplicated by title
family (region/version tags stripped), so one title in several dumps prints once.

Inherits every reqscan.py limit (linear decode, guessed helper entries, no indirect jumps, no
NMI-vs-main-loop placement, byte-pattern writer counts that include data coincidences).  These are
rankings for choosing which ROMs to read by hand, not classifications.  The modes differ enough in
what they surface that none supersedes another; `asrc` is the narrowest and the one the Metroid
follow-up leaned on.  (Merged from four scratchpad scripts, rank/rank2/rank3/rank4.)
"""
import collections
import json
import re
import sys

SH = {'LSR', 'ASL', 'ROR', 'ROL'}
OKADDR = {1: {'0x8000', '0xa000', '0xc000', '0xe000', '0x9fff', '0xbfff', '0xdfff', '0xffff'},
          4: {'0x8000', '0x8001', '0xa000', '0xa001', '0xc000', '0xc001', '0xe000', '0xe001'}}
LOADS = ('LDA', 'LDY', 'LDX')


def fam(n):
    """Title family: strip region/version/dump tags and the extension."""
    return re.sub(r'\s*\((?!U\)|J\)|E\)).*?\)|\s*\[.*?\]|\.nes$', '', n).strip()


def mapper_ok(m, h, sa):
    if m in OKADDR and not sa <= OKADDR[m]:
        return False
    return not (m == 1 and not (h['hasLSR'] and len(h['stores']) >= 4))


def mode_adj(d, maxfrac, maxrows):
    best = {}
    mc = collections.Counter()
    for name, r in d.items():
        m = r['mapper']
        mc[m] += 1
        for h in r.get('helpers', []):
            if h['ncalls'] < 1:
                continue
            sa = set(h['storeAddrs'])
            if not mapper_ok(m, h, sa):
                continue
            srcs = set(h['callSrcRam'].keys())
            for c, w in h['cells'].items():
                k = {a: b for a, b in w['kinds'].items() if a not in SH}
                tot = sum(k.values())
                if tot < 2 or tot > 40:
                    continue
                inwin = any(ld[2] == c and ld[0] in LOADS for ld in h['loads'])
                fromcall = c in srcs
                if not (inwin or fromcall):
                    continue
                adj = w['adjacentToHelperCall']
                best[(fam(name), m, h['cpu'], c)] = (
                    adj / tot, fam(name), m, h['cpu'], ','.join(sorted(sa)), h['ncalls'], c, tot,
                    adj, inwin, fromcall, k)
    rows = sorted(best.values(), key=lambda x: (x[0], -x[7]))
    print('mappers', sorted(mc.items()))
    n = 0
    for x in rows:
        if x[0] <= maxfrac:
            print('%.2f %-38s m%-2d h=%04x %s calls=%d cell=%s w=%d adj=%d inwin=%s fromcall=%s %s' % x)
            n += 1
            if n > maxrows:
                break


def mode_callargs(d):
    seen, out = set(), []
    for name, r in d.items():
        m, f = r['mapper'], fam(name)
        for h in r.get('helpers', []):
            if h['ncalls'] < 2:
                continue
            sa = set(h['storeAddrs'])
            if not mapper_ok(m, h, sa):
                continue
            ck = h['callKinds']
            if ck.get('A=imm', 0) / h['ncalls'] > 0.5:
                continue
            ramloads = sorted({ld[2] for ld in h['loads']
                               if ld[0] in LOADS and '@' not in ld[1] and int(ld[2], 16) >= 8})
            callram = sorted(h['callSrcRam'].keys())
            if not (ramloads or callram):
                continue
            key = (f, m, h['cpu'])
            if key in seen:
                continue
            seen.add(key)
            out.append((f, m, h['cpu'], h['ncalls'], ck, ramloads, callram))
    out.sort()
    for o in out:
        print('%-40s m%-2d %04x n=%d %s inwinLoads=%s callRam=%s' % o)
    print(len(out))


def mode_readclear(d):
    seen, rows = set(), []
    for name, r in d.items():
        f = fam(name)
        for h in r.get('helpers', []):
            for c, k in h.get('readClear', {}).items():
                if int(c, 16) < 8:
                    continue
                w = h['cells'].get(c)
                key = (f, h['cpu'], c)
                if key in seen:
                    continue
                seen.add(key)
                rows.append((f, r['mapper'], h['cpu'], h['ncalls'], c, k, h['readers'].get(c),
                             w['writers'] if w else None, w['kinds'] if w else None, h['winClears']))
    rows.sort()
    for x in rows:
        print('%-36s m%-2d h=%04x calls=%d cell=%s readClear=%d readers=%s w=%s %s winClears=%s' % x)
    print(len(rows))


def mode_asrc(d):
    seen = set()
    cnt = collections.Counter()
    for name, r in d.items():
        for h in r.get('helpers', []):
            s = h.get('aSrc')
            cnt[(r['mapper'], s[0] if s else None)] += 1
            if not s or s[0] != 'ram':
                continue
            if r['mapper'] == 1 and not any(int(a, 16) >= 0xe000 for a in h['storeAddrs']):
                continue
            if r['mapper'] == 4 and '0x8001' not in h['storeAddrs']:
                continue
            w = h['aSrcWriters']
            k = {a: b for a, b in w['kinds'].items() if a not in SH}
            tot = sum(k.values())
            key = (fam(name), s[1])
            if key in seen:
                continue
            seen.add(key)
            if tot < 2 or tot > 30 or h['ncalls'] < 1:
                continue
            print('%-34s m%-2d h=%04x calls=%d cell=%x readersOutside=%d writers=%d adjToHelperCall=%d %s'
                  % (fam(name), r['mapper'], h['cpu'], h['ncalls'], s[1], h['aSrcReaders'], tot,
                     w['adjacentToHelperCall'], k))
    print(sorted(cnt.items(), key=str)[:80])


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ('adj', 'callargs', 'readclear', 'asrc'):
        sys.exit(__doc__)
    mode = sys.argv[1]
    d = json.load(open(sys.argv[2]))
    if mode == 'adj':
        mode_adj(d, float(sys.argv[3]) if len(sys.argv) > 3 else 0.3,
                 int(sys.argv[4]) if len(sys.argv) > 4 else 60)
    elif mode == 'callargs':
        mode_callargs(d)
    elif mode == 'readclear':
        mode_readclear(d)
    else:
        mode_asrc(d)


if __name__ == '__main__':
    main()
