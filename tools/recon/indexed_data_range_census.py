#!/usr/bin/env python3
"""Aggregate IndexedDataRangeProbe logs: which evidence proves an index range at indexed data reads.

Written for bead grm-9nxj.41.1 (survey step of grm-9nxj.41, the table-minus-k operand reference).
Input: the per-row `<id>.log` files that `tools/banktest/IndexedDataRangeProbe.java` writes when
run as a real-ROM extra postScript:

    REALROM_EXTRA_POSTSCRIPT=IndexedDataRangeProbe.java REALROM_WORK_DIR=<dir> \\
        bash tools/banktest/realrom-test.sh check nes snes-analysis

Usage:
    indexed_data_range_census.py <dir-or-log> [<dir-or-log> ...]            census tables
    indexed_data_range_census.py <dir> --show CATEGORY [--limit N] [--row R] raw probe lines

CATEGORY (for --show): sym, symG, symL, symF, symnone (symptom sites no class proves),
disagree, GL, GF, LF, lo2 (some class proves lo >= 2), loop-unknown, Lweak (L proven only
weakly: unknown init or a variable limit, see `Lw=`), and with --baseline: newL (L proven now,
not in the baseline logs), newLexpl (newL sites whose symptom L explains), newdis (disagreement
absent from the baseline).

Round 2 (grm-9nxj.41.2): `--baseline <dir>` also prints a before/after comparison of the L class.

Definitions (see the probe's header for the evidence rules):
  site       a register-indexed absolute access whose base is in an initialized non-RAM block;
             reads are the population, stores (and RMW) are counted separately.
  G / L / F  the class proves a range [start, end) of the table the site reads (start = base+rlo);
  T          sym=1: the base lands on an instruction / inside an instruction / inside other data
             (the grm-9nxj.41 symptom: the operand reference sits one byte before the table).
  lo         (start - base) / stride, in entries; 0 means the reference is already at the start.
  explains   a class "explains" a symptom site when it proves lo > 0 and its start lands on
             something that is NOT itself a symptom kind (so moving the reference there is sane).
  disagree   two proven classes differ in start, or in end when both ends are finite.
"""
import argparse
import os
import re
import sys
from collections import Counter, defaultdict

LINE = re.compile(r'\bIDR (?!blocks|summary|error)(\S+) (.*?)(?: \(GhidraScript\))?\s*$')
SYMPTOM = {'INSN', 'INSIDE', 'DATA_MID', 'DATA_TAIL'}
CLASSES = ('G', 'L', 'F')


def parse_line(line):
    m = LINE.search(line)
    if not m:
        return None
    rec = {'prog': m.group(1), 'raw': line[m.start():].replace(' (GhidraScript)', '').strip()}
    for tok in m.group(2).split(' '):
        if '=' in tok:
            k, v = tok.split('=', 1)
            rec[k] = v
    return rec


def hexv(s):
    return None if s in (None, '*', '-') else int(s, 16)


def klass(rec, c):
    """(start, end_or_None, at_kind) for a proven class, else None."""
    if c + 'start' in rec:
        return hexv(rec[c + 'start']), hexv(rec.get(c + 'end')), rec.get(c + 'at', '?')
    return None


def lo_of(rec, c):
    k = klass(rec, c)
    if not k:
        return None
    base, stride = int(rec['base'], 16), int(rec['stride'])
    return (k[0] - base) // stride


def collect(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(os.path.join(p, f) for f in os.listdir(p) if f.endswith('.log'))
        else:
            files.append(p)
    recs = []
    seen = set()  # batch logs repeat the per-row lines
    for f in files:
        with open(f, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                if 'IDR ' not in line:
                    continue
                r = parse_line(line)
                if r and r['raw'] not in seen:
                    seen.add(r['raw'])
                    r['file'] = os.path.basename(f)
                    recs.append(r)
    return recs


def disagreements(rec):
    out = []
    present = [c for c in CLASSES if klass(rec, c)]
    for i, a in enumerate(present):
        for b in present[i + 1:]:
            ka, kb = klass(rec, a), klass(rec, b)
            if ka[0] != kb[0]:
                out.append(a + b + ':start')
            elif ka[1] is not None and kb[1] is not None and ka[1] != kb[1]:
                out.append(a + b + ':end')
    return out


def explains(rec, c):
    k = klass(rec, c)
    return bool(k) and lo_of(rec, c) > 0 and k[2] not in SYMPTOM


def bucket(n):
    return '0' if n == 0 else '1' if n == 1 else '2+' if n >= 2 else 'neg'


def category(rec, cat, base=None):
    key = (rec['prog'], rec.get('at'))
    old = base.get(key) if base is not None else None
    sym = rec.get('sym') == '1'
    has = {c: klass(rec, c) is not None for c in CLASSES}
    return {
        'sym': sym,
        'symG': sym and has['G'],
        'symL': sym and has['L'],
        'symF': sym and has['F'],
        'symnone': sym and not any(has.values()),
        'disagree': bool(disagreements(rec)),
        'GL': has['G'] and has['L'],
        'GF': has['G'] and has['F'],
        'LF': has['L'] and has['F'],
        'lo2': any(has[c] and lo_of(rec, c) >= 2 for c in CLASSES),
        'loop-unknown': 'Lunk' in rec,
        'Lweak': has['L'] and 'Lw' in rec,
        'newL': base is not None and has['L'] and not (old and klass(old, 'L')),
        'newLexpl': base is not None and has['L'] and not (old and klass(old, 'L')) and
                    sym and explains(rec, 'L'),
        'newdis': base is not None and bool(set(disagreements(rec)) -
                                            set(disagreements(old) if old else [])),
    }[cat]


def census(recs):
    rows = defaultdict(Counter)
    tot = Counter()
    combos = Counter()
    lodist = {c: Counter() for c in CLASSES}
    symcombo = Counter()
    lunk = Counter()
    pair_dis = Counter()
    explained = Counter()
    zero_but_sym = Counter()
    for r in recs:
        stores = r.get('rw') == 'S'
        key = 'stores' if stores else 'reads'
        for cnt in (rows[r['prog']], tot):
            cnt[key] += 1
        if stores:
            continue
        present = ''.join(c for c in CLASSES if klass(r, c)) or '-'
        sym = r.get('sym') == '1'
        for cnt in (rows[r['prog']], tot):
            for c in CLASSES:
                if c in present:
                    cnt[c] += 1
            if present != '-':
                cnt['any'] += 1
            if sym:
                cnt['sym'] += 1
                cnt['tshape'] += r.get('tshape') == '1'
                if present == '-':
                    cnt['symnone'] += 1
                if any(explains(r, c) for c in CLASSES):
                    cnt['symexpl'] += 1
            if 'Lunk' in r:
                cnt['Lunk'] += 1
            if klass(r, 'L') and 'Lw' in r:
                cnt['Lweak'] += 1
            if sym and klass(r, 'L') and explains(r, 'L'):
                cnt['symexplL'] += 1
        combos[present] += 1
        if sym:
            symcombo[present] += 1
            for c in CLASSES:
                if klass(r, c):
                    if explains(r, c):
                        explained[c] += 1
                    elif lo_of(r, c) == 0:
                        zero_but_sym[c] += 1
        for c in CLASSES:
            if klass(r, c):
                lodist[c][bucket(lo_of(r, c))] += 1
        if 'Lunk' in r:
            lunk[r['Lunk']] += 1
        d = disagreements(r)
        if d:
            tot['disagree'] += 1
            rows[r['prog']]['disagree'] += 1
            for x in d:
                pair_dis[x] += 1
        if 'F' in present and r.get('Fn') and False:
            pass
    return rows, tot, combos, lodist, symcombo, lunk, pair_dis, explained, zero_but_sym


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--show')
    ap.add_argument('--limit', type=int, default=15)
    ap.add_argument('--row')
    ap.add_argument('--baseline', help='earlier log dir to compare L proofs against')
    a = ap.parse_args()
    recs = collect(a.paths)
    if a.row:
        recs = [r for r in recs if a.row in r['prog']]
    if not recs:
        sys.exit('no IDR lines found')
    base = None
    if a.baseline:
        base = {(r['prog'], r.get('at')): r for r in collect([a.baseline])
                if r.get('rw') == 'R'}
    if a.show:
        n = 0
        for r in recs:
            if r.get('rw') == 'R' and category(r, a.show, base):
                print(r['raw'])
                n += 1
                if n >= a.limit:
                    break
        return
    rows, tot, combos, lodist, symcombo, lunk, pair_dis, explained, zero_but_sym = census(recs)
    cols = ('reads', 'stores', 'G', 'L', 'Lweak', 'F', 'any', 'Lunk', 'sym', 'tshape', 'symexpl',
            'symnone', 'disagree')
    print('%-28s' % 'row' + ''.join('%9s' % c for c in cols))
    for p in sorted(rows):
        print('%-28s' % p + ''.join('%9d' % rows[p][c] for c in cols))
    print('%-28s' % 'TOTAL' + ''.join('%9d' % tot[c] for c in cols))
    reads = tot['reads']
    print('\nclass combinations (reads):')
    for k, v in combos.most_common():
        print('  %-5s %6d  %5.1f%%' % (k, v, 100.0 * v / reads))
    print('\nlo distribution (entries, per proving class):')
    for c in CLASSES:
        d = lodist[c]
        print('  %s: lo=0 %d  lo=1 %d  lo>=2 %d  neg %d' % (c, d['0'], d['1'], d['2+'], d['neg']))
    print('\nsymptom sites (base on an instruction / inside other data): %d of %d reads' %
          (tot['sym'], reads))
    print('  by class combination: ' + ', '.join('%s=%d' % kv for kv in symcombo.most_common()))
    print('  explained (class proves lo>0 landing on a non-symptom): ' +
          ', '.join('%s=%d' % (c, explained[c]) for c in CLASSES) + '; any=%d' % tot['symexpl'])
    print('  class proves lo=0 yet base is a symptom: ' +
          ', '.join('%s=%d' % (c, zero_but_sym[c]) for c in CLASSES))
    print('  T only (no class proves a range): %d; of all symptom sites tshape=1 (base+1 not code): %d'
          % (tot['symnone'], tot['tshape']))
    print('\ndisagreements: %d sites; by pair/kind: %s' %
          (tot['disagree'], ', '.join('%s=%d' % kv for kv in pair_dis.most_common()) or 'none'))
    print('\nunknown loop shapes (%d reads): %s' %
          (tot['Lunk'], ', '.join('%s=%d' % kv for kv in lunk.most_common())))
    print('L proofs: %d (weak: %d); symptom sites explained by L: %d' %
          (tot['L'], tot['Lweak'], tot['symexplL']))
    if base is not None:
        rd = [r for r in recs if r.get('rw') == 'R']
        newl = sum(1 for r in rd if category(r, 'newL', base))
        newx = sum(1 for r in rd if category(r, 'newLexpl', base))
        newd = sum(1 for r in rd if category(r, 'newdis', base))
        have = {(r['prog'], r.get('at')) for r in rd if klass(r, 'L')}
        progs = {r['prog'] for r in recs}
        lost = sum(1 for key, o in base.items()
                   if key[0] in progs and klass(o, 'L') and key not in have)
        print('vs baseline: newly proven L %d, of which explain a symptom %d, new disagreements '
              '%d, baseline L proofs no longer proven %d' % (newl, newx, newd, lost))


if __name__ == '__main__':
    main()
