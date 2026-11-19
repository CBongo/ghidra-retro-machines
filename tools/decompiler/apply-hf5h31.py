"""EXPERIMENTAL candidate (grm-hf5h.31, not installed, awaiting owner ruling): stacked on candidate
14 (tools/decompiler/apply-hf5h11.py, apply-hf5h11-c13.py, apply-hf5h20.py).

ROOT CAUSE. JumpBasicOverride::trialNorm enumerates a trial normalized Varnode from startingvalue
upward and gives up after `tolerance` (10) CONSECUTIVE values whose emulated address is not one of
the override's destinations. A real table can hold a long run of unused (null) entries: w_ff3
c077fe (FUN_c07578, SBC #$c6 / ASL / TAX / LDA $c07807,X / ... JMP ($002d)) has 58 entries, 27
handlers and an 18-entry run of $0000 at 0x21..0x32, with the last 6 handlers after it. trialNorm
finds 21 of 27 destinations and fails, so the override falls back to the trivial model and prints
ADDRESS labels.

FIX. While the trial Varnode's NZ mask bounds it to at most 0x10000 values and the scan has not
passed that bound, a run of misses does not end the scan. The bound is what makes this safe: a
byte index costs at most 256 emulations. Unbounded Varnodes keep the stock tolerance.

Measured in WSL replay (grm-hf5h.31 comment 2026-11-19), table bytes spliced from the ROM:
today's language -> offset labels case 0,2,..,0x72; with ADC/SBC binary-only
(tools/decompiler/sinc-adcsbc-binary-only.py) -> exact value labels switch(A) case 0xc6..0xff.

usage: python -I tools/decompiler/apply-hf5h31.py <decompile cpp dir already patched to candidate 14>
"""
import os
import sys


def edit(path, pairs):
    s = open(path, newline='').read()
    nl = '\r\n' if '\r\n' in s else '\n'
    for old, new in pairs:
        old = old.replace('\n', nl)
        new = new.replace('\n', nl)
        assert s.count(old) == 1, 'anchor not unique/found in %s: %r' % (path, old[:80])
        s = s.replace(old, new, 1)
    open(path, 'w', newline='').write(s)
    print('patched', path)


d = sys.argv[1]
edit(os.path.join(d, 'jumptable.cc'), [(
    '      miss += 1;\n'
    '      if (miss >= tolerance) break;\n',
    '      miss += 1;\n'
    '      // A bounded index scans its whole range: a table may hold long runs of unused entries\n'
    '      if (miss >= tolerance && !(nz != 0 && nz <= 0xffff && val < nz)) break;\n',
)])
