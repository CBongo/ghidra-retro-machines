"""Classify switch sites that still print byte-OFFSET labels by where their index comes from
(written for grm-hf5h.11).

Usage:
  python -I tools/recon/offset_label_classify.py <census_logdir> <backchain.txt> [--detail]

<census_logdir>  REALROM_WORK_DIR of a realrom-test.sh run with
                 REALROM_EXTRA_POSTSCRIPT=SwitchLabelCensus.java (its `kind=offset` SLC lines give
                 each site's label stride).
<backchain.txt>  `IBC ...` lines from tools/banktest/IndexBackChainProbe.java over the same sites,
                 prefix stripped (the probe's header shows the one-liner that produces it).

Per site prints: row, site, stride, class, and the index evidence. Classes (first match wins):
  stride-N          label stride is not 2 (e.g. 3-byte entries: megaman 99b5)
  shift-in-chain    an ASL A / ROL A feeds the index register in the visible chain (the decompiler
                    should have undone it -- grm-hf5h.2's rule missed this site)
  mem-index         the index register is loaded straight from memory (LDX/LDY mem, or LDA mem /
                    TAX|TAY with no shift): a pre-doubled RAM variable, no shift to undo
  arith-index       the index is computed (ADC/SBC/AND/ORA/EOR, INX/INY...) with no shift seen
  unknown           the chain ended before the index's origin (block head, depth limit)
"""
import glob
import os
import re
import sys
from collections import Counter, defaultdict

SLC = re.compile(r"SwitchLabelCensus\.java> SLC \S+ (\S+) (\S+) .*kind=offset .*?ex=(\S+)")
IBC = re.compile(r"^IBC (\S+) (\S+) (\d+): (\S+) (.*?)(?: <- from .*)?$")
# 6502 `LDA tbl,X` (pointer built in RAM, then JMP (ptr)), or 65816 `JMP (!$tbl,X)`.
TABLE_LOAD = re.compile(r"^(?:LDA 0x[0-9a-f]+,([XY])|JMP \(!\$0x[0-9a-f]+,(X)\))$", re.I)


def strides(logdir):
    out = {}
    for p in glob.glob(os.path.join(logdir, "*.log")):
        with open(p, encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = SLC.search(ln)
                if m:
                    ex = [int(v, 16) for v in m.group(3).split(",") if v]
                    out[(m.group(1), m.group(2))] = ex[1] - ex[0] if len(ex) > 1 else 0
    return out


def chains(path):
    out = defaultdict(dict)
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = IBC.match(ln.strip())
            if m:
                out[(m.group(1), m.group(2))][int(m.group(3))] = m.group(5).strip()
    return {k: [v[i] for i in sorted(v)] for k, v in out.items()}


def classify(chain):
    """chain[0] is the JMP, then backwards. Returns (class, evidence)."""
    hits = [(n, TABLE_LOAD.match(ins)) for n, ins in enumerate(chain)]
    hits = [(n, m) for n, m in hits if m]
    if not hits:
        return "unknown", "no indexed table load in chain"
    start, m = hits[0]
    seen = []
    want = (m.group(1) or m.group(2)).upper()  # traced register: X/Y, then A after TAX/TAY
    for ins in chain[start + 1:]:
        op = ins.split()[0].upper()
        seen.append(ins)
        if want in "XY":
            if op in ("T" + "A" + want,):  # TAX / TAY
                want = "A"
                continue
            if op in ("LD" + want,):
                return ("mem-index" if "#" not in ins else "arith-index"), "; ".join(seen)
            if op in ("IN" + want, "DE" + want):
                return "arith-index", "; ".join(seen)
            continue
        # tracing A
        if op in ("ASL", "ROL") and ins.upper().endswith(op):
            return "shift-in-chain", "; ".join(seen)
        if ins.upper() in ("ASL A", "ROL A"):
            return "shift-in-chain", "; ".join(seen)
        if op == "LDA":
            return "mem-index", "; ".join(seen)
        if op in ("ADC", "SBC", "AND", "ORA", "EOR", "TXA", "TYA", "PLA"):
            return "arith-index", "; ".join(seen)
    return "unknown", "; ".join(seen) or "chain ended"


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    st = strides(sys.argv[1])
    ch = chains(sys.argv[2])
    detail = "--detail" in sys.argv
    counts = Counter()
    for key in sorted(st):
        stride = st[key]
        chain = ch.get(key)
        if chain is None:
            cls, ev = "no-chain", ""
        elif stride != 2:
            cls, ev = "stride-%d" % stride, ""
        else:
            cls, ev = classify(chain)
        counts[cls] += 1
        print("%-22s %-28s stride=%d %-15s %s" % (key[0], key[1], stride, cls,
                                                  ev[:150] if detail else ""))
    print()
    for cls, n in counts.most_common():
        print("%-15s %d" % (cls, n))


if __name__ == "__main__":
    main()
