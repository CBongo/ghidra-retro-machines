"""Join census kind=none sites with IndexBackChainProbe chains and pre-classify by shape
(written for grm-gipk.29).

Usage:
  python -I tools/recon/nosites_classify.py <none_full.txt> <ibc.txt> [--detail]

<none_full.txt>  distinct `SLC ...` bodies (prefix stripped) of the census's kind=none lines.
<ibc.txt>        `IBC ...` lines (prefix stripped) from tools/banktest/IndexBackChainProbe.java over
                 the same sites (GRM_BACKCHAIN_SITES = `<program> <addr>` lines).
Prints one line per site: row, site, fn, heuristic shape, and the chain nearest-first
(--detail: whole chain). The shape is a LEAD for a human/agent read, not a verdict:
  inline-jsr-engine       LDA (zp),Y twice with PLA/PLA before: the shared JumpEngine JMP
  word-table-interleaved  two LDA abs,X/Y one byte apart (one word table, bound not recovered)
  split-lo-hi-table       two LDA abs,X/Y further apart (lo table + hi table)
  one-table-load          a single LDA abs,X/Y in the chain (other half out of depth)
  table-by-zp-pointer     LDA (zp),Y pair, no PLA: table address handed in a zp pointer
  bare-vector             the chain is the JMP alone (trampoline through a vector)
  ram-vector              JMP (abs) with no table load in the chain
  65816-*        JMP (abs,X) / JML [..] / JSR (abs,X) forms
  return-insn    the site is RTI/RTL/RTS (stock reports 'Too many branches' on a return): not a dispatch
  unknown        none of the above
"""
import collections
import re
import sys

IBC = re.compile(r"^IBC (\S+) (\S+) (\d+): (\S+) (.*?)(?: <- from .*)?$")


def load(path):
    chains = collections.defaultdict(dict)
    for ln in open(path, encoding="utf-8"):
        m = IBC.match(ln.strip())
        if m:
            chains[(m.group(1), m.group(2))][int(m.group(3))] = (m.group(4), m.group(5))
    return chains


def shape(chain, cpu65816):
    ins = [chain[k][1] for k in sorted(chain)]
    site = ins[0] if ins else ""
    back = ins[1:]
    if site.startswith(("RTI", "RTL", "RTS")):
        return "return-insn"
    if cpu65816:
        if re.match(r"(JMP|JSR) \(.*,X\)", site):
            return "65816-jmp-abs-x"
        if site.startswith(("JML", "JMP [")) or "[" in site:
            return "65816-long-indirect"
        if site.startswith("JMP ("):
            return "65816-jmp-ind"
    ypair = sum(1 for i in back if re.match(r"LDA \(0x[0-9a-f]+\),Y", i))
    pulls = sum(1 for i in back if i.startswith("PLA"))
    if ypair >= 2 and pulls >= 2:
        return "inline-jsr-engine"
    bases = [int(m.group(1), 16) for i in back
             for m in [re.match(r"LDA 0x([0-9a-f]{3,4}),[XY]", i)] if m]
    if len(bases) >= 2:
        return "word-table-interleaved" if abs(bases[0] - bases[1]) == 1 else "split-lo-hi-table"
    if len(bases) == 1:
        return "one-table-load"
    if ypair >= 2:
        return "table-by-zp-pointer"
    if site.startswith("JMP ("):
        return "bare-vector" if not back else "ram-vector"
    return "unknown"


def main():
    detail = "--detail" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    chains = load(args[1])
    cnt = collections.Counter()
    for ln in sorted(open(args[0], encoding="utf-8")):
        f = ln.split()
        if len(f) < 4:
            continue
        lang, row, site = f[0], f[1], f[2]
        fn = f[3]
        ch = chains.get((row, site), {})
        sh = shape(ch, lang.startswith("65816"))
        cnt[(lang.split(":")[0], sh)] += 1
        seq = " ; ".join(ch[k][1] for k in sorted(ch)[: (99 if detail else 7)])
        print(f"{lang.split(':')[0]} {row} {site} {fn} [{sh}] {seq}")
    print()
    for k, v in sorted(cnt.items()):
        print(k, v)


if __name__ == "__main__":
    main()
