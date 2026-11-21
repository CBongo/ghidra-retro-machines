"""Aggregate ParamReturnCensusProbe output into a per-platform table (bead grm-etbh, step 1).

Usage:
    python -I tools/recon/param_return_census.py <dir-with-.prc-files> [--md]

Inputs are the `<program>.prc` files the probe writes when GRM_PRC_OUT names a directory
(tools/banktest/ParamReturnCensusProbe.java), run via
    GRM_PRC_OUT=<dir> REALROM_EXTRA_POSTSCRIPT=ParamReturnCensusProbe.java \
        bash tools/banktest/realrom-test.sh check <sets>
Platform is taken from the SUMMARY line's language id. For each case the table prints
callee evidence, caller evidence and both (confirmed), as counts and as % of analyzed functions.
callee-only = callee - both; caller-only = caller - both.
"""
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


def platform(lang):
    if "65816" in lang:
        return "65816"
    if "6510" in lang:
        return "6510"
    if "6502" in lang:
        return "6502"
    if "spc700" in lang.lower():
        return "spc700"
    return lang


def kv(line):
    return dict(re.findall(r"(\w+)=(\S+)", line))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    md = "--md" in sys.argv
    plat = defaultdict(lambda: defaultdict(int))
    cases = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))
    rows = defaultdict(int)
    props = defaultdict(lambda: defaultdict(int))
    psamples = defaultdict(list)
    for p in sorted(Path(sys.argv[1]).glob("*.prc")):
        pl = None
        for line in p.read_text().splitlines():
            if " SUMMARY " in line:
                d = kv(line)
                pl = platform(d["lang"])
                rows[pl] += 1
                for k in ("fns", "analyzed", "skippedCap", "noCallers", "callSites",
                          "indirectJumps", "tailExit", "noReturnPath", "jumpRefsIn"):
                    plat[pl][k] += int(d[k])
            elif " PROP " in line and pl:
                d = kv(line)
                props[pl][d["key"]] += int(d["count"])
            elif " PSAMPLE " in line and pl:
                psamples[pl].append((p.stem, line.split(" PSAMPLE ", 1)[1]))
            elif " CASE " in line and pl:
                d = kv(line)
                c = cases[pl][d["case"]]
                c[0] += int(d["callee"])
                c[1] += int(d["caller"])
                c[2] += int(d["both"])
    sep = "|" if md else " "
    for pl in sorted(plat):
        t = plat[pl]
        n = max(t["analyzed"], 1)
        print(f"\n== {pl}: rows={rows[pl]} analyzed={t['analyzed']} noCallers={t['noCallers']} "
              f"callSites={t['callSites']} indirectJumps={t['indirectJumps']} "
              f"tailExit={t['tailExit']} noReturnPath={t['noReturnPath']} "
              f"jumpRefsIn={t['jumpRefsIn']} skippedCap={t['skippedCap']}")
        hdr = ["case", "callee-only", "caller-only", "both", "callee%", "caller%", "both%"]
        if md:
            print("| " + " | ".join(hdr) + " |")
            print("|" + "---|" * len(hdr))
        else:
            print(f"{hdr[0]:28s}" + "".join(f"{h:>12s}" for h in hdr[1:]))
        for name, (ce, cr, b) in sorted(cases[pl].items()):
            vals = [ce - b, cr - b, b, 100.0 * ce / n, 100.0 * cr / n, 100.0 * b / n]
            cells = [f"{v:d}" for v in vals[:3]] + [f"{v:.1f}" for v in vals[3:]]
            if md:
                print(f"| {name} | " + " | ".join(cells) + " |")
            else:
                print(f"{name:28s}" + "".join(f"{c:>12s}" for c in cells))
    _ = sep
    # Evidence-engine output (ParamReturnEvidenceDump.java): proposal counts per platform.
    for pl in sorted(props):
        print(f"\n== {pl}: proposals (ParamReturnEvidence)")
        for k, v in sorted(props[pl].items(), key=lambda kv_: (not kv_[0].startswith("#"), -kv_[1])):
            print(f"  {k:28s}{v:8d}")
        for row, text in psamples[pl][:int(os.environ.get("GRM_PRC_PSAMPLES", "0"))]:
            print(f"  sample {row}: {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
