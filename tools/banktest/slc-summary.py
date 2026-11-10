"""Tabulate and diff SwitchLabelCensus.java output (written for grm-hf5h stage 1).

Usage:
  python -I tools/banktest/slc-summary.py <logdir> [<logdir2>]

<logdir> is a REALROM_WORK_DIR holding the per-row/per-batch .log files of a realrom-test.sh run with
REALROM_EXTRA_POSTSCRIPT=SwitchLabelCensus.java. One dir: prints a language x analyzer x kind
count table (sites keyed by row/site/function, so a site shared by several rows counts per row).
Two dirs (baseline then candidate): additionally lists every site whose `kind` differs between
the two, and sites present on only one side.
"""
import collections
import glob
import os
import re
import sys

LINE = re.compile(r"SwitchLabelCensus\.java> (SLC (\S+) (\S+) (\S+) .*?)(?: \(GhidraScript\))?\s*$")
KV = re.compile(r"(\w+)=(\S*)")


def load(d):
    sites = {}
    for p in sorted(glob.glob(os.path.join(d, "*.log"))):
        with open(p, encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = LINE.search(ln)
                if not m or m.group(1).startswith("SLC-SUM"):
                    continue
                body = m.group(1)
                lang, prog, site = m.group(2), m.group(3), m.group(4)
                kv = dict(KV.findall(body))
                kv["lang"], kv["site"], kv["line"] = lang, site, body
                row = prog
                sites[(row, site, kv.get("fn", "-"))] = kv
    return sites


def table(sites, title):
    cnt = collections.Counter()
    for kv in sites.values():
        cnt[(kv["lang"], kv["analyzer"], kv["kind"])] += 1
    print("== %s: %d sites ==" % (title, len(sites)))
    for (lang, an, kind), n in sorted(cnt.items()):
        print("%-24s %-28s %-13s %5d" % (lang, an, kind, n))


def main():
    dirs = sys.argv[1:]
    if not dirs:
        sys.exit(__doc__)
    a = load(dirs[0])
    table(a, dirs[0])
    if len(dirs) > 1:
        b = load(dirs[1])
        table(b, dirs[1])
        print("== kind CHANGED (baseline -> candidate) ==")
        n = 0
        for k in sorted(set(a) & set(b)):
            if a[k]["kind"] != b[k]["kind"]:
                n += 1
                print("%s %s fn=%s analyzer=%s: %s -> %s" % (k[0], k[1], k[2], a[k]["analyzer"],
                      a[k]["kind"], b[k]["kind"]))
                print("   base: " + a[k]["line"][:230])
                print("   cand: " + b[k]["line"][:230])
        print("changed=%d  only-baseline=%d  only-candidate=%d" %
              (n, len(set(a) - set(b)), len(set(b) - set(a))))
        for k in sorted(set(a) ^ set(b)):
            print("only-%s %s %s fn=%s" % ("base" if k in a else "cand", k[0], k[1], k[2]))


if __name__ == "__main__":
    main()
