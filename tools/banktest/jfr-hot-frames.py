"""Attribute JFR CPU samples to this project's own code: which of OUR methods are hot.

Written for bead grm-949h.1 (65816 Direct Page analyzer profiling). `jfr view hot-methods`
names the leaf frame, which for analyzer work is usually Ghidra's (Sleigh p-code emission,
HashMap) and says nothing about which analyzer method drove it. This tool walks each sample's
stack from the leaf and charges it to the first frame matching --prefix (default
'retromachines.'). The --callers option also shows the chain of our frames above it.

Record a row (realrom-test.sh appends GHIDRA_HEADLESS_JAVA_OPTIONS; repeat always imports
fresh, and GRM_HEADLESS_TIMEOUT=0 stops a slow row being killed before the recording dumps):
    GRM_HEADLESS_TIMEOUT=0 GHIDRA_HEADLESS_JAVA_OPTIONS="-XX:StartFlightRecording=filename=<f>.jfr,settings=profile,dumponexit=true" \
        bash tools/banktest/realrom-test.sh repeat 1 <set> --only <row> --no-build
Then:
    python -I tools/banktest/jfr-hot-frames.py <f>.jfr [--top N] [--callers K] [--jfr PATH]
--jfr defaults to $JAVA_HOME/bin/jfr, else `jfr` on PATH.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

FRAME = re.compile(r"^\s+([\w.$<>]+)\(.*\)\s+line:")


def jfr_tool(given):
    if given:
        return given
    jh = os.environ.get("JAVA_HOME")
    if jh:
        for name in ("jfr.exe", "jfr"):
            p = os.path.join(jh, "bin", name)
            if os.path.isfile(p):
                return p
    p = shutil.which("jfr")
    if not p:
        sys.exit("no jfr tool: pass --jfr or set JAVA_HOME")
    return p


def samples(tool, path, depth):
    proc = subprocess.Popen([tool, "print", "--events", "jdk.ExecutionSample",
                             "--stack-depth", str(depth), path],
                            stdout=subprocess.PIPE, text=True, errors="replace")
    stack = []
    for line in proc.stdout:
        if line.startswith("jdk.ExecutionSample"):
            if stack:
                yield stack
            stack = []
            continue
        m = FRAME.match(line)
        if m:
            stack.append(m.group(1))
    if stack:
        yield stack
    proc.wait()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("jfr_file")
    ap.add_argument("--prefix", default="retromachines.")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--callers", type=int, default=0,
                    help="also key by the first K matching frames (innermost first)")
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--jfr")
    a = ap.parse_args()
    total = 0
    first = Counter()
    chains = Counter()
    for st in samples(jfr_tool(a.jfr), a.jfr_file, a.depth):
        total += 1
        ours = [f for f in st if f.startswith(a.prefix)]
        if not ours:
            continue
        first[ours[0]] += 1
        if a.callers:
            chains[" <- ".join(ours[:a.callers])] += 1
    mine = sum(first.values())
    print(f"samples {total}; with a {a.prefix} frame {mine} ({100.0 * mine / max(total, 1):.1f}%)")
    for name, n in first.most_common(a.top):
        print(f"{n:8d} {100.0 * n / max(total, 1):6.2f}%  {name}")
    if a.callers:
        print("\nby chain:")
        for name, n in chains.most_common(a.top):
            print(f"{n:8d} {100.0 * n / max(total, 1):6.2f}%  {name}")


if __name__ == "__main__":
    main()
