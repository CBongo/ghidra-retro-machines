"""Per-program phase times and per-analyzer times from Ghidra's headless application.log.

Written for bead grm-949h (gate timing evaluation). Every headless run in this project
(build-and-test.sh fixtures, realrom-test.sh rows) logs into the isolated per-worktree
user-settings dir's application.log, which -- unlike the per-batch -log files -- carries a
timestamp on every line. Headless imports run one program at a time, so consecutive
IMPORTING / ANALYZING / SCRIPT / post-script / Save lines delimit each program's phases.

Usage:
    python -I tools/banktest/headless-phase-times.py [--since 'YYYY-MM-DD HH:MM:SS']
        [--until ...] [--analyzers N] [--tsv] [LOG]

LOG defaults to build/ghidra-home/*/ghidra_<ghidraTargetVersion>_PUBLIC/application.log.
Phases (seconds, 1 s log resolution):
    import   IMPORTING -> ANALYZING (or first SCRIPT when -noanalysis)
    pre      prescripts run between import and analysis are folded into import
    analysis ANALYZING all memory -> first postScript SCRIPT
    script   first postScript SCRIPT -> 'ANALYZING changes made by post scripts' / save
    post     post-script re-analysis -> save
'atable' is Ghidra's own Total Time for the main analysis; --analyzers N lists the top N
analyzers by seconds for each program (from the multi-line analysis-times table).
"""

import argparse
import glob
import os
import re
import sys
from datetime import datetime

LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\w+)\s+\((\w+)\) (.*)$")
ANALYZER = re.compile(r"^\s{2,}(\S.*?)\s+([\d.]+) secs\s*$")
TOTAL = re.compile(r"^\s+Total Time\s+([\d.]+) secs")


def default_log():
    ver = None
    with open("gradle.properties", encoding="utf-8") as f:
        for ln in f:
            if ln.startswith("ghidraTargetVersion="):
                ver = ln.split("=", 1)[1].strip()
    hits = glob.glob(f"build/ghidra-home/*/ghidra_{ver}_PUBLIC/application.log")
    if not hits:
        sys.exit(f"no application.log for Ghidra {ver} under build/ghidra-home")
    return hits[0]


def parse(path, since, until):
    progs, cur = [], None
    in_table = False
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            m = LINE.match(raw)
            if not m:
                if cur is not None and in_table:
                    t = TOTAL.match(raw)
                    if t:
                        cur["atable"] = float(t.group(1))
                        in_table = False
                        continue
                    a = ANALYZER.match(raw)
                    if a:
                        cur["analyzers"].append((a.group(1), float(a.group(2))))
                continue
            ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            if since and ts < since:
                continue
            if until and ts > until:
                break
            msg = m.group(4).strip()
            if msg.startswith("IMPORTING: file:"):
                cur = {"name": os.path.basename(msg.split("file:", 1)[1]),
                       "t": {"import": ts}, "analyzers": [], "atable": None,
                       "end": ts}
                progs.append(cur)
                in_table = False
            elif cur is None:
                continue
            elif msg.startswith("ANALYZING all memory"):
                cur["t"]["analysis"] = ts
                in_table = True
            elif msg.startswith("SCRIPT:") and "analysis" in cur["t"] \
                    and "script" not in cur["t"]:
                cur["t"]["script"] = ts
            elif msg.startswith("SCRIPT:") and "analysis" not in cur["t"] \
                    and "script" not in cur["t"] and "noanalysis_script" not in cur["t"]:
                cur["t"]["noanalysis_script"] = ts
            elif msg.startswith("ANALYZING changes made by post"):
                cur["t"]["post"] = ts
            elif msg.startswith("REPORT: Save succeeded") or msg.startswith(
                    "REPORT: Import succeeded"):
                cur["t"].setdefault("save", ts)
            cur["end"] = ts
    return progs


def phases(p):
    t = p["t"]
    end = t.get("save", p["end"])
    # A -noanalysis row's first SCRIPT is either a prescript or its postScript; with no
    # ANALYZING line the two cannot be told apart, so count it all as 'script'.
    if "analysis" not in t and "noanalysis_script" in t:
        t = dict(t, script=t["noanalysis_script"])
    order = [k for k in ("import", "analysis", "script", "post") if k in t]
    out = {k: 0 for k in ("import", "analysis", "script", "post")}
    for i, k in enumerate(order):
        nxt = t[order[i + 1]] if i + 1 < len(order) else end
        out[k] = (nxt - t[k]).total_seconds()
    out["total"] = (end - t["import"]).total_seconds()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log", nargs="?")
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--analyzers", type=int, default=0)
    ap.add_argument("--tsv", action="store_true")
    a = ap.parse_args()
    fmt = "%Y-%m-%d %H:%M:%S"
    since = datetime.strptime(a.since, fmt) if a.since else None
    until = datetime.strptime(a.until, fmt) if a.until else None
    progs = parse(a.log or default_log(), since, until)
    sep = "\t" if a.tsv else "  "
    cols = ("total", "import", "analysis", "script", "post")
    print(sep.join(["program".ljust(0 if a.tsv else 34)] +
                   [c.rjust(0 if a.tsv else 8) for c in cols] + ["atable"]))
    for p in progs:
        ph = phases(p)
        row = [p["name"].ljust(0 if a.tsv else 34)]
        row += [f"{ph[c]:.0f}".rjust(0 if a.tsv else 8) for c in cols]
        row.append("" if p["atable"] is None else f"{p['atable']:.0f}")
        print(sep.join(row))
        if a.analyzers and p["analyzers"]:
            for name, s in sorted(p["analyzers"], key=lambda x: -x[1])[:a.analyzers]:
                print(f"{sep}    {s:8.1f}  {name}")
    tot = {c: sum(phases(p)[c] for p in progs) for c in cols}
    print(sep.join(["TOTAL".ljust(0 if a.tsv else 34)] +
                   [f"{tot[c]:.0f}".rjust(0 if a.tsv else 8) for c in cols]))


if __name__ == "__main__":
    main()
