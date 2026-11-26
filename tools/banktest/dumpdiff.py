#!/usr/bin/env python3
"""Classify a real-ROM golden dump diff for bless review (bead grm-2a2a.12).

Usage:
  dumpdiff.py <golden.dump|row-id> <new.dump|row-id> [--full] [--width N]
  dumpdiff.py --commit <rev> <row-id|path> ...     diff <rev>^ against <rev> for each row
  dumpdiff.py --list-sections                      the cap/sort table this tool knows

A row id resolves to tools/banktest/realrom/expected/<id>.dump. The other argument is a path
(for example a candidate under build/). Reads the diff the way memory realrom-diff-sample-cap
says to, mechanically:

  (a) COUNTS    every non-listing REALROM line, printed `key old -> new` in the format of the
                bless record realrom-test.sh prints (a port of lib/bless-record.awk).
  (b) SLIDE     a capped, sorted sample section (sample.*, calls.disagree, exitwidth, block)
                is a PREFIX of its sorted list, so a line present on one side only that lies
                OUTSIDE the other side's [first line, last line] window fell off (or came in
                at) the cap boundary and says nothing about the program. "Outside" is proved
                from the dump itself: the writer (RealRomDumpSupport.emitSample) prints
                `<tag>.truncated <shown> of <total>` exactly when it cut the list, and sorts
                by the whole line string (Collections.sort), so the window is the first..last
                emitted line. Dumps older than grm-3pnz (acfca0e) carry no marker: a section
                of exactly 25 lines whose count line says more is treated as the legacy cap
                (SAMPLE = 25) and shown as such.
  (c) REAL      a line whose address sits inside both windows but whose text changed
                (old/new matched by address), and an added or removed line strictly inside
                the overlap of the two windows. Printed in full, per section.

Then per-section tallies and ONE verdict: "counts only", "counts + slide only", or
"N real content changes". Sections that are listings but have no cap knowledge (entry, seed,
bookmark, spc*, ...) are never slide-eligible: any difference there is REAL.
Exit status is 0 always (it is a reader, not a gate).
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = HERE / "realrom" / "expected"

# tag -> (cap as of the dump writers, count line that totals it, writer).  The cap is only used
# for the legacy (no-marker) inference; modern dumps carry `<tag>.truncated N of M` themselves.
# Sort is the writer's Collections.sort on the whole line for every capped section below.
SECTIONS = {
    "sample.bankcomment": (250, "bankComments", "RealRomDump/C64RealRomDump"),
    "sample.warn": (250, "warnings", "RealRomDump/C64RealRomDump"),
    "sample.note": (250, "notes", "RealRomDump/C64RealRomDump"),
    "sample.ref": (25, "refs.intoOverlay.retargeted", "RealRomDump"),
    "sample.symbol": (25, "symbols", "RealRomDump/SnesRealRomDump/C64RealRomDump"),
    "sample.jumptable": (8, "jumptable.wordArrays", "RealRomDump"),
    "sample.jumptable.planar": (8, "jumptable.planarArrays", "RealRomDump"),
    "sample.forth": (40, "forth.words", "C64RealRomDump"),
    "sample.bit": (100, None, "C64RealRomDump"),
    "block": (600, "blocks.total", "SnesRealRomDump"),
    "calls.disagree": (40, None, "W65816WidthDump/SnesRealRomDump"),
    "exitwidth": (40, None, "W65816WidthDump/SnesRealRomDump"),
}
LEGACY_CAP = 25  # RealRomDump.SAMPLE before grm-3pnz


def is_listing(tag, rest):
    """Same split as lib/bless-record.awk listing(): per-site lines are not count lines."""
    return (tag.startswith("sample.") or tag.endswith(".truncated") or tag == "calls.disagree"
            or tag in ("entry", "bookmark", "block")
            or (tag == "exitwidth" and not (rest and "=" in rest[0])))


class Dump:
    def __init__(self, text, name):
        self.name = name
        self.sections = {}   # tag -> [line text after the tag]
        self.trunc = {}      # tag -> (shown, total)
        self.counts = []     # [(key, [(name, val)])] in order, skeleton-paired later
        self.plain = []      # non-listing lines w/o any number: sha256, program, ...
        seen = {}
        for raw in text.splitlines():
            if not raw.startswith("REALROM "):
                continue
            toks = raw.split()
            tag, rest = toks[1], toks[2:]
            body = raw.split(None, 2)[2] if len(toks) > 2 else ""
            if tag.endswith(".truncated"):
                m = re.match(r"(\d+) of (\d+)", body)
                if m:
                    self.trunc[tag[:-10]] = (int(m.group(1)), int(m.group(2)))
                continue
            if is_listing(tag, rest):
                self.sections.setdefault(tag, []).append(body)
                continue
            self._scan(toks, seen, raw)

    def _scan(self, toks, seen, raw):
        skel, vals, lead, after = [], [], [], False
        for t in toks[1:]:
            if re.fullmatch(r"[0-9]+", t):
                skel.append("#")
                vals.append((" ".join(lead), t))
            elif re.search(r"=[0-9]+$", t):
                k, v = t.split("=", 1)
                skel.append(k + "=#")
                vals.append((" ".join(lead + [k]), v))
                after = True
            else:
                skel.append(t)
                if not after:
                    lead.append(t)
        sk = " ".join(skel)
        seen[sk] = seen.get(sk, 0) + 1
        if not vals:
            self.plain.append(raw)
            return
        vals = [(re.sub(r"^count ", "", n.strip()), v) for n, v in vals]
        self.counts.append(((sk, seen[sk]), vals))

    def count_value(self, name):
        for _, vals in self.counts:
            for n, v in vals:
                if n == name and v.isdigit():
                    return int(v)
        return None


def count_movement(a, b):
    ia = {k: v for k, v in a.counts}
    ib = {k: v for k, v in b.counts}
    out = []
    for k, vals in b.counts:
        if k not in ia:
            out += [f"{n} (new) {v}" for n, v in vals]
            continue
        for (n, v0), (_, v1) in zip(ia[k], vals, strict=False):
            if v0 != v1:
                out.append(f"{n} {v0} -> {v1}")
    for k, vals in a.counts:
        if k not in ib:
            out += [f"{n} {v} (gone)" for n, v in vals]
    return out


def window(d, tag):
    """(lo, hi, how) for a dump's section: None bounds = unbounded (complete section)."""
    lines = d.sections.get(tag, [])
    if tag in d.trunc and lines:
        return min(lines), max(lines), f"{d.trunc[tag][0]} of {d.trunc[tag][1]}"
    info = SECTIONS.get(tag)
    if tag not in d.trunc and info and tag.startswith("sample.") and len(lines) == LEGACY_CAP:
        total = d.count_value(info[1]) if info[1] else None
        if total is None or total > LEGACY_CAP:
            tot = "?" if total is None else str(total)
            return min(lines), max(lines), f"legacy cap 25 of {tot}"
    return None, None, "complete"


def inside(line, lo, hi):
    return lo is None or lo <= line <= hi


def key_of(line):
    return line.split(None, 1)[0] if line else ""


def sorted_ok(lines):
    return all(x <= y for x, y in zip(lines, lines[1:], strict=False))


def classify_section(tag, a, b):
    old, new = a.sections.get(tag, []), b.sections.get(tag, [])
    lo_a, hi_a, how_a = window(a, tag)
    lo_b, hi_b, how_b = window(b, tag)
    capped = SECTIONS.get(tag) is not None and (lo_a is not None or lo_b is not None)
    if capped and not (sorted_ok(old) and sorted_ok(new)):
        lo_a = lo_b = hi_a = hi_b = None   # cannot prove a window on an unsorted list
        how_a = how_b = "UNSORTED: no slide proof"
    if SECTIONS.get(tag) is None:
        lo_a = lo_b = hi_a = hi_b = None
    from collections import Counter
    ca, cb = Counter(old), Counter(new)
    removed = list((ca - cb).elements())
    added = list((cb - ca).elements())
    slide_out = [x for x in removed if not inside(x, lo_b, hi_b)]
    slide_in = [x for x in added if not inside(x, lo_a, hi_a)]
    rem = [x for x in removed if x not in slide_out]
    add = [x for x in added if x not in slide_in]
    changed, by_key = [], {}
    for x in add:
        by_key.setdefault(key_of(x), []).append(x)
    lost = []
    for x in rem:
        q = by_key.get(key_of(x))
        if q:
            changed.append((x, q.pop(0)))
        else:
            lost.append(x)
    gained = [x for q in by_key.values() for x in q]
    return dict(tag=tag, old=len(old), new=len(new), how_a=how_a, how_b=how_b,
                slide_out=sorted(slide_out), slide_in=sorted(slide_in),
                changed=sorted(changed), lost=sorted(lost), gained=sorted(gained))


def weakness(old, new):
    qa, qb = old.count("?"), new.count("?")
    return "weakened" if qb > qa else "strengthened" if qb < qa else "other"


def trunc_str(r):
    return r["how_a"] if r["how_a"] == r["how_b"] else f"{r['how_a']} -> {r['how_b']}"


def trunc_movement(a, b):
    out = []
    for tag in sorted(set(a.trunc) | set(b.trunc)):
        x, y = a.trunc.get(tag), b.trunc.get(tag)
        if x != y:
            f = lambda t: "none" if t is None else f"{t[0]} of {t[1]}"  # noqa: E731
            out.append(f"{tag}.truncated {f(x)} -> {f(y)}")
    return out


def run(a, b, full, width, label):
    P = print
    fit = (lambda s: s) if full else (lambda s: s if len(s) <= width else s[: width - 3] + "...")
    P(f"== {label}")
    moved = count_movement(a, b)
    P("(a) counts: " + (", ".join(moved) if moved else "unchanged"))
    for t in trunc_movement(a, b):
        P("    " + t)
    other = sorted(set(b.plain) ^ set(a.plain))
    if other:
        P(f"    non-count lines differ ({len(other)}, counted as real content):")
        for x in other[:6 if not full else None]:
            P("      " + ("- " if x in a.plain else "+ ") + fit(x[8:]))
    tags = sorted(set(a.sections) | set(b.sections))
    results = [classify_section(t, a, b) for t in tags]
    results = [r for r in results if r["old"] != r["new"] or r["slide_out"] or r["slide_in"]
               or r["changed"] or r["lost"] or r["gained"]
               or a.sections.get(r["tag"]) != b.sections.get(r["tag"])]
    real_total = len(other)   # a non-count, non-sample line that moved is content
    slides = False
    tallies = []
    for r in results:
        n_real = len(r["changed"]) + len(r["lost"]) + len(r["gained"])
        real_total += n_real
        n_slide = len(r["slide_out"]) + len(r["slide_in"])
        slides = slides or n_slide > 0
        weak = {"weakened": 0, "strengthened": 0, "other": 0}
        for o, n in r["changed"]:
            weak[weakness(o, n)] += 1
        t = f"{r['tag']}: lines {r['old']} -> {r['new']}"
        if r["how_a"] != "complete" or r["how_b"] != "complete":
            t += f" [window {trunc_str(r)}]"
        t += (f"; real: lost {len(r['lost'])} added {len(r['gained'])} changed {len(r['changed'])}"
              f"; slide: out {len(r['slide_out'])} in {len(r['slide_in'])}")
        if r["tag"] == "sample.bankcomment" and r["changed"]:
            t += f"; changed = weakened {weak['weakened']} strengthened {weak['strengthened']} other {weak['other']}"
        tallies.append(t)
        if n_slide:
            P(f"(b) slide {r['tag']} [{trunc_str(r)}]: {len(r['slide_out'])} fell off the cap end, "
              f"{len(r['slide_in'])} came in at it (not content)")
            if full:
                for x in r["slide_out"]:
                    P("      slid out " + x)
                for x in r["slide_in"]:
                    P("      slid in  " + x)
            else:
                for lab, xs in (("out", r["slide_out"]), ("in", r["slide_in"])):
                    if xs:
                        P(f"      {lab}: {key_of(xs[0])}" + (f" .. {key_of(xs[-1])}" if len(xs) > 1 else "")
                          + f" ({len(xs)})")
    P("(c) real content changes:" + ("" if real_total else " none"))
    for r in results:
        if not (r["changed"] or r["lost"] or r["gained"]):
            continue
        P(f"  [{r['tag']}]")
        for o, n in r["changed"]:
            P(f"    changed {key_of(o)}")
            P("      - " + fit(o))
            P("      + " + fit(n))
        for x in r["lost"]:
            P("    removed " + fit(x))
        for x in r["gained"]:
            P("    added   " + fit(x))
    if tallies:
        P("tallies:")
        for t in tallies:
            P("  " + t)
    if real_total:
        verdict = f"{real_total} real content change{'s' if real_total != 1 else ''}" \
            + (" (+ slide)" if slides else "")
    elif slides:
        verdict = "counts + slide only"
    else:
        verdict = "counts only"
    P(f"VERDICT: {verdict}")
    return verdict


def load_arg(arg):
    p = Path(arg)
    if not p.exists():
        p = EXPECTED / (arg if arg.endswith(".dump") else arg + ".dump")
    if not p.exists():
        sys.exit(f"dumpdiff: no such dump or row id: {arg}")
    return Dump(p.read_text(encoding="utf-8", errors="replace"), str(p)), str(p)


def git_show(rev, path):
    r = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return r.stdout if r.returncode == 0 else ""


def main():
    ap = argparse.ArgumentParser(description="classify a real-ROM dump diff (grm-2a2a.12)")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--commit", metavar="REV", help="diff REV^ against REV for each row/path")
    ap.add_argument("--full", action="store_true", help="no truncation of lines or slide lists")
    ap.add_argument("--width", type=int, default=150)
    ap.add_argument("--list-sections", action="store_true")
    o = ap.parse_args()
    if o.list_sections:
        print("tag (sorted by whole line; window = first..last emitted when truncated)")
        for t, (cap, cnt, w) in SECTIONS.items():
            print(f"  {t:26} cap {cap:4} total-count {cnt or '-':30} {w}")
        return
    if o.commit:
        for a in o.args:
            path = a if a.endswith(".dump") else f"tools/banktest/realrom/expected/{a}.dump"
            old, new = git_show(o.commit + "^", path), git_show(o.commit, path)
            if not old or not new:
                print(f"== {a}: not in both {o.commit}^ and {o.commit}")
                continue
            run(Dump(old, "old"), Dump(new, "new"), o.full, o.width, f"{a} @ {o.commit}")
        return
    if len(o.args) != 2:
        ap.error("need <golden> <new>")
    (a, pa), (b, pb) = load_arg(o.args[0]), load_arg(o.args[1])
    run(a, b, o.full, o.width, f"{pa} -> {pb}")


if __name__ == "__main__":
    main()
