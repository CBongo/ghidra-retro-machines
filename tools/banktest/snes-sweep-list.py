"""Prioritized SNES sweep list for snes-rom-sweep.sh --list: the game-tier (realrom manifest)
titles first, then the rest of the deduped collection (accepted, checksum-valid, one per title,
unheadered preferred). Owner principle 2026-10-29: tier games first, but survey as many as
possible.

    python -I tools/banktest/snes-sweep-list.py <repo root> "$GRM_SNES_ROM_DIR" <out list>
"""
import csv
import glob
import os
import sys

repo, romdir, out = sys.argv[1], sys.argv[2], sys.argv[3]

tier_files = []
for m in sorted(glob.glob(os.path.join(repo, "tools/banktest/realrom/manifest-snes*.tsv"))):
    with open(m, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or line.startswith("id\t"):
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) > 2:
                tier_files.append(cols[1])

rows = []
with open(os.path.join(repo, "build/snes-rom-corpus/roms.tsv"), encoding="utf-8") as f:
    for r in csv.DictReader(f, delimiter="\t"):
        rows.append(r)

by_title = {}
for r in rows:
    if r["accepted"] != "yes" or r["checksumValid"] != "true":
        continue
    cur = by_title.get(r["title"])
    if cur is None or (cur["copier"] != "no" and r["copier"] == "no"):
        by_title[r["title"]] = r

file_title = {r["file"]: r["title"] for r in rows}
ordered, seen_titles, seen_files = [], set(), set()
for fn in tier_files:
    if fn in seen_files or not os.path.exists(os.path.join(romdir, fn)):
        continue
    seen_files.add(fn)
    seen_titles.add(file_title.get(fn))
    ordered.append(fn)
ntier = len(ordered)
for t in sorted(by_title):
    if t in seen_titles:
        continue
    ordered.append(by_title[t]["file"])

with open(out, "w", encoding="utf-8") as f:
    for fn in ordered:
        f.write(os.path.join(romdir, fn).replace("\\", "/") + "\n")
print(f"tier={ntier} total={len(ordered)}")
