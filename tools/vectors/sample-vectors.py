#!/usr/bin/env python3
"""Vendors a deterministic sample of a SingleStepTests CPU vector suite (grm-2a2a.4).

One script for all three suites; `--cpu` picks the table row below. It replaces the near-clone
tools/{mos6502,w65816,spc700}/sample-vectors.py (beads grm-hzv8, grm-9nxj.3, grm-c9d.2).

The full suites are far too large to commit (SPC700 ~76 MB, 65816 ~2.87 GB), so the repo vendors
a sample, plus an env-var-gated full run against a separate clone. This script reads a full clone
of the upstream repo and writes the first N cases of each opcode file to the CPU's vendored
resource directory, plus a MANIFEST.txt recording provenance so the sample is regenerable.

The suites' cases are already effectively randomly ordered, so taking a prefix is deliberately NOT
followed by a seeded shuffle: a shuffle is one more thing an agent regenerating the sample later
would have to reproduce exactly, for no benefit. (65816 MVN/MVP are the one exception, below.)

Per-CPU differences:
  spc700   SingleStepTests/spc700 `v1/<hex>.json`, all 256 opcodes.
  mos6502  SingleStepTests/65x02 `6502/v1/<hex>.json`, all 256 opcodes. Deliberately ignores
           `nes6502/` (2A03, no decimal mode) and the 65c02 variants: this targets NMOS 6502 with
           illegal opcodes only.
  w65816   SingleStepTests/65816 `v1/<hex>.<n|e>.json` (native + emulation). Does NOT default to
           every opcode (5.12M cases): name them with --opcodes. MVN (54) and MVP (44) take the
           N cases with the SMALLEST initial A instead of a prefix, since their cycles arrays
           scale with A. MANIFEST.txt describes the whole destination directory, not just this
           run, so adding one opcode later does not erase the record of the rest.

Usage:
    python3 tools/vectors/sample-vectors.py --cpu {mos6502,w65816,spc700} --source <full-clone-dir>
        [--n 32] [--dest <override>]
        [--opcodes a9,a2,...]        (w65816 only)
        [--loose] [--commit <sha>]   (w65816 only: --source is a flat dir of <hex>.<mode>.json)

The full clone is NOT vendored and not this repo's job to fetch (network access during a build is
exactly what the sample avoids): `git clone --depth 1 <upstream repo> <dir>`, kept outside the repo.
"""
import argparse
import json
import pathlib
import subprocess
import sys

# 65816 subset chosen (grm-9nxj.3) to exercise width machinery and 65816-only forms.
W65816_OPCODES = [
    "a9", "a2", "c0", "e0", "69", "e9", "c2", "e2", "fb", "af", "54", "44", "08", "28", "40", "22",
]

CPUS = {
    "spc700": {
        "repo": "SingleStepTests/spc700", "subdir": "v1", "dest": "src/test/resources/spc700-vectors",
        "pattern": "v1/<opcode-hex>.json", "modes": None,
    },
    "mos6502": {
        "repo": "SingleStepTests/65x02", "subdir": "6502/v1",
        "dest": "src/test/resources/mos6502-vectors",
        "pattern": "6502/v1/<opcode-hex>.json", "modes": None,
    },
    "w65816": {
        "repo": "SingleStepTests/65816", "subdir": "v1", "dest": "src/test/resources/w65816-vectors",
        "pattern": "v1/<opcode-hex>.<n|e>.json", "modes": ["n", "e"],
    },
}

# 65816 block moves run to completion upstream (initial A capped at 999), so each case's cycles
# array is up to ~7 * (A+1) entries and a plain prefix came to 1.3-2.0 MB per file.
SMALLEST_INITIAL_A_OPCODES = {"44", "54"}


def pick_sample(cpu: str, opcode: str, cases: list, n: int) -> list:
    if cpu != "w65816" or opcode not in SMALLEST_INITIAL_A_OPCODES:
        return cases[:n]
    # sorted() is stable, so equal initial A keeps original file order.
    chosen = sorted(range(len(cases)), key=lambda i: cases[i]["initial"]["a"])[:n]
    return [cases[i] for i in sorted(chosen)]


def git_commit(clone_dir: pathlib.Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True)
        return out.stdout.strip()
    except Exception as e:  # pragma: no cover - best-effort provenance only
        return f"<unknown: {e}>"


def write_sample(path: pathlib.Path, sample: list) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(sample, f, indent=1)
        f.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cpu", required=True, choices=sorted(CPUS))
    ap.add_argument("--source", required=True, type=pathlib.Path,
        help="path to a full clone of the CPU's upstream suite (or, w65816 --loose, a flat "
            "directory of <hex>.<mode>.json files)")
    ap.add_argument("--dest", type=pathlib.Path, default=None,
        help="output directory (default: src/test/resources/<cpu>-vectors, relative to cwd)")
    ap.add_argument("--n", type=int, default=32, help="cases to keep per file (default: 32)")
    ap.add_argument("--opcodes", default=None,
        help="w65816 only: comma-separated lowercase opcode hex bytes (default: the "
            "grm-9nxj.3 subset)")
    ap.add_argument("--loose", action="store_true",
        help="w65816 only: --source is a flat directory, not a clone with a v1/ subdirectory")
    ap.add_argument("--commit", default=None,
        help="w65816 only: record this as upstream_commit instead of resolving --source as a "
            "git repo (needed with --loose)")
    args = ap.parse_args()

    cpu = args.cpu
    cfg = CPUS[cpu]
    if cpu != "w65816" and (args.opcodes or args.loose or args.commit):
        ap.error("--opcodes/--loose/--commit are w65816-only")
    dest = args.dest or pathlib.Path(cfg["dest"])
    script = "tools/vectors/sample-vectors.py"

    src_dir = args.source if args.loose else args.source / cfg["subdir"]
    if not src_dir.is_dir():
        print(f"FAIL: {src_dir} does not exist -- is --source a clone of {cfg['repo']} "
            f"(it must contain a {cfg['subdir']}/ directory)"
            + (", or did you mean --loose?" if cpu == "w65816" else "?"), file=sys.stderr)
        return 1

    if cpu == "w65816":
        opcodes = [o.strip().lower()
                   for o in (args.opcodes or ",".join(W65816_OPCODES)).split(",") if o.strip()]
        if not opcodes:
            print("FAIL: --opcodes resolved to an empty list", file=sys.stderr)
            return 1
        wanted = [(op, src_dir / f"{op}.{m}.json") for op in opcodes for m in cfg["modes"]]
        missing = [f.name for _, f in wanted if not f.is_file()]
        wanted = [(op, f) for op, f in wanted if f.is_file()]
    else:
        files = sorted(src_dir.glob("*.json"))
        if not files:
            print(f"FAIL: no *.json files found under {src_dir}", file=sys.stderr)
            return 1
        wanted = [(f.stem, f) for f in files]
        missing = []

    dest.mkdir(parents=True, exist_ok=True)
    commit = args.commit if args.commit else git_commit(args.source)

    written = 0
    total_cases = 0
    for opcode, src_file in wanted:
        with src_file.open("r", encoding="utf-8") as f:
            cases = json.load(f)
        sample = pick_sample(cpu, opcode, cases, args.n)
        write_sample(dest / src_file.name, sample)
        written += 1
        total_cases += len(sample)

    if missing:
        print(f"FAIL: {len(missing)} expected file(s) not found under {src_dir}: "
            f"{', '.join(missing)}", file=sys.stderr)
        return 1

    head = [f"# Generated by {script} --cpu {cpu} -- do not hand-edit."]
    common = [
        f"upstream_repo: https://github.com/{cfg['repo']}",
        f"upstream_commit: {commit}",
        f"cases_per_file: {args.n}",
        f"source_pattern: {cfg['pattern']}",
    ]
    if cpu == "w65816":
        # The manifest describes WHAT IS IN THE DIRECTORY, not what this invocation wrote:
        # deriving it from --opcodes once understated coverage (caught 2026-09-05).
        present = sorted({f.name.split(".")[0].lower() for f in dest.glob("*.json")
                          if len(f.name.split(".")) == 3})
        present_files = sorted(f.name for f in dest.glob("*.json"))
        manifest = head + [
            "# Regenerate the WHOLE sample against a full clone with:",
            f"#     python3 {script} --cpu w65816 --source <full-clone-dir>",
            "#         --opcodes " + ",".join(present),
            "# (this file lists every opcode present in the directory, not merely the ones the "
            "last",
            "#  invocation wrote, so adding one opcode later does not erase the record of the "
            "rest)",
            "#",
        ] + common + [
            "sampling_rule: first cases_per_file cases of each file, in file order; EXCEPT "
            "opcodes 44 (MVP) and 54 (MVN), which take the cases_per_file cases with the "
            "SMALLEST initial A (ties by file order), kept in file order, because their cycles "
            "arrays scale with A",
            "",
            "# PARTIAL COVERAGE -- READ THIS BEFORE TRUSTING A 'PASS' ROW FOR AN OPCODE NOT "
            "LISTED.",
            "# A passing baseline says nothing about the 256 - N opcodes this sample never runs.",
            f"opcodes_covered: {','.join(o.upper() for o in present)}",
            f"opcodes_covered_count: {len(present)} of 256",
            f"file_count: {len(present_files)}",
            f"files_written_this_run: {written}",
            f"cases_written_this_run: {total_cases}",
        ]
    else:
        manifest = head + [
            f"# Regenerate: python3 {script} --cpu {cpu} --source <full-clone-dir>",
            "#",
        ] + common + [f"file_count: {len(wanted)}", f"total_cases_written: {total_cases}"]
    (dest / "MANIFEST.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")

    print(f"wrote {written} files, {total_cases} cases, to {dest}")
    print(f"upstream commit: {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
