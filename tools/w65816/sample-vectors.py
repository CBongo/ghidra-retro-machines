#!/usr/bin/env python3
"""Vendors a deterministic sample of the SingleStepTests/65816 vector suite (bead grm-9nxj.3).

The full suite is 512 files (`v1/<hex>.n.json` native + `v1/<hex>.e.json` emulation, all 256
opcodes), 10,000 cases each, ~2.87 GB uncommitted -- far too large to commit, mirroring the
existing SPC700 sample split (`tools/spc700/sample-vectors.py`, see its own doc for the shape of
this ruling). This script produces the vendored slice: reads a full clone of
https://github.com/SingleStepTests/65816 and writes the first N cases of each of the selected
`v1/<hex>.<mode>.json` files to `src/test/resources/w65816-vectors/`, plus a MANIFEST.txt
recording provenance and exactly which opcodes are covered.

Unlike the SPC700 script, this one does NOT default to "every opcode": the 65816 suite is 20x
the SPC700 case count (5.12M cases total across all 256 opcodes x 2 modes), and downloading a
full clone is explicitly out of scope for routine sampling on a machine that does not have one
(bead grm-9nxj.3's brief) -- callers name the opcodes they want via --opcodes, and the script
covers exactly those, both `.n` and `.e`.

The suite's cases are already effectively randomly ordered (each file was generated
independently) -- taking a prefix is deliberately NOT followed by a seeded shuffle, for the same
reason as the SPC700 script: a shuffle is one more thing an agent regenerating this sample later
would have to reproduce exactly, for no benefit over a plain prefix.

Usage:
    python3 tools/w65816/sample-vectors.py --source <full-clone-dir> [--n 32]
        [--dest src/test/resources/w65816-vectors]
        [--opcodes a9,a2,c0,e0,69,e9,c2,e2,fb,af,54,44,08,28,40,22]

    # or, opcode files already sitting in one directory (e.g. downloaded one at a time and about
    # to be deleted -- see the class doc on why this repo does not vendor a full clone):
    python3 tools/w65816/sample-vectors.py --source <dir-of-loose-v1-style-files> --loose

The full clone is NOT vendored by this script and is not this repo's job to fetch automatically
(network access during a build is exactly what the sample avoids needing) -- point --source at a
`git clone --depth 1 https://github.com/SingleStepTests/65816 <dir>` you made yourself, kept
outside the repo, or (with --loose) a scratch directory holding a handful of `v1/`-shaped files
fetched by hand.
"""
import argparse
import json
import pathlib
import subprocess
import sys

DEFAULT_OPCODES = [
    "a9", "a2", "c0", "e0", "69", "e9", "c2", "e2", "fb", "af", "54", "44", "08", "28", "40", "22",
]
MODES = ["n", "e"]


def git_commit(clone_dir: pathlib.Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True)
        return out.stdout.strip()
    except Exception as e:  # pragma: no cover - best-effort provenance only
        return f"<unknown: {e}>"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True, type=pathlib.Path,
        help="path to a full clone of github.com/SingleStepTests/65816, or (with --loose) a "
            "directory directly holding <hex>.<mode>.json files")
    ap.add_argument("--dest", type=pathlib.Path,
        default=pathlib.Path("src/test/resources/w65816-vectors"),
        help="output directory (default: src/test/resources/w65816-vectors, relative to cwd)")
    ap.add_argument("--n", type=int, default=32,
        help="cases to keep per opcode/mode file (default: 32)")
    ap.add_argument("--opcodes", default=",".join(DEFAULT_OPCODES),
        help="comma-separated opcode hex bytes to sample, lowercase, no 0x prefix "
            "(default: the grm-9nxj.3 subset chosen to exercise width machinery and "
            "65816-only forms)")
    ap.add_argument("--loose", action="store_true",
        help="--source is a flat directory of <hex>.<mode>.json files (e.g. fetched one at a "
            "time from raw.githubusercontent.com), not a git clone with a v1/ subdirectory")
    ap.add_argument("--commit", default=None,
        help="record this as upstream_commit in MANIFEST.txt instead of resolving --source as a "
            "git repo (needed with --loose, where --source is not a clone)")
    args = ap.parse_args()

    src_dir = args.source if args.loose else (args.source / "v1")
    if not src_dir.is_dir():
        print(f"FAIL: {src_dir} does not exist -- is --source a clone of "
            "SingleStepTests/65816 (it must contain a v1/ directory), or did you mean --loose?",
            file=sys.stderr)
        return 1

    opcodes = [o.strip().lower() for o in args.opcodes.split(",") if o.strip()]
    if not opcodes:
        print("FAIL: --opcodes resolved to an empty list", file=sys.stderr)
        return 1

    args.dest.mkdir(parents=True, exist_ok=True)
    commit = args.commit if args.commit else git_commit(args.source)

    written = 0
    total_cases = 0
    missing = []
    for opcode in opcodes:
        for mode in MODES:
            src_file = src_dir / f"{opcode}.{mode}.json"
            if not src_file.is_file():
                missing.append(src_file.name)
                continue
            with src_file.open("r", encoding="utf-8") as f:
                cases = json.load(f)
            sample = cases[:args.n]
            dest_file = args.dest / src_file.name
            with dest_file.open("w", encoding="utf-8", newline="\n") as f:
                json.dump(sample, f, indent=1)
                f.write("\n")
            written += 1
            total_cases += len(sample)

    if missing:
        print(f"FAIL: {len(missing)} expected file(s) not found under {src_dir}: "
            f"{', '.join(missing)}", file=sys.stderr)
        return 1

    manifest_lines = [
        "# Generated by tools/w65816/sample-vectors.py -- do not hand-edit.",
        "# Regenerate: python3 tools/w65816/sample-vectors.py --source <full-clone-dir>",
        "#     --opcodes " + ",".join(opcodes),
        "#",
        "upstream_repo: https://github.com/SingleStepTests/65816",
        f"upstream_commit: {commit}",
        f"cases_per_file: {args.n}",
        "source_pattern: v1/<opcode-hex>.<n|e>.json",
        f"opcodes_covered: {','.join(o.upper() for o in opcodes)}",
        f"opcodes_covered_count: {len(opcodes)} of 256 -- see MANIFEST.txt's own note on partial "
            "coverage",
        f"file_count: {written}",
        f"total_cases_written: {total_cases}",
    ]
    (args.dest / "MANIFEST.txt").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

    print(f"wrote {written} files, {total_cases} cases, to {args.dest}")
    print(f"upstream commit: {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
