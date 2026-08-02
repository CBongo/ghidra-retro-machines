# Hash-pinned real-ROM regression set

`manifest.tsv` is the row list for the optional real-ROM tier — a regression net that runs
the shipped NES board descriptors against *actual commercial cartridges*, the fidelity
check synthetic fixtures can't give. It is **not** part of the default gate. See
[`docs/testing.md`](../../../docs/testing.md) for where this tier sits among the others,
and `../realrom-test.sh` for the driver.

**ROM binaries are not committed.** They are copyrighted and user-supplied; you point the
driver at directories you already have:

```bash
bash tools/banktest/realrom-test.sh check [--only|--except <ids>] <romdir> [<romdir> ...]
bash tools/banktest/realrom-test.sh bless [--only|--except <ids>] <romdir> [<romdir> ...]
```

(or set `GRM_ROM_DIR`). The goldens under `expected/` — our derived, copyright-safe
analysis metadata, never ROM bytes or disassembly — *are* committed.

## Coverage

One representative title per shipped board, plus fuller coverage of the boards where a
single title proves least — Bandai FCG (mappers 16/157/159) and GxROM (66), which were the
newest additions when this set was assembled.

## Why every row is pinned by hash

Each row pins one exact known-good dump by whole-file **SHA-256**, and the driver
hash-indexes the supplied directories rather than matching filenames. That makes the tier
filename-independent (sidestepping the parenthesis-rename and bad-dump-header traps) and
means a ROM that is **absent, or a different dump, SKIPs** — never a spurious FAIL. Only a
present, hash-matched ROM whose dump differs from its golden FAILs. A run that matches
nothing exits 0, so the tier is safe to ship for users with no ROMs at all.

## Columns

The file is tab-separated with a bare header row. It carries **no `#` comment block on
purpose**: GitHub's tabular viewer has no comment syntax, so line 1 becomes the column
headers and every other line becomes a row. Notes belong here, not in the data file.

| column | meaning |
| --- | --- |
| `id` | Short key. Names the row for `--only`/`--except`, and supplies the default golden name. An id not in this file is a hard error, never a silent no-op. |
| `title` | Human-readable dump name. Display only — matching is by hash. |
| `sha256` | Whole-file SHA-256 of the pinned dump. Compared case- and whitespace-insensitively, and re-checked against the hash Ghidra itself computed after import. |
| `mapper` | iNES mapper number. **Documentation only** — parsed but never used by the driver. |
| `board` | Board descriptor the mapper selects. **Documentation only**, same as `mapper`. |
| `golden` | Golden file under `expected/`. Defaults to `<id>.dump` when empty. |
| `loader_opts` | Optional; extra `analyzeHeadless` arguments for this title. Trailing column, so most rows simply end early. |

`loader_opts` is expanded **unquoted** onto the headless command line, and it is folded
into the candidate-dump cache key — so editing it forces a fresh import rather than
reusing a stale candidate.

Today only the `zelda` row uses it, to run `RunFromElsewhereTransfer.java` over a copied
code block. That string is a hand-authored per-title fact keyed by hash, living in the
test harness because the shipped extension currently has nowhere to put it;
[`docs/per-game-descriptors-design.md`](../../../docs/per-game-descriptors-design.md) §1.3
covers lifting it into a real per-game descriptor tier, after which this column can go
away.

## Adding a row

1. `sha256sum` the dump you intend to pin, and append a row.
2. `bash tools/banktest/realrom-test.sh check --only <id> <romdir>` — expect FAIL with a
   missing golden.
3. Review what the run reports, then `bless --only <id>` and inspect the new
   `expected/<id>.dump` before committing it.

## Bless discipline

Regenerate with `bless`, review the `expected/*.dump` diff, commit deliberately — same
rule as the other golden tiers. Because ROMs aren't in the repo, only someone holding the
pinned dump can re-bless a row.

`--except` earns its keep here: this tier's recurring shape is *one title deliberately
held back at a pre-regression golden while every other title needs re-blessing*.
`megaman` has been that title twice (grm-g73, then grm-hum), and blessing it would erase
the record those beads depend on.

## Line endings

`.gitattributes` pins `*.tsv` to LF. Without it, a `core.autocrlf=true` checkout leaves a
trailing `\r` on whichever field happens to be **last** on a row — which varies row to row,
since `loader_opts` is optional — and that `\r` rides into a path or an argument. It
surfaces as a mystifying "golden not found" for a file that plainly exists.
