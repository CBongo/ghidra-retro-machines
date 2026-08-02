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

## Two sets

| file | what it is | selected by |
| --- | --- | --- |
| `manifest.tsv` | The **curated minimum**: one representative title per shipped board, plus fuller coverage of the boards where a single title proves least — Bandai FCG (mappers 16/157/159) and GxROM (66), the newest additions when the set was assembled. | *(default)* |
| `manifest-gme.tsv` | The **expanded reference set**: titles of interest to the parent game-music-extraction project. Deliberately *not* a gate — it is a reference point for planning and an occasional thorough check. | `--gme` |
| both | The thorough pass. | `--all` |

```bash
bash tools/banktest/realrom-test.sh check <romdir>          # curated set
bash tools/banktest/realrom-test.sh check --gme <romdir>    # GME set only
bash tools/banktest/realrom-test.sh check --all <romdir>    # both
```

The flags **select** a set rather than adding to one, and every run announces which set it
picked. `--gme` meaning "the GME set *plus* the curated twelve" is a costly surprise under
`bless`, where it silently re-blesses goldens you never asked about.

Each row costs a ~1min+ headless import, which is the whole reason the expanded set is
opt-in. An id must be unique **across both files** — ids name goldens and name the ROM
copy the import sees, so a duplicate would import twice and let the second row silently
overwrite the first's golden. The driver hard-errors on that rather than letting it look
like success.

### Populating the expanded set

`nominate` does the three error-prone steps for you — hashing the dump, decoding the iNES
mapper byte (including the NES 2.0 and `DiskDude!`-archaic header forms that
`NesRomLoader` special-cases), and resolving which shipped board claims that mapper:

```bash
bash tools/banktest/realrom-test.sh nominate <romdir> [<romdir> ...]
```

It emits paste-ready rows. Where a ROM sits in a per-title subdirectory, that directory
name becomes the `id`; otherwise the file's base name does. Titles already pinned in
either manifest are reported rather than re-nominated, and it needs no Ghidra install.

A mapper no shipped descriptor claims is reported as a comment rather than a row. **That
is a board gap, not a bad dump** — it is the most useful thing the expanded set surfaces,
and a candidate for a new descriptor.

## A note on `wizwarr`

`wizwarr` in game-music-extraction means **Wizards & Warriors (U)**. The row this
repository originally called `wizwarr` is its *sequel*, Ironsword — so that row is now
`ironsword`, freeing the shorthand to mean what it means everywhere else. Both are worth
keeping: Ironsword's `FUN_ffc0` drove the store-forwarding work (grm-mej.1, grm-6pi) and
exercises idioms likely to appear elsewhere.

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
| `loader_opts` | Optional; extra `analyzeHeadless` arguments for this title. Empty on most rows. |

**Every row carries all seven fields**, so rows without `loader_opts` end in an explicit
empty final field — a trailing tab. GitHub's tabular viewer wants a uniform column count
and renders ragged rows badly. The parser treats a trailing empty field and a missing one
identically, so an editor that strips trailing whitespace costs you the rendering, never
the test.

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

## Diagnostics

Two read-only probes answer "why did this title resolve nothing?", run alongside a normal
import via `REALROM_EXTRA_POSTSCRIPT`. Give each its **own** invocation — the cache key does
not cover them, so a cached `bless` would skip the import they need. Their output is
diagnostic-only and never reaches a golden (the driver's awk carve extracts only the
`REALROM` block). Read the scripts' headers for details; both are commented at length.

```bash
REALROM_EXTRA_POSTSCRIPT=BankReachProbe.java  bash tools/banktest/realrom-test.sh check --only <id> <romdir>
REALROM_EXTRA_POSTSCRIPT=HelperShapeProbe.java bash tools/banktest/realrom-test.sh check --only <id> <romdir>
```

- **`BankReachProbe.java`** — separates the three reasons a **memory-latch** store never
  fired: never disassembled, disassembled but in no function, or reachable but invisible to
  `writesInRange`. It requires a `memory-latch` mechanism and reports an error on boards
  without one (MMC1 is `serial-shift`).
- **`HelperShapeProbe.java`** — board-agnostic. For every warning bookmark, reports the
  containing function, its callers (distinguishing `JSR` from a tail-call `JMP`), the
  instructions feeding each site, and **which sites carry incoming flow of their own**. That
  last one finds mid-body entry points — an address the helper model cannot describe, because
  `findHelpers` keys on the containing *function* while the real argument convention belongs
  to the entry actually jumped to (grm-nju).

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
