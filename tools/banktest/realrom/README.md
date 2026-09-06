# Hash-pinned real-ROM regression set

`manifest.tsv` is the row list for the optional real-ROM tier — a regression net that runs
the shipped NES board descriptors against *actual commercial cartridges*, the fidelity
check synthetic fixtures can't give. `manifest-snes.tsv` (bead `grm-9nxj.15`) does the same
job for the **SNES cartridge loader**, from a different environment variable and against a
different platform. Neither is part of the default gate. See
[`docs/testing.md`](../../../docs/testing.md) for where this tier sits among the others,
and `../realrom-test.sh` for the driver.

**ROM binaries are not committed.** They are copyrighted and user-supplied; you point the
driver at directories you already have:

```bash
bash tools/banktest/realrom-test.sh check [SET ...] [--only|--except <ids>] <romdir> [<romdir> ...]
bash tools/banktest/realrom-test.sh bless [SET ...] [--only|--except <ids>] <romdir> [<romdir> ...]
```

(or set `GRM_ROM_DIR`/`GRM_SNES_ROM_DIR`). The goldens under `expected/` — our derived,
copyright-safe analysis metadata, never ROM bytes or disassembly — *are* committed.

## The sets

Row selection is by **positional set name** (bead `grm-ughg`), not a flag per platform. Sets
are declared in [`sets.tsv`](sets.tsv), and platform groups (every set on one platform, plus
the driver's own `all`, every set on every platform) are derived from
[`platforms.tsv`](platforms.tsv) — see "`sets.tsv` and `platforms.tsv`" below. `--list-sets`
prints the resolved table. Sets **compose** and are deduplicated by id, so naming several is
safe.

| set | platform | manifest(s) | rows | what |
| --- | --- | --- | --- | --- |
| `core` | nes | both | kicarus, cv2, tmnt, smb, zelda | Always-run floor (~46s measured): the two stable grm-mu7 victims, the thread-pin canary, and two controls. **The default for a bare `check`.** |
| `nes-curated` | nes | `manifest.tsv` | every row | The curated NES minimum: one representative title per shipped board, plus fuller coverage of the boards where a single title proves least — Bandai FCG (mappers 16/157/159) and GxROM (66), the newest additions when the set was assembled. |
| `nes-gme` | nes | `manifest-gme.tsv` | every row | The expanded NES reference set: titles of interest to the parent game-music-extraction project. Deliberately *not* a gate — a reference point for planning and an occasional thorough check. |
| `snes-cart` | snes | `manifest-snes.tsv` | every row | The SNES loader set: thirteen cartridges covering the alt-board axis the eleven-ROM GME corpus does not — SA-1, SuperFX 1/2, DSP-1 in both LoROM and HiROM form, S-DD1, CX4, the one genuine ExHiROM, a clean/copier pair on each of two titles, and one cartridge whose declared map mode contradicts its header location. |

Platform groups, derived from `platforms.tsv`: **`nes`** (`nes-curated` + `nes-gme`, 33 rows —
what `--all` used to mean, and still does under that spelling) and **`snes`** (`snes-cart`, 13
rows — what `--snes` used to mean). **`all`** is the driver's own union of every set on every
platform (46 rows) — the word that changed meaning in `grm-ughg`, since before it there was no
bare `all` at all, only the `--all` flag meaning "both NES manifests."

```bash
bash tools/banktest/realrom-test.sh check <romdir>              # core floor (default), 5 rows
bash tools/banktest/realrom-test.sh check nes-curated <romdir>  # curated NES set only
bash tools/banktest/realrom-test.sh check nes-gme <romdir>      # NES GME set only
bash tools/banktest/realrom-test.sh check nes <romdir>          # both NES manifests (formerly --all)
bash tools/banktest/realrom-test.sh check snes <romdir>         # SNES set only (formerly --snes)
bash tools/banktest/realrom-test.sh check all <romdir>          # every set, every platform
```

**The old flags still work, as deprecated aliases that print a one-line note:** `(no flag)` →
`nes-curated`, `--gme` → `nes-gme`, `--all` → `nes`, `--snes` → `snes`. The flags/sets *select*
rather than adding to a running total, and every run announces which sets it resolved and the
rows they expanded to — `--gme` silently meaning "the GME set *plus* the curated thirteen" would
be a costly surprise under `bless`, re-blessing goldens you never asked about.

**`nes` means the two NES manifests, and deliberately does *not* include `snes`.** The SNES rows
come from a different environment variable, a different loader (`SnesRomLoader`), and a
different dump script, and they assert loader *layout* rather than banking analysis — so folding
them into the NES platform group would make "the NES tier" silently SKIP thirteen rows on any
machine that has NES ROMs and no SNES ones. Reach for `all` to run both platforms in one
invocation: a platform whose ROM-dir variable is unset SKIPs its rows loudly rather than killing
the run, and only refuses outright if *no* platform has any dirs at all.

For the same reason, a `snes`-only run **does not refresh the `REALROM STALENESS:` stamp** —
`platforms.tsv` declares `stamps_staleness=no` for the SNES platform, not a check on the set's
name. That stamp answers one question — "has anyone checked real-ROM *analysis* regressions at
this commit" — and the SNES rows import with `-noanalysis`. The run says so out loud rather than
letting a loader pass mark the analysis tier freshly verified. As of `grm-ughg` the stamp also
records, as a third line, which sets a run resolved, so a `core`-only run is visibly *not* the
full-tier requirement below, and a stamp written before this change reads as "unknown
(pre-grm-ughg stamp)" rather than guessing its scope.

## `sets.tsv` and `platforms.tsv`

Two small tables carry everything that used to be a `case` block or a scattered flag check:

- **`sets.tsv`** (`set`, `platform`, `manifests`, `rows`, `description`) names each set, which
  platform it belongs to, which manifest file(s) it draws from, and which row ids it selects
  (`*` for "every row in those manifests," or a comma list for a cross-manifest subset like
  `core`). Adding a set — a new curated slice of an existing manifest, say — is a row here.
- **`platforms.tsv`** (`platform`, `rom_dir_env`, `image_exts`, `copy_ext`, `loader`,
  `dump_script`, `import_args`, `nominate`, `stamps_staleness`, `fallback_chunk`) names
  everything that differs *per platform*: the ROM-dir environment variable, the file extensions
  the sha256 index scans, the extension of the temp copy the import sees, the Ghidra loader,
  the dump post-script, extra `analyzeHeadless` arguments (`-noanalysis` for SNES), whether
  `nominate` supports the platform, whether a row on this platform refreshes the
  `REALROM STALENESS:` stamp, and which `build-and-test.sh` chunk to name in an isolation hint.
  **Adding a platform — a future PSX ISO tier, say — is a row in each table, not a code
  change**: `realrom-test.sh` resolves every per-row parameter from `platforms.tsv` rather than
  branching on platform name.

### What differs per platform

Everything platform-specific is one `case` block near the top of `realrom-test.sh`, not
branches scattered through it: the manifest, the loader, the dump `-postScript`, the ROM-dir
environment variable, the file extensions the sha256 index scans (`.nes`; or `.sfc .smc .fig
.swc` for SNES — a SNES collection uses all four interchangeably and the copier-headered rows
are precisely the `.smc` ones), the extension of the temp copy the import sees, and whether
analysis runs at all. The SNES rows import with `-noanalysis`: they are loader rows, nothing
the dump emits depends on auto-analysis, and skipping it is both much faster on a 4–6 MB
cartridge and immune to the analyzer jitter that makes two NES rows unstable.

The SNES rows use **`SnesRealRomDump.java`**, not `RealRomDump.java`, and not
`VerifyBankTest.java`. `RealRomDump` is entirely about the NES banking model — overlay
spaces, cross-bank references, bank-switch comments — and `SnesRomLoader` creates *no*
overlays at all, so every one of those counters would read zero on every row forever.
`VerifyBankTest` was the other tempting reuse and is the worse one: it dispatches on fixture
*name*, an unrecognized name falls through to the C64 default and prints plausible nonsense
instead of failing, and its `snestest` branch is written against the synthetic fixture's own
specifics (reset target `$008000`, a single `ROM_00_8000`) that no real cartridge shares.
What `SnesRealRomDump` emits instead is what a cartridge import actually establishes: the
parsed header (map type, copier flag, map-mode and chipset bytes, declared sizes, title,
FastROM, and whether the declared mapping agrees with where the header was found), the ten
CPU vectors, a sorted block inventory with each byte-mapped block's mirror source, a
per-mirror **boolean** saying whether reading through it yields its source's bytes, block and
symbol counts, and the reset entry point. No ROM bytes, ever.

### The clean/copier pairs

Two titles appear **twice**, differing only in the 512-byte copier header the dumping
hardware prepended: `pilotwings`/`pilotwingscopier` and `starfox`/`starfoxcopier`. This is
the real-ROM form of the principle the synthetic `snestest`/`snestestcopier` fixtures already
encode — a copier-detection regression shifts *every* offset in the image, so it cannot pass
by matching one golden of a pair.

`pilotwings` is the cleaner control: its two goldens differ **only** in the program name, the
sha256, and `copier=true`, because the loader strips the header and the two images are
otherwise the same cartridge. The Star Fox pair is also a *revision* pair (V1.0 vs Rev 2), so
its diff legitimately includes moved vectors and a moved entry point; useful, but it cannot
isolate the copier variable the way Pilotwings does.

### Two rows that pin a disagreement rather than a success

- **`marioearlyyears`** (Mario's Early Years - Fun with Numbers) declares HiROM but its header
  sits at `$7FC0`, where a LoROM header belongs. `SnesRomLoader` **reports and proceeds**
  rather than refusing (see its "Reported, not refused" comment) — the header validated its
  own checksum, so this is a real cartridge saying something surprising, and the map mode is
  what the hardware wires. This row pins that behaviour.
- **`tofphant`** (Tales of Phantasia) is the corpus's only genuine ExHiROM, 6 MB and
  copier-headered, and its header is likewise at `$7FC0`. Its golden pins **known-incomplete**
  ExHiROM behaviour: `SnesAddressMap` models ExHiROM only as far as HiROM arithmetic over the
  first 4 MiB, so this cartridge's blocks past 4 MB wrap to bank `$00` and swallow the
  low-RAM and IO windows (the golden shows `blocks.volatile 0` and a `ROM_00_0000` block), and
  the HiROM system-bank mirrors are created a full 64 KiB wide where hardware shows only the
  upper half. **Do not read this golden as an assertion that the layout is right.** It is a
  deterministic record of what the loader does today, so that fixing it shows up as a
  reviewable diff instead of silently.

### Deliberately excluded

**`Super Adventure Island (USA).sfc` is not here, and that is not an oversight.** Its map-mode
byte parses as `MapType.UNKNOWN`, so `SnesRomLoader` refuses it outright — it needs a
*rejection-shaped* row, not a golden. `analyzeHeadless` exits 0 even when a loader refuses
(the `headless-rejection-exit-zero` bd memory; CLAUDE.md's loader rule), so such a row must
assert on log content and on the absence of a committed program, which this driver has no
shape for. It belongs to bead `grm-9nxj.14` and becomes an ordinary positive row once the
map-type override option exists there.

Each row costs a headless import — median ~7s, worst ~52s, so a full 33-row `check nes` run
(formerly `--all`) is about 6 minutes (measured 2026-08-31, bead `grm-yfma`; see docs/testing.md "How long the
gates actually take"). The expanded set is opt-in because it needs user-supplied hash-pinned
ROMs this repo cannot ship, not because it is slow. An id must be unique **across every manifest** — ids name goldens and name the ROM
copy the import sees, so a duplicate would import twice and let the second row silently
overwrite the first's golden. The driver hard-errors on that rather than letting it look
like success.

### Populating the expanded set (NES only)

`nominate` is **NES-only** and refuses SNES rows rather than emitting garbage: it decodes iNES
headers and resolves `machines/nes-*.yaml`, neither of which means anything for a SNES
cartridge. SNES rows are selected instead from the `grm-9nxj.13` corpus survey
(`bash tools/banktest/build-and-test.sh check snes-rom-corpus` produces
`build/snes-rom-corpus/roms.tsv`), which emits name, size, sha256 and every parsed header
field per image. That is where the current thirteen rows and their hashes came from;
re-deriving a hash by hand is how a wrong pin gets in.

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
| `title` | Human-readable dump name. Display only — matching is by hash. On the SNES rows this is the **exact filename** the corpus survey recorded, so a hash miss can say *which* dump was expected rather than only that one is missing (the `grm-9nxj.15` schema note: pin the input, and let the failure name it). |
| `sha256` | Whole-file SHA-256 of the pinned dump. Compared case- and whitespace-insensitively, and re-checked against the hash Ghidra itself computed after import. |
| `mapper` | NES: iNES mapper number. SNES: the **map-mode byte**, e.g. `0x23`. **Documentation only** — parsed but never used by the driver. |
| `board` | NES: board descriptor the mapper selects. SNES: a descriptive board id (`snes_sa1`, `snes_superfx`, `snes_dsp`, `snes_sdd1`, `snes_cx4`, `snes_lorom`, `snes_hirom`, `snes_exhirom`). **Documentation only**, same as `mapper`. |
| `golden` | Golden file under `expected/`. Defaults to `<id>.dump` when empty. |
| `loader_opts` | Optional; extra `analyzeHeadless` arguments for this title. Empty on most rows. |
| `member` | **Reserved, empty on every row today.** Row identity is currently the whole-file
  SHA-256 in `sha256` alone. When it is non-empty, identity becomes the pair (container
  SHA-256 in `sha256`, member path in `member`) — e.g. one file inside a PSX ISO or a C64
  `.d64` image — rather than a change in meaning of `sha256` itself. Container support is
  **not implemented**; the column exists so that a future container-based platform is a code
  change in the row-resolution path, not a schema migration across every existing manifest. |

**Every row carries all eight fields**, so a row whose trailing columns are empty (`loader_opts`,
`member`, or both) still ends in the right number of tabs. GitHub's tabular viewer wants a
uniform column count and renders ragged rows badly. The parser treats a trailing empty field and
a missing one identically, so an editor that strips trailing whitespace costs you the rendering,
never the test.

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

Three read-only probes answer "why did this title resolve nothing?", run alongside a normal
import via `REALROM_EXTRA_POSTSCRIPT`. Give each its **own** invocation — the cache key does
not cover them, so a cached `bless` would skip the import they need. Their output is
diagnostic-only and never reaches a golden (the driver's awk carve extracts only the
`REALROM` block). Read the scripts' headers for details; all three are commented at length.

```bash
REALROM_EXTRA_POSTSCRIPT=BankReachProbe.java    bash tools/banktest/realrom-test.sh check --only <id> <romdir>
REALROM_EXTRA_POSTSCRIPT=HelperShapeProbe.java  bash tools/banktest/realrom-test.sh check --only <id> <romdir>
REALROM_EXTRA_POSTSCRIPT=BankConsumerProbe.java bash tools/banktest/realrom-test.sh check --only <id> <romdir>
```

They divide the pipeline in three, and it is worth picking the right one rather than running
all three: `BankReachProbe` asks whether the mechanism **write** was seen, `HelperShapeProbe`
asks whether the **call** into a switch helper was resolvable, and `BankConsumerProbe` asks
whether anything **consumes** the switchable window once a bank is known.

- **`BankReachProbe.java`** — separates the three reasons a bank-switch store never fired:
  never disassembled, disassembled but in no function, or reachable and in a function yet
  never annotated. Runs on `memory-latch` (UxROM/AxROM/BNROM/Bandai FCG), `serial-shift`
  (MMC1) and `select-data` (MMC3) — all three take their range from the same `start`/`end`
  params; any other strategy is reported unsupported *by name* rather than silently probed.
  Its `today=` column is production's own output (a `bank ->` EOL comment, or a
  `Bank state becomes unknown here:` warning bookmark — the Phase-3
  `Bank state requirement violated:` bookmarks are excluded, they mark call sites), so it is
  authoritative rather than re-derived. The re-implemented `writesInRange` survives as the
  `mirror.*` columns purely as a cross-check: a non-zero `count mirror.disagree` means one of
  the two is wrong and is always worth chasing (grm-8cq, grm-8iy.2).
- **`HelperShapeProbe.java`** — board-agnostic. For every warning bookmark, reports the
  containing function, its callers (distinguishing `JSR` from a tail-call `JMP`, with the
  instructions preceding each call), the instructions feeding each site, and **which sites
  carry incoming flow of their own**. That last one finds mid-body entry points — an address
  the helper model cannot describe, because `findHelpers` keys on the containing *function*
  while the real argument convention belongs to the entry actually jumped to (grm-nju).
  Its **section 5** carries a private copy of `BoardBankAnalyzer.reachableEntries` and walks
  every call through it, reporting the hop chain, whether the entry reached is mid-body, and
  whether the argument is a constant — i.e. it answers "how much would this be worth?" before
  the work is done. That is how grm-nju was sized: bionic 4 of 5 call sites constant and all 5
  hop-only, ff1 54 of 59, and cv2/blmaster/tmnt zero hops (so **not** this bead's shape —
  their zero resolution has some other cause).
- **`BankConsumerProbe.java`** — the **consumer** side, i.e. the half the other two cannot
  see. Derives the switchable/fixed offset ranges from the descriptor (not from block names —
  on MMC1 the overlay-name union is `8000-ffff`, which cannot distinguish home-mode switchable
  `8000-bfff` from home-mode fixed `c000-ffff`, and that distinction is the whole question),
  censuses every reference into a switchable range by source bucket and ref type, counts
  indirect dispatches, and walks forward from each **fully-known non-home** switch site to see
  whether the recovered bank ever reaches a consumer. Its `refs.intoOverlay.retargeted` is the
  honest fix metric that `RealRomDump`'s `refs.intoOverlay` is not — the latter also counts
  intra-overlay references, which dominate on a healthy title (grm-jwh).
  Used in grm-8iy to refute a consumer-side gate hypothesis and localize all six remaining
  zero-resolvers to call-site helper-argument recovery instead.

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
