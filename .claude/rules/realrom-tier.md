---
paths:
  - "src/main/java/**"
  - "ghidra_scripts/**"
  - "tools/banktest/**"
  - "data/**"
---

# Real-ROM tier: sets, staleness, ROM dirs, patched decompiler

<!-- Moved verbatim from CLAUDE.md (grm-yaat). Loaded only when a file matching the paths above is read. -->

**Selection is by positional SET NAME, not a flag per platform (bead grm-ughg).** This mirrors
`build-and-test.sh`'s chunk vocabulary — the in-repo precedent for exactly this problem — and
replaced a design where a flag selected a platform-specific subset and this file spent three
paragraphs warning which third of the tier each flag actually covered (a bare `check` meant the
curated NES set alone, `--all` didn't mean "all", `--snes` was a fourth undocumented meaning of
the same word). Sets **compose** and are deduplicated by id, so naming several is safe:

| name | rows | what |
|---|---|---|
| `core` | 5 | Always-run floor: the two stable grm-mu7 victims, the thread-pin canary, and two controls. **The default for a bare `check`.** |
| `nes-curated` | 14 | Curated NES board-representative set (one title per shipped board) |
| `nes-gme` | 20 | NES game-music-extraction titles of interest |
| `snes-cart` | 13 | SNES alt-board cartridge loader sample (loader layout only, `-noanalysis`) |
| `nes` | 34 | platform group: every NES set (`nes-curated` + `nes-gme`) |
| `snes` | 13 | platform group: every SNES set (`snes-cart`) |
| `all` | 47 | every set on every platform |

**A bare `check` now runs `core`, not the curated NES set** — the owner's ruling on grm-ughg.
`core` is a *new* always-run floor, not a renamed manifest: it is a cross-manifest subset of
existing rows (kicarus, cv2, tmnt, smb, zelda), assembled to be cheap (measured 46s) so there is
no longer an excuse to run nothing. It does **not** satisfy the full-tier requirement below —
see that paragraph.

**The old flags still work, as deprecated aliases that print a one-line note:** `(no flag)` used
to mean `nes-curated`, and is now spelled `nes-curated`; `--gme` → `nes-gme`; `--all` → `nes`;
`--snes` → `snes`. Note `--all` still maps to exactly what it always meant — both NES manifests,
33 rows — that part of the old contract is honored, not broken. The word that changed meaning is
the *bare, unflagged* `all`: it now spans every platform (47 rows), because a word that didn't
mean what it said is what grm-ughg was filed to fix.

**Multi-platform runs now work in one invocation.** `all` runs NES and SNES rows together;
every per-row parameter (ROM-dir env var, image extensions indexed, loader, dump script,
import args, whether the row refreshes the staleness stamp) is resolved per row from
`tools/banktest/realrom/platforms.tsv` rather than fixed once per invocation, so adding a
platform is a table row, not a code change. A platform whose ROM-dir variable is unset SKIPs its
rows loudly rather than killing the run — `all` is usable by someone holding only one platform's
images — but if *no* platform has any dirs the run still refuses outright with a nonzero exit;
this tier never reports a clean gate for something that did not execute.

The SNES rows still import with `-noanalysis`: they are LOADER rows (block inventory,
byte-mapped mirrors, IO typing, entry point), nothing `SnesRealRomDump.java` emits depends on
auto-analysis, and skipping it is both much faster on a 4–6 MB cartridge and immune to the
analyzer jitter that makes some NES rows unstable. For the same reason a SNES row never
refreshes the `REALROM STALENESS:` stamp described below (`platforms.tsv` declares
`stamps_staleness=no` for it) — that stamp answers "has anyone checked real-ROM *analysis*
regressions at this commit", which a `-noanalysis` loader pass answers not at all.

`nominate` is NES-only and refuses SNES rows rather than emitting garbage (it decodes iNES
headers). Select SNES rows from the `grm-9nxj.13` corpus survey's
`build/snes-rom-corpus/roms.tsv` instead, which carries name, size, sha256 and every parsed
header field — that is where the thirteen rows and their hashes came from.


Both `realrom-test.sh` and `build-and-test.sh check` print a `REALROM STALENESS:` line naming the
commit (or "absent") of the last real-ROM run *that actually verified rows*, and, as of grm-ughg,
a third line naming which sets that run resolved — including a run that ended `FAIL` on the
known-baseline rows below, since the point is "did anyone run this lately", not "did it pass";
only a run that matched no ROMs at all leaves the stamp untouched. A `core`-only run reports
that plainly ("sets: core... does NOT satisfy the full-tier requirement for analysis changes"),
and a stamp written before grm-ughg reads as "unknown (pre-grm-ughg stamp)" rather than guessing
its scope. A gate that never ran that tier, or ran only its floor, says so out loud instead of
reporting a quiet green. Do not treat a stale/absent/floor-only stamp as informational only — if
it names a commit behind changes you are about to commit that touch analysis behaviour, run
`check nes` before committing, per the paragraph above.

**A run that did not cover its sets in full is stamped `PARTIAL`, with counts** — because naming
the sets is a *more specific* claim than the pre-grm-ughg stamp made, and would be a wronger one
if the run only touched some of their rows. Both causes count, and the second is the dangerous
one: `--only`/`--except` filtering is partial on purpose and the caller knows it, whereas a
**SKIPPED** row means the ROM was not found, which is usually a wrong dir list rather than a
missing image (see the `GRM_ROM_DIR` paragraph below). Counting only the deliberate cause would
have left a run where 6 of 33 rows ran and 27 ROMs went unfound stamping identically to a clean
full-tier pass. The stamp may under-claim; it must never over-claim. It stays a *whole-run*
signal, though — it cannot say WHICH rows are stale. For that, use the per-row mode (`grm-eawl`):

```bash
bash tools/banktest/realrom-test.sh coverage [SET ...] [--only|--except <ids>] [--no-build]
```

It is **read-only**: no imports, no ROM dirs needed, no state file, never fails a run (seconds, plus
the usual `stageExtensionForTests` preflight). For each selected row it computes `realrom_cache_key()`
and reports `ran` if `build/realrom-cache/<key>.dump` exists, else `--`. Decisions worth knowing:
(1) **it stages the build first, like `check`** (honouring `--no-build`/`GRM_SKIP_BUILD`), because
`EXT_ID` is in the key and must be the build a `check` would use right now — under `--no-build` it
reports against whatever is installed, and the banner names that identity; (2) **it uses the
manifest's pinned ROM sha256**, not a hash of the file: a cache entry only exists if the dump's own
sha matched that pin, so the two are equivalent and no ROM is found or hashed; a row whose ROM is
absent just reads `--`. **`ran` means imported and cached, NOT matched-its-golden** — a failing row
(`megaman`, `wizwarr`, or any drifting golden) also reads `ran`, deliberately, per grm-6kv. The key
also includes `REALROM_EXTRA_PRESCRIPT`, `GRM_THREAD_PIN` and the toolchain id, so run it with the
same environment as the `check` you are asking about. The cache is per worktree, so a fresh
worktree reads `--` everywhere.

`GRM_ROM_DIR` is set per machine (`.claude/settings.local.json`, gitignored) and holds **several
space-separated dirs**, because the curated manifest is split across more than one and the driver
indexes each at **depth 1 only**. The driver reads it as `ROM_DIRS=($GRM_ROM_DIR)` — unquoted,
so it splits on *any* whitespace with no escaping: multiple dirs separated by spaces work, but a
**single directory whose own name contains a space cannot be represented** this way (pass it on
the command line instead, where each argument is a distinct dir regardless of its contents). So:
**never conclude "this machine doesn't have the ROM" from a `SKIP`** — suspect the dir list first,
and look at the dirs the driver prints beside the skip count. `smb3` was blessed 2026-08-16 once a
hand pass established that its two remaining warnings are honest (`FUN_c542` really is a
bank-switch helper — `c5f5` is inside its body — so the output was right and the golden was two
lines stale). The long-standing "golden correct, output wrong; never bless it" rule was written
before `grm-67g` closed the `ca23`/`ca2e` half of that diff, and no longer applies.

**The install carries a LOCALLY PATCHED `decompile.exe`, and the real-ROM tier says which build
it ran on** (`grm-qp5x.3`, owner ruling 2026-09-20). Stock Ghidra 12.1.3 (GP-6936, upstream issue
#9655) rewrites every 6502 `JSR`'s return-address store into a join varnode and destroys
bank-argument recovery on `megaman` and `wizwarr` (`grm-9wl6`); the three-hunk fix from
`grm-qp5x.2` ships in no release, so the reference machine's install runs a MinGW build of the
`Ghidra_12.1.3_build` tag with that patch, and `megaman`/`wizwarr` are blessed on it. 12.1.4
changed no decompiler source (Java or C++) and still has the bug, so the same patched binary was
carried over unchanged on the 12.1.4 retarget (`grm-rap8`). The stock binary sits beside it as
`decompile.exe.stock-12.1.4`. Every runner prints `== decompiler: … ==`
naming the build by sha256 (`grm_decompiler_build_name` in `tools/banktest/lib/common.sh`), and the
`REALROM STALENESS` stamp records it, so **a `megaman`/`wizwarr` failure whose banner says `12.1.x
stock` is the missing patch, not a regression**. The candidate cache keys on the same hash, so a
swap can never serve the other build's dump. `rcransom` was re-blessed at
1221/5722 on it (owner, 2026-09-20, `grm-qp5x.4`): the patch turned out to be innocent — stock in
a shadow install gives the same numbers — and the old 6434 was a 128-entry jump-table over-read
that only one configuration ever produced; the real blocker is a decompiler crash on `FUN_9314`
(`grm-gz42`). See `grm-qp5x`, and the **`realrom-current-fails`** bd
memory for the current, authoritative row list — that memory is the single place a row's status
lives, is revised as rows get fixed or reclassified, and supersedes any older summary including
this one. (It replaced `realrom-expected-baseline-fails`, which was only half-authoritative: it
was never itself updated when a *later* memory superseded its `megaman` paragraph, so it named a
jitter signature that no longer applies while still calling itself current. Its durable method
content — invocation, manifest-set semantics, cache and A/B mechanics — now lives in
`realrom-howto`, which carries no row-status content and so cannot rot the same way.) To
decide whether some *other* movement is yours, use **`tools/banktest/ab-test.sh`** (grm-5jjs)
rather than the older hand-run stash/rebuild/diff dance: it puts each side in its own throwaway
`git worktree` (so each side gets its own isolated `build/ghidra-home` and "forgot to rebuild
between sides" is structurally impossible), enforces that the two sides actually differ before
trusting anything, and diffs the two sides' dumps directly. See `tools/banktest/ab-test.sh
--help` and the `realrom-ab-needs-rebuild`/`realrom-howto` memories, revised for it.
**Known caveat:** the script's own "sides differ" check is based on `ext_identity()`, which was
measured (2026-08-29) to differ across two builds of the *same* commit built in two different
worktree paths, even though the resulting dumps were byte-identical — almost certainly build
output (e.g. a Ghidra GDT archive) embedding something path/build-instance-specific. Treat an
`ext_identity()` mismatch as informative, not proof of a real source difference; the dump-vs-dump
diff `ab-test.sh` prints is the reliable signal regardless.

**Editing the decompiler's C++ (`$GRM_GHIDRA_SRC/.../src/decompile/cpp`) to rebuild that patched
binary? Enable the `clangd-lsp` plugin first** — it is off by default on purpose. `bd recall
cpp-decompiler-work-enable-clangd-lsp` has the switch, the `compile_flags.txt` contents (MinGW
target; they come from the Makefile's `ghidra_opt` target, NOT `buildNatives.gradle`), how to
re-derive them, and which clangd errors are real.

When none of the selected sets' platforms have a ROM-dir variable set (`GRM_ROM_DIR` for NES,
`GRM_SNES_ROM_DIR` for SNES) and no romdir is passed, `realrom-test.sh` refuses to run (nonzero
exit, loud stderr message naming the variable(s) it wanted) rather than silently doing nothing —
it never reports a clean gate for a tier that did not execute. A multi-platform run with only
*some* dirs set still executes; it SKIPs the platform it can't see rather than refusing.
