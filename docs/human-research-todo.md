# Human research TODO

Work that is **deliberately not agent work** — where a person with a disassembler, an emulator, or
a judgment call gets there faster and better than an agent burning tokens on a
build/measure/interpret loop.

This is a running list, not a snapshot. Add to it whenever an agent stops and asks (see the
"Stop and ask when a human would be more efficient" directive in `CLAUDE.md`), and strike items as
they're answered.

**Where answers go:** `bd comment <id>` on the owning bead. That's what the next session reads.
This file only tracks *what still needs a human*; the findings themselves live in beads.

**`docs/human recon notes.txt` is NOT an answer source.** It is untracked scratch holding the
raw observations that *prompted* the questions below — not their answers. Anything useful in it
has already been carried into beads. Mine it for new questions if you like; do not treat a line
in it as a recorded finding, and do not sweep it into beads.

**Useful commands**

```bash
bd show <id>                                            # the bead behind any item here
bash tools/banktest/realrom-test.sh check --gme H:/emulators/nes/roms
bash tools/banktest/realrom-test.sh nominate H:/emulators/nes/roms   # board-gap survey
```

---

## 1. Small decisive checks

Each is minutes of work and settles something specific. Highest value per unit effort on this list.

- [ ] **Why does contra's realrom result depend on run scope?** (`grm-lwu` comment, 2026-08-08)
      contra PASSES when run as `--only contra` but FAILS as part of the full `--all` set, and both
      outcomes reproduce exactly. The diff is always the same four added helper-call warnings at
      `c094`/`c0a2`/`c21b`/`c9c0` naming `FUN_c139`, a helper the golden doesn't know about. It is
      **not** `grm-izu`'s fix — applying that fix's three files inside a clean baseline worktree
      still PASSES, so the source is exonerated by A/B.

      **Already eliminated (2026-08-09, on paper — do not re-check).** It is *not* a manifest
      difference. `contra` has exactly one gating row (`realrom/manifest.tsv:4`), and `--all` is
      `manifest.tsv` + `manifest-gme.tsv`, in which contra does not appear. So `id`, `sha256` and
      `loader_opts` are byte-identical across both runs. (`manifest-goodnes.tsv`'s `contra_u`
      rows are a different SHA and non-gating.)

      **Reframe:** the *failing* run finds **more**, not less — which is what `grm-4nr`/`grm-g73`
      bistability looks like. The `--only`/`--all` correlation may simply be coincidence, and
      that is the cheapest thing to rule out.

      **Step 1 — is contra just bistable?** (~10 min; either settles it or eliminates it)
      ```bash
      for i in $(seq 1 10); do
        REALROM_WORK_DIR=$PWD/build/contra$i \
          bash tools/banktest/realrom-test.sh check --only contra H:/emulators/nes/roms
      done
      sha256sum build/contra*/contra.dump | awk '{print $1}' | sort | uniq -c
      ```
      More than one distinct hash ⇒ contra is bistable, run scope is a red herring, and this item
      **merges into the bistable-distribution check below**. Stop there.

      **Step 2 — only if step 1 is 10/10 identical.** Then scope really is the variable, and the
      suspect is state shared *across titles within one invocation*: `$WORK` and the Ghidra
      settings/cache dirs (`-Dapplication.settingsdir` / `-Dapplication.cachedir`,
      `realrom-test.sh:400`). Bisect for the smallest set that flips it:
      ```bash
      bash tools/banktest/realrom-test.sh check --only contra,megaman H:/emulators/nes/roms
      bash tools/banktest/realrom-test.sh check --all --only contra,megaman,cv2,tmnt H:/…
      ```
      A **two-title** set that flips contra means cross-title contamination; only the *full* set
      flipping it means load or timing.

      **Step 3 — the descriptor-drift check** this item originally named: does `build-and-test.sh`'s
      install into `build/ghidra-home` differ from what `realrom-test.sh` puts there?
      `ext_identity()` (`realrom-test.sh:417`) already fingerprints the installed jars **and** the
      loose `data/machines/*.map` descriptors — print `EXT_ID` in both runs and compare. If it
      differs, the two installs differ and that alone explains everything. This is the
      `realrom-cache-key-invariant` hazard: the 16 compiled board descriptors ship **loose** next
      to the jar, so an install can drift from the source that supposedly produced it. If a stale
      `nes-uxrom.map` is what varies, that is a live footgun for every measurement in this tier,
      not a contra quirk. contra is also one of the two goldens `788f09b` skipped (see `grm-bj6`
      for the other, smb3) — worth checking together.

- [ ] **Bistable-golden distribution.** (`grm-g73` P2, `grm-4nr` P2)
      Run the tier ~10 times, keep every dump. How many distinct outcomes exist per title; do
      megaman and ff1 flip *together*; is ff1's delta always exactly −33/−44/−14? Co-flipping
      implies one shared nondeterministic input, independent flips implies two causes.

      **Verified, so the loop is sound:** `check` **never reads** the candidate cache — the reuse
      fast path (`realrom-test.sh:589`) is gated on `MODE = bless`. Every iteration is a genuine
      fresh import, and `-deleteProject` gives each one a fresh Ghidra project.

      **Footgun — read this before blessing anything afterwards.** Every `check` still *writes*
      `build/realrom-cache/<key>.dump`. After a loop like this, a later `bless` will silently
      serve whichever outcome the **last** iteration happened to produce. Run
      `rm -rf build/realrom-cache` before blessing any title that appears here.

      Fold contra (see above) and the other two suspects into one loop — same cost per run, four
      more answers. Budget ~1 min/title/run, so ~50 min for 5 titles × 10 runs; run it detached.
      ```bash
      for i in $(seq 1 10); do
        REALROM_WORK_DIR=$PWD/build/bistable$i \
          bash tools/banktest/realrom-test.sh check --all \
            --only megaman,ff1,contra,dodge,rcproam H:/emulators/nes/roms
      done
      # distinct outcomes per title
      for t in megaman ff1 contra dodge rcproam; do
        echo "== $t"; sha256sum build/bistable*/$t.dump | awk '{print $1}' | sort | uniq -c
      done
      # co-flip matrix: one row per run, one column per title
      for i in $(seq 1 10); do
        printf '%2d' "$i"
        for t in megaman ff1 contra dodge rcproam; do
          printf ' %.8s' "$(sha256sum build/bistable$i/$t.dump 2>/dev/null | cut -c1-8)"
        done; echo
      done
      ```
      **What to record on the bead:** the per-title outcome count, the co-flip matrix, and for any
      title with exactly two outcomes, the `diff -u` between them. A count-line-only delta is
      jitter; a changed or vanished `sample.bankcomment … via FUN_xxx` line is a real behavioural
      difference and names the nondeterministic input.

---

## 2. Def-use passes on untraced titles

The method is proven — four titles done. **Use the tables in `grm-8iy.5`'s comments as the
template**: mechanism-writing set, wrapper set, call-site table (`site · reach · arg class · value ·
notes`), shadow-writer table.

The one question at every undeterminable store: *what computes the value in the accumulator
immediately before it?* Classified as `immediate` / `RAM load <addr>` / `ROM table <base>` /
`computed <expr>` / `passed-in`.

**Three things to check on every title** — all three were discovered the hard way and all three
change what the numbers mean:

1. **Are the "sites" actually PRG?** cv2's 20 stores were 15 CHR/CTRL + 5 PRG; rcransom's 35 were
   32 CHR selects; wizwarr's were mostly VRAM page bits at bank 0. Count PRG chains, not stores.
2. **Is there a wrapper?** A function that writes no mechanism but carries the argument to one —
   4 of 4 titles had one. Reached by tail `JMP`, by fallthrough, or by internal `JSR`.
3. **Is there a bank shadow?** 4 of 4 titles, 7 shadows. Note whether it holds a bank *number* or a
   whole composite register (wizwarr's `$00`).

- [ ] **contra / dragonpower / shenlong** (`grm-hum`, P1 — the only P1 besides `grm-2dr`)
      All three at 0 refs / 0 bank comments, helper identified (`FUN_c13f`, `FUN_ffbe`, `FUN_8eeb`)
      but the argument unrecoverable at every call site. dragonpower and shenlong are both GxROM
      Dragon Ball titles and likely share one engine — **one trace probably covers two.**

- [ ] **smb2 / rcransom** (`grm-8iy.4` P2)
      Both have zero constant-arg call sites. rcransom's real PRG switching is `FUN_ff07` /
      `FUN_ff29` (warnings at `f1d0`, `f21d`) plus undeterminable writes at `ff21`/`ff25`/`ff4b`.
      Separately: smb2's fixed window `WC000` is 100% undisassembled — 8192 bytes, 0 instructions,
      while the others hold 1501/559/2053. Genuinely unreachable, or an entry nothing follows?

- [ ] **DB3** (`grm-azv` P3) — three copy loops at `e69e`/`e707`/`e712` copy from
      `e7d4`/`e826`/`e7fd` into `RAM:0200`; the bank-switch stub executes there and its ROM image is
      never disassembled. Trace source, length, destination; disassemble the copied bytes; identify
      the switch site and argument convention. Your answer *is* the per-game tier's first hint, and
      it bypasses the `grm-1.7` epic. Probe raw material, explicitly unverified: `cand.total 580`,
      `cand.decodeMatch 124`, `verdict.hint` listed `8d00` first.
      **Note `grm-k5m` may partly subsume this** — same RAM-resident-code class, found on wizwarr,
      where the ROM images turned out to be readable in place.

---

## 3. Board documentation

Descriptors are declarative YAML in `machines/`, so a complete fact sheet converts to a shipped
board with very little agent time. Per mapper:

- window layout — which ranges switchable, which fixed, at what granularity
- register addresses, plus the `addr_mask` / `addr_match` decode that distinguishes the PRG register
  from its CHR/IRQ/mirroring siblings
- bank-number **bit layout** within the written byte
- **power-on / reset state** — what bank is live before any write
- whether PRG mode itself is switchable, and how
- write protocol: single write, serial shift, or latch

- [ ] **mapper 9 (MMC2)** (`grm-tas` P3) — the sanctioned next descriptor. 8K switchable at
      `8000-9fff`, three fixed 8K above; latch-driven CHR banking is irrelevant to PRG but worth
      documenting *as explicitly ignored*. Seven local Punch-Out!! dumps already available. Once it
      ships, `realrom-test.sh nominate` flips those rows from comments into paste-ready TSV.

- [ ] **Wider gap**, by local sample count: MMC5 (5) 16 · MMC2 (9) 7 · 118 5 · FME-7 (69) 4 · 87 3 ·
      206 3 · 68 2 · 23 2 · 18 2 · 119 2 · Color Dreams (11) 2, then singletons. Beyond MMC2,
      **FME-7** and **Color Dreams** are the best effort-to-payoff — both simple single-write
      latches. MMC5 has the most samples and is a far bigger board.

- [ ] **NES 2.0 exponent PRG size** (`grm-dfj` P3) — scan local headers for `h[9] & 0x0F == 0x0F`.
      The bead says fix it "when a real image demands it rather than speculatively", so **"none
      locally" is a valid and useful answer** that justifies leaving it alone.

- [ ] **6502 ADC/RRA flag vectors** (`grm-o9k` P3) — the bug is diagnosed and the fix is one line;
      what's missing is a vector table to test against, binary *and* BCD. Sources: Bruce Clark's
      "Decimal Mode in the NMOS 6502" (6502.org), the `ProcessorTests` 65x02 JSON suites.
      Include the two the bead already names: `A=$FF, op=$00, C=1` → `$00`, C=1; and
      `A=$50, op=$50, C=0` → `$A0`, V=1.

---

## 4. Decisions only you can make

Blocked on judgment, not effort.

- [ ] **Community disassembly licensing survey** (`grm-hb6.6` P3). The bead names licensing as "the
      gating constraint and a per-source judgment, not a policy set once". Deliverable: a table of
      *project · URL · license · redistributable? · symbol format · maintenance state* for Zelda
      (already hash-pinned), Metroid, Mega Man, SMB. The schema side is solved — `docs/SCHEMA.md`
      defines named symbol sets with provenance and `tools/gensymbols/gen_c64ref_symbols.py` is the
      generator precedent. Only one new concept is needed: a `block: bank` qualifier, since a label
      at `$8000` is ambiguous across 16 UxROM banks.

- [ ] **c64ref sourcing** (`grm-p5w`, typed as a `decision`) — generator + committed
      `generated/*.yaml`, or git submodule + build-time generation. Binds `grm-hb6.6` and `grm-54p`
      too. Decide once.

- [ ] **SPC700 language sourcing** (`grm-y7d` P3) — blocks `grm-1.7.3`. Stock Ghidra ships no SPC700
      module. Evaluate `qwertymodo/SPCdra` for Apache-2.0 compatibility, sleigh completeness (the ISA
      is small and 6502-adjacent), and bundle vs. depend vs. reimplement. The `.spc` loader is the
      fastest value — those rips are full 64K sound-RAM snapshots, an immediate AKAO disassembly
      target.

---

## 5. Upstream (needs your GitHub identity)

Agents can't file these — they need an account and CLA agreement.

- [ ] **`grm-b3m`** (P2) — `jumptable.cc findSmallestNormal` stride-aware guard. Issue text is
      **already drafted** in the scratchpad as `ghidra-issue.md`, and `grm-eyn` confirms no existing
      upstream issue covers it. File the issue first for a number to reference from the PR.
      **Unblocks `grm-g73`.**
- [ ] **`grm-6xh`** (P3) — the one-line `setMinStoreLoadOffset` field-assignment bug (assigns
      `maxSpeculativeOffset`). Verified tag-exact against `Ghidra_12.1.2_build`; affects the base
      analyzer and all 13 per-processor subclasses. Trivial PR, high goodwill.

---

## Answered (kept as a record of what the method produced)

| question | answer | bead |
|---|---|---|
| blmaster's 13 constant-arg sites vs 4 comments | Measurement artifact — a warning-derived helper population inflated 5 helpers to 36 and constArg 2 to 13 | `grm-8iy.3` **closed** |
| Was megaman's `9067` regression real? | No — the *old* annotation was wrong. `d846`'s tail `JMP c3b3` sets bank 5 on exit; old "bank 6" came from the last write in its own body. `bankComments` 156 now exceeds the pre-regression 153 | `grm-hum` |
| Are megaman's `c39c` warnings lost information? | No — `$31` is a stateful counter with a wrap-adjust; the declines are honest | `grm-hum` |
| Do cv2/tmnt have pre-body entry points? | No — Ghidra creates functions at all of them. Both are *wrapper* cases | `grm-i7v` **closed, no instances** |
| Does tmnt's `$F0` guard interleave with the serial chain? | No — it brackets it. Chain is contiguous and standard | `grm-oiu` (premise disproven, dropped to P3) |
| Is the wrapper idiom an MMC1 artifact? | No — wizwarr's AxROM single-write latch has it too | `grm-2dr` |
| Does `grm-izu` explain `grm-lwu`? | Yes, via the POISON branch, not the unknown-commit one. `c2a1 → dec2 → df05 → e61b → e63c`; `e61b` round-trips A through `$DB`, so bit 7 is unresolvable and the chain poisons every field — mirroring included. Fixed at strategy level (`effectDependsOnPriorState()`); blmaster 90 → 24 warnings, exactly as predicted | `grm-izu` **closed** |
| How big is blmaster's `c9a4` prize? | **~281 targets** — ~136 entries in bank 4, ~145 in bank 6, on a title currently at 0 refs / 0 instrs in overlay. Tables live in the *switched* window (bank switch precedes the first pointer fetch), so nothing is readable before the merge is solved. Targets stay in-bank, so retargeting is unambiguous once the bank is known. Table base differs per bank (`4:$8006` / `6:$8002`), which argues for path-forking over set-valued state | `grm-wul` |
| `grm-78b` root cause: (a) over-extension or (b) seeding gap? | (a). RESET → `fff4` (`INC RESET`, the MMC1 reset idiom) → `JMP f23b`, so `f23b` **is** referenced; `FUN_f1ca`'s body simply claimed those bytes first by running past the always-looping pair at `f237`. Acceptance amended — `f23b` is a JMP target, so it should belong to the RESET function, not become standalone | `grm-78b` |
| Does tmnt's `$F0` helper guard defeat argument recovery? (`cea7` vs an unguarded MMC1 helper) | No — all three behave alike, so the bead's own close condition fired. The guard is empirically harmless: tmnt's golden carries real recoveries *through* the guarded helpers (`c003 prg_bank=2 via FUN_cea7`, plus `via FUN_ce56` and six `via FUN_cea5`), which could not exist if the bracket defeated argument identification. **cv2 `c187` was the strong control** — a `PHA / LDA #1 / STA $0103 / PLA` sits between entry and its chain (an unrelated memory write *and* a stack save-restore of the tracked parameter) and recovery still works. **Reframe worth carrying forward:** "24 of 30 direct stores recover nothing" was counting the five in-body serial stores per helper, which are parameter-valued by construction in *every* MMC1 title — count call-site chains, not mechanism stores (recorded on `grm-8iy.5`) | `grm-oiu` **closed not-a-bug** |
| Why does cv2 recover only 2 of its 10 `c183` call sites? | It recovers 2 of **2**. Only two xrefs to `c183` exist in the program at all — `c081` and `c4de`, both `JSR`, both base space — and production annotates both. The ~30 further `JSR $c183` and 3 `JMP $c183` found by byte search are base-space but **undisassembled**, so they are not instructions and cannot warn. Not a defect; expect it to self-resolve as coverage rises. Full table in the bead | `grm-093` **closed** |
| Does `BoardBankAnalyzer`'s `isCall()` gate silently drop `JMP`-reached call sites? | **No — refuted, not merely unmeasured** (`grm-2dr` increment 2, measured rather than argued). `df07` is a `JMP`-reached site and it resolves `prg_bank=5`: shared-return analysis retypes the `JMP` to `CALL_TERMINATOR`, which reports `isCall()`. All four plain-immediate sites resolve regardless of reach (`c55f`/`c57a`/`e2c3` by `JSR`, `df07` by `JMP`), and the three that still decline split 2 `JMP` / 1 `JSR`. **No reach asymmetry exists — do not file an `isCall()` bead.** Also corrected in the same pass: `e61b` was *misclassified* as a shadow-**establishing** wrapper. It is a **forwarding** wrapper — `STA $DB` on entry, reloads `$DB` **inside its own body** — which `grm-mu7`'s `argumentCells`/`argumentReloadSource` save-restore model already covers. cv2's `c185`, the wrapper it was grouped with, loads a cell a *different function* wrote, and that is the real establishing shape. blmaster was therefore never blocked on `grm-mej.2`; it was blocked on the *call edge*, and that is fixed. What its remaining sites need is shadow-**restore** modelling (`LDA $D3`), which is genuine `grm-mej` scope | `grm-093` / `grm-2dr` |
