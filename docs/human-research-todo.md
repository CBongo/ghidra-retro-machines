# Human research TODO

Work that is **deliberately not agent work** — where a person with a disassembler, an emulator, or
a judgment call gets there faster and better than an agent burning tokens on a
build/measure/interpret loop.

This is a running list, not a snapshot. Add to it whenever an agent stops and asks (see the
"Stop and ask when a human would be more efficient" directive in `CLAUDE.md`).

## Retiring an answered item — the exact procedure

Sections 1–5 hold **only open questions**. An answered item does not stay here in any form.

1. `bd comment <id>` the finding on the owning bead. That is what the next session actually reads.
2. **Delete the item from its section**, entirely — heading line, body, code blocks, all of it.
3. **Add one row to the `## Answered` table at the bottom of this file** (`question | answer |
   bead`). Condense to a few sentences; the full record lives in the bead. If the answer *retires*
   a line of investigation, say so imperatively in the row — "do not bisect for it", "do not file
   an `isCall()` bead" — so nobody re-spends the tokens.

**Never mark an item `- [x]`.** The checkbox has exactly one state here. A checked box left in
place looks like open work to the next reader and silently drops the finding out of the archive,
which is the one thing this file exists to prevent. *(This mistake has been made more than once —
the `- [ ]` syntax invites it, and the archive table is far enough down the file that a targeted
read of a single item never sees that it exists. Scroll to the bottom before editing.)*

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

- [ ] **Does any real Bandai cart write an FCG register with an *indexed* store?** (`grm-egw` P3.)
      The soundness hole is verified in code, not merely suspected:
      `MosConstantReferenceAnalyzer.addBaseReferenceOnce` replaces a computed reference with one to
      the operand *base*, and Bandai FCG decodes `addr_mask 0xF / addr_match 0x8` — so `$8008`
      matches but the `$8000` that replaces it misses, and an indexed register write stops being
      detected. The bead calls the triggering shape (`STA reg,X` into a mapper register file)
      "ordinary", but **no shipped title exercises it** — the four Bandai goldens did not move when
      the bug was introduced.

      **The question:** in `db3` / `dbz2` / `dbz_datach` / `dbz_saiyan`, does any indexed store
      (`9D`/`99` opcodes) target `$8000-$FFFF`? A byte search finds candidates in seconds; deciding
      whether a hit is a genuine mapper-register write rather than data needs eyes on the
      surrounding code, which is the part that costs an agent a build/measure cycle per candidate.

      **"No" is a valuable answer** — it justifies leaving `grm-egw` at P3 indefinitely rather than
      pre-emptively hardening a path nothing uses. "Yes" makes it a live correctness bug on a
      shipped board and should raise the priority.

- [ ] **Does any corpus title run the 6502 stack deep enough to reach the low stack page?**
      (`grm-mej.3` increment 2, commit `ba1efc3`.) Increment 2 removed
      `StoredValueScanner`'s blanket refusal to forward values through `$0100-$01FF`, on the ruling
      that a `PHA` would need a ~253-byte-deep stack to alias a scratch cell like dodge's `$0103`,
      and that games park scratch low in the page precisely because the stack never reaches them.
      `argumentSurvivesPrologue` already assumed the same thing, so the refusal was inconsistent
      rather than conservative.

      **The residual risk was accepted, not eliminated,** and it is documented that way in
      `forwardedStoreValue`'s javadoc. **The question:** does the stack in any pinned title ever
      descend far enough to write a cell the scanner now forwards through — i.e. does `S` ever go
      below roughly `$20`? One watchpoint or a min-`S` trace in an emulator answers it for a whole
      title; static analysis cannot answer it at all, which is why this is here rather than on the
      bead as agent work.

      A confirmed "never below ~`$80`" retires the concern permanently and is worth recording. A
      title that *does* run deep is a genuine counter-example and would justify re-introducing a
      narrowed guard (refusing only the upper part of the page) rather than the blanket one.

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

- [ ] **dragonpower / shenlong** (`grm-hum`, P1 — the only P1 besides `grm-2dr`)
      Helper identified on each (`FUN_ffbe`, `FUN_8eeb`) but the argument unrecoverable at the call
      sites. Both are GxROM Dragon Ball titles and likely share one engine — **one trace probably
      covers two.**

      **contra is DONE and was removed from this item** (traced 2026-08-09, see the Answered table).
      All ten of its warnings are classified: three are recoverable and blocked on one fix
      (`grm-k90`), one is a five-valued ROM table, three are shadow/read-back restores (`grm-mej`),
      one is the helper's own mechanism write, and two are phantoms from a switch-table over-read
      (`grm-eyn`). Do not re-trace it, and in particular **do not trace `811a` →
      `FUN_PRG_LO_B1__8259`** — that "third helper in overlay space" is not real code.

      Note before starting these two: `grm-hum`'s 2026-08-01 comment already records both engines'
      disassembly, the `$F2` shadow, the `$FFDC` inline far-call trampoline, and the measured
      cross-bank invariant regions. It also records a **structural blocker** independent of dataflow
      — both descriptors declare a single fully-overlaid `PRG_ALL` window, so
      `bankInvariantRomByte` returns null for every address and the `$FFCC` table is unreadable to
      the engine even with a perfect index (`grm-e7v`). Read that comment before spending anything
      here; the trace may not be the binding constraint.

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

- [ ] **Should `bless` still write a golden when the fixture's criteria failed?** (`grm-aqi`, filed
      **P1** by the 2026-08-10 quality review.) The review found that `run-banktest.sh:311-314`
      records the failure and then copies into `expected/` anyway at `:325-328`, and that the cache
      path is worse — `:256` copies *before* checking the cached criteria at `:258-261`.

      **What the review missed, and why this is your call:** the behavior is **deliberate**. The
      comment at `:244-245` states the intent — *"Mirrors the non-cache bless below: copy the
      candidate regardless, but flag the suite if its cached criteria failed."* Someone chose to
      always produce a candidate for inspection. So fixing this overturns a design decision, not an
      oversight, and an agent should not do that unilaterally.

      **The case for changing it:** `bless` is the only thing between a bad run and a committed
      oracle, and the whole gate discipline rests on goldens being trustworthy. **The case for
      leaving it:** `bless` is a manual command, it prints FAIL, it exits nonzero, and the change is
      visible in `git diff` before commit — so it cannot silently corrupt anything, and always
      producing the candidate makes a failing run diagnosable.

      Whichever way you rule, the atomic-write half of `grm-z34` is the same work and is already
      linked as blocked on this.

- [ ] **CI and dependency locking: yes or no?** (`grm-e7w` P2, already narrowed to just these two
      questions; the mechanical half — the hardcoded `/d/gradle-8.13/bin/gradle` default — was split
      out to `grm-ycv` and needs no decision.)

      1. **Should this repo have CI at all?** Enforcing the synthetic gate means a runner that
         fetches and pins a Ghidra install matching `ghidraTargetVersion`. Feasible — Ghidra is
         publicly downloadable — but it is an ongoing cost and a hosting choice. The real-ROM tier
         must stay opt-in regardless; those ROMs are copyrighted and machine-local.
      2. **Is Gradle dependency locking + verification metadata worth it here?** Version strings are
         already pinned in `build.gradle`. Full verification metadata is real supply-chain hardening
         with real maintenance friction for a project this size.

      A "no" on either is a perfectly good answer — record it and close that half, so the question
      does not get re-opened by the next review.

- [ ] **Close `grm-4nr` (ff1 bistability) as not-reproducible?** (P2.) The bead was filed on five
      runs splitting 3:2 between two states (`refs -33 / instrs -44 / warnings -14`). `grm-g73`'s
      answer then measured ff1 at **10/10 identical**, making the old 40% rate statistically dead
      (P = 0.6%), most likely killed by the `grm-izu` / `grm-2dr` work. It explicitly says **do not
      spend a bisect speculatively — a future ff1 FAIL is the cheap signal.**

      Since then ff1 has passed every observed run, including the full GME sweep on 2026-08-11
      (19/19). So the bead is tracking a defect nobody can currently reproduce. **The question is
      bead hygiene, not analysis:** close it not-reproducible with the evidence recorded, or keep it
      open as a standing watch item? Closing risks losing the signature if it returns; keeping it
      open leaves a P2 that no one can act on.

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
| Why does contra's realrom result depend on run scope? | **It doesn't — the premise was false.** Ten consecutive `--only contra` runs gave **one** dump sha, and a mixed-title invocation fails contra in **both** scopes. The `--only` PASS / `--all` FAIL correlation was an artifact of *when* the runs happened: the PASSing ones consumed a `build/ghidra-home` install predating `788f09b`, the FAILing ones an install after it — same source, different installed extension. contra is a **stale golden**, the twin of `grm-bj6` (`788f09b` re-blessed seven goldens and skipped exactly smb3 and contra), and cheaper to settle: its diff is purely additive annotation, no count-line or resolved-value movement. **No cross-title contamination exists — do not bisect for it.** Side finding, real but *not* the cause: `run-banktest.sh`'s `ext_identity` omits the loose `data/machines/*.map` files that `realrom-test.sh`'s includes, but `EXT_ID` feeds only `*_cache_key()`, the cache is **read** solely under `[ "$MODE" = bless ]` (`realrom-test.sh:589`), and the two scripts use **separate** cache dirs — so it can cause a stale *bless*, never a wrong *check*. **Settled 2026-08-09:** `FUN_c139` confirmed a genuine helper — sets the bank shadow `$07ec` from the bank id at `$8000`, then falls through to the PRG register write at `c13f`, a textbook pass-through wrapper — so the recognition was right and the golden was stale. Blessed; diff was the 4 warnings and the count line, nothing else | `grm-3t8` **closed**; `grm-9mw` for the script library; premise retired on `grm-lwu`; bless recorded on `grm-2dr` |
| Are smb3's new `ca23`/`ca2e` values (`r7=27`/`26` -> `r7=7`) right, or is the argument coming from the wrong site? | **Wrong site — a REGRESSION, and the golden is correct. smb3 must not be blessed.** MMC3 is a two-write protocol and smb3's helper `ffc2` does both halves: `LDA #$47 ; STA $0721 ; STA $8000 ; LDA $0720 ; STA $8001`. `$8000` takes the register-SELECT byte, `$8001` the bank — which arrives via RAM shadow `$0720`, not a register. Production now reports `$47 & $3F = 7`, i.e. the select constant leaking into the bank field. **Direct proof:** `ca23` is preceded by `LDA #$1b ; STA $0720` and `ca2e` by `LDA #$1a ; STA $0720`, so `$1B`=27 and `$1A`=26 *are* the call-site constants the old golden recorded. Corroboration: both sites collapse to one value (a helper-body constant, not a call-site one), and the direct sites `c5f5`/`c9f7` (`LDA #$1a ; STA $8001`, no shadow update) still read 26 correctly. The count movement fits a regression, not a fix — a wrong bank retargets into a wrong/absent overlay, hence `refs 846->822`, `instrs 4263->4173`. **Shadow map recorded for the per-game tier:** `$0721` = `$8000` select/mode, `$0720` = R7 bank, `$071F` = R6 bank; `ffd1` sets R6, `ffbf` (`JSR $ffd1` + fallthrough) sets both; the IRQ handler restores `$8000` from `$0721` on exit; PRG mode 1 confirmed (`$8000` bit 6 always set), so R6 drives `$C000` | `grm-67g` filed **P1**; `grm-bj6` retitled and blocked on it; `grm-evn` for the unrelated `FUN_c542` leftover |
| Are rcransom's `f1d0`/`f21d` values (`select=6,prg_mode=0,r6=0,r7=1`) real, or the same `firstSite` artifact as smb3's `r7=7`? | **Artifacts — both of them, and wrong in TWO ways.** `FUN_ff07`/`FUN_ff29` are interrupt-exit RESTORE routines (called immediately before the NMI and IRQ handlers return). Each writes R6 from shadow `$fc` and R7 from `$fd`, then rewrites `$8000` itself from `$ff`/`$fb`. So (1) the reported `select=6` is the state after the helper's FIRST select write, not its net effect — the LAST select write loads `$8000` from RAM and is statically unknown; and (2) `r6=0,r7=1` were stale in-state values claimed as fully known (those lines carry no `[known:…]` bracket at all) because the mis-anchored deposit owned only `select`+`prg_mode` and never poisoned r6/r7 across a helper that overwrites both. A confident stale bank is the same defect class as smb3's confident wrong one. `grm-67g`'s fix replaces both with warnings, which is the honest answer, so **rcransom was a second correctness win, not collateral** — blessed. Stable under the planned `grm-mej` follow-up: the data comes from cells the caller never writes, so it stays unknown. **New gap this exposed:** bank state across an INTERRUPT boundary — a handler that restores banking on exit means the interrupted code's state is preserved, which the engine has no way to express | `grm-1fv` **closed**; unblocked `grm-67g`; rcransom removed from the section-2 def-use list |
| Why does smb2 have zero constant-arg call sites, and is its 100%-undisassembled `WC000` a defect? | **Neither is a gap — smb2 is a stack/shadow title and `WC000` is data. Do not re-trace it, do not file a coverage bead for `WC000`.** The whole PRG mechanism is one wrapper plus one helper: `ff85` (`STA $06f2`, falls through) into `ff88` (`ASL A ; PHA / LDA #$86 / STA $8000 / PLA / STA $8001 ; ORA #1 ; PHA / LDA #$87 / STA $8000 / PLA / STA $8001`). `$86`/`$87` select R6/R7 with bit 6 clear (prg_mode 0), so **R6 = raw×2, R7 = raw×2+1** — a UxROM-shaped contiguous 16K window at `$8000-bfff` driven by a single 16K index. The user found **no other refs to `$8000`/`$8001`** in disassembled code, which closes site accounting exactly at the probe's `sites.total 6` (four in `ff88`, two in the `ff73` CHR helper, which loads from a table at `$06f7`). So nothing is undiscovered; the bank simply crosses a `PHA`/`PLA` pair — with an `LDA #imm / STA $8000` clobbering A in between — at **every** mechanism site, making `grm-mej.3` the binding constraint, plus arithmetic in the deposit (`ASL`/`ORA #1`) and scaling on the shadow: **`$06f2` holds the *unscaled* 16K index, unlike smb3's `$0720` or rcransom's `$fc`/`$fd` which hold register banks directly.** `WC000` is bank 14, the prg_mode-0 fixed second-last bank, and per the Xkeeper0/smb2 disassembly it is mostly DPCM samples and ending event data — data, not an unreached entry | `grm-8iy.4`; second motivating case recorded on `grm-mej.3` |
| How is the bistable-golden outcome distributed — how many states per title, do megaman and ff1 flip together, is ff1's delta always −33/−44/−14? | **Two states each for megaman/dodge/rcproam, ONE for ff1, and the flips are INDEPENDENT — do not hunt for a single shared nondeterministic input.** Ten fresh imports × five titles: megaman 8/2, dodge 9/1, rcproam 8/2, ff1 **10/10 identical**, contra 10/10 (control — so the loop and harness add no noise of their own). Only run 4 flipped two titles at once (megaman+dodge), which is what independence predicts at those rates (expected 0.2 joint occurrences in 10 runs); megaman also flipped alone. Every diff is **count-line-only**, no `sample.*` line moves, `bankComments`/`warnings` constant — jitter by the bead's own criterion. megaman refs 1704→1703 / instrs 7429→7431 (opposite signs, the same 1-ref/2-instr signature since 2026-07-25); dodge refs 2739→**2740** with instrs pinned, a *third* known value alongside 2736/2739; rcproam refs 1298→1296, instrs pinned. The golden is the majority state in all four, so the unchanged-tree FAIL rate is megaman 20%, rcproam 20%, dodge 10%, ff1 0%. **ff1's 40% rate is dead** (P(0 in 10 \| p=0.4) = 0.6%), most likely removed by the grm-izu / grm-2dr work, though n=10 leaves a low residual rate unexcluded and no bisect was run — **do not spend one speculatively; a future ff1 FAIL is the cheap signal.** Two operational notes: `build/realrom-cache` now holds run 10's dumps, so `rm -rf build/realrom-cache` before blessing any of these five; and the whole `bistable1..10` set predates 09d9c97, so contra's dumps legitimately differ from today's golden and the set is **not** a baseline against HEAD | `grm-g73`; ff1 result on `grm-4nr` (candidate to close not-reproducible) |
| What are contra's ten remaining warnings? | **All classified; contra needs no further tracing.** Engine: `c13f` (`LDA $ffd0,Y` / `STA $ffd0,Y`, bank arrives in **Y**), wrapper `c139` (sets shadow `$07ec` from `$8000`, falls through), plus a **second** shadow `$07ed` used only by the `c14c`/`c15e` save-restore bracket. Split: **3 recoverable** — `c094`/`c0a2` (`LDY #1`) and `c21b` (`LDY #6`) call the *wrapper* and warn, while the identical `LDY #imm` idiom calling `c13f` directly (`c0cb`, `c157`) resolves; **1 honest** — `c9c0` takes Y from a 3-byte-stride CHR-pointer table at `$c950` (`LDA $c952,X / AND #7 / TAY`) reaching five banks {0,2,4,5,6}, so no static value exists; **3 out of scope** — `c0d3` (reads live bank back from `$8000` through the stack), `c149` (`LDY $07ec`), `c164` (`LDY $07ed`) are all `grm-mej` shadow/read-back restores where unknown *is* correct, same disposition as rcransom; **1 by construction** — `c142` is the helper's own mechanism write; **2 phantoms** — `8efc` and `811a` are cruft from a switch-table over-read at `8492`, so **`FUN_PRG_LO_B1__8259` is not real code, do not trace it**. Ceiling is 3 more sites, +3 if `grm-mej` lands | `grm-hum`; fix on `grm-k90` (retitled, P3→P2); over-read on `grm-eyn` |
| Is wizwarr's `FUN_ff69` a save/restore trampoline — does it save the bank *before* its own switch, and restore on every path out? | **Yes on both counts — increment 1's `bc0a` claim is correct.** `ff69` saves Y in `$1b`, pushes `$00` (wizwarr's composite bank shadow) on the **stack**, sets the bank to A via `$1d`, `JSR $ff83` (which is `JMP ($1b)`, the indirect far call), then restores `$00` and sets the bank back from the stack. The save precedes the switch, which is exactly the ordering the increment assumes, and the restore reloads both shadow cell and latch on the way out — so net effect on the caller is nil and `ownedMask = 0` is the right deposit. Calling convention: target address through `$1b` (Y supplies a byte), requested bank in A. Note the shape difference from ironsword's `FUN_ffc0` — wizwarr saves through the **stack**, ironsword does not — so increment 1 recognizing both is a real generality result, not one idiom fitted twice. **Do not re-trace `ff69`.** **Both real-ROM goldens are now unblocked for blessing**: ironsword was held only by this item, and wizwarr's other blocker `grm-p9y` is closed (fix `53059ed`). Expected diff is warnings only — ironsword 11 → 4, wizwarr 4 → 3, no `refs.intoOverlay` / `instrs.inOverlay` movement; anything touching a count line is *not* this change. Clear `build/realrom-cache` before blessing | `grm-mej.3` |
| Are `grm-mej.2` increment 2's two new bank annotations (megaman `d571`, wizwarr `ffa6`) right? | **Both WRONG, and they are ONE bug, not two.** Both sites are the tail of an **NMI handler restoring the interrupted bank**, and both handlers switch banks by writing the **latch directly, bypassing the shadow cell** — which is the whole point of the idiom: it leaves the shadow holding the pre-interrupt bank so the restore is a bare `LDA shadow / STA latch`. megaman (NMI vector `$D4A8`): `D54C LDA #$04 / D54E STA $C004` switches to bank 4 without touching `$42` (`$C000` = `00 01 02 … 07`, the UNROM bus-conflict table), then `D56E LDA $42 / D570 TAX / D571 STA $C000,X` restores. wizwarr (NMI vector `$FF86`): `FF9C AND #$18 / FF9E STA $8000` switches to bank 0 without storing back to `$00`, then `FFA4 LDA $00 / FFA6 STA $8000` restores. Correct answer at both restore stores is **unknown**. Root cause is in **consumption, not derivation**: `MemoryLatchBankSwitchStrategy.mirroredByte` answers a `WRITE_THROUGH` mirror load from tracked in-state with no proof the shadow is still *coherent* with the live bank — the existing precedence ladder models only the opposite window (shadow leads in-state, cv2 `c183`/`c185`/`c187`). **Three retirements: do not re-trace the derivation** — `$42` and `$00` genuinely *are* `WRITE_THROUGH` (wizwarr's pairs are visible in `FUN_ff69` at `FF74`/`FF76` and `FF7D`/`FF7F`), so leave `BankMirrors.Discovery` and the `SAVE_SLOT` guard alone; **do not blame interrupt-entry seeding** — it is real and unsound but was investigated and excluded, megaman's `4` comes from `D54E` and wizwarr's `0` from `FF9E`; and **the `$C5` / Rare `PHA…PLA` hypothesis was wrong on every count** — wizwarr's shadow is `$00`, `$C5` is *ironsword's*, and no stack save-restore is involved at `ffa6`. Note the discriminating case any fix must preserve: wizwarr's `ff9e bank -> 0` is **correct** while `ffa6 bank -> 0` two instructions later is wrong — same value, same handler, same cell, so the value cannot separate them. Scorecard: these two claims are increment 2's *entire* observable real-ROM output on the `WRITE_THROUGH` half, which is therefore 0-for-2. **Still do not bless megaman or wizwarr** — now pending the fix, not an answer | `grm-ii6` **closed**; fix on `grm-p9y` (**P2**, carries the design and regression cases, blocks `grm-mej.2`); seeding on `grm-913` (P3) |
