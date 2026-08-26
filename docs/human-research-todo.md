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
bash tools/banktest/realrom-test.sh check --gme         # romdirs come from GRM_ROM_DIR
bash tools/banktest/realrom-test.sh nominate <romdir>   # board-gap survey
```

---

## 1. Small decisive checks

Each is minutes of work and settles something specific. Highest value per unit effort on this list.

- [ ] **Why do Lemmings and Mario show zero SPC-side port references?** (`grm-ced`.) Counting
      direct-page `$F4`–`$F7` accesses across the `*spc.dis` listings gives sd3 113, ct 87, ff3 78,
      som 60, ff5 49 — then g3 5, fzero 2, **lem 0, mario 0**. A working driver must talk to the
      65816 somehow, so zero is not a fact about those drivers, it is a fact about those files.
      Three candidates: the listing covers only part of the image, the disassembler wrote those
      operands in a form the grep missed, or the driver really does poll differently.

      **Opening one of those two listings settles it in a minute** and is not worth an agent
      round trip. It matters because `grm-uy9s` and any future protocol work will use "find the
      port accesses" as the way to locate the interesting code, and a method that silently finds
      nothing on two of nine titles needs to be understood before it is relied on.

- [ ] **Is F-Zero's upload fully resident, or does it stream too?** (`grm-ced`, `grm-1.7.3`.) You
      established that on-demand sample loading is an AKAO trait and that you don't recall how the
      others handled it. F-Zero is the one non-AKAO title where we can nearly guess: five blocks
      totalling ~24 KB, two of them large (13306 at `$0800`, 10381 at `$A080`), which is a lot to
      be pure code — so it *looks* fully resident. **That is an inference from size and is recorded
      as such, not as a measurement.**

      Worth settling because it is the discriminating case for the recovery model: if a driver
      uploads everything once, `accumulate-all-transfers` yields a *complete* image and every
      recovered region is stable; if it streams, the image is a point in time. One example of each
      would let the design be written against both ends of the spectrum instead of one.

- [ ] **Does the SPC driver compute the BRR directory, or does the 65816 send it?** (`grm-1.7.3`.)
      You flagged that it's been too long to recall. The answer changes what an analyzer should
      expect: if the 65816 sends it, the directory in SPC RAM has *no writer visible in the SPC
      image* and an analyzer should say so rather than leaving an unexplained data region; if the
      driver builds it, the writer is right there and should be found.

      An agent already recorded the wrong half of this as fact once and had to retract it, which is
      the argument for answering it from the code rather than from inference. FF2's `notes.txt`
      names three uploaded dir tables (`$1E00`, `$1D00`, `$FD00`) with the sample regions they
      serve, so the resident case is documented; the open question is only about the *streamed*
      ones.

- [ ] **Locate your older Ghidra projects** (`grm-w4w3`). You mentioned previous Ghidra projects
      exist somewhere. **These would be worth more than every other annotation source in the
      corpus combined**, and the reason is purely mechanical: a `.gpr` + `.rep` pair opens
      directly in the Ghidra this project already targets — functions, labels, applied types,
      comments, bookmarks and memory layout intact, no parser, no conversion, and diffable
      against a fresh import of the same binary. Every other artifact (nine `.dis` text
      listings, ten `.idb` databases) needs a tool and a translation step first.

      Only you can find them. Once located, `grm-w4w3` can proceed without any of the `.idb`
      tooling for whatever titles they cover.

- [ ] **smb3: which bank survives `FUN_c542` back to its callers at `867b`/`ac6d`?** (`grm-gyi`,
      answered and closed; this is the one residue.) The routine performs its own mechanism write
      at `c5fc` — bank `$1a` by your 2026-08-16 reading — and later, at `c6e9`, does
      `LDA #$0b / STA $0720 / JSR $ffc2`, i.e. a switch to the **constant `$0b`** through the
      `$0720` argument cell. Two switches, two different constants.

      **The question is just where `c6e9` sits relative to the `RTS`**, and hence which of the two
      is live when control returns to `867b`/`ac6d`. If `c6e9` runs before returning, the caller
      sees `$0b`; if it is on a path that does not return there, the caller sees `$1a`.

      Why it needs you: this is a listing read, and for an agent it is a build/measure/interpret
      cycle per guess. Why it is worth answering: today both call sites emit *"bank argument could
      not be recovered"*, which is a misframing either way — `c542` takes no argument, it commits
      constants — so we know the current output is wrong but not yet what the right output is.
      Note the bead's own two candidate answers (annotate `$1a`; or `ownedMask = 0` verified no-op)
      are **both refuted** — the `$ffc2` call is not an entry-bank restore, so "no-op" is
      affirmatively wrong. Do not re-open the `restoresEntryBank`-is-MMC3-blind line either; it was
      measured false (declines at the board-independent branch guard, `BoardBankAnalyzer:2506`).

      Ghidra has split the routine into `FUN_c542` and `FUN_c54a`, which report the *same*
      `switchSite=c5fc`; the body you want is `c542`–`c6f1`.

- [ ] **Upgrade `bd` 1.0.4 → 1.2.2 — it unblocks a designed fix for the memory truncation.**
      (`grm-8ctl` P1, researched 2026-08-26.) Minutes of work; run
      `.\tools\upgrade-bd.ps1` (`-WhatIf` first if you want to see the paths). It checksums the
      download, refuses to run while `bd` is live, and keeps the outgoing binary as
      `bd-previous.exe` so rollback is a rename.

      **Why it needs you:** `bd` is a standalone binary in `%LOCALAPPDATA%\Programs\bd` with no
      self-update, so this writes outside the repo — same category as `tools/install-gui.ps1`.

      **What it buys:** `bd prime --no-memories` (merged upstream 2026-07-14, ships in v1.1.2) lets
      both hooks emit `bd prime --no-memories` + `bd memories` instead of bare `bd prime`. Measured
      here: **101,019 bytes → ~10 KB**, using only shipped flags instead of the brittle
      output-stripping that upstream added the flag specifically to eliminate. Today the hook payload
      is 95% memory bodies and the host truncates it to a ~2 KB preview, so everything after the
      first memory alphabetically never reaches the session — that is the mechanism behind the
      retracted `grm-7rct`.

      **Two things worth knowing before you run it.** v1.2.2 *is* v1.1.2's code under a higher
      version number (v1.2.0/v1.2.1 were published by accident without release testing), so "latest"
      and "conservative" are the same binary — and the release notes' alarming "schema version
      mismatch" section applies only to people who ran v1.2.1, not to you coming from 1.0.4. It does
      migrate the local Dolt schema forward, one-way; beads data is already pushed to
      `refs/dolt/data`.

      **When it's done, hand it back.** Rewiring the two hooks and the matching wording in
      `AGENTS.md` are agent work, deliberately held until the binary is in place rather than written
      blind. Verification is then free: start one fresh session and see whether the SessionStart hook
      still says `Output too large ... Preview (first 2KB)`.

*Not an item — a note.* The `.idb` inventory itself (`grm-w4w3`) is **agent work and is
deliberately deferred to a future session** at your request; the tooling question is settled
(`python-idb` Apache-2.0 / `idbutil` MIT, no IDA needed) so nobody re-derives it. Worth knowing
what turned up while looking: **ten** IDA databases, not one — including `nes/zelda/zelda.idb`
(a title already hash-pinned in the real-ROM manifest, and named in section 4's community-
disassembly item — your own database sidesteps that licensing question entirely) and
`c64/rds/files/f-drive0500.idb`, which reads as **1541 drive code at $0500**, i.e. a worked
example of the C64→1541 upload case `docs/smc-survey.md:164` names as the sibling of the
SPC700 problem.

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

*No titles are queued right now — dragonpower and shenlong closed out 2026-08-15 (see the Answered
table), and contra, cv2, tmnt, wizwarr, blmaster, smb2, rcransom and smb3 are done before them. The
method above is kept because the next untraced title will want it. Pick candidates from `grm-8iy`.*

---

## 3. Board documentation

Descriptors are declarative YAML in `machines/`, so a complete fact sheet converts to a shipped
board with very little agent time.

**Source of record: the NESdev wiki iNES 1.0 mapper grid — <https://www.nesdev.org/wiki/Mapper>.**
That is the project owner's own primary reference for mapper behavior (2026-08-15); use it, and
cite it in board work. Note its structure: the grid is an **index** (mapper numbers 000–255 with
manufacturer icons, each linking out) and carries none of the detail below — register addresses,
bit layouts, power-on state and write protocol live on the **individual mapper pages** one click
away. Grid = coverage map; per-mapper page = the fact sheet.

Because those per-mapper pages are web-fetchable, **assembling a fact sheet is agent work.** What
genuinely belongs in this file is the judgment (is this board worth shipping at all?) and anything
needing the local dumps — sample counts, header scans — which require `GRM_ROM_DIR`.

Per mapper:

- window layout — which ranges switchable, which fixed, at what granularity
- register addresses, plus the `addr_mask` / `addr_match` decode that distinguishes the PRG register
  from its CHR/IRQ/mirroring siblings
- bank-number **bit layout** within the written byte
- **power-on / reset state** — what bank is live before any write
- whether PRG mode itself is switchable, and how
- write protocol: single write, serial shift, or latch

- [ ] **Wider gap**, by local sample count: MMC5 (5) 16 · MMC2 (9) 7 · 118 5 · FME-7 (69) 4 · 87 3 ·
      206 3 · 68 2 · 23 2 · 18 2 · 119 2 · Color Dreams (11) 2, then singletons. **MMC2 shipped and
      MMC5 is sanctioned** (see the Answered table), so what is left to judge is the tail:
      **FME-7** and **Color Dreams** are the best effort-to-payoff — both simple single-write
      latches — and everything below them is 3 samples or fewer. The open question is whether the
      tail is worth shipping at all, or whether the board list should now be considered closed
      pending a title that demands one.

- [ ] **Heads-up, not yet a question: MMC5 will probably bounce a schema decision back to you.**
      (`grm-fxm` P3.) The fact sheet is agent work and the descriptor follows the shipped pattern,
      but two shapes may not be expressible in the current vocabulary: **four** switchable PRG modes
      (32K / 16K+16K / 16K+8K / 8K×4), and a bank register whose high bit selects **PRG-RAM instead
      of ROM** — a bank number meaning two different memories is new here. The bead's standing
      instruction is to surface that early rather than invent schema, so expect the ask before any
      YAML is written, not after.

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

- [ ] **Overlay blocks for PRG modes a ROM never uses — prune, script, hint, or leave?** (`grm-ic5`
      P3, your own idea.) smb3 carries `blocks.total 103 / blocks.overlay 95`, and its `$8000` bit 6
      is set at every observed write, so the mode-0 window blocks are never live. Three shapes are
      filed and **none is chosen**: (a) post-analysis prune on evidence (zero instructions, zero
      inbound refs, no resolved mode-selecting write), (b) a user-invoked script — explicit and
      undoable, (c) a per-game `grm-hb6` hint declaring the live mode as a recorded fact.

      This needs your call rather than more analysis because the bead already concedes the value is
      **convenience, not correctness** (you noted the blocks are easy to delete by hand today), and
      that judgment is what decides how much machinery is justified. Note the trap the bead records:
      load-time suppression is the one shape that cannot work, since the evidence does not exist
      until after analysis has run.

- [ ] **Is Gradle dependency locking + verification metadata worth it here?** (`grm-e7w`, now P4 and
      `blocked-on-human`.) Version strings are already pinned in `build.gradle`. Full verification
      metadata is real supply-chain hardening with real maintenance friction for a project this
      size. A "no" is a perfectly good answer — record it and close that half.

      *(The CI half of this question was answered 2026-08-15 — see the Answered table.)*

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

- [ ] **The `game-music-extraction` corpus: is it durable, and whose format is it?** (`grm-ced`.)
      Two small questions that together decide how far we can lean on it.

      *Durability:* can a test hash-pin one of those `.bin` extracts the way the real-ROM tier pins
      ROMs, or are they reproduced by the `dumpspc.pl` scripts on demand? If they're regenerable
      rather than archival, the pinning story changes and the scripts become the artifact of record.

      *Provenance:* is the `[len][addr][data]…[0][entry]` container your own convention, or a
      third-party format with a name? It decides whether we document it as "the GME upload format"
      or as ours — and whether anything derived from it could ever be committed here.

      *(The `lufia/lufia.idb` half of this item moved out — reading it turns out to be cheap
      agent work, not a judgment call. See the note under section 1.)*

---

## 5. Upstream (needs your GitHub identity)

Agents can't file these — they need an account and CLA agreement.

- [ ] **`Loader.validateOptions()` is never called outside the GUI import dialogs — document it or
  wire it up?** (`grm-vsg`, investigated 2026-08-21.) At 12.1.3 the only callers are
  `ImporterDialog:442`, `AddToProgramDialog:82`, `LoadLibrariesOptionsDialog:60`. Not
  `ProgramLoader`, not `HeadlessAnalyzer`/`analyzeHeadless`, not `GhidraScript.importFile`/
  `importFileAsBinary`, and **not even the GUI's own `ImportBatchTask`** — so a loader author's
  option validation runs on GUI single-file import and nowhere else. **This is NOT a 12.x
  regression**, which is how our own bd memory framed it: the pre-refactor 11.4-era
  `AutoImporter`/`HeadlessAnalyzer`/`GhidraScript`/`ImportBatchTask` did not call it either, and
  `git log -S` on `Loader.java` shows the method unchanged in this respect since the original
  open-source commit. Whether GUI-only was *intended* is unrecorded anywhere — no comment, commit
  message, or javadoc says. So the ask is modest and has two acceptable outcomes: either document
  the limitation on `validateOptions()`'s javadoc so loader authors stop relying on it, or wire it
  into `ProgramLoader` so it runs everywhere. **A drafted issue body is on `grm-vsg`'s close
  comment** — it leads with the call-site list and explicitly concedes the not-a-regression point,
  since opening with a wrong severity claim is how these get closed unread. Low urgency: we have no
  live exposure (see that bead), so this is a courtesy report, not a request for a fix we need.

- [ ] **Two PRs for the ADC/RRA flag fix**, landed locally as `grm-o9k` 2026-08-22. Different
  repos, different maintainers — `6510_illegal.sinc` is vendored from deity-informant, not Ghidra.
  **Patch text, reasoning and PR framing are already drafted on the beads**; nothing left but your
  identity (and a CLA check for the second).

  - `grm-ef46` → NationalSecurityAgency/ghidra, `6502.slaspec`, the ADC half. Fork recipe below.
  - `grm-c9hv` → anarkiwi/deity-informant, `6510_illegal.sinc`, the RRA half.

- [ ] **`bd prime`: ask beads for an index emission for memories, instead of all-or-nothing.**
  (`grm-8ctl`, researched 2026-08-26.) **The full issue body is drafted verbatim on `grm-8ctl`'s
  comments** — title on the first line — so this is review-and-post, nothing left to write.

  The ask: `bd prime` today emits every memory body in full, or (since `--no-memories`, merged
  2026-07-14) none at all. Neither is right for a workspace whose memories are load-bearing. We
  measured 101,019 bytes of prime output, 95% of it memory bodies, truncated by the host to a
  ~2 KB preview — so the memories are stored, synced, and silently absent from the context they
  exist to inform. `bd memories` already produces the right artifact (5,297 bytes for 34 entries)
  and `bd recall <key>` already fetches one body; the only missing piece is `bd prime` being able
  to emit the former.

  Two things the draft is careful about, worth preserving if you edit it: it concedes that
  **there is no per-memory summary field** to index on (`bd memories --json` is flat
  `{key: body}`, `bd remember` has no `--summary`), so a v1 can only truncate — and it explicitly
  does *not* ask for the schema change. And it distances itself from **#5153**, whose ask #1
  (list/search) is already satisfied by `bd memories` and which would otherwise be a tempting
  place to close this as a duplicate.

  Prior art to cite, both verified by direct API read: **#3961** (closed, merged as PR **#4336**)
  is the same problem from `loom`, whose maintainer measured >150 KB and whose workaround was the
  brittle stdout-stripping this would replace.

  **Note `gh` on this machine is not authenticated** (`gh auth login` needed) — an agent found
  that out trying to read the release metadata, so budget for it.

*Two things learned that the next upstream item should inherit:*

- *`CBongo/ghidra` now exists as a fork, and `D:/git/ghidra-fork` is a full clone whose `origin`
  is the **read-only reference checkout**, not GitHub — name the GitHub remote explicitly, cut the
  branch from a freshly fetched `master` (not `HEAD`), and use `git worktree add` so the b3m fork
  build tree stays on its own branch. Full recipe on `grm-6xh`.*
- *An agent cannot confirm a fork exists by searching for it: GitHub repo search omits forks unless
  the query carries `fork:true`. Check the fork's `master` head directly instead.*

---

## Answered (kept as a record of what the method produced)

| question | answer | bead |
|---|---|---|
| Should `bless` still write a golden when the fixture's criteria failed? | **No — ruled 2026-08-12: fail closed, with a `--force-criteria` override.** The "deliberate design decision" the bead warned about was real but made about a different harness: the unconditional bless dates to the suite's *first* commit (`159ce7e`, 2026-07-08), and the candidate cache arrived two weeks later (`c915ec2`, `grm-lne`) and simply *mirrored* it — nobody ever weighed it against the check-then-bless workflow. Two findings killed the case for leaving it. **The stated rationale was never load-bearing:** `check` already writes the candidate to `$WORK` and prints the full `diff -u`, and since `grm-lne` also persists it to the cache with a `.crit` verdict — nothing about diagnosing a failure ever required overwriting `expected/`. **And the golden carries no record of the verdict:** the dump is only the `BANKDUMP` section, so a blessed-over-a-failure oracle is byte-indistinguishable from a good one, which makes "visible in `git diff`" false as a mitigation — every durable artifact says "fine". Also settled: `bless` was never "bless no matter what" anyway (headless-nonzero and missing-`BANKDUMP` already refused; only `SUITE FAIL` fell through), so this makes the three cases uniform rather than inventing a new rule. **Implemented as one shared `bless_candidate` helper both routes call**, because the cached and fresh paths had already drifted in four ways (only the cached one showed the golden diff; they flagged criteria on opposite sides of the copy; only the cached one printed the `SUITE` line; only the cached one announced a missing golden) — parity by construction, not by review. Refusal is per row, so good rows in the same run still bless. Missing/empty `.crit` counts as failure. `--force-criteria` exits 0 and names what it forced. Atomic temp+rename included, which closes `grm-aqi`'s own acceptance criteria — **`grm-z34` keeps only its remaining non-`run_one` write sites** | `grm-aqi` **closed**; unblocks `grm-z34` |
| In `ff3spc.dis`, is the raw `NOT1 $E04D` form the tool's output and `NOT1 $004D.7` your hand correction? | **Yes — the disassembler did not handle those correctly** (owner, 2026-08-18). This turned out to be one thread of a larger pattern the corpus differential then confirmed: **the two earliest listings were produced by an earlier, buggier version of the same tool, and the corpus dates the fixes.** ff2 (May 2000) reverses the operand order of every `dp,dp` form — its own `<d>`/`<s>` markers state the wrong claim outright, and the vector suite settles which side is right — and mis-decodes `5A`, `3B`, `BE`, `A7`. ff3 (Feb 2001) has all of that right but still prints the bit instructions' raw 16-bit operand. Both compute a short branch with offset **exactly `0x7F`** one page low (a sign test written `>= 0x7F`), while handling `0x7E` and every negative offset correctly; fzero (Aug 2001) gets `0x7F` right too. **Retires the earlier reading that ff3's `BEQ $0E13` was a one-character typo** — it is the same systematic off-by-`0x100`, 2 for 2 across two files. Consequence: read an ff2/ff3-only oddity as an early-tool artifact first, and do not spend effort reconciling one against a later listing. | `grm-uy9s` |
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
| Does any corpus title run the 6502 stack deep enough to reach the low stack page? | **Not measured — retired by ruling instead, 2026-08-12. Do not run the emulator trace, and do not re-open this as a measurement question.** The project owner declined the min-`S` watchpoint on cost grounds and replaced it with an *estimated* threshold: assume `S` never descends below `$40`, so `$0100-$013F` is fair game for shadows and stashed arguments and `$0140-$01FF` is refused. The reasoning is that a trace answers only for the titles traced, while a movable threshold covers the corpus and every future title at once. Implemented as `StackFloor` (`DEFAULT_FLOOR = 0x40`), consulted by all three walks that previously made the assumption tacitly and separately: `StoredValueScanner.forwardedStoreValue`, `BoardBankAnalyzer.argumentSurvivesPrologue` (the `PHA`/`PHP` cases now drop tracked cells the push may have hit), and `BoardBankAnalyzer.inboundArgumentCell` (where the caller's own `JSR` return address is the unseen write, and a wrong answer is a confident wrong bank rather than a forfeited forward). Overridable per program via the `Retro Machines.Stack Floor` program-info property — the seam a game `.yaml` should write when the descriptor tier grows a field — or per run via the `retromachines.stackFloor` system property; both accept `$40`/`0x40`/`64`, and a malformed value falls back rather than failing the import. The endpoints reproduce both historical behaviors exactly (`0` = the pre-increment-2 blanket refusal, `0x100` = increment 2 as shipped). **Measured cost: zero.** Full gate green, real-ROM curated 10/12 with only the two documented baseline fails (smb3 `grm-evn`, megaman `grm-g73` jitter), and GME 19/19 including dodge, cv2 and kicarus — the exact titles the assumption was argued from, whose scratch cell `$0103` sits well below the floor. **What would reopen this:** not a trace, but a *title* — a real ROM where a bank shadow or stashed argument stops resolving and the cell turns out to be at `$0140` or above. The fix then is to move the floor for that title, not to re-litigate the walks | `grm-mej.3` |
| Is ff1's bistability still real — close `grm-4nr` or keep it as a standing watch item? | **Closed not-reproducible 2026-08-15 — then REOPENED THE SAME DAY when it reproduced.** The close reasoned from consecutive runs (3:2 at filing, then 10/10, then 19/19; P = 0.6%). Hours later a full `realrom-test.sh check --all` at afe399a produced **the same two states as 12 days earlier** — refs 1847↔1880, instrs 7382↔7426, an identical ±33/±44 delta, everything else byte-identical (bankComments 75, warnings 34 both ways). So the bistability was never removed and the grm-izu/grm-2dr speculation was wrong; only the *warnings* component vanished, because the warning population itself collapsed ~600→34. **The real lesson is methodological: these states are STICKY, not independent per-run draws.** ff1's golden was re-blessed on 08-11 to the *opposite* state from the one originally blessed, so the title had migrated and then sat there — meaning a long clean streak shows it is PARKED IN ONE STATE, not that the other is gone. Binomial/rule-of-three reasoning systematically understates this; **do not close a bistable-golden bead on a clean streak.** Caught only because the run used `--all` (ff1 is a GME row; a bare `check` reads just the 12 curated rows). Still NOT linked to megaman's jump table — megaman failed in the same run with its own distinct grm-g73 signature (refs 1704→1703, instrs pinned). Next step, still never done: a DeterminismProbe localization run on ff1 | `grm-4nr` **REOPENED P2**; memory `bistable-golden-sticky-states` |
| Should this repo have CI at all? | **No, not at this time — ruled 2026-08-15.** We are the sole contributors, so there is no integration to continuously integrate: CI would only re-run the testing already required before every push, at the cost of a runner that fetches and pins a Ghidra install matching `ghidraTargetVersion`. **Revisit trigger is people, not effort** — when outside contributors start submitting changes, CI stops being redundant re-testing and becomes the only way to trust a contributor's claim that the gate was green. `grm-e7w` dropped P2 → P4 and marked `blocked-on-human`, grouped with `grm-9ut`/`grm-fy0` behind the public-release decision; of the three, **`grm-9ut` lands first** (release builds serve people who USE the extension, a real audience; CI serves people who DEVELOP it, which is hypothetical). The dependency-locking half of the original question is still open — it stays in section 4 | `grm-e7w` (deferred, not closed) |
| Does the real-ROM tier need to run in the default gate, given contributors without ROMs? | **No — question dissolved, 2026-08-15.** `grm-6kv` carried an open design question ("what should the gate do on a machine with no ROMs?") that assumed a contributor who lacks them. For both current contributors the ROMs are **always** present, and the ROM-less contributor is hypothetical — so there is nothing to design around. **Do not redesign the tier model.** The resolution is process, not architecture: make the real-ROM pass a documented local pre-push requirement, make *not having run it* visible via a staleness signal (the `grm-mu7` failure mode was that nothing told anyone the tier had not run), and skip LOUDLY when `GRM_ROM_DIR` is unset rather than reporting a clean gate. This moved `grm-6kv` off the planning list and onto the mechanical/farm-out list at unchanged P2 | `grm-6kv` |
| Is mapper 9 (MMC2) worth a descriptor for essentially one game? | **Yes — ship it, ruled 2026-08-15, and it SHIPPED the same day** (`c4424cc`, `machines/nes-mmc2.yaml`). Punch-Out!! is in scope for the GME project, which is the consuming use case, so a one-game board is justified. **Do not model the latch-driven CHR banking** — it is PPU-read-triggered, so there is no CPU-recoverable switch to find at all. Two modelling choices worth carrying to the next board: the three FIXED windows carry `on_write: mechanism` (real hardware routes *every* write in `$A000-$FFFF` to some register), and the third-to-last bank is expressed as `second_last - 0x2000` rather than inventing a `third_last` keyword. Two traps it surfaced: `_write_rom`'s `prg_banks` counts 16 KiB *header* units, not the fixture's internal bank size; and **a fixture name not registered in `VerifyBankTest.java`'s dispatch chain falls through to the C64 default and prints nonsense instead of failing** — adding a board is a two-side job | `grm-tas` **closed** |
| Is MMC5 (mapper 5) worth the effort, given it is the biggest board Nintendo shipped? | **Yes — "we should absolutely do MMC5", ruled 2026-08-15.** 16 local samples, the largest count in the corpus survey, so the payoff is real rather than speculative. Filed as `grm-fxm` **separately from `grm-tas` on purpose** — folding the most capable Nintendo mapper into the one-window MMC2 bead would hide a large piece of work behind a small one. Sequencing is MMC2 first (it establishes a fresh end-to-end precedent against the current tree), then MMC5 against that pattern; MMC2 has since shipped, so MMC5 is unblocked. ExRAM, split-screen, the multiplier and the vertical-split modes are PPU-side and out of scope — but say so *explicitly in the descriptor comments* rather than leaving the next reader wondering. **One thing may still come back to you:** the four-mode PRG plan and the ROM-vs-RAM bank-select bit may not be expressible in the current vocabulary, and the standing instruction is to surface that as a schema decision early rather than invent one — see section 3 | `grm-fxm` |
| Does any real Bandai cart write an FCG register with an *indexed* store? | **No — and structurally, not by luck. Leave `grm-egw` at P3 indefinitely; do not pre-emptively harden the path.** Indexed stores into the register file are common (dbz2 has "several" `99 00 80`, dbz_saiyan three) but every one is a `STA $8000,Y` loop with **Y counting 7 down to 0**, i.e. `$8000-$8007` — the eight CHR registers. The PRG register is `$8008` and Y never reaches 8. That is the register file's own layout: CHR occupies the low 8 slots and forms a natural 8-iteration loop, PRG is a single slot past the end, and nothing has a reason to index to it. Compounding it, the bug needs a **known** index to fire (`addBaseReferenceOnce` only retargets when the index resolves) and a loop-carried Y presents no constant. Per-title: db3 register base `$6008`, no `99 00 60`/`9D 00 60`, helper db2f (shadow `$6a`); dbz2 helper d12f (shadow `$4c`) → `$8008`, no `9D 00 80`; dbz_datach helper cc28 (shadow `$59`) → `$8008`, neither pattern; dbz_saiyan helper c9c0 (shadow `$49`) → `$8008`, no `9D 00 80`. Unchanged by `grm-46h`'s new `$6000-$7FFF` range (same $x008 geometry, and db3 has no indexed stores there either). If it is ever fixed, the `writesInRange` fallback must still DECLINE on (addr_mask present AND indexed operand) | `grm-egw` |
| Where is DB3's bank-switch stub copied into RAM `$0200`, and what is its argument convention? | **Wrong question — there is no stub. `grm-azv`'s premise was disproven on both counts, and this exposed a live descriptor bug.** db3 switches PRG with an ordinary ROM helper at **db2f** writing shadow `$6a` and register **`$6008`**; the copy loops at e69e/e707/e712 copy **data, not code**. We saw no mechanism write because `nes-bandai-fcg.yaml` declares one latch range, `$8000-$FFFF`. **db3 is iNES mapper 16 submapper 4 (FCG-1/2), which decodes registers only in `$6000-$7FFF`** — and the descriptor's module header has the submapper table backwards, calling 16.4 an LZ93D50 `$8000` board and 16.1/16.2 the legacy generation. NESdev's actual table: 16.1/16.2/16.3 are deprecated aliases for mappers 159/157/153; **16.4 = FCG-1/2, `$6000-$7FFF`; 16.5 = LZ93D50, `$8000-$FFFF`**. All four pinned fixtures carry **NES 2.0** headers with the submapper in `h[8]`'s high nibble (db3 `40` → 4; dbz2 `50` → 5; datach/saiyan are mappers 157/159), matching the observed register bases exactly — and `NesRomLoader.InesHeader.parse` reads `h[8]` only for the mapper's high bits and **discards the submapper**. Fix is a second memory-latch mechanism at `$6000-$7FFF` (NESdev's own submapper-0 prescription: model both ranges; each real board responds in only one). **Do not pursue the RAM-resident route, and do not use db3 as `grm-hb6`'s first customer** — it needs a descriptor change, not a per-game hint, so the hint tier needs a new acceptance target. "Dragon Ball - Daimaou Fukkatsu" is a second local submapper-4 title, so this is not a one-off | `grm-46h` filed **P2**; `grm-azv` retitled and blocked on it; copy-loop premise retired on `grm-7pp` |
| dragonpower / shenlong def-use pass: is `FUN_8eeb` PRG or CHR, what is the call-site table, and what are the four unexplained mechanism writes? | **Pass complete; one trace did cover two, now measured. `FUN_8eeb` IS NOT CODE.** All four banks of dragonpower are essentially identical over `ff88-fff9`, and shenlong's four are identical to each other *and to dragonpower* — the byte-compare prerequisite is settled and every finding transfers. **Engine, completed:** `$FFE8` (`STA $F2 / JSR $FFBE / JMP ($17)`) is the far-call entry, bank arriving in **A**; `$FFBE` recomposes the mapper-66 composite register from shadows `$F2`/`$F9` and **takes no register argument**; `$FFDC` is the far-*return* (sets `$17/$18` from the caller's return address + 1, pulls the saved bank, falls through to `$FFE8`). Worked call site: `$983F` pushes `$F2`, sets `$17/$18` from a 3-byte-stride 6-entry table at `$8000`, then `LDA #1 / JSR $FFE8` — a **constant** bank argument does exist. Shadow-writer table is a one-liner: **`$F2` is written by exactly one instruction**, `$FFE8`'s `STA $F2`. **Site dispositions (6 per title):** `8ee4` phantom from an over-read jump table at `$8F00` (30 real entries) — this is where "`FUN_8eeb`, co-equal second helper" came from, so **stop looking for one**; `e3bb` phantom (data-as-code, table at `$91AF`); `e906` phantom (mid-instruction resync, table at `$9076`); `ffc8` is `$FFBE`'s own `STA $FFCC,Y` (contra's c142 disposition, honest by construction); `ffea` is `$FFE8`'s internal `JSR $FFBE` — **but the bank arrives via the `$F2` shadow one instruction earlier, so this is `grm-mej.2`, not the `grm-mej.3` stack case previously predicted**; `9913` calls the no-argument `$FFBE`, so "argument could not be recovered" is a misframing and likely a **`grm-xym`** spurious warning. Wrapper set (check #2) is empty by elimination. **Three of dragonpower's six warnings are `grm-eyn` phantoms from three distinct over-read tables in one title** — denser than megaman's single `a737`, and it means the warning count on these titles overstates the real gap ~2×. Ceiling still gated on `grm-e7v` (`$FFCC` unreadable under a single fully-overlaid `PRG_ALL` window) plus `grm-mej.2`; `grm-mej.3` is **not** on the critical path. **Closed out the same day:** shenlong's last two sites are phantoms too — `a03f` from an over-read table at `$87D0`, `d9a9` from one at `$9076`. So **all four** "unexplained mechanism writes outside the invariant region" were the same artifact, and the hypothesis they supported — per-bank code switching that bypasses the helper — is **dead on both titles; do not revive it.** Each title's six warnings are now 3 phantoms + 1 by-construction + 2 engine-internal, identically. `$9076` is over-read in **both** ROMs at the same address (they share a codebase well past the engine region), making the pair `grm-eyn`'s best regression case: one root cause, two images, two distinct symptoms. **Read the result precisely:** no *unexplained* site remains, but nothing is *resolved* either — both titles stay at 0 refs, gated on `grm-e7v` + `grm-mej.2`. The result is that **no new mechanism is missing**: the entire gap is attributable to four named beads with no residual unknown, which accounts for two of `grm-8iy`'s eight zero-instruction GME titles | `grm-hum`; phantom density and the regression pair on `grm-eyn`; spurious-warning suspicion on `grm-xym` |
| Is smb3's `FUN_c542` a real bank-switch helper, or a false one? | **Real.** `c5f5` — already in your earlier smb3 trace as a direct `$8000`/`$8001` write — is *inside* `c542`'s body, which is why that trace listed the site but never named the function. `c542` sets PRG bank `$1a` and restores it later via a call to `$ffc2`. So the `867b`/`ac6d` warnings are honest, the production output is correct, and **smb3's golden is stale by exactly two lines** — the opposite of the standing "golden correct, output wrong" rule in `CLAUDE.md`, which was written when the diff still held the `ca23`/`ca2e` regression `grm-67g` has since closed. Update that rule in the same change that blesses. **Second, separate finding: the warning text is itself wrong.** A helper that deposits a *constant* has no argument to recover, so `867b`/`ac6d` should annotate bank `$1a`, not warn. Suspected cause (hypothesis, not measured): `c542` is a save/switch/restore shape like wizwarr `ff69`, "last switch wins" lands on the `$ffc2` restore, and `restoresEntryBank` is not firing — every case it has handled so far is AxROM/UxROM, and smb3 is MMC3. | `grm-evn`; unblocks `grm-bj6` |
| What is the real extent of rcproam's jump table at `$8068`? | **Six entries, at `$806b`, holding four distinct targets: `8077`, `818a` ×3, `8675`, `884d`.** Entry 0 (`8077`) is the first address *after* the table — a self-terminating layout, and direct corroboration that the lowest-target bound's premise is sound here. **Decisive: none of the five targets the bound stops recovering (`80a2`, `80f0`, `812a`, `8500`, `8509`) is a real target.** So rcproam's refs 1298→931 / instrs 4810→4094 is the fix removing code seeded by an over-read, not a loss — the corpus's "only clear loss" was the fix working. **Do not add a decline condition on rcproam's evidence**; there is no legitimate target sitting below the table. Still to measure agent-side: that the bound computes 6 rather than truncating further (check refs to all four targets against the PATCHED install — both env vars, `grm-k0h`). | `grm-eyn` |
| Are megaman's 12 shed bank comments real losses or phantoms? | **Phantoms — `8d1f`–`8dbf` is all data, no code.** The `bank -> 5 (bank=5) via RESET` comments hung off instructions that existed only because a bogus jump target seeded disassembly into a data region, so `bankComments` 156→144 is a correction. Explains the counts moving against each other (instrs +42, comments −12): phantom code removed in one region, real code recovered in another. **Bonus, and the more actionable half — three more over-read tables named with true lengths: `e000` (over-read to `e0ed`, true 18), `e121` (`e2a2`, true 19), `e44e` (`e55a`, true 10)**, "the sources of the bad refs". So megaman's over-read problem is at least four tables, not just `a737`. Pin 18/19/10 as acceptance expectations rather than re-deriving them. | `grm-eyn` |
| What is worth a human's GitHub identity on `grm-b3m` — the stride-guard PR, or something else? | **Neither, as written. Posted the fix-shape argument to [#9447](https://github.com/NationalSecurityAgency/ghidra/issues/9447#issuecomment-5310139901) on 2026-08-16 — but built around the *working* fix, not the failure report this item described.** This entry predated grm-eyn's 2026-08-16 adjudication; by posting time the lowest-target rule was validated against hand disassembly, so the comment leads with it and uses the stride guard's collapse only to motivate it. Two mechanism facts carry the argument, and they are the reusable part: `sanityCheck` already owns the truncation machinery *and* its `diff > 0xffff` test is dead code on 16-bit targets (the slot is vacant), and it runs **before** `LoadTable::collapseTable`, so per-entry LOADs are still live and **no stride inference is needed anywhere**. Safety rests on `minTarget > tableStart`, which declines on the `.rodata` arrangement. **Every per-title measurement table was deliberately cut** (~780 → ~440 words): they argue a case upstream has not disputed, and the comment's job is to demand minimal attention — post them only if asked. One number survived, `44 → 0` refs. Corpus-is-6502-only and the proven-identical control build were stated up front. **The stride formulation stays dead and `grm-g73` stays blocked.** Next signal is a `caheckman` reply naming a preferred fix shape; **continued silence is not a reason to send a patch speculatively** | `grm-b3m` (open, waiting on upstream) |
| `grm-6xh` — file the trivial setter PR | **Submitted 2026-08-17: [#9513](https://github.com/NationalSecurityAgency/ghidra/pull/9513)**, one file, +3/−3, cut from master `d5f144c2`. **It is a two-line fix, not the one line the bead recorded:** the javadoc above the setter was copy-pasted from `setMaxSpeculativeOffset` and wrong in the same direction as the bug, so shipping the assignment alone would have left the method contradicting its own documentation. Bug re-verified on **master** before filing rather than trusted from the 12.1.2-tag investigation. The framing that answers "how did nobody notice this" — and the line worth reusing — is that the **three-argument constructor assigns both fields correctly, so the bug is reachable only through the fluent form, which is the form the analyzer itself uses**. `mergeable_state: blocked` at submission is the normal fresh-PR state pending the CLA check | `grm-6xh` (open, pending merge) |
| SPC700 language sourcing — bundle SPCdra, depend on it, or write our own? | **Vendor the decode table, rewrite the semantics, write our own loader — and SPC700 is a PRIMARY PLATFORM, ruled 2026-08-16.** Both halves answered: Apache-2.0 vendoring approved ("i'm good with vendoring the spcdra sleigh"), and the product call went further than the bead asked — *"spc700 is an important part of reversing SNES games and should be considered a primary platform, so the work is worthy."* Hence a new epic (`grm-c9d`) rather than a task under the SMC work, and `grm-1.7.3` raised P3→P2. **The bead's own "bundle vs depend vs reimplement" framing was the wrong axis** and none of the three describes the answer. Evidence: the DECODE TABLE is complete and sound (256/256 opcodes — 208 explicit plus three low-nibble families, no collisions; correct operand text, lengths, and TCALL vector arithmetic), but the SEMANTICS are broken in ways **measured from real p-code, not inferred** — `ADDR8`/`ADDR16` double-dereference every data access (`MOV A,$10` emits two LOADs and means `A = **(word**)0x10`; absolute and stores affected too), `CMP`/`SBC` set carry inverted so every `CMP`/`BCS` decompiles backwards, `ADC` hardcodes `N=0`, `ASL`/`ROL` can never set carry (a byte assigned into a 1-bit bitrange), `INC`/`DEC` set no flags, `MOV dp,X` stores to the wrong address. **The tell, worth remembering: the disassembly TEXT is correct in every case** — decode tables get exercised constantly, p-code never does. And the `.spc` loader the bead called "the fastest value" is **5.4 KB, one file** — not the valuable half. **Do not hand-review the semantics rewrite**; `SingleStepTests/spc700` vectors exist and the harness (`grm-c9d.2`) is deliberately sequenced *before* the rewrite. Same vector family as the `grm-o9k` 6502 ADC/RRA fix names, so build the runner reusable | `grm-y7d` **closed**; epic `grm-c9d` + `.1`–`.5` |
| Do you want to cut a public release, and when? | **No — not any time soon, ruled 2026-08-16.** *"i don't have any plans for cutting a release anytime soon, so the CI and release and user docs beads can all stay on the back burner."* All three stay **blocked** at current priorities (`grm-9ut` P2, `grm-fy0` P3, `grm-e7w` P4) — blocked is the correct state, not a bug to fix, since it keeps speculative work out of `bd ready` sweeps. **Nothing technical is outstanding and none of it should be re-derived**: the trigger mechanism, the Ghidra 12.0 hard floor, the reference workflow, and the together-ships-with rule (`grm-9ut` + `grm-fy0`; a release zip nobody can use is half a deliverable) were all settled earlier. **Revisit trigger is an audience, not a date** — no milestone was given and none was asked for, since "not soon" is complete on its own. Note the two triggers differ by population: `grm-9ut`/`grm-fy0` wait on *users*, `grm-e7w` waits on *outside contributors* per its own 2026-08-15 ruling. **Do not re-ask this in a future "what should we work on" sweep** — ask again only if a trigger actually fires | `grm-9ut` / `grm-fy0` / `grm-e7w`, all still blocked |
| Are the bank claims `grm-913` weakened honest losses, or is the bank knowable across an interrupt boundary? | **Honest losses — outcome (a), ruled by hand disassembly of `rcransom` 2026-08-22.** The IRQ handler calls `fa54`, which saves the live bank by reading `$BFFF` (a ROM-resident bank ID byte), calls `$8003` in bank 5, and restores it via `fed1` — which clobbers the `$fc`/`$fd` shadows, so the handler stack-saves them and puts them back just before `ff29`. The NMI path does the same around `ff07` (its guard may even be dead code — no intervening PRG switch was found). A cartridge that saves and restores the live bank **at runtime** proves the entering bank is not a compile-time constant, so `r6=0,r7=1` came from the entry seed and nowhere else. **All 11 rows / 128 weakened sites and the 9 lost claims are blessable; do not reopen this as `grm-mej` scope.** The 10 `rcransom` "requirement violated" warnings are NOT covered — `fa54` is bank-*preserving*, so that wording looks like our own derivation conflating two unknowns, which is agent work under `grm-vgod`, not a question for you. The `$BFFF` idiom itself is `grm-sen5`. | `grm-2pie` |
| Is SNES a supported machine, or only a means to the SPC700 end? | **Fully supported machine — ruled 2026-08-22.** *"yes SNES is intended to be a fully supported machine, not just a means to load the SPC."* The cheap "ROM side stays minimal" option is off the table: 65816 language, LoROM/HiROM/ExHiROM mapping, the `.smc`/`.sfc`/`.fig` loader with copier-header detection, and `$2100-$43FF` typed IO are all in scope. `grm-9nxj` promoted P4→P2 and is no longer a placeholder; it still needs **scoping**, which is a separate step from this product call. Next agent step is already filed as `grm-9wbv` — evaluate Ghidra's shipped 65816 processor (decode coverage, m/x width modeling, semantics) on the `grm-y7d` SPCdra template — and needs no further human input. **Do not re-open LoROM/HiROM as an open question**: it is a header lookup, per the bead's 2026-08-17 correction. | `grm-9nxj` |
| Which wrappers does the analyzer admit at nesskiptest's site B (`FUN_c170`, `FUN_c173`, both, neither)? | **Still unknown — but the GUI route asked for here is provably incapable of answering it, so this is no longer a human question.** You ran it (2026-08-22): the pre-repair pass logs `[FUN_c150, FUN_c15a, FUN_c170, FUN_c175]`, and the post-repair re-analysis ran but emitted *nothing* — worker completed in 0.016s, zero lines. Cause is ours: `BoardBankAnalyzer.java:226` gates every diagnostic on `verbose = AnalyzerRunLog.isInitialRun(...)`, which a persisted Program option flips off after the first stable run. **So no GUI observation can ever report on a second-pass analyzer run — do not request one again.** The golden can't settle it either: `annotateBankSwitch` sets EOL comments and never clears them, so the `via FUN_c170` line at `c00c` may be a stale pre-repair leftover, byte-indistinguishable from a fresh one — **do not close `grm-gpi` on the golden.** Moved to agent work as `grm-135j` (clear the annotations between passes, re-run headless) with `grm-w0k6` as the durable fix. Two useful by-products: the analyzer log *is* persisted at `%APPDATA%/ghidra/ghidra_<ver>_PUBLIC/application.log` (ask for that, not the Window menu — the panel may not exist), and `FUN_c170` sits in the helper list with **no** `[bank-summary]` line because `modifiedMask` unions over direct calls only and `c170` reaches `c175` by fallthrough. | `grm-gpi`; `grm-135j`, `grm-w0k6` |
