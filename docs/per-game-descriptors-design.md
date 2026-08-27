# Per-Game Descriptors: The Title Tier (design)

Design for the **per-game descriptor tier** — a third descriptor level below console and board,
in which a reverse engineer records what they discovered about one specific *title*, so the
discovery persists, gets shared, and feeds back into the loader and analyzer.

**No code is written by this note.** It is the design the beads sequence; every "must" below
describes work that does not exist yet. Following the `docs/smc-*-design.md` precedent, all
API/schema facts were validated against the tree and the `Ghidra_12.1.2_build` checkout,
which was this project's `ghidraTargetVersion` when the note was written (the
project has since retargeted; see `gradle.properties` for the current value); citations are
`file:line`.

Companions: [`SCHEMA.md`](SCHEMA.md) (descriptor authoring reference — this tier adds sections to
it, it does not fork it), [`MAP_FORMAT.md`](MAP_FORMAT.md) (the compiled-artifact contract, which
this tier extends with a sibling artifact), [`vision-board-banking.md`](vision-board-banking.md)
(§5.5 states the tier's place; principle 6 was amended to permit it), and
[`smc-runfromelsewhere-design.md`](smc-runfromelsewhere-design.md) /
[`smc-inplace-vs-overlay.md`](smc-inplace-vs-overlay.md), whose `copied_from` front-end is the
closest existing analogue and supplies most of the design properties inherited here.

Motivating beads: **grm-2yx** (bank-switch sites automation cannot see), **grm-m95** (bank values
fed by helper/table), **grm-54p** (the C64 instance: import a fully pre-analyzed ROM), **grm-p5w**
(sourcing external reference data), closed **grm-hnm** (the working symbol-generation precedent).

---

## 1. The problem and the scope

### 1.1 What the board tier structurally cannot carry

`DescriptorCopyHintAnalyzer` already drew this boundary, and drew it correctly, in the sentence
that opens its class javadoc (`src/main/java/retromachines/DescriptorCopyHintAnalyzer.java:37-45`):

> *Some copies are machine facts, not program facts.* The C64 KERNAL copies the CHRGET byte-fetch
> routine from ROM `$E3A2` into zero page `$0073` during its own init […] A descriptor states such
> a fact once, in the destination region's `copied_from[]` list […]

Everything in `machines/*.yaml` today is a machine fact: it is true of every program that ever ran
on that board. The C64 KERNAL copies CHRGET whatever cartridge is plugged in. UxROM latches on any
write to `$8000-$FFFF` regardless of which game is doing the writing.

**Per-game hints are program facts** — true of exactly one PRG image and nothing else. They cannot
go in a board descriptor without making the board descriptor lie about every other title that
shares the board, and there is no honest way to put "Contra latches at `$C34A`" in
`machines/nes-uxrom.yaml`, which also serves Mega Man. The tier is required by the shape of the
data, not by convenience.

### 1.2 The two gaps that motivated it

- **grm-2yx — site discovery.** Contra (UxROM) and Dragon Ball 3 (Bandai FCG) load with a provably
  correct overlay layout yet produce zero bank comments and zero cross-bank references, while Mega
  Man on the *same board* resolves 1781. The analyzer's dataflow seeds are function entry points
  and external entry points only (`BoardBankAnalyzer.java:568-576`), so a latch store that is never
  disassembled, or sits in no function, is not merely mis-analyzed — it is not visited at all.
- **grm-m95 — value recovery.** A latch site whose bank argument arrives through a helper or a
  table defeats the backward value scanner. The site is found; the value is `unknown()`.

These are different failures needing different hint kinds (a *site* hint and a *value* hint), and
§6 gives them deliberately different precedence rules.

### 1.3 The feature already exists, in the wrong place

The zelda row of `tools/banktest/realrom/manifest.tsv` carries a hand-authored per-game hint
keyed by whole-file SHA-256, in its `loader_opts` column:

```
-preScript RunFromElsewhereTransfer.java src:W8000_M3_B1:a500 dst:6c90 len:0x1270 \
    disassemble:true function:true site:W8000_M3_B1:8d00 jump:W8000_M3_B1:a13b
```

That is a per-title fact, pinned by hash, applied at import, living in the **test harness** because
the shipped extension has nowhere to put it. `ghidra_scripts/RunFromElsewhereTransfer.java` is the
shipped manual front-end for the same fact, and it requires a human to retype the addresses every
time. This tier is that prototype lifted into the extension. Demand is not hypothetical.

### 1.4 The larger payload is annotation, not banking

Bank-switch sites are the first hint kind because grm-2yx needs them. They are the *smallest*
payload. The high-value one is labels, comments and types — and for popular titles that work is
already done to a high standard by the community (Zelda, Metroid, Mega Man and SMB all have mature
public disassemblies). Harvesting that is the difference between a fresh import that reads as
`FUN_c34a` soup and one that reads as a disassembly. §3b covers it; §3c covers the same file
pointed the other way, which is how the tier answers portability and upgrade with no new format.

### 1.5 Scope of this document

**In scope:** identity, schema, distribution, lookup, degradation, consumption, export,
round-trip, and testing for the tier as a whole; the site-hint and value-hint kinds in full.

**Out of scope, by explicit ruling:** descriptor-declared matching criteria (§2.5, deferred to a
bead); a per-game `.gdt` for `types[]` (§3b.4, a later increment); the harvest generators
themselves (§3b.2 designs their *output* contract, not their parsers).

---

## 2. Identity: which descriptor belongs to this program

### 2.1 The extension computes no hash of any kind today

This is worth stating plainly because it sets the size of the work. Grepping `src/main/java` for
`SHA256`, `getExecutableSHA` or `crc` returns nothing. The only per-title identity the extension
derives is `NesRomLoader`'s parsed iNES header:

```java
private record InesHeader(int prgBanks, int chrBanks, int mapper, boolean trainer)
```

(`src/main/java/retromachines/NesRomLoader.java:104`), consumed to pick a *board* and nothing more
(`:321-331`). Mapper number is a board key, not a title key — mapper 2 is Contra and Mega Man and
several hundred others. **Per-title identity is entirely net-new.**

### 2.2 Primary key: SHA-256 over the PRG slice

The primary key is a SHA-256 over the **PRG-ROM content only**, excluding the 16-byte iNES header
and the optional 512-byte trainer.

Rationale, in order of weight:

1. **It is the thing the descriptor's claims are about.** A site hint names an address in PRG. If
   two files differ only in header bytes, every hint in the descriptor is equally true of both, and
   a key that distinguishes them is keying on the wrong thing.
2. **Header rot is endemic.** Headerless dumps, headers "corrected" by a ROM manager, NES 2.0
   headers regenerated over iNES 1.0 originals, and `DiskDude!`-scribbled archaic headers
   (`NesRomLoader.java:136-139` already special-cases those) all produce different whole-file
   hashes over identical PRG content. Keying on PRG makes one descriptor serve all of them.
3. **The slice bounds are already in hand.** `InesHeader` exposes `prgSize()` and
   `prgFileOffset()` (`NesRomLoader.java:106-113`), and the loader already refuses to proceed when
   the declared PRG runs past EOF (`:313-319`) — so by the time identity is computed, the slice is
   known to be readable.

The digest is computed **at import**, from the `ByteProvider`, in the loader — not from
`Memory` afterwards. Reading it back out of the program would mean reassembling PRG order from the
window/overlay layout, which is loader policy and mode-dependent, and would silently change meaning
the first time an analyzer patches a byte.

### 2.3 Alias key: whole-file SHA-256

Every descriptor may also declare a whole-file SHA-256. It serves two purposes and only two:

- **Exactness** when a user genuinely wants to pin one dump — the "this and nothing else" case.
- **Agreement with the harness.** `tools/banktest/realrom/manifest.tsv` pins every row by whole-file
  SHA-256, so the harness and the extension can name the same object with the same string. A
  curated descriptor for a manifest title can literally copy the hash from the manifest row, and a
  future consistency check between the two files is a `sort | comm`.

**Resolution order:** PRG hash first; whole-file hash only if no PRG match was found. A whole-file
match therefore never overrides a PRG match, which keeps the alias from resurrecting a stale
descriptor for a variant whose PRG has since been keyed properly.

**Ambiguity is an error, not a preference.** Two descriptors claiming the same PRG hash within one
source (§4) is a build failure for the curated set and a skip-both-and-log for the overlay. This is
deliberately harsher than "first wins": a silently-picked winner among duplicate claims is
unreproducible across filesystem enumeration order, and the failure mode (someone's hints silently
not applying) is invisible.

### 2.4 Recording the resolution on the program

Two Program Info string properties, alongside the two that already exist in
`src/main/java/retromachines/DescriptorSupport.java`:

| Property | Constant | Value |
|---|---|---|
| `Retro Machine Map` | `MAP_PATH_PROPERTY` (`:79`) | existing — the board descriptor's resource path |
| `Retro Machines.Placement Override` | `PLACEMENT_OVERRIDE_PROPERTY` (`:89`) | existing — user bank placement |
| `Retro Machines.Game Identity` | *new* | `prg:<64 hex> file:<64 hex>` |
| `Retro Machines.Game Descriptor` | *new* | resolved descriptor path, or absent |

Why two and not one: the **identity** is a fact about the file and is computed even when no
descriptor matches — so a user who later drops an overlay file in can be told what hash to key it
on, and the export script (§7) has the value without recomputing it. The **descriptor path** is a
resolution result, absent when nothing matched, and it is what an analyzer reads back the same way
`BoardBankAnalyzer` reads `MAP_PATH_PROPERTY` today (`NesRomLoader.java:334-335` writes it,
`BoardBankAnalyzer.java:211` reads it through `getMapPath`).

**The identity grammar uses `:` and never `=`, and this is not a style choice.**
`DescriptorSupport.java:91-94` records why, for the existing placement grammar:

> The separator is a colon, not `'='`: the headless `analyzeHeadless.bat` arg parser (cmd.exe)
> splits values on `'='`, so an `'='`-based grammar can't be passed on Windows.

Any new grammar in this tier inherits that rule unconditionally — the game identity, any future
`-loader-gameDescriptor` option, and the export script's arguments
(`ghidra_scripts/RunFromElsewhereTransfer.java:166-171` already splits `key:value` with
`split(":", 2)`, precisely so a space-qualified address like `W8000_M3_B1:a500` survives).

### 2.5 Deferred: descriptor-declared matching criteria

A descriptor could declare *criteria* rather than a hash — mapper number plus PRG size plus an
optional byte signature at an offset — so one file covers a ROM-set variant family (regional
releases, revisions, the (U)/(E)/(J) spread) whose hints are identical.

**Deferred to a bead, deliberately.** It is not a schema addition, it is a *resolution policy*
question: two criteria descriptors can both match, criteria and hashes can disagree, and a
signature-matched hint applied to the wrong revision produces a confident falsehood at a real
address, which is the one outcome §6 exists to prevent. Ship exact identity first, watch what the
curated set actually needs, then design the precedence rule with cases in hand.

---

## 3. Schema

### 3.0 Shape, with a complete worked example

A game descriptor is a YAML file carrying `schema: 2` like every other descriptor in this repo
(`docs/SCHEMA.md:45`), with one new top-level `game:` section that establishes identity, plus
tier-scoped sections that reuse existing schema wherever one exists.

```yaml
# machines/games/contra-u.yaml
# Per-game descriptor (title tier). Curated; compiled to data/games/contra-u.gmap.
schema: 2

game:
  id: contra_u
  title: "Contra (U)"
  board: nes_uxrom               # cross-check only -- see §3.2
  identity:
    prg_sha256: "<64 hex digits -- SHA-256 of the PRG slice; see §2.2>"
    file_sha256: "26541a5550ee22deeb3d5484e4a96130219b58cff74d068fb1eb6567fa5e5519"
  provenance: "hand-authored from the grm-2yx investigation, 2026-07-31"

banking:
  switch_sites:
    # A SITE hint: "there is a bank-switch store here." Consumed as a dataflow seed (§6.2).
    - addr: 0xC34A
      comment: "UxROM bus-conflict latch (STA table,X); reached only via JMP ($0300)"
      discovered_by: "BankReachProbe candidate scan, confirmed by hand"

    # A SITE hint that also pins the VALUE (grm-m95). Ranks below recovered dataflow (§6.3).
    - addr: 0xE7D4
      bank: 3
      comment: "bank index arrives from a jump table the value scanner cannot follow"
      discovered_by: "hand, 2026-07-31"

symbols:
  # Exactly the schema of docs/SCHEMA.md:484-495 -- a named, user-toggleable set with
  # provenance -- plus the per-tier `block:` qualifier of §3b.3.
  - set: contra-community
    default: on
    block: W8000_M3_B1           # default residence for entries that name no block
    provenance: "<upstream project> @ <revision>, <license>, harvested 2026-07-31 by
                 tools/gensymbols/gen_nes_disasm_symbols.py"
    source: generated/games/contra-u-symbols.yaml
```

`prg_sha256` above is a **placeholder**, spelled as one; the `file_sha256` is the real value, copied
from the `contra` row of `tools/banktest/realrom/manifest.tsv`, which is exactly the
copy-from-the-manifest workflow
§2.3 describes. Addresses are hex in YAML and decimal integers in the compiled artifact, per
`docs/MAP_FORMAT.md`'s conventions section — the game tier changes nothing there.

### 3.1 A declarative claim, never an imperative instruction

This is the single most important property of the tier, and it is inherited rather than invented.
`docs/SCHEMA.md:471-477` states it for `copied_from`:

> Per descriptor principle 5 ("descriptor declares facts, loader decides representation") the
> directive is a claim about the hardware, not an instruction to produce a block. […] with no
> user-supplied KERNAL image the directive is **ignored outright** — no block, no overlay fallback,
> a log note only.

The game tier adopts that verbatim, with one strengthening: a game descriptor comes from a
**less trusted source** than a board descriptor. A board descriptor is in-repo, reviewed, and
regression-tested against goldens. An overlay game descriptor may have been downloaded from a
stranger, authored against a different extension version, or exported from a program whose analysis
was wrong. Every consumption rule in §6 is written on the assumption that the hint may be false.

Concretely, a hint whose preconditions fail costs nothing but a log line. It never blocks the
import, never produces a fallback representation, and never annotates.

### 3.2 `game.board` is a cross-check, not a selector

The board is chosen by the iNES header through `NesBoardRegistry.forMapper`
(`NesRomLoader.java:321-323`) or by the user's board override. `game.board` does **not** participate
in that. It exists so a descriptor can state which board its addresses were reasoned about on.

**Ruling: a mismatch ignores the whole file, with a log line naming both boards.** Not "apply
anyway" and not "override the board". A hint reasoned about on MMC1 applied to a program laid out
for UxROM names addresses in windows that do not exist or hold different content; there is no
partial-credit reading of that file. And overriding the board from a game descriptor would let an
untrusted overlay file silently relayout memory, which is a much larger blast radius than any hint.

### 3.3 Ruling on the version field: the game tier is the reason to add one

`DescriptorCopyHintAnalyzer.java:116-121` records this repo's compatibility idiom:

> Probed with `has(...)` rather than against a schema version, because the .map carries no version
> field — optional-key probing is this repo's compatibility idiom, and it means a descriptor
> compiled before `copied_from` existed simply reports "nothing to do".

**That idiom is correct for machine maps and wrong for game descriptors, and the distinguishing
property is who ships the file.** A `machines/*.map` and the Java that reads it are built from one
commit and packaged into one zip; they cannot disagree, so a version field there could never fire
and duck-typing costs nothing. A game descriptor is the **first artifact in this repo that crosses
a version boundary in the wild**: an overlay file was authored against whatever extension was
installed the day it was written and is read by whatever is installed today, and a shared file was
authored against a version nobody in this repo controls.

Duck-typing degrades to "silently ignore the keys I do not recognize". For a compiled machine map
that means "nothing to do". For someone's annotation payload it means **silently dropping their
work with no diagnostic** — the worst available failure mode for a tier whose entire purpose is
that discoveries are not lost.

So:

- Game descriptors carry `schema: 2` in YAML like every other descriptor
  (`docs/SCHEMA.md:45`; `MapCompiler.java:86-89` already rejects other values), and the version is
  **propagated into the compiled artifact** rather than consumed and dropped.
- The runtime compares it and, on a mismatch, **reports** it: "descriptor `<path>` declares schema
  N; this extension reads schema M — skipping" is a log line, not a silent no-op.
- **Within** a schema version, unknown keys remain duck-typed-ignored, so additive keys stay
  forward-compatible. The version field is for breaking changes only; it does not replace
  optional-key probing, it bounds it.

Machine maps are unaffected. This is a game-tier addition, not a `MAP_FORMAT.md` revision.

---

### 3b. Beyond site hints: what a game descriptor actually carries

#### 3b.1 The payload ranking

| Kind | Size | Status |
|---|---|---|
| Bank-switch site/value hints | tens of bytes | designed here, first increment (grm-2yx, grm-m95) |
| Symbols (labels + entry points) | thousands of entries | reuses the existing schema, §3b.2 |
| Comments | thousands of entries | rides on symbol entries in v1; see §9 q4 |
| Types | hundreds | later increment, §3b.4 |

The banking hints are what unblocks grm-2yx today. The symbols are what makes the tier matter.

#### 3b.2 Symbols reuse the existing schema and the existing generator pattern

`docs/SCHEMA.md:484-495` already defines everything needed: named sets the user toggles at import,
each carrying `provenance` (upstream project, license, generation date), with `kind: entry` symbols
becoming functions with entry points. The generated shape is already exactly what a harvest
produces — `machines/generated/c64ref-kernal.yaml` is a flat `entries:` list of
`{ addr, name, kind, comment }` behind the header

```
# generated by tools/gensymbols/gen_c64ref_symbols.py from mist64/c64ref -- do not hand-edit
```

and `tools/gensymbols/gen_c64ref_symbols.py` (the closed **grm-hnm**) is the working precedent for
converting an external reference project into that file.

**A per-game symbol set is that same file with a different provenance block.** Per-title harvesters
are new instances of an existing pattern, one per upstream disassembly format — new *parsers*, not
new schema. `machines/generated/games/` is the natural home, mirroring `machines/generated/`.

#### 3b.3 The one genuinely new symbol concept: a bank qualifier

Machine symbol sets carry an optional `region:` (`docs/SCHEMA.md:484-495`) because a KERNAL symbol
lives at one address in one always-visible region. **A game symbol does not have that property.** A
label at `$8000` on a UxROM cartridge is ambiguous across sixteen banks, each of which is a
different overlay block — and the whole point of the banking engine is that those are unrelated
content.

So game symbol sets need an optional **`block:`** qualifier, at set level (a default) and per
entry (an override), naming an overlay/occupant block: `W8000_M3_B1`, `PRG_LO_B7`. Entries naming
no block resolve in the base space, which is right for RAM and zero-page symbols.

This reuses vocabulary that already exists rather than inventing any: `RunFromElsewhereTransfer`
accepts space-qualified addresses (`src:W8000_M3_B1:a500`, the manifest's zelda row) and its arg parser
splits `key:value` with `split(":", 2)` specifically to keep them intact
(`ghidra_scripts/RunFromElsewhereTransfer.java:166-171`); the block names themselves come from
`DescriptorSupport.OverlayNaming` (`BoardBankAnalyzer.java:1515-1539`) and are documented in
`docs/MAP_FORMAT.md`'s layouts table. An unresolvable block name ignores that entry and logs — §3.1
again.

*(This is a correction to the framing that symbols need "no new schema concept" at all: they need
exactly one, and it is forced by banking rather than by the game tier.)*

#### 3b.4 Types are a later increment, for a build-system reason

`types[]` compiles per-machine into a `.gdt` via `GdtBuilder` (`docs/SCHEMA.md:496-500`). A per-game
type archive is therefore a **new build artifact and a new runtime lookup**, and unlike
`MapCompiler`, `GdtBuilder` cannot be casually shipped: it constructs Ghidra `DataType` objects and
must bootstrap `Application.initializeApplication`, which `docs/MAP_FORMAT.md:18-20` calls out as
the property that distinguishes it from the plain translator. Symbols and comments land first;
`types[]` in a game descriptor is a bead, not a v1 key.

#### 3b.5 Licensing is the gating constraint, and `provenance` is the designed answer

Community NES disassemblies range from public-domain to unlicensed-with-no-statement. This repo has
already committed to the discipline (`docs/SCHEMA.md` principle 3: "Provenance on all imported
knowledge […] Prevents the c64_ghidra trap: great data, no license") and is currently deciding the
sourcing question for c64ref in **grm-p5w** (submodule + build-time generation vs committed
artifacts) with **grm-54p** flagging provenance/licensing of the annotation source as an explicit
sub-decision.

**Ruling: decide per source, not once globally**, and make the decision mechanical:

- Every generated per-game symbol set carries `provenance` with project, revision, license and
  harvest date — the same block `machines/c64.yaml:205` already writes for c64ref.
- A set whose license does not permit redistribution is **excluded at build time** from the shipped
  curated set, while remaining generatable locally into the user's overlay directory. This is the
  same shape as the copyright-safe ROM slots of `docs/SCHEMA.md` principle 4: the extension ships
  the *slot*, the user supplies the *content*.
- The sourcing mechanism (submodule vs committed) is **the same question grm-p5w is answering for
  c64ref** and should be answered once for both. The game tier must not grow a second mechanism.

Zelda is the natural first harvest target: the real-ROM tier already pins it
(the `zelda` row of `manifest.tsv`) and it has mature public disassemblies.

#### 3b.6 grm-54p is the C64 instance of this idea, and they must converge

grm-54p asks for "import a fully pre-analyzed / labeled / commented ROM", and its recorded comment
already proposes a user-runnable script that builds the import file from inputs the user supplies on
their own terms. That is §7's export script pointed the other way, for ROMs instead of titles. The
game tier generalizes it. **The two should converge on one artifact rather than growing separate
mechanisms** — this is the single highest-value cross-link in the beads for this epic.

---

### 3c. Portability and upgrade: the same file, pointed the other way

A user with months of work in a Ghidra program needs two things. The tier supplies both with no new
format, which is the main reason the export script (§7) is part of this design rather than a
follow-on convenience.

#### 3c.1 Export your own work, reapply on a fresh import

Ghidra already ships whole-program carriers — Program XML and `.gzf`. What is missing is a
**selective** export of just the annotation layer, which is precisely what a descriptor is. Because
`ExportGameDescriptor.java` writes the same `entries:` shape a harvester writes, *your* annotations
and *harvested* annotations are the same kind of object, differing only in the `provenance` block.
That is what makes "reverse → export → share → curate" a loop rather than three formats.

#### 3c.2 Re-analysis picks up newly shipped data — and one concrete defect blocks it

Most of the machinery exists. `setSupportsOneTimeAnalysis()` puts a manual re-run in reach
(`DescriptorCopyHintAnalyzer.java:93`, and `BoardBankAnalyzer.java:174` already sets it too),
materialization is idempotent (`:60-61`), and existing-comment guards mean a second pass is cheap.

**The gap is exact and verifiable.** `BoardBankAnalyzer`'s redundant-rerun cache remembers:

```java
/** What {@link #LAST_COMPLETED} remembers: entry-time fingerprint + descriptor path. */
private record RunStamp(long fingerprint, String mapPath) {}
```

(`BoardBankAnalyzer.java:150-160`), checked at `:216-226`. The class javadoc is already candid about
the hole (`:140-141`): "Edits to the map *file's content* under an unchanged path are not detected —
acceptable for compiled resources bundled with the extension." That acceptability argument holds
for a bundled machine map and **fails immediately** for a game descriptor: an upgraded extension
shipping a revised descriptor at the same path, or a user editing their overlay file mid-session, is
judged "already done" and skipped, with the user's fingerprint unchanged because no functions or
instructions moved.

**Rule: whatever identifies a descriptor *version* must enter that cache key.** Concretely,
`RunStamp` gains a third component — a digest of the resolved game descriptor's compiled content
(absent when none matched). The same javadoc already states the obligation this discharges (`:143-145`):
"A future change that makes the analysis consume mutable inputs outside these […] must widen the
fingerprint or drop the cache." Consuming a user-editable overlay file is exactly that change.

#### 3c.3 User edits must survive, unconditionally

Ghidra's `SourceType` discipline is the mechanism and the rule is absolute:

> **Descriptor-applied and analyzer-applied annotations go in as `IMPORTED` or `ANALYSIS`, never
> `USER_DEFINED`, and never overwrite an existing `USER_DEFINED` symbol, comment or reference.**

`SourceType` is already imported and used across the loader stack
(`DescriptorSupport.java:59`), so this is a discipline to hold rather than a mechanism to build.
It is what makes "re-analyze after upgrading" safe to *recommend* to someone who has been working
in a program for months — without it, the upgrade path is a footgun and users will decline to take
it, which defeats the tier.

The symmetric rule for the export side: `ExportGameDescriptor` exports **only** `USER_DEFINED`
annotations by default (§7). Round-tripping analyzer output back into a descriptor would launder
a guess into a recorded fact.

---

## 4. Distribution: two sources, one format

### 4.1 Curated: `machines/games/*.yaml` → `data/games/*.gmap`, bundled

The curated set reuses the entire existing build path:

- Authored in `machines/games/*.yaml`, alongside `machines/*.yaml` and `machines/generated/`.
- Composed and validated by `MapCompiler` at build time, including `include:` fragment composition
  (`docs/SCHEMA.md:60-90`) and every existing structural check.
- Emitted into `data/games/`, which ships because `build.gradle:189-192`'s `SHIPPED_TOP_LEVEL`
  allowlist already names `data` wholesale (and `:204-210` fails the build if it goes missing).
- **Gitignored**, like every other compiled descriptor artifact. `.gitignore` currently lists
  `data/machines/*.map` and not `data/games/*` — **that is a concrete, required addition**, and
  omitting it would commit build output on the first `gradle buildExtension`.

#### The compiled artifact's extension is `.gmap`, not `.map`

`NesBoardRegistry.scan` enumerates `Application.findFilesByExtensionInMyModule(".map")`
(`NesBoardRegistry.java:83`), and `Application.findFilesByExtension` matches by plain filename
suffix (`Application.java:867-875`, and see the `endsWith` filter at `:638` for the sibling API).
Compiled game descriptors under `data/games/*.map` would therefore land in the **board** scan. They
would be skipped harmlessly today — `system == null` continues at `NesBoardRegistry.java:88-90` —
but that is an accident, not a design: it costs a JSON parse per game file on first board
resolution, and the day anything adds a `system:` block to a game map for any reason, a phantom
board appears in the registry. A distinct extension makes the collision structurally impossible for
the price of four characters.

### 4.2 Overlay: a user directory, scanned at runtime, holding YAML

The overlay directory is `<Ghidra user settings>/retro-machines/games/`, holding `*.yaml`.

**Use `Application.getUserSettingsFiles(dirName, fileExtension)`** (`Application.java:635-646`),
not a hand-rolled `getUserSettingsDirectory()` + `listFiles()`. It is worth being specific about why,
because the difference is a user-visible feature:

```java
public static List<File> getUserSettingsFiles(String dirName, String fileExtension) {
    File userSettingsDir = getUserSettingsDirectory();
    File subSettingsDir = new File(userSettingsDir, dirName);
    FileFilter filter = f -> f.getName().endsWith(fileExtension);

    if (!subSettingsDir.exists()) {
        subSettingsDir.mkdir();
        copyFilesFromPreviousVersion(subSettingsDir, dirName, filter);
    }
    ...
}
```

The `copyFilesFromPreviousVersion` branch (`:640-643`, implemented `:648-653`) means **a user's
overlay descriptors migrate across a Ghidra version upgrade for free**, because Ghidra's settings
dir is per-version. Hand-rolling the scan silently loses that, and the loss surfaces months later
as "my hints vanished when I upgraded Ghidra" — the exact failure this tier exists to prevent.

The upstream precedent is `BSimServerManager` (`BSimServerManager.java:56-64`), which scans
`<userSettings>/bsim/*.server.properties` the same way. It is also a useful **anti**-precedent: it
does that scan in the private constructor of a memoized singleton (`:46-51`), so a file dropped in
after first use is never seen. See §5.3.

Caveat to accept knowingly: the API `mkdir()`s the directory as a side effect of reading. That is
Ghidra's behavior, it is what BSim does, and a created-empty directory is a reasonable discovery
affordance ("here is where these go") rather than a surprise.

### 4.3 This requires shipping `MapCompiler` + snakeyaml, reversing a deliberate decision

`build.gradle:212-223` is explicit, and the decision it records is a good one:

> There is deliberately no YAML parser in the shipped extension: the builder below (source set
> `gdtBuilder`) and its snakeyaml dependency are build-only and are never copied into the
> extension's `lib/` […]

wired at `:244-250` as `gdtBuilderImplementation 'org.yaml:snakeyaml:2.2'`, and echoed in
`docs/MAP_FORMAT.md:5-16` ("without a YAML parser bundled in the shipped extension") and
`docs/SCHEMA.md:74-76` ("neither the directive nor SnakeYAML is shipped in the extension").

**The reversal is narrow and it is for one stated reason: one authoring format and, more
importantly, one validator.** If the overlay path had its own reader, the runtime and the build
would hold two independent opinions about what a valid descriptor means, and they would drift —
first on error messages, then on defaulting, eventually on semantics. A user's overlay file that
works would then fail as a pull request, or worse, pass review and behave differently once compiled.
That would break §7's round-trip requirement at the seam it most needs to hold.

**What is *not* reversed:**

- **The curated set is still compiled at build time.** Shipping snakeyaml does not mean shipping
  YAML. Build-time compilation is where a curated file's validation errors become build failures
  (which is the whole point of curating), it is where `include:` composition happens
  (`docs/SCHEMA.md:74-79` — the shipped artifact must be the *composed* result), and it keeps the
  common path — the bundled set — on gson with no YAML parse at all.
- **`MapCompiler` is runtime-safe by construction, and that is why this is affordable.**
  `docs/MAP_FORMAT.md:18-20`: it "is a plain YAML-in/JSON-out translator: unlike `GdtBuilder`
  (which constructs Ghidra `DataType` objects and therefore must bootstrap
  `Application.initializeApplication`), `MapCompiler` never touches a Ghidra runtime class." Its
  imports are gson + JDK. Only its YAML front-end (`YamlSupport`) needs snakeyaml.
- **`GdtBuilder` does not ship.** §3b.4.

**Concrete work items this creates** (all beads, none of them one-liners):

1. **Move `MapCompiler` + `YamlSupport` from `tools/gdtbuilder/src/main/java/gdtbuilder/` into
   `src/main/java/`.** `buildExtension` packages the `main` source set and the `dependencies {}`
   block, not `gdtBuilder`'s (`build.gradle:239-250`), so residence in the `gdtBuilder` source set
   is precisely what keeps them out of the zip today. The `gdtBuilder` source set then depends on
   `sourceSets.main.output` rather than the other way around.
2. **Add `org.yaml:snakeyaml:2.2` to the extension's runtime `dependencies {}`**, same version, so
   build and runtime cannot diverge on parser behavior.
3. **Update the `build.gradle:212-223` comment with the new rationale.** It must not be left
   silently contradicted: the reasoning it records is still correct for `GdtBuilder`, and the
   comment should say *that*, plus why `MapCompiler` is now the exception and what property makes it
   safe. A stale "never shipped" comment above a shipped dependency is how the next reader learns to
   distrust the comments.
4. **Simplify the test wiring.** `build.gradle:264-272` currently gives the test source set both
   `sourceSets.gdtBuilder.output` and an explicit snakeyaml dependency solely because
   `MapCompilerTest` needs them; after the move, `sourceSets.main.output` (`:266`) already carries
   `MapCompiler` and the extension's own snakeyaml is on the path.

**Costs, stated honestly:** roughly 330 KB added to the extension zip; a second parser on the
Ghidra classpath (snakeyaml is not among Ghidra's bundled jars, so there is no version conflict to
manage — verified by `build.gradle:268-271`, which has to add it explicitly for tests *because*
Ghidra ships none); and a permanent obligation to keep the two dependency declarations in lockstep.

### 4.4 Compile on read, do not cache

Descriptors are tiny — kilobytes of YAML, parsed once per import or analysis pass. This repo has
already rejected a cache-backed mode elsewhere on exactly these grounds (`CLAUDE.md`, on headless
project caching: "a correct cache would need explicit invalidation rules"), and the invalidation
rules here would be worse, because the overlay directory is user-writable at any moment. Parse on
read; measure before optimizing.

---

## 5. Lookup, search order, and degradation

### 5.1 The largest net-new piece

There is currently **no mechanism anywhere in the extension to find a descriptor outside an
installed module**. `DescriptorResources.loadMap` goes through `Application.findDataFileInAnyModule`
(`DescriptorSupport.java:142-151`); `NesBoardRegistry.scan` goes through
`Application.findFilesByExtensionInMyModule` (`NesBoardRegistry.java:81-110`). A grep of
`src/main/java` for user-settings-directory usage returns nothing at all. §4.2 is therefore not a
detail — it is the single biggest new capability in the tier.

**It is testable per-worktree for free.** `tools/banktest/run-banktest.sh:120-131` already relocates
the user settings dir per invocation via `-Dapplication.settingsdir`, precisely so parallel agents
do not share an Extensions directory. The overlay lands under that relocated root automatically, so
a Tier-3 fixture can plant an overlay descriptor with no new isolation machinery.

### 5.2 Search order and shadowing

**Overlay first, curated second, and shadowing is always logged.**

The order follows from what each source is *for*: a user's local work-in-progress on a title must
win over a bundled file for the same title, or the tier cannot be iterated in. The alternative
(curated wins) would mean a user's own corrections to a shipped descriptor are unreachable without
editing the installed extension, which is exactly the situation the overlay exists to fix.

The logging is not optional and is the risk this ordering creates: a stale overlay file silently
shadowing a corrected curated one is indistinguishable from "the fix did not ship". So a shadow
emits a log line naming both paths and both `game.id`s, at import, every time — not on first
occurrence, not at debug level.

### 5.3 No static memoization

`NesBoardRegistry` caches its scan in a static field:

```java
private static List<Board> boards;
...
static synchronized List<Board> boards() {
    if (boards == null) { boards = scan(); }
    return boards;
}
```

(`NesBoardRegistry.java:49, 54-59`). That is correct there — bundled `.map` files cannot change
while the JVM runs. It is **wrong for the game registry**, whose overlay half is a user-writable
directory: a mid-session drop-in would never be re-scanned, and the user's diagnosis would be "the
file does nothing", followed by restarting Ghidra and it mysteriously working. `BSimServerManager`
(`:46-51`) has this same shape and the same limitation, so it is not a pattern to copy.

**Ruling: the game registry holds no static cache.** The curated half may be memoized (it is
bundled and immutable); the overlay half is enumerated per resolution. The cost is one directory
listing plus N small YAML parses per import — bounded by §4.4's "descriptors are tiny", and paid on
a path that is already doing a full program import.

If profiling ever contradicts this, the answer is an **explicit refresh** (a menu action, an option)
and never implicit memoization — the same reasoning as §4.4.

### 5.4 Malformed input costs only that file

`MapCompiler` today **fails the build** on any structural error — `main` throws
(`MapCompiler.java:76`), the schema check throws (`:86-89`), and roughly twenty further
`IllegalArgumentException` sites throw for unknown sources, inverted ranges, escaping ranges and
bad expressions. That is exactly right for a build. It is exactly wrong for a runtime scan of a
directory of user-supplied files, where one bad file must not cost the other nine.

The rule is the one `DescriptorCopyHintAnalyzer.java:185-188` already states for directives:

> Checked anyway because the alternative failure mode is disproportionate: an NPE out of `added()`
> aborts the entire analysis pass for the program, where a malformed directive should cost only that
> directive.

**Ruling: add an error-collecting mode to `MapCompiler` — do not rewrite the throw sites.** The
existing exceptions stay; a new entry point catches per file, attributes the failure to that path,
and continues. The build path then treats any collected error as fatal, so nothing about build
strictness changes. **One validator, two dispositions** — which is the same principle §4.3 shipped
the compiler for in the first place. Rewriting twenty throw sites into an accumulator would be a
large diff whose only effect at build time is to report several errors at once, and it would put the
strictness guarantee at the mercy of every future contributor remembering to check the sink.

Granularity is per **file**, not per hint. A YAML parse failure has no per-hint granularity to
offer, and a file that fails structural validation cannot be trusted to have parsed the hints it
*did* produce correctly. Within a successfully compiled file, an individual hint that fails its
preconditions costs only itself (§3.1, §6).

`NesBoardRegistry.java:104-107` already models the shape — catch, `Msg.warn` naming the file,
continue.

### 5.5 Ruling: `include:` is allowed in curated files and rejected in overlay files

Three reasons, in order of weight:

1. **A shared descriptor must be one self-contained file, or it is not shareable.** The export
   script emits one file; §7 requires that file to be valid as an overlay descriptor *and* as a
   pull request. A composed overlay file has fragments that no recipient of the file has.
2. **Include paths are relative to the including file and must remain relative**
   (`docs/SCHEMA.md:76-78`). An overlay directory has no fragment library, so every include in a
   downloaded file would have to reach *outward* — into the bundled module data or up the
   filesystem. That is a path-traversal surface in a directory whose contents arrive from strangers.
   Resolving includes against "the overlay dir plus bundled fragments" does not fix it; it
   *specifies* it.
3. **Composition is a build-time source convenience** and says so
   (`docs/SCHEMA.md:74-76`). Curated files keep it precisely because they are compiled at build
   time (§4.3) and the shipped artifact is the composed result.

Rejection is loud: `include:` in an overlay file is a per-file error under §5.4, with a message
saying the key is build-time-only and pointing at `machines/games/`. Silently ignoring it would
apply a fraction of the intended descriptor, which is the "confident falsehood" outcome §6 exists to
prevent.

---

## 6. Consumption: analyzer-side, and seeds rather than injections

### 6.1 An analyzer, not a loader — inherited wholesale

`DescriptorCopyHintAnalyzer.java:55-61` explains the choice for `copied_from`, and every word
transfers:

> **Why an analyzer and not loader-time work.** Because of that gate, consuming the directive only
> at import would make the common path unreachable: a user who imports first and supplies a KERNAL
> dump afterwards (File → Add To Program) could never get the copy. `setSupportsOneTimeAnalysis()`
> below is therefore load-bearing rather than decoration […] Materialization is idempotent […] so
> re-running costs nothing.

For the game tier this is not a corner case, it is **the normal path**: the descriptor arrives after
the import in nearly every workflow — you import, you discover the site, you write the hint, you
re-run. A loader-only consumer would make the tier's primary use case unreachable.

Three properties to inherit exactly:

- **One-shot re-run support** (`:93`) — the user-facing recovery path.
- **Idempotent application** (`:60-61`) — a second pass is a no-op, not a duplicate annotation.
- **Provenance labelling.** `ORIGIN = "descriptor copied_from hint"` (`:85`) makes a hint-derived
  annotation permanently distinguishable from a derived one. The game tier's equivalent must name
  the *descriptor*, not just the tier — `"game descriptor contra_u"` — because with two sources
  (§4) and shadowing (§5.2), "which file said this" is the first question anyone debugging a wrong
  annotation will ask.

**The cheapest entry point already exists**, and it was built for this:

```java
/**
 * Apply every {@code copied_from[]} directive in {@code map}. Split out from
 * {@link #added} as the testable seam: {@code loadMap} goes through
 * {@code Application.findDataFileInAnyModule}, which resolves only against installed module
 * data directories, so a Tier-2 test cannot hand it a descriptor without an installed
 * extension -- but it can hand this method one.
 */
boolean applyAll(Program program, JsonObject map, TaskMonitor monitor, MessageLog log)
```

(`DescriptorCopyHintAnalyzer.java:148-155`). The game-descriptor consumer takes the same shape: a
package-private `applyAll(program, gameDescriptor, monitor, log)` that a Tier-2 test hands a
hand-built object, with the file resolution above it. §8 depends entirely on this.

### 6.2 Site hints are dataflow **seeds**, not injected results — the load-bearing ruling

A site hint is consumed by adding its address to `runDataflow`'s seed set
(`BoardBankAnalyzer.java:568-576`), which today is exactly the external entry points plus every
function entry:

```java
Set<Address> seeds = new LinkedHashSet<>();
AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
while (eps.hasNext()) { seeds.add(eps.next()); }
FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
for (Function f : funcs) { seeds.add(f.getEntryPoint()); }
```

seeded with `BankState.fullyKnown(board.mask(), board.initialState())` at `:578-581`.

**It must not inject a `SwitchResult`.** This is the most consequential ruling in the document, and
it has two independent justifications:

1. **A wrong hint must produce no annotation, never a confident falsehood.** Seeding means the
   site's own `computeSwitch` still runs. If the hint names an address that is not a bank-switch
   store, the strategy's own predicate — `MemoryLatchBankSwitchStrategy.writesInRange`
   (`:193-203`) and its `matchesDecode` companion — simply does not match, and nothing is
   annotated. If it *is* a switch store, analysis derives the answer itself and the hint has done
   its only job: getting the engine to look. Injecting a result would make every hint
   unfalsifiable, and hints in this tier come from the least trusted source in the system (§3.1).
2. **Everything downstream cascades for free.** The hinted address enters the same worklist as any
   other seed, so helper detection, the second dataflow pass, reference retargeting and residence
   clamping all apply without a single new code path. An injected result would sit outside that
   machinery and would have to re-implement each of those, or silently not have them.

**One mandatory prerequisite: disassemble first.** The worklist loop skips addresses with no
instruction —

```java
Address addr = worklist.poll();
Instruction instr = listing.getInstructionAt(addr);
if (instr == null) { continue; }
```

(`:586-589`) — so a hint naming an address in undisassembled bytes, which is precisely case (ii),
the case the hint exists to solve, would do **nothing at all** without this step. The idiom to reuse
is the one `addOverlayRef` already uses for cross-bank flow targets (`:1588-1596`):
`new DisassembleCommand(addr, null, true).applyTo(program, monitor)`, followed by a
`CreateFunctionCmd` where the hint says the site is a routine entry.

A pleasing consequence for testing: because the hint *is* the seed, the Tier-3 fixture in §8 needs
no `DisassembleAt.java` preScript to bootstrap it.

### 6.3 Value hints rank below recovered dataflow and above descriptor defaults

An optional `bank:` on a site hint (grm-m95's gap: the bank index arrives through a helper or a
table the value scanner cannot follow) supplies a value where the strategy recovered none.

Its precedence slot is **exactly the one placement overrides already occupy**, and the rule is the
one `DescriptorSupport.java:84-86` states in one clause — the analyzer "consults it only where dataflow
did not determine the bank at a reference site (**flow always wins when it knows**)". The
implementation shape is visible at `BoardBankAnalyzer.java:1520-1531`:

```java
// When dataflow did not pin the switchable bank at this site, the value above is just the
// initial-state fallback; a user placement override for this window instance takes over
// (flow always wins when it knows). See grm-hsv.3 -- the override is the residual escape
// hatch, never a guess.
boolean bankKnown = (inState.knownMask() & instance.bankField().positionedMask()) != 0;
Integer overrideBank = placementOverride.get(instance.name());
boolean overridden = !bankKnown && overrideBank != null;
```

A value hint gates on the same `!known` test. Full ordering, highest first:

| Rank | Source | Why here |
|---|---|---|
| 1 | Recovered dataflow value | Derived from the program's own instructions; the only evidence. |
| 2 | **Game descriptor value hint** | A human's recorded finding about this title. |
| 3 | User placement override | Session-scoped escape hatch, per window not per site. |
| 4 | Descriptor `initial_state` default | What is true before anything switches. |

Ranks 2 and 3 are distinguishable because they answer different questions: a value hint says "this
*site* drives bank N", a placement override says "this *window* holds bank N where nothing else
decided". Where both could apply, the site-specific statement is more specific and wins.

**Disagreement is reported, not swallowed.** If dataflow recovers a value and the hint states a
different one, dataflow wins (rank 1) *and* the analyzer emits a `BookmarkType.WARNING` at the site
naming both values and the descriptor. The hint is now demonstrably stale — the ROM was re-dumped,
the descriptor was written for a variant, or the analysis improved — and silently discarding it
would hide exactly the staleness the user needs to fix in their file. This is the tier's answer to
the hint-rot risk.

### 6.4 Site hints raise no precedence question at all

Worth stating explicitly because it is easy to miss: **a site hint cannot contradict analysis.** It
adds an address to a worklist. Everything the engine concludes at that address, it concludes from
the instruction it finds there. There is no ordering to define, no conflict to resolve, and no
"hint wins / analysis wins" policy to get wrong later. That property is bought entirely by §6.2's
seed-don't-inject ruling, and it is most of the reason for it.

---

## 7. Export: `ghidra_scripts/ExportGameDescriptor.java`

A `GhidraScript` alongside the existing `RunFromElsewhereTransfer.java` and
`FixSkipInstructions.java` (the current occupants of `ghidra_scripts/`, which
`build.gradle:189-192` already ships). It writes a YAML game descriptor
containing:

- the computed identity (§2), read back from the `Retro Machines.Game Identity` property so the
  export cannot disagree with what the loader computed;
- the bank-switch sites this program's analysis resolved, plus any it was hinted with;
- `USER_DEFINED` labels and comments as a `symbols:` set with a `provenance` block naming the
  program, the user, and the date — and **only** `USER_DEFINED`, per §3c.3, so an analyzer's guess
  is never laundered into a recorded fact;
- `schema: 2` and a `game:` block (§3.3).

snakeyaml **emits** as well as parses, so §4.3's dependency serves both directions; the export needs
no separate serializer.

### The round-trip requirement

> **The script's output must be valid, without editing, as BOTH an overlay descriptor and a
> `machines/games/*.yaml` pull request.**

This is the requirement that closes the loop — reverse → export → share → curate — and it is the
reason §4.3 ships the compiler at all. If the two paths could accept different files, "share your
descriptor" and "contribute your descriptor" become different tasks with different formats, and the
curated set stops being a promotion of user work and becomes a separate authoring effort.

Two consequences follow mechanically, and both are already ruled on above: the exporter never emits
`include:` (§5.5), and the same `MapCompiler` validates both destinations (§4.3, §5.4).

**Round-trip test, as an acceptance criterion rather than a nicety:** export from an annotated
program, compile the output, re-consume it into a fresh import of the same ROM, and assert the same
annotations at the same addresses with the same `SourceType`. Anything the exporter can write that
the consumer cannot read is a bug in one of them, and this test is the only thing that can tell you
which.

---

## 8. Testing

Across this repo's three tiers (`docs/testing.md:10-20`; the "when to add which" guidance at
`:158-171` maps cleanly onto the work here).

### Tier 1 — pure JUnit, `src/test/java` (`gradle test`)

- **Identity hashing.** PRG-slice digest over synthetic iNES byte arrays: with and without a
  trainer, iNES 1.0 vs NES 2.0 PRG-size encodings, and the property that matters most — two files
  differing only in header bytes produce the **same** `prg_sha256` and **different** `file_sha256`.
  Pure byte math, no `Program`, no Ghidra runtime.
- **YAML → compiled game descriptor.** Extend the existing `MapCompilerTest` pattern
  (`docs/testing.md:114-117`: `TemporaryFolder` + `assertThrows`, the migrated `verifyMapCompiler`)
  to the `game:` section: identity required, `schema: 2` enforced, hex→int normalization, duplicate
  `prg_sha256` rejected (§2.3), `include:` rejected in overlay mode and accepted in curated mode
  (§5.5).
- **The error-collecting mode itself** (§5.4): a directory of three files, one malformed, yields two
  compiled descriptors and one attributed error — and the *build* disposition of the same input
  still fails.

### Tier 2 — `ProgramBuilder` JUnit, via the `applyAll` seam

The seam exists precisely for this (`DescriptorCopyHintAnalyzer.java:148-155`), and the game-tier
consumer must expose the same one (§6.1). With a `ProgramBuilder` fixture and a hand-built
descriptor object — no installed extension, no file on disk:

- A site hint at an address holding a latch store is seeded, and the site resolves.
- A site hint at an address holding something else produces **no annotation** — the direct test of
  §6.2's ruling, and the single most important assertion in the tier.
- A site hint at undisassembled bytes triggers disassembly first, then resolves (the `:586-589`
  skip).
- A value hint fills an unknown bank; the same hint contradicting a recovered value loses and
  emits the warning (§6.3).
- A `game.board` mismatch ignores the whole file (§3.2).

`BankStrategyProgramTest` (`docs/testing.md:118-121`) is the model: a real strategy driven against a
`ProgramBuilder`-built fixture.

### Tier 3 — E2E golden image (the acceptance authority)

1. **A synthetic fixture that resolves only because a descriptor names the site.** Build a NES
   fixture whose latch store is reachable only through `JMP ($0300)`, so it is in no function and
   never disassembled — case (ii). Golden A: imported with no descriptor, zero bank refs. Golden B:
   imported with a curated descriptor naming the site, refs resolved. The delta between the two
   goldens *is* the feature. Because the hint is the seed (§6.2), this needs no `DisassembleAt.java`
   preScript.
2. **An overlay-path fixture**, planting a descriptor under the relocated user settings dir that
   `run-banktest.sh:120-131` already provides (§5.1) — asserting the overlay is found, that it
   shadows a curated file of the same identity, and that the shadow is logged (§5.2).
3. **Real ROMs, last.** Once the tier works, put contra's and db3's descriptors in the curated set
   and re-bless the real-ROM goldens (`docs/testing.md:173-196`). This is the point at which
   grm-2yx's titles resolve. **megaman stays measurement-only** — capture the baseline, record any
   delta as a comment on grm-g73, do not bless it.

The full gate remains `bash tools/banktest/build-and-test.sh check`.

---

## 9. Open questions

Each of these should become a bead rather than be resolved inline; they are listed here so the
document does not hedge in the sections above.

1. **Descriptor-declared matching criteria** (§2.5). Mapper + PRG size + optional byte signature, to
   cover ROM-set variant families with one file. Blocked on an ambiguity/precedence rule: what
   happens when two criteria descriptors match, and when criteria and hashes disagree. Deferred by
   explicit decision, not by oversight.

2. **Trust model for shared descriptor files.** §3.1 and §6.2 make a *wrong* hint harmless. Neither
   addresses a *hostile* one. The known surfaces: `include:` path traversal (closed by §5.5),
   resource exhaustion via a YAML bomb or a directory of thousands of files, and — the real one —
   an annotation payload that is plausible, wrong, and attributed to a project that did not write
   it. Is a signature or a checksum manifest warranted, or is "provenance is recorded and shadowing
   is logged" the whole answer? Related to grm-p5w's sourcing decision.

3. **Should value hints cover grm-m95's helper/table-fed arguments directly?** §6.3 designs a
   per-site `bank:` value. grm-m95's actual shape is often "this *helper* takes the bank in A" or
   "this *table* at `$XXXX` holds the bank per index", which a per-site value cannot express without
   one hint per call site. A helper-shaped or table-shaped hint kind may be the right vocabulary —
   but it is a much larger claim about program structure, so it wants grm-m95's findings first.

4. **Free-standing comments at unlabelled addresses.** §3b.1 rides comments on symbol entries,
   because `docs/SCHEMA.md:484-495`'s `entries[]` already carries `comment` and reusing it costs
   nothing. That covers a labelled address and not a mid-routine EOL comment, which is a large
   fraction of what a real annotation layer contains. Inventing a carrier now would fork the schema
   before the harvest generators (§3b.2) have told us what shape upstream data actually takes;
   revisit with a real harvest in hand.

5. **Does the tier want a per-title `.gdt`** (§3b.4), and if so does `GdtBuilder`'s
   `Application.initializeApplication` requirement (`docs/MAP_FORMAT.md:18-20`) force build-time-only
   type compilation — meaning types can be *curated* but never *overlaid*? That asymmetry, if real,
   is worth knowing before anyone designs a `types:` key for this tier.

6. **Where does the C64 side of this live?** grm-54p wants a pre-annotated *ROM* import; this tier
   describes a per-*title* descriptor. C64 titles are PRG files with no header-declared identity and
   no board registry, so §2's identity derivation has no NES-shaped equivalent. Converging the two
   (§3b.6) requires answering what a C64 "game identity" is — whole-file hash of the PRG, presumably,
   but the load-address-varying and packed/crunched cases need thought.

---

## 10. Deliverable status

Design only, except for the identity line below, which ships in bead grm-hb6.1: every NES import
now carries `Retro Machines.Game Identity` (`prg:<64 hex> file:<64 hex>`), and its companion
`Retro Machines.Game Descriptor` is *declared but never written* — nothing resolves a game
descriptor yet, which is beads grm-hb6.2/grm-hb6.3. Nothing else below is implemented.

- [x] Identity: PRG-slice + whole-file SHA-256, two Program Info properties — §2
- [ ] `game:` schema section, `switch_sites[]`, and the schema-version ruling — §3, §3.3
- [ ] Symbol reuse plus the `block:` bank qualifier — §3b.2, §3b.3
- [ ] Curated set `machines/games/*.yaml` → `data/games/*.gmap` (+ `.gitignore`) — §4.1
- [ ] Overlay scan on `Application.getUserSettingsFiles` — §4.2
- [ ] Ship `MapCompiler` + snakeyaml; move the source set; update `build.gradle:212-223` — §4.3
- [ ] Error-collecting `MapCompiler` mode (build stays strict) — §5.4
- [ ] Overlay-before-curated search order with logged shadowing; no static memoization — §5.2, §5.3
- [ ] Analyzer-side consumption: seeds not injections, value-hint precedence, provenance — §6
- [ ] `RunStamp` widened with a descriptor-content digest — §3c.2
- [ ] `ghidra_scripts/ExportGameDescriptor.java` + the round-trip test — §7
- [ ] Tier 1/2/3 coverage — §8
