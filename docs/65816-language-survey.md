# 65816 language sourcing for SNES — evaluation and recommendation

Bead: `grm-9wbv`. Feeds the language half of `grm-9nxj` (SNES machine target). Written 2026-09-04
against `ghidraTargetVersion` 12.1.3.

**Scope fence, from the bead:** this evaluates the LANGUAGE only. The loader, descriptor,
LoROM/HiROM mapping and IO typing are `grm-9nxj`'s own work. Section 6's banking note is included
only because the measurement fell out of the corpus pass and materially changes `grm-9nxj`'s
shape; it is not a proposal.

Each claim below is tagged **[verified]** (measured in this session against the local toolchain or
the local corpus) or **[reported]** (research finding, URL given, not independently reproduced).

---

## Status since this was written

The owner ruled on §9 on 2026-09-04: vendor and fix immediates, full vector tier, and treat the
SNES banking question (§6) as an explicit decision. Steps 1 and 2 of the sequencing have landed —
the language is bundled as `65816:LE:24:retro` with the emulation-mode context defaults, and
immediates are constants (`W65816LanguageTest` asserts on p-code, not on operand rendering). The
fix took a different shape than §9 step 2 proposed: rather than splitting each instruction into
immediate and memory variants, which would have duplicated 24 bodies including ADC/SBC's decimal
arithmetic, a value-exporting layer (`PRIMARY_VAL8`/`PRIMARY_VAL16` and siblings) sits above
upstream's reference tables — the memory alternative dereferences exactly as upstream does, so the
16-bit bank-boundary wrap survives, and the immediate alternative exports a constant.

That work also turned up a defect this survey did not find by reading: **`CPY`'s two width
variants had their `ctx_XF` constraints swapped upstream**, so with 8-bit index registers the
16-bit body ran, comparing a 16-bit `Y` against a two-byte read whose second byte is the following
opcode. `CPX` was always correct and nothing else in the file has the mismatch (audited across
every width-split constructor). Fixed locally; `grm-9nxj.7` covers reporting it upstream. It is a
small vindication of §7's closing note — nobody has ever run this spec against an oracle — and of
the decision not to adopt as-is.

`grm-wrmf`'s `VectorRunner` context hook has also landed, which was §8's blocker for any 65816
vector tier.

---

## 0. Bottom line

The bead asks "Ghidra ships a 65816 processor — is it sound enough to adopt as-is?" **The premise
is false: Ghidra 12.1.3 ships no 65816 at all.** The real landscape is one third-party
implementation, MIT-licensed, written 2019–2021, archived by its author in 2024, and redistributed
by one active maintainer.

That implementation is **much better than SPCdra was on the axis this bead flagged as highest
risk** — M/X width modeling is done properly, with SLEIGH context registers and `globalset`, the
way ARM does Thumb. It compiles clean on 12.1.3.

But it has one defect that is close to disqualifying **for this project specifically, while being
merely cosmetic for a general user**: immediate operands are modelled as memory reads from the
instruction stream rather than as constants. Constant propagation out of immediates is the
mechanism this entire repo's bank-value recovery is built on.

**Recommendation: vendor it, then fix the immediate representation before anything else.** The
decode table and the M/X machinery — the expensive halves — are done and sound. The defect is
localized to one subtable in one file. Full reasoning in §7; the decisions that are yours are in §9.

---

## 1. There is nothing shipped to evaluate **[verified]**

A whole-tree search of the 12.1.3 source checkout for `65816`/`65c816`/`W65C816` returns three
files, none of them a language:

- `Ghidra/Features/Base/.../elf/ElfConstants.java` — an `EM_` machine-number constant.
- its compiled `.class`.
- `Ghidra/Processors/6502/data/manuals/65c02.idx` — one manual index line.

`Ghidra/Processors/` has no 65816 module, and `6502.ldefs` declares exactly two languages:
`6502:LE:16:default` and `65C02:LE:16:default`.

### Ghidra's 6502 is not a viable base to extend **[verified]**

Three structural blocks in `6502.slaspec`, any one of which alone would make "start from the
shipped 6502" a rewrite rather than a delta:

| | 6502 as shipped | 65816 needs |
|---|---|---|
| Address space | `define space RAM type=ram_space size=2` (16-bit) | 24-bit |
| Registers | `define register offset=0x00 size=1 [ A X Y P ]` (byte) | 16-bit A/X/Y in native mode |
| Context | **no `define context` anywhere in the 6502 family** | M/X/E context fields |

`65c02.slaspec` is a 222-line `@include "6502.slaspec"` delta and adds no context register.

Worth noting for the "a shipped-looking spec can be wrong underneath" theme that motivated this
bead's method: `65c02.slaspec`'s ADC reads `C = carry(A, op1); A = A + op1 + tmpC; V = C;` — the
carry-in is excluded from the carry-out and V is aliased to C. That is the defect already filed
upstream as `grm-ef46`, sitting in exactly the code a 6502-derived 65816 module would have copied.

### Upstream has declined it, twice **[reported]**

- [ghidra#250 "65816 support (SNES)"](https://github.com/NationalSecurityAgency/ghidra/issues/250)
  — closed `not_planned`, 2020, by a maintainer: *"We may implement new processors and variants via
  pull-requests but we aren't planning on specifically incorporating the 65816 at this time."*
- [ghidra#9133](https://github.com/NationalSecurityAgency/ghidra/issues/9133) — 2026 duplicate,
  closed the same way.

A PR would be considered; nobody has ever submitted one. Upstreaming is therefore an option
downstream of adopting, not a path to getting a language.

---

## 2. The landscape is one implementation with three wrappers **[reported]**

| Candidate | License | Last real code | ★ | What it is |
|---|---|---|---|---|
| [achan1989/ghidra-65816](https://github.com/achan1989/ghidra-65816) | MIT | 2021-10 | 29 | The original. **Archived 2024, "no longer maintained."** |
| [joshleaves/ghidra-snes](https://github.com/joshleaves/ghidra-snes) | MIT | 2026-05 | 76 | Active. Vendors achan1989's language + a real SNES loader (LoROM/HiROM/ExHiROM/SA-1/GSU/CX4/DSP-n/OBC1/S-DD1/SPC7110). Targets 12.0.4. |
| [n1tesh4dez/ghidra-65816](https://github.com/n1tesh4dez/ghidra-65816) | MIT | 2024-03 | — | One commit: drops `type="unknown"` from the cspec for an 11.0.1 load error. |
| [saffronisa/ghidra-saffron](https://github.com/saffronisa/ghidra-saffron) | MIT | pinned | — | Plain fork, byte-identical. |

A direct diff of joshleaves' `658xx.sinc` against achan1989's found **only whitespace alignment and
one comment typo fix** — despite a commit message claiming a JMP p-code fix. joshleaves' own
`CREDITS.md` is candid about this: the modifications are 12.0.4 compatibility, the cspec attribute,
and added registers. **So "which implementation" is not a real choice.** The question is what to do
about the one that exists.

Licensing is clean either way: MIT, the same posture as the already-vendored Apache-2.0
qwertymodo/SPCdra SPC700 sleigh.

---

## 3. It compiles clean on 12.1.3 **[verified]**

The survey could not confirm the 12.0.4→12.1.3 gap. I closed it. Fetched the module at
`joshleaves/ghidra-snes@d33ce5d` and ran the target toolchain's own compiler:

```
$ <ghidra 12.1.3 install>/support/sleigh -a <scratch>/w65816
Compiling 65816.slaspec:
WARN  2 NOP constructors found (SleighCompile)
1 languages successfully compiled
```

22,600-byte `.sla`, exit 0, no errors. The two NOP-constructor warnings are the only output.

The language id is `65816:LE:24:snes`, `size="24"` — a genuine 24-bit space, `define space bus
type=ram_space size=3 default`.

---

## 4. M/X width modeling: good, and it is the ARM pattern **[verified]**

This was the bead's "single highest-risk item." It is handled correctly.

```
define register offset=0x40  size=4  contextreg;
define context contextreg
    ctx_MF=(0,0)
    ctx_XF=(1,1)
    ctx_EF=(3,3)
;
```

Operand width is chosen by a context-keyed subtable — decode-time, which is what makes instruction
*length* correct:

```
RefImmMF: RefImm8    is ctx_MF=1; RefImm8  { export RefImm8; }
RefImmMF: RefImm16   is ctx_MF=0; RefImm16 { export RefImm16; }
RefImmXF: RefImm8    is ctx_XF=1; RefImm8  { export RefImm8; }
RefImmXF: RefImm16   is ctx_XF=0; RefImm16 { export RefImm16; }
```

`REP`/`SEP` stamp context forward with `globalset`, and each has variants keyed on the *current*
context so the constructor knows the pre-REP width. There are separate emulation-mode variants that
do not touch M/X, because E architecturally forces M=X=1 — a detail a careless spec gets wrong.
`XCE` sets `ctx_EF` from carry and forces M=X=1.

This is the same three-part mechanism ARM uses for Thumb (see `grm-wkk`, which already proposes it
for C64 bank state): a context field for decode, `globalset` for static flow, and — the part
**this spec does not have** — a Java analyzer for dynamic flow.

### The three real gaps

**(a) `PLP`/`RTI` cannot restore M/X. [verified]** The spec is honest about it, and the honesty is
in the source:

```
# UNSUPPORTED: pulling the context flags MF and XF.
define pcodeop unknown_native_status_pull;
:PLP    is (ctx_EF=0 & op=0x28)
{
    pull_status_native();
    local is_x16:1 = unknown_native_status_pull();
    ...
}
```

Interrupt handlers that restore mode by stack pull are unmodelled. There is no SLEIGH-level fix —
this is precisely the case that needs a Java analyzer stamping `ProgramContext.setValue(...)`, the
way `ArmAnalyzer` does for TMode at computed flows.

**(b) No default context in the pspec. [verified]** `65816-snes.pspec` has **no `<context_data>`
block at all** — it carries `default_symbols` for the vectors (`VEC_RESET_EMULATION` at `00FFFC`
etc.) and nothing else. The contextreg therefore defaults to all-zero: MF=0, XF=0, EF=0 — *native
mode, 16-bit A and 16-bit X/Y*. A real SNES resets into **emulation** mode. So out of the box, the
reset vector decodes in the wrong mode. Cheap to fix on our side (a `<context_set>` in our pspec,
or a loader that stamps it), and the fix belongs to us regardless of adoption path.

**(c) Initial mode is a manual, per-entry-point GUI action. [reported]** achan1989's README
documents the workflow: right-click the first instruction byte, "Processor Options...", set MF/XF/EF.
There is no analyzer that infers mode at an entry point. §5 measures how much that costs.

---

## 5. What real code actually does — 1.72M instructions **[verified]**

Measured against the owner's own listings in the `game-music-extraction` `snes/` archive. The bead
named four titles; the pass found **62 files across 13 titles** (adds Chrono Trigger, FF4-US's 32
banks, FF5, Gradius III, Lufia, Super Mario World, Seiken Densetsu 3), **1,722,102 instruction
lines**. All produced by one 1994 disassembler, so its quirks are common-mode. Per the standing
rule, these listings are **not an oracle** — they are used here for statistics about what shipped
code does, never for correctness judgments.

### Width is not a corner case

| immediates (`LDA/LDX/LDY/CMP/CPX/CPY/ADC/SBC/AND/ORA/EOR/BIT #imm`) | count |
|---|---|
| 1-byte (8-bit) | 71,981 |
| 2-byte (16-bit) | **52,311** |

**58/42.** Not lopsided. A language that guesses one width mis-lengths a large minority of
immediates — and a single mis-length desynchronizes everything downstream of it. Index registers
skew wider than the accumulator (`CPX` 61% 16-bit; `LDA` 28%), matching the usual convention. The
per-file spread is 1.1% to 81.9% — **no global default is safe**, which retires any idea of picking
one width and living with it.

### Mode changes are frequent in the median and rare in the tail

Instructions between consecutive REP/SEP (n=32,475 gaps): **median 10, p90 100, p99 667, max
14,200.** So local context tracking covers the common case comfortably, while long stretches with
no local mode information are real, not hypothetical.

`XCE`: 4,536, clustering at reset/IRQ/NMI entry — consistent with "go native once at boot, plus
handler re-entry."

### The number that decides usability, with its error bars

**~70.5% (13,196/18,715) of routine entries reach a width-sensitive immediate before any local
REP/SEP** — i.e. they run at a width their caller set.

The method is a proxy: scan forward from each `RTS`/`RTL` (as a stand-in for "next routine starts
here") until either a `#`-immediate or a REP/SEP is hit. It does **not** follow `JSR`/`JSL` targets,
so some "entries" are padding, jump-table data, or mid-routine early-exit points. Read it as
directional — *roughly two-thirds to three-quarters* — not as a precise figure. Tightening it means
building a per-file call-target index, which is real work and was not done.

Directionally it is still decisive, because of what it collides with:

> **Ghidra cannot represent one address decoded at two widths.** `Disassembler.java` handles a
> second flow arriving with different context via `setParseConflict` /
> `setInconsistentPrototypeConflict` — it does not re-decode. A routine genuinely called at both
> 8- and 16-bit accumulator width is not representable at one address in one Program, exactly as
> ARM/Thumb are not.

So the practical ceiling on SNES analysis is not opcode coverage. It is: *how well can we infer,
per entry point, the width the caller established?* That is analyzer work (`grm-wkk`'s ArmAnalyzer
pattern), not language work — and it is the part no existing implementation has.

### 65816-only addressing is used heavily, so decode coverage genuinely matters

| form | count | form | count |
|---|---|---|---|
| `long` + `long,X` | 152,073 | `[dp]` + `[dp],Y` | 45,643 |
| `sr,S` + `(sr,S),Y` | 67,292 | block move `MVN`/`MVP` | 9,504 |
| `PER`/`BRL` | 8,431 | `PEA`/`PEI` | 5,964 |
| `[abs]` (`JML [$nnnn]`) | 1,123 | | |

All 92 mnemonics appear. The corpus exercises the full ISA, not a 6502 subset.

### Decode-coverage claim, checked

`grep -oE "op=0x[0-9a-fA-F]{2}" 658xx.sinc | sort -u | wc -l` → **256** [reported]. 191 top-level
constructors, more than one per opcode where M/X/E variants exist. The addressing-mode subtables in
`658xx_memaccess.sinc` cover long, long-indexed, `[dp]`, `[dp],Y`, stack-relative, stack-relative
indirect indexed, and block move — the forms above show are heavily used [verified by reading].

### Caveats the corpus pass surfaced about itself

Honest noise, stated so nobody over-reads the tables: `BRK`'s 165,756 count is mostly `$00`
zero-fill in data decoded as code (Lufia's listing spans the entire address space, not a code
range); ~34% of REP/SEP-classified lines carry non-canonical operand values, meaning `$C2`/`$E2`
bytes in data are being read as mode changes; 5,155 lines (0.3%) are the 1994 tool's own `???`.

---

## 6. Note for `grm-9nxj`: SNES banking is not this repo's banking **[verified, out of scope]**

Falls out of the same pass, and it changes `grm-9nxj`'s shape rather than this bead's:

- `JSL` is ~15% of subroutine calls globally (9,441 vs 54,856 `JSR`) — but **all 32 FF4-US LoROM
  bank files contain zero `JSL`/`JML`**, while Chrono Trigger's HiROM bank $07 is 43% `JSL`.
- 148,006 long-form operands name a bank other than the instruction's own — **overstated for LoROM
  titles**, where banks `$80-$FF` are mirrors of the same physical ROM rather than a different bank.

The SNES looks like *a flat 24-bit space with genuine cross-bank calls*, not like the C64/NES
window-switching MMU machinery this repo has. LoROM and HiROM are two different physical stories
sharing one instruction set. Reusing the existing overlay/banking abstraction for SNES should be an
explicit decision, not an assumption.

---

## 7. The defect that decides the recommendation **[verified]**

**Immediate operands are not constants.** Every operand — immediates included — is packed into a
6-byte "reference" that is then dereferenced through a macro:

```
# 658xx_memaccess.sinc
@define REF_EXPORT "local ref:6 = (zext(ref_lo) << 24) | zext(ref_hi); export ref"

RefImm8: #$imm8    is imm8  {
    local ref_lo:3 = inst_start + 1;
    local ref_hi:3 = ref_lo + 1;  # Do not access.
    $(REF_EXPORT);
}

macro deref_read8(_out, _ref) {
    local big_ref_lo:6 = _ref >> 24;
    local ref_lo:3 = big_ref_lo:3;
    _out = *:1 ref_lo;
}
```

So `LDA #$12` emits p-code that **loads a byte from the instruction stream at `inst_start+1`**
instead of materializing `0x12`.

Upstream files this as [achan1989#10](https://github.com/achan1989/ghidra-65816/issues/10),
"Immediate Loads are treated as Offsets rather than values" — a *cosmetic* complaint about operands
rendering as `LDA #$0x0=>LAB_xxxxxx+1`. Open since 2019, unfixed in every fork.

**It is not cosmetic here.** `SymbolicPropogator`, `StoredValueScanner`, and every bank-value
recovery path in this repo work by propagating constants out of immediate loads — `LDA #bank` /
`STA <mechanism>` is the shape the whole `BoardBankAnalyzer` strategy library is built around.
Against this spec, that constant is an opaque memory read of the code stream, and propagation dies
at the first instruction. The one available language is broken in precisely the dimension this
project exists to exploit.

The good news: it is **localized**. `RefImm8`/`RefImm16` are two constructors in one file; the fix
is to export the operand value directly (what Ghidra's own 6502 does — `OP1: "#"imm8 is bbb=2;
imm8 { tmp:1 = imm8; export tmp; }`) and give the immediate-taking instructions a path that skips
`deref_read`. It is not a rewrite of the semantics the way SPCdra was.

### Semantic quality otherwise **[reported]**

Real p-code, not stubs: ADC/SBC implement binary *and* decimal arithmetic with digit-wise carry
adjustment; MVN/MVP are genuine loops with correct direction and the `C != 0xFFFF` termination.
The README self-assesses decompilation as "probably unusable," which is consistent with the
immediate defect above more than with the arithmetic. Issue history shows M/X width bugs (#4, LDX
length under XF=1) were found and fixed in 2019; nothing width-related is currently open.

**Unverified, and it is the biggest remaining unknown:** nobody has run this spec against an
oracle. Which brings us to the thing that changes the calculus.

---

## 8. The oracle exists, and our harness cannot drive it yet

**`SingleStepTests/65816`** [reported]: 512 files (`<hex>.n.json` native + `<hex>.e.json`
emulation), all 256 opcodes, **10,000 cases per file — 5.12M cases, ~2.87 GB**, 20× the SPC700
suite. Each case carries `pc, s, p, a, x, y, dbr, d, pbr, e` plus 24-bit flat `ram`. Critically,
**`p` carries M and X per case and `e` is a separate scalar**, so mode state is explicit rather
than inferred, and native/emulation are deliberately partitioned rather than mixed. Register naming
lines up field-for-field with the candidate spec's `C`/`A`/`B`, `X`/`Y`, `SP`, `DP`, `DBR`, `PBR`
[verified by reading both].

Also found, as an independent cross-check rather than a harness input: PeterLemon/SNES `CPUTest/*`
self-checking test ROMs (mirrored in `higan/snes-test-roms`).

### The harness gap **[verified]**

`VectorRunner.java:328` is the *entire* context story in our vector harness — it is the only
context-related line in the file:

```java
thread.overrideContextWithDefault();
```

In Ghidra's `DefaultPcodeThread.java:412` that resolves the language's **static default** at the
counter address. Fine for SPC700 and stock 6502, neither of which has a meaningful context
register. For a 65816 it is quietly fatal: every case would decode in whatever single mode the
pspec default declares, so a case whose `p` says M=0 gets decoded 8-bit, the emulator steps the
wrong instruction, and the comparison fails against the wrong final state. **It would not throw.**
It would produce plausible per-opcode PASS/FAIL ratios that read as semantic defects in the
language — the `silent-noop-reports-green` failure mode in a new costume.

No Ghidra-side work is needed: `PcodeThread.overrideContext(RegisterValue)` exists (interface
line 99, impl `DefaultPcodeThread.java:407`) [verified]. What is needed is ours:

| | work |
|---|---|
| Reusable as-is | `VectorCase`, `VectorParser` (already schema-agnostic — the 65816's extra register fields just become more map keys), `VectorRunner`'s reset/seed/step/compare loop, the fresh-`PcodeThread`-per-case decoder workaround, `OpcodeBaseline` and its bless discipline, `FlagLayout`'s mechanism |
| Needs a sibling | `W65816VectorHarnessSupport` (language id, register map, `WAI`/`STOP` in `NOT_APPLICABLE_OPCODES`), sample + exhaustive test classes, two baselines, a `build.gradle` task, a `w65816-vectors` chunk. `VectorHarness6502Test` is the precedent for a non-SPC700 language |
| Genuinely new | **A per-case `p`/`e` → `RegisterValue` translation plus a context-provider hook in `VectorRunner`** (compatibly, e.g. an optional `Function<VectorCase,RegisterValue>` defaulting to today's call). Also: `OpcodeBaseline`'s one-row-per-opcode model must become one row per (opcode, mode); `compare()`'s fixed `reg.getMinimumByteSize()` masking must become mode-dependent when A/X/Y are 16-bit registers holding 8-bit values |

At 20× the case count with larger payloads, the exhaustive tier's heap and wall-clock need
re-measuring from scratch — SPC700's ~15s/256K figure does not extrapolate.

---

## 9. Recommendation

**Vendor `joshleaves/ghidra-snes`' language module (MIT, with attribution, under our own
`variant="retro"` id), fix the immediate representation first, then validate against
`SingleStepTests/65816`.**

The shape mirrors the SPC700 decision, with the halves swapped. There, the decode table was sound
and the semantics were broken. Here, **both the decode table and the M/X machinery — the two
expensive halves — are sound**, and the breakage is one localized operand-representation choice
that happens to sit exactly on this project's critical path.

Why not the alternatives:

- **Adopt as-is.** Ships a language into our users' analysis where no bank value can ever be
  recovered from an immediate. That is not a degraded experience, it is the feature missing.
- **Depend on joshleaves' extension** (tell users to install it too). Two-extension install, we
  cannot fix the defect, and its id `65816:LE:24:snes` would collide with ours if we ever ship one
  — the same collision reasoning that produced `SPC700:LE:16:retro`.
- **Write from scratch.** Throws away a correct 256-opcode table *and* a correct context-based
  width model — the two things that are genuinely hard — to avoid an MIT license that costs
  nothing.
- **Extend Ghidra's 6502.** §1: wrong space size, wrong register widths, no context register.

Suggested sequencing, all agent work once ruled:

1. Vendor under `65816:LE:24:retro` with attribution; add the missing `<context_data>` default
   (E=1/M=1/X=1 at reset) the upstream pspec lacks.
2. Fix `RefImm8`/`RefImm16` to export the operand value, and prove it: `LDA #$12` must produce a
   constant, and a `LDA #bank / STA $2100` fixture must recover the bank through
   `SymbolicPropogator`. This is the go/no-go step — everything else is worthless without it.
3. Add the `VectorRunner` context hook and the `w65816-vectors` chunk; establish a baseline. Expect
   it to be red in places — that is the point, and the baseline idiom is built for it.
4. Fix semantics against the oracle, `PLP`/`RTI` last.
5. Only then, an analyzer for per-entry-point M/X inference (§5's ~70%) — `ArmAnalyzer`'s pattern,
   and the same shape `grm-wkk` wants for C64.

Steps 1–2 are small and decisive. Step 5 is the one that determines whether SNES analysis is good
or merely functional, and it is the piece nobody upstream has built.
