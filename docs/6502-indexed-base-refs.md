# Indexed 6502 References: Base vs Computed (grm-phv)

Why this extension ships its own `Constant Reference Analyzer` for the 6502/6510 rather than
asking Ghidra upstream to fix the behavior. It closes the "plausibly upstreamable afterwards"
question the bead was opened with.

**No code is written by this note** — it is the decision `MosConstantReferenceAnalyzer`
implements. All Ghidra facts are validated against the pinned `Ghidra_12.1.2_build` source
checkout at `D:\git\ghidra`, matching `gradle.properties`' `ghidraTargetVersion=12.1.2`;
citations are `file:line`.

**Verdict, up front: the extension analyzer *is* the sanctioned fix, not a workaround. There is
no upstream ask for the behavior itself — upstream has already adjudicated it twice and pointed
at exactly what we built.** One genuinely upstreamable bug came out of the investigation, but it
is a different, one-line defect, tracked separately as `grm-6xh`.

## 1. The problem and its measured cost

Ghidra resolves an indexed 6502 operand to the *computed* address. `LDA $2000,X` with `X`
resolved to 5 gets a data reference to `$2005`. On the 6502 that is almost always the wrong
thing to record: the programmer means the table at `$2000`, and scattering references across
`$2000+n` buries the table instead of revealing it.

Measured in this repo by grm-bqs (2026-07-27): for the `STA $E000,X` driving an 8-byte
down-counting copy loop, the references actually attached to the store are `$E006` and `$E007`
— never `$E000`. A consumer asking "which occupant does this indexed access reach" cannot match
on the base at all. `LoopIdioms.overlayWriteTarget` (`:149-169`) works around it by matching a
re-homed reference anywhere in `[base, base+len)`.

**It is strictly a *known-index* bug.** When the index register is unknown, the base survives as
the offset inside a synthetic symbolic space, and
`SymbolicPropogator.addLoadStoreReference` (`:2173-2192`) already lays down a `RefType.DATA`
reference to the base — on the MNEMONIC. So the propagator's *success* at resolving the index is
what loses the table. `emteere` states this precisely in #201 (2024-07-16): *"Were Y to be
unknown, it would produce a reference to the base value."*

## 2. Verdict: extension analyzer, no upstream ask for the behavior

Five findings, verified against the pinned checkout.

1. **Upstream closed this as intended behavior, and has not moved in seven years.**
   [ghidra#201](https://github.com/NationalSecurityAgency/ghidra/issues/201) is this exact bug,
   filed 2019-03-14 by `tautology0`; `tom-seddon` announced the Ghidra6502 extension in that same
   thread. `emteere`, who owns constant propagation, returned on 2024-07-16: *"This is currently
   expected behavior... The constant analysis is a semi-symbolic flow analysis which follows all
   paths... There would need to be a more full function data flow analysis done to know that a
   register is variable within an area of code that is executed more than once, such as a
   loop."* The last comment (2024-09-17, asking for an option) drew two 👍 and no reply. No PR
   has ever been attempted. A PR changing the *generic* behavior asks upstream to reverse a
   documented position and take on the dataflow work they have declined to schedule.

2. **Upstream named the fix we built.** `emteere`, 2019-04-12: *"A small amount of tuning could be
   done in a 6502 targeted analyzer."* And the architecture agrees — **thirteen** processor
   modules ship a `ConstantPropagationAnalyzer` subclass (x86, MIPS, ARM, PowerPC, SuperH4 ×2,
   PIC16, 68000, Hexagon, RISCV, Sparc ×2, NDS32, Loongarch, Toy). 6502 ships none, so until now
   every 6502/6510 program here was analyzed by the fallback whose display name is literally
   *"Basic Constant Reference Analyzer"* (`ConstantPropagationAnalyzer.java:112-121`, name built
   as `processorName + " Constant Reference Analyzer"`).

3. **The extension point needs nothing from upstream.** `super(processorName)` calls
   `claimProcessor` (`:132`, public static), which makes the Basic analyzer's `canAnalyze` return
   `false` for that processor (`:162-167`); `ClassSearcher` discovers `Analyzer` extension points
   from the extension jar with no manifest entry. Customization is via `flowConstants` plus an
   anonymous `ConstantPropagationContextEvaluator` — the idiom every one of those thirteen uses,
   and nobody in the tree declares a named subclass of the evaluator.

4. **There is no sleigh fix and no per-language configuration to ask for.** The proximate cause is
   that `OP1: imm16,X ... { tmp:2 = imm16 + zext(X); export *:1 tmp; }`
   (`6502.slaspec:80-121`) exports a dereference of a *unique temp*, so
   `SleighInstructionPrototype.getOperandType` returns `DYNAMIC` (`:521-537`) and
   `getAddress(0)` returns `null` (`:806-809`) — killing the disassembly-time markup that makes
   plain `LDA $2000` work. But SLEIGH has no construct for "the scalar sub-piece of this dynamic
   operand is the base address of the access," and changing the p-code would falsify the
   semantics. Nor is there a pspec knob: `GhidraLanguagePropertyKeys.java` has no
   reference-targeting key (its closest relative, `addressesDoNotAppearDirectlyInCode`, is the
   *opposite* switch), and both `6502.pspec` and this repo's `6502undoc.pspec` have no
   `<properties>` element at all. Adding such a key *would itself be* the upstream change.

5. **Our targets are not upstream's.** `6510`, `6502:LE:16:undoc`, and `6510:...:undoc` are this
   repo's bundled languages (`data/languages/6510.ldefs`, `6502undoc.ldefs`). An upstream
   6502-only analyzer would not cover them, so we would ship our own regardless — and the
   `processor=` attribute is what `Processor` equality tests, which is why one subclass per
   processor covers the `:undoc` variants for free.

This is the same split the repo has drawn before: `docs/smc-inplace-vs-overlay.md:13-19` (no core
change when the public API suffices) and `docs/rfc-banked-memory.md` (ask upstream only for the
one genuine core hook, discussion #9349). Adding a second, weaker ask would only dilute that one.

## 3. Rejected alternatives

- **`ConstantPropagationContextEvaluator.evaluateConstant` / an offset reference.** An
  `OffsetReference` looks like the idiomatic representation of `base + index`, and
  `SymbolicPropogator.java:2253-2264` even carries the author's own TODO saying so ("this could
  be a calculated OFFSET reference with a base address"). It does not solve this problem:
  `ReferenceDBManager.addOffsetMemReference` with `toAddrIsBase=true` does
  `toAddr = toAddr.addWrap(offset)` (`:540`) and stores the reference at **base+offset**
  (`:553`). The base is recoverable only via `OffsetReference.getBaseAddress()`, so
  `getReferencesTo($2000)` still finds nothing and no label lands at the table start. Retargeting
  is required, not decoration.
- **`ContextEvaluator.unknownValue` returning 0 for X/Y.** Tempting — it would collapse the
  symbolic value and let the stock pipeline lay down an exact base reference in ~10 lines. But it
  is consulted only when a value is *unknown*, which is precisely the case that already works.
  It cannot touch the known-index bug this bead is about.
- **`ScalarOperandAnalyzer` / `OperandReferenceAnalyzer`.** Conceptually close — the former walks
  `getOpObjects` and adds operand references for scalars that resolve to addresses. Both are
  unusable on 6502: `OperandReferenceAnalyzer.canAnalyze` hard-requires a default address space
  wider than 16 bits (`:142-163`), and `ScalarOperandAnalyzer` discards every scalar below 4096
  (`:161-167`), which on a 16-bit machine throws away most of the address space. Recorded in
  `grm-6xh`; not worth a PR, as both are behavior arguments rather than defects.
- **`OperandType.INDIRECT` to identify the indirect modes.** Does not work.
  `SleighInstructionPrototype.isIndirect` (`:540-556`) tests only for `CALLIND`/`BRANCHIND`, i.e.
  indirect *flow*, so `(zp,X)` and `(zp),Y` both report false. Classification is done from the
  opcode byte instead.

## 4. What was built

`MosConstantReferenceAnalyzer` (abstract) with `Mos6502ConstantReferenceAnalyzer` and
`Mos6510ConstantReferenceAnalyzer` — the same abstract-base-plus-thin-subclass shape as
`BoardBankAnalyzer` → `C64BankingAnalyzer`/`NesBankingAnalyzer`. Per addressing mode:

| Mode | Reference target | Source of the base |
|---|---|---|
| `zp,X` `zp,Y` `abs,X` `abs,Y` | the base | the operand's own scalar, via `LoopIdioms.indexedBase` |
| `(zp),Y` | the pointer's target | `computed − Y`; the stock pointer-slot reference is kept |
| `(zp,X)` | unchanged | — the index selects *which pointer*, so there is no static base |

Two details that are easy to get wrong and are pinned by tests:

- **Use the operand scalar, not `computed − index`, for the direct modes.** `zp,X` wraps inside
  the zero page (`tmp:2 = zext(imm8 + X)`), so `$80,X` with `X=$F0` computes `$70`; subtracting
  `X` would yield `$FF80`. `tautology0` reported this exact wraparound in #201 on 2019-04-04.
- **`(zp),Y` performs two memory accesses**, and the propagator calls `evaluateReference` for
  each on the same instruction: a 2-byte pointer fetch from the zero-page slot, then the real
  1-byte access through the dereferenced-and-indexed pointer. Only the second carries a `Y` term
  and is retargeted. The first is passed through to stock handling on purpose — the instruction
  genuinely reads the pointer at `$80`, and on a 6502 that zero-page pointer is usually a named
  global whose cross-reference is worth more than the table's. The remit is which address an
  indexed access *itself* names, not deleting a sibling access.

The behavior is gated by a *"Reference indexed operand base"* analysis option, default on — which
is what `tautology0` asked upstream for in 2024-09 and never got. It is this extension's first
analyzer option.

`LoopIdioms.overlayWriteTarget`'s range match becomes redundant for its own caller but is
deliberately retained: the option can be off, the analyzer can be disabled, and programs analyzed
by older builds keep the references they were given.

## 5. The one real upstream PR (grm-6xh)

Found while researching this, and kept deliberately separate — nothing here depends on it
landing:

```java
// ConstantPropagationContextEvaluator.java:127-130
public ConstantPropagationContextEvaluator setMinStoreLoadOffset(long minStoreLoadRefAddress) {
    maxSpeculativeOffset = minStoreLoadRefAddress;   // should be minStoreLoadOffset
    return this;
}
```

It is chained **last** in `ConstantPropagationAnalyzer.flowConstants` (`:507-512`), so it clobbers
`maxSpeculativeOffset` with `minStoreLoadRefAddress` (default `4`) and leaves `minStoreLoadOffset`
at its constructor default (`:56`). Net effect: the user-visible *"Min absolute reference"* option
is inert, for the base analyzer and all thirteen subclasses. One-line fix, no behavior argument.

It matters here because "Min absolute reference" is exactly the knob a 6502 user must lower to get
zero-page references — and it is the field tom-seddon's prior art was trying to set.

## 6. Prior art

[`tom-seddon/Ghidra6502`](https://github.com/tom-seddon/Ghidra6502) (Apache 2.0) does the same
retargeting and reaches the same conclusion about `(zp,X)`. Its implementation needs two things
this one does not:

- **Reflection into the private `SleighInstructionPrototype.rootState` field** to read sleigh
  operand symbol names (`"ZPX"`, `"ABX"`, `"ZIY"`, …), with its own comment conceding *"This is a
  bit ugly, but it appears to be impossible to get this info out any other way."* Here
  `Instruction.getOpObjects` plus the raw opcode byte are public API.
- **A `wordOffset = -65536` hack** to dodge `SymbolicPropogator.makeReference`'s assumption that a
  reference to address 0 is invalid. Not needed here: every computed base is checked against real
  memory before use.

It also copy-pastes `ConstantPropagationAnalyzer.analyzeLocation` wholesale in order to substitute
a `SymbolicPropogator` subclass, noting *"sadly there doesn't seem to be any way to just replace
the SymbolicPropogator derived type."* Overriding `flowConstants` and intercepting
`evaluateReference` avoids that too, so nothing here forks upstream code.
