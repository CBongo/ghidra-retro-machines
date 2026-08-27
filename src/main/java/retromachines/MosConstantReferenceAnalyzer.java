/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package retromachines;

import java.math.BigInteger;

import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Retargets 6502-family indexed data references to their addressing mode's static
 * <em>base</em> address instead of the propagator's computed one, when the index register's
 * value is known at analysis time.
 *
 * <p><b>The problem, concretely (bead grm-bqs).</b> An 8-byte down-counting copy loop --
 * {@code LDX #7 ; loop: LDA base,X ; STA $E000,X ; DEX ; BPL loop} -- disassembles fine, but
 * the references {@link ConstantPropagationAnalyzer} lays down on the {@code STA} land on
 * {@code $E006} and {@code $E007} (whichever X values the symbolic propagator happened to
 * resolve on its walk), and never once on {@code $E000}. The table/buffer's actual start is
 * invisible in the cross-reference view -- exactly the address a human or a downstream
 * analyzer (bank-window carving among them) needs.
 *
 * <p><b>Strictly a known-index bug.</b> When X (or Y) is <em>not</em> known, there is nothing
 * wrong to fix here: {@code SymbolicPropogator.addLoadStoreReference} (:2173-2192) already
 * falls back to placing a reference on the base address at the mnemonic in that case. It is
 * precisely the propagator's *success* at resolving the index that loses the base -- the more
 * precisely it computes, the more thoroughly the table's identity gets buried under whichever
 * offsets the loop happened to visit.
 *
 * <p><b>Why here, and not fixed upstream.</b> This is a known, closed upstream issue --
 * ghidra#201 (filed 2019-04-04) -- closed as expected behavior. {@code emteere}, who owns
 * constant propagation, wrote on 2019-04-12: <em>"A small amount of tuning could be done in a
 * 6502 targeted analyzer."</em> Thirteen processor modules in the Ghidra tree already ship a
 * {@link ConstantPropagationAnalyzer} subclass tuned this way (x86, MIPS, ARM, PowerPC, SuperH4,
 * ...); the stock 6502 module ships none, so every 6502/6510 program in this extension has been
 * getting the untuned generic behavior. See {@code docs/6502-indexed-base-refs.md} for the full
 * design decision this class implements.
 *
 * <p><b>Prior art, and why this design needs less of it.</b>
 * <a href="https://github.com/tom-seddon/Ghidra6502">tom-seddon/Ghidra6502</a> solves the same
 * problem, but has to reach into the private {@code SleighInstructionPrototype.rootState} field
 * via reflection to read sleigh operand symbol names, plus apply a {@code wordOffset = -65536}
 * hack to dodge {@code SymbolicPropogator}'s "address 0 is not a valid reference" assumption.
 * This design needs neither: {@link Instruction#getOpObjects(int)} and the raw opcode byte are
 * public API, and every base this class computes is checked against the program's real memory
 * before use, so there is no reason to fake an out-of-range offset.
 */
public abstract class MosConstantReferenceAnalyzer extends ConstantPropagationAnalyzer {

	protected static final String OPTION_NAME_INDEXED_BASE = "Reference indexed operand base";
	protected static final String OPTION_DESCRIPTION_INDEXED_BASE =
		"For 6502-family indexed loads/stores (zp,X / zp,Y / abs,X / abs,Y / (zp),Y) whose "
			+ "index register value is known, place the operand-0 reference on the "
			+ "addressing mode's base address (e.g. the $2000 in \"LDA $2000,X\") instead of "
			+ "the computed address (e.g. $2005), so the table/buffer's identity survives "
			+ "in the cross-reference view instead of being scattered across whichever "
			+ "offsets a loop happened to visit. (zp,X) indexed-indirect is excluded: its "
			+ "index selects which zero-page POINTER is read, not an offset into a fixed "
			+ "table, so there is no single base address to name.";

	/** Package-visible so {@code MosConstantReferenceAnalyzerTest} can flip it directly to
	 *  exercise the "option off" path without going through the full {@code Options} plumbing
	 *  when convenient, and read it back to assert the default. */
	protected boolean referenceIndexedBase = true;

	protected MosConstantReferenceAnalyzer(String processorName) {
		super(processorName);
	}

	// Deliberately NOT overriding canAnalyze(). ConstantPropagationAnalyzer's stock
	// implementation (ConstantPropagationAnalyzer.java:145-172) does two things at once:
	// it gates on processor identity (which super(processorName) already wired up via
	// claimProcessor, and which is exactly what we want per-subclass here), AND it computes
	// per-program defaults this analyzer depends on for a 16-bit address space --
	// minSpeculativeRefAddress=256, maxSpeculativeRefAddress=128,
	// checkPointerParamRefsOption=true, checkStoredRefsOption=false. Overriding canAnalyze
	// without reproducing that computation would silently lose those defaults. Leave it
	// alone; do not "helpfully" add an override here.

	// Deliberately NOT overriding the analysis priority set by the super() call above
	// (AnalysisPriority.REFERENCE_ANALYSIS.before().before().before().before()). It must
	// stay strictly before BoardBankAnalyzer's priority (REFERENCE_ANALYSIS.after()) so
	// that base-address references already exist by the time
	// BankAnnotationAdapter.retargetReferences re-homes references into per-bank overlays --
	// otherwise there is nothing yet for it to re-home.

	/**
	 * The four shapes an opcode's low 5 bits (bbb and cc, with aaa masked off) can put into
	 * operand 0 that this analyzer cares about. See {@link #classify(Instruction)}.
	 */
	private enum IndexedMode {
		/** zp,X / zp,Y / abs,X / abs,Y -- base is the operand's own scalar. */
		DIRECT,
		/** (zp),Y indirect indexed -- base is {@code address - Y}. */
		INDIRECT_INDEXED,
		/** (zp,X) indexed indirect -- no single base; left to stock behavior. */
		INDEXED_INDIRECT,
		/** Not one of the above; left to stock behavior. */
		OTHER
	}

	/**
	 * Classifies an instruction's addressing mode from its raw opcode byte.
	 *
	 * <p>6502 opcodes encode as {@code aaabbbcc}: {@code bbb = (op >> 2) & 7} selects the
	 * addressing-mode column, {@code cc = op & 3} selects which instruction group that column
	 * belongs to, and {@code aaa = (op >> 5) & 7} selects which instruction within the column
	 * -- irrelevant to addressing mode. Masking with {@code op & 0x1f} keeps {@code bbb} and
	 * {@code cc} together and drops {@code aaa}, which is exactly "same addressing mode,
	 * regardless of which instruction". From the constructors in
	 * {@code Ghidra/Processors/6502/data/languages/6502.slaspec:80-121}, reproduced verbatim
	 * in this repo's {@code data/languages/6502core.sinc:96-134} (its {@code OP1}/{@code OP2}
	 * nonterminals) and {@code data/languages/6510_illegal.sinc} (its {@code OP3}
	 * nonterminal, the undocumented SLO/RLA/SRE/RRA/SAX/LAX/DCP/ISC column, {@code cc=3}):
	 *
	 * <ul>
	 * <li>{@code (zp,X)} indexed indirect is {@code bbb=0}: {@code op & 0x1f} is
	 * {@code 0x01} (documented, {@code cc=1}) or {@code 0x03} (undocumented, {@code cc=3}).
	 * <li>{@code (zp),Y} indirect indexed is {@code bbb=4}: {@code op & 0x1f} is
	 * {@code 0x11} or {@code 0x13}.
	 * <li>Everything else that turns out to carry an index register in operand 0 is a direct
	 * indexed mode ({@code zp,X}, {@code zp,Y}, {@code abs,X}, {@code abs,Y}).
	 * </ul>
	 *
	 * <p><b>{@code OperandType.INDIRECT} does NOT work for this and must not be used
	 * instead.</b> {@code SleighInstructionPrototype.isIndirect} (:540-556) only tests for
	 * {@code CALLIND}/{@code BRANCHIND} p-code ops -- i.e. indirect <em>flow</em> -- so both
	 * {@code (zp,X)} and {@code (zp),Y}, which are indirect <em>data</em> accesses, report
	 * {@code OperandType.INDIRECT} as false. Do not retry that approach.
	 *
	 * <p>This only narrows by opcode; it does not confirm the operand actually names an index
	 * register (e.g. plain {@code LDA #imm} also falls through to {@code DIRECT} here). For the
	 * direct modes that check is {@link LoopIdioms#indexedBase}'s job, via {@code getOpObjects};
	 * its caller relies on it returning null for a non-indexed operand.
	 *
	 * @return the classified mode, or {@link IndexedMode#OTHER} if the opcode byte cannot be
	 *         read (e.g. instruction not fully backed by initialized memory) -- handled the same
	 *         as {@link IndexedMode#DIRECT} by every caller, since {@link LoopIdioms#indexedBase}
	 *         independently returns null for anything it cannot make sense of either
	 */
	private static IndexedMode classify(Instruction instr) {
		int op;
		try {
			op = instr.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return IndexedMode.OTHER;
		}

		int mode5 = op & 0x1f;
		if (mode5 == 0x01 || mode5 == 0x03) {
			return IndexedMode.INDEXED_INDIRECT;
		}
		if (mode5 == 0x11 || mode5 == 0x13) {
			return IndexedMode.INDIRECT_INDEXED;
		}
		return IndexedMode.DIRECT;
	}

	/**
	 * Base address for a {@code (zp),Y} reference: {@code address - Y}, given the already-known
	 * live value of the Y register.
	 *
	 * @return the base address, or null if the subtraction would underflow the address space
	 *         (Y bigger than the low bits of {@code address} -- e.g. a table living right at the
	 *         start of the space; nothing sane to retarget to)
	 */
	private static Address indirectIndexedBase(Address address, BigInteger yValue) {
		long offset = address.getOffset() - yValue.longValue();
		try {
			return address.getAddressSpace().getAddress(offset);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Whether {@code base} is a resolved base worth retargeting to, given the computed
	 * {@code address} it would replace.
	 *
	 * <p>The memory check is the load-bearing part and is easy to leave out. Retargeting takes
	 * over from stock behavior by returning {@code false} from {@code evaluateReference}, which
	 * bypasses {@code ConstantPropagationContextEvaluator}'s own vetting -- and that vetting is
	 * what normally keeps references off addresses the program does not actually map. Without
	 * this check a {@code LDA $0700,X} in a program where {@code $0700} is unmapped would gain a
	 * reference into nothing, where stock would correctly have produced none. Falling through to
	 * {@code super} instead is the conservative choice: stock then vets the computed address the
	 * way it always would, so an unmappable base costs us the improvement but never invents a
	 * reference.
	 *
	 * <p>Rejects three cases: no base resolved ({@code null} -- e.g. the operand is not indexed
	 * at all), a base equal to the computed address (index value zero, so stock is already
	 * naming the base), and a base outside program memory.
	 */
	private static boolean retargetable(Program program, Address base, Address address) {
		return base != null && !base.equals(address) && program.getMemory().contains(base);
	}

	/**
	 * Adds a reference to {@code base} on operand 0, unless one is already there.
	 *
	 * <p>Operand 0 is always the memory operand for every 6502 indexed addressing mode. The
	 * propagator may call {@code evaluateReference} once per flow path reaching an instruction,
	 * each time with a different index value resolved on that path -- that is exactly how
	 * {@code STA $E000,X} over an 8-byte down-counting loop ends up with references at
	 * {@code $E006} and {@code $E007} under stock behavior: each visited X value gets its own
	 * computed reference. Deduping on the exact target address (not merely "operand 0 already
	 * has some reference") is what collapses all of those calls into a single base reference
	 * instead of one per path/index value, while still permitting a base reference to be added
	 * when operand 0 already carries an <em>unrelated</em> reference from a different memory
	 * access on the same instruction -- which is exactly the {@code (zp),Y} case, where the
	 * sibling pointer fetch legitimately references the zero-page slot. It is load-bearing,
	 * not a defensive nicety.
	 *
	 * <p>Note that the base reference is deliberately <em>not</em> forced primary. When a
	 * sibling reference already claimed primary -- again {@code (zp),Y}, where the pointer slot
	 * is what the operand text literally names -- promoting the base would make the listing
	 * render {@code LDA (DAT_2010),Y}, which is false. The goal here is that a cross-reference
	 * exists at the base and none at base+index; which reference the operand renders is a
	 * separate, and correctly stock, question.
	 */
	private static void addBaseReferenceOnce(Instruction instr, Address base, RefType refType) {
		for (Reference ref : instr.getOperandReferences(0)) {
			if (ref.getToAddress().equals(base)) {
				return;
			}
		}
		instr.addOperandReference(0, base, refType, SourceType.ANALYSIS);
	}

	/**
	 * Copies the shape of {@code ConstantPropagationAnalyzer.flowConstants} (:503-515) and
	 * {@code X86Analyzer.flowConstants} (:46-99): install an evaluator that overrides
	 * {@code evaluateReference}, re-apply the same fluent setter chain the stock
	 * implementation uses, and flow constants exactly as the base class would.
	 *
	 * <p>Note {@code setMinStoreLoadOffset} (in {@code ConstantPropagationContextEvaluator})
	 * is buggy upstream -- it assigns {@code maxSpeculativeOffset} instead of
	 * {@code minStoreLoadOffset} (tracked as bead grm-6xh). We reproduce the stock chain
	 * verbatim rather than working around it here, so this analyzer's speculative-offset
	 * behavior matches every other processor's {@link ConstantPropagationAnalyzer} subclass
	 * bit for bit, bug included.
	 */
	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size, DataType dataType,
						RefType refType) {

					if (!referenceIndexedBase) {
						return super.evaluateReference(context, instr, pcodeop, address, size,
							dataType, refType);
					}

					// Flow references (e.g. the computed target of JMP (abs,X)) are a
					// control-transfer concern, not the "buries the table" data-reference
					// problem this analyzer exists for. Leave them to stock handling.
					if (refType.isFlow()) {
						return super.evaluateReference(context, instr, pcodeop, address, size,
							dataType, refType);
					}

					// PcodeOp.UNIMPLEMENTED here does not mean a real memory access is
					// happening -- SymbolicPropogator uses it as a "could this be a
					// parameter?" probe value, not a genuine load/store (identical guard
					// and comment at SH4AddressAnalyzer.java:139: "unimplemented is a flag
					// for a parameter check"). Retargeting under it would act on a value
					// nothing actually reads.
					if (pcodeop == PcodeOp.UNIMPLEMENTED) {
						return super.evaluateReference(context, instr, pcodeop, address, size,
							dataType, refType);
					}

					IndexedMode mode = classify(instr);

					if (mode == IndexedMode.INDEXED_INDIRECT) {
						// (zp,X): the index selects which zero-page POINTER is dereferenced,
						// not an offset into one fixed table -- there is no single base
						// address to name statically. Leave stock behavior alone.
						return super.evaluateReference(context, instr, pcodeop, address, size,
							dataType, refType);
					}

					if (mode == IndexedMode.INDIRECT_INDEXED) {
						// (zp),Y compiles to TWO distinct memory accesses per the sinc
						// definition (addr:2 = imm8; tmp:2 = *:2 addr; tmp = tmp + zext(Y);
						// export *:1 tmp;), and the propagator calls evaluateReference once
						// for EACH: first a 2-byte pointer fetch from the fixed zero-page
						// slot the operand names (address here is that zp slot, NOT indexed
						// by Y at all), then separately the real 1-byte data access through
						// the dereferenced-and-indexed pointer -- the one this analyzer
						// exists to retarget. classify() alone cannot tell these two calls
						// apart, since both see the exact same instruction; size can, since
						// on the 6502 every real data transfer is a single byte while the
						// pointer fetch is always 2.
						Register y = LoopIdioms.indexReg(instr);
						BigInteger yValue = y == null ? null : context.getValue(y, false);
						if (yValue == null) {
							// Y unknown on this path: SymbolicPropogator.addLoadStoreReference
							// (:2173-2192) already lays down a correct base reference in this
							// case for whichever of the two accesses it can resolve -- leave
							// both untouched.
							return super.evaluateReference(context, instr, pcodeop, address,
								size, dataType, refType);
						}
						if (size != 1) {
							// The pointer-fetch access, whose `address` is the zero-page slot
							// itself and carries no Y term -- so it must NOT be retargeted
							// (subtracting Y here would invent a garbage base $007B for a
							// pointer at $0080). But it must not be suppressed either: the
							// instruction genuinely reads the pointer at $80, that reference
							// is stock, correct, and often the more useful cross-reference on
							// a 6502, where zero-page pointers are named globals. This
							// analyzer's remit is which address an indexed access *itself*
							// names, not deleting a sibling access by the same instruction.
							// Operand 0 therefore ends up with the pointer slot AND the
							// table base, and never the pointer's target plus Y.
							return super.evaluateReference(context, instr, pcodeop, address,
								size, dataType, refType);
						}
						Address base = indirectIndexedBase(address, yValue);
						if (!retargetable(program, base, address)) {
							return super.evaluateReference(context, instr, pcodeop, address,
								size, dataType, refType);
						}
						addBaseReferenceOnce(instr, base, refType);
						return false;
					}

					// DIRECT (zp,X / zp,Y / abs,X / abs,Y), or OTHER (opcode byte unreadable
					// -- treated the same, see classify()'s javadoc): the base is the
					// operand's own scalar, built in the executing instruction's own address
					// space -- see LoopIdioms.indexedBase's javadoc for why that space (not
					// the base program space) is what makes this correct on banked machines.
					// Using the scalar, and NOT (address - index), matters concretely: zp,X
					// wraps inside the zero page (sleigh: tmp:2 = zext(imm8 + X)), so "$80,X"
					// with X=$F0 computes $70 -- subtracting X from the computed address
					// would instead give the wrong, non-wrapped $FF80. The operand scalar is
					// wrap-safe by construction; this exact class of bug is upstream
					// ghidra#201 (2019-04-04).
					Address base = LoopIdioms.indexedBase(instr);
					if (!retargetable(program, base, address)) {
						// Not actually an indexed operand (e.g. plain LDA #imm, which also
						// classifies as DIRECT -- see classify()'s javadoc), the computed
						// address already equals the base (index value zero), or the base is
						// not backed by memory: stock behavior is already correct.
						return super.evaluateReference(context, instr, pcodeop, address, size,
							dataType, refType);
					}
					addBaseReferenceOnce(instr, base, refType);
					return false;
				}
			};

		eval.setTrustWritableMemory(trustWriteMemOption)
			.setMinSpeculativeOffset(minSpeculativeRefAddress)
			.setMaxSpeculativeOffset(maxSpeculativeRefAddress)
			.setMinStoreLoadOffset(minStoreLoadRefAddress)
			.setCreateComplexDataFromPointers(createComplexDataFromPointers);

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		super.registerOptions(options, program);
		options.registerOption(OPTION_NAME_INDEXED_BASE, referenceIndexedBase, null,
			OPTION_DESCRIPTION_INDEXED_BASE);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		referenceIndexedBase = options.getBoolean(OPTION_NAME_INDEXED_BASE, referenceIndexedBase);
	}
}
