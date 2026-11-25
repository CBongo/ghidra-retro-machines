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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.OffsetReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * grm-9nxj.41.3: acts on the PROVEN live index range {@code [lo, hi]} of a register-indexed
 * absolute data read ({@code LDA/CMP/ADC.. base,X} or {@code base,Y}) into ROM. Owner ruling
 * 2026-11-25 after the survey beads grm-9nxj.41.1/.2: the evidence is exactly one of
 * <ul>
 * <li><b>G</b>, a {@code CMP #imm / BCC|BCS} guard ({@link IndexGuardRecovery#guardedIndexedLoad}),
 * used only when it gives BOTH ends (a guard that only says {@code reg >= imm} bounds nothing
 * above);</li>
 * <li><b>L</b>, the strong loop proof ({@link IndexLoopRange}): an immediate init, a closing
 * branch on the index register, restores and register-preserving callees allowed.</li>
 * </ul>
 * and nothing else. In particular "the base lands on code" is never evidence (grm-c9d.8), and
 * neither is the same-index family tiling of {@link SplitDispatchTableAnalyzer}. When G and L both
 * prove a range and they differ, the site is declined.
 *
 * <p>At a proven site (operand {@code B}, register range {@code lo..hi}, reads at
 * {@code B+lo .. B+hi}), and only when that span lies in one initialized, non-volatile,
 * non-writable memory block:
 * <ol>
 * <li>{@code lo > 0}: the operand's primary memory reference becomes an {@link OffsetReference}
 * whose BASE is the table start {@code B+lo} and whose offset is {@code -lo}. Verified against
 * Ghidra 12.2: an offset reference is stored by its "to" address {@code = base + offset}, which
 * is still {@code B}, the operand's own value, so analyses reading {@code getToAddress()} see
 * what they saw before; only {@code getBaseAddress()} names the table start. The old plain
 * reference at {@code B} is the one replaced (same from/to/operand, so none is left behind and
 * it stays primary). NOTE: the stock listing does NOT render {@code table-lo} for these
 * operands: {@code CodeUnitFormat} marks up a 6502 {@code abs,X} operand (a {@code Scalar} in a
 * three-element operand list) with the label of the "to" address, and only an offset reference
 * met through an {@code Address} operand or the extended markup goes through
 * {@code getOffsetReferenceRepresentation}.</li>
 * <li>stride 1 only: a byte array over {@code [B+lo, B+hi+1)}, when every byte there is undefined
 * (no instruction, no defined data); anything else skips the sizing and clears nothing. Proven
 * ranges that overlap are merged into one array, and an array already covering the range is left
 * alone.</li>
 * </ol>
 * A doubled index ({@code ASL A / TAX}, register step 2) keeps the reference move but is never
 * sized: it reads every other byte of a word table, whose extent a byte count would misstate.
 *
 * <p><b>Scope</b>: the 6502 family (6502, 6510, undocumented variants). The 65816 is not covered:
 * its {@code abs,X} has no static data bank and a 16-bit index width, so the base only becomes
 * known through {@link W65816DataBankAnalyzer}'s reference and the width analysis; the guard and
 * loop proofs here are 8-bit. The SPC700 has different mnemonics and operand shapes.
 *
 * <p><b>Priority</b>: {@code LOW_PRIORITY}, after every disassembly- and reference-producing
 * analyzer. This analyzer only ever adds data over bytes that are still undefined, so running
 * early could let a (correct) array win a race against code discovery that would later have
 * turned those bytes into instructions; running last means everything reachable has been
 * disassembled first and the array never competes with code.
 */
public class IndexedDataRangeAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Indexed Data Range";
	private static final String DESCRIPTION =
		"Proves the live index range of an abs,X / abs,Y data read (a CMP/BCC guard or a counted " +
			"loop), anchors the operand's reference on the table start (table-N) and sizes the " +
			"byte table (grm-9nxj.41.3).";

	public IndexedDataRangeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!AnalyzerGates.is8BitPcode(program)) {
			return false;
		}
		Processor processor = program.getLanguage().getProcessor();
		return processor != null &&
			("6502".equals(processor.toString()) || "6510".equals(processor.toString()));
	}

	/** One proven read: the span {@code [start, last]} it can reach and how it was proven. */
	record Proven(Instruction instr, Reference ref, int lo, int step, Address start, Address last,
			String evidence) {}

	/** What happened to the sites of one run, for the log line (and tests). */
	static final class Counts {
		int sites;
		int proven;
		int byGuard;
		int byLoop;
		int refsMoved;
		int arraysCreated;
		int declinedDisagree;
		int declinedBlock;
		int declinedRef;
		int declinedStride;
		int arraysSkippedCovered;
		int arraysSkippedOverlap;

		@Override
		public String toString() {
			return "sites=" + sites + " proven=" + proven + " (guard " + byGuard + ", loop " +
				byLoop + ") refsMoved=" + refsMoved + " arrays=" + arraysCreated +
				" declined[disagree=" + declinedDisagree + " block=" + declinedBlock + " ref=" +
				declinedRef + " stride=" + declinedStride + "] arraysSkipped[covered=" +
				arraysSkippedCovered + " overlap=" + arraysSkippedOverlap + "]";
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Counts counts = analyze(program, set, monitor);
		if (counts.sites > 0) {
			AnalyzerLog.info(this, counts.toString());
		}
		return true;
	}

	/** The analysis proper, separate from the analyzer plumbing so tests can read the counts. */
	static Counts analyze(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		Counts counts = new Counts();
		List<Proven> proven = new ArrayList<>();
		for (Instruction instr : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			Proven p = prove(program, instr, counts);
			if (p != null) {
				proven.add(p);
			}
		}
		for (Proven p : proven) {
			if (p.lo() > 0 && moveReference(program, p)) {
				counts.refsMoved++;
			}
		}
		sizeArrays(program, proven, counts);
		return counts;
	}

	// ------------------------------------------------------------------ evidence

	/** The {@code abs,X}/{@code abs,Y} read shape: one X/Y register, one scalar, 3 bytes. */
	private static Register indexRegister(Instruction instr, long[] baseOut) {
		if (instr.getLength() != 3 || !instr.getFlowType().isFallthrough() ||
			instr.getNumOperands() != 1) {
			return null;
		}
		Register index = null;
		int indexes = 0;
		int scalars = 0;
		for (Object o : instr.getOpObjects(0)) {
			if (o instanceof Register r && (r.getName().equals("X") || r.getName().equals("Y"))) {
				index = r;
				indexes++;
			}
			else if (o instanceof Scalar sc) {
				baseOut[0] = sc.getUnsignedValue();
				scalars++;
			}
		}
		return indexes == 1 && scalars == 1 ? index : null;
	}

	private static Proven prove(Program program, Instruction instr, Counts counts) {
		long[] base = new long[1];
		Register index = indexRegister(instr, base);
		if (index == null || PcodeShapes.dataAccess(instr) != PcodeShapes.DATA_READ ||
			PcodeShapes.writesMemory(instr)) {
			return null;
		}
		counts.sites++;
		// the operand's one memory reference: it is what we re-anchor, and where B really is
		Reference ref = null;
		for (Reference r : instr.getReferencesFrom()) {
			if (!r.isMemoryReference() || r.getOperandIndex() != 0) {
				continue;
			}
			if (ref != null) {
				ref = null; // several memory references on the operand: not the simple shape
				counts.declinedRef++;
				return null;
			}
			ref = r;
		}
		if (ref == null || !ref.isPrimary() || !ref.getReferenceType().isData() ||
			ref instanceof OffsetReference || ref.getSource() == SourceType.USER_DEFINED ||
			(ref.getToAddress().getOffset() & 0xffff) != base[0]) {
			if (!(ref instanceof OffsetReference)) {
				counts.declinedRef++;
			}
			return null;
		}
		// G: a guard that bounds BOTH ends
		int[] g = null;
		IndexGuardRecovery.LoadGuard guard = IndexGuardRecovery.guardedIndexedLoad(program, instr);
		if (guard != null && guard.base() == base[0] && guard.range().hi() < 255 &&
			guard.range().lo() <= guard.range().hi()) {
			g = new int[] { guard.range().lo(), guard.range().hi(), guard.range().step() };
		}
		// L: the strong loop proof
		int[] l = null;
		IndexLoopRange.Outcome loop = IndexLoopRange.prove(program, instr, index);
		if (loop.proof() != null) {
			l = new int[] { loop.proof().lo(), loop.proof().hi(), loop.proof().step() };
		}
		if (g == null && l == null) {
			return null;
		}
		if (g != null && l != null && !java.util.Arrays.equals(g, l)) {
			counts.declinedDisagree++;
			return null;
		}
		int[] r = g != null ? g : l;
		if (r[2] != 1 && r[2] != 2) {
			counts.declinedStride++;
			return null;
		}
		Address to = ref.getToAddress();
		Address start;
		Address last;
		try {
			start = to.addNoWrap(r[0]);
			last = to.addNoWrap(r[1]);
		}
		catch (ghidra.program.model.address.AddressOverflowException e) {
			counts.declinedBlock++;
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(start);
		if (block == null || !block.equals(program.getMemory().getBlock(last)) || !block.isInitialized() ||
			block.isVolatile() || block.isWrite()) {
			counts.declinedBlock++;
			return null;
		}
		counts.proven++;
		String evidence;
		if (g != null) {
			counts.byGuard++;
			evidence = "guard";
		}
		else {
			counts.byLoop++;
			evidence = "loop";
		}
		return new Proven(instr, ref, r[0], r[2], start, last, evidence);
	}

	// ------------------------------------------------------------------ actions

	/**
	 * Replaces the operand's plain reference to {@code B} with an offset reference based on the
	 * table start: base {@code B+lo}, offset {@code -lo}, so "to" stays {@code B}.
	 */
	private static boolean moveReference(Program program, Proven p) {
		Reference old = p.ref();
		try {
			program.getReferenceManager()
					.addOffsetMemReference(old.getFromAddress(), p.start(), true, -p.lo(),
						old.getReferenceType(), SourceType.ANALYSIS, old.getOperandIndex());
			return true;
		}
		catch (RuntimeException e) {
			return false;
		}
	}

	/** Byte arrays over the merged stride-1 spans whose bytes are all undefined. */
	private static void sizeArrays(Program program, List<Proven> proven, Counts counts) {
		List<Address[]> spans = new ArrayList<>();
		for (Proven p : proven) {
			if (p.step() != 1) {
				continue;
			}
			Address s = p.start();
			Address e = p.last();
			boolean merged = false;
			for (Address[] sp : spans) {
				if (sp[0].getAddressSpace().equals(s.getAddressSpace()) &&
					s.compareTo(sp[1]) <= 0 && e.compareTo(sp[0]) >= 0) {
					sp[0] = s.compareTo(sp[0]) < 0 ? s : sp[0];
					sp[1] = e.compareTo(sp[1]) > 0 ? e : sp[1];
					merged = true;
					break;
				}
			}
			if (!merged) {
				spans.add(new Address[] { s, e });
			}
		}
		// a merge can make two earlier spans overlap: repeat until stable
		boolean again = true;
		while (again) {
			again = false;
			for (int i = 0; i < spans.size() && !again; i++) {
				for (int j = i + 1; j < spans.size() && !again; j++) {
					Address[] a = spans.get(i);
					Address[] b = spans.get(j);
					if (a[0].getAddressSpace().equals(b[0].getAddressSpace()) &&
						a[0].compareTo(b[1]) <= 0 && b[0].compareTo(a[1]) <= 0) {
						a[0] = a[0].compareTo(b[0]) < 0 ? a[0] : b[0];
						a[1] = a[1].compareTo(b[1]) > 0 ? a[1] : b[1];
						spans.remove(j);
						again = true;
					}
				}
			}
		}
		Listing listing = program.getListing();
		for (Address[] sp : spans) {
			long len = sp[1].subtract(sp[0]) + 1;
			if (len < 2) {
				continue;
			}
			Data covering = listing.getDefinedDataContaining(sp[0]);
			if (covering != null && covering.getMinAddress().compareTo(sp[0]) <= 0 &&
				covering.getMaxAddress().compareTo(sp[1]) >= 0) {
				counts.arraysSkippedCovered++;
				continue;
			}
			if (!listing.isUndefined(sp[0], sp[1])) {
				counts.arraysSkippedOverlap++;
				continue;
			}
			try {
				CodeUnit cu = listing.createData(sp[0],
					new ArrayDataType(ByteDataType.dataType, (int) len, 1));
				if (cu != null) {
					counts.arraysCreated++;
				}
			}
			catch (ghidra.program.model.util.CodeUnitInsertionException | RuntimeException e) {
				counts.arraysSkippedOverlap++;
			}
		}
	}
}
