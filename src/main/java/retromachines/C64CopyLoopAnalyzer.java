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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers run-from-elsewhere self-modifying code: 6502 loops that copy a range of bytes
 * <em>verbatim</em> from one region into another and execute (or read) it there (grm-1.7.1).
 * Statically the destination is uninitialized, so the copied code/data is invisible; this
 * analyzer recognizes the copy loop and hands a neutral {@link TransferSpec} to
 * {@link TransferMaterializer}, which puts the bytes at the destination.
 *
 * <p>The recognized shape is the canonical down-counting indexed copy -- structurally
 * {@link C64DecryptLoopAnalyzer}'s loop minus the transform, and with the load and store to
 * <em>different</em> bases (relocation, not in-place):
 * <pre>
 *       LDX #len-1
 *  loop: LDA src,X    ; indexed load  (loop top)
 *       STA dst,X     ; indexed store to a DIFFERENT base -> a copy, not a decrypt
 *       DEX
 *       BPL loop
 *       JMP dst       ; optional: a jump INTO the copy proves it runs as code -> AUTO
 * </pre>
 *
 * <p><b>Materialize is not disassemble.</b> A copy can carry data or code, so the destination
 * bytes are always placed (safe, and makes them visible), but the payload is disassembled only
 * when a {@code JMP}/{@code JSR} into the range proves it is code. A copy with no such call
 * (e.g. CHRGET: copied at boot, invoked much later) is materialized as data and left as bytes,
 * since disassembling data would poison analysis.
 *
 * <p>Where the bytes land -- carved into the destination's own block, or a byte-mapped overlay
 * when that is impossible -- is {@link TransferMaterializer}'s decision, not this recognizer's;
 * it emits {@link TransferSpec.TargetKind#SAME_SPACE} and lets the materializer choose. Keeping
 * the recovery core front-end-agnostic is what lets a later manual command, a descriptor
 * {@code copied_from} hint, or the SPC700 separate-Program target (grm-1.7.3) reuse it. Shared
 * 6502 loop-idiom recognition lives in {@link LoopIdioms}.
 */
public class C64CopyLoopAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "C64 Copy Loop";
	private static final String DESCRIPTION =
		"Recovers run-from-elsewhere SMC: recognizes verbatim ROM/image->RAM copy loops and " +
			"materializes the copied bytes at the destination -- carved into its own memory " +
			"block where possible, otherwise a dual-home byte-mapped COPY_xxxx overlay -- " +
			"disassembling them only when a jump into the range proves they are code.";
	private static final String CATEGORY = "C64CopyLoopAnalyzer";

	public C64CopyLoopAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// After reference analysis so branch flows exist (back-edge + jump-into-range).
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		return format != null && format.equals(C64PrgLoader.NAME);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		Listing listing = program.getListing();
		for (Instruction sta : listing.getInstructions(set, true)) {
			if (monitor.isCancelled()) {
				break;
			}
			if (!LoopIdioms.mnem(sta).equals("STA")) {
				continue;
			}
			TransferSpec spec = tryRecognize(program, listing, sta);
			if (spec != null) {
				TransferMaterializer.materialize(program, spec, CATEGORY, monitor, log);
			}
		}
		return true;
	}

	/** Recognize a verbatim copy loop whose store step is {@code sta}, or return null. Anchors
	 *  on the STA (a copy has no transform between the load and store, unlike the decrypt
	 *  analyzer which anchors on the EOR). */
	private TransferSpec tryRecognize(Program program, Listing listing, Instruction sta) {
		Instruction lda = listing.getInstructionBefore(sta.getAddress());
		if (lda == null || !LoopIdioms.mnem(lda).equals("LDA")) {
			return null;
		}

		// Indexed load and store to DIFFERENT bases with the same index register: a relocation
		// (src != dst), which is exactly what distinguishes a copy from an in-place decrypt.
		Address src = LoopIdioms.indexedBase(lda);
		Register idx = LoopIdioms.indexReg(lda);
		Address dst = LoopIdioms.indexedBase(sta);
		Register staIdx = LoopIdioms.indexReg(sta);
		if (src == null || dst == null || idx == null || staIdx == null) {
			return null;
		}
		if (src.equals(dst) || !idx.equals(staIdx)) {
			return null;
		}

		// Index step + conditional back-branch to the loop head (the LDA).
		Instruction step = listing.getInstructionAfter(sta.getAddress());
		Instruction branch = step == null ? null : listing.getInstructionAfter(step.getAddress());
		boolean downCount = step != null && LoopIdioms.mnem(step).equals(LoopIdioms.decMnemonic(idx));
		boolean bpl = branch != null && LoopIdioms.mnem(branch).equals("BPL");
		boolean backEdge = branch != null && LoopIdioms.branchTargets(branch, lda.getAddress());

		// Bound the range from the LDX/LDY #imm counter init. Only the clean down-counting form
		// gives a range certain to be [dst, dst+len).
		Instruction init = LoopIdioms.findCounterInit(listing, lda, idx);
		Integer n = init == null ? null : StoredValueScanner.immediateOperandValue(init);
		if (!(downCount && bpl && backEdge)) {
			return null; // not a copy loop -- an ordinary adjacent indexed load/store, ignore
		}
		if (n == null) {
			program.getBookmarkManager().setBookmark(lda.getAddress(), BookmarkType.WARNING,
				CATEGORY, "copy-shaped loop " + TransferMaterializer.fmt(src) + " -> " +
					TransferMaterializer.fmt(dst) + " could not be bounded; not applied");
			return null;
		}
		int len = n + 1;

		Address entry = init.getAddress();
		Address jumpInto = LoopIdioms.findJumpIntoRange(listing, branch, dst, len);
		TransferSpec.Confidence conf = jumpInto != null
				? TransferSpec.Confidence.AUTO
				: TransferSpec.Confidence.CANDIDATE;
		boolean code = conf == TransferSpec.Confidence.AUTO;

		return new TransferSpec(src, dst, len, TransferSpec.Transform.IDENTITY,
			TransferSpec.TargetKind.SAME_SPACE, entry, conf, code, code, dst, jumpInto);
	}
}
