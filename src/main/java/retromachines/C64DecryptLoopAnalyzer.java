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

import java.io.ByteArrayInputStream;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers decrypt-on-the-fly self-modifying code: 6502 loops that EOR a range of bytes
 * in place at runtime and then execute it (grm-1.7.2). A static listing of the encrypted
 * bytes is garbage; this analyzer recognizes the decrypt loop, recovers the plaintext, and
 * exposes it as a {@code DECRYPTED_xxxx} overlay block so disassembly can proceed, while
 * the encrypted original stays navigable in the base space.
 *
 * <p><b>Tier 1 (constant key)</b> -- an {@code EOR #imm} loop -- is decrypted inline (a
 * pure byte XOR over a known range with a known constant). <b>Tier 2 (rolling/computed
 * key)</b> is handed to the shared {@link EmulationRecovery} harness (grm-edg) with a
 * dirty-watch on the target range. Both converge on the same materialization.
 *
 * <p>The recognized shape is the canonical down-counting in-place decryptor:
 * <pre>
 *       LDX #len-1
 *  loop: LDA base,X   ; indexed load
 *       EOR #key      ; constant (tier 1) or EOR keytab,X (rolling, tier 2)
 *       STA base,X    ; indexed store to the SAME base+index -> in place
 *       DEX
 *       BPL loop
 *       JMP base      ; enters the decrypted range -> AUTO confidence
 * </pre>
 * Auto-apply requires a {@code JMP}/{@code JSR} into the rewritten range (proof the bytes
 * run as code); a loop without one is recorded as a candidate bookmark only, never
 * rewritten, so an ordinary indexed table transform is not mistaken for a decryptor.
 */
public class C64DecryptLoopAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "C64 Decrypt Loop";
	private static final String DESCRIPTION =
		"Recovers decrypt-on-the-fly SMC: recognizes in-place EOR decrypt loops, recovers " +
			"the plaintext (inline for a constant key, via emulation for a rolling key), and " +
			"exposes it as a DECRYPTED_xxxx overlay block.";
	private static final String CATEGORY = "C64DecryptLoopAnalyzer";

	// How far back to look for the loop-counter init, and how far past the loop for the
	// jump-into-range; both are small because a decrypt stub is a tight, local construct.
	private static final int COUNTER_LOOKBACK = 8;
	private static final int JUMP_LOOKAHEAD = 6;

	public C64DecryptLoopAnalyzer() {
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
		for (Instruction eor : listing.getInstructions(set, true)) {
			if (monitor.isCancelled()) {
				break;
			}
			if (!mnem(eor).equals("EOR")) {
				continue;
			}
			tryRecognize(program, listing, eor, monitor, log);
		}
		return true;
	}

	/** Attempt to recognize a decrypt loop with {@code eor} as its transform step. */
	private void tryRecognize(Program program, Listing listing, Instruction eor,
			TaskMonitor monitor, MessageLog log) {
		Instruction lda = listing.getInstructionBefore(eor.getAddress());
		Instruction sta = listing.getInstructionAfter(eor.getAddress());
		if (lda == null || sta == null || !mnem(lda).equals("LDA") || !mnem(sta).equals("STA")) {
			return;
		}

		// Invariant 1: indexed load and store to the SAME base and index register (in place).
		Address base = indexedBase(lda);
		Register idx = indexReg(lda);
		Address staBase = indexedBase(sta);
		Register staIdx = indexReg(sta);
		if (base == null || staBase == null || idx == null || staIdx == null) {
			return;
		}
		if (!base.equals(staBase) || !idx.equals(staIdx)) {
			return;
		}

		// Key model from the EOR operand.
		RecognizedDecryptor.KeyModel key;
		if (StoredValueScanner.isImmediate(eor)) {
			Integer k = StoredValueScanner.immediateOperandValue(eor);
			if (k == null) {
				return;
			}
			key = RecognizedDecryptor.KeyModel.constant(k);
		}
		else if (indexedBase(eor) != null) {
			key = RecognizedDecryptor.KeyModel.rolling(indexedBase(eor));
		}
		else {
			key = RecognizedDecryptor.KeyModel.of(RecognizedDecryptor.KeyModel.Kind.UNKNOWN);
		}

		// Invariant 3: index step + conditional back-branch to the loop head (the LDA).
		Instruction step = listing.getInstructionAfter(sta.getAddress());
		Instruction branch = step == null ? null : listing.getInstructionAfter(step.getAddress());
		boolean downCount = step != null && mnem(step).equals(decMnemonic(idx));
		boolean bpl = branch != null && mnem(branch).equals("BPL");
		boolean backEdge = branch != null && branchTargets(branch, lda.getAddress());

		// Bound the range. Only the clean form -- LDX/LDY #(len-1); ...; DEX/DEY; BPL loop --
		// gives a range certain to be [base, base+len); other counter/branch forms have
		// off-by-one traps, so we recognize but do not auto-apply them.
		Instruction init = findCounterInit(listing, lda, idx);
		Integer n = init == null ? null : StoredValueScanner.immediateOperandValue(init);
		if (!(downCount && bpl && backEdge) || n == null) {
			program.getBookmarkManager().setBookmark(lda.getAddress(), BookmarkType.WARNING,
				CATEGORY, "decrypt-shaped loop (key=" + key + ") could not be bounded; not applied");
			return;
		}
		int len = n + 1;

		AddressRange target;
		try {
			target = new AddressRangeImpl(base, base.add(len - 1));
		}
		catch (AddressOutOfBoundsException e) {
			return;
		}

		Address entry = init.getAddress();
		Address jumpInto = findJumpIntoRange(listing, branch, base, len);
		RecognizedDecryptor.Confidence conf = jumpInto != null
				? RecognizedDecryptor.Confidence.AUTO
				: RecognizedDecryptor.Confidence.CANDIDATE;

		RecognizedDecryptor rd = new RecognizedDecryptor(entry, target, key, conf, jumpInto);
		apply(program, rd, monitor, log);
	}

	/** Route a recognized decryptor to inline decrypt (tier 1), emulation (tier 2), or a
	 *  candidate warning, and materialize any recovered plaintext. */
	private void apply(Program program, RecognizedDecryptor rd, TaskMonitor monitor,
			MessageLog log) {
		Address base = rd.target().getMinAddress();
		int len = (int) rd.target().getLength();
		RecognizedDecryptor.KeyModel.Kind kind = rd.key().kind();

		if (rd.confidence() != RecognizedDecryptor.Confidence.AUTO) {
			program.getBookmarkManager().setBookmark(rd.entry(), BookmarkType.WARNING, CATEGORY,
				"possible decrypt loop " + rd.target() + " (key=" + rd.key() +
					"); no jump into range, not applied");
			return;
		}

		if (kind == RecognizedDecryptor.KeyModel.Kind.CONSTANT) {
			byte[] plain = decryptConstant(program, base, len, rd.key().constant());
			if (plain == null) {
				program.getBookmarkManager().setBookmark(rd.entry(), BookmarkType.WARNING, CATEGORY,
					"constant decrypt: could not read encrypted bytes at " + base);
				return;
			}
			materialize(program, rd, plain,
				String.format("static constant-EOR key $%02X", rd.key().constant()), false, log);
		}
		else {
			// Tier 2: rolling/computed/unknown key -> emulate the loop and read back the range.
			RecoveryResult res = runEmulation(program, rd, monitor);
			byte[] plain = res.recoveredBytes(base, len);
			if (plain == null) {
				program.getBookmarkManager().setBookmark(rd.entry(), BookmarkType.WARNING, CATEGORY,
					"emulated decrypt did not cover " + rd.target() + " (" + res.stopReason() +
						"); not applied");
				return;
			}
			// A hardware-tainted run (IO/uninit reads) still recovers bytes, but flags them
			// suspect so the overlay is a WARNING, not an authoritative NOTE.
			materialize(program, rd, plain, "emulated (" + kind + ")", res.provenance().suspect(),
				log);
		}
	}

	private byte[] decryptConstant(Program program, Address base, int len, int key) {
		byte[] buf = new byte[len];
		try {
			program.getMemory().getBytes(base, buf);
		}
		catch (MemoryAccessException e) {
			return null;
		}
		for (int i = 0; i < len; i++) {
			buf[i] = (byte) ((buf[i] & 0xFF) ^ (key & 0xFF));
		}
		return buf;
	}

	private RecoveryResult runEmulation(Program program, RecognizedDecryptor rd,
			TaskMonitor monitor) {
		AddressSet watch = new AddressSet(rd.target().getMinAddress(), rd.target().getMaxAddress());
		StopConditions stop = StopConditions.builder().dirtyWatch(watch).build();
		return new EmulationRecovery(program).recover(rd.entry(), stop,
			IoPolicy.volatileBlocks(program), monitor);
	}

	/** Create the {@code DECRYPTED_xxxx} overlay seeded with the recovered bytes and link it
	 *  back to the decryptor with bookmarks and a comment. A suspect (emulation-derived,
	 *  hardware-tainted) result gets a WARNING bookmark instead of NOTE. */
	private void materialize(Program program, RecognizedDecryptor rd, byte[] plain, String detail,
			boolean suspect, MessageLog log) {
		Address base = rd.target().getMinAddress();
		String name = "DECRYPTED_" + String.format("%04x", base.getOffset());
		if (program.getMemory().getBlock(name) != null) {
			return; // already recovered on a prior pass -- idempotent
		}
		try {
			MemoryBlockUtils.createInitializedBlock(program, true, name, base,
				new ByteArrayInputStream(plain), plain.length,
				"decrypted view of " + rd.target() + " (" + detail + ")", CATEGORY,
				true, false, true, log, TaskMonitor.DUMMY);
		}
		catch (AddressOverflowException e) {
			log.appendMsg(name + ": could not create overlay: " + e.getMessage());
			return;
		}

		String kindTag = suspect ? "SUSPECT " : "";
		String msg = kindTag + "decrypted " + rd.target() + " key=" + rd.key() + "; " + detail;
		program.getBookmarkManager().setBookmark(rd.entry(),
			suspect ? BookmarkType.WARNING : BookmarkType.NOTE, CATEGORY, msg);
		program.getBookmarkManager().setBookmark(base,
			suspect ? BookmarkType.WARNING : BookmarkType.NOTE, CATEGORY,
			"decrypted range start; see overlay " + name);
		program.getListing().setComment(rd.entry(), CommentType.EOL, "decrypt loop -> " + name);
	}

	// ------------------------------------------------------------------
	// Recognition helpers (6502 operand/flow idioms; see StoredValueScanner)
	// ------------------------------------------------------------------

	private static String mnem(Instruction instr) {
		return instr.getMnemonicString().toUpperCase();
	}

	/** The DEX/DEY mnemonic that decrements index register {@code idx}, or "" if neither. */
	private static String decMnemonic(Register idx) {
		String n = idx.getName().toUpperCase();
		if (n.equals("X")) {
			return "DEX";
		}
		if (n.equals("Y")) {
			return "DEY";
		}
		return "";
	}

	/** The single base address of an indexed operand (abs,X / abs,Y / zp,X), or null when the
	 *  operand is not indexed or names more than one base. An indexed operand's base arrives
	 *  as a {@link Scalar} (no static reference is made for a runtime base+index target), so
	 *  this is the inverse of {@link StoredValueScanner#plainAbsoluteTarget}, which handles
	 *  only the unindexed {@link Address} case. */
	private static Address indexedBase(Instruction instr) {
		Long base = null;
		boolean indexed = false;
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Register) {
				indexed = true;
			}
			else if (obj instanceof Address a) {
				if (base != null) {
					return null;
				}
				base = a.getOffset();
			}
			else if (obj instanceof Scalar s) {
				if (base != null) {
					return null;
				}
				base = s.getUnsignedValue();
			}
		}
		if (!indexed || base == null) {
			return null;
		}
		try {
			return instr.getMinAddress().getAddressSpace().getAddress(base);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private static Register indexReg(Instruction instr) {
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Register r) {
				return r;
			}
		}
		return null;
	}

	/** Whether {@code branch} is a conditional jump that targets {@code target}. */
	private static boolean branchTargets(Instruction branch, Address target) {
		FlowType ft = branch.getFlowType();
		if (ft == null || !ft.isJump() || !ft.isConditional()) {
			return false;
		}
		for (Address a : branch.getFlows()) {
			if (a.equals(target)) {
				return true;
			}
		}
		return false;
	}

	/** Walk back from {@code lda} for the {@code LDX/LDY #imm} that seeds index {@code idx}. */
	private Instruction findCounterInit(Listing listing, Instruction lda, Register idx) {
		String load = "LDX";
		if (idx.getName().equalsIgnoreCase("Y")) {
			load = "LDY";
		}
		else if (!idx.getName().equalsIgnoreCase("X")) {
			return null;
		}
		Instruction cur = listing.getInstructionBefore(lda.getAddress());
		for (int i = 0; i < COUNTER_LOOKBACK && cur != null; i++) {
			if (mnem(cur).equals(load) && StoredValueScanner.isImmediate(cur)) {
				return cur;
			}
			cur = listing.getInstructionBefore(cur.getAddress());
		}
		return null;
	}

	/** A {@code JMP}/{@code JSR} into {@code [base, base+len)} shortly after the loop, or null. */
	private Address findJumpIntoRange(Listing listing, Instruction branch, Address base, int len) {
		if (branch == null || branch.getFallThrough() == null) {
			return null;
		}
		Address end;
		try {
			end = base.add(len - 1);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
		Instruction cur = listing.getInstructionAt(branch.getFallThrough());
		for (int i = 0; i < JUMP_LOOKAHEAD && cur != null; i++) {
			String m = mnem(cur);
			if (m.equals("JMP") || m.equals("JSR")) {
				Address t = StoredValueScanner.plainAbsoluteTarget(cur);
				if (t != null && t.compareTo(base) >= 0 && t.compareTo(end) <= 0) {
					return cur.getAddress();
				}
			}
			cur = listing.getInstructionAfter(cur.getAddress());
		}
		return null;
	}
}
