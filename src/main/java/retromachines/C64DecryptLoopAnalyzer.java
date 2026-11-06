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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
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
 *
 * <p>The up-counting form (grm-430b) is also recognized, with its range
 * {@code [base+start, base+end-1]} (INX/INY, then {@code CPX/CPY #end} or nothing for 256, then
 * {@code BNE loop}), as in the Summer Games loader:
 * <pre>
 *       LDY #$0E
 *  loop: LDA $C001,Y
 *       EOR $C000,Y   ; rolling key: the previous, already decrypted byte
 *       STA $C001,Y
 *       INY
 *       CPY #$B7
 *       BNE loop      ; its operand is itself inside the range, so the loop PATCHES this branch
 *                     ; and the static target is garbage; exit falls through into the range
 * </pre>
 * A back-branch operand inside the range is judged by computing the patched operand for a
 * constant key, or accepted tentatively for a rolling key (the emulated run executes the real
 * branch). The up-count form uses the far (CFG-dominating) counter init too.
 * Auto-apply requires a {@code JMP}/{@code JSR} into the rewritten range, or the loop's exit
 * branch falling through into it (proof the bytes run as code); a loop without one is
 * recorded as a candidate bookmark only, never rewritten, so an ordinary indexed table transform is not mistaken for a decryptor.
 */
public class C64DecryptLoopAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "C64 Decrypt Loop";
	private static final String DESCRIPTION =
		"Recovers decrypt-on-the-fly SMC: recognizes in-place EOR decrypt loops, recovers " +
			"the plaintext (inline for a constant key, via emulation for a rolling key), and " +
			"exposes it as a DECRYPTED_xxxx overlay block.";
	private static final String CATEGORY = "C64DecryptLoopAnalyzer";

	/** Creates the C64 decrypt-loop recovery analyzer. */
	public C64DecryptLoopAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// After reference analysis so branch flows exist (back-edge + jump-into-range).
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	/** Returns whether the program uses the C64 PRG loader. */
	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		return format != null && format.equals(C64PrgLoader.NAME);
	}

	/** Scans changed instructions for recognized in-place decrypt loops. */
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		Listing listing = program.getListing();
		for (Instruction eor : listing.getInstructions(set, true)) {
			if (monitor.isCancelled()) {
				break;
			}
			if (!LoopIdioms.mnem(eor).equals("EOR")) {
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
		if (lda == null || sta == null || !LoopIdioms.mnem(lda).equals("LDA") ||
			!LoopIdioms.mnem(sta).equals("STA")) {
			return;
		}

		// Invariant 1: indexed load and store to the SAME base and index register (in place).
		Address base = LoopIdioms.indexedBase(lda);
		Register idx = LoopIdioms.indexReg(lda);
		Address staBase = LoopIdioms.indexedBase(sta);
		Register staIdx = LoopIdioms.indexReg(sta);
		if (base == null || staBase == null || idx == null || staIdx == null) {
			return;
		}
		if (!base.equals(staBase) || !idx.equals(staIdx)) {
			return;
		}

		// Key model from the EOR operand.
		RecognizedDecryptor.KeyModel key;
		if (MosOperands.isImmediate(eor)) {
			Integer k = MosOperands.immediateOperandValue(eor);
			if (k == null) {
				return;
			}
			key = RecognizedDecryptor.KeyModel.constant(k);
		}
		else if (LoopIdioms.indexedBase(eor) != null) {
			key = RecognizedDecryptor.KeyModel.rolling(LoopIdioms.indexedBase(eor));
		}
		else {
			key = RecognizedDecryptor.KeyModel.of(RecognizedDecryptor.KeyModel.Kind.UNKNOWN);
		}

		// Invariant 3: index step + conditional back-branch to the loop head (the LDA).
		Instruction step = listing.getInstructionAfter(sta.getAddress());
		Instruction branch = step == null ? null : listing.getInstructionAfter(step.getAddress());
		boolean downCount = step != null && LoopIdioms.mnem(step).equals(LoopIdioms.decMnemonic(idx));
		boolean bpl = branch != null && LoopIdioms.mnem(branch).equals("BPL");
		boolean backEdge = branch != null && LoopIdioms.branchTargets(branch, lda.getAddress());

		// Bound the range. Only the clean form -- LDX/LDY #(len-1); ...; DEX/DEY; BPL loop --
		// gives a range certain to be [base, base+len); other counter/branch forms have
		// off-by-one traps, so we recognize but do not auto-apply them.
		Instruction init = LoopIdioms.findCounterInit(listing, lda, idx);
		// grm-29ua (as grm-7pp in CopyLoopAnalyzer): an init further back than the linear lookback
		// is found by walking the CFG backwards; it must dominate the loop on every path. Such an
		// init can be shared between loops, so bookmarks and provenance anchor on this loop's own
		// LDA, while an emulated run still starts at the init (it seeds the index register).
		boolean farInit = false;
		if (init == null && downCount && bpl && backEdge) {
			init = LoopIdioms.findDominatingCounterInit(program, lda, idx, branch);
			farInit = init != null;
		}
		if (!downCount && tryUpCount(program, listing, lda, step, idx, base, key, monitor, log)) {
			return;
		}
		Integer n = init == null ? null : MosOperands.immediateOperandValue(init);
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
		Address jumpInto = LoopIdioms.findJumpIntoRange(listing, branch, base, len);
		Address fallInto = fallThroughInto(branch, base, base.add(len - 1));
		RecognizedDecryptor.Confidence conf = jumpInto != null || fallInto != null
				? RecognizedDecryptor.Confidence.AUTO
				: RecognizedDecryptor.Confidence.CANDIDATE;

		Address anchor = farInit ? lda.getAddress() : entry;
		RecognizedDecryptor rd = new RecognizedDecryptor(entry, anchor, target, key, conf,
			jumpInto, fallInto, false);
		apply(program, rd, monitor, log);
	}

	/** The branch's fall-through address when it lies in {@code [lo, hi]}, else null. */
	private static Address fallThroughInto(Instruction branch, Address lo, Address hi) {
		Address ft = branch.getFallThrough();
		if (ft != null && ft.compareTo(lo) >= 0 && ft.compareTo(hi) <= 0) {
			return ft;
		}
		return null;
	}

	/**
	 * The up-counting form (grm-430b): {@code LDX/LDY #start; loop: LDA base,I; EOR ..; STA base,I;
	 * INX/INY; [CPX/CPY #end]; BNE loop}, range {@code [base+start, base+end-1]} (no compare means
	 * end = 256). The loop may patch its own back-branch operand (the Summer Games loader does);
	 * then the static target is meaningless: a constant key lets us compute the patched operand,
	 * a rolling key is accepted tentatively and the emulated run (which executes the patched
	 * branch) must cover the range. Returns true when the shape was recognized here (applied or
	 * bookmarked), false to let the caller fall back to its generic "could not be bounded" warning.
	 */
	private boolean tryUpCount(Program program, Listing listing, Instruction lda, Instruction step,
			Register idx, Address base, RecognizedDecryptor.KeyModel key, TaskMonitor monitor,
			MessageLog log) {
		if (step == null || !LoopIdioms.mnem(step).equals(LoopIdioms.incMnemonic(idx))) {
			return false;
		}
		Instruction next = listing.getInstructionAfter(step.getAddress());
		if (next == null) {
			return false;
		}
		String cmpMnem = idx.getName().equalsIgnoreCase("X") ? "CPX" : "CPY";
		int end = 256;
		Instruction branch = next;
		if (LoopIdioms.mnem(next).equals(cmpMnem) && MosOperands.isImmediate(next)) {
			Integer e = MosOperands.immediateOperandValue(next);
			if (e == null) {
				return false;
			}
			end = e == 0 ? 256 : e;
			branch = listing.getInstructionAfter(next.getAddress());
		}
		if (branch == null || !LoopIdioms.mnem(branch).equals("BNE") || branch.getLength() != 2) {
			return false;
		}

		Instruction init = LoopIdioms.findCounterInit(listing, lda, idx);
		boolean farInit = false;
		if (init == null) {
			init = LoopIdioms.findDominatingCounterInit(program, lda, idx, branch);
			farInit = init != null;
		}
		Integer start = init == null ? null : MosOperands.immediateOperandValue(init);
		if (start == null || end <= start) {
			return false;
		}

		long baseOff = base.getOffset();
		if (baseOff + end - 1 > base.getAddressSpace().getMaxAddress().getOffset()) {
			return false;
		}
		Address lo;
		Address hi;
		AddressRange target;
		try {
			lo = base.add(start);
			hi = base.add(end - 1);
			target = new AddressRangeImpl(lo, hi);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		int len = end - start;

		// Back edge. A branch operand inside the range is rewritten by the loop itself.
		Address opAddr = branch.getAddress().add(1);
		boolean selfPatched = target.contains(opAddr);
		if (target.contains(branch.getAddress())) {
			return false; // the opcode itself is rewritten: cannot judge the loop
		}
		if (selfPatched) {
			if (key.kind() == RecognizedDecryptor.KeyModel.Kind.CONSTANT) {
				byte[] raw = new byte[1];
				try {
					program.getMemory().getBytes(opAddr, raw);
				}
				catch (MemoryAccessException e) {
					return false;
				}
				int patched = (raw[0] & 0xFF) ^ key.constant();
				Address after = branch.getAddress().add(2);
				Address patchedTarget;
				try {
					patchedTarget = after.add((byte) patched);
				}
				catch (AddressOutOfBoundsException e) {
					return false;
				}
				if (!patchedTarget.equals(lda.getAddress())) {
					return false;
				}
			}
			// rolling/unknown key: tentative back edge; emulation must cover the range.
		}
		else if (!LoopIdioms.branchTargets(branch, lda.getAddress())) {
			return false;
		}

		Address entry = init.getAddress();
		Address jumpInto = LoopIdioms.findJumpIntoRange(listing, branch, lo, len);
		Address fallInto = fallThroughInto(branch, lo, hi);
		RecognizedDecryptor.Confidence conf = jumpInto != null || fallInto != null
				? RecognizedDecryptor.Confidence.AUTO
				: RecognizedDecryptor.Confidence.CANDIDATE;
		Address anchor = farInit ? lda.getAddress() : entry;
		apply(program, new RecognizedDecryptor(entry, anchor, target, key, conf, jumpInto, fallInto,
			selfPatched), monitor, log);
		return true;
	}

	/** Route a recognized decryptor to inline decrypt (tier 1), emulation (tier 2), or a
	 *  candidate warning, and materialize any recovered plaintext. */
	private void apply(Program program, RecognizedDecryptor rd, TaskMonitor monitor,
			MessageLog log) {
		Address base = rd.target().getMinAddress();
		int len = (int) rd.target().getLength();
		RecognizedDecryptor.KeyModel.Kind kind = rd.key().kind();

		if (rd.confidence() != RecognizedDecryptor.Confidence.AUTO) {
			program.getBookmarkManager().setBookmark(rd.anchor(), BookmarkType.WARNING, CATEGORY,
				"possible decrypt loop " + rd.target() + " (key=" + rd.key() +
					"); no jump into range, not applied");
			return;
		}

		if (kind == RecognizedDecryptor.KeyModel.Kind.CONSTANT) {
			byte[] plain = decryptConstant(program, base, len, rd.key().constant());
			if (plain == null) {
				program.getBookmarkManager().setBookmark(rd.anchor(), BookmarkType.WARNING, CATEGORY,
					"constant decrypt: could not read encrypted bytes at " + base);
				return;
			}
			materialize(program, rd, plain,
				String.format("static constant-EOR key $%02X", rd.key().constant()), false, monitor,
				log);
		}
		else {
			// Tier 2: rolling/computed/unknown key -> emulate the loop and read back the range.
			RecoveryResult res = runEmulation(program, rd, monitor);
			byte[] plain = res.recoveredBytes(base, len);
			if (plain == null) {
				program.getBookmarkManager().setBookmark(rd.anchor(), BookmarkType.WARNING, CATEGORY,
					"emulated decrypt did not cover " + rd.target() + " (" + res.stopReason() +
						"); not applied");
				return;
			}
			// A hardware-tainted run (IO/uninit reads) still recovers bytes, but flags them
			// suspect so the overlay is a WARNING, not an authoritative NOTE.
			materialize(program, rd, plain, "emulated (" + kind + ")", res.provenance().suspect(),
				monitor, log);
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

	/** Create the {@code DECRYPTED_xxxx} overlay ({@link RecoveredBlockNames#forDecrypted}, which
	 *  also qualifies the name with the address space when the plaintext is not in the default
	 *  space -- the name doubles as the idempotence key, grm-0p7) seeded with the recovered
	 *  bytes, disassemble the payload there so it is navigable as code, and link it back to the
	 *  decryptor with bookmarks and a comment. A suspect (emulation-derived, hardware-tainted)
	 *  result gets a WARNING bookmark -- with a pointer to the accurate manual-recovery paths --
	 *  instead of an authoritative NOTE. */
	private void materialize(Program program, RecognizedDecryptor rd, byte[] plain, String detail,
			boolean suspect, TaskMonitor monitor, MessageLog log) {
		Address base = rd.target().getMinAddress();
		String name = RecoveredBlockNames.forDecrypted(program, base);
		AddressSpace targetSpace = base.getAddressSpace();
		RecoveredBlockNames.ExistingBlock existing = RecoveredBlockNames.probeExistingBlock(program, name);
		if (existing.sameSpaceAs(targetSpace)) {
			return; // already recovered on a prior pass -- idempotent
		}
		if (existing.collidesWith(targetSpace)) {
			// sanitizeSpaceName folded two distinct address spaces to the same recovered name
			// (grm-ppmr) -- refuse rather than silently treat this as an idempotent no-op.
			AnalyzerLog.warn(this, log,
				RecoveredBlockNames.collisionMessage(name, existing.existingSpace(), targetSpace));
			return;
		}
		MemoryBlock block;
		try {
			block = MemoryBlockUtils.createInitializedBlock(program, true, name, base,
				new ByteArrayInputStream(plain), plain.length,
				"decrypted view of " + rd.target() + " (" + detail + ")", CATEGORY,
				true, false, true, log, TaskMonitor.DUMMY);
		}
		catch (AddressOverflowException e) {
			AnalyzerLog.warn(this, log, name + ": could not create overlay: " + e.getMessage());
			return;
		}
		if (block == null) {
			AnalyzerLog.warn(this, log, name + ": overlay creation failed");
			return;
		}

		// Disassemble the recovered payload in the overlay so it reads as code -- the whole
		// point of decrypting it. Same idiom BoardBankAnalyzer uses for cross-bank targets.
		Address overlayStart = block.getStart();
		// A self-patched loop's range starts at its own branch OPERAND, which is not code; only
		// the code entry below is disassembled then.
		if (!rd.selfPatched() && program.getListing().getInstructionAt(overlayStart) == null) {
			new DisassembleCommand(overlayStart, null, true).applyTo(program, monitor);
			if (program.getListing().getInstructionAt(overlayStart) != null &&
				program.getFunctionManager().getFunctionAt(overlayStart) == null) {
				new CreateFunctionCmd(overlayStart).applyTo(program, monitor);
			}
		}
		// The range can start with a rewritten loop operand rather than code (grm-430b): also
		// disassemble where execution actually enters it.
		if (rd.codeEntry() != null) {
			Address ce = overlayStart.getAddressSpace().getAddress(rd.codeEntry().getOffset());
			if (ce != null && program.getListing().getInstructionAt(ce) == null) {
				new DisassembleCommand(ce, null, true).applyTo(program, monitor);
				if (program.getListing().getInstructionAt(ce) != null &&
					program.getFunctionManager().getFunctionAt(ce) == null) {
					new CreateFunctionCmd(ce).applyTo(program, monitor);
				}
			}
		}

		// Provenance. A suspect result also points at the manual paths that can get
		// hardware-accurate bytes (tier 3), since the emulated value is not trustworthy.
		String referral = suspect
				? "; recovered value depends on hardware the emulator does not model -- for " +
					"accurate bytes use a VICE .vsf snapshot import or the Debugger pure-emulation " +
					"Copy-Into-Program"
				: "";
		String msg = (suspect ? "SUSPECT " : "") + "decrypted " + rd.target() + " key=" + rd.key() +
			"; " + detail +
			(rd.selfPatched() ? "; back branch self-patched (operand inside range)" : "") + referral;
		program.getBookmarkManager().setBookmark(rd.anchor(),
			suspect ? BookmarkType.WARNING : BookmarkType.NOTE, CATEGORY, msg);
		program.getBookmarkManager().setBookmark(base,
			suspect ? BookmarkType.WARNING : BookmarkType.NOTE, CATEGORY,
			"decrypted range start; see overlay " + name);
		AnalyzerCommentRecord.set(program, rd.anchor(), CommentType.EOL, "decrypt loop -> " + name);
	}
}
