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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;

/**
 * Shared 6502 loop-idiom recognition helpers used by the run-from-elsewhere family of
 * analyzers ({@link C64DecryptLoopAnalyzer}, grm-1.7.2; {@link CopyLoopAnalyzer},
 * grm-1.7.1). Both recognize the same down-counting indexed loop
 * ({@code LDX #n; loop: LDA base,X; ...; STA base,X; DEX; BPL loop}); they differ only in
 * the per-step transform (an EOR for decrypt, nothing for a verbatim copy) and in whether
 * the load and store share a base (in-place vs relocation). Extracted from
 * {@code C64DecryptLoopAnalyzer} without behavior change so the substrate is defined once
 * and is reusable by future recognizers (the seam is deliberately space/ISA-agnostic).
 */
final class LoopIdioms {

	// How far back to look for the loop-counter init, and how far past the loop for the
	// jump-into-range; both small because these stubs are tight, local constructs.
	private static final int COUNTER_LOOKBACK = 8;
	private static final int JUMP_LOOKAHEAD = 6;

	private LoopIdioms() {
	}

	static String mnem(Instruction instr) {
		return instr.getMnemonicString().toUpperCase();
	}

	/** The DEX/DEY mnemonic that decrements index register {@code idx}, or "" if neither. */
	static String decMnemonic(Register idx) {
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
	static Address indexedBase(Instruction instr) {
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

	/**
	 * The space where {@code a} actually has bytes: its own if a block lives there, otherwise the
	 * underlying physical (base) address, otherwise {@code a} unchanged.
	 *
	 * <p>{@link #indexedBase} necessarily builds its result in the <em>executing instruction's</em>
	 * space, since that is all an operand scalar tells you. On a banked machine the copy loop runs
	 * inside a bank overlay, so an NES {@code STA $6C90} executing from overlay {@code W8000_M3_B1}
	 * yields {@code W8000_M3_B1:6c90} -- an offset outside that block's own {@code 8000-bfff}
	 * range, where no block exists at all. Left alone it would defeat the in-place carve and
	 * silently produce an overlay copy instead. PRG-RAM lives in the base space, and
	 * {@code getPhysicalAddress()} maps an overlay address to the base one at the same offset, so
	 * this lands the address where its bytes really are. A no-op wherever no overlay is involved.
	 */
	static Address resolve(Program program, Address a) {
		if (a == null || program.getMemory().getBlock(a) != null) {
			return a;
		}
		Address physical = a.getPhysicalAddress();
		return program.getMemory().getBlock(physical) != null ? physical : a;
	}

	static Register indexReg(Instruction instr) {
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Register r) {
				return r;
			}
		}
		return null;
	}

	/** Whether {@code branch} is a conditional jump that targets {@code target}. */
	static boolean branchTargets(Instruction branch, Address target) {
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
	static Instruction findCounterInit(Listing listing, Instruction lda, Register idx) {
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
	static Address findJumpIntoRange(Listing listing, Instruction branch, Address base, int len) {
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
