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
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

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
	 *  only the unindexed {@link Address} case.
	 *
	 *  <p><b>Banked machines re-home themselves</b> -- worth knowing before anyone "fixes" this.
	 *  The base can only be built in the <em>executing instruction's</em> space, since an operand
	 *  scalar carries no space of its own, and on a banked machine that space is a bank overlay.
	 *  An NES {@code STA $6C90} running from overlay {@code W8000_M3_B1} therefore looks like it
	 *  ought to yield {@code W8000_M3_B1:6c90} -- an offset outside that overlay's own
	 *  {@code 8000-bfff} region, where no block exists, which would defeat the in-place carve and
	 *  silently produce an overlay copy instead. It does not:
	 *  {@code OverlayAddressSpace.getAddress(long)} (:128-134) returns
	 *  {@code baseSpace.getAddress(offset)} whenever {@code contains(offset)} is false, and
	 *  {@code ProgramOverlayAddressSpace.contains} (:90-98) tests the overlay's <em>defined block
	 *  set</em>. So an out-of-overlay offset already arrives as {@code RAM:6c90}, while one that
	 *  really is in the overlay correctly stays there. Verified against
	 *  {@code Ghidra_12.1.2_build}; the {@code nescopytest} fixture pins the outcome end to end. */
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

	/** Where a store's bytes actually land, when the banking analyzer has re-homed the store's own
	 *  write reference into another address space -- or null when it has not, which is every
	 *  unbanked destination and the normal case.
	 *
	 *  <p>On a banked machine the base-space block at a store's target is only the <em>home</em>
	 *  occupant of the containing window. A C64 copy loop writing to {@code $E000} targets the RAM
	 *  under the KERNAL ROM, but {@link #indexedBase} can only name {@code base:$E000}, which is
	 *  where the loader put the KERNAL block -- so carving there would shred a ROM image
	 *  (bead grm-bqs).
	 *
	 *  <p><b>The descriptor alone cannot settle this, and does not have to.</b> Which occupant a
	 *  write reaches is bank-state-dependent in general: a C64 store to {@code $D000} hits the I/O
	 *  registers when I/O is banked in and {@code RAM_D000} when it is not, and the schema has no
	 *  {@code on_read} key at all because a read simply goes to whichever occupant is live. But
	 *  {@code BoardBankAnalyzer.retargetReferences} has already resolved this store against the bank
	 *  state live at this very instruction and attached a WRITE reference to the occupant the write
	 *  actually reaches. Read that answer instead of deriving a weaker one from the descriptor.
	 *
	 *  <p>Requires the banking analyzer to have run first -- {@link CopyLoopAnalyzer} orders itself
	 *  after it for exactly this reason. If it has not, no such reference exists, the caller keeps
	 *  the base-space target, and behavior is what it was before banked destinations were resolved
	 *  at all.
	 *
	 *  @param store the storing instruction a copy loop is anchored on (the {@code STA})
	 *  @param base  that store's base-space target, from {@link #indexedBase}
	 */
	static Address overlayWriteTarget(Instruction store, Address base) {
		for (Reference ref : store.getReferencesFrom()) {
			if (!ref.getReferenceType().isWrite()) {
				continue;
			}
			Address to = ref.getToAddress();
			// Same offset, different space: addOverlayRef only ever re-homes an offset into another
			// occupant's space, so a reference to some other offset belongs to a different operand.
			if (to.getAddressSpace().isOverlaySpace() && to.getOffset() == base.getOffset()) {
				return to;
			}
		}
		return null;
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
