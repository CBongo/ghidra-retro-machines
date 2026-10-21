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

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

/**
 * Shared state and helpers of the range-based bank-switch strategies
 * ({@link SelectDataBankSwitchStrategy}, {@link SerialShiftBankSwitchStrategy},
 * {@link MemoryLatchBankSwitchStrategy}): a descriptor-supplied {@code [start, end]} register
 * range in the default space, the observed bank mirrors, and the field-layout lookup.
 * <p>
 * Deliberately NOT a forwarding {@code StoredValueScanner.Hooks} base: each strategy's probe
 * forwards only the hooks it means to, and forwarding more changes scan paths.
 * <p>
 * {@link MemoryLatchBankSwitchStrategy} has its own, differently shaped two-tier
 * {@code writesInRange} (a {@code boolean} with address-decode); the plain two-tier lookup
 * shared by the other two is therefore named {@link #registerOffsetWritten} here so the two
 * never collide.
 */
abstract class AbstractRangeBankSwitchStrategy implements BankSwitchStrategy {
	protected AddressSpace space;
	protected long rangeStart;
	protected long rangeEnd;

	/**
	 * The addresses that MIRROR THE LIVE BANK on this program (bead grm-mej.2), delivered by
	 * {@link #observeMirrors} between {@code BoardBankAnalyzer}'s two dataflow passes. Empty for
	 * pass 1 and for every board with no derivable mirror, in which case a strategy behaves
	 * exactly as it did before mirrors existed.
	 */
	protected BankMirrors mirrors = BankMirrors.none();

	/** Records bank-mirror locations discovered by the analyzer. */
	@Override
	public void observeMirrors(BankMirrors observed) {
		mirrors = observed == null ? BankMirrors.none() : observed;
	}

	@Override
	public BankMirrors observedMirrors() {
		return mirrors;
	}

	/** The shared prologue of every {@code configure}: default space and {@code start}/{@code end}. */
	protected final void configureRange(Program program, JsonObject params) {
		space = program.getAddressFactory().getDefaultAddressSpace();
		rangeStart = params.get("start").getAsLong();
		rangeEnd = params.get("end").getAsLong();
	}

	/** The field-layout entry for {@code fieldName}, or an error naming this strategy. */
	protected final BitField fieldPos(JsonObject fieldLayout, String fieldName) {
		JsonObject fl = fieldLayout.has(fieldName) ? fieldLayout.getAsJsonObject(fieldName) : null;
		if (fl == null) {
			throw new IllegalArgumentException(
				strategyName() + ": no field-layout entry for '" + fieldName +
					"' -- is it listed in this mechanism's 'sets:'?");
		}
		return new BitField(fl.get("lsb").getAsInt(), fl.get("width").getAsInt());
	}

	/**
	 * The register offset {@code instr} writes, or null: a write reference first, then the
	 * store's own plain-absolute operand, compared by PHYSICAL space (grm-xwnc): a store in a
	 * banked overlay copy references its own overlay's address inside the switchable window,
	 * typed {@code DATA} rather than {@code WRITE}. Gated on {@link MosOperands#storeRegister}
	 * (true STA/STX/STY), and plain absolute only, so no read-modify-write and no indexed store
	 * is newly seen.
	 */
	protected final Long registerOffsetWritten(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && inRange(to)) {
				return to.getOffset();
			}
		}
		if (MosOperands.storeRegister(instr) == null) {
			return null;
		}
		Address target = MosOperands.plainAbsoluteTarget(instr);
		return target != null && inRange(target) ? target.getOffset() : null;
	}

	/** True when {@code to} lies in {@code [rangeStart, rangeEnd]} of the configured space, by PHYSICAL space. */
	protected final boolean inRange(Address to) {
		return to.getAddressSpace().getPhysicalSpace().equals(space) &&
			to.getOffset() >= rangeStart && to.getOffset() <= rangeEnd;
	}
}
