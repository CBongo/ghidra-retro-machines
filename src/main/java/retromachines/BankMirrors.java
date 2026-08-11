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
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The addresses on this program that MIRROR THE LIVE BANK -- the derived half of bead
 * grm-mej.2, delivered to each configured {@link BankSwitchStrategy} via
 * {@link BankSwitchStrategy#observeMirrors} between {@code BoardBankAnalyzer}'s two
 * dataflow passes.
 * <p>
 * Two independent facts share one type because they answer one question ("what does a load
 * of this address tell me about the bank?") in two storage classes:
 * <ul>
 * <li>a <b>ROM offset whose byte is its own bank's number</b> in every realized bank -- a
 * cartridge convention, derived from image content by {@link #romIdentifyingOffsets}. Contra
 * and TMNT both have one at the base of their switchable window; TMNT's {@code cec0} reads it
 * as an API ({@code LDA $8000} = "which bank am I in?").</li>
 * <li>a <b>RAM cell the game writes through</b> on its way to the mechanism, or hands the
 * wrapper its argument in -- derived from code by {@link Discovery#scanWriteThroughShadows}
 * and {@link Discovery#scanArgumentCells}. Five of five hand-traced titles have at least one
 * (Mega Man {@code $42}, Castlevania 2 {@code $1C}, TMNT {@code $21}, Blaster Master
 * {@code $DB}/{@code $D3}, Wizards &amp; Warriors {@code $00}).</li>
 * </ul>
 * <p>
 * <b>Keyed by raw base-space offset, never by {@link Address}.</b> {@code Address.equals} is
 * address-SPACE sensitive, so a {@code Map<Address, ?>} populated from base space would
 * silently miss a query made from inside a {@code PRG_LO_B<n>} overlay -- and the failure mode
 * is a silent decline that no non-overlay fixture would catch. Membership therefore normalizes
 * through {@link AddressSpace#getPhysicalSpace()} exactly as
 * {@code MemoryLatchBankSwitchStrategy.inLatchRange} does, and for the same physical-bus reason:
 * it is the same wire whichever space names it.
 * <p>
 * <b>Provenance is carried, not flattened</b> ({@link Kind}). The consuming rule is
 * kind-dependent: only {@link Kind#WRITE_THROUGH} and {@link Kind#ROM_IDENTIFYING} may be
 * answered from tracked in-state. An {@link Kind#INPUT} or {@link Kind#SAVE_SLOT} cell holds a
 * bank that is deliberately NOT the live one -- TMNT saves the current bank precisely because it
 * is about to change it -- so resolving one from in-state would ship a confidently wrong bank,
 * which this engine rates strictly worse than no bank. They are carried for grm-mej.3's
 * cross-block forwarding and grm-mej.4's labelling to consume.
 */
public final class BankMirrors {

	/**
	 * What a mirror address is a mirror OF. One address may carry several: Blaster Master's
	 * {@code $D3} is written as a bank REQUEST by three functions and as a SAVE SLOT by two
	 * others, at one address.
	 */
	public enum Kind {
		/**
		 * A ROM offset holding its own bank's number in every realized bank of a switchable
		 * window. Reads the LIVE bank by construction, so it resolves from tracked in-state.
		 */
		ROM_IDENTIFYING,
		/**
		 * A RAM cell the game stores the bank into on its way to the mechanism write, so it
		 * tracks the live bank. Resolves from tracked in-state.
		 */
		WRITE_THROUGH,
		/**
		 * A RAM cell a caller loads its bank ARGUMENT out of immediately before calling a
		 * bank-switch wrapper. It holds the REQUESTED bank, which is the live one only after
		 * the wrapper runs -- so it does NOT resolve from in-state here.
		 */
		INPUT,
		/**
		 * A RAM cell holding a bank number stashed for later restoration, filled from a
		 * read-back rather than from the value being committed. It holds the OLD bank by
		 * intent, so it does NOT resolve from in-state.
		 */
		SAVE_SLOT
	}

	/**
	 * How many realized banks a switchable window must have before its content is allowed to
	 * establish an identifying offset. At two banks "byte K equals the bank number" is a
	 * one-in-256 coincidence per offset over a whole window's worth of offsets, i.e. not
	 * evidence at all; at three it is one in 65536 and the eight-bank boards this actually
	 * fires on (Contra, TMNT) clear it comfortably.
	 */
	static final int MIN_IDENTIFYING_BANKS = 3;

	/**
	 * Instruction budget for the discovery walks below. Same value and same reason as
	 * {@code StoredValueScanner}'s own backward scan: the idioms being matched are two to five
	 * instructions long, and the cap bounds a pathological straight-line block rather than
	 * standing in for a real termination argument (the fall-through linkage test provides that).
	 */
	private static final int MAX_BACKWARD_SCAN = 16;

	/** The 6502 stack page, refused as a mirror cell for {@code StoredValueScanner.inStackPage}'s
	 *  reason: a {@code PHA} writes it without naming an address any detector here can see. */
	private static final long STACK_PAGE_START = 0x0100;
	private static final long STACK_PAGE_END = 0x01FF;

	private static final BankMirrors EMPTY = new BankMirrors(null, Map.of(), Map.of());

	/** Null exactly when this set is empty, in which case no query can match anyway. */
	private final AddressSpace baseSpace;
	private final Map<Long, Set<Kind>> byOffset;
	/** Per cell, the mechanism writes it is known to be kept in step with -- see
	 *  {@link #pairedSwitchSites} and bead grm-p9y. */
	private final Map<Long, Set<Address>> pairedByOffset;

	private BankMirrors(AddressSpace baseSpace, Map<Long, Set<Kind>> byOffset,
			Map<Long, Set<Address>> pairedByOffset) {
		this.baseSpace = baseSpace;
		this.byOffset = byOffset;
		this.pairedByOffset = pairedByOffset;
	}

	/** The empty set -- what every board with no derivable mirror gets. */
	public static BankMirrors none() {
		return EMPTY;
	}

	/**
	 * A mirror set stated outright rather than derived -- for tests of the CONSUMPTION rules
	 * (grm-mej.2 increment 2), which are about "given that $42 is a write-through shadow, what
	 * does a load of it resolve to" and have no business also re-proving how $42 was found. The
	 * derivation is {@link Discovery}'s, exercised on its own by
	 * {@code BankMirrorDerivationProgramTest}; keeping the two separable is what stops a
	 * consumption regression from hiding behind a derivation one.
	 * <p>
	 * Package-private on purpose: production code has exactly one route into this type, and it is
	 * {@link Discovery#build()}.
	 */
	static BankMirrors of(AddressSpace baseSpace, Map<Long, Set<Kind>> byOffset) {
		if (byOffset.isEmpty()) {
			return EMPTY;
		}
		Map<Long, Set<Kind>> frozen = new LinkedHashMap<>();
		byOffset.forEach((k, v) -> frozen.put(k, Set.copyOf(v)));
		return new BankMirrors(baseSpace, Collections.unmodifiableMap(frozen), Map.of());
	}

	public boolean isEmpty() {
		return byOffset.isEmpty();
	}

	/**
	 * What {@code addr} mirrors, or an empty set when it mirrors nothing. Normalizes
	 * {@code addr} to the physical bus first, so an overlay-space query for an offset recorded
	 * in base space matches -- see the class javadoc for why that is not optional.
	 */
	public Set<Kind> kindsAt(Address addr) {
		if (addr == null || baseSpace == null ||
			!addr.getAddressSpace().getPhysicalSpace().equals(baseSpace)) {
			return Set.of();
		}
		return byOffset.getOrDefault(addr.getOffset(), Set.of());
	}

	/** Whether {@code addr} is a mirror of exactly this kind. */
	public boolean is(Address addr, Kind kind) {
		return kindsAt(addr).contains(kind);
	}

	/**
	 * The mechanism-write sites this cell is known to be kept in step with -- the switches whose
	 * own backward walk found it (bead grm-p9y). Empty when nothing is known, including for a set
	 * stated outright via {@link #of}.
	 * <p>
	 * This is what makes "is the shadow still coherent with the live bank?" answerable. A
	 * write-through shadow tracks the bank only for as long as every switch keeps updating it; a
	 * mechanism write OUTSIDE this set wrote the latch and left the shadow holding the previous
	 * bank. That is not an oddity but the standard interrupt-handler idiom, and it is why
	 * increment 2's write-through read-back shipped two confidently wrong banks.
	 */
	public Set<Address> pairedSwitchSites(Address addr) {
		Long offset = normalizedQueryOffset(addr);
		return offset == null ? Set.of() : pairedByOffset.getOrDefault(offset, Set.of());
	}

	/** {@code addr}'s offset on the physical bus, or null when it is not on this program's. */
	private Long normalizedQueryOffset(Address addr) {
		if (addr == null || baseSpace == null ||
			!addr.getAddressSpace().getPhysicalSpace().equals(baseSpace)) {
			return null;
		}
		return addr.getOffset();
	}

	/** Every mirror offset with its kinds, in discovery order -- for logging and for tests. */
	Map<Long, Set<Kind>> byOffset() {
		return byOffset;
	}

	@Override
	public String toString() {
		if (byOffset.isEmpty()) {
			return "no bank mirrors";
		}
		List<String> parts = new ArrayList<>();
		for (Map.Entry<Long, Set<Kind>> e : byOffset.entrySet()) {
			parts.add(String.format("$%04X%s", e.getKey(), e.getValue()));
		}
		return String.join(" ", parts);
	}

	// ------------------------------------------------------------------
	// Derivation: the bank-identifying ROM offset (content)
	// ------------------------------------------------------------------

	/**
	 * The offsets in one switchable window whose byte is, in EVERY realized bank of that
	 * window, that bank's own number. Contra passes at {@code $8000} (banks 0..7 hold
	 * {@code 00 01 02 ... 07} at byte 0); Mega Man correctly fails there
	 * ({@code 00 00 00 00 00 00 06 00}).
	 * <p>
	 * Content-derived rather than descriptor-declared, per the ruling on grm-mej.2: the
	 * per-game hint tier (grm-hb6.11's {@code bank_identifying_offset:}) does not exist yet, and
	 * blocking on it would strand this. A hint overrides a derivation later; deriving now also
	 * satisfies the vision doc's "prefer derivation to a hint" test, which Contra has already
	 * failed twice as a hint candidate when it was really an analyzer bug.
	 * <p>
	 * Reads each bank's window image ONCE rather than probing byte by byte: the nominal cost is
	 * {@code |window| * |banks|} single-byte reads, but the offsets die on their second bank
	 * comparison, so the loop below is a couple of array compares per offset over images that
	 * cost one bulk read each.
	 *
	 * @param realizedBanks the banks this window actually has an image slice for, from
	 *                      {@code BoardBankAnalyzer.realizedBanks} -- the program's own address
	 *                      spaces, not the container header
	 * @return the qualifying offsets in base-space coordinates, empty when the window has fewer
	 *         than {@link #MIN_IDENTIFYING_BANKS} realized banks, names a bank a byte cannot
	 *         hold, or has any bank whose image cannot be read in full
	 */
	static Set<Long> romIdentifyingOffsets(Program program, String windowName, long start,
			long end, Set<Integer> realizedBanks) {
		if (realizedBanks.size() < MIN_IDENTIFYING_BANKS || end < start) {
			return Set.of();
		}
		long span = end - start + 1;
		if (span > Integer.MAX_VALUE) {
			return Set.of();
		}
		int length = (int) span;
		List<Integer> banks = new ArrayList<>(realizedBanks);
		Collections.sort(banks);
		byte[][] images = new byte[banks.size()][];
		for (int i = 0; i < banks.size(); i++) {
			int bank = banks.get(i);
			if (bank < 0 || bank > 0xFF) {
				return Set.of(); // a byte cannot name this bank, so no offset can identify it
			}
			images[i] = readWindowImage(program, windowName, bank, start, length);
			if (images[i] == null) {
				return Set.of();
			}
		}

		Set<Long> offsets = new LinkedHashSet<>();
		nextOffset: for (int k = 0; k < length; k++) {
			for (int i = 0; i < banks.size(); i++) {
				if ((images[i][k] & 0xFF) != banks.get(i)) {
					continue nextOffset;
				}
			}
			offsets.add(start + k);
		}
		return offsets;
	}

	/**
	 * One bank's slice of one window, as bytes. The loader realizes exactly one bank of a
	 * switchable window in BASE space (the home bank) and every other as a
	 * {@code <window>_B<n>} overlay, so the space lookup falling back to the default space IS
	 * the home-bank case -- see {@code DescriptorSupport.OverlayNaming}. Returns {@code null}
	 * unless the whole {@code [start, start+length)} range is initialized memory.
	 */
	private static byte[] readWindowImage(Program program, String windowName, int bank, long start,
			int length) {
		AddressSpace space = program.getAddressFactory()
				.getAddressSpace(DescriptorSupport.OverlayNaming.bankBlockName(windowName, bank));
		if (space == null) {
			space = program.getAddressFactory().getDefaultAddressSpace();
		}
		Address addr;
		try {
			addr = space.getAddress(start);
		}
		catch (Exception e) {
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null || !block.isInitialized() ||
			block.getEnd().getOffset() < start + length - 1) {
			return null;
		}
		byte[] image = new byte[length];
		try {
			program.getMemory().getBytes(addr, image);
		}
		catch (Exception e) {
			return null;
		}
		return image;
	}

	// ------------------------------------------------------------------
	// Derivation: the RAM shadow (code)
	// ------------------------------------------------------------------

	/**
	 * Accumulates evidence for one candidate cell. Kept separate from the classification rule
	 * below so that "what did we see" and "is that enough" stay separable questions -- the
	 * thresholds have already moved once (see {@link #build}).
	 */
	private static final class Cell {
		/** Distinct {@code ST<r> S} instructions on a path into a mechanism write. */
		final Set<Address> writeThroughStores = new LinkedHashSet<>();
		/**
		 * The MECHANISM WRITES whose backward walk found this cell -- i.e. the switch sites this
		 * cell is known to be kept in step with (bead grm-p9y). Retained because "is this shadow
		 * still coherent with the live bank?" is answerable only against the set of switches that
		 * maintain it: a mechanism write OUTSIDE this set wrote the latch and left the shadow
		 * behind, which is the standard interrupt-handler idiom and the defect grm-p9y is about.
		 */
		final Set<Address> pairedSwitchSites = new LinkedHashSet<>();
		/** Distinct {@code LD<r> S} instructions feeding a mechanism write -- corroboration. */
		final Set<Address> writeThroughLoads = new LinkedHashSet<>();
		/** Distinct {@code LD<argReg> S} instructions feeding a call to a bank-switch helper. */
		final Set<Address> argumentLoads = new LinkedHashSet<>();
		/** Set when a store into this cell was sourced from a bank READ-BACK, not from the
		 *  value being committed -- the one shape that must never be typed WRITE_THROUGH. */
		boolean savedFromReadBack;
	}

	/**
	 * The mutable side of {@link BankMirrors}: one derivation pass's accumulated evidence,
	 * classified into kinds by {@link #build}. Scoped to a single {@code BoardBankAnalyzer}
	 * run and never published.
	 */
	static final class Discovery {

		private final AddressSpace baseSpace;
		private final Set<Long> romIdentifying = new LinkedHashSet<>();
		private final Map<Long, Cell> cells = new LinkedHashMap<>();

		Discovery(AddressSpace baseSpace) {
			this.baseSpace = baseSpace;
		}

		/** Records a content-derived identifying offset (see {@link #romIdentifyingOffsets}). */
		void addRomIdentifying(Collection<Long> offsets) {
			romIdentifying.addAll(offsets);
		}

		/**
		 * Discovery route (a): from each recognized mechanism write, walk ITS OWN basic block
		 * backward looking for the cell the committed value was mirrored into.
		 * <p>
		 * The walk is register-directed -- it tracks the register the mechanism write stores --
		 * and collects two kinds of evidence as it goes:
		 * <ul>
		 * <li>a {@code ST<r> S} means "the game wrote the bank to S as well as to the
		 * mechanism". Mega Man's {@code $42} (written alongside every switch), TMNT's
		 * {@code $21} and Castlevania 2's {@code $1C} are all this.</li>
		 * <li>a {@code LD<r> S} means "the value being committed CAME from S", which is the same
		 * claim from the other side, and the walk deliberately CONTINUES past it: {@code r} now
		 * holds S's value, so a store to S found further back is still evidence about the same
		 * cell. Castlevania 2 needs exactly this -- walking back from its chain crosses
		 * {@code c185 LDA $1C} and then {@code c183 STA $1C}, and treating the load as a plain
		 * register modifier would stop one instruction short of the store.</li>
		 * </ul>
		 * <p>
		 * <b>"Outside the latch range" is enforced as "in WRITABLE memory"</b>, which is the
		 * same test one level up: a mechanism latch lives in the cartridge's non-writable ROM
		 * window, so a writable target cannot be one. Doing it this way keeps the analyzer from
		 * having to ask each strategy for its range, and it also excludes the other thing a
		 * shadow must not be -- a second mechanism register.
		 * <p>
		 * <b>Not restricted to the zero page</b> (same ruling as grm-mej.1): Contra's save slots
		 * are {@code $07EC}/{@code $07ED}. The stack page is refused, because a {@code PHA}
		 * writes it invisibly.
		 *
		 * @param switchSites every recognized mechanism-write address from pass 1; also the
		 *                    walk's abort set, since a value read further back predates the
		 *                    switch there and cannot be attributed forward
		 */
		void scanWriteThroughShadows(Program program, Collection<Address> switchSites) {
			Listing listing = program.getListing();
			Set<Address> sites = switchSites instanceof Set<Address> s ? s
					: new LinkedHashSet<>(switchSites);
			for (Address site : sites) {
				Instruction store = listing.getInstructionAt(site);
				if (store == null) {
					continue;
				}
				Character reg = StoredValueScanner.storeRegister(store);
				if (reg == null) {
					continue;
				}
				walkFromMechanismWrite(program, listing, store, reg, sites);
			}
		}

		private void walkFromMechanismWrite(Program program, Listing listing, Instruction store,
				char reg, Set<Address> switchSites) {
			String storeMnem = "ST" + reg;
			String loadMnem = "LD" + reg;
			// The stores seen on THIS walk, retyped wholesale if the walk turns out to have been
			// carrying a read-back rather than a bank being committed (see below).
			List<Cell> storedOnThisWalk = new ArrayList<>();

			Instruction cur = store;
			for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
				Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
				if (prev == null || !fallsInto(prev, cur) ||
					StoredValueScanner.isControlFlowJoin(program, cur, prev) ||
					prev.getFlowType().isCall() || switchSites.contains(prev.getMinAddress())) {
					return;
				}
				String mnem = prev.getMnemonicString().toUpperCase();

				if (mnem.equals(storeMnem)) {
					Long offset = writableCellOffset(program, prev);
					if (offset != null) {
						Cell cell = cells.computeIfAbsent(offset, k -> new Cell());
						cell.writeThroughStores.add(prev.getMinAddress());
						cell.pairedSwitchSites.add(store.getMinAddress());
						storedOnThisWalk.add(cell);
					}
					cur = prev;
					continue;
				}

				if (mnem.equals(loadMnem) && !StoredValueScanner.isImmediate(prev)) {
					Address target = StoredValueScanner.plainAbsoluteTarget(prev);
					if (target != null && normalizedOffset(target) != null &&
						romIdentifying.contains(normalizedOffset(target))) {
						// The register was carrying a bank READ-BACK, so anything it was stored
						// into on the way here is a save slot, not a write-through shadow. TMNT's
						// LDA $8000 / STA $59 is the shape; typing it WRITE_THROUGH would later
						// answer its reload with the live bank when the whole point of the save
						// was that the bank is about to change.
						for (Cell cell : storedOnThisWalk) {
							cell.savedFromReadBack = true;
						}
						return;
					}
					Long offset = writableCellOffset(program, prev);
					if (offset == null) {
						return; // loaded from somewhere this pass cannot attribute
					}
					cells.computeIfAbsent(offset, k -> new Cell())
							.writeThroughLoads.add(prev.getMinAddress());
					cur = prev;
					continue;
				}

				if (StoredValueScanner.modifiesRegister(prev, reg)) {
					return;
				}
				cur = prev;
			}
		}

		/**
		 * Discovery route (b): the cell a CALLER loads its bank argument out of immediately
		 * before calling a bank-switch wrapper.
		 * <p>
		 * Route (a) is structurally unable to find these, and they are the more consequential
		 * half on the one title measured: Blaster Master's {@code $D3} is written at five sites
		 * in five functions, NONE of which contains a mechanism write, so no backward scan from
		 * any mechanism write reaches it -- yet it feeds six of the twelve call sites into the
		 * switch wrapper. This route starts from the call instead.
		 * <p>
		 * These are typed {@link Kind#INPUT}: the cell holds the bank the caller is ASKING for,
		 * which becomes the live bank only once the wrapper runs. That is why the kind is
		 * carried rather than merged into {@link Kind#WRITE_THROUGH}.
		 *
		 * @param helperCallSites call address to the argument register that call's helper takes
		 *                        its bank in, from {@code BoardBankAnalyzer}'s helper models
		 */
		void scanArgumentCells(Program program, Map<Address, Character> helperCallSites) {
			Listing listing = program.getListing();
			for (Map.Entry<Address, Character> entry : helperCallSites.entrySet()) {
				Instruction call = listing.getInstructionAt(entry.getKey());
				if (call == null || entry.getValue() == null) {
					continue;
				}
				char reg = entry.getValue();
				String loadMnem = "LD" + reg;

				Instruction cur = call;
				for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
					Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
					if (prev == null || !fallsInto(prev, cur) ||
						StoredValueScanner.isControlFlowJoin(program, cur, prev) ||
						prev.getFlowType().isCall()) {
						break;
					}
					String mnem = prev.getMnemonicString().toUpperCase();
					if (mnem.equals(loadMnem)) {
						if (!StoredValueScanner.isImmediate(prev)) {
							Long offset = writableCellOffset(program, prev);
							if (offset != null) {
								cells.computeIfAbsent(offset, k -> new Cell())
										.argumentLoads.add(prev.getMinAddress());
							}
						}
						break; // the argument's source, whatever it was
					}
					if (StoredValueScanner.modifiesRegister(prev, reg)) {
						break;
					}
					cur = prev;
				}
			}
		}

		/**
		 * Discovery route (c): a cell filled by COPYING one that already mirrors the live bank --
		 * {@code LD<r> <mirror> / ST<r> S} -- which makes {@code S} a {@link Kind#SAVE_SLOT}.
		 * <p>
		 * <b>The role route (a) is structurally unable to see, on the one title that was traced by
		 * hand for it.</b> Blaster Master's {@code $D3} carries TWO roles at ONE address: a bank
		 * REQUEST written before a switch (c251, e692, c9ba), and a SAVE SLOT holding a copy of the
		 * {@code $DB} shadow stashed across a region and written back at the end (e9bb, e9d5). Route
		 * (a) walks backward from a mechanism write and none of those five sites has one nearby;
		 * route (b) starts from a switch-helper call and sees only the LOAD side. So before this,
		 * {@code $D3} came out {@link Kind#INPUT} alone and its save-slot role was invisible -- and
		 * the bead's own warning about that shape is explicit: "the DISCOVERY pass has to tell the
		 * two apart or it will treat a save slot as a bank request".
		 * <p>
		 * <b>This is the existing save-slot rule, one notch more general, not a new idea.</b>
		 * {@link #walkFromMechanismWrite} already retypes a cell {@code SAVE_SLOT} when the register
		 * that filled it was carrying a READ-BACK of a {@link Kind#ROM_IDENTIFYING} offset (TMNT's
		 * {@code LDA $8000 / STA $59}). The only thing special about an identifying offset there is
		 * that reading it yields the live bank -- which is equally true of a {@link
		 * Kind#WRITE_THROUGH} shadow. So the source set is widened from "the identifying offset" to
		 * "anything already established as mirroring the live bank", and the destination is typed
		 * the same way for the same reason: a stashed COPY is a snapshot. It held the live bank at
		 * the instant it was written and stops tracking the moment the next switch happens, which is
		 * exactly what makes resolving it from in-state a confidently wrong answer.
		 * <p>
		 * <b>Runs after the other two routes and reads their result</b>, because "already
		 * established as mirroring" is only knowable once they have. Only cells that would qualify
		 * on their own evidence are treated as sources ({@link #liveMirrorOffsets}), so a
		 * single-store coincidence cannot seed a chain of save slots. The scan is forward rather
		 * than backward -- the copy's destination comes AFTER the load -- but honours the identical
		 * discipline: same basic block, unbroken fall-through, no control-flow join, no intervening
		 * modification of the register, {@link #MAX_BACKWARD_SCAN} steps.
		 * <p>
		 * <b>TWO copy sites are required, not one</b>, because this route records only a store into
		 * {@link Cell#writeThroughStores} and {@link #build} then applies its ordinary corroboration
		 * rule. That is deliberate rather than incidental: it is the same "one site is a
		 * coincidence" threshold route (a) enforces, and the measured case clears it (blmaster's
		 * {@code $D3} has two, e9bb and e9d5). It is arguably stricter than this route needs --
		 * {@code LD<r> <established mirror> / ST<r> S} is a specific two-instruction pattern rather
		 * than mere proximity to a mechanism write, so one occurrence is better evidence here than
		 * it is there -- but the threshold errs toward under-reporting, which for a KIND that only
		 * ever causes a decline is the harmless direction. Loosen it only with a case that needs it.
		 * <p>
		 * <b>This can REMOVE a recovered bank, which is the one way it is not inert.</b> Save slots
		 * do not resolve from in-state in either strategy, so nothing new resolves because of this
		 * route -- but a cell route (a) had typed {@link Kind#WRITE_THROUGH} and that this route
		 * retypes {@link Kind#SAVE_SLOT} stops resolving. That is the intended direction: if the
		 * cell really is a stash, the bank it was answering with was the OLD one, and losing a
		 * confidently wrong answer is a fix rather than a regression. It does mean this route's
		 * blast radius has to be measured on real ROMs and not assumed away.
		 * <p>
		 * Otherwise this exists so that grm-mej.3's cross-block forwarding and grm-mej.4's labelling
		 * are handed the right KIND rather than having to re-derive it -- and, more immediately, so
		 * that a cell carrying both roles cannot be silently flattened into the request half.
		 */
		void scanSaveSlotCopies(Program program) {
			Set<Long> sources = liveMirrorOffsets();
			if (sources.isEmpty()) {
				return;
			}
			Listing listing = program.getListing();
			for (Instruction load : listing.getInstructions(true)) {
				String mnem = load.getMnemonicString().toUpperCase();
				if (mnem.length() != 3 || !mnem.startsWith("LD") ||
					StoredValueScanner.isImmediate(load)) {
					continue;
				}
				char reg = mnem.charAt(2);
				if (reg != 'A' && reg != 'X' && reg != 'Y') {
					continue;
				}
				Long from = normalizedOffset(StoredValueScanner.plainAbsoluteTarget(load));
				if (from == null || !sources.contains(from)) {
					continue;
				}
				walkToCopyDestination(program, listing, load, reg);
			}
		}

		/** Forward half of route (c): from {@code LD<reg> <mirror>}, find the {@code ST<reg> S}
		 *  that stashes it, stopping at anything that could have changed {@code reg} on the way. */
		private void walkToCopyDestination(Program program, Listing listing, Instruction load,
				char reg) {
			String storeMnem = "ST" + reg;
			Instruction cur = load;
			for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
				Address fallThrough = cur.getFallThrough();
				if (fallThrough == null) {
					return;
				}
				Instruction next = listing.getInstructionAt(fallThrough);
				if (next == null || StoredValueScanner.isControlFlowJoin(program, next, cur) ||
					next.getFlowType().isCall()) {
					return;
				}
				if (next.getMnemonicString().toUpperCase().equals(storeMnem)) {
					Long offset = writableCellOffset(program, next);
					if (offset != null) {
						Cell cell = cells.computeIfAbsent(offset, k -> new Cell());
						cell.writeThroughStores.add(next.getMinAddress());
						cell.savedFromReadBack = true;
					}
					return; // the copy's destination, whatever it was
				}
				if (StoredValueScanner.modifiesRegister(next, reg)) {
					return;
				}
				cur = next;
			}
		}

		/**
		 * The offsets that, on the evidence gathered so far, genuinely track the LIVE bank -- the
		 * only cells a copy may be attributed to by {@link #scanSaveSlotCopies}. Deliberately
		 * recomputed from raw evidence rather than from {@link #build}'s output, so that a cell this
		 * very pass is about to retype {@code SAVE_SLOT} cannot act as a source for another one.
		 */
		private Set<Long> liveMirrorOffsets() {
			Set<Long> live = new LinkedHashSet<>(romIdentifying);
			for (Map.Entry<Long, Cell> entry : cells.entrySet()) {
				Cell cell = entry.getValue();
				if (!cell.savedFromReadBack && (cell.writeThroughStores.size() >= 2 ||
					(cell.writeThroughStores.size() == 1 && !cell.writeThroughLoads.isEmpty()))) {
					live.add(entry.getKey());
				}
			}
			return live;
		}

		/**
		 * Classifies the accumulated evidence into the immutable set.
		 * <p>
		 * <b>The corroboration rule.</b> One store site is a coincidence, so a write-through
		 * shadow needs either TWO distinct store sites or one store corroborated by a load of
		 * the same cell feeding a mechanism write. The corroboration half is not a softening:
		 * Castlevania 2 has exactly one PRG mechanism chain (its other fifteen mechanism writes
		 * are CHR and CTRL), so the literal "two distinct sites" rule rejects its {@code $1C} --
		 * an easy case the pass is supposed to find. Both of its evidences come out of one
		 * backward walk, which is exactly what corroboration means here.
		 * <p>
		 * A load-only cell is NOT admitted: without a store there is nothing tying the cell's
		 * content to the bank rather than to some unrelated byte that happened to be written to
		 * the latch.
		 */
		BankMirrors build() {
			Map<Long, Set<Kind>> byOffset = new LinkedHashMap<>();
			for (Long offset : romIdentifying) {
				byOffset.computeIfAbsent(offset, k -> EnumSet.noneOf(Kind.class))
						.add(Kind.ROM_IDENTIFYING);
			}
			for (Map.Entry<Long, Cell> entry : cells.entrySet()) {
				Cell cell = entry.getValue();
				Set<Kind> kinds = EnumSet.noneOf(Kind.class);
				boolean corroborated = cell.writeThroughStores.size() >= 2 ||
					(cell.writeThroughStores.size() == 1 && !cell.writeThroughLoads.isEmpty());
				if (corroborated) {
					kinds.add(cell.savedFromReadBack ? Kind.SAVE_SLOT : Kind.WRITE_THROUGH);
				}
				if (cell.argumentLoads.size() >= 2) {
					kinds.add(Kind.INPUT);
				}
				if (!kinds.isEmpty()) {
					byOffset.computeIfAbsent(entry.getKey(), k -> EnumSet.noneOf(Kind.class))
							.addAll(kinds);
				}
			}
			if (byOffset.isEmpty()) {
				return EMPTY;
			}
			Map<Long, Set<Kind>> frozen = new LinkedHashMap<>();
			byOffset.forEach((k, v) -> frozen.put(k, Collections.unmodifiableSet(v)));
			Map<Long, Set<Address>> paired = new LinkedHashMap<>();
			cells.forEach((offset, cell) -> {
				if (byOffset.containsKey(offset) && !cell.pairedSwitchSites.isEmpty()) {
					paired.put(offset, Collections.unmodifiableSet(
						new LinkedHashSet<>(cell.pairedSwitchSites)));
				}
			});
			return new BankMirrors(baseSpace, Collections.unmodifiableMap(frozen),
				Collections.unmodifiableMap(paired));
		}

		/** Whether the fall-through path from {@code prev} is exactly {@code cur} -- the block
		 *  linkage test both {@code StoredValueScanner} walks use. */
		private static boolean fallsInto(Instruction prev, Instruction cur) {
			Address fallThrough = prev.getFallThrough();
			return fallThrough != null && fallThrough.equals(cur.getMinAddress());
		}

		/**
		 * The base-space offset of a statically certain operand target in WRITABLE memory, or
		 * {@code null} when the operand is indexed/indirect, names ROM (which is where a
		 * mechanism latch lives -- see {@link #scanWriteThroughShadows}), or names the stack
		 * page. Normalizes to base space before asking about the block, so an instruction
		 * executing from inside an overlay resolves against the same RAM every other space
		 * shares.
		 */
		private Long writableCellOffset(Program program, Instruction instr) {
			Address target = StoredValueScanner.plainAbsoluteTarget(instr);
			Long offset = normalizedOffset(target);
			if (offset == null || (offset >= STACK_PAGE_START && offset <= STACK_PAGE_END)) {
				return null;
			}
			MemoryBlock block = program.getMemory().getBlock(baseSpace.getAddress(offset));
			return block != null && block.isWrite() ? offset : null;
		}

		/** {@code addr}'s offset on the physical bus, or {@code null} if it is not on it. */
		private Long normalizedOffset(Address addr) {
			if (addr == null ||
				!addr.getAddressSpace().getPhysicalSpace().equals(baseSpace)) {
				return null;
			}
			return addr.getOffset();
		}
	}
}
