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
import ghidra.program.model.address.AddressSetView;
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
 * <li>a <b>ROM offset whose byte encodes its own bank's number</b> in every realized bank -- a
 * cartridge convention, derived from image content by {@link #romIdentifyingOffsets}. The
 * common case is the byte holding the bank number outright ({@code byte == bank}, Contra and
 * TMNT both have one at the base of their switchable window; TMNT's {@code cec0} reads it as an
 * API, {@code LDA $8000} = "which bank am I in?"). River City Ransom (MMC3) proved a second,
 * narrower shape necessary: its {@code WA000} window holds {@code byte == bank >> 1} on the ODD
 * banks only, because {@code fed1}'s 16K-index convention always leaves R7 odd (bead grm-km4f).
 * {@link IdentifyingEncoding} is what carries which shape an offset actually proved, so a
 * consumer answers exactly the case the image supports and refuses everything else.</li>
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
 * which this engine rates strictly worse than no bank. They are carried for grm-zsxz's
 * cross-block forwarding (split out of grm-mej.3) and grm-mej.4's labelling to consume.
 */
public final class BankMirrors {

	/**
	 * What a mirror address is a mirror OF. One address may carry several: Blaster Master's
	 * {@code $D3} is written as a bank REQUEST by three functions and as a SAVE SLOT by two
	 * others, at one address.
	 */
	public enum Kind {
		/**
		 * A ROM offset that content-derivation proved encodes its own bank's number, by SOME
		 * {@link IdentifyingEncoding}, over a congruent, significant subset of the realized banks
		 * of a switchable window. Reads the LIVE bank by construction, so it resolves from
		 * tracked in-state -- but only for a bank the recorded encoding actually verified; see
		 * {@link IdentifyingEncoding#byteFor} for the refusal that keeps an unverified bank from
		 * answering anyway (bead grm-km4f).
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
	 * How many realized banks must AGREE with a candidate {@link IdentifyingEncoding} before its
	 * offset is admitted. At two banks "byte K equals f(bank)" is a one-in-256 coincidence per
	 * offset over a whole window's worth of offsets, i.e. not evidence at all; at three it is one
	 * in 65536.
	 * <p>
	 * <b>Since grm-km4f the count is over CONGRUENT, NON-EXEMPT matching banks, not over every
	 * realized bank of the window.</b> Before, "significant" and "every realized bank agrees"
	 * were the same test because the only candidate was {@code shift == 0}. They came apart once
	 * a shift-form candidate is tried: River City Ransom's {@code WA000} byte agrees with
	 * {@code bank >> 1} on the ODD banks ONLY (MMC3's {@code fed1} always leaves R7 odd), so the
	 * denominator this floor counts against is the odd-bank subset that shares the candidate's
	 * congruence class, exempt banks aside -- three or more of THOSE, not three or more realized
	 * banks overall, is what keeps the floor's original one-in-65536 argument true for a
	 * shift-form encoding instead of silently weakening it to "any three banks in the window,
	 * whichever congruence class they happen to fall in."
	 */
	static final int MIN_IDENTIFYING_BANKS = 3;

	/**
	 * The floor for a SHIFT-FORM candidate ({@code shift != 0}), one bank stricter than
	 * {@link #MIN_IDENTIFYING_BANKS} -- the "raise the floor for the weaker signature" the owner
	 * asked for on grm-km4f, and it was needed. The random-byte argument above says three exact
	 * matches are one in 65536, but real cartridges are not random: banks that share a data
	 * layout hold the same small integers at the same offsets, and a shift-form candidate only
	 * asks a few of them to agree. Measured 2026-09-21 over the pinned NES corpus with the floor
	 * at three: kicarus admitted 23 spurious shift-form offsets, wizwarr and bionic 3 each, Mega
	 * Man 4, Mega Man 2 and River City Ransom 2 each, Legendary Wings 1 -- and River City
	 * Ransom's genuine {@code $BFFF} was the ONLY offset in the corpus with more than three
	 * matches (seven, every odd bank but the exempt fifteenth). At four every spurious admission
	 * disappears and the genuine one stays. A wrong admission here is not a wrong VALUE (the
	 * byte was read from the image) but a wrong CLASSIFICATION -- a {@code bank_id_} label and a
	 * save/restore reading of every load of that offset -- which is still guessing, and the
	 * ruling is to refuse.
	 */
	static final int MIN_SHIFTED_IDENTIFYING_BANKS = 4;

	/**
	 * How many of a switchable window's highest-numbered realized banks are EXEMPT from having to
	 * agree with a SHIFT-FORM ({@code shift != 0}) candidate {@link IdentifyingEncoding} (bead
	 * grm-km4f). River City Ransom's bank 15 is the case this exists for: it is
	 * {@code PRG[last]}, MMC3's fixed {@code WE000} bank, and never enters the switchable
	 * {@code WA000} window at runtime, yet it is still "realized" there because the loader gives
	 * every bank an overlay. Its {@code WA000} image byte is {@code f1} -- neither its own number
	 * nor half of it -- which would otherwise fail the {@code bank >> 1} candidate that every bank
	 * that DOES enter the window satisfies.
	 * <p>
	 * <b>This is a PROXY, not the real test, and it is deliberately NEVER applied to {@code shift
	 * == 0}.</b> The real fact is "this bank is {@code PRG[last]} (or {@code PRG[second_last]})
	 * and this board pins it to a fixed window", which lives in the descriptor's fixed-bank
	 * declarations, not in anything {@code romIdentifyingOffsets} can see from image content and
	 * a realized-bank set alone. Exempting the top two NUMBERED banks is the safe approximation
	 * available without that descriptor plumbing for a board shaped like MMC3, where the
	 * numerically highest realized banks genuinely are the ones pinned outside the switchable
	 * window -- but the proxy is simply WRONG on a board where the register can select every
	 * realized bank into the window, MMC2's {@code W8000} among them (a 4-bit field, all sixteen
	 * banks genuinely reachable there). Applying the exemption at {@code shift == 0} broke exactly
	 * that board's existing golden: MMC2's home bank (which happens to be numerically highest, and
	 * holds live RESET code rather than a bank-number marker at the offset under test) got
	 * exempted, and its disagreement was tolerated into a spurious identity admission from
	 * coincidental agreement among the other banks -- a real board's identifying offset invented
	 * from a shape the image never proved. Restricting the exemption to {@code shift != 0} keeps
	 * identity EXACTLY as strict as it was before this bead (unconditionally, every realized bank
	 * must agree) while still admitting RCR's {@code shift == 1} case. A future increment that
	 * threads the descriptor's actual {@code last}/{@code second_last} bank set through to this
	 * derivation should replace this constant with that set outright, at which point the
	 * shift-independence restriction can be revisited on real proof rather than a numeric guess.
	 */
	private static final int FIXED_BANK_EXEMPTION_COUNT = 2;

	/**
	 * Instruction budget for the discovery walks below. Same value and same reason as
	 * {@code StoredValueScanner}'s own backward scan: the idioms being matched are two to five
	 * instructions long, and the cap bounds a pathological straight-line block rather than
	 * standing in for a real termination argument (the fall-through linkage test provides that).
	 */
	private static final int MAX_BACKWARD_SCAN = 16;

	/**
	 * The 6502 stack page, refused as a mirror cell independently of
	 * {@code StoredValueScanner}'s own (now-relaxed, grm-mej.3 increment 2) stack-page
	 * forwarding stance: {@code PHA} writes it without naming an address any detector here can
	 * see, so this discovery walk cannot tell a genuine write-through mirror in the stack page
	 * from a cell that merely happens to sit beneath a push. Mirror discovery has a different
	 * risk profile than value forwarding -- a wrongly nominated mirror poisons every later query
	 * against it, not just one -- so it keeps the conservative blanket refusal rather than
	 * adopting the low-stack-depth aliasing assumption {@code StoredValueScanner} now accepts.
	 */
	private static final long STACK_PAGE_START = 0x0100;
	private static final long STACK_PAGE_END = 0x01FF;

	private static final BankMirrors EMPTY =
		new BankMirrors(null, Map.of(), Map.of(), Map.of(), Map.of(), Map.of());

	/** Null exactly when this set is empty, in which case no query can match anyway. */
	private final AddressSpace baseSpace;
	private final Map<Long, Set<Kind>> byOffset;
	/** Per cell, the mechanism writes it is known to be kept in step with -- see
	 *  {@link #pairedSwitchSites} and bead grm-p9y. */
	private final Map<Long, Set<Address>> pairedByOffset;
	/** Per cell, the instructions that established it as a mirror -- see {@link #evidenceSites}
	 *  and bead grm-mej.4, which needs this to write a "how do you know" comment. */
	private final Map<Long, Set<Address>> evidenceByOffset;
	/** Per {@link Kind#ROM_IDENTIFYING} offset, the state field that selects the bank of the
	 *  window it lives in -- see {@link #identifyingField} and bead grm-sen5. */
	private final Map<Long, BoardDescriptorModel.FieldSpec> identifyingFieldByOffset;
	/** Per {@link Kind#ROM_IDENTIFYING} offset, the encoding {@code romIdentifyingOffsets} proved
	 *  for it -- see {@link #identifyingEncoding} and bead grm-km4f. */
	private final Map<Long, IdentifyingEncoding> identifyingEncodingByOffset;

	private BankMirrors(AddressSpace baseSpace, Map<Long, Set<Kind>> byOffset,
			Map<Long, Set<Address>> pairedByOffset, Map<Long, Set<Address>> evidenceByOffset,
			Map<Long, BoardDescriptorModel.FieldSpec> identifyingFieldByOffset,
			Map<Long, IdentifyingEncoding> identifyingEncodingByOffset) {
		this.baseSpace = baseSpace;
		this.byOffset = byOffset;
		this.pairedByOffset = pairedByOffset;
		this.evidenceByOffset = evidenceByOffset;
		this.identifyingFieldByOffset = identifyingFieldByOffset;
		this.identifyingEncodingByOffset = identifyingEncodingByOffset;
	}

	/**
	 * How one {@link Kind#ROM_IDENTIFYING} offset's byte relates to the bank number, proved by
	 * {@link #romIdentifyingOffsets} against the realized banks of the window it lives in (bead
	 * grm-km4f).
	 * <p>
	 * <b>The shape is {@code byte == bank >> shift}, valid only on banks congruent to {@code low}
	 * in the low {@code shift} bits</b> -- {@code shift == 0} is the ordinary {@code byte == bank}
	 * convention (Contra, TMNT); River City Ransom's MMC3 {@code WA000} window is
	 * {@code shift == 1, low == 1}: {@code fed1}'s 16K-index convention (r6=2i, r7=2i+1) means R7
	 * is always odd when the window is live, and its {@code byte == bank >> 1} holds on exactly
	 * those banks. {@code low} ranges over {@code [0, 2^shift)}, so it identifies which residue
	 * class of banks the encoding was proved for.
	 * <p>
	 * <b>{@code verified} and {@code realized} answer two different questions.</b> {@code realized}
	 * is every bank the window has an image for at all (the derivation's own input); {@code
	 * verified} is the subset {@code romIdentifyingOffsets} actually confirmed the formula against
	 * -- ordinarily every congruent bank, but a bank exempted as {@code PRG[last]}/
	 * {@code PRG[second_last]} (see {@link #FIXED_BANK_EXEMPTION_COUNT}) is verified only if its
	 * image happened to agree anyway. A consumer must refuse a bank that is {@code realized} but
	 * not {@code verified}: that bank's byte was never proved to obey this formula, and answering
	 * it anyway would ship a confidently wrong number for a bank that only ever fails safe here
	 * because nothing tried to read it as one.
	 */
	record IdentifyingEncoding(int shift, int low, Set<Integer> verified, Set<Integer> realized) {

		/** The trivial encoding: {@code byte == bank}, unconditionally. */
		static IdentifyingEncoding identity() {
			return new IdentifyingEncoding(0, 0, Set.of(), Set.of());
		}

		/** Whether this is the ordinary {@code byte == bank} convention, with no congruence
		 *  restriction at all. */
		boolean isIdentity() {
			return shift == 0;
		}

		/**
		 * A short human-readable statement of the formula, for {@code BankAnnotationAdapter
		 * .nameBankMirrors}' comment. Identity keeps the pre-grm-km4f text exactly
		 * ({@code "byte = bank"}) so a golden with no shift-form encoding never churns; a
		 * shift-form encoding names its divisor and residue class, e.g.
		 * {@code "byte = (bank-1)/2 on odd banks"} for River City Ransom's {@code WA000}.
		 */
		String describe() {
			if (isIdentity()) {
				return "byte = bank";
			}
			int divisor = 1 << shift;
			String numerator = low == 0 ? "bank" : "(bank-" + low + ")";
			String suffix = divisor == 2
					? " on " + (low == 0 ? "even" : "odd") + " banks"
					: " on banks == " + low + " (mod " + divisor + ")";
			return "byte = " + numerator + "/" + divisor + suffix;
		}

		/**
		 * The raw byte a load of an offset carrying this encoding yields, given the tracked
		 * bank-selecting field lifted to bit 0, or {@link BankState#unknown()} when the proof does
		 * not cover the tracked value -- never a guess (bead grm-km4f, owner ruling: prefer
		 * refusing to guessing).
		 * <p>
		 * Three refusals, in order:
		 * <ol>
		 * <li>the tracked field's low {@code shift} bits are not fully known, or are known but
		 * disagree with {@code low} -- the bank is not provably in this encoding's congruence
		 * class at all;</li>
		 * <li>the tracked field, together with what is unknown about it, is still consistent with
		 * some {@code realized} bank that is NOT in {@code verified} -- the formula was never
		 * proved for that bank, so answering would risk shipping its (possibly wrong) value under
		 * cover of a proof that does not actually reach it;</li>
		 * <li>(none -- the answer below is proved).</li>
		 * </ol>
		 * Otherwise the field is shifted right by {@code shift} and the bits above the resulting
		 * byte-mask are PROVED zero, exactly as the {@code shift == 0} case always was: every
		 * realized-but-unverified value has already been excluded by refusal 2, so nothing above
		 * the shifted field can be anything the image did not prove.
		 *
		 * @param fieldKnown the tracked field's known-bits mask, lifted to bit 0
		 * @param fieldBits  the tracked field's bits, lifted to bit 0
		 * @param fieldMask  the tracked field's own width mask, e.g. {@code (1 << width) - 1}
		 * @return the resolved byte, or {@link BankState#unknown()} when the proof does not reach it
		 */
		BankState byteFor(int fieldKnown, int fieldBits, int fieldMask) {
			int lowMask = (1 << shift) - 1;
			if ((fieldKnown & lowMask) != lowMask || (fieldBits & lowMask) != low) {
				return BankState.unknown();
			}
			for (int bank : realized) {
				if ((bank & fieldKnown & fieldMask) == (fieldBits & fieldKnown & fieldMask) &&
					!verified.contains(bank)) {
					return BankState.unknown();
				}
			}
			int byteMaskOut = fieldMask >> shift;
			int known = ((fieldKnown >> shift) & byteMaskOut) | (~byteMaskOut & 0xFF);
			int bits = (fieldBits >> shift) & byteMaskOut;
			return new BankState(known, bits);
		}
	}

	/**
	 * Returns the shared empty mirror set.
	 *
	 * @return the empty set used by every board with no derivable mirror
	 */
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
		return of(baseSpace, byOffset, Map.of());
	}

	/**
	 * {@link #of(AddressSpace, Map)} plus the per-offset window field an identifying offset
	 * carries (see {@link #identifyingField}) -- for consumption tests of a strategy that
	 * refuses an identifying offset whose owning field it cannot name (select-data, bead
	 * grm-sen5). An offset absent from {@code identifyingFields} answers {@code null} there,
	 * which is the shape a derivation that did not attribute the window produces.
	 * <p>
	 * Every offset carrying {@link Kind#ROM_IDENTIFYING} defaults to {@link
	 * IdentifyingEncoding#identity} unless {@link #of(AddressSpace, Map, Map, Map)} states
	 * otherwise -- so every consumption test written before grm-km4f, which never mentions an
	 * encoding at all, keeps stating {@code byte == bank} exactly as it always implicitly did.
	 */
	static BankMirrors of(AddressSpace baseSpace, Map<Long, Set<Kind>> byOffset,
			Map<Long, BoardDescriptorModel.FieldSpec> identifyingFields) {
		return of(baseSpace, byOffset, identifyingFields, Map.of());
	}

	/**
	 * {@link #of(AddressSpace, Map, Map)} plus an explicit per-offset {@link IdentifyingEncoding}
	 * -- for consumption tests that need to state a NON-identity encoding (bead grm-km4f), such as
	 * River City Ransom's shift-form {@code WA000} byte. An offset present in {@code byOffset}
	 * with {@link Kind#ROM_IDENTIFYING} but absent from {@code identifyingEncodings} still
	 * defaults to identity, exactly as the shorter overloads do -- only a test that actually cares
	 * about a shift-form answer needs to reach for this one.
	 */
	static BankMirrors of(AddressSpace baseSpace, Map<Long, Set<Kind>> byOffset,
			Map<Long, BoardDescriptorModel.FieldSpec> identifyingFields,
			Map<Long, IdentifyingEncoding> identifyingEncodings) {
		if (byOffset.isEmpty()) {
			return EMPTY;
		}
		Map<Long, Set<Kind>> frozen = new LinkedHashMap<>();
		byOffset.forEach((k, v) -> frozen.put(k, Set.copyOf(v)));
		Map<Long, IdentifyingEncoding> encodings = new LinkedHashMap<>(identifyingEncodings);
		frozen.forEach((offset, kinds) -> {
			if (kinds.contains(Kind.ROM_IDENTIFYING)) {
				encodings.putIfAbsent(offset, IdentifyingEncoding.identity());
			}
		});
		return new BankMirrors(baseSpace, Collections.unmodifiableMap(frozen), Map.of(), Map.of(),
			Map.copyOf(identifyingFields), Map.copyOf(encodings));
	}

	/**
	 * Tests whether any mirrors were discovered.
	 *
	 * @return whether this set contains no bank mirrors
	 */
	public boolean isEmpty() {
		return byOffset.isEmpty();
	}

	/**
	 * What {@code addr} mirrors, or an empty set when it mirrors nothing. Normalizes
	 * {@code addr} to the physical bus first, so an overlay-space query for an offset recorded
	 * in base space matches -- see the class javadoc for why that is not optional.
	 *
	 * @param addr the address to query
	 * @return the mirror kinds associated with {@code addr}, or an empty set
	 */
	public Set<Kind> kindsAt(Address addr) {
		if (addr == null || baseSpace == null ||
			!addr.getAddressSpace().getPhysicalSpace().equals(baseSpace)) {
			return Set.of();
		}
		return byOffset.getOrDefault(addr.getOffset(), Set.of());
	}

	/**
	 * Tests one address for one mirror kind.
	 *
	 * @param addr the address to query
	 * @param kind the mirror kind to test
	 * @return whether {@code addr} is a mirror of {@code kind}
	 */
	public boolean is(Address addr, Kind kind) {
		return kindsAt(addr).contains(kind);
	}

	/**
	 * Whether {@code addr} MIRRORS THE LIVE BANK as a matter of KIND alone -- a
	 * {@link Kind#WRITE_THROUGH} shadow or a {@link Kind#ROM_IDENTIFYING} offset (bead grm-yflf,
	 * widened to direct sites by grm-rd6h). This is the one test
	 * {@code HelperArgumentRecovery.OracleHooks#isLiveBankMirror} and every strategy's direct-site
	 * {@code StoredValueScanner.Hooks#isLiveBankMirror} must share, so the call-site and
	 * direct-site classifications cannot drift apart on what counts as a live-bank mirror.
	 * {@link Kind#INPUT} (a caller's requested bank, live only after the wrapper runs) and
	 * {@link Kind#SAVE_SLOT} (the OLD bank, saved because a switch is about to happen) are
	 * deliberately excluded -- see {@code MemoryLatchBankSwitchStrategy.mirroredByte}'s javadoc
	 * for why those two kinds never answer a live-bank query.
	 *
	 * @param addr the address to query, or {@code null} (answers {@code false})
	 * @return whether {@code addr} is a write-through or ROM-identifying mirror of the live bank
	 */
	public boolean isLiveBankMirror(Address addr) {
		return addr != null && (is(addr, Kind.WRITE_THROUGH) || is(addr, Kind.ROM_IDENTIFYING));
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
	 *
	 * @param addr the mirror address to query
	 * @return the mechanism-write sites paired with {@code addr}, or an empty set
	 */
	public Set<Address> pairedSwitchSites(Address addr) {
		Long offset = normalizedQueryOffset(addr);
		return offset == null ? Set.of() : pairedByOffset.getOrDefault(offset, Set.of());
	}

	/**
	 * The instructions that established {@code addr} as a mirror -- the union of the cell's
	 * {@code writeThroughStores} (route (a)/(c)) and {@code argumentLoads} (route (b)), i.e. the
	 * evidence {@link Discovery#build} actually classified on. {@code writeThroughLoads} is
	 * deliberately excluded: those are corroboration for a store elsewhere, not an independent
	 * site establishing the cell, and grm-mej.4's naming pass wants "where do I look to see why
	 * this is a mirror," not every instruction the backward walk happened to pass through. Empty
	 * when {@code addr} is not a mirror at all, including for a set stated outright via
	 * {@link #of}.
	 *
	 * @param addr the mirror address to query
	 * @return the instructions that established {@code addr} as a mirror, or an empty set
	 */
	public Set<Address> evidenceSites(Address addr) {
		Long offset = normalizedQueryOffset(addr);
		return offset == null ? Set.of() : evidenceByOffset.getOrDefault(offset, Set.of());
	}

	/**
	 * For a {@link Kind#ROM_IDENTIFYING} offset, the {@code banking.state} field whose value
	 * selects the bank of the switchable window the offset lives in -- i.e. WHICH tracked bank
	 * a load of {@code addr} reads back (bead grm-sen5). {@code null} when {@code addr} is not
	 * an identifying offset, or when the derivation did not attribute its window to a field.
	 * <p>
	 * <b>Why a consumer needs this.</b> A single-field mechanism can assume "the bank" means
	 * its one field, and {@code MemoryLatchBankSwitchStrategy}/{@code SerialShiftBankSwitchStrategy}
	 * do. A mechanism that tracks SEVERAL switchable windows through separate registers cannot:
	 * on MMC3, {@code $A000-$BFFF} is R7 and {@code $8000-$9FFF} is R6 (in prg_mode 0), so the
	 * byte read at an identifying offset is a function of the register that owns THAT window,
	 * and answering it from the wrong field ships a confidently wrong bank. The field is
	 * recorded here, at derivation time, from the window the offset was found in -- it is the
	 * proof a multi-window consumer narrows its answer with, and a consumer that cannot match
	 * it to a field it tracks must refuse rather than guess.
	 * <p>
	 * <b>Valid in every mode, and only because of how it is derived.</b>
	 * {@code BankAnnotationAdapter.deriveBankMirrors} content-scans mode-INVARIANT computed
	 * windows only, so the field recorded here selects the window's bank under every mode the
	 * board has (MMC3's {@code WA000} is R7 in both prg_modes; its mode-varying {@code W8000}/
	 * {@code WC000} are never scanned). A future derivation over mode-varying windows must
	 * record the mode alongside the field, and every consumer must then refuse when the tracked
	 * mode is unknown or differs -- do not widen the derivation without widening this.
	 */
	BoardDescriptorModel.FieldSpec identifyingField(Address addr) {
		Long offset = normalizedQueryOffset(addr);
		if (offset == null || !byOffset.getOrDefault(offset, Set.of()).contains(Kind.ROM_IDENTIFYING)) {
			return null;
		}
		return identifyingFieldByOffset.get(offset);
	}

	/**
	 * For a {@link Kind#ROM_IDENTIFYING} offset, the {@link IdentifyingEncoding} that proved it --
	 * i.e. exactly how its byte relates to the bank number and which banks that proof actually
	 * covers (bead grm-km4f). {@code null} when {@code addr} is not an identifying offset.
	 * <p>
	 * Every production {@link Kind#ROM_IDENTIFYING} offset carries one: {@link
	 * #romIdentifyingOffsets} never admits an offset without recording the encoding that admitted
	 * it, and both {@link Discovery#addRomIdentifying(java.util.Collection)} overloads and every
	 * {@link #of} overload default an unstated one to {@link IdentifyingEncoding#identity}. A
	 * {@code null} return at an offset {@code kindsAt} reports as {@code ROM_IDENTIFYING} would
	 * therefore mean a caller built a {@code BankMirrors} some other way -- treat it as a defensive
	 * refusal, not an expected case.
	 */
	IdentifyingEncoding identifyingEncoding(Address addr) {
		Long offset = normalizedQueryOffset(addr);
		if (offset == null || !byOffset.getOrDefault(offset, Set.of()).contains(Kind.ROM_IDENTIFYING)) {
			return null;
		}
		return identifyingEncodingByOffset.get(offset);
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
	 * The offsets in one switchable window whose byte {@link IdentifyingEncoding proves} it
	 * encodes its own bank's number, tried as {@code byte == bank >> shift} for
	 * {@code shift in {0, 1, 2}} and every congruence class {@code low in [0, 2^shift)}, in that
	 * order, with the FIRST admitted encoding recorded per offset (bead grm-km4f -- an offset
	 * cannot honestly satisfy two encodings at once, so the more general one, tried first, wins).
	 * Contra passes {@code shift == 0} at {@code $8000} (banks 0..7 hold {@code 00 01 02 ... 07}
	 * at byte 0); Mega Man correctly fails every shift there
	 * ({@code 00 00 00 00 00 00 06 00}); River City Ransom's MMC3 {@code WA000} passes only
	 * {@code shift == 1, low == 1} (odd banks), because {@code fed1}'s 16K-index convention
	 * (r6=2i, r7=2i+1) never leaves an even bank live in that window.
	 * <p>
	 * <b>An offset is admitted for {@code (shift, low)} iff</b> every CONGRUENT realized bank that
	 * is not one of the window's {@link #FIXED_BANK_EXEMPTION_COUNT} highest-numbered ("fixed")
	 * banks agrees with the formula, AND the set of banks that agree (fixed ones included, when
	 * they happen to) numbers at least {@link #MIN_IDENTIFYING_BANKS} for identity or
	 * {@link #MIN_SHIFTED_IDENTIFYING_BANKS} for a shift form. A single non-exempt
	 * disagreement refuses the WHOLE {@code (shift, low)} candidate at that offset -- prefer
	 * refusing to guessing (owner ruling on grm-km4f) -- rather than only the offending bank.
	 * <p>
	 * Content-derived rather than descriptor-declared, per the ruling on grm-mej.2: the
	 * per-game hint tier (grm-hb6.11's {@code bank_identifying_offset:}) does not exist yet, and
	 * blocking on it would strand this. A hint overrides a derivation later; deriving now also
	 * satisfies the vision doc's "prefer derivation to a hint" test, which Contra has already
	 * failed twice as a hint candidate when it was really an analyzer bug.
	 * <p>
	 * Reads each bank's window image ONCE rather than probing byte by byte: the nominal cost is
	 * {@code |window| * |banks|} single-byte reads, but the offsets die on their second bank
	 * comparison, so the loop below is a handful of array compares per offset over images that
	 * cost one bulk read each.
	 *
	 * @param realizedBanks the banks this window actually has an image slice for, from
	 *                      {@code BankAnnotationAdapter.realizedBanks} -- the program's own address
	 *                      spaces, not the container header
	 * @return the qualifying offsets in base-space coordinates, each with the encoding that
	 *         admitted it; empty when the window has fewer than {@link #MIN_IDENTIFYING_BANKS}
	 *         realized banks, names a bank a byte cannot hold, or has any bank whose image cannot
	 *         be read in full
	 */
	static Map<Long, IdentifyingEncoding> romIdentifyingOffsets(Program program, String windowName,
			long start, long end, Set<Integer> realizedBanks) {
		if (realizedBanks.size() < MIN_IDENTIFYING_BANKS || end < start) {
			return Map.of();
		}
		long span = end - start + 1;
		if (span > Integer.MAX_VALUE) {
			return Map.of();
		}
		int length = (int) span;
		List<Integer> banks = new ArrayList<>(realizedBanks);
		Collections.sort(banks);
		byte[][] images = new byte[banks.size()][];
		for (int i = 0; i < banks.size(); i++) {
			int bank = banks.get(i);
			if (bank < 0 || bank > 0xFF) {
				return Map.of(); // a byte cannot name this bank, so no offset can identify it
			}
			images[i] = readWindowImage(program, windowName, bank, start, length);
			if (images[i] == null) {
				return Map.of();
			}
		}

		// The window's own fixed-bank proxy (see FIXED_BANK_EXEMPTION_COUNT): the highest-numbered
		// realized banks, exempted from having to agree with a SHIFT-FORM candidate. NOT applied
		// at shift == 0 -- see the loop below for why identity draws no exemption at all.
		Set<Integer> exempt = new LinkedHashSet<>();
		for (int i = banks.size() - 1; i >= 0 && exempt.size() < FIXED_BANK_EXEMPTION_COUNT; i--) {
			exempt.add(banks.get(i));
		}
		Set<Integer> realized = Set.copyOf(realizedBanks);

		Map<Long, IdentifyingEncoding> offsets = new LinkedHashMap<>();
		nextOffset: for (int k = 0; k < length; k++) {
			for (int shift = 0; shift <= 2; shift++) {
				// Identity draws NO exemption, ever (bead grm-km4f). The exemption exists to admit
				// a bank that CANNOT reach this window at runtime even though the loader realized
				// an overlay for it (RCR's PRG[last] never enters WA000) -- but "highest-numbered
				// realized bank" is only a proxy for that fact, and on a board where the register
				// really can select ANY realized bank into this window (MMC2's W8000 takes all 16),
				// the proxy is simply wrong. Measured regression: exempting MMC2's own highest W8000
				// bank (which holds live RESET code, not a bank-number marker, at the offset under
				// test) admitted $8000 as identity from three coincidental agreements plus one
				// tolerated disagreement -- a real board's offset invented from a shape the image
				// never actually proved. Restricting the exemption to shift != 0 keeps identity
				// exactly as strict as it was before this bead (never admits on anything short of
				// EVERY realized bank agreeing) while still letting RCR's shift == 1 case through.
				Set<Integer> exemptForThisShift = shift == 0 ? Set.of() : exempt;
				int congruenceClasses = 1 << shift;
				for (int low = 0; low < congruenceClasses; low++) {
					Set<Integer> matched = new LinkedHashSet<>();
					boolean nonExemptDisagreed = false;
					for (int i = 0; i < banks.size(); i++) {
						int bank = banks.get(i);
						if ((bank & (congruenceClasses - 1)) != low) {
							continue; // not in this candidate's congruence class at all
						}
						if ((images[i][k] & 0xFF) == (bank >> shift)) {
							matched.add(bank);
						}
						else if (!exemptForThisShift.contains(bank)) {
							nonExemptDisagreed = true;
							break;
						}
					}
					if (nonExemptDisagreed) {
						continue; // this (shift, low) is refused at this offset -- try the next
					}
					int floor = shift == 0 ? MIN_IDENTIFYING_BANKS : MIN_SHIFTED_IDENTIFYING_BANKS;
					if (matched.size() >= floor) {
						offsets.put(start + k,
							new IdentifyingEncoding(shift, low, Set.copyOf(matched), realized));
						continue nextOffset; // first admitted encoding wins -- see class javadoc
					}
				}
			}
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
	 * Which bit-field of the tracked bank state a mechanism write commits -- the granularity at
	 * which {@link Discovery#build} asks "is this cell maintained by EVERY switch?". Two sites
	 * share a field exactly when a shadow store paired with both maintains the same bits, which
	 * is what {@code SwitchResult}'s {@code lsb}/{@code effectMask} pair already expresses.
	 */
	record MechanismField(int lsb, int effectMask) {}

	/** The field the {@code Collection} form of {@link Discovery#scanWriteThroughShadows} assumes
	 *  when the caller does not distinguish mechanisms: every site commits the same field, so
	 *  coverage means "paired with all of them". Correct for a single-mechanism fixture, and
	 *  strictly conservative otherwise, since merging fields can only enlarge the denominator. */
	private static final MechanismField SOLE_FIELD = new MechanismField(0, -1);

	/**
	 * The mutable side of {@link BankMirrors}: one derivation pass's accumulated evidence,
	 * classified into kinds by {@link #build}. Scoped to a single {@code BoardBankAnalyzer}
	 * run and never published.
	 */
	static final class Discovery {

		private final AddressSpace baseSpace;
		private final Set<Long> romIdentifying = new LinkedHashSet<>();
		/** The window field each identifying offset was found under -- see
		 *  {@link BankMirrors#identifyingField}. Offsets recorded through the field-less
		 *  {@link #addRomIdentifying(Collection)} have no entry. */
		private final Map<Long, BoardDescriptorModel.FieldSpec> romIdentifyingField =
			new LinkedHashMap<>();
		/** The {@link IdentifyingEncoding} each identifying offset was admitted under -- see
		 *  {@link BankMirrors#identifyingEncoding} and bead grm-km4f. Every offset in
		 *  {@link #romIdentifying} has an entry here: the {@code Collection<Long>} overloads
		 *  below default the unstated ones to {@link IdentifyingEncoding#identity}. */
		private final Map<Long, IdentifyingEncoding> romIdentifyingEncoding =
			new LinkedHashMap<>();
		private final Map<Long, Cell> cells = new LinkedHashMap<>();
		/** Every mechanism write {@link #scanWriteThroughShadows} was handed, grouped by the
		 *  bit-field it commits -- the denominator of {@link #coversAMechanismField}. */
		private final Map<MechanismField, Set<Address>> sitesByField = new LinkedHashMap<>();

		Discovery(AddressSpace baseSpace) {
			this.baseSpace = baseSpace;
		}

		/**
		 * Records content-derived identifying offsets by raw offset alone, without naming the
		 * window field OR the {@link IdentifyingEncoding} that admitted each -- the form the
		 * derivation tests use when only the KIND matters. Every recorded offset defaults to
		 * {@link IdentifyingEncoding#identity} (bead grm-km4f): a consumer that needs the window
		 * field ({@link BankMirrors#identifyingField}) still sees {@code null} for these and
		 * refuses, but a consumer that only needs the encoding (every shipped strategy) gets the
		 * ordinary {@code byte == bank} answer, matching what this overload always implicitly meant
		 * before shift-form encodings existed.
		 */
		void addRomIdentifying(Collection<Long> offsets) {
			addRomIdentifying(offsets, null);
		}

		/**
		 * {@link #addRomIdentifying(Collection)} plus the {@code banking.state} field that selects
		 * the bank of the window the offsets were found in (bead grm-sen5), so a multi-window
		 * mechanism can answer a load of one from the right tracked field. {@code null} for
		 * {@code windowField} degrades to the field-less form. Encodings still default to
		 * {@link IdentifyingEncoding#identity}, same reasoning as the single-argument overload.
		 */
		void addRomIdentifying(Collection<Long> offsets,
				BoardDescriptorModel.FieldSpec windowField) {
			romIdentifying.addAll(offsets);
			for (Long offset : offsets) {
				romIdentifyingEncoding.putIfAbsent(offset, IdentifyingEncoding.identity());
			}
			if (windowField != null) {
				for (Long offset : offsets) {
					romIdentifyingField.put(offset, windowField);
				}
			}
		}

		/**
		 * The production form (bead grm-km4f): the offsets AND ENCODINGS {@link
		 * #romIdentifyingOffsets} proved, plus the {@code banking.state} field that selects the
		 * bank of the window they were found in (bead grm-sen5) so a multi-window mechanism can
		 * answer a load of one from the right tracked field. {@code null} for {@code windowField}
		 * degrades to the field-unattributed form, same as the {@code Collection<Long>} overload.
		 */
		void addRomIdentifying(Map<Long, IdentifyingEncoding> encodings,
				BoardDescriptorModel.FieldSpec windowField) {
			romIdentifying.addAll(encodings.keySet());
			romIdentifyingEncoding.putAll(encodings);
			if (windowField != null) {
				for (Long offset : encodings.keySet()) {
					romIdentifyingField.put(offset, windowField);
				}
			}
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
			Map<Address, MechanismField> single = new LinkedHashMap<>();
			for (Address site : switchSites) {
				single.put(site, SOLE_FIELD);
			}
			scanWriteThroughShadows(program, single);
		}

		/**
		 * The production form, which additionally says WHICH bit-field of the tracked state each
		 * site commits, so {@link #build} can ask whether a cell is maintained by every switch to
		 * a field rather than only how many times it was seen. See {@link #coversAMechanismField}.
		 */
		void scanWriteThroughShadows(Program program, Map<Address, MechanismField> switchSites) {
			Listing listing = program.getListing();
			Set<Address> sites = switchSites.keySet();
			switchSites.forEach((site, field) -> sitesByField
					.computeIfAbsent(field, k -> new LinkedHashSet<>()).add(site));
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
		 * <p>
		 * <b>The same load is also route (a)'s missing corroboration when the called helper
		 * itself stores its argument into that cell</b> (bead grm-yflf, the {@code helperBodies}
		 * form). Route (a)'s second rule -- one {@code ST<r> S} on the path into a mechanism
		 * write, corroborated by a {@code LD<r> S} feeding one -- is two-sided evidence that S
		 * carries the committed bank: written from the value going in, read back as the value
		 * going in. Mega Man 2 has exactly that pair with one call boundary in the middle:
		 * {@code FUN_c000}'s first instruction is {@code STA $29} (route (a) records the store,
		 * paired with the chain's first write) and its NMI tail is {@code LDA $29 / JSR $C000}
		 * (this route records the load) -- the read-back feeds the mechanism THROUGH the helper
		 * rather than directly. So an argument load of a cell that one of the called helper's own
		 * write-through stores lives in is recorded as a {@code writeThroughLoad} too, and
		 * {@link #build}'s ordinary rule 2 then types {@code $29} {@link Kind#WRITE_THROUGH}.
		 * Nothing else about the rule changes: the {@code savedFromReadBack} guard still
		 * demotes a cell filled from a bank READ-BACK to {@link Kind#SAVE_SLOT}, and the store
		 * itself was found by route (a)'s walk from a real mechanism write, never inferred here.
		 * Without {@code helperBodies} (the two-argument form, kept for the derivation tests)
		 * this route records argument loads alone, exactly as before.
		 *
		 * @param helperCallSites call address to the argument register that call's helper takes
		 *                        its bank in, from {@code BoardBankAnalyzer}'s helper models
		 */
		void scanArgumentCells(Program program, Map<Address, Character> helperCallSites) {
			scanArgumentCells(program, helperCallSites, Map.of());
		}

		/**
		 * {@link #scanArgumentCells(Program, Map)} with, per call site, the BODY of the helper it
		 * calls -- the production form (bead grm-yflf). See the two-argument form's javadoc for
		 * what the body enables.
		 *
		 * @param helperBodies call address to the called helper function's body; a call absent
		 *                     here contributes an argument load only
		 */
		void scanArgumentCells(Program program, Map<Address, Character> helperCallSites,
				Map<Address, AddressSetView> helperBodies) {
			Listing listing = program.getListing();
			for (Map.Entry<Address, Character> entry : helperCallSites.entrySet()) {
				Instruction call = listing.getInstructionAt(entry.getKey());
				if (call == null || entry.getValue() == null) {
					continue;
				}
				char reg = entry.getValue();
				AddressSetView helperBody = helperBodies.get(entry.getKey());
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
								Cell cell = cells.computeIfAbsent(offset, k -> new Cell());
								cell.argumentLoads.add(prev.getMinAddress());
								if (helperBody != null && cell.writeThroughStores.stream()
										.anyMatch(helperBody::contains)) {
									// The called helper writes this very cell through from its
									// argument, and this load feeds that argument: the two-sided
									// evidence of route (a)'s rule 2, across the call.
									cell.writeThroughLoads.add(prev.getMinAddress());
								}
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
		 * Otherwise this exists so that grm-zsxz's cross-block forwarding and grm-mej.4's labelling
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
				if (!cell.savedFromReadBack && corroborated(cell)) {
					live.add(entry.getKey());
				}
			}
			return live;
		}

		/**
		 * The three ways a cell's evidence adds up to "this mirrors the live bank" -- two distinct
		 * store sites, one store corroborated by a load feeding the mechanism write, or coverage
		 * of a whole mechanism field. Shared by {@link #build} and {@link #liveMirrorOffsets},
		 * which must agree: a cell {@code build} declines is not a legitimate copy source either.
		 */
		private boolean corroborated(Cell cell) {
			return cell.writeThroughStores.size() >= 2 ||
				(cell.writeThroughStores.size() == 1 && !cell.writeThroughLoads.isEmpty()) ||
				(!cell.writeThroughStores.isEmpty() && coversAMechanismField(cell));
		}

		/**
		 * Whether this cell is stored by EVERY recognized switch to at least one mechanism field
		 * -- the third corroboration route, and the one that admits a program whose banking is
		 * CENTRALISED in a single helper (bead grm-3n4f; db3's two-instruction
		 * {@code STA $6A / STA $6008} is the measured case).
		 * <p>
		 * The other two routes count evidence, on the reasoning that one store site is a
		 * coincidence. That reasoning is really a proxy for the property {@code WRITE_THROUGH}
		 * consumption actually needs: the cell must equal the live bank at the load, which holds
		 * only if every switch updates it. Coverage tests that property DIRECTLY, so a single
		 * store site satisfies it completely when it is the only switch site there is -- not
		 * weakly, the way a bare count would suggest.
		 * <p>
		 * Sites the walk could not start from still count against coverage: a switch committed by
		 * an RMW idiom ({@code INC} of the latch, bead grm-4kc) genuinely does not maintain the
		 * shadow, so leaving it in the denominator is the conservative and correct reading.
		 */
		private boolean coversAMechanismField(Cell cell) {
			for (Set<Address> field : sitesByField.values()) {
				if (!field.isEmpty() && cell.pairedSwitchSites.containsAll(field)) {
					return true;
				}
			}
			return false;
		}

		/**
		 * Classifies the accumulated evidence into the immutable set.
		 * <p>
		 * <b>The corroboration rule</b> ({@link #corroborated}, three routes). One store site
		 * seen in isolation is a coincidence, so a write-through shadow needs either TWO distinct
		 * store sites, or one store corroborated by a load of the same cell feeding a mechanism
		 * write, or -- since grm-3n4f -- coverage of a whole mechanism field. Neither of the
		 * latter two is a softening:
		 * Castlevania 2 has exactly one PRG mechanism chain (its other fifteen mechanism writes
		 * are CHR and CTRL), so the literal "two distinct sites" rule rejects its {@code $1C} --
		 * an easy case the pass is supposed to find. Both of its evidences come out of one
		 * backward walk, which is exactly what corroboration means here. And coverage
		 * ({@link #coversAMechanismField}) is a STRONGER claim than any count, not a weaker one:
		 * it establishes directly that every switch to the field maintains the cell, which is the
		 * property the counting rules were only ever a proxy for.
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
				if (corroborated(cell)) {
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
			Map<Long, Set<Address>> evidence = new LinkedHashMap<>();
			cells.forEach((offset, cell) -> {
				if (!byOffset.containsKey(offset)) {
					return;
				}
				if (!cell.pairedSwitchSites.isEmpty()) {
					paired.put(offset, Collections.unmodifiableSet(
						new LinkedHashSet<>(cell.pairedSwitchSites)));
				}
				Set<Address> established = new LinkedHashSet<>(cell.writeThroughStores);
				established.addAll(cell.argumentLoads);
				if (!established.isEmpty()) {
					evidence.put(offset, Collections.unmodifiableSet(established));
				}
			});
			return new BankMirrors(baseSpace, Collections.unmodifiableMap(frozen),
				Collections.unmodifiableMap(paired), Collections.unmodifiableMap(evidence),
				Collections.unmodifiableMap(new LinkedHashMap<>(romIdentifyingField)),
				Collections.unmodifiableMap(new LinkedHashMap<>(romIdentifyingEncoding)));
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
