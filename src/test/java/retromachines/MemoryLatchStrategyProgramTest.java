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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

/**
 * Pins {@link MemoryLatchBankSwitchStrategy}'s mechanism-write predicate, in particular the
 * operand-decode tier added by grm-3x1.
 * <p>
 * The gap these cover: a 6502 indexed operand's base arrives as a {@code Scalar}, so
 * disassembly lays down no default operand reference, and constant propagation -- the only
 * later source of one -- runs over function bodies only. A reference-only predicate therefore
 * cannot see the canonical UxROM bus-conflict switch ({@code LDA #n / TAX / STA banktable,X}),
 * which is precisely how Contra and Dragon Power switch banks. These tests assert the absence
 * of the reference explicitly rather than assuming it, so the fixture stays honest if a future
 * Ghidra starts emitting one.
 * <p>
 * All boards using {@code memory-latch} are NES discrete mappers, whose latch range is the
 * whole {@code $8000-$FFFF} ROM area; the fixture mirrors that.
 */
public class MemoryLatchStrategyProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private MemoryBlock prg;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		prg = builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		// Zero page is RAM, and has to be said out loud: MemoryMapDB creates every block with
		// MemoryBlock.READ alone (:684), so a ProgramBuilder block is NOT writable by default.
		// Leaving it is not a harmless omission -- bankInvariantRomByte would then treat a load
		// from zero page as a constant ROM byte, and the tests that mean to model an
		// unrecoverable RAM-sourced value would quietly recover one instead.
		makeWritable(zp);
	}

	/** A discrete-mapper latch over the whole ROM area, no address-decode predicate. */
	private MemoryLatchBankSwitchStrategy discreteLatch() {
		return latch(null, null, false);
	}

	/**
	 * A discrete-mapper latch with {@code bus_conflict: true} -- UxROM/Contra/Mega Man.
	 * <p>
	 * Needed as a separate helper because {@link #latch} deliberately leaves bus conflict off,
	 * so no pre-grm-hum test ever exercised the AND at all.
	 */
	private MemoryLatchBankSwitchStrategy busConflictLatch() {
		return latch(null, null, true);
	}

	/**
	 * A latch configured like Bandai FCG when {@code addrMask != null}: the PRG bank register
	 * is the nibble-8 mirror, every other nibble in range is a sibling register.
	 */
	private MemoryLatchBankSwitchStrategy latch(Long addrMask, Long addrMatch) {
		return latch(addrMask, addrMatch, false);
	}

	private MemoryLatchBankSwitchStrategy latch(Long addrMask, Long addrMatch,
			boolean busConflict) {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x0F);
		if (addrMask != null) {
			params.addProperty("addr_mask", addrMask);
			params.addProperty("addr_match", addrMatch);
		}
		if (busConflict) {
			params.addProperty("bus_conflict", true);
		}
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0xFF);
		return strategy;
	}

	/**
	 * States that PRG is ROM, which {@code bankInvariantRomByte} requires. Redundant with
	 * {@link ProgramBuilder}'s own default today (see {@link #setUp}) and kept anyway, so a
	 * test asserting a recovered ROM byte does not rest silently on that default.
	 */
	private void romifyPrg() {
		setWritable(prg, false);
	}

	private void makeWritable(MemoryBlock block) {
		setWritable(block, true);
	}

	private void makeReadOnly(MemoryBlock block) {
		setWritable(block, false);
	}

	private void setWritable(MemoryBlock block, boolean writable) {
		int tx = program.startTransaction("set block write permission");
		try {
			block.setWrite(writable);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/**
	 * Models the store as constant propagation never covered it. Disassembly does lay down a
	 * DEFAULT operand reference for a <em>plain absolute</em> operand, so an absolute fixture
	 * has to have that reference removed to stand in for code const-prop never reached; an
	 * indexed operand never gets one in the first place, which is the whole point of tier 2.
	 * Always paired with {@link #assertNoWriteReference} so a test cannot quietly stop
	 * exercising the tier it names.
	 */
	private void stripWriteReferences(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isWrite()) {
				builder.deleteReference(ref);
			}
		}
	}

	/** Asserts this really is the tier-2-only case -- see {@link #stripWriteReferences}. */
	private void assertNoWriteReference(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			assertFalse("fixture no longer models the refless case: " + instr + " -> " + ref,
				ref.getReferenceType().isWrite());
		}
	}

	/**
	 * Adds a write reference by hand. Needed for the reference-tier tests: a bare
	 * {@link ProgramBuilder} disassembly inside an overlay block lays down no operand reference
	 * at all, so the reference those tests are about has to be constructed rather than observed.
	 */
	private void addWriteReference(Instruction instr, Address to) {
		int tx = program.startTransaction("add write reference");
		try {
			program.getReferenceManager()
					.addMemoryReference(instr.getMinAddress(), to, RefType.READ_WRITE,
						SourceType.ANALYSIS, 0);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	// ------------------------------------------------------------------
	// GAP 1: stores carrying no write reference at all
	// ------------------------------------------------------------------

	/**
	 * The canonical UxROM bus-conflict idiom. {@code STA $FFD0,X} stores <em>A</em> (indexed by
	 * X), so the backward scan resolves the {@code LDA #$05} across the intervening {@code TAX}.
	 */
	@Test
	public void reflessIndexedStoreLatchesViaOperandDecode() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "aa", true); // TAX
		builder.setBytes("0x8003", "9d d0 ff", true); // STA $FFD0,X

		Instruction store = instructionAt("0x8003");
		assertNoWriteReference(store);

		BankState result = discreteLatch().computeSwitch(program, store, BankState.unknown());

		assertNotNull("indexed latch store was not recognized as a mechanism write", result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(0x05, result.bits());
	}

	/**
	 * Refless <em>absolute</em> stores exist too -- the grm-2yx probe found four in Wizards
	 * &amp; Warriors -- so the operand tier must not be indexed-only.
	 */
	@Test
	public void reflessAbsoluteStoreLatchesViaOperandDecode() throws Exception {
		builder.setBytes("0x8000", "a9 03", true); // LDA #$03
		builder.setBytes("0x8002", "8d 00 90", true); // STA $9000

		Instruction store = instructionAt("0x8002");
		stripWriteReferences(store);
		assertNoWriteReference(store);

		BankState result = discreteLatch().computeSwitch(program, store, BankState.unknown());

		assertNotNull("absolute latch store was not recognized as a mechanism write", result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(0x03, result.bits());
	}

	/** Out-of-range stores stay invisible: the operand tier widens reach, not the range. */
	@Test
	public void reflessStoreBelowRangeDoesNotLatch() throws Exception {
		builder.setBytes("0x8000", "a9 03", true); // LDA #$03
		builder.setBytes("0x8002", "8d 10 00", true); // STA $0010

		Instruction store = instructionAt("0x8002");
		stripWriteReferences(store);
		assertNoWriteReference(store);

		assertNull(discreteLatch().computeSwitch(program, store, BankState.unknown()));
	}

	/**
	 * Read-modify-write stores keep reference-only behaviour. {@code computeSwitch} answers
	 * {@link BankState#unknown()} for them, so newly <em>seeing</em> one would poison bank state
	 * rather than recover it -- the wrong direction for a reachability fix.
	 */
	@Test
	public void reflessReadModifyWriteStoreDoesNotLatch() throws Exception {
		builder.setBytes("0x8000", "ee 00 90", true); // INC $9000

		Instruction store = instructionAt("0x8000");
		stripWriteReferences(store);
		assertNoWriteReference(store);

		assertNull("RMW store must stay tier-1-only, not poison state",
			discreteLatch().computeSwitch(program, store, BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// The address-decode soundness ruling
	// ------------------------------------------------------------------

	/**
	 * The sharp case: {@code $FFF8}'s low nibble <em>is</em> the PRG register's, yet the store is
	 * {@code $FFF8,X} -- and {@code base & 0x0F} says nothing about {@code (base + X) & 0x0F}.
	 * Claiming a match here would latch {@code prg_bank} off an IRQ-register write, exactly what
	 * {@code addr_mask} exists to prevent, so the operand tier must decline.
	 */
	@Test
	public void indexedStoreDeclinesWhenAnAddressDecodeIsConfigured() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "9d f8 ff", true); // STA $FFF8,X

		Instruction store = instructionAt("0x8002");
		assertNoWriteReference(store);

		assertNull("indexed operand under addr_mask must decline, not guess",
			latch(0x0FL, 0x08L).computeSwitch(program, store, BankState.unknown()));
	}

	/** An absolute target is statically certain, so the decode predicate still applies to it. */
	@Test
	public void reflessAbsoluteStoreStillHonorsAddressDecode() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "8d f8 ff", true); // STA $FFF8 -- nibble 8, the PRG register
		builder.setBytes("0x8005", "a9 06", true); // LDA #$06
		builder.setBytes("0x8007", "8d f0 ff", true); // STA $FFF0 -- nibble 0, a sibling register

		Instruction prgWrite = instructionAt("0x8002");
		Instruction siblingWrite = instructionAt("0x8007");
		stripWriteReferences(prgWrite);
		stripWriteReferences(siblingWrite);
		assertNoWriteReference(prgWrite);
		assertNoWriteReference(siblingWrite);

		MemoryLatchBankSwitchStrategy strategy = latch(0x0FL, 0x08L);

		BankState latched = strategy.computeSwitch(program, prgWrite, BankState.unknown());
		assertNotNull("nibble-8 absolute write is this mechanism's register", latched);
		assertEquals(0x05, latched.bits());

		assertNull("nibble-0 write belongs to a sibling register, not the PRG latch",
			strategy.computeSwitch(program, siblingWrite, BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// GAP 2: write references living in an overlay space
	// ------------------------------------------------------------------

	/**
	 * A latch store executing from inside a bank overlay gets its write reference in that
	 * overlay's space, and it is the same physical bus address either way -- the reference tier
	 * must not require the default space.
	 * <p>
	 * An RMW store is used deliberately: it is exactly the case {@link
	 * MemoryLatchBankSwitchStrategy#operandStoresInRange} declines, so a pass here can only come
	 * from the reference tier and cannot be the operand tier answering for the wrong reason.
	 */
	@Test
	public void writeReferenceInOverlaySpaceLatches() throws Exception {
		MemoryBlock overlay = builder.createOverlayMemory("PRG_LO_B1", "0x8000", 0x4000);
		Address site = overlay.getStart();
		builder.setBytes(site.toString(), "ee 00 90", true); // INC $9000, from inside the overlay

		Instruction store = program.getListing().getInstructionAt(site);
		assertNotNull("nothing disassembled at " + site, store);

		Address overlayTarget = site.getAddressSpace().getAddress(0x9000);
		assertTrue("fixture must name the target in overlay space",
			overlayTarget.getAddressSpace().isOverlaySpace());
		addWriteReference(store, overlayTarget);

		BankState result = discreteLatch().computeSwitch(program, store, BankState.unknown());

		assertNotNull("overlay-space write reference was not seen as a mechanism write", result);
		assertEquals("an RMW store's value is not modelled", 0x00, result.knownMask());
	}

	/**
	 * The space test is a normalization, not a free-for-all: an in-range <em>offset</em> in a
	 * space that is not the code space (nor an overlay over it) still cannot latch. {@code OTHER}
	 * stands in for any such space -- it is where Ghidra parks addresses that have no place in
	 * the processor's memory map at all.
	 */
	@Test
	public void writeReferenceOutsideTheCodeSpaceDoesNotLatch() throws Exception {
		builder.setBytes("0x8000", "ee 00 90", true); // INC $9000

		Instruction store = instructionAt("0x8000");
		stripWriteReferences(store);

		AddressSpace other = program.getAddressFactory().getAddressSpace(AddressSpace.OTHER_SPACE
				.getName());
		assertNotNull("no OTHER space to model a foreign-space reference with", other);
		addWriteReference(store, other.getAddress(0x9000));

		assertNull("only the code space (or an overlay over it) carries the latch",
			discreteLatch().computeSwitch(program, store, BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// grm-hum GAP 1: an indexed access whose index register is a known constant
	// ------------------------------------------------------------------

	/**
	 * The load side: {@code LDA table,X} with X pinned to a constant reads one statically
	 * certain ROM byte, so the driven value is recoverable even though the operand is indexed.
	 */
	@Test
	public void resolvableIndexedLoadRecoversRomByte() throws Exception {
		builder.setBytes("0x9000", "00 01 02 07 04 05 06 03"); // bank table; $9003 = 0x07
		builder.setBytes("0x8000", "a2 03", true); // LDX #$03
		builder.setBytes("0x8002", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8005", "8d 00 c0", true); // STA $C000
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8005"), BankState.unknown());

		assertNotNull(result);
		assertEquals("index resolved -> $9003 is a statically known ROM byte", 0x0F,
			result.knownMask());
		assertEquals(0x07, result.bits());
	}

	/**
	 * Mega Man's actual {@code FUN_d846} index chain: {@code LDA #imm / STA zp / ASL A / TAX}.
	 * Exercises the accumulator-form {@code ASL}, the {@code TAX} transfer, and the recursion
	 * depth all at once.
	 */
	@Test
	public void megamanStyleAslChainResolvesIndex() throws Exception {
		builder.setBytes("0x9000", "00 01 02 03 06 05 04 07"); // $9004 = 0x06
		builder.setBytes("0x8000", "a9 02", true); // LDA #$02
		builder.setBytes("0x8002", "85 0c", true); // STA $0C   (irrelevant to A)
		builder.setBytes("0x8004", "0a", true); // ASL A     -> A = 4
		builder.setBytes("0x8005", "aa", true); // TAX       -> X = 4
		builder.setBytes("0x8006", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8009", "8d 00 c0", true); // STA $C000
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8009"), BankState.unknown());

		assertNotNull(result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(0x06, result.bits());
	}

	/**
	 * Mega Man (U) {@code FUN_d846} reproduced at its real addresses, <b>including its loop back
	 * edge</b> -- bytes transcribed from the ROM whose SHA-256 is pinned in
	 * {@code realrom/manifest.tsv}. It is a CHR upload loop: ten chunks, each preceded by a
	 * switch to that chunk's own bank, then bank 6 restored on the way out.
	 * <p>
	 * <b>Why the back edge is the entire point.</b> Without {@code BNE $D859} this fixture
	 * "resolves" the middle switch to bank 0 -- and that is exactly the mistake that produced a
	 * wrong verdict on this bead. Read straight-line, {@code LDA $D81E,X} looks like a constant
	 * read of {@code $D81E} with {@code X == 0}. With the loop present, {@code $D859} is a
	 * control-flow join, {@code X} is {@code 2 * counter}, and the site latches a DIFFERENT bank
	 * on each of ten iterations. The warning there is honest, and
	 * {@link StoredValueScanner}'s join guard declining is the correct answer, not a gap.
	 * <p>
	 * So this test pins two things at once: GAP 1 must not over-reach into a loop-carried index
	 * ({@code $D861} stays unknown), and the site that decides the helper's post-call state is
	 * the LAST one ({@code $D88D} -> bank 6), which is what {@code BoardBankAnalyzer.findHelpers}
	 * selects with its max-address {@code switchSite} rule.
	 */
	@Test
	public void megamanFunD846LoopCarriedIndexStaysUnknown() throws Exception {
		layMegamanFunD846();

		MemoryLatchBankSwitchStrategy latch = busConflictLatch();

		BankState first = latch.computeSwitch(program, instructionAt("0xd84a"), BankState.unknown());
		assertNotNull("STA $C006 is a mechanism write", first);
		assertEquals("switch #1 is a plain immediate", 0x0F, first.knownMask());
		assertEquals(0x06, first.bits());

		BankState looped =
			latch.computeSwitch(program, instructionAt("0xd861"), BankState.unknown());
		assertNotNull("STA $C000,Y is a mechanism write (tier-2 operand decode)", looped);
		assertEquals("loop-carried index must NOT resolve -- $D859 is a control-flow join", 0x00,
			looped.knownMask());

		BankState last = latch.computeSwitch(program, instructionAt("0xd88d"), BankState.unknown());
		assertNotNull(last);
		assertEquals("the post-loop restore is what the helper actually leaves behind", 0x0F,
			last.knownMask());
		assertEquals(0x06, last.bits());
	}

	/**
	 * The {@code FUN_d846} bytes, shared by the tests above and below so the transcription --
	 * back edge included -- exists exactly once.
	 */
	private void layMegamanFunD846() throws Exception {
		builder.setBytes("0xc000", "00 01 02 03 04 05 06 07"); // UxROM bank table
		builder.setBytes("0xd81e", "00 02 00 02 00 02 00 01"); // per-chunk bank/count table
		builder.setBytes("0xd846", "a9 06", true); // LDA #$06
		builder.setBytes("0xd848", "85 42", true); // STA $42       (bank shadow)
		builder.setBytes("0xd84a", "8d 06 c0", true); // STA $C006  <- switch #1 -> bank 6
		builder.setBytes("0xd84d", "a9 00", true); // LDA #$00
		builder.setBytes("0xd84f", "8d 06 20", true); // STA $2006  (PPU, not in latch range)
		builder.setBytes("0xd852", "8d 06 20", true); // STA $2006
		builder.setBytes("0xd855", "a9 00", true); // LDA #$00
		builder.setBytes("0xd857", "85 0c", true); // STA $0C       (chunk counter)
		builder.setBytes("0xd859", "0a", true); // ASL A            <- LOOP HEAD
		builder.setBytes("0xd85a", "aa", true); // TAX              X = 2 * counter
		builder.setBytes("0xd85b", "bd 1e d8", true); // LDA $D81E,X  per-chunk bank
		builder.setBytes("0xd85e", "a8", true); // TAY
		builder.setBytes("0xd85f", "85 42", true); // STA $42
		builder.setBytes("0xd861", "99 00 c0", true); // STA $C000,Y <- switch #2, LOOP-CARRIED
		builder.setBytes("0xd881", "e6 0c", true); // INC $0C
		builder.setBytes("0xd883", "a5 0c", true); // LDA $0C
		builder.setBytes("0xd885", "c9 0a", true); // CMP #$0A
		builder.setBytes("0xd887", "d0 d0", true); // BNE $D859     <- the back edge
		builder.setBytes("0xd889", "a9 06", true); // LDA #$06
		builder.setBytes("0xd88b", "85 42", true); // STA $42
		builder.setBytes("0xd88d", "8d 06 c0", true); // STA $C006  <- switch #3 -> bank 6
		romifyPrg();
	}

	/** {@code DEX} in the index chain: the index arithmetic is modeled, not just transfers. */
	@Test
	public void decrementInIndexChainResolves() throws Exception {
		builder.setBytes("0x9000", "00 01 02 07 04 05 06 03"); // $9003 = 0x07
		builder.setBytes("0x8000", "a2 04", true); // LDX #$04
		builder.setBytes("0x8002", "ca", true); // DEX -> X = 3
		builder.setBytes("0x8003", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8006", "8d 00 c0", true); // STA $C000
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8006"), BankState.unknown());

		assertNotNull(result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(0x07, result.bits());
	}

	/** {@code AND #imm} on A ahead of the transfer: the immediate ALU ops are modeled too. */
	@Test
	public void immediateAndInIndexChainResolves() throws Exception {
		builder.setBytes("0x9000", "00 01 02 07 04 05 06 03"); // $9003 = 0x07
		builder.setBytes("0x8000", "a9 fb", true); // LDA #$FB
		builder.setBytes("0x8002", "29 07", true); // AND #$07 -> A = 3
		builder.setBytes("0x8004", "aa", true); // TAX
		builder.setBytes("0x8005", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8008", "8d 00 c0", true); // STA $C000
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8008"), BankState.unknown());

		assertNotNull(result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(0x07, result.bits());
	}

	/**
	 * An index that comes from RAM is not statically known, so the effective address is not
	 * either. The point is that it <em>declines</em> cleanly rather than guessing a base.
	 */
	@Test
	public void unresolvableIndexDeclines() throws Exception {
		builder.setBytes("0x9000", "07 01 02 03 04 05 06 07"); // $9000 = 0x07, the naive answer
		builder.setBytes("0x8000", "a5 00", true); // LDA $00 -- from writable zero page
		builder.setBytes("0x8002", "aa", true); // TAX
		builder.setBytes("0x8003", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8006", "8d 00 c0", true); // STA $C000
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8006"), BankState.unknown());

		assertNotNull(result);
		assertEquals("an unknown index must yield no bits, not the base's byte", 0x00,
			result.knownMask());
	}

	/**
	 * The store side: with the index resolved, an indexed bus-conflict store has a static
	 * target after all, so the driven value is ANDed with that target's ROM byte -- the claim
	 * the class javadoc used to deny outright.
	 */
	@Test
	public void indexedBusConflictStoreAppliesTheRomAnd() throws Exception {
		builder.setBytes("0xffd0", "00 01 02 03 04 05 06 07 08 09"); // $FFD9 = 0x09
		builder.setBytes("0x8000", "a9 09", true); // LDA #$09
		builder.setBytes("0x8002", "aa", true); // TAX
		builder.setBytes("0x8003", "9d d0 ff", true); // STA $FFD0,X -> $FFD9
		romifyPrg();

		Instruction store = instructionAt("0x8003");
		assertNoWriteReference(store);

		BankState result = busConflictLatch().computeSwitch(program, store, BankState.unknown());

		assertNotNull(result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(0x09, result.bits());
	}

	/**
	 * The Mega Man shape, and the reason GAP 1 is worth closing: the CPU-driven value is
	 * genuinely unrecoverable (it comes from RAM), yet the resolved store target's ROM byte is
	 * {@code 0x00}, and on a bus-conflict board every 0 bit of the ROM byte is a <em>known</em>
	 * 0 in the latched value whatever the CPU drove. The AND alone therefore pins the bank.
	 */
	@Test
	public void indexedBusConflictAndPinsBankWhenDrivenValueIsUnknown() throws Exception {
		builder.setBytes("0xc000", "ff ff ff ff ff 00"); // $C005 = 0x00
		builder.setBytes("0x8000", "a0 05", true); // LDY #$05
		builder.setBytes("0x8002", "a5 10", true); // LDA $10 -- RAM, unrecoverable
		builder.setBytes("0x8004", "99 00 c0", true); // STA $C000,Y -> $C005
		romifyPrg();

		BankState result =
			busConflictLatch().computeSwitch(program, instructionAt("0x8004"), BankState.unknown());

		assertNotNull(result);
		assertEquals("ROM byte 0x00 forces every field bit to a known 0", 0x0F,
			result.knownMask());
		assertEquals(0x00, result.bits());
	}

	/**
	 * Zero-page indexed must decline: {@code $80,X} with {@code X == $FF} wraps inside the zero
	 * page to {@code $7F}, it does not reach {@code $017F}. The fixture puts a resolvable ROM
	 * byte at exactly that wrong address, so a naive {@code base + index} would produce a
	 * confident falsehood rather than merely a miss.
	 */
	@Test
	public void zeroPageIndexedLoadDeclines() throws Exception {
		MemoryBlock ro = builder.createMemory("RO", "0x100", 0x100);
		builder.setBytes("0x017f", "0b"); // the non-existent "$0080 + $FF"
		builder.setBytes("0x8000", "a2 ff", true); // LDX #$FF
		builder.setBytes("0x8002", "b5 80", true); // LDA $80,X -- wraps to $7F
		builder.setBytes("0x8004", "8d 00 c0", true); // STA $C000
		romifyPrg();
		makeReadOnly(ro);

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8004"), BankState.unknown());

		assertNotNull(result);
		assertEquals("zp,X wraps in page zero -- must not resolve to $017F", 0x00,
			result.knownMask());
	}

	/** {@code (zp),Y} reads through a pointer this scanner does not model, so it declines. */
	@Test
	public void indirectIndexedLoadDeclines() throws Exception {
		builder.setBytes("0x0080", "00 90"); // pointer -> $9000
		builder.setBytes("0x9000", "07 01 02 03 04 05 06 07");
		builder.setBytes("0x8000", "a0 00", true); // LDY #$00
		builder.setBytes("0x8002", "b1 80", true); // LDA ($80),Y
		builder.setBytes("0x8004", "8d 00 c0", true); // STA $C000
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8004"), BankState.unknown());

		assertNotNull(result);
		assertEquals("(zp),Y is an unmodeled pointer read, not a base+index", 0x00,
			result.knownMask());
	}

	/**
	 * <b>INVARIANT: the mid-scan mechanism-write abort is not relaxed for index resolution.</b>
	 * The intervening {@code STA $8000} latches the bank, so anything read further back
	 * predates it and cannot be attributed to the state at the second store. The index chain
	 * must abort on it exactly as the value chain does.
	 * <p>
	 * Do not "fix" a future failure here by letting the index walk past a mechanism write --
	 * that is the one relaxation grm-hum explicitly forbids. The fixture makes the cost of
	 * getting it wrong visible: {@code $9001} holds a perfectly resolvable {@code 0x06}.
	 */
	@Test
	public void mechanismWriteMidScanAbortsIndexResolution() throws Exception {
		builder.setBytes("0x9000", "00 06 02 03 04 05 06 07"); // $9001 = 0x06
		builder.setBytes("0x8000", "a2 01", true); // LDX #$01
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000 -- a latch write
		builder.setBytes("0x8005", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8008", "8d 00 80", true); // STA $8000 -- the store under test
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8008"), BankState.unknown());

		assertNotNull(result);
		assertEquals("index resolution must abort at an intervening mechanism write", 0x00,
			result.knownMask());
	}

	/** A join between the load and the store forfeits the fold, as it always has. */
	@Test
	public void controlFlowJoinBeforeStoreDeclines() throws Exception {
		builder.setBytes("0x9000", "00 01 02 07 04 05 06 03"); // $9003 = 0x07
		builder.setBytes("0x8000", "a2 03", true); // LDX #$03
		builder.setBytes("0x8002", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8005", "8d 00 c0", true); // STA $C000 -- also a branch target
		builder.setBytes("0x8008", "b0 fb", true); // BCS $8005

		Instruction store = instructionAt("0x8005");
		assertTrue("fixture must actually create the join",
			program.getReferenceManager().getReferenceCountTo(store.getMinAddress()) > 0);
		romifyPrg();

		BankState result = discreteLatch().computeSwitch(program, store, BankState.unknown());

		assertNotNull(result);
		assertEquals(0x00, result.knownMask());
	}

	/** The same guard inside the index chain: a join before the load forfeits the index too. */
	@Test
	public void controlFlowJoinInIndexChainDeclines() throws Exception {
		builder.setBytes("0x9000", "00 01 02 07 04 05 06 03"); // $9003 = 0x07
		builder.setBytes("0x8000", "a2 03", true); // LDX #$03
		builder.setBytes("0x8002", "bd 00 90", true); // LDA $9000,X -- also a branch target
		builder.setBytes("0x8005", "8d 00 c0", true); // STA $C000
		builder.setBytes("0x8008", "b0 f8", true); // BCS $8002

		assertTrue("fixture must actually create the join", program.getReferenceManager()
				.getReferenceCountTo(builder.addr("0x8002")) > 0);
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8005"), BankState.unknown());

		assertNotNull(result);
		assertEquals("X's value on the branching path is not known", 0x00, result.knownMask());
	}

	/**
	 * {@code ROL}/{@code ROR} rotate through the carry flag, which nothing in this scanner
	 * models. Declining is the point: treating {@code ROL A} as {@code ASL A} would give
	 * {@code X = 8} here and confidently recover {@code $9008}'s {@code 0x0E}.
	 */
	@Test
	public void rotateInIndexChainDeclines() throws Exception {
		builder.setBytes("0x9000", "00 01 02 03 04 05 06 07 0e"); // $9008 = 0x0E
		builder.setBytes("0x8000", "a9 04", true); // LDA #$04
		builder.setBytes("0x8002", "2a", true); // ROL A -- carry unknown
		builder.setBytes("0x8003", "aa", true); // TAX
		builder.setBytes("0x8004", "bd 00 90", true); // LDA $9000,X
		builder.setBytes("0x8007", "8d 00 c0", true); // STA $C000
		romifyPrg();

		BankState result =
			discreteLatch().computeSwitch(program, instructionAt("0x8007"), BankState.unknown());

		assertNotNull(result);
		assertEquals("ROL's carry bit is unmodeled -- decline, do not guess", 0x00,
			result.knownMask());
	}

	/**
	 * The {@link MemoryLatchBankSwitchStrategy#cacheable()} contract: {@code computeSwitch} is a
	 * pure function of {@code (program, instr)}, so two different in-states must give the same
	 * answer. {@code BoardBankAnalyzer}'s {@code matchCache} is keyed by address alone and
	 * relies on it -- including for the paths GAP 1 newly resolves.
	 */
	@Test
	public void computeSwitchIsIndependentOfInState() throws Exception {
		builder.setBytes("0xffd0", "00 01 02 03 04 05 06 07 08 09"); // $FFD9 = 0x09
		builder.setBytes("0x8000", "a9 09", true); // LDA #$09
		builder.setBytes("0x8002", "aa", true); // TAX
		builder.setBytes("0x8003", "9d d0 ff", true); // STA $FFD0,X
		romifyPrg();

		MemoryLatchBankSwitchStrategy strategy = busConflictLatch();
		Instruction store = instructionAt("0x8003");

		BankState fromUnknown = strategy.computeSwitch(program, store, BankState.unknown());
		BankState fromKnown =
			strategy.computeSwitch(program, store, BankState.fullyKnown(0x0F, 0x02));

		assertTrue("cacheable() promises a state-independent result", strategy.cacheable());
		assertEquals(fromUnknown, fromKnown);
	}

	// ------------------------------------------------------------------
	// grm-hum GAP 2: mini-inlining a helper under one call site's registers
	// ------------------------------------------------------------------

	/**
	 * Contra's helper, at its real addresses and with its real bank table. The bank argument
	 * arrives in <b>Y</b>; the mechanism write is an {@code STA}, so {@code findHelpers} can
	 * only ever record {@code A} as the argument register -- which is exactly why the recovery
	 * has to re-evaluate the switch site under all of A/X/Y rather than chase one nominated
	 * register.
	 *
	 * <pre>
	 * $FFD0: 00 01 02 03 04 05 06 07
	 * C13D: LDY #$07        &lt;- NOT part of the helper; the trap for walking past the entry
	 * C13F: LDA $FFD0,Y     &lt;- helper entry
	 * C142: STA $FFD0,Y     &lt;- the mechanism write
	 * C145: RTS
	 * </pre>
	 *
	 * The {@code LDY #$07} sitting immediately before the entry, falling through into it, is
	 * deliberate: {@code $FFD7} holds a perfectly resolvable {@code 0x07}, so a scan that walks
	 * past the entry produces a confident wrong answer rather than a miss.
	 */
	private void layContraHelper() throws Exception {
		builder.setBytes("0xffd0", "00 01 02 03 04 05 06 07"); // the real Contra bank table
		builder.setBytes("0xc13d", "a0 07", true); // LDY #$07 -- the caller-of-nobody trap
		builder.setBytes("0xc13f", "b9 d0 ff", true); // LDA $FFD0,Y  <- entry
		builder.setBytes("0xc142", "99 d0 ff", true); // STA $FFD0,Y  <- switch site
		builder.setBytes("0xc145", "60", true); // RTS
		romifyPrg();
	}

	/** The helper entry, and the switch site the engine would mini-inline. */
	private Address contraEntry() {
		return builder.addr("0xc13f");
	}

	private RegisterEnv envAt(Address entry, BankState y) {
		return new RegisterEnv(entry, BankState.unknown(), BankState.unknown(), y);
	}

	/**
	 * The headline case: a call site that puts {@code $02} in Y reaches bank 2, recovered by
	 * re-running the latch's own semantics at the switch site with the caller's Y supplied at
	 * the entry. Nothing here nominates Y as "the argument register" -- the backward scan is
	 * demand-driven and simply asks for whatever the indexed operand needs.
	 */
	@Test
	public void helperMiniInlineResolvesArgumentArrivingInY() throws Exception {
		layContraHelper();

		BankSwitchStrategy.HelperDeposit deposit = busConflictLatch().depositHelperArgument(program,
			instructionAt("0xc142"), BankState.unknown(), BankState.unknown(), 0x0F,
			envAt(contraEntry(), BankState.fullyKnown(0xFF, 0x02)));

		assertEquals("a memory-latch call replaces this mechanism's whole field", 0x0F,
			deposit.ownedMask());
		assertEquals(0x0F, deposit.value().knownMask());
		assertEquals("$FFD0 + Y=2 is the table's bank 2", 0x02, deposit.value().bits());
	}

	/**
	 * The honest half. Contra's other three call sites take their bank out of a RAM save slot
	 * or off the CPU stack, so Y is genuinely not statically known -- and an unknown Y must
	 * stay unresolved, not fall back to the table's base entry (which would answer {@code 0}
	 * with full confidence). This is the property the synthetic fixture's U3 criterion guards
	 * at the whole-analyzer level.
	 */
	@Test
	public void helperMiniInlineWithUnknownArgumentStaysUnknown() throws Exception {
		layContraHelper();

		BankSwitchStrategy.HelperDeposit deposit =
			busConflictLatch().depositHelperArgument(program, instructionAt("0xc142"),
				BankState.unknown(), BankState.unknown(), 0x0F,
				envAt(contraEntry(), BankState.unknown()));

		assertEquals("the call still writes the field -- it is owned, just unresolved", 0x0F,
			deposit.ownedMask());
		assertEquals("an unknown argument must not resolve to the table base", 0x00,
			deposit.value().knownMask());
	}

	/**
	 * <b>INVARIANT: the scan does not walk past the helper entry.</b> The instruction physically
	 * preceding a function's entry is not its predecessor -- it belongs to whatever code the
	 * assembler happened to place before it -- so adopting its register values would be exactly
	 * the "any nearby {@code LD<reg> #imm} will do" guess this bead exists to eliminate.
	 * <p>
	 * The fixture makes the difference observable both ways: with no entry stop at all
	 * ({@code computeSwitch}, {@link RegisterEnv#NONE}) the walk really does reach
	 * {@code LDY #$07} and confidently reports bank 7, while an entry-stopped query with nothing
	 * known about Y must report nothing. If a future change makes the second assertion produce
	 * {@code 7}, the entry stop has been lost.
	 */
	@Test
	public void helperMiniInlineDoesNotWalkPastTheEntry() throws Exception {
		layContraHelper();

		MemoryLatchBankSwitchStrategy latch = busConflictLatch();
		Instruction switchSite = instructionAt("0xc142");

		BankState noEntryStop = latch.computeSwitch(program, switchSite, BankState.unknown());
		assertNotNull(noEntryStop);
		assertEquals("fixture must actually be walkable, or the test proves nothing", 0x0F,
			noEntryStop.knownMask());
		assertEquals(0x07, noEntryStop.bits());

		BankSwitchStrategy.HelperDeposit deposit = latch.depositHelperArgument(program, switchSite,
			BankState.unknown(), BankState.unknown(), 0x0F,
			envAt(contraEntry(), BankState.unknown()));

		assertEquals("must stop at the entry, not adopt the LDY #$07 that precedes it", 0x00,
			deposit.value().knownMask());
	}

	/**
	 * The mini-inline gets its one argued exception to the control-flow-join refusal at the
	 * <em>entry</em> only (there the "other paths in" are other call sites, which is precisely
	 * what the environment answers for). A join <em>inside</em> the helper, between the switch
	 * site and the entry, is an ordinary join and must still decline: the register values on the
	 * branching path are not the caller's.
	 *
	 * <pre>
	 * C150: LDA $FFD0,Y   &lt;- entry
	 * C153: NOP           &lt;- branch target: an INTERNAL join
	 * C154: STA $FFD0,Y   &lt;- switch site
	 * C157: RTS
	 * C158: BCS $C153
	 * </pre>
	 */
	@Test
	public void helperMiniInlineDeclinesAtAnInternalJoin() throws Exception {
		builder.setBytes("0xffd0", "00 01 02 03 04 05 06 07");
		builder.setBytes("0xc150", "b9 d0 ff", true); // LDA $FFD0,Y  <- entry
		builder.setBytes("0xc153", "ea", true); // NOP -- the join
		builder.setBytes("0xc154", "99 d0 ff", true); // STA $FFD0,Y  <- switch site
		builder.setBytes("0xc157", "60", true); // RTS
		builder.setBytes("0xc158", "b0 f9", true); // BCS $C153
		romifyPrg();

		assertTrue("fixture must actually create the internal join",
			program.getReferenceManager().getReferenceCountTo(builder.addr("0xc153")) > 0);

		BankSwitchStrategy.HelperDeposit deposit = busConflictLatch().depositHelperArgument(program,
			instructionAt("0xc154"), BankState.unknown(), BankState.unknown(), 0x0F,
			envAt(builder.addr("0xc150"), BankState.fullyKnown(0xFF, 0x02)));

		assertEquals("an internal join must not be mini-inlined past", 0x00,
			deposit.value().knownMask());
	}

	/**
	 * Mega Man's {@code FUN_d846} through the helper path, which is what restores the ~78
	 * overlay references grm-3x1 cost. {@code findHelpers} keeps the max-address switch site
	 * ({@code $D88D}, the post-loop restore) and drops {@code constState} to null because the
	 * three sites disagree (6 / unknown / 6), so every call is recovered individually -- and
	 * mini-inlining {@code $D88D} finds {@code LDA #$06} two instructions back, entirely
	 * independent of the caller. Asserted under two different environments precisely to pin
	 * that independence: this helper's post-call state is a fact about the helper.
	 */
	@Test
	public void megamanFunD846MiniInlinesToBankSixWhateverTheCaller() throws Exception {
		layMegamanFunD846();

		MemoryLatchBankSwitchStrategy latch = busConflictLatch();
		Instruction restoreSite = instructionAt("0xd88d");
		Address entry = builder.addr("0xd846");

		BankSwitchStrategy.HelperDeposit blind = latch.depositHelperArgument(program, restoreSite,
			BankState.unknown(), BankState.unknown(), 0x0F, envAt(entry, BankState.unknown()));
		BankSwitchStrategy.HelperDeposit seeded = latch.depositHelperArgument(program, restoreSite,
			BankState.unknown(), BankState.unknown(), 0x0F,
			envAt(entry, BankState.fullyKnown(0xFF, 0x03)));

		assertEquals(0x0F, blind.ownedMask());
		assertEquals(0x0F, blind.value().knownMask());
		assertEquals("the restore is an immediate -- bank 6, caller-independent", 0x06,
			blind.value().bits());
		assertEquals(blind, seeded);
	}

	/**
	 * {@code argValue} is ignored by this strategy's override, and must be: the argument
	 * register {@code findHelpers} nominates is the one the {@code STA} stores, which on the
	 * Contra shape is A -- a register that has nothing to do with the bank. Feeding a wrong,
	 * fully-confident {@code argValue} must not change the answer.
	 */
	@Test
	public void helperMiniInlineIgnoresTheNominatedArgumentValue() throws Exception {
		layContraHelper();

		MemoryLatchBankSwitchStrategy latch = busConflictLatch();
		RegisterEnv env = envAt(contraEntry(), BankState.fullyKnown(0xFF, 0x02));

		BankSwitchStrategy.HelperDeposit fromUnknownArg = latch.depositHelperArgument(program,
			instructionAt("0xc142"), BankState.unknown(), BankState.unknown(), 0x0F, env);
		BankSwitchStrategy.HelperDeposit fromMisleadingArg = latch.depositHelperArgument(program,
			instructionAt("0xc142"), BankState.fullyKnown(0x0F, 0x0D), BankState.unknown(), 0x0F,
			env);

		assertEquals(0x02, fromUnknownArg.value().bits());
		assertEquals("the evaluated switch semantics win over the register convention",
			fromUnknownArg, fromMisleadingArg);
	}

	// ------------------------------------------------------------------
	// Increment 3: the impossible-bank guard
	// ------------------------------------------------------------------

	/**
	 * Lays a 4-bank UxROM image's overlay spaces: bank 0 is home (base space, no overlay of its
	 * own), banks 1-3 each get a {@code PRG_LO_B<n>} overlay -- the naming contract
	 * {@link DescriptorSupport.OverlayNaming} defines and the loader realizes. Bank 9's block is
	 * pointedly absent, because "bank values beyond the image simply don't exist".
	 */
	private void layFourBankOverlays() {
		for (int bank = 1; bank <= 3; bank++) {
			builder.createOverlayMemory("PRG_LO_B" + bank, "0x8000", 0x4000);
		}
	}

	/**
	 * An out-of-range immediate: {@code LDA #$09 / STA $FFD9} on an image with four banks. The
	 * store target's ROM byte is {@code 0x09} on purpose, so the bus-conflict AND is a faithful
	 * no-op and the recovered value is one the hardware really would have latched -- the guard
	 * has to fire on that, not on a value the AND had already laundered into a legal bank.
	 * <p>
	 * Recovery itself is working correctly here; the bank index is simply impossible, which is
	 * a value-recovery bug rather than a game behavior. Tier 3 ({@code nesuxhelpertest} U8) pins
	 * the resulting WARNING-instead-of-annotation end to end; this pins the two halves the
	 * analyzer joins -- that recovery does produce 9, and that 9 is not in the image's realized
	 * bank set.
	 */
	@Test
	public void outOfRangeRecoveredBankIsNotRealizedByTheImage() throws Exception {
		builder.setBytes("0xffd0", "00 01 02 03 04 05 06 07 08 09"); // $FFD9 = 0x09
		builder.setBytes("0x8000", "a9 09", true); // LDA #$09
		builder.setBytes("0x8002", "8d d9 ff", true); // STA $FFD9
		romifyPrg();
		layFourBankOverlays();

		Instruction store = instructionAt("0x8002");
		stripWriteReferences(store);

		BankState result = busConflictLatch().computeSwitch(program, store, BankState.unknown());

		assertNotNull(result);
		assertEquals("the AND against ROM byte 0x09 leaves the driven 9 intact", 0x0F,
			result.knownMask());
		assertEquals(0x09, result.bits());

		java.util.Set<Integer> realized =
			BoardBankAnalyzer.realizedBanks(program, "PRG_LO", 0);
		assertEquals("home bank 0 in base space plus overlays for 1-3", 4, realized.size());
		assertFalse("bank 9 has no image slice, so it must not pass for an occupant",
			realized.contains(result.bits()));
	}

	/**
	 * The other half of the same guard: an in-range recovered bank must still be accepted, or
	 * the tripwire would suppress every annotation instead of the wrong ones.
	 */
	@Test
	public void inRangeRecoveredBankIsRealizedByTheImage() throws Exception {
		builder.setBytes("0xffd0", "00 01 02 03");
		builder.setBytes("0x8000", "a9 02", true); // LDA #$02
		builder.setBytes("0x8002", "8d d2 ff", true); // STA $FFD2
		romifyPrg();
		layFourBankOverlays();

		Instruction store = instructionAt("0x8002");
		stripWriteReferences(store);

		BankState result = busConflictLatch().computeSwitch(program, store, BankState.unknown());

		assertNotNull(result);
		assertEquals(0x02, result.bits());
		assertTrue("bank 2 is realized as the PRG_LO_B2 overlay",
			BoardBankAnalyzer.realizedBanks(program, "PRG_LO", 0).contains(result.bits()));
	}

	/**
	 * The home bank is realized in BASE space, not as a {@code PRG_LO_B0} overlay, so it has to
	 * be added from the descriptor's {@code initial_state} rather than discovered by scanning
	 * spaces. Missing that would make every home-bank annotation warn.
	 */
	@Test
	public void homeBankCountsAsRealizedEvenWithNoOverlayOfItsOwn() throws Exception {
		layFourBankOverlays();

		assertTrue("home bank lives in base space",
			BoardBankAnalyzer.realizedBanks(program, "PRG_LO", 0).contains(0));
		assertFalse("a differently-named window's overlays are not this window's banks",
			BoardBankAnalyzer.realizedBanks(program, "PRG_HI", 3).contains(1));
	}
}
