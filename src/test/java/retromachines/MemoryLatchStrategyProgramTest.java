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

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/** A discrete-mapper latch over the whole ROM area, no address-decode predicate. */
	private MemoryLatchBankSwitchStrategy discreteLatch() {
		return latch(null, null);
	}

	/**
	 * A latch configured like Bandai FCG when {@code addrMask != null}: the PRG bank register
	 * is the nibble-8 mirror, every other nibble in range is a sibling register.
	 */
	private MemoryLatchBankSwitchStrategy latch(Long addrMask, Long addrMatch) {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x0F);
		if (addrMask != null) {
			params.addProperty("addr_mask", addrMask);
			params.addProperty("addr_match", addrMatch);
		}
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0xFF);
		return strategy;
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
}
