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
import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Pins {@code BankAnnotationAdapter.nameBankMirrors} (bead grm-mej.4): turning the {@link
 * BankMirrors} set grm-mej.2 derives into actual symbols and comments -- "the documentary payoff,
 * arguably the point" of the whole mirror-derivation effort, and until this bead nothing did it.
 * <p>
 * Mirror sets here are stated outright via the package-private {@link BankMirrors#of}, the same
 * route {@link BankMirrorConsumptionProgramTest} uses for the same reason: this file is about the
 * LABELLING rule ("given this kind set at this offset, what symbol/comment results"), not about
 * how a kind set was discovered -- that is {@link BankMirrorDerivationProgramTest}'s concern.
 * {@link #evidenceAddressesAppearInTheCommentSortedByOffset} is the one exception, because the
 * evidence-site text it pins comes only from a real {@link BankMirrors.Discovery} build.
 */
public class BankMirrorNamingProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace baseSpace;
	private Listing listing;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		listing = program.getListing();

		// ProgramBuilder blocks are created read-only (BankMirrorConsumptionProgramTest's own
		// fixture note); the write-through derivation test below needs $42 to be writable RAM,
		// or Discovery.writableCellOffset refuses it before it ever becomes evidence.
		int tx = program.startTransaction("make zero page writable");
		try {
			zp.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/** States a mirror set outright -- see {@link BankMirrors#of}'s javadoc for why this route
	 *  is the right one for a labelling-rule test rather than a derivation one. */
	private BankMirrors mirrorsOf(long offset, BankMirrors.Kind... kinds) {
		return BankMirrors.of(baseSpace, Map.of(offset, Set.of(kinds)));
	}

	private void name(BankMirrors mirrors) {
		int tx = program.startTransaction("name bank mirrors");
		try {
			BankAnnotationAdapter.nameBankMirrors(program, listing, mirrors, baseSpace);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Symbol primarySymbol(long offset) {
		return program.getSymbolTable().getPrimarySymbol(baseSpace.getAddress(offset));
	}

	private String eolComment(long offset) {
		return listing.getComment(CommentType.EOL, baseSpace.getAddress(offset));
	}

	// ------------------------------------------------------------------
	// 1. One name per kind
	// ------------------------------------------------------------------

	/** {@code WRITE_THROUGH} names {@code bank_shadow_<offset>}, per the kind's meaning: it
	 *  tracks the live bank by construction. */
	@Test
	public void writeThroughMirrorGetsABankShadowName() throws Exception {
		name(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		Symbol sym = primarySymbol(0x42);
		assertNotNull("nameBankMirrors must label a WRITE_THROUGH cell", sym);
		assertEquals("bank_shadow_0042", sym.getName());
		assertEquals("analyzer-derived, never USER_DEFINED", SourceType.ANALYSIS, sym.getSource());
	}

	/** {@code SAVE_SLOT} names {@code bank_saved_<offset>}: it holds a stashed OLD bank, not the
	 *  live one. */
	@Test
	public void saveSlotMirrorGetsABankSavedName() throws Exception {
		name(mirrorsOf(0x59, BankMirrors.Kind.SAVE_SLOT));

		Symbol sym = primarySymbol(0x59);
		assertNotNull(sym);
		assertEquals("bank_saved_0059", sym.getName());
	}

	/** {@code INPUT} names {@code bank_request_<offset>}: it holds the bank a caller is ASKING
	 *  for, live only once the wrapper runs. */
	@Test
	public void inputMirrorGetsABankRequestName() throws Exception {
		name(mirrorsOf(0xD3, BankMirrors.Kind.INPUT));

		Symbol sym = primarySymbol(0xD3);
		assertNotNull(sym);
		assertEquals("bank_request_00d3", sym.getName());
	}

	/** {@code ROM_IDENTIFYING} names {@code bank_id_<offset>}: a cartridge convention byte that
	 *  identifies its own bank, read as an API by e.g. TMNT's {@code cec0}. */
	@Test
	public void romIdentifyingMirrorGetsABankIdName() throws Exception {
		name(mirrorsOf(0x8000, BankMirrors.Kind.ROM_IDENTIFYING));

		Symbol sym = primarySymbol(0x8000);
		assertNotNull(sym);
		assertEquals("bank_id_8000", sym.getName());
	}

	// ------------------------------------------------------------------
	// 2. The offset suffix is unconditional
	// ------------------------------------------------------------------

	/** Two WRITE_THROUGH cells (Blaster Master's shape: {@code $DB} and {@code $D3}) get two
	 *  DISTINCT names, both carrying their own offset -- the suffix is not collision-triggered,
	 *  so the result cannot depend on which cell discovery happened to find first. */
	@Test
	public void twoCellsOfTheSameKindGetDistinctNames() throws Exception {
		BankMirrors mirrors = BankMirrors.of(baseSpace, Map.of(
			0xDBL, Set.of(BankMirrors.Kind.WRITE_THROUGH),
			0xD3L, Set.of(BankMirrors.Kind.WRITE_THROUGH)));
		name(mirrors);

		assertEquals("bank_shadow_00db", primarySymbol(0xDB).getName());
		assertEquals("bank_shadow_00d3", primarySymbol(0xD3).getName());
	}

	// ------------------------------------------------------------------
	// 3. Multi-kind precedence
	// ------------------------------------------------------------------

	/**
	 * A cell carrying both {@code INPUT} and {@code SAVE_SLOT} (Blaster Master's {@code $D3}, a
	 * bank REQUEST at three sites and a SAVE SLOT at two others) gets named for {@code SAVE_SLOT}
	 * -- the higher-precedence kind, because the two kinds that hold a bank deliberately NOT the
	 * live one win the name: a cell that looks like a live shadow and is not is exactly the trap
	 * this labelling exists to flag. The comment must still list BOTH kinds, so the INPUT role is
	 * not silently lost to the one-name-per-address limit.
	 */
	@Test
	public void multiKindCellIsNamedBySaveSlotPrecedenceButCommentListsBothKinds()
			throws Exception {
		name(mirrorsOf(0xD3, BankMirrors.Kind.INPUT, BankMirrors.Kind.SAVE_SLOT));

		Symbol sym = primarySymbol(0xD3);
		assertNotNull(sym);
		assertEquals("SAVE_SLOT must win the name over INPUT", "bank_saved_00d3", sym.getName());

		String comment = eolComment(0xD3);
		assertNotNull(comment);
		assertTrue("the comment must still list INPUT even though it lost the name",
			comment.contains("INPUT"));
		assertTrue("the comment must still list SAVE_SLOT", comment.contains("SAVE_SLOT"));
	}

	// ------------------------------------------------------------------
	// 4. The forbidden substring
	// ------------------------------------------------------------------

	/**
	 * <b>THE ONE TRAP.</b> Both golden dumps ({@code VerifyBankTest}, {@code RealRomDump}) count
	 * EOL comments containing the literal {@code "bank ->"} as {@code bankComments} -- the
	 * vocabulary {@code annotateBankSwitch}/{@code annotatePlacementProvenance} use for
	 * switch-value provenance. A mirror comment must never trip that counter, or it inflates a
	 * metric two other beads reason against. Checked against both a bare cell and one with
	 * evidence sites, since the evidence clause is where free-form text is most likely to drift
	 * into the forbidden phrase by accident.
	 */
	@Test
	public void mirrorCommentNeverContainsTheBankArrowSubstring() throws Exception {
		BankMirrors mirrors = BankMirrors.of(baseSpace, Map.of(
			0x42L, Set.of(BankMirrors.Kind.WRITE_THROUGH),
			0xD3L, Set.of(BankMirrors.Kind.INPUT, BankMirrors.Kind.SAVE_SLOT)));
		name(mirrors);

		assertFalse("bare-cell comment must not contain 'bank ->'",
			eolComment(0x42).contains("bank ->"));
		assertFalse("multi-kind comment must not contain 'bank ->'",
			eolComment(0xD3).contains("bank ->"));
	}

	// ------------------------------------------------------------------
	// 5. Evidence sites in the comment
	// ------------------------------------------------------------------

	/**
	 * With a REAL derivation (not a stated-outright {@link BankMirrors#of} set), the comment
	 * names the instructions that established the cell -- the "how do you know" record grm-mej.4
	 * exists to surface. Two write-through shadow sites at {@code $8000} and {@code $9000} (the
	 * same two-site corroboration shape {@code BankMirrorConsumptionProgramTest} uses to satisfy
	 * {@code Discovery}'s threshold) must both appear, in ascending address order regardless of
	 * scan order.
	 */
	@Test
	public void evidenceAddressesAppearInTheCommentSortedByOffset() throws Exception {
		builder.setBytes("0x9000", "85 42", true); // STA $42   -- shadow write, higher address
		builder.setBytes("0x9002", "8d 02 c0", true); // STA $C002 -- switch site B

		builder.setBytes("0x8000", "85 42", true); // STA $42   -- shadow write, lower address
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000 -- switch site A

		BankMirrors.Discovery discovery = new BankMirrors.Discovery(baseSpace);
		discovery.scanWriteThroughShadows(program,
			Set.of(builder.addr("0x8002"), builder.addr("0x9002")));
		BankMirrors mirrors = discovery.build();
		assertFalse("the derivation must have actually classified $42, or this test proves "
			+ "nothing about the evidence-listing rule", mirrors.isEmpty());

		name(mirrors);

		String comment = eolComment(0x42);
		assertNotNull(comment);
		int at8000 = comment.indexOf("8000");
		int at9000 = comment.indexOf("9000");
		assertTrue("both evidence sites must be listed", at8000 >= 0 && at9000 >= 0);
		assertTrue("evidence sites must be listed in ascending address order", at8000 < at9000);
	}

	// ------------------------------------------------------------------
	// 6. Idempotence
	// ------------------------------------------------------------------

	/**
	 * The analyzer framework re-invokes {@code added()} on every settled round (see its own
	 * redundant-re-run gate). A second call to {@code nameBankMirrors} over the identical mirror
	 * set must neither create a duplicate symbol nor stack a second copy of the comment --
	 * exactly the guarantees {@link AnnotationGuard#applyLabel} and {@link
	 * AnnotationGuard#addComment}'s marker already provide, pinned here at the call-site level
	 * rather than only inside {@code AnnotationGuard} itself.
	 */
	@Test
	public void aSecondRunChangesNothing() throws Exception {
		BankMirrors mirrors = mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH);
		name(mirrors);
		String firstComment = eolComment(0x42);
		Symbol[] firstSymbols = program.getSymbolTable().getSymbols(baseSpace.getAddress(0x42));

		name(mirrors);

		Symbol[] secondSymbols = program.getSymbolTable().getSymbols(baseSpace.getAddress(0x42));
		String secondComment = eolComment(0x42);

		assertEquals("re-running must not create a duplicate symbol", firstSymbols.length,
			secondSymbols.length);
		assertEquals("re-running must not create a duplicate symbol", 1, secondSymbols.length);
		assertEquals("re-running must not stack a second copy of the comment", firstComment,
			secondComment);
	}

	// ------------------------------------------------------------------
	// 7. USER_DEFINED is never displaced
	// ------------------------------------------------------------------

	/**
	 * A human who already labelled a mirror address (e.g. renamed it before this bead existed, or
	 * disagreed with the derived name) keeps their label. {@code nameBankMirrors} routes entirely
	 * through {@link AnnotationGuard#applyLabel}, which declines outright at a {@code
	 * USER_DEFINED} primary symbol -- so no {@code bank_shadow_...} symbol is created at all, and
	 * the user's label remains primary, unrenamed.
	 */
	@Test
	public void userDefinedLabelAtAMirrorAddressIsNotDisplaced() throws Exception {
		Address addr = baseSpace.getAddress(0x42);
		int tx = program.startTransaction("create user label");
		try {
			program.getSymbolTable().createLabel(addr, "my_own_name", SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(tx, true);
		}

		name(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		Symbol primary = primarySymbol(0x42);
		assertEquals("the user's label must survive untouched", "my_own_name", primary.getName());
		assertEquals(SourceType.USER_DEFINED, primary.getSource());
		for (Symbol sym : program.getSymbolTable().getSymbols(addr)) {
			assertFalse("no analyzer-derived bank_shadow_ symbol may have been created here",
				sym.getName().startsWith("bank_shadow_"));
		}
	}
}
