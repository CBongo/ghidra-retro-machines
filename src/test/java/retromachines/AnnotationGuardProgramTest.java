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
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Pins {@link AnnotationGuard} -- the never-overwrite-user-work rule from
 * {@code docs/per-game-descriptors-design.md} 3c.3 -- against a real {@link ProgramDB}, since
 * the rule is meaningless without Ghidra's actual {@code SourceType} bookkeeping backing it.
 * <p>
 * This is the regression suite for bead {@code grm-mej.4}: before this bead, nothing in the
 * repo read {@code Symbol.getSource()} or {@code Reference.getSource()} at all, so every
 * descriptor/analyzer write path could silently clobber a human's label, comment, or reference
 * the moment the address collided. Each test below states which half of that hole it closes.
 */
public class AnnotationGuardProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private Address addr;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		addr = builder.addr("0x8010");
	}

	// ------------------------------------------------------------------
	// Symbols
	// ------------------------------------------------------------------

	/**
	 * Invariant: a {@code USER_DEFINED} label is never replaced or displaced by a later
	 * {@code IMPORTED} write at the same address. This is the core of 3c.3 -- without it, a
	 * descriptor re-apply (e.g. after a curated descriptor upgrade) can quietly rename a symbol
	 * a human typed in by hand. {@link AnnotationGuard#applyLabel} must report {@code false} (it
	 * declined) and the original symbol must remain, unrenamed and still primary.
	 */
	@Test
	public void userDefinedLabelIsNeverReplaced() throws Exception {
		createLabel(addr, "user_named", SourceType.USER_DEFINED);

		boolean wrote;
		int tx = program.startTransaction("apply guarded label");
		try {
			wrote = AnnotationGuard.applyLabel(program, addr, "descriptor_named",
				SourceType.IMPORTED);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertFalse("a USER_DEFINED symbol must block the write", wrote);
		Symbol primary = program.getSymbolTable().getPrimarySymbol(addr);
		assertEquals("the user's label must survive untouched", "user_named", primary.getName());
		assertEquals(SourceType.USER_DEFINED, primary.getSource());
	}

	/**
	 * Invariant: the guard is not a blanket refusal -- an address with no symbol, or only an
	 * {@code IMPORTED}/{@code ANALYSIS} one, must still accept a new {@code IMPORTED} label.
	 * Pairs with {@link #userDefinedLabelIsNeverReplaced} to prove the guard discriminates on
	 * {@code SourceType} rather than always saying no.
	 */
	@Test
	public void nonUserDefinedAddressAcceptsANewLabel() throws Exception {
		boolean wrote;
		int tx = program.startTransaction("apply guarded label");
		try {
			wrote = AnnotationGuard.applyLabel(program, addr, "descriptor_named",
				SourceType.IMPORTED);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertTrue("an unclaimed address must accept the label", wrote);
		Symbol primary = program.getSymbolTable().getPrimarySymbol(addr);
		assertEquals("descriptor_named", primary.getName());
		assertEquals(SourceType.IMPORTED, primary.getSource());
	}

	/**
	 * Invariant: applying the identical label twice (e.g. a descriptor re-applied, or an
	 * analyzer re-run to convergence) is a no-op the second time -- it neither throws
	 * {@code DuplicateNameException} nor creates a second symbol at the address. This is what
	 * makes re-analysis safe to run repeatedly rather than a one-shot operation.
	 */
	@Test
	public void reapplyingTheSameLabelIsIdempotent() throws Exception {
		int tx = program.startTransaction("apply guarded label twice");
		boolean firstWrote;
		boolean secondWrote;
		try {
			firstWrote =
				AnnotationGuard.applyLabel(program, addr, "descriptor_named", SourceType.IMPORTED);
			secondWrote =
				AnnotationGuard.applyLabel(program, addr, "descriptor_named", SourceType.IMPORTED);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertTrue(firstWrote);
		assertTrue("re-applying the same name must report success without erroring", secondWrote);
		Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
		assertEquals("must not have created a duplicate symbol", 1, symbols.length);
	}

	// ------------------------------------------------------------------
	// Comments
	// ------------------------------------------------------------------

	/**
	 * Invariant: a non-empty pre-existing comment is appended to, never overwritten. This is the
	 * regression test for the {@code DescriptorSupport.java:581} bug this bead fixes -- before
	 * the fix, {@code applySymbolSet} called {@code Listing.setComment} unconditionally, so a
	 * descriptor comment silently destroyed anything a user had typed at that address. The
	 * append must preserve the original text verbatim as a substring of the result.
	 */
	@Test
	public void nonEmptyExistingCommentIsAppendedNotOverwritten() throws Exception {
		int tx = program.startTransaction("comment setup + guarded append");
		String result;
		try {
			program.getListing().setComment(addr, CommentType.EOL, "user's own note");
			AnnotationGuard.addComment(program.getListing(), addr, CommentType.EOL,
				"descriptor comment", "descriptor comment");
			result = program.getListing().getComment(CommentType.EOL, addr);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertTrue("the user's text must survive verbatim", result.contains("user's own note"));
		assertTrue("the new comment must still show up", result.contains("descriptor comment"));
	}

	/**
	 * Invariant: when there is nothing to preserve (no comment, or a blank one), the guard sets
	 * the text directly rather than always appending -- otherwise every fresh address would grow
	 * a leading "; " from concatenating onto an empty string.
	 */
	@Test
	public void blankExistingCommentIsSetDirectly() throws Exception {
		String result;
		int tx = program.startTransaction("guarded comment on empty address");
		try {
			AnnotationGuard.addComment(program.getListing(), addr, CommentType.EOL,
				"first comment", "first comment");
			result = program.getListing().getComment(CommentType.EOL, addr);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertEquals("first comment", result);
	}

	/**
	 * Invariant: the {@code marker} parameter makes repeated calls idempotent -- calling
	 * {@link AnnotationGuard#addComment} twice with the same marker must leave exactly one copy
	 * of the annotation, not stack a duplicate on every analyzer re-run. Mirrors the proven
	 * {@code "bank ->"} idiom this method generalises (see {@code BoardBankAnalyzer}).
	 */
	@Test
	public void repeatedCallsWithTheSameMarkerDoNotStack() throws Exception {
		String result;
		int tx = program.startTransaction("guarded comment applied twice");
		try {
			AnnotationGuard.addComment(program.getListing(), addr, CommentType.EOL,
				"bank -> 3", "bank ->");
			AnnotationGuard.addComment(program.getListing(), addr, CommentType.EOL,
				"bank -> 3", "bank ->");
			result = program.getListing().getComment(CommentType.EOL, addr);
		}
		finally {
			program.endTransaction(tx, true);
		}

		int firstIndex = result.indexOf("bank ->");
		int lastIndex = result.lastIndexOf("bank ->");
		assertEquals("the marker must appear exactly once, not stacked", firstIndex, lastIndex);
	}

	// ------------------------------------------------------------------
	// References
	// ------------------------------------------------------------------

	/**
	 * Invariant: a {@code USER_DEFINED} reference is not displaced. {@link AnnotationGuard#mayDisplace}
	 * is the guard {@code BankAnnotationAdapter.addOverlayRef} consults before calling
	 * {@code ReferenceManager.setPrimary} on an analysis-derived overlay reference, so that an
	 * analyzer re-run can never bump a reference the user pinned by hand out of primacy.
	 */
	@Test
	public void userDefinedReferenceIsNotDisplaceable() throws Exception {
		Address to = builder.addr("0x8020");
		Reference userRef;
		int tx = program.startTransaction("create user reference");
		try {
			userRef = program.getReferenceManager()
					.addMemoryReference(addr, to, RefType.DATA, SourceType.USER_DEFINED, 0);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertFalse("a USER_DEFINED reference must never be reported displaceable",
			AnnotationGuard.mayDisplace(userRef));
	}

	// ------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------

	private void createLabel(Address at, String name, SourceType source) throws Exception {
		int tx = program.startTransaction("create label");
		try {
			program.getSymbolTable().createLabel(at, name, source);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}
}
