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
// Shared base, constants and helpers for the banktest criteria families. Split out of
// VerifyBankTest.java (bead grm-rx1i.17) and recomposed by grm-rx1i.21: VerifyBankTest (the
// GhidraScript: Check registry, run(), dispatch) constructs the sibling families
// VerifyDumpCriteria, VerifyCbmCriteria, VerifyDescriptorCriteria and VerifyNesCriteria, each
// of which extends this class. This class is NOT a GhidraScript; it exposes the few script
// members the criteria use under their original names (currentProgram, println) so the moved
// bodies stay verbatim, and forwards output to the owning script so text and order are
// unchanged. Compiled with the rest of the script dir as one bundle, the same arrangement as
// RealRomDumpSupport.java.

import java.util.Map;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import retromachines.C64BankingAnalyzer;

public abstract class VerifyBase {

	/** Run-wide verdict shared by every family (the old single {@code allPassed} field). */
	static final class Verdict {
		boolean allPassed = true;
	}

	/** The owning script: the single writer/output path for every family. */
	private final GhidraScript script;
	/** The script's current program; fixed for the duration of one run() (families are built in run()). */
	protected final Program currentProgram;
	/** The script's task monitor (set before run() builds the families). */
	protected final TaskMonitor monitor;
	private final Verdict verdict;

	protected VerifyBase(GhidraScript script, Verdict verdict) {
		this.script = script;
		this.currentProgram = script.getCurrentProgram();
		this.monitor = script.getMonitor();
		this.verdict = verdict;
	}

	protected void println(String message) {
		script.println(message);
	}

	// Each BoardBankAnalyzer subclass bookmarks under its own class-name category
	// (BoardBankAnalyzer.getBookmarkCategory() default); the C64 and NES fixtures never
	// run in the same program, but the dump/lookup helpers below accept either so one
	// script covers both suites.
	protected static final String CATEGORY_C64 = "C64BankingAnalyzer";
	protected static final String CATEGORY_NES = "NesBankingAnalyzer";

	// Program-info property a loader stamps with the image's per-game identity
	// (DescriptorHints.GAME_IDENTITY_PROPERTY -- package-private, so it is re-declared as a
	// literal here rather than referenced; this script links against only the public analyzer
	// classes). Same convention as the "Retro Machine Map" literal in checkPet4032() and the
	// literals at tools/banktest/RealRomDump.java:57-60.
	protected static final String GAME_IDENTITY_PROPERTY = "Retro Machines.Game Identity";

	// Program-info property a loader stamps with the entry points reached asynchronously --
	// the 6502 NMI/IRQ vector targets (DescriptorHints.ASYNC_ENTRY_POINTS_PROPERTY, bead
	// grm-913). Re-declared as a literal for the reason above.
	protected static final String ASYNC_ENTRY_POINTS_PROPERTY = "Retro Machines.Async Entry Points";

	protected boolean hasSymbol(long offset, String name) {
		for (Symbol s : currentProgram.getSymbolTable().getSymbols(addr(offset))) {
			if (name.equals(s.getName())) {
				return true;
			}
		}
		return false;
	}

	protected boolean hasAnySymbol(long offset) {
		return currentProgram.getSymbolTable().getSymbols(addr(offset)).length > 0;
	}

	/**
	 * Reads through an ADDRESS rather than a block. Necessary for byte-mapped blocks, which
	 * report {@code isInitialized() == false} (their bytes belong to the block they map onto)
	 * and so read as -1 through {@link #readByte}.
	 */
	protected int readByteAt(long address) {
		try {
			return currentProgram.getMemory().getByte(addr(address)) & 0xFF;
		}
		catch (Exception e) {
			return -1;
		}
	}

	protected int readByte(MemoryBlock block, long offsetInBlock) {
		if (block == null || !block.isInitialized()) {
			return -1;
		}
		try {
			return block.getByte(block.getStart().add(offsetInBlock)) & 0xFF;
		}
		catch (Exception e) {
			return -1;
		}
	}

	protected static String hx(int b) {
		return b < 0 ? "??" : String.format("%02x", b);
	}

	protected static String hex(byte[] bytes) {
		if (bytes == null) {
			return "<none>";
		}
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			if (sb.length() > 0) {
				sb.append(" ");
			}
			sb.append(String.format("%02x", b & 0xFF));
		}
		return sb.toString();
	}

	protected static String describeBlock(MemoryBlock b) {
		if (b == null) {
			return "<missing>";
		}
		return b.getName() + " " + fmt(b.getStart()) + "-" + fmt(b.getEnd()) + " overlay=" +
			b.isOverlay();
	}

	protected static long fileOffset(MemoryBlock block) {
		if (block == null || block.getSourceInfos().isEmpty()) {
			return -1;
		}
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		return info.getFileBytes() == null ? -1 : info.getFileBytesOffset();
	}

	protected static long fileOffset(MemoryBlock block, long addressOffset) {
		if (block == null || block.getSourceInfos().isEmpty()) {
			return -1;
		}
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		Address address = block.getStart().getAddressSpace().getAddress(addressOffset);
		return info.getFileBytes() == null ? -1 : info.getFileBytesOffset(address);
	}

	protected MemoryBlock blockAt(String spaceName, long offset) {
		AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(spaceName);
		return space == null ? null : currentProgram.getMemory().getBlock(space.getAddress(offset));
	}

	protected static boolean initializedOverlay(MemoryBlock block, String spaceName) {
		return block != null && block.isInitialized() && block.isOverlay() &&
			spaceName.equals(block.getStart().getAddressSpace().getName());
	}

	protected String bytesAt(String spaceName, long offset, int length) {
		try {
			Address start = spaceName == null ? addr(offset) : overlayAddr(spaceName, offset);
			byte[] bytes = new byte[length];
			currentProgram.getMemory().getBytes(start, bytes);
			return hex(bytes);
		}
		catch (Exception e) {
			return "<unreadable>";
		}
	}

	protected static String names(MemoryBlock... blocks) {
		StringBuilder result = new StringBuilder();
		for (MemoryBlock block : blocks) {
			if (result.length() > 0) {
				result.append(" ");
			}
			result.append(block == null ? "<missing>" : block.getName());
		}
		return result.toString();
	}

	// ------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------

	protected void criterion(String id, boolean passed, String detail) {
		if (!passed) {
			verdict.allPassed = false;
		}
		println("CRITERION " + id + " " + (passed ? "PASS" : "FAIL") + " " + detail);
	}

	/** criterion(id, ref is a primary call, prefix + describe(ref)) -- the retargeted-call shape. */
	protected void criterionPrimaryCall(String id, Reference ref, String detailPrefix) {
		criterion(id, ref != null && ref.getReferenceType().isCall() && ref.isPrimary(),
			detailPrefix + describe(ref));
	}

	/** criterion(id, comment contains needle and has no unresolved "?", lead + comment + closing quote).
	 *  {@code detailLead} must already end with an escaped opening quote. */
	protected void criterionEolKnown(String id, String comment, String needle, String detailLead) {
		criterion(id, comment.contains(needle) && !comment.contains("?"),
			detailLead + comment + "\"");
	}

	protected Address addr(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	protected static String fmt(Address a) {
		return String.format("%04x", a.getOffset());
	}

	protected String eol(long offset) {
		String c = currentProgram.getListing().getComment(CommentType.EOL, addr(offset));
		return c == null ? "" : c;
	}

	protected String preComment(long offset) {
		String c = currentProgram.getListing().getComment(CommentType.PRE, addr(offset));
		return c == null ? "" : c;
	}

	protected boolean hasFunctionAt(long offset) {
		return currentProgram.getListing().getFunctionAt(addr(offset)) != null;
	}

	/** Overlay-space address, or the base-space address if {@code spaceName} does not
	 *  resolve (lets callers fail with a null-instruction criterion rather than an NPE). */
	protected Address overlayAddr(String spaceName, long offset) {
		AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(spaceName);
		return space == null ? addr(offset) : space.getAddress(offset);
	}

	/** {@link #eol(long)}, but for an instruction physically located in an overlay space
	 *  (e.g. a mode-qualified overlay -- {@code memory.layouts[]} instances, bead grm-qvi). */
	protected String eol(String spaceName, long offset) {
		String c = currentProgram.getListing().getComment(CommentType.EOL,
			overlayAddr(spaceName, offset));
		return c == null ? "" : c;
	}

	protected boolean hasWarningBookmark(long offset) {
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(offset))) {
			boolean ourCategory = CATEGORY_C64.equals(bm.getCategory()) ||
				CATEGORY_NES.equals(bm.getCategory());
			if (ourCategory && "Warning".equals(bm.getTypeString())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * As {@link #hasWarningBookmark} but for a {@code Note} -- the HONEST half of the gap
	 * classification (bead {@code grm-3ou} part 1). Same category filter, deliberately: a note
	 * from {@code CopyLoopAnalyzer} or {@code TransferMaterializer} must not satisfy a criterion
	 * about a bank gap.
	 */
	protected boolean hasNoteBookmark(long offset) {
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(offset))) {
			boolean ourCategory = CATEGORY_C64.equals(bm.getCategory()) ||
				CATEGORY_NES.equals(bm.getCategory());
			if (ourCategory && "Note".equals(bm.getTypeString())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The text of our own Warning bookmark at {@code offset}, or "" when there is none --
	 * companion to {@link #hasWarningBookmark} for criteria whose diagnosis depends on WHICH
	 * warning fired. A bank-state requirement violation and an unrecoverable helper argument
	 * both present as an empty EOL comment plus a warning, and telling them apart from the
	 * criterion line alone is otherwise impossible (bead grm-67g).
	 */
	protected String warningBookmarkText(long offset) {
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(offset))) {
			boolean ourCategory = CATEGORY_C64.equals(bm.getCategory()) ||
				CATEGORY_NES.equals(bm.getCategory());
			if (ourCategory && "Warning".equals(bm.getTypeString())) {
				return bm.getComment() == null ? "" : bm.getComment();
			}
		}
		return "";
	}

	/**
	 * {@link #warningBookmarkText}'s companion for a {@code Note} bookmark (bead grm-yflf): the
	 * text of our own Note bookmark at {@code offset}, or "" when there is none. Needed wherever a
	 * criterion must accept EITHER an honest warning OR an honest {@code RESTORED_BANK} note as the
	 * same underlying claim ("declines honestly, no fabricated bank"), and must still be able to
	 * check WHICH note it got (e.g. that it names the expected save cell).
	 */
	protected String noteBookmarkText(long offset) {
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(offset))) {
			boolean ourCategory = CATEGORY_C64.equals(bm.getCategory()) ||
				CATEGORY_NES.equals(bm.getCategory());
			if (ourCategory && "Note".equals(bm.getTypeString())) {
				return bm.getComment() == null ? "" : bm.getComment();
			}
		}
		return "";
	}

	protected boolean hasSysNoteBookmark(long offset) {
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(offset))) {
			if ("Note".equals(bm.getTypeString()) && bm.getComment().contains("SYS argument")) {
				return true;
			}
		}
		return false;
	}

	protected Reference findOverlayRef(long from, String spaceName, long toOffset) {
		return findOverlayRefFrom(addr(from), spaceName, toOffset);
	}

	/** {@link #findOverlayRef}, but for an instruction physically located in an overlay
	 *  space (see {@link #overlayAddr}) rather than base space. */
	protected Reference findOverlayRefFrom(Address from, String spaceName, long toOffset) {
		Instruction instr = currentProgram.getListing().getInstructionAt(from);
		if (instr == null) {
			return null;
		}
		for (Reference r : instr.getReferencesFrom()) {
			AddressSpace toSpace = r.getToAddress().getAddressSpace();
			if (toSpace.isOverlaySpace() && toSpace.getName().equals(spaceName) &&
				r.getToAddress().getOffset() == toOffset) {
				return r;
			}
		}
		return null;
	}

	/** True when a function's ENTRY POINT is exactly this base-space address. */
	protected boolean isFunctionEntry(long offset) {
		return currentProgram.getFunctionManager()
				.getFunctionAt(currentProgram.getAddressFactory()
						.getDefaultAddressSpace()
						.getAddress(offset)) != null;
	}

	protected boolean hasInstructionAt(String spaceName, long offset) {
		AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			return false;
		}
		return currentProgram.getListing().getInstructionAt(space.getAddress(offset)) != null;
	}

	/** Number of references out of the instruction at {@code from} into BASE space at
	 *  {@code toOffset} -- the stock reference the disassembler placed, which grm-bfb retires
	 *  once an overlay reference has replaced it. */
	protected int baseRefCount(long from, long toOffset) {
		Instruction instr = currentProgram.getListing().getInstructionAt(addr(from));
		if (instr == null) {
			return 0;
		}
		AddressSpace base = currentProgram.getAddressFactory().getDefaultAddressSpace();
		int count = 0;
		for (Reference r : instr.getReferencesFrom()) {
			if (r.getToAddress().getAddressSpace().equals(base) &&
				r.getToAddress().getOffset() == toOffset) {
				count++;
			}
		}
		return count;
	}

	protected int overlayRefCount(long from) {
		Instruction instr = currentProgram.getListing().getInstructionAt(addr(from));
		if (instr == null) {
			return 0;
		}
		int count = 0;
		for (Reference r : instr.getReferencesFrom()) {
			if (r.getToAddress().getAddressSpace().isOverlaySpace()) {
				count++;
			}
		}
		return count;
	}

	protected static String describe(Reference r) {
		if (r == null) {
			return "<no matching overlay reference>";
		}
		return r.getToAddress().getAddressSpace().getName() + "::" + fmt(r.getToAddress()) +
			" " + r.getReferenceType().getName() + " primary=" + r.isPrimary();
	}

	protected static String describeData(Data d) {
		if (d == null) {
			return "<undefined>";
		}
		return d.getDataType().getName() + " len=" + d.getLength() + " value=" +
			d.getDefaultValueRepresentation();
	}
}
