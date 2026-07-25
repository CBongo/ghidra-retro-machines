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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Turns a recovered {@link TransferSpec} into real bytes in the Program -- the single,
 * front-end-agnostic materializer shared by the auto copy-loop recognizer, a later manual
 * command (grm-1.7.1.1), and the descriptor {@code copied_from} hint (grm-1.7.1.2), which runs
 * from the loader rather than an analyzer.
 *
 * <p><b>Placement (grm-chu).</b> The destination of a run-from-elsewhere copy normally sits
 * inside a loader-created <em>uninitialized</em> block, so grm-1.7.1 originally materialized it
 * as a byte-mapped <em>overlay</em>. That made a real call site unreachable: a base-space
 * {@code JSR $0073} resolves to {@code base:$0073}, never to an overlay copy, so every entering
 * reference had to be hand-bridged one site at a time. We now carve the destination out of its
 * containing block and initialize it <b>in place</b>, so the copied bytes live at the address
 * the CPU actually runs them from and references resolve with no bridging at all. The overlay
 * remains as the fallback for destinations that cannot be carved.
 *
 * <p>The carve is the pattern Ghidra core blesses -- {@code split} the containing block around
 * the destination, {@link Memory#convertToInitialized} the isolated piece, write the bytes --
 * as used by {@code GolangSymbolAnalyzer} to isolate {@code runtime.writeBarrier}, and by this
 * repo's own loader (see {@code AbstractCbmPrgLoader.createCarvedTarget}) to place PRG slices
 * inside RAM regions. No Ghidra core change is required. See
 * {@code docs/smc-inplace-vs-overlay.md} for the full decision record.
 *
 * <p><b>Two invariants keep the carve honest</b>, because {@code convertToInitialized} fills a
 * range with a synthetic byte and a block that <em>reports</em> initialized while holding
 * invented bytes is a worse lie than an uninitialized one:
 * <ol>
 * <li><b>{@code IDENTITY} only.</b> Carving is legal solely because a run-from-elsewhere
 * destination holds nothing meaningful before the copy runs. That is false for a transformed
 * transfer -- a decrypt-in-place has real encrypted bytes at the destination -- so a non-verbatim
 * transfer never carves, whatever the destination looks like.</li>
 * <li><b>Carve range == write range.</b> We carve exactly {@code [dst, dst+len)} and immediately
 * overwrite every byte of it, so no fill byte survives. Never carve wider than can be filled.</li>
 * </ol>
 *
 * <p><b>An unreadable source materializes nothing.</b> A snapshot needs bytes to snapshot; when
 * the source range is uninitialized (a {@code copied_from} hint naming a KERNAL ROM the user
 * never supplied) the transfer is skipped entirely rather than inventing bytes or falling back to
 * an overlay of {@code ??}. Materialization is idempotent, so once the missing bytes are present
 * a re-run picks the transfer up.
 */
final class TransferMaterializer {

	/** Block-name prefix for a materialized copy; the suffix is the destination offset. */
	private static final String BLOCK_PREFIX = "COPY_";

	private TransferMaterializer() {
	}

	/** Where a transfer's bytes actually ended up. */
	enum Placement {
		/** Carved out of the containing uninitialized block and initialized at the real address. */
		IN_PLACE,
		/** A byte-mapped overlay in its own address space (destination was not carvable). */
		OVERLAY,
		/** Nothing was materialized. */
		SKIPPED;
	}

	/**
	 * Materialize {@code spec}, honoring its disassembly directive, and cross-link the result to
	 * the copy site with provenance.
	 *
	 * @param program  the program to materialize into
	 * @param spec     the recovered transfer
	 * @param category bookmark category to file provenance under (the calling front-end's name)
	 * @param monitor  monitor for the disassembly/function commands
	 * @param log      import/analysis log for the cases that produce nothing
	 * @return where the bytes landed
	 */
	static Placement materialize(Program program, TransferSpec spec, String category,
			TaskMonitor monitor, MessageLog log) {

		if (spec.target() == TransferSpec.TargetKind.SEPARATE_PROGRAM) {
			log.appendMsg(category, "cross-processor transfers are not implemented (grm-1.7.3)");
			return Placement.SKIPPED;
		}
		if (spec.transform() != TransferSpec.Transform.IDENTITY) {
			// grm-1.7.1 recovers verbatim copies only; a transformed transfer has no computed
			// bytes to place. (Carving is independently fenced to IDENTITY in canCarve.)
			log.appendMsg(category,
				"unsupported transform (" + spec.transform() + "); only IDENTITY is implemented");
			return Placement.SKIPPED;
		}

		String name = BLOCK_PREFIX + String.format("%04x", spec.dstStart().getOffset());
		if (program.getMemory().getBlock(name) != null) {
			return Placement.SKIPPED; // already recovered on a prior pass -- idempotent
		}

		// Gate 0: a snapshot needs readable source bytes. Produce nothing rather than invent them.
		byte[] bytes = readSource(program, spec);
		if (bytes == null) {
			program.getBookmarkManager().setBookmark(spec.provenanceSite(), BookmarkType.WARNING,
				category, "copy " + fmt(spec.srcStart()) + " -> " + fmt(spec.dstStart()) +
					" not materialized: source bytes are uninitialized (supply the ROM image, " +
					"then re-run this analyzer)");
			return Placement.SKIPPED;
		}

		MemoryBlock block;
		Placement placement;
		if (canCarve(program, spec)) {
			try {
				block = carveInPlace(program, spec, name, bytes);
			}
			// MemoryBlockException (split/convertToInitialized) extends MemoryAccessException.
			catch (LockException | MemoryAccessException | IllegalArgumentException e) {
				log.appendMsg(category, name + ": in-place carve failed (" + e.getMessage() +
					"); no block materialized");
				return Placement.SKIPPED;
			}
			placement = Placement.IN_PLACE;
		}
		else {
			if (spec.target() == TransferSpec.TargetKind.SAME_SPACE_INPLACE) {
				log.appendMsg(category, name + ": in-place placement was requested but the " +
					"destination is not carvable; using a byte-mapped overlay instead");
			}
			block = createOverlay(program, spec, name, log);
			if (block == null) {
				return Placement.SKIPPED;
			}
			placement = Placement.OVERLAY;
		}

		recordProvenance(program, spec, block, category, placement);

		if (!spec.disassemble()) {
			return placement;
		}
		disassemble(program, spec, block, monitor);
		if (placement == Placement.OVERLAY) {
			// Only an overlay copy needs help: the entering jump's own operand already resolves
			// to the in-place bytes, which is the whole point of carving.
			bridgeJump(program, spec, block);
		}
		return placement;
	}

	// ------------------------------------------------------------------
	// Placement decision
	// ------------------------------------------------------------------

	/**
	 * Whether {@code spec}'s destination can be carved out of its containing block and
	 * initialized in place. Every check is total and side-effect free, so the caller can commit
	 * to the carve knowing no half-split map can result.
	 */
	private static boolean canCarve(Program program, TransferSpec spec) {
		// The fence: only a verbatim copy into content-free memory may be overwritten with a
		// synthetic fill. Kept here as well as at the top of materialize() so that unifying the
		// decrypt transforms onto this materializer cannot silently enable carving.
		if (spec.transform() != TransferSpec.Transform.IDENTITY) {
			return false;
		}
		if (spec.target() == TransferSpec.TargetKind.SAME_SPACE_OVERLAY) {
			return false; // front-end explicitly asked for the overlay representation
		}
		if (spec.dstStart().getAddressSpace().isOverlaySpace()) {
			return false; // carving inside an overlay would not fix reference resolution
		}
		Address dstEnd = endOf(spec);
		if (dstEnd == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(spec.dstStart());
		if (block == null || !block.contains(dstEnd)) {
			return false; // must lie wholly within one block; multi-block carve is out of scope
		}
		// Uninitialized and splittable: never overwrite loaded file bytes (the pre-copy image
		// stays navigable), and Memory.split rejects mapped blocks.
		return !block.isInitialized() && !block.isMapped() &&
			block.getType() == MemoryBlockType.DEFAULT;
	}

	// ------------------------------------------------------------------
	// The two materialization strategies
	// ------------------------------------------------------------------

	/**
	 * Split the containing block around {@code [dst, dst+len)}, initialize the isolated piece,
	 * and write the copied bytes into it. Preconditions are {@link #canCarve}'s.
	 */
	private static MemoryBlock carveInPlace(Program program, TransferSpec spec, String name,
			byte[] bytes) throws LockException, MemoryAccessException {
		Memory memory = program.getMemory();
		Address dst = spec.dstStart();
		Address dstEnd = endOf(spec);
		MemoryBlock block = memory.getBlock(dst);
		String origName = block.getName();

		// split() keeps the lower piece and names the new upper piece "<name>.split", so the
		// block holding dst must be re-fetched after each cut. Both cuts are conditional:
		// splitting at a block's own start address is an error, not a no-op.
		if (!dst.equals(block.getStart())) {
			memory.split(block, dst);
			block = memory.getBlock(dst);
		}
		if (!dstEnd.equals(block.getEnd())) {
			Address tailStart = dstEnd.next();
			memory.split(block, tailStart);
			memory.getBlock(tailStart).setName(fragmentName(origName, tailStart));
			block = memory.getBlock(dst);
		}

		block = memory.convertToInitialized(block, (byte) 0);
		memory.setBytes(dst, bytes); // carve range == write range: no fill byte survives
		block.setName(name);
		block.setComment("run-from-elsewhere copy of " + fmt(spec.srcStart()) + " (" + spec.len() +
			" bytes), carved from " + origName);
		// An overlay records its origin in the byte-map (getSourceInfos().getMappedRange()); a
		// snapshot has no map, so the source address goes in the block's own sourceName field --
		// "where these bytes came from", the same sense the loader uses it in createDirectBlock.
		block.setSourceName(fmt(spec.srcStart()));
		return block;
	}

	/**
	 * The fallback representation: a dual-home byte-mapped overlay mapped 1:1 back at the source,
	 * so the copy and its master stay the same live bytes. Used when the destination cannot be
	 * carved -- it already holds real bytes, straddles blocks, or is itself in an overlay.
	 */
	private static MemoryBlock createOverlay(Program program, TransferSpec spec, String name,
			MessageLog log) {
		try {
			MemoryBlock block = program.getMemory().createByteMappedBlock(name, spec.dstStart(),
				spec.srcStart(), spec.len(), true);
			if (block == null) {
				log.appendMsg(name + ": byte-mapped block creation failed");
			}
			return block;
		}
		catch (LockException | MemoryConflictException | AddressOverflowException |
				IllegalArgumentException e) {
			log.appendMsg(name + ": could not create byte-mapped block: " + e.getMessage());
			return null;
		}
	}

	// ------------------------------------------------------------------
	// Provenance, disassembly, reference bridging
	// ------------------------------------------------------------------

	/** Cross-link the copy site and the destination, whatever the placement. */
	private static void recordProvenance(Program program, TransferSpec spec, MemoryBlock block,
			String category, Placement placement) {
		String where = placement == Placement.IN_PLACE
				? "initialized in place as " + block.getName()
				: "byte-mapped overlay " + block.getName();
		String kindNote = spec.disassemble()
				? "; disassembled as code"
				: "; materialized as data, not disassembled -- no call into range observed " +
					"(may be data, or a deferred-call routine like CHRGET)";

		BookmarkManager bm = program.getBookmarkManager();
		bm.setBookmark(spec.provenanceSite(), BookmarkType.NOTE, category,
			"copy loop -> " + block.getName() + ": " + spec.len() + " bytes " +
				fmt(spec.srcStart()) + " -> " + fmt(spec.dstStart()) + kindNote);
		bm.setBookmark(spec.dstStart(), BookmarkType.NOTE, category,
			"run-from-elsewhere copy of " + fmt(spec.srcStart()) + "; " + where);
		program.getListing().setComment(spec.provenanceSite(), CommentType.EOL,
			"copy loop -> " + block.getName());
	}

	/** Disassemble from the (possibly mid-range) entry point and optionally make it a function. */
	private static void disassemble(Program program, TransferSpec spec, MemoryBlock block,
			TaskMonitor monitor) {
		Address entry;
		try {
			// For an in-place carve the block starts at dstStart, so this is the entry itself;
			// for an overlay it re-homes the entry into the overlay space.
			entry = block.getStart()
					.add(spec.entryPoint().getOffset() - spec.dstStart().getOffset());
		}
		catch (AddressOutOfBoundsException e) {
			return;
		}
		Listing listing = program.getListing();
		if (listing.getInstructionAt(entry) == null) {
			new DisassembleCommand(entry, null, true).applyTo(program, monitor);
		}
		if (spec.makeFunction() && listing.getInstructionAt(entry) != null &&
			program.getFunctionManager().getFunctionAt(entry) == null) {
			new CreateFunctionCmd(entry).applyTo(program, monitor);
		}
	}

	/**
	 * Retarget the entering {@code JMP}/{@code JSR}'s reference from {@code base:target} into the
	 * overlay copy, so navigation reaches the materialized code. Needed only for the overlay
	 * placement; carried over from grm-1.7.1 and mirrors {@code BoardBankAnalyzer.addOverlayRef}.
	 */
	private static void bridgeJump(Program program, TransferSpec spec, MemoryBlock overlay) {
		if (spec.jumpSite() == null) {
			return;
		}
		Instruction jmp = program.getListing().getInstructionAt(spec.jumpSite());
		if (jmp == null) {
			return;
		}
		Address target = StoredValueScanner.plainAbsoluteTarget(jmp);
		if (target == null) {
			return;
		}
		Address overlayTarget;
		try {
			overlayTarget = overlay.getStart().add(target.getOffset() - spec.dstStart().getOffset());
		}
		catch (AddressOutOfBoundsException e) {
			return;
		}
		RefType refType = LoopIdioms.mnem(jmp).equals("JSR")
				? RefType.UNCONDITIONAL_CALL
				: RefType.UNCONDITIONAL_JUMP;
		ReferenceManager refMgr = program.getReferenceManager();
		Reference ref = refMgr.addMemoryReference(jmp.getMinAddress(), overlayTarget, refType,
			SourceType.ANALYSIS, 0);
		refMgr.setPrimary(ref, true);
	}

	// ------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------

	/** The source bytes, or null when any of them is uninitialized (gate 0). */
	private static byte[] readSource(Program program, TransferSpec spec) {
		byte[] bytes = new byte[spec.len()];
		try {
			return program.getMemory().getBytes(spec.srcStart(), bytes) == spec.len() ? bytes : null;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/** Last destination byte, or null if the range runs off the end of the address space. */
	private static Address endOf(TransferSpec spec) {
		try {
			return spec.dstStart().addNoWrap(spec.len() - 1L);
		}
		catch (AddressOverflowException e) {
			return null;
		}
	}

	/**
	 * Name for a leftover fragment of a carved block, following the loader's own carve
	 * convention (see {@code AbstractCbmPrgLoader.createDirectBlock}, which yields
	 * {@code RAM_MAIN_0816} / {@code P6510_0001}): the original name plus the fragment's start.
	 */
	private static String fragmentName(String origName, Address start) {
		return origName + String.format("_%04X", start.getOffset());
	}

	/** Compact {@code space:offset} rendering for bookmark/log text. */
	static String fmt(Address a) {
		return a.getAddressSpace().getName() + ":" + String.format("%04x", a.getOffset());
	}
}
