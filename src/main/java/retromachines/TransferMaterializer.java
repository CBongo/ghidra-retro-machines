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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Turns a recovered {@link TransferSpec} into real bytes in the Program -- the single,
 * front-end-agnostic materializer shared by the auto copy-loop recognizer
 * ({@link CopyLoopAnalyzer}), the manual command (grm-1.7.1.1), and the descriptor
 * {@code copied_from} hint ({@link DescriptorCopyHintAnalyzer}, grm-1.7.1.2). Front-ends do not
 * call this directly -- they go through {@link RunFromElsewhere}, which validates their input.
 *
 * <p><b>Placement (grm-chu).</b> The destination of a run-from-elsewhere copy normally sits
 * inside a loader-created <em>uninitialized</em> block, so grm-1.7.1 originally materialized it
 * as a byte-mapped <em>overlay</em>. That made a real call site unreachable: a base-space
 * {@code JSR $0073} resolves to {@code base:$0073}, never to an overlay copy, so every entering
 * reference had to be hand-bridged one site at a time. We now carve the destination out of its
 * containing block and initialize it <b>in place</b>, so the copied bytes live at the address
 * the CPU actually runs them from and references resolve with no bridging at all. When nothing is
 * mapped over the destination at all there is no block to carve <em>and</em> no conflict to avoid,
 * so a plain new block goes in the base space instead (grm-1.7.6). The overlay remains as the
 * fallback for destinations that can be neither carved nor freshly created -- already
 * initialized, straddling two blocks, or themselves inside an overlay.
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
 * <p><b>A banked destination is resolved by the front-end, not guessed here (grm-bqs).</b> On a
 * banked machine the base-space block at a destination is only the window's <em>home</em> occupant:
 * a C64 copy to {@code $E000} finds {@code KERNAL}, which with no ROM supplied is uninitialized and
 * would therefore be carved -- shredding a ROM image into {@code KERNAL / COPY_e000 / KERNAL_E008}
 * and labelling a RAM copy as ROM. The right destination is the RAM under the ROM, and which
 * occupant a write reaches is <em>bank-state-dependent</em> in general (a C64 store to {@code $D000}
 * hits I/O registers or {@code RAM_D000} depending on the state), so the descriptor cannot answer it
 * alone. It does not have to: {@code BoardBankAnalyzer} has already resolved every store against the
 * bank state live at that instruction, so {@link CopyLoopAnalyzer} reads the answer off the store's
 * own reference ({@code LoopIdioms.overlayAccessTarget}) and hands us a destination already homed in
 * the right space, marked {@link TransferTarget#RESOLVED_SPACE}. Front-ends with no instruction to
 * read -- a descriptor directive, the manual command -- are covered instead by the blanket rule that
 * only plain RAM is ever carved: never a block that is unwritable (ROM) or volatile (I/O).
 *
 * <p><b>A banked source is resolved the same way (grm-9a0), and needs nothing here.</b> The same
 * helper read with READ polarity off the {@code LDA} gives a source already homed in the live
 * occupant's overlay -- a C64 loop reading {@code $D000} with {@code CHAREN} cleared is copying the
 * character ROM, not the I/O registers the base space holds there. {@code readSource} takes the
 * source address as given, so an overlay source needs no special case: it simply reads the
 * occupant's bytes, and if that occupant is an unsupplied ROM image the "unreadable source" gate
 * below refuses, exactly as it does for a base-space ROM.
 *
 * <p><b>An unreadable source materializes nothing.</b> A snapshot needs bytes to snapshot; when
 * the source range is uninitialized (a {@code copied_from} hint naming a KERNAL ROM the user
 * never supplied) the transfer is skipped entirely rather than inventing bytes or falling back to
 * an overlay of {@code ??}. Materialization is idempotent, so once the missing bytes are present
 * a re-run picks the transfer up.
 *
 * <p><b>The materialized block's name is both its label and its idempotence key</b>, and is
 * derived from the destination address by {@link RecoveredBlockNames#forCopy} -- {@code COPY_}
 * plus the offset in the default space, plus the space name as well anywhere else, so two
 * recoveries at the same offset in different overlays no longer read as one (grm-0p7).
 */
final class TransferMaterializer {

	private TransferMaterializer() {
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
	static TransferPlacement materialize(Program program, TransferSpec spec, String category,
			TaskMonitor monitor, MessageLog log) {

		if (spec.target() == TransferTarget.SEPARATE_PROGRAM) {
			log.appendMsg(category, "cross-processor transfers are not implemented (grm-1.7.3)");
			return TransferPlacement.SKIPPED;
		}
		if (spec.transform() != TransferTransform.IDENTITY) {
			// grm-1.7.1 recovers verbatim copies only; a transformed transfer has no computed
			// bytes to place. (Carving is independently fenced to IDENTITY in canCarve.)
			log.appendMsg(category,
				"unsupported transform (" + spec.transform() + "); only IDENTITY is implemented");
			return TransferPlacement.SKIPPED;
		}

		String name = RecoveredBlockNames.forCopy(program, spec.dstStart());
		if (program.getMemory().getBlock(name) != null) {
			return TransferPlacement.SKIPPED; // already recovered on a prior pass -- idempotent
		}

		// Gate 0: a snapshot needs readable source bytes. Produce nothing rather than invent them.
		byte[] bytes = readSource(program, spec);
		if (bytes == null) {
			String why = "copy " + fmt(spec.srcStart()) + " -> " + fmt(spec.dstStart()) +
				" not materialized: source bytes are uninitialized (supply the ROM image, " +
				"then re-run)";
			// A front-end with no instruction to annotate (a descriptor directive) gets a log note
			// only -- which is exactly the "directive is ignored, log note only" rule of
			// docs/smc-inplace-vs-overlay.md section 6.
			if (spec.provenanceSite() != null) {
				program.getBookmarkManager().setBookmark(spec.provenanceSite(),
					BookmarkType.WARNING, category, why);
			}
			else {
				log.appendMsg(category, why);
			}
			return TransferPlacement.SKIPPED;
		}

		MemoryBlock block = null;
		TransferPlacement placement;
		if (canCarve(program, spec)) {
			try {
				block = carveInPlace(program, spec, name, bytes);
			}
			// MemoryBlockException (split/convertToInitialized) extends MemoryAccessException.
			catch (LockException | MemoryAccessException | IllegalArgumentException e) {
				log.appendMsg(category, name + ": in-place carve failed (" + e.getMessage() +
					"); no block materialized");
				return TransferPlacement.SKIPPED;
			}
			placement = spec.dstStart().getAddressSpace().isOverlaySpace()
					? TransferPlacement.IN_PLACE_BANKED
					: TransferPlacement.IN_PLACE;
		}
		else if (canCreateNewBlock(program, spec) &&
			(block = createNewBlock(program, spec, name, bytes, monitor, log)) != null) {
			placement = TransferPlacement.NEW_BLOCK;
		}
		else {
			if (spec.target() == TransferTarget.SAME_SPACE_INPLACE) {
				log.appendMsg(category, name + ": in-place placement was requested but the " +
					"destination is not carvable; using a byte-mapped overlay instead");
			}
			block = createOverlay(program, spec, name, log);
			if (block == null) {
				return TransferPlacement.SKIPPED;
			}
			placement = TransferPlacement.OVERLAY;
		}

		recordProvenance(program, spec, block, category, placement);

		if (!spec.disassemble()) {
			return placement;
		}
		disassemble(program, spec, block, monitor);
		if (placement == TransferPlacement.OVERLAY ||
			placement == TransferPlacement.IN_PLACE_BANKED) {
			// A base-space carve needs no help -- the entering jump's own operand already resolves
			// to the bytes, which is the whole point of carving. Both overlay-homed placements do:
			// the jump names a base-space address, and for a banked carve that address is the
			// window's home occupant, not the RAM the copy landed in.
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
		if (spec.transform() != TransferTransform.IDENTITY) {
			return false;
		}
		if (spec.target() == TransferTarget.SAME_SPACE_OVERLAY) {
			return false; // front-end explicitly asked for the overlay representation
		}
		if (spec.dstStart().getAddressSpace().isOverlaySpace() &&
			spec.target() != TransferTarget.RESOLVED_SPACE) {
			// Carving inside an overlay does not fix reference resolution -- unless the front-end
			// aimed at that overlay because it is where the write really lands (grm-bqs).
			return false;
		}
		Address dstEnd = endOf(spec);
		if (dstEnd == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(spec.dstStart());
		if (block == null || !block.contains(dstEnd)) {
			return false; // must lie wholly within one block; multi-block carve is out of scope
		}
		// Never carve memory that is not plain RAM (grm-bqs). A copied payload comes to rest in
		// RAM: a ROM occupant is not writable and an IO occupant is volatile
		// (DescriptorSupport.canWrite/markVolatileIfIo), so a destination reported as either is a
		// window's home occupant standing in for the RAM behind it, not somewhere bytes can land.
		// This is the safety net for the front-ends that have no storing instruction to resolve
		// through -- a descriptor copied_from directive, or the manual command.
		if (!block.isWrite() || block.isVolatile()) {
			return false;
		}
		// Uninitialized and splittable: never overwrite loaded file bytes (the pre-copy image
		// stays navigable), and Memory.split rejects mapped blocks.
		return !block.isInitialized() && !block.isMapped() &&
			block.getType() == MemoryBlockType.DEFAULT;
	}

	/**
	 * Whether nothing at all is mapped over the destination, so a plain new block can simply be
	 * created there (grm-1.7.6). This is the case the descriptors do not cover -- an NES board
	 * whose YAML declares no PRG-RAM region, say -- where {@link #canCarve} fails only because
	 * there is no containing block to carve. Falling through to an overlay there would be the
	 * worst of the three placements: with the range wholly unmapped there is no conflict to
	 * avoid, so the bytes belong in the base space where references resolve for free.
	 *
	 * <p>The emptiness test is deliberately whole-range ({@link Memory#intersects}) rather than
	 * {@code getBlock(dst) == null}: a range that starts in a hole but ends inside a block has no
	 * block at its start yet cannot host a new one, and would throw on creation.
	 */
	private static boolean canCreateNewBlock(Program program, TransferSpec spec) {
		if (spec.transform() != TransferTransform.IDENTITY) {
			return false;
		}
		if (spec.target() == TransferTarget.SAME_SPACE_OVERLAY) {
			return false;
		}
		// Deliberately strict where canCarve is not: a resolved banked destination
		// (TransferTarget.RESOLVED_SPACE) is always in an overlay, and a hole inside the occupant
		// the write resolves to means the loader and the descriptor disagree. Inventing a block
		// there on that evidence is worse than the byte-mapped fallback. Belt-and-braces --
		// createCarvedTarget and createUninitializedBlock between them cover a whole window.
		if (spec.dstStart().getAddressSpace().isOverlaySpace()) {
			return false;
		}
		Address dstEnd = endOf(spec);
		return dstEnd != null && !program.getMemory().intersects(spec.dstStart(), dstEnd);
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
	 * Create a fresh, non-overlay initialized block at the destination and fill it, for the case
	 * where nothing was mapped there at all. Preconditions are {@link #canCreateNewBlock}'s.
	 * Returns null on failure, so the caller falls through to the overlay.
	 *
	 * <p>Holds the same carve-range == write-range invariant as {@link #carveInPlace}: the block
	 * is exactly {@code len} bytes and every one of them is overwritten, so the zero fill
	 * {@link Memory#createInitializedBlock} lays down never survives.
	 */
	private static MemoryBlock createNewBlock(Program program, TransferSpec spec, String name,
			byte[] bytes, TaskMonitor monitor, MessageLog log) {
		try {
			Memory memory = program.getMemory();
			MemoryBlock block = memory.createInitializedBlock(name, spec.dstStart(), spec.len(),
				(byte) 0, monitor, false);
			memory.setBytes(spec.dstStart(), bytes);
			block.setComment("run-from-elsewhere copy of " + fmt(spec.srcStart()) + " (" +
				spec.len() + " bytes); nothing was mapped here, so the copy is its own block");
			block.setSourceName(fmt(spec.srcStart()));
			return block;
		}
		catch (LockException | MemoryConflictException | AddressOverflowException |
				MemoryAccessException | CancelledException | IllegalArgumentException e) {
			log.appendMsg(name + ": could not create a block at the unmapped destination: " +
				e.getMessage());
			return null;
		}
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

	/**
	 * Cross-link the copy site and the destination, whatever the placement. The destination
	 * bookmark is unconditional; the site bookmark and EOL comment are skipped when the
	 * front-end has no instruction to anchor them to (a descriptor directive).
	 */
	private static void recordProvenance(Program program, TransferSpec spec, MemoryBlock block,
			String category, TransferPlacement placement) {
		String where = switch (placement) {
			case IN_PLACE -> "initialized in place as " + block.getName();
			case IN_PLACE_BANKED -> "initialized in place as " + block.getName() + " in the " +
				block.getStart().getAddressSpace().getName() + " overlay -- the write lands in that " +
				"banked-window occupant, so the occupant homed here in the base space is untouched";
			case NEW_BLOCK -> "initialized as new block " + block.getName() +
				" (nothing was mapped here)";
			default -> "byte-mapped overlay " + block.getName();
		};
		String kindNote = spec.disassemble()
				? "; disassembled as code"
				: "; materialized as data, not disassembled -- no call into range observed " +
					"(may be data, or a deferred-call routine like CHRGET)";

		BookmarkManager bm = program.getBookmarkManager();
		if (spec.provenanceSite() != null) {
			bm.setBookmark(spec.provenanceSite(), BookmarkType.NOTE, category,
				spec.originLabel() + " -> " + block.getName() + ": " + spec.len() + " bytes " +
					fmt(spec.srcStart()) + " -> " + fmt(spec.dstStart()) + kindNote);
			program.getListing().setComment(spec.provenanceSite(), CommentType.EOL,
				spec.originLabel() + " -> " + block.getName());
		}
		bm.setBookmark(spec.dstStart(), BookmarkType.NOTE, category,
			"run-from-elsewhere copy of " + fmt(spec.srcStart()) + "; " + where);
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
	 * placement; carried over from grm-1.7.1 and mirrors {@code BankAnnotationAdapter.addOverlayRef}.
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
