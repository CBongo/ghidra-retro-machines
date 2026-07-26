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

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * The public entry point for run-from-elsewhere transfers (grm-1.7.x): materialize bytes that a
 * program copies somewhere at run time, at the address it runs them from.
 *
 * <p>Four front-ends funnel through {@link #apply}, and this class exists so that they share not
 * just the materializer but also its <em>validation</em>:
 * <ul>
 * <li>{@link CopyLoopAnalyzer} -- the automatic recognizer, for copy loops matching its idiom;</li>
 * <li>{@link DescriptorCopyHintAnalyzer} -- a per-machine descriptor {@code copied_from}
 * directive (grm-1.7.1.2);</li>
 * <li>{@code ghidra_scripts/RunFromElsewhereTransfer.java} -- the manual script, for the long
 * tail of copies no recognizer can see (grm-1.7.1.1);</li>
 * <li>{@link RunFromElsewherePlugin} -- the same thing from the GUI.</li>
 * </ul>
 *
 * <p><b>Why a facade rather than publishing the internals.</b> {@link TransferSpec} is a
 * twelve-component record that has grown a field per front-end; {@link TransferMaterializer} is
 * an implementation detail whose placement policy has already changed once (grm-chu). Both stay
 * package-private so that neither is a compatibility surface, and callers construct a
 * {@link Request} instead -- three required arguments, everything else defaulted.
 *
 * <p><b>Transactions are the caller's.</b> {@link #apply} mutates the program and does not open a
 * transaction, because its callers are already inside one: analysis runs inside
 * {@code BackgroundCommandTask}'s (GUI) or {@code HeadlessAnalyzer}'s, and a {@code GhidraScript}
 * inside the one {@code executeNormal()} opens. A Swing action is the exception -- it has no
 * transaction, which is exactly why {@link RunFromElsewherePlugin} submits a
 * {@code BackgroundCommand} rather than calling this directly. Calling with no open transaction
 * is a programming error and fails immediately rather than corrupting the program.
 */
public final class RunFromElsewhere {

	private RunFromElsewhere() {
	}

	/**
	 * What {@link #apply} did.
	 *
	 * @param placement      where the bytes landed; {@link TransferPlacement#SKIPPED} if nowhere
	 * @param blockName      the materialized block's name, or null when nothing was materialized
	 * @param alreadyPresent true when the transfer had already been materialized by an earlier
	 *                       pass, so this call was a no-op. Distinguishing this from failure is
	 *                       the point: materialization is idempotent by design (re-running after
	 *                       supplying a ROM is the documented recovery path), so a repeat call is
	 *                       success, not an error, even though both report SKIPPED.
	 * @param detail         human-readable reason, for a caller that wants to report failure
	 */
	public record Result(TransferPlacement placement, String blockName, boolean alreadyPresent,
			String detail) {

		/** Whether bytes were placed by <em>this</em> call. */
		public boolean materialized() {
			return placement != TransferPlacement.SKIPPED;
		}

		/** Whether the destination now holds the copy, whether or not this call put it there. */
		public boolean satisfied() {
			return materialized() || alreadyPresent;
		}
	}

	/**
	 * A transfer to perform: source, destination and length are required, everything else has a
	 * sensible default. Mutable and fluent, so the common verbatim copy is a single expression
	 * and only the front-ends that need the disassembly directive mention it.
	 */
	public static final class Request {

		private final Address srcStart;
		private final Address dstStart;
		private final int len;

		private TransferTransform transform = TransferTransform.IDENTITY;
		private TransferTarget target = TransferTarget.SAME_SPACE;
		private Address provenanceSite = null;
		private boolean disassemble = false;
		private boolean makeFunction = false;
		private Address entryPoint = null;
		private Address jumpSite = null;
		private String originLabel = "transfer";

		private Request(Address srcStart, Address dstStart, int len) {
			this.srcStart = srcStart;
			this.dstStart = dstStart;
			this.len = len;
		}

		/** How source bytes map to destination bytes. Default {@link TransferTransform#IDENTITY}. */
		public Request transform(TransferTransform value) {
			this.transform = value;
			return this;
		}

		/** Placement override. Default {@link TransferTarget#SAME_SPACE} (materializer chooses). */
		public Request target(TransferTarget value) {
			this.target = value;
			return this;
		}

		/**
		 * The instruction to anchor the provenance bookmark and EOL comment to -- the copy site.
		 * Default null: no site annotation, only the bookmark at the destination. A descriptor
		 * directive has no instruction to point at, so null is a real case, not just an omission.
		 */
		public Request provenanceSite(Address value) {
			this.provenanceSite = value;
			return this;
		}

		/** Whether to disassemble the destination after materializing it. Default false. */
		public Request disassemble(boolean value) {
			this.disassemble = value;
			return this;
		}

		/** Whether to create a function at the entry point. Default false; implies disassembly. */
		public Request makeFunction(boolean value) {
			this.makeFunction = value;
			return this;
		}

		/** Address to disassemble from; may sit mid-range. Default: the destination start. */
		public Request entryPoint(Address value) {
			this.entryPoint = value;
			return this;
		}

		/**
		 * The call/jump that enters the destination, used to bridge a reference into an overlay
		 * copy. Default null. Only consulted for the overlay placement -- an in-place copy's
		 * references resolve natively.
		 */
		public Request jumpSite(Address value) {
			this.jumpSite = value;
			return this;
		}

		/**
		 * What produced this transfer, as it should read in provenance text: "copy loop",
		 * "descriptor copied_from hint", "manual transfer". Default "transfer".
		 */
		public Request originLabel(String value) {
			this.originLabel = value;
			return this;
		}
	}

	/**
	 * Start building a transfer.
	 *
	 * @throws IllegalArgumentException if either address is null or {@code len} is not positive
	 */
	public static Request request(Address srcStart, Address dstStart, int len) {
		if (srcStart == null || dstStart == null) {
			throw new IllegalArgumentException("source and destination addresses are required");
		}
		if (len <= 0) {
			throw new IllegalArgumentException("transfer length must be positive, got " + len);
		}
		return new Request(srcStart, dstStart, len);
	}

	/**
	 * Materialize {@code request} into {@code program}, honoring its disassembly directive and
	 * recording provenance.
	 *
	 * <p>Never throws for bad input that a human could plausibly supply: an out-of-range length or
	 * an address the program does not cover comes back as a {@code SKIPPED} result carrying the
	 * reason, and is also written to {@code log}. That matters because the manual front-ends take
	 * their arguments from a person, and a silent overlay in the wrong place is far worse than a
	 * refusal.
	 *
	 * @param program  the program to materialize into; the caller must hold an open transaction
	 * @param request  the transfer
	 * @param category bookmark category to file provenance under (the calling front-end's name)
	 * @param monitor  monitor for the block/disassembly commands
	 * @param log      log for anything that produces no bytes
	 * @return what happened
	 * @throws IllegalStateException if no transaction is open on {@code program}
	 */
	public static Result apply(Program program, Request request, String category,
			TaskMonitor monitor, MessageLog log) {

		if (program.getCurrentTransactionInfo() == null) {
			throw new IllegalStateException("RunFromElsewhere.apply requires an open transaction " +
				"on the program; a Swing action must submit a BackgroundCommand instead");
		}

		String rejection = validate(program, request);
		if (rejection != null) {
			log.appendMsg(category, rejection);
			return new Result(TransferPlacement.SKIPPED, null, false, rejection);
		}

		Address entry = request.entryPoint != null ? request.entryPoint : request.dstStart;
		// The recognizer's AUTO/CANDIDATE distinction is "did something prove this is code"; the
		// jump site is exactly that evidence, and the explicit front-ends state the answer through
		// disassemble() instead.
		TransferSpec.Confidence confidence = request.jumpSite != null || request.disassemble
				? TransferSpec.Confidence.AUTO
				: TransferSpec.Confidence.CANDIDATE;

		TransferSpec spec = new TransferSpec(request.srcStart, request.dstStart, request.len,
			request.transform, request.target, request.provenanceSite, confidence,
			request.disassemble || request.makeFunction, request.makeFunction, entry,
			request.jumpSite, request.originLabel);

		// Probe before and after so an idempotent no-op is distinguishable from a failure: the
		// materializer reports SKIPPED for both.
		String blockName = blockNameFor(request.dstStart);
		boolean present = program.getMemory().getBlock(blockName) != null;

		TransferPlacement placement =
			TransferMaterializer.materialize(program, spec, category, monitor, log);

		boolean nowPresent = program.getMemory().getBlock(blockName) != null;
		String detail = placement == TransferPlacement.SKIPPED && !present
				? "not materialized; see the analysis log for the reason"
				: "";
		return new Result(placement, nowPresent ? blockName : null, present, detail);
	}

	/** The name {@link TransferMaterializer} gives the block for a copy landing at {@code dst}. */
	private static String blockNameFor(Address dst) {
		return "COPY_" + String.format("%04x", dst.getOffset());
	}

	/**
	 * Front-end-neutral sanity checks the auto recognizer never needed -- it derives its addresses
	 * from real operands -- but a human-driven or descriptor-driven front-end very much does.
	 * Returns the reason for refusal, or null when the request is worth attempting.
	 */
	private static String validate(Program program, Request request) {
		if (request.transform != TransferTransform.IDENTITY) {
			return "transform " + request.transform + " is not implemented yet (grm-1.7.2)";
		}
		if (!request.srcStart.isMemoryAddress() || !request.dstStart.isMemoryAddress()) {
			return "source and destination must be memory addresses";
		}
		try {
			request.srcStart.addNoWrap(request.len - 1L);
		}
		catch (AddressOverflowException e) {
			return "source range " + TransferMaterializer.fmt(request.srcStart) + " + " +
				request.len + " bytes runs off the end of its address space";
		}
		try {
			request.dstStart.addNoWrap(request.len - 1L);
		}
		catch (AddressOverflowException e) {
			return "destination range " + TransferMaterializer.fmt(request.dstStart) + " + " +
				request.len + " bytes runs off the end of its address space";
		}
		if (request.entryPoint != null) {
			long delta = request.entryPoint.getOffset() - request.dstStart.getOffset();
			if (!request.entryPoint.getAddressSpace().equals(request.dstStart.getAddressSpace()) ||
				delta < 0 || delta >= request.len) {
				return "entry point " + TransferMaterializer.fmt(request.entryPoint) +
					" is not inside the destination range";
			}
		}
		return null;
	}
}
