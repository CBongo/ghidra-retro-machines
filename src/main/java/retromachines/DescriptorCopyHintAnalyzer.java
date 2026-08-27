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

import java.io.IOException;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Tier A of run-from-elsewhere recovery (grm-1.7.1.2): materializes the boot copies a machine
 * descriptor <em>declares</em>, rather than the ones a recognizer can see.
 *
 * <p>Some copies are machine facts, not program facts. The C64 KERNAL copies the CHRGET byte-fetch
 * routine from ROM {@code $E3A2} into zero page {@code $0073} during its own init, so a loaded PRG
 * contains no copy loop at all -- {@link CopyLoopAnalyzer} has nothing to recognize -- yet every
 * BASIC-interpreter trace runs through {@code $0073}, which statically reads as uninitialized RAM.
 * A descriptor states such a fact once, in the destination region's {@code copied_from[]} list
 * (docs/SCHEMA.md; the C64's is machines/c64.yaml under {@code ZEROPAGE}), and this analyzer
 * applies it through {@link RunFromElsewhere} exactly as the recognizer applies a recovered loop.
 *
 * <p><b>ROM-gated: an unreadable source means the directive is ignored</b> -- no block, no overlay
 * fallback, a log note only (docs/smc-inplace-vs-overlay.md §6). That policy is not implemented
 * here: {@code TransferMaterializer}'s gate 0 refuses to materialize a transfer whose source bytes
 * are uninitialized, and its null-{@code provenanceSite} path downgrades the warning bookmark it
 * would otherwise leave at a copy site to a log line, which is precisely the rule. So a C64
 * imported without {@code -loader-kernalRom} silently produces nothing at {@code $0073}, as it
 * should: the CHRGET bytes are the user's ROM dump, and we will not invent them.
 *
 * <p><b>Why an analyzer and not loader-time work.</b> Because of that gate, consuming the directive
 * only at import would make the common path unreachable: a user who imports first and supplies a
 * KERNAL dump afterwards (File &rarr; Add To Program) could never get the copy. {@code
 * setSupportsOneTimeAnalysis()} below is therefore load-bearing rather than decoration -- it is the
 * only thing that puts "Analysis &rarr; One Shot &rarr; Descriptor Copy Hints" in reach after the
 * ROM arrives. Materialization is idempotent ({@code getBlock(name) != null} guard), so re-running
 * costs nothing and {@link RunFromElsewhere.Result#alreadyPresent()} distinguishes the no-op.
 *
 * <p><b>Why {@link AnalyzerType#BYTE_ANALYZER} at {@link AnalysisPriority#BLOCK_ANALYSIS}.</b> A
 * descriptor directive is anchored to no instruction, so an {@code INSTRUCTION_ANALYZER} -- which
 * only fires over ranges where code already exists -- is the wrong shape entirely; nothing would
 * ever schedule it over untouched zero page. A byte analyzer's {@code added()} fires over whole
 * memory exactly once per run, both at import and on a re-run: {@code
 * AutoAnalysisManager.reAnalyzeAll} calls {@code blockAdded(program.getMemory())}
 * (AutoAnalysisManager.java:331), which is {@code byteTasks.notifyAdded(<all memory>)}
 * (AutoAnalysisManager.java:256-259), with no dependency on instructions existing. The priority
 * sits after {@code FORMAT_ANALYSIS} and before {@code DISASSEMBLY}
 * (AnalysisPriority.java:57-71), so the copied bytes are present before Ghidra's own disassembler
 * and reference analysis reach {@code $0073} and read it as undefined RAM.
 */
public class DescriptorCopyHintAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Descriptor Copy Hints";
	private static final String DESCRIPTION =
		"Materializes the boot copies a machine descriptor declares (memory.regions[].copied_from" +
			", e.g. the C64 KERNAL's CHRGET routine copied to zero page $0073), when the source " +
			"bytes are readable -- supply the ROM image and re-run if they are not.";
	private static final String CATEGORY = "DescriptorCopyHintAnalyzer";

	/** What {@link RunFromElsewhere} should call this front-end in provenance text. */
	private static final String ORIGIN = "descriptor copied_from hint";

	public DescriptorCopyHintAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS);
		setDefaultEnablement(true);
		// Load-bearing: the ROM-gated rule makes "user supplies the ROM after import, then
		// re-runs" the documented recovery path, and one-shot analysis is how that is reached.
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return hasCopyHints(loadMap(program));
		}
		catch (IOException | RuntimeException e) {
			return false;
		}
	}

	/** The program's compiled descriptor, or null when it was not imported with one. */
	private static JsonObject loadMap(Program program) throws IOException {
		String mapPath = program.getOptions(Program.PROGRAM_INFO)
				.getString(DescriptorSupport.MAP_PATH_PROPERTY, "");
		if (mapPath == null || mapPath.isBlank()) {
			return null;
		}
		return DescriptorResources.loadMap(mapPath);
	}

	/**
	 * Whether any region declares a boot copy at all. Probed with {@code has(...)} rather than
	 * against a schema version, because the .map carries no version field -- optional-key probing
	 * is this repo's compatibility idiom, and it means a descriptor compiled before
	 * {@code copied_from} existed simply reports "nothing to do".
	 */
	private static boolean hasCopyHints(JsonObject map) {
		if (map == null || !map.has("regions")) {
			return false;
		}
		for (JsonElement re : map.getAsJsonArray("regions")) {
			if (re.getAsJsonObject().has("copied_from")) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		JsonObject map;
		try {
			map = loadMap(program);
		}
		catch (IOException | RuntimeException e) {
			AnalyzerLog.warn(this, log, "could not read the descriptor: " + e.getMessage());
			return false;
		}
		return applyAll(program, map, monitor, log);
	}

	/**
	 * Apply every {@code copied_from[]} directive in {@code map}. Split out from
	 * {@link #added} as the testable seam: {@code loadMap} goes through
	 * {@code Application.findDataFileInAnyModule}, which resolves only against installed module
	 * data directories, so a Tier-2 test cannot hand it a descriptor without an installed
	 * extension -- but it can hand this method one.
	 */
	boolean applyAll(Program program, JsonObject map, TaskMonitor monitor, MessageLog log) {
		if (!hasCopyHints(map)) {
			return true;
		}

		// Region iteration mirrors AbstractCbmPrgLoader (:351, :605): regions[] in descriptor
		// order, each an object with name/start/end. The `set` argument of added() is
		// deliberately not used as a filter -- a byte analyzer's added() is called over whole
		// memory (see the class javadoc), and a directive's destination is a fixed
		// descriptor-declared address, not something that "appeared" in the added range.
		for (JsonElement re : map.getAsJsonArray("regions")) {
			JsonObject region = re.getAsJsonObject();
			if (!region.has("copied_from")) {
				continue;
			}
			String regionName = region.get("name").getAsString();
			for (JsonElement ce : region.getAsJsonArray("copied_from")) {
				if (monitor.isCancelled()) {
					return false;
				}
				applyHint(program, regionName, ce.getAsJsonObject(), monitor, log);
			}
		}
		return true;
	}

	/** Resolve one {@code copied_from[]} entry into a request and hand it to the facade. */
	private void applyHint(Program program, String regionName, JsonObject hint,
			TaskMonitor monitor, MessageLog log) {

		// MapCompiler requires all five of these, so a compiled descriptor always carries them.
		// Checked anyway because the alternative failure mode is disproportionate: an NPE out of
		// added() aborts the entire analysis pass for the program, where a malformed directive
		// should cost only that directive.
		for (String required : new String[] { "name", "start", "end", "source", "source_addr" }) {
			if (!hint.has(required)) {
				AnalyzerLog.warn(this, log, regionName + ": copied_from entry is missing '" +
					required + "'; ignoring it");
				return;
			}
		}

		String name = hint.get("name").getAsString();
		String what = regionName + "." + name;
		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

		long start = hint.get("start").getAsLong();
		long end = hint.get("end").getAsLong();
		long len = end - start + 1;
		if (len <= 0 || len > Integer.MAX_VALUE) {
			AnalyzerLog.warn(this, log, what + ": copied range is empty or absurd; ignoring");
			return;
		}

		Address dst;
		Address src;
		try {
			// Regions always live in the base space (the loader creates them there), so the
			// destination needs no block lookup -- unlike the source, which may be a banked
			// occupant.
			dst = baseSpace.getAddress(start);
			src = resolveSource(program, baseSpace, hint.get("source").getAsString(),
				hint.get("source_addr").getAsLong());
		}
		catch (AddressOutOfBoundsException | IllegalArgumentException e) {
			AnalyzerLog.warn(this, log, what + ": could not resolve addresses (" + e.getMessage() +
				"); ignoring");
			return;
		}

		RunFromElsewhere.Request request = RunFromElsewhere.request(src, dst, (int) len)
				.originLabel(ORIGIN)
				.disassemble(optionalFlag(hint, "disassemble"))
				.makeFunction(optionalFlag(hint, "create_function"));
		if (hint.has("entry")) {
			// A headered payload's real entry may sit mid-block; the facade rejects one outside
			// the copied range.
			request.entryPoint(baseSpace.getAddress(hint.get("entry").getAsLong()));
		}
		// No provenanceSite: a descriptor directive has no instruction to annotate. That null is
		// also what turns an unreadable source into a log note instead of a warning bookmark.

		RunFromElsewhere.Result result =
			RunFromElsewhere.apply(program, request, CATEGORY, monitor, log);
		if (result.materialized() && hint.has("comment")) {
			// Append rather than replace: the materializer's own comment records where the bytes
			// came from and how they were placed, which the descriptor's prose does not.
			MemoryBlock block = program.getMemory().getBlock(result.blockName());
			block.setComment(hint.get("comment").getAsString() + " -- " + block.getComment());
		}
	}

	/**
	 * Resolve a hint's {@code source}/{@code source_addr} pair to a real address. {@code
	 * source_addr} is an absolute CPU address, and the block named by {@code source} is where
	 * those bytes actually are -- which for a banked occupant is only the base space while that
	 * occupant is the home one. The C64's KERNAL is home in the descriptor's initial state
	 * ({@code LORAM/HIRAM/CHAREN = 1}, machines/c64.yaml), so its block is created in the base
	 * space by {@code AbstractCbmPrgLoader.createWindowOccupant} and both resolutions agree; but
	 * an alternate occupant lives in an overlay space named after it, and preferring the named
	 * block picks up its bytes there instead of reading whatever happens to be home.
	 * <p>
	 * Falls back to the base space when no such block exists, or when it does not cover the
	 * address -- a descriptor may legitimately name a source whose block the loader split or
	 * renamed (the loader's own carve produces {@code RAM_MAIN_0800}-style fragments).
	 * <p>
	 * <b>Deliberately a separate path from {@code LoopIdioms.overlayAccessTarget}</b> (grm-9a0),
	 * which resolves the same question for {@link CopyLoopAnalyzer}'s recognized loops by reading
	 * {@code BoardBankAnalyzer}'s re-homed READ reference off the {@code LDA}. They are not
	 * converged because they answer from fundamentally different evidence: that one has an
	 * instruction and a bank state resolved at it, this one has only a block <em>name</em> a human
	 * wrote in a descriptor and no instruction to resolve against. Sharing code would require
	 * inventing a fake instruction here, or degrading that one to a descriptor-only derivation --
	 * which cannot work, because which occupant a read reaches is bank-state-dependent and the
	 * schema deliberately has no {@code on_read} key ({@code docs/smc-runfromelsewhere-design.md}
	 * section 8 open question 3). The naming here is the descriptor author's own statement of
	 * intent, and is the right and only available evidence on this path.
	 */
	private static Address resolveSource(Program program, AddressSpace baseSpace, String source,
			long sourceAddr) {
		MemoryBlock block = program.getMemory().getBlock(source);
		if (block != null && sourceAddr >= block.getStart().getOffset() &&
			sourceAddr <= block.getEnd().getOffset()) {
			return block.getStart().getAddressSpace().getAddress(sourceAddr);
		}
		return baseSpace.getAddress(sourceAddr);
	}

	/** An optional boolean directive key; absent means false. */
	private static boolean optionalFlag(JsonObject hint, String key) {
		return hint.has(key) && hint.get(key).getAsBoolean();
	}
}
