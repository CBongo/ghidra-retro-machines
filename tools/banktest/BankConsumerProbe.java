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
// Read-only diagnostic that measures the CONSUMER side of bank retargeting -- the half no
// other probe in tools/banktest looks at. Serves beads grm-8iy / grm-8iy.1.
//
// THE QUESTION. Six of the nineteen GME titles resolve ZERO instructions into overlay space
// (grm-8iy). Every existing probe measures the SWITCH-SITE side: BankReachProbe asks "is the
// latch store even seen?", HelperShapeProbe asks "does the call site reach a helper?".
// Neither can explain tmnt, which HAS three fully-known NON-HOME banks (c003 prg_bank=2,
// c340 prg_bank=7, c354 prg_bank=7, all in home mode 3 where the home bank is 0) and still
// retargets nothing. Those sites clear retargetReferences' home gate
// (BoardBankAnalyzer.java:2137) and produce no reference at all, so the failure is
// downstream of value recovery -- and invisible from the switch-site side.
//
// This probe measures what retargetReferences is actually handed: the population of
// references that point INTO a switchable window, bucketed by where their SOURCE
// instruction lives. retargetReferences (:2026) walks instr.getReferencesFrom() and only
// ever retargets a reference that already exists in the default space; a cross-bank
// dispatch that never materializes such a reference is structurally unreachable by it, no
// matter how good value recovery gets.
//
// THE CLASSES IT SEPARATES
//   WORKING -- refs.intoOverlay.retargeted > 0. The pipeline demonstrably produces overlay
//         references on this title, so whatever else the counters say, it is not stuck. Tested
//         FIRST: without it a healthy title scores STATE-UNCONSUMED, because "consumers exist"
//         and "walks reach consumers" are both true of a title that works.
//   INDIRECT-DISPATCH -- the ROM crosses the bank boundary only through computed jumps
//         (JMP (ptr) / RTS-trampolines). Those produce no base-space reference for
//         retargetReferences to retarget, so no amount of state recovery helps; the fix is
//         placement (grm-v60) or jump-table resolution, not dataflow. Signature: the headline
//         consumers.<switchable>.fromFixed.flow is 0 while control.fixedToFixed.flow is large
//         (the ROM makes plenty of DIRECT calls -- just never one across the boundary) and
//         indirect.unresolved is large.
//   VALUE-RECOVERY -- consumers exist, but walk.sites is 0: not ONE switch site in the whole
//         ROM recovered a fully-known NON-HOME bank, so there was never a non-home state for
//         retargetReferences to act on. This is upstream of anything consumer-side, and it is
//         what all six of grm-8iy's remaining zero-resolvers turned out to be.
//   STATE-UNCONSUMED -- non-home banks WERE recovered (walk.sites > 0) but none reaches a
//         consumer before the state is lost or the walk ends. Distinct from VALUE-RECOVERY:
//         here the value exists and the question is propagation (BankState.effective,
//         BankState.java:65, folds UNKNOWN bits to initialState, so "unknown" and "home" are
//         indistinguishable at the gate). Named STATE-LOST in the first draft; renamed because
//         "lost" implied it had once reached the consumer.
//   NO-CONSUMERS -- nothing references the switchable window at all; the finding is upstream of
//         banking entirely. Plus UNDECIDED.
//
//   BOARDS WITH NO FIXED WINDOW (AxROM: all of $8000-$FFFF is switchable) take a separate
//   branch. There, fromFixed.flow and control.fixedToFixed.flow are VACUOUSLY 0 -- "references
//   from the fixed window" is not a question that can be asked -- so the fixed-window tests are
//   skipped and headlineConsumersTotal carries the "are there consumers" signal instead. Before
//   that branch existed, wizwarr scored NO-CONSUMERS while actually having 873 consumers.
//
// WHY SECTION 1 PARSES THE DESCRIPTOR RATHER THAN THE BLOCK NAMES. On MMC1 the union of the
// realized overlay blocks is $8000-$FFFF, which cannot distinguish home-mode SWITCHABLE
// ($8000-$BFFF, prg_bank) from home-mode FIXED ($C000-$FFFF, "last") -- and that distinction
// IS the tmnt question. So the windows are derived from the descriptor (authoritative) and
// only CROSS-CHECKED against the realized blocks; a disagreement is reported as
// "blockcheck ... agree=NO" and never aborts the run.
//
// Emits a bounded block between
//   === BANKCONSUME BEGIN ===  /  === BANKCONSUME END ===
// with every line prefixed "BANKCONSUME ".
//
// COPYRIGHT POSTURE -- follows RealRomDump.java's rule (its header, ~:16-33): no ROM bytes
// and no disassembled instruction text. A reference's source instruction is described by a
// DERIVED srcKind=CALL|JUMP|BRANCH|IJUMP|LOAD|STORE|OTHER computed from
// instr.getFlowType() plus the RefType, never by its mnemonic or operand text. Section 4's
// "stackOps" count is likewise derived from the instruction's pcode-level register
// inputs/results (the 6502 SP/S registers), not from PLA/TSX text. The output is
// diagnostic-only and never reaches a golden: realrom-test.sh's awk carve (~:204) extracts
// only the REALROM block. (The SCRIPT is committed and documented -- it is its OUTPUT that
// never lands in an expected/*.dump.)
//
// USAGE (opt-in, alongside the normal dump):
//   REALROM_WORK_DIR=... REALROM_EXTRA_POSTSCRIPT=BankConsumerProbe.java \
//     bash tools/banktest/realrom-test.sh check --gme --only <ids> <romdir>
// Run it in its OWN invocation: the realrom cache key (~:121-131) hashes RealRomDump.java
// only, so a cached `check`/`bless` pair would silently skip the import this script needs.
//
// WHY THE HELPERS ARE RE-IMPLEMENTED HERE
// retromachines.DescriptorSupport (planWindows, referencedFields, OverlayNaming, the maps:
// expression parser) is package-private and this script is not in that package. Widening any
// of it would make a production class public FOREVER for the sake of a diagnostic, so the
// handful of helpers this probe needs are re-implemented privately below, each pinned by
// comment to the production line numbers it mirrors. The redundancy is a feature: an
// independent re-implementation means a DISAGREEMENT with production is itself a finding
// (that is exactly what the blockcheck lines report) rather than a silent shared bug.
//
// VERDICT THRESHOLDS (see also verdict.class below; every raw counter is emitted so a human
// can override the call):
//   "fromFixed.flow ~= 0"          -> == 0 exactly. One direct cross-boundary flow reference
//                                     is already a counterexample to INDIRECT-DISPATCH.
//   "control.fixedToFixed.flow     -> >= LARGE_CONTROL (16). Sixteen direct intra-fixed flow
//    large"                           references means the disassembly is real code, not a
//                                     handful of stubs.
//   "indirect.unresolved large"    -> >= LARGE_INDIRECT (4).
// Rules, applied in order (revised 2026-08-03 after the first grm-8iy campaign; see "THE
// CLASSES IT SEPARATES" above for why the first two tests exist):
//   retargeted > 0                                                   -> WORKING
//   no fixed home range  -> consumersTotal == 0 ? NO-CONSUMERS
//                         : walk.sites == 0     ? VALUE-RECOVERY
//                         : walk.sitesWithConsumer == 0 ? STATE-UNCONSUMED : UNDECIDED
//   fromFixed.flow == 0 && control >= 16 && indirect.unresolved >= 4 -> INDIRECT-DISPATCH
//   fromFixed.flow == 0 && control <  16                             -> NO-CONSUMERS
//   walk.sites == 0                                                  -> VALUE-RECOVERY
//   walk.sitesWithConsumer == 0                                      -> STATE-UNCONSUMED
//   otherwise                                                        -> UNDECIDED
//
// TWO PLACES WHERE THIS SCRIPT REFINES ITS OWN SPEC, both to keep the output bounded and
// honest, and both stated on a "note" line at run time:
//   * The "payload" reference list (emitted first and, budget permitting, in full) is
//     restricted to references whose TARGET lands in a home-mode SWITCHABLE range. The
//     unrestricted "srcBucket=FIXED flow=YES write=NO" population is every control-flow
//     reference in the fixed bank -- tens of thousands of lines on a real cartridge, and
//     already summarized exactly by control.fixedToFixed.flow.
//   * "blockcheck ... banksExpected" is derived from the descriptor's maps: expression
//     evaluated over the bank field's full value range, bounded by the largest slice any
//     REALIZED bank occupies (the image size is not recorded anywhere the program can be
//     asked for it). So it is a SHAPE check -- it catches holes, strays and naming
//     misparses (notably the W8000_M3_B7-read-as-mode-fixed trap that
//     OverlayNaming.parseModeBankValue exists to prevent) -- not an independent count.
//@category RetroMachines.Test

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class BankConsumerProbe extends GhidraScript {

	/**
	 * Cap on the payload reference sample -- references from the home-mode FIXED range INTO a
	 * home-mode SWITCHABLE range. These are the entire point of the probe (a nonzero count
	 * refutes INDIRECT-DISPATCH outright), so the cap is generous and they are emitted ahead
	 * of everything else, exactly as BankReachProbe emits its {@code today=NO} sites first.
	 * On the zero-resolver titles this list is expected to be short or empty.
	 */
	private static final int SAMPLE_PAYLOAD = 400;

	/**
	 * Cap on the NON-payload reference sample. This population is the whole reference graph
	 * of a real cartridge (tens of thousands of entries); it is emitted only so a human can
	 * eyeball the shape, and every question it could answer is answered exactly by the
	 * {@code count} lines below it.
	 */
	private static final int SAMPLE_REFS = 200;

	/** Cap on emitted {@code indirect} lines; the count lines still report full totals. */
	private static final int SAMPLE_INDIRECT = 200;

	/** Cap on emitted {@code switchsite} lines. Real ROMs have tens, not thousands. */
	private static final int SAMPLE_SITES = 200;

	/** Cap on emitted {@code walkref} lines across ALL walks. */
	private static final int SAMPLE_WALKREF = 200;

	/**
	 * Cap on the {@code verdict.hint} address list. A hint a human actually writes names a
	 * handful of addresses; a thousand-entry list is noise. Truncation is reported on its own
	 * {@code note} line so the number is never silently lost.
	 */
	private static final int HINT_MAX = 32;

	/**
	 * Instruction budget for one post-switch forward walk. The walk exists to answer "does a
	 * consumer of the newly-selected bank appear BEFORE the state is lost again?", which is a
	 * local question; a walk that runs 200 instructions without hitting the next switch site,
	 * an unknown-state bookmark or a function exit has already left the neighbourhood.
	 */
	private static final int WALK_STEP_CAP = 200;

	/** {@code control.fixedToFixed.flow} at or above this counts as "large" -- i.e. the fixed
	 *  bank really is disassembled code making direct calls, so a zero cross-boundary count is
	 *  a statement about the boundary and not about the disassembly. */
	private static final int LARGE_CONTROL = 16;

	/** {@code indirect.unresolved} at or above this counts as "large". */
	private static final int LARGE_INDIRECT = 4;

	/**
	 * Program-info property the loader stamps with the board's .map path
	 * (DescriptorSupport.MAP_PATH_PROPERTY -- kept as a literal here, exactly as
	 * RealRomDump.java:57-60 and BankReachProbe.java do, so this script needs no extension
	 * classes on its path; DescriptorSupport is package-private and unreachable from a script
	 * regardless).
	 */
	private static final String MAP_PATH_PROPERTY = "Retro Machine Map";

	/** Prefix of the WARNING bookmark text {@code BoardBankAnalyzer.annotateOrWarn} (:1439)
	 *  writes when a site pins down no tracked bit at all, and of the impossible-bank
	 *  diagnostic ({@code ImpossibleBank.message}); both mean "state is gone from here on",
	 *  which is exactly what stops a post-switch walk. */
	private static final String UNKNOWN_BOOKMARK_PREFIX = "Bank state becomes unknown here:";

	/** {@code [known: <bits>; assumed from initial: <bits>]}, the partial-state tail
	 *  {@code annotateBankSwitch} (:1617, tail built at :1650-1672) appends. */
	private static final Pattern KNOWN_ASSUMED =
		Pattern.compile("\\[known: (.*?); assumed from initial: (.*?)\\]");

	/** {@code <field>=<value>,<field>=<value>,...} -- the packed-tuple head form
	 *  {@code annotateBankSwitch} uses on a multi-field computed board (:1640-1647). */
	private static final Pattern TUPLE_HEAD =
		Pattern.compile("[A-Za-z_]\\w*=\\d+(,[A-Za-z_]\\w*=\\d+)*");

	/** {@code <effective> (<description>)} -- the head form on enumerated and single-field
	 *  computed boards (:1640-1647). */
	private static final Pattern VALUE_HEAD = Pattern.compile("(\\d+) \\((.*)\\)");

	// ------------------------------------------------------------------
	// Model
	// ------------------------------------------------------------------

	/**
	 * One {@code banking.state[]} field. Bit offsets are assigned cumulatively LSB-first
	 * (field i's lsb is the sum of the widths of fields 0..i-1), pinned to
	 * BoardBankAnalyzer.java:2379-2397 -- {@code new FieldSpec(fieldName, stateBitNames.size(),
	 * bits)} inside the {@code banking.state} loop, where {@code stateBitNames.size()} IS that
	 * running sum. The per-bit names built alongside it there ({@code name} for a 1-bit field,
	 * {@code name.0 .. name.<w-1>} otherwise) are what the partial-state comment's
	 * "assumed from initial" list is written in, so {@link #bitNames} reproduces them exactly.
	 */
	private static final class Field {
		final String name;
		final int lsb;
		final int width;
		final int home;

		Field(String name, int lsb, int width, int initialState) {
			this.name = name;
			this.lsb = lsb;
			this.width = width;
			this.home = valueIn(initialState);
		}

		int valueIn(int state) {
			return (state >>> lsb) & ((1 << width) - 1);
		}

		/** Mirrors BoardBankAnalyzer.java:2386-2394. */
		List<String> bitNames() {
			List<String> names = new ArrayList<>();
			if (width == 1) {
				names.add(name);
			}
			else {
				for (int i = 0; i < width; i++) {
					names.add(name + "." + i);
				}
			}
			return names;
		}
	}

	/**
	 * One window instance from the descriptor: a top-level {@code windows[]} entry
	 * ({@code mode == null}), a layout window hoisted because every layout defines it
	 * identically ({@code mode == null}), or one {@code (name, mode)} pair of a mode-varying
	 * window. Mirrors DescriptorSupport.PlannedWindow plus the SWITCHABLE/FIXED ruling
	 * BoardBankAnalyzer.BoardModel.parse makes from {@code referencedFields(expr)}
	 * (:2434-2440 for invariant windows, :2476-2498 for varying ones).
	 */
	private static final class Instance {
		final String window;
		final Integer mode;
		final long start;
		final long end;
		final String expr;
		final String onWrite;
		final Field bankField; // null => FIXED instance

		Instance(String window, Integer mode, long start, long end, String expr, String onWrite,
				Field bankField) {
			this.window = window;
			this.mode = mode;
			this.start = start;
			this.end = end;
			this.expr = expr;
			this.onWrite = onWrite;
			this.bankField = bankField;
		}

		boolean switchable() {
			return bankField != null;
		}

		boolean covers(long offset) {
			return offset >= start && offset <= end;
		}

		boolean pokeOnWrite() {
			return "mechanism".equals(onWrite);
		}
	}

	/** How a base-space range behaves under the HOME mode. */
	private enum HomeKind {
		SWITCHABLE, FIXED, NONE
	}

	/**
	 * One atomic base-space offset range -- a maximal interval over which every window
	 * instance's coverage is constant, so the SWITCHABLE/FIXED verdict is well defined for
	 * every mode at once. Built by cutting the union of all instance extents at every
	 * instance boundary; on MMC1 that yields exactly $8000-$BFFF and $C000-$FFFF, which is
	 * the split the whole probe exists to expose.
	 */
	private static final class Range {
		final long lo;
		final long hi;
		final Set<Integer> switchableModes = new TreeSet<>();
		final Set<Integer> fixedModes = new TreeSet<>();
		HomeKind homeKind = HomeKind.NONE;
		String homeWindow = "NONE";
		Field homeBankField;
		boolean pokeOnWrite;

		long total;
		long flow;
		long call;
		long data;
		long write;
		long fromFixed;
		long fromFixedFlow;
		long fromFixedNonPoke;
		long fromSwitchable;
		long fromRam;
		long reachable;
		long unreachable;

		Range(long lo, long hi) {
			this.lo = lo;
			this.hi = hi;
		}

		boolean covers(long offset) {
			return offset >= lo && offset <= hi;
		}

		String key() {
			return off(lo) + "-" + off(hi);
		}
	}

	/** One reference, fully classified. */
	private static final class Ref {
		Address src;
		String srcSpace;
		String srcBucket;
		long dst;
		String dstRange;
		String type;
		boolean flow;
		boolean call;
		boolean write;
		boolean primary;
		boolean reach;
		String func;
		String kind;
		boolean payload;

		String render() {
			return "ref " + off(src.getOffset()) + " srcSpace=" + srcSpace + " srcBucket=" +
				srcBucket + " dst=" + off(dst) + " dstRange=" + dstRange + " type=" + type +
				" flow=" + yn(flow) + " call=" + yn(call) + " write=" + yn(write) + " primary=" +
				yn(primary) + " reach=" + yn(reach) + " func=" + func + " srcKind=" + kind;
		}
	}

	/** One parsed {@code bank ->} EOL comment. */
	private static final class SwitchSite {
		Address at;
		String tuple;
		Map<String, Integer> values = new LinkedHashMap<>();
		Set<String> knownFields = new LinkedHashSet<>();
		String via = "NONE";
		boolean bankKnown;
		int bank = -1;
		boolean modeKnown;
		int mode = -1;
		boolean nonhome;
	}

	// ------------------------------------------------------------------
	// State shared by the sections
	// ------------------------------------------------------------------

	private Program program;
	private Listing listing;
	private Memory memory;
	private AddressSpace defaultSpace;

	private final List<Field> fields = new ArrayList<>();
	private final List<Instance> instances = new ArrayList<>();
	private final List<Range> ranges = new ArrayList<>();
	private final Set<Integer> allModes = new TreeSet<>();
	private final Map<Long, String> regionKindByOffset = new HashMap<>();
	private Field modeField;
	private int homeMode;
	private int initialState;

	// ------------------------------------------------------------------
	// Entry point
	// ------------------------------------------------------------------

	@Override
	protected void run() throws Exception {
		// The fence is opened and closed unconditionally, and every failure inside becomes a
		// "BANKCONSUME error" line: a stack trace escaping run() would leave headless emitting a
		// half-open block that the caller's carve cannot interpret.
		println("=== BANKCONSUME BEGIN ===");
		try {
			probe();
		}
		catch (Exception e) {
			println("BANKCONSUME error " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		println("=== BANKCONSUME END ===");
	}

	private void probe() throws Exception {
		program = currentProgram;
		listing = program.getListing();
		memory = program.getMemory();
		defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

		String sha = program.getExecutableSHA256();
		String mapPath = program.getOptions(Program.PROGRAM_INFO).getString(MAP_PATH_PROPERTY, null);

		println("BANKCONSUME program " + program.getName());
		println("BANKCONSUME sha256 " + (sha == null ? "NONE" : sha));
		println("BANKCONSUME map " + (mapPath == null ? "NONE" : mapPath));

		if (mapPath == null || mapPath.isBlank()) {
			println("BANKCONSUME error no '" + MAP_PATH_PROPERTY + "' property -- this program was " +
				"not imported by a RetroMachines loader, so there is no board to probe");
			return;
		}

		JsonObject root;
		try {
			root = loadDescriptor(mapPath);
		}
		catch (Exception e) {
			println("BANKCONSUME error descriptor " + mapPath + ": " + e.getClass().getSimpleName() +
				": " + e.getMessage());
			return;
		}

		println("BANKCONSUME note payload.scope the full 'ref' list below is restricted to " +
			"references whose TARGET lands in a home-mode SWITCHABLE range; the unrestricted " +
			"srcBucket=FIXED flow population is every control-flow reference in the fixed bank " +
			"and is summarized exactly by control.fixedToFixed.flow");

		section1(root);
		Set<Address> reached = reachableSet();
		Section2 refs = section2(reached);
		Section3 indirect = section3(reached);
		Section4 walks = section4(reached);
		section5(refs, indirect, walks);
	}

	// ==================================================================
	// Section 1 -- board / window derivation
	// ==================================================================

	private void section1(JsonObject root) throws Exception {
		JsonObject banking = root.has("banking") ? root.getAsJsonObject("banking") : null;
		if (banking == null || !banking.has("initial_state")) {
			println("BANKCONSUME error descriptor has no banking.initial_state; " +
				"no window derivation is possible");
			return;
		}
		initialState = banking.get("initial_state").getAsInt();

		// --- fields: cumulative LSB-first, pinned to BoardBankAnalyzer.java:2379-2397 ---
		int lsb = 0;
		if (banking.has("state")) {
			for (JsonElement fe : banking.getAsJsonArray("state")) {
				JsonObject f = fe.getAsJsonObject();
				String name = f.get("name").getAsString();
				int bits = f.get("bits").getAsInt();
				fields.add(new Field(name, lsb, bits, initialState));
				lsb += bits;
			}
		}
		for (Field f : fields) {
			println("BANKCONSUME field " + f.name + " lsb=" + f.lsb + " width=" + f.width + " home=" +
				f.home);
		}

		// --- regions[]: the descriptor's own RAM/IO classification, used to bucket a
		// reference source that falls outside every window range (better than guessing from
		// block permissions, which the loader sets for its own reasons).
		if (root.has("regions")) {
			for (JsonElement re : root.getAsJsonArray("regions")) {
				JsonObject r = re.getAsJsonObject();
				if (!r.has("start") || !r.has("kind")) {
					continue;
				}
				long start = r.get("start").getAsLong();
				long end = r.has("end") ? r.get("end").getAsLong()
						: start + r.get("size").getAsLong() - 1;
				String kind = "io".equals(r.get("kind").getAsString()) ? "IO" : "RAM";
				for (long o = start; o <= end; o++) {
					regionKindByOffset.put(o, kind);
				}
			}
		}

		// --- window plan (re-implements DescriptorSupport.planWindows, :920-983) ----
		List<PlannedWindow> planned = planWindows(root);
		String modeFieldName = plannedModeField;
		modeField = modeFieldName == null ? null : fieldByName(modeFieldName);
		homeMode = modeField == null ? 0 : modeField.valueIn(initialState);
		println("BANKCONSUME modefield " + (modeField == null ? "NONE" : modeField.name) + " home=" +
			(modeField == null ? "NONE" : String.valueOf(homeMode)));

		for (PlannedWindow pw : planned) {
			if (pw.mode != null) {
				allModes.add(pw.mode);
			}
			Field bankField = null;
			if (pw.expr != null) {
				Set<String> referenced = referencedFields(pw.expr);
				if (modeField != null) {
					referenced.remove(modeField.name);
				}
				if (referenced.size() > 1) {
					println("BANKCONSUME note window.multifield " + pw.name + " mode=" +
						(pw.mode == null ? "NONE" : pw.mode) + " references " +
						String.join(",", referenced) +
						"; production does not support multi-field windows and skips the instance");
				}
				else if (referenced.size() == 1) {
					bankField = fieldByName(referenced.iterator().next());
				}
			}
			instances.add(
				new Instance(pw.name, pw.mode, pw.start, pw.end, pw.expr, pw.onWrite, bankField));
		}
		if (modeField != null && allModes.isEmpty()) {
			allModes.add(homeMode);
		}
		for (Instance in : instances) {
			println("BANKCONSUME instance window=" + in.window + " mode=" +
				(in.mode == null ? "NONE" : in.mode) + " start=" + off(in.start) + " end=" +
				off(in.end) + " kind=" + (in.switchable() ? "SWITCHABLE" : "FIXED") + " bankfield=" +
				(in.bankField == null ? "NONE" : in.bankField.name));
		}

		buildRanges();
		for (Range r : ranges) {
			println("BANKCONSUME range " + r.key() + " switchable.modes=" +
				renderModes(r.switchableModes) + " fixed.modes=" + renderModes(r.fixedModes) +
				" home=" + r.homeKind + " homeBankField=" +
				(r.homeBankField == null ? "NONE" : r.homeBankField.name) + " homeBank=" +
				(r.homeBankField == null ? "NONE" : String.valueOf(r.homeBankField.home)));
		}

		blockCheck();
	}

	/**
	 * Cuts the union of every instance's extent at every instance boundary, producing atomic
	 * ranges over which the per-mode SWITCHABLE/FIXED verdict is constant, then tags each with
	 * which modes make it switchable/fixed and what the HOME mode does with it. A
	 * mode-invariant instance (top-level {@code windows[]} or a hoisted layout window) counts
	 * for every mode, and for the home mode when the board has no mode field at all.
	 */
	private void buildRanges() {
		TreeSet<Long> cuts = new TreeSet<>();
		for (Instance in : instances) {
			cuts.add(in.start);
			cuts.add(in.end + 1);
		}
		List<Long> bounds = new ArrayList<>(cuts);
		for (int i = 0; i + 1 < bounds.size(); i++) {
			long lo = bounds.get(i);
			long hi = bounds.get(i + 1) - 1;
			boolean covered = false;
			for (Instance in : instances) {
				if (in.covers(lo)) {
					covered = true;
					break;
				}
			}
			if (!covered) {
				continue;
			}
			Range r = new Range(lo, hi);
			for (Instance in : instances) {
				if (!in.covers(lo)) {
					continue;
				}
				Set<Integer> modes = in.mode == null ? allModes : Set.of(in.mode);
				if (in.switchable()) {
					r.switchableModes.addAll(modes);
				}
				else {
					r.fixedModes.addAll(modes);
				}
				boolean isHome = in.mode == null || in.mode == homeMode;
				if (isHome) {
					r.homeKind = in.switchable() ? HomeKind.SWITCHABLE : HomeKind.FIXED;
					r.homeWindow = in.window;
					r.homeBankField = in.bankField;
					r.pokeOnWrite = in.pokeOnWrite();
				}
			}
			ranges.add(r);
		}
	}

	private String renderModes(Set<Integer> modes) {
		if (modeField == null) {
			return modes.isEmpty() ? "NONE" : "ALL";
		}
		if (modes.isEmpty()) {
			return "NONE";
		}
		if (modes.containsAll(allModes)) {
			return "ALL";
		}
		List<String> parts = new ArrayList<>();
		for (Integer m : modes) {
			parts.add(String.valueOf(m));
		}
		return String.join(",", parts);
	}

	/**
	 * Cross-checks each derived instance against the overlay blocks the loader actually
	 * realized. Honours OverlayNaming's contract (DescriptorSupport.java:1118-1124) that a
	 * {@code <w>_M<m>_B<v>} name must FAIL the plain {@code <w>_M<m>} parse -- otherwise
	 * {@code W8000_M3_B7} is misread as a mode-fixed instance and the home-mode switchable
	 * window silently reports one realized bank instead of eight.
	 * <p>
	 * {@code banksExpected} is the descriptor's own statement, obtained by evaluating the
	 * instance's {@code maps.expr} over the bank field's full value range and keeping the
	 * values whose slice fits below the highest slice any realized bank occupies (see the file
	 * header for why the image size cannot be asked for directly). Never aborts: a mismatch is
	 * reported as {@code agree=NO} and the rest of the probe carries on.
	 */
	private void blockCheck() {
		Set<String> spaceNames = new LinkedHashSet<>();
		for (AddressSpace s : program.getAddressFactory().getAllAddressSpaces()) {
			if (s.isOverlaySpace()) {
				spaceNames.add(s.getName());
			}
		}
		for (Instance in : instances) {
			String modeText = in.mode == null ? "NONE" : String.valueOf(in.mode);
			int realized;
			int expected;
			if (!in.switchable()) {
				// A fixed instance is realized as exactly one thing: the base-space block when it
				// is the home instance, or one <window>_M<mode> overlay otherwise.
				boolean isHome = in.mode == null || in.mode == homeMode;
				realized = isHome ? 1 : 0;
				for (String name : spaceNames) {
					Integer m = parseModeValue(in.window, name);
					if (m != null && in.mode != null && m.intValue() == in.mode.intValue()) {
						realized++;
					}
				}
				expected = 1;
			}
			else {
				Set<Integer> banks = new TreeSet<>();
				boolean homeInstance =
					in.mode == null ? true : (modeField != null && in.mode == homeMode);
				if (homeInstance) {
					banks.add(in.bankField.home); // lives in base space, not as an overlay
				}
				for (String name : spaceNames) {
					if (in.mode == null) {
						Integer v = parseBankValue(in.window, name);
						if (v != null) {
							banks.add(v);
						}
					}
					else {
						int[] mb = parseModeBankValue(in.window, name);
						if (mb != null && mb[0] == in.mode) {
							banks.add(mb[1]);
						}
					}
				}
				realized = banks.size();
				expected = expectedBanks(in, banks);
			}
			println("BANKCONSUME blockcheck window=" + in.window + " mode=" + modeText +
				" banksRealized=" + realized + " banksExpected=" + expected + " agree=" +
				(realized == expected ? "YES" : "NO"));
		}
	}

	/**
	 * The number of bank values the descriptor's expression can place, bounded by the largest
	 * slice any realized bank occupies. Returns the realized count itself (so {@code agree=YES})
	 * only when the expression genuinely admits exactly that many values; an unevaluatable
	 * expression yields -1, which reports as a disagreement rather than a fabricated match.
	 */
	private int expectedBanks(Instance in, Set<Integer> realized) {
		if (in.expr == null || realized.isEmpty()) {
			return -1;
		}
		long windowSize = in.end - in.start + 1;
		long bound = -1;
		for (Integer v : realized) {
			Long slice = evalExpr(in.expr, in.bankField.name, v);
			if (slice == null) {
				return -1;
			}
			bound = Math.max(bound, slice + windowSize);
		}
		int count = 0;
		int limit = 1 << in.bankField.width;
		for (int v = 0; v < limit; v++) {
			Long slice = evalExpr(in.expr, in.bankField.name, v);
			if (slice == null) {
				return -1;
			}
			if (slice >= 0 && slice + windowSize <= bound) {
				count++;
			}
		}
		return count;
	}

	// ==================================================================
	// Section 2 -- consumer census
	// ==================================================================

	private static final class Section2 {
		long refsTotal;
		long refsFromBase;
		long intoOverlayTotal;
		long intoOverlayRetargeted;
		long intoOverlayIntra;
		long controlFixedToFixedFlow;
		long headlineFromFixedFlow;
		long headlineFromFixedNonPoke;
		/** Every consumer of the home-switchable range, whatever bucket it came from. On a board
		 *  with no fixed window (AxROM: the whole space is switchable) the fromFixed counters are
		 *  vacuously 0, so this is the only honest "are there consumers" signal there. */
		long headlineConsumersTotal;
		/** Whether ANY range is fixed under the home mode. False on AxROM/BNROM-style boards. */
		boolean hasFixedHomeRange;
	}

	private Section2 section2(Set<Address> reached) throws Exception {
		Section2 out = new Section2();
		// From the DESCRIPTOR, not from whether a reference happened to land in a fixed range:
		// a board can have a fixed window that nothing references, and that is still not the
		// same board shape as AxROM, which has no fixed window to reference.
		for (Range r : ranges) {
			if (r.homeKind == HomeKind.FIXED) {
				out.hasFixedHomeRange = true;
				break;
			}
		}
		List<Ref> payload = new ArrayList<>();
		List<Ref> rest = new ArrayList<>();

		InstructionIterator instrs = listing.getInstructions(true);
		while (instrs.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrs.next();
			Reference[] from = instr.getReferencesFrom();
			if (from.length == 0) {
				continue;
			}
			Address at = instr.getMinAddress();
			boolean srcInOverlay = at.getAddressSpace().isOverlaySpace();
			String bucket = bucketOf(at.getOffset());
			Function containing = program.getFunctionManager().getFunctionContaining(at);
			boolean reach = reached.contains(at);

			for (Reference reference : from) {
				out.refsTotal++;
				if (!srcInOverlay) {
					out.refsFromBase++;
				}
				AddressSpace toSpace = reference.getToAddress().getAddressSpace();
				// Reproduces RealRomDump.java:107-115 exactly, so the total is cross-checkable
				// against "REALROM count refs.intoOverlay" in the committed golden.
				if (toSpace.isOverlaySpace()) {
					out.intoOverlayTotal++;
					if (srcInOverlay) {
						out.intoOverlayIntra++;
					}
					else {
						out.intoOverlayRetargeted++;
					}
				}

				RefType rt = reference.getReferenceType();
				Ref r = new Ref();
				r.src = at;
				r.srcSpace = at.getAddressSpace().getName();
				r.srcBucket = bucket;
				r.dst = reference.getToAddress().getOffset();
				r.type = rt.getName();
				r.flow = rt.isFlow();
				r.call = rt.isCall();
				r.write = rt.isWrite();
				r.primary = reference.isPrimary();
				r.reach = reach;
				r.func = containing == null ? "NONE" : containing.getName();
				r.kind = srcKind(instr, rt);

				Range target = rangeAt(r.dst);
				r.dstRange = target == null ? "NONE" : target.key();
				if (target != null) {
					boolean poke = r.write && target.pokeOnWrite;
					target.total++;
					if (r.flow) {
						target.flow++;
					}
					else {
						target.data++;
					}
					if (r.call) {
						target.call++;
					}
					if (r.write) {
						target.write++;
					}
					if ("FIXED".equals(bucket)) {
						target.fromFixed++;
						if (r.flow) {
							target.fromFixedFlow++;
						}
						if (!poke) {
							target.fromFixedNonPoke++;
						}
					}
					else if ("SWITCHABLE".equals(bucket)) {
						target.fromSwitchable++;
					}
					else if ("RAM".equals(bucket)) {
						target.fromRam++;
					}
					if (reach) {
						target.reachable++;
					}
					else {
						target.unreachable++;
					}
					if (target.homeKind == HomeKind.FIXED && "FIXED".equals(bucket) && r.flow) {
						out.controlFixedToFixedFlow++;
					}
					if (target.homeKind == HomeKind.SWITCHABLE) {
						out.headlineConsumersTotal++;
					}
					if (target.homeKind == HomeKind.SWITCHABLE && "FIXED".equals(bucket)) {
						r.payload = true;
						if (r.flow) {
							out.headlineFromFixedFlow++;
						}
						if (!poke) {
							out.headlineFromFixedNonPoke++;
						}
					}
				}
				(r.payload ? payload : rest).add(r);
			}
		}

		// Payload first and (budget permitting) in full, exactly as BankReachProbe emits its
		// today=NO sites ahead of everything else; within the payload, flow references that are
		// not latch pokes lead, because those are the ones retargetReferences should have caught.
		Comparator<Ref> payloadOrder = (a, b) -> {
			int c = Boolean.compare(!a.flow || a.write, !b.flow || b.write);
			if (c != 0) {
				return c;
			}
			c = a.src.compareTo(b.src);
			return c != 0 ? c : Long.compare(a.dst, b.dst);
		};
		payload.sort(payloadOrder);
		rest.sort((a, b) -> {
			int c = a.src.compareTo(b.src);
			return c != 0 ? c : Long.compare(a.dst, b.dst);
		});
		emitCapped(payload, SAMPLE_PAYLOAD, "refs.payload.truncated");
		emitCapped(rest, SAMPLE_REFS, "refs.other.truncated");

		println("BANKCONSUME count refs.total " + out.refsTotal);
		println("BANKCONSUME count refs.fromBaseSpace " + out.refsFromBase);
		println("BANKCONSUME count refs.intoOverlay.total " + out.intoOverlayTotal);
		println("BANKCONSUME count refs.intoOverlay.retargeted " + out.intoOverlayRetargeted);
		println("BANKCONSUME count refs.intoOverlay.intraOverlay " + out.intoOverlayIntra);
		for (Range r : ranges) {
			String p = "count consumers." + r.key() + ".";
			println("BANKCONSUME " + p + "total " + r.total);
			println("BANKCONSUME " + p + "flow " + r.flow);
			println("BANKCONSUME " + p + "call " + r.call);
			println("BANKCONSUME " + p + "data " + r.data);
			println("BANKCONSUME " + p + "write " + r.write);
			println("BANKCONSUME " + p + "fromFixed " + r.fromFixed);
			println("BANKCONSUME " + p + "fromFixed.flow " + r.fromFixedFlow);
			println("BANKCONSUME " + p + "fromSwitchable " + r.fromSwitchable);
			println("BANKCONSUME " + p + "fromRam " + r.fromRam);
			println("BANKCONSUME " + p + "reachable " + r.reachable);
			println("BANKCONSUME " + p + "unreachable " + r.unreachable);
		}
		println("BANKCONSUME count control.fixedToFixed.flow " + out.controlFixedToFixedFlow);
		return out;
	}

	private void emitCapped(List<Ref> refs, int cap, String noteKey) {
		int shown = Math.min(cap, refs.size());
		for (int i = 0; i < shown; i++) {
			println("BANKCONSUME " + refs.get(i).render());
		}
		if (shown < refs.size()) {
			println("BANKCONSUME note " + noteKey + " " + (refs.size() - shown) +
				" further reference(s) omitted (cap " + cap + ")");
		}
	}

	// ==================================================================
	// Section 3 -- indirect-dispatch census
	// ==================================================================

	private static final class Section3 {
		long total;
		long inFixed;
		long unresolved;
		long resolvedIntoSwitchable;
		final List<String> hint = new ArrayList<>();
	}

	private Section3 section3(Set<Address> reached) throws Exception {
		Section3 out = new Section3();
		List<String> lines = new ArrayList<>();
		InstructionIterator instrs = listing.getInstructions(true);
		while (instrs.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrs.next();
			FlowType ft = instr.getFlowType();
			// Classified off the FlowType only -- never off the mnemonic, per the copyright
			// posture in the file header.
			if (!ft.isComputed()) {
				continue;
			}
			Address at = instr.getMinAddress();
			String kind = ft.isCall() ? "ICALL" : ft.isJump() ? "IJUMP" : "COMPUTED";
			Address[] flows = instr.getFlows();
			out.total++;
			boolean inFixed = "FIXED".equals(bucketOf(at.getOffset()));
			if (inFixed) {
				out.inFixed++;
			}
			if (flows.length == 0) {
				out.unresolved++;
				if (inFixed) {
					out.hint.add(off(at.getOffset()));
				}
			}
			else {
				for (Address f : flows) {
					Range r = rangeAt(f.getOffset());
					if (r != null && r.homeKind == HomeKind.SWITCHABLE) {
						out.resolvedIntoSwitchable++;
						break;
					}
				}
			}
			Function containing = program.getFunctionManager().getFunctionContaining(at);
			lines.add("indirect " + off(at.getOffset()) + " space=" +
				at.getAddressSpace().getName() + " kind=" + kind + " flows=" + flows.length +
				" reach=" + yn(reached.contains(at)) + " func=" +
				(containing == null ? "NONE" : containing.getName()));
		}
		int shown = Math.min(SAMPLE_INDIRECT, lines.size());
		for (int i = 0; i < shown; i++) {
			println("BANKCONSUME " + lines.get(i));
		}
		if (shown < lines.size()) {
			println("BANKCONSUME note indirect.truncated " + (lines.size() - shown) +
				" further site(s) omitted (cap " + SAMPLE_INDIRECT + ")");
		}
		println("BANKCONSUME count indirect.total " + out.total);
		println("BANKCONSUME count indirect.inFixed " + out.inFixed);
		println("BANKCONSUME count indirect.unresolved " + out.unresolved);
		println("BANKCONSUME count indirect.resolvedIntoSwitchable " + out.resolvedIntoSwitchable);
		return out;
	}

	// ==================================================================
	// Section 4 -- post-switch forward walk
	// ==================================================================

	private static final class Section4 {
		long sites;
		long sitesWithConsumer;
		long consumers;
		final List<String> hint = new ArrayList<>();
	}

	private Section4 section4(Set<Address> reached) throws Exception {
		Section4 out = new Section4();

		// Every address production annotated, and every address at which it declared the state
		// lost -- the two things a forward walk must stop at. Collected first so a walk can test
		// membership in O(1).
		Set<Address> switchAddrs = new LinkedHashSet<>();
		Set<Address> unknownAddrs = new LinkedHashSet<>();
		List<SwitchSite> sites = new ArrayList<>();
		List<String> siteLines = new ArrayList<>();

		InstructionIterator instrs = listing.getInstructions(true);
		while (instrs.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrs.next();
			Address at = instr.getMinAddress();
			for (Bookmark bm : program.getBookmarkManager().getBookmarks(at)) {
				if (bm.getComment() != null && bm.getComment().startsWith(UNKNOWN_BOOKMARK_PREFIX)) {
					unknownAddrs.add(at);
					break;
				}
			}
			String eol = listing.getComment(CommentType.EOL, at);
			if (eol == null || !eol.contains("bank ->")) {
				continue;
			}
			switchAddrs.add(at);
			SwitchSite site = parseSwitchComment(at, eol);
			if (site == null) {
				println("BANKCONSUME error comment.unparsed " + off(at.getOffset()));
				continue;
			}
			sites.add(site);
		}

		Range homeSwitch = homeSwitchableRange();
		Field bankField = homeSwitch == null ? null : homeSwitch.homeBankField;
		for (SwitchSite s : sites) {
			if (bankField != null) {
				Integer v = s.values.get(bankField.name);
				s.bankKnown = v != null && s.knownFields.contains(bankField.name);
				s.bank = v == null ? -1 : v;
			}
			if (modeField != null) {
				Integer m = s.values.get(modeField.name);
				s.modeKnown = m != null && s.knownFields.contains(modeField.name);
				s.mode = m == null ? -1 : m;
			}
			s.nonhome = (s.bankKnown && bankField != null && s.bank != bankField.home) ||
				(s.modeKnown && s.mode != homeMode);
			siteLines.add("switchsite " + off(s.at.getOffset()) + " space=" +
				s.at.getAddressSpace().getName() + " state=" + s.tuple + " bankKnown=" +
				yn(s.bankKnown) + " bank=" + (s.bank < 0 ? "NONE" : String.valueOf(s.bank)) +
				" home=" + (bankField == null ? "NONE" : String.valueOf(bankField.home)) +
				" nonhome=" + yn(s.nonhome) + " via=" + s.via);
		}
		int shownSites = Math.min(SAMPLE_SITES, siteLines.size());
		for (int i = 0; i < shownSites; i++) {
			println("BANKCONSUME " + siteLines.get(i));
		}
		if (shownSites < siteLines.size()) {
			println("BANKCONSUME note switchsite.truncated " + (siteLines.size() - shownSites) +
				" further site(s) omitted (cap " + SAMPLE_SITES + ")");
		}

		List<String> walkRefs = new ArrayList<>();
		for (SwitchSite s : sites) {
			monitor.checkCancelled();
			if (!s.nonhome || !(s.bankKnown || s.modeKnown)) {
				continue;
			}
			out.sites++;
			out.hint.add(off(s.at.getOffset()));
			Walk w = walk(s.at, switchAddrs, unknownAddrs);
			out.consumers += w.consumers.size();
			if (!w.consumers.isEmpty()) {
				out.sitesWithConsumer++;
			}
			println("BANKCONSUME walk " + off(s.at.getOffset()) + " steps=" + w.steps + " stop=" +
				w.stop + " consumers=" + w.consumers.size() + " firstConsumer=" +
				(w.consumers.isEmpty() ? "NONE" : off(w.consumers.get(0).srcOff)) + " firstType=" +
				(w.consumers.isEmpty() ? "NONE" : w.consumers.get(0).type) + " indirectSeen=" +
				w.indirectSeen + " callsSeen=" + w.callsSeen + " retsSeen=" + w.retsSeen);
			for (WalkRef wr : w.consumers) {
				walkRefs.add("walkref " + off(s.at.getOffset()) + " src=" + off(wr.srcOff) +
					" dst=" + off(wr.dst) + " type=" + wr.type + " dist=" + wr.dist);
			}
		}
		int shownWalkRefs = Math.min(SAMPLE_WALKREF, walkRefs.size());
		for (int i = 0; i < shownWalkRefs; i++) {
			println("BANKCONSUME " + walkRefs.get(i));
		}
		if (shownWalkRefs < walkRefs.size()) {
			println("BANKCONSUME note walkref.truncated " + (walkRefs.size() - shownWalkRefs) +
				" further reference(s) omitted (cap " + SAMPLE_WALKREF + ")");
		}
		println("BANKCONSUME count walk.sites " + out.sites);
		println("BANKCONSUME count walk.sitesWithConsumer " + out.sitesWithConsumer);

		emitHelperShapes(sites);
		return out;
	}

	/**
	 * Parses one {@code bank ->} EOL comment against the contract
	 * {@link ghidra.program.model.listing.Listing}-side production writes in
	 * BoardBankAnalyzer.annotateBankSwitch (declared :1617; head forms built :1636-1647,
	 * fully-known form :1649, partial form and its {@code [known: ...; assumed from initial:
	 * ...]} tail :1650-1673, the {@code [switch-value flow]} provenance tag :1674-1680) and
	 * annotatePlacementProvenance ({@code [user override]}, :1691). Returns null when the text
	 * does not match any of those forms, which the caller reports as
	 * {@code error comment.unparsed} -- never a silent skip.
	 * <p>
	 * Per-field known-ness comes from the ASSUMED list, not the known list: production emits
	 * one entry per tracked BIT, so a field is fully known exactly when none of its bit names
	 * ({@code name} for a 1-bit field, {@code name.0 .. name.<w-1>} otherwise -- see
	 * {@link Field#bitNames}) appears among the assumed bits.
	 */
	private SwitchSite parseSwitchComment(Address at, String eol) {
		int idx = eol.indexOf("bank -> ");
		if (idx < 0) {
			return null;
		}
		String s = eol.substring(idx + "bank -> ".length());

		SwitchSite site = new SwitchSite();
		site.at = at;

		int viaIdx = s.indexOf(" via ");
		if (viaIdx >= 0) {
			int end = s.indexOf(' ', viaIdx + 5);
			site.via = end < 0 ? s.substring(viaIdx + 5) : s.substring(viaIdx + 5, end);
		}
		int tagIdx = s.indexOf(" [");
		int cut = s.length();
		if (viaIdx >= 0) {
			cut = Math.min(cut, viaIdx);
		}
		if (tagIdx >= 0) {
			cut = Math.min(cut, tagIdx);
		}
		String head = s.substring(0, cut).trim();
		boolean partial = head.indexOf('?') >= 0;
		head = head.replace("?", "");
		site.tuple = head.replace(' ', '_');

		if (s.contains("[user override]")) {
			// A placement override, not a recovered switch: the head is a bare bank index and no
			// field tuple exists. Recorded so the site is visible, but never walked (no field is
			// known), and never silently dropped.
			site.knownFields.clear();
			return site;
		}

		Matcher tuple = TUPLE_HEAD.matcher(head);
		if (tuple.matches()) {
			for (String part : head.split(",")) {
				int eq = part.indexOf('=');
				if (eq < 0) {
					return null;
				}
				String name = part.substring(0, eq);
				if (fieldByName(name) == null) {
					return null; // a field name this descriptor does not declare
				}
				try {
					site.values.put(name, Integer.parseInt(part.substring(eq + 1)));
				}
				catch (NumberFormatException e) {
					return null;
				}
			}
		}
		else {
			Matcher value = VALUE_HEAD.matcher(head);
			if (!value.matches()) {
				return null;
			}
			int effective;
			try {
				effective = Integer.parseInt(value.group(1));
			}
			catch (NumberFormatException e) {
				return null;
			}
			for (Field f : fields) {
				site.values.put(f.name, f.valueIn(effective));
			}
		}

		if (!partial) {
			for (String name : site.values.keySet()) {
				site.knownFields.add(name);
			}
			return site;
		}
		Matcher m = KNOWN_ASSUMED.matcher(s);
		if (!m.find()) {
			return null; // a "?" with no [known: ...] tail is not a form production emits
		}
		Set<String> assumed = new LinkedHashSet<>();
		for (String bit : m.group(2).split(",")) {
			String trimmed = bit.trim();
			if (!trimmed.isEmpty()) {
				assumed.add(trimmed);
			}
		}
		for (Field f : fields) {
			if (!site.values.containsKey(f.name)) {
				continue;
			}
			boolean known = true;
			for (String bitName : f.bitNames()) {
				if (assumed.contains(bitName)) {
					known = false;
					break;
				}
			}
			if (known) {
				site.knownFields.add(f.name);
			}
		}
		return site;
	}

	private static final class WalkRef {
		long srcOff;
		long dst;
		String type;
		int dist;
	}

	private static final class Walk {
		int steps;
		String stop = "NOFLOW";
		int indirectSeen;
		int callsSeen;
		int retsSeen;
		final List<WalkRef> consumers = new ArrayList<>();
	}

	/**
	 * Breadth-first forward walk from one switch site, bounded by {@link #WALK_STEP_CAP}.
	 * State-free by design: it never re-derives a bank value, it only asks whether any
	 * reference into a home-mode SWITCHABLE range appears between this site and the point
	 * where production's own annotations say the state is gone again.
	 * <p>
	 * Call targets are deliberately NOT followed (the fall-through after a call is). Following
	 * them would turn a local "what happens next in this routine" question into a whole-program
	 * reachability question, and the callee's own switch sites are walked in their own right.
	 * <p>
	 * The reported {@code stop} is the reason the FIRST path to terminate did so; a cap hit
	 * overrides everything, since it means the walk was cut short rather than concluded.
	 */
	private Walk walk(Address siteAddr, Set<Address> switchAddrs, Set<Address> unknownAddrs)
			throws Exception {
		Walk w = new Walk();
		Instruction site = listing.getInstructionAt(siteAddr);
		if (site == null) {
			return w;
		}
		Map<Address, Integer> dist = new LinkedHashMap<>();
		Deque<Address> queue = new ArrayDeque<>();
		for (Address next : successors(site)) {
			if (dist.putIfAbsent(next, 1) == null) {
				queue.add(next);
			}
		}
		Set<Address> visited = new HashSet<>();
		String stop = null;
		while (!queue.isEmpty()) {
			monitor.checkCancelled();
			if (w.steps >= WALK_STEP_CAP) {
				stop = "CAP";
				break;
			}
			Address addr = queue.poll();
			if (!visited.add(addr)) {
				continue;
			}
			if (switchAddrs.contains(addr)) {
				if (stop == null) {
					stop = "SWITCH";
				}
				continue;
			}
			if (unknownAddrs.contains(addr)) {
				if (stop == null) {
					stop = "UNKNOWN";
				}
				continue;
			}
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				if (stop == null) {
					stop = "NOFLOW";
				}
				continue;
			}
			w.steps++;
			int d = dist.getOrDefault(addr, 0);
			FlowType ft = instr.getFlowType();
			if (ft.isComputed()) {
				w.indirectSeen++;
			}
			if (ft.isCall()) {
				w.callsSeen++;
			}
			for (Reference reference : instr.getReferencesFrom()) {
				Range r = rangeAt(reference.getToAddress().getOffset());
				if (r == null || r.homeKind != HomeKind.SWITCHABLE) {
					continue;
				}
				RefType rt = reference.getReferenceType();
				if (rt.isWrite() && r.pokeOnWrite) {
					continue; // a latch poke, not a consumer of the newly-selected bank
				}
				WalkRef wr = new WalkRef();
				wr.srcOff = addr.getOffset();
				wr.dst = reference.getToAddress().getOffset();
				wr.type = rt.getName();
				wr.dist = d;
				w.consumers.add(wr);
			}
			if (ft.isTerminal() && !ft.isCall()) {
				w.retsSeen++;
				if (stop == null) {
					stop = "EXIT";
				}
				continue;
			}
			List<Address> next = successors(instr);
			if (next.isEmpty() && stop == null) {
				stop = "NOFLOW";
			}
			for (Address n : next) {
				if (dist.putIfAbsent(n, d + 1) == null) {
					queue.add(n);
				}
			}
		}
		if (stop != null) {
			w.stop = stop;
		}
		w.consumers.sort(Comparator.comparingInt((WalkRef a) -> a.dist));
		return w;
	}

	/** Forward successors for the walk: flow targets plus fall-through, minus a call's callee
	 *  (see {@link #walk}). */
	private static List<Address> successors(Instruction instr) {
		List<Address> out = new ArrayList<>();
		FlowType ft = instr.getFlowType();
		if (!ft.isCall()) {
			for (Address f : instr.getFlows()) {
				out.add(f);
			}
		}
		Address fall = instr.getFallThrough();
		if (fall != null) {
			out.add(fall);
		}
		return out;
	}

	/**
	 * One line per function containing a recognized switch site, shaped for bead grm-v60 (the
	 * far-call trampoline: {@code PLA/PLA/.../JMP (ptr)} resumes execution in the DESTINATION
	 * bank after the caller's JSR). If a title's switch helpers all report
	 * {@code trampolineShape=YES}, the "consumer" of the switch is the trampoline's own
	 * computed jump and no direct base-space reference will ever exist for
	 * retargetReferences to retarget -- the same conclusion INDIRECT-DISPATCH reaches from the
	 * other direction.
	 * <p>
	 * {@code stackOps} is derived from each instruction's pcode-level register inputs/results
	 * (the 6502 {@code SP}/{@code S}/{@code SH} registers, 6502.slaspec:10-11), excluding calls
	 * and returns -- which touch SP by definition and would drown the signal. No mnemonic text
	 * is consulted, and none is emitted.
	 */
	private void emitHelperShapes(List<SwitchSite> sites) throws Exception {
		// Keyed by entry point, not by the Function object: getFunctionContaining need not
		// return the same instance twice, so an identity-keyed map would split one function
		// across several rows.
		Map<Address, Function> byEntry = new LinkedHashMap<>();
		Map<Address, Integer> siteCount = new LinkedHashMap<>();
		for (SwitchSite s : sites) {
			Function f = program.getFunctionManager().getFunctionContaining(s.at);
			if (f != null) {
				byEntry.putIfAbsent(f.getEntryPoint(), f);
				siteCount.merge(f.getEntryPoint(), 1, Integer::sum);
			}
		}
		for (Map.Entry<Address, Function> entry : byEntry.entrySet()) {
			monitor.checkCancelled();
			Function f = entry.getValue();
			int stackOps = 0;
			Instruction last = null;
			InstructionIterator it = listing.getInstructions(f.getBody(), true);
			while (it.hasNext()) {
				Instruction instr = it.next();
				last = instr;
				FlowType ft = instr.getFlowType();
				if (ft.isCall() || ft.isTerminal()) {
					continue;
				}
				if (touchesStack(instr)) {
					stackOps++;
				}
			}
			String endsWith = "FALL";
			if (last != null) {
				FlowType ft = last.getFlowType();
				if (ft.isComputed() && ft.isJump()) {
					endsWith = "IJUMP";
				}
				else if (ft.isTerminal() && !ft.isCall()) {
					endsWith = "RTS";
				}
				else if (ft.isJump() && ft.isUnConditional()) {
					endsWith = "JMP";
				}
			}
			boolean trampoline = "IJUMP".equals(endsWith) || stackOps > 0;
			println("BANKCONSUME helper " + f.getName() + " entry=" +
				off(f.getEntryPoint().getOffset()) + " sites=" + siteCount.get(entry.getKey()) +
				" endsWith=" + endsWith + " stackOps=" + stackOps + " trampolineShape=" +
				yn(trampoline));
		}
	}

	/** True when the instruction reads or writes the 6502 stack pointer (6502.slaspec:10-11
	 *  defines {@code SP} 16-bit and {@code S}/{@code SH} as its halves). Register objects, not
	 *  mnemonic text. */
	private static boolean touchesStack(Instruction instr) {
		return touchesStack(instr.getInputObjects()) || touchesStack(instr.getResultObjects());
	}

	private static boolean touchesStack(Object[] objects) {
		for (Object obj : objects) {
			if (obj instanceof Register r) {
				String name = r.getName();
				if (name.equals("SP") || name.equals("S") || name.equals("SH")) {
					return true;
				}
			}
		}
		return false;
	}

	// ==================================================================
	// Section 5 -- verdicts
	// ==================================================================

	private void section5(Section2 refs, Section3 indirect, Section4 walks) {
		boolean consumersExist = refs.headlineFromFixedNonPoke > 0;
		boolean dispatchIndirectOnly =
			refs.headlineFromFixedFlow == 0 && indirect.unresolved >= LARGE_INDIRECT;

		// Ordered most-decisive first. The first two tests were ADDED after the first campaign
		// (grm-8iy, 2026-08-03) because the original rules misclassified two titles in ways that
		// would have sent a reader down the wrong path -- the failure mode grm-8cq warns about:
		//
		//   (a) NO 'WORKING' CLASS. ff1 and megaman2, the two titles that DO populate overlays,
		//       came out STATE-LOST (fromFixed.flow > 0 and sitesWithConsumer > 0 are both true
		//       of a healthy title). retargeted > 0 is the ground truth that the pipeline works
		//       here, so it has to be tested before anything else.
		//   (b) A BOARD WITH NO FIXED WINDOW BROKE THE 'NO-CONSUMERS' TEST. On AxROM the whole
		//       $8000-$FFFF is switchable, so fromFixed.flow and control.fixedToFixed.flow are
		//       vacuously 0 and wizwarr scored NO-CONSUMERS while actually having 873 consumers.
		//       Where there is no fixed window, "references from the fixed window" is not a
		//       question that can be asked, and the honest signal is headlineConsumersTotal.
		String verdict;
		if (refs.intoOverlayRetargeted > 0) {
			verdict = "WORKING";
		}
		else if (!refs.hasFixedHomeRange) {
			// Fully-overlaid board: only the consumer total and the walk are meaningful.
			verdict = refs.headlineConsumersTotal == 0 ? "NO-CONSUMERS"
					: walks.sites == 0 ? "VALUE-RECOVERY"
					: walks.sitesWithConsumer == 0 ? "STATE-UNCONSUMED" : "UNDECIDED";
		}
		else if (refs.headlineFromFixedFlow == 0 && refs.controlFixedToFixedFlow >= LARGE_CONTROL &&
			indirect.unresolved >= LARGE_INDIRECT) {
			verdict = "INDIRECT-DISPATCH";
		}
		else if (refs.headlineFromFixedFlow == 0 && refs.controlFixedToFixedFlow < LARGE_CONTROL) {
			verdict = "NO-CONSUMERS";
		}
		else if (walks.sites == 0) {
			// Consumers exist, but not one switch site in the whole ROM recovered a fully-known
			// NON-HOME bank -- so there was never a non-home state for retargetReferences to act
			// on. This is the discriminator, and it is upstream of anything consumer-side.
			verdict = "VALUE-RECOVERY";
		}
		else if (walks.sitesWithConsumer == 0) {
			// Non-home banks WERE recovered, but none of them reaches a consumer before the state
			// is lost or the walk ends. Distinct from VALUE-RECOVERY: here the value exists.
			verdict = "STATE-UNCONSUMED";
		}
		else {
			verdict = "UNDECIDED";
		}

		println("BANKCONSUME verdict.consumers-exist " + yn(consumersExist));
		println("BANKCONSUME verdict.dispatch-indirect-only " + yn(dispatchIndirectOnly));
		println("BANKCONSUME verdict.postswitch-consumers " + walks.consumers);
		println("BANKCONSUME verdict.class " + verdict);

		// The addresses a human would look at first: the non-home switch sites this probe
		// walked, then the unresolved indirect dispatches sitting in the fixed bank.
		Set<String> hint = new LinkedHashSet<>();
		hint.addAll(walks.hint);
		hint.addAll(indirect.hint);
		List<String> list = new ArrayList<>(hint);
		int shown = Math.min(HINT_MAX, list.size());
		println("BANKCONSUME verdict.hint " + String.join(",", list.subList(0, shown)));
		if (shown < list.size()) {
			println("BANKCONSUME note hint.truncated " + (list.size() - shown) +
				" further address(es) omitted (cap " + HINT_MAX + ")");
		}
	}

	// ==================================================================
	// Reachability
	// ==================================================================

	/**
	 * The set of instruction addresses runDataflow would ever dequeue, with the bank state
	 * removed: seeds, then {@code instr.getFlows()} + {@code getFallThrough()} to fixpoint
	 * (:687-694), dropping any address with no instruction exactly as {@code mergeAndEnqueue}
	 * does (:744-747). Dropping the state is sound for this question -- state affects the
	 * VALUE a switch produces, never which addresses are visited.
	 * <p>
	 * Copied VERBATIM from BankReachProbe.java (its {@code reachable}), including this
	 * pinning comment: the two probes must answer {@code reach=} identically or a
	 * cross-reading of their output is meaningless.
	 */
	private Set<Address> reachable(Listing listing, Set<Address> seeds) throws Exception {
		Set<Address> reached = new HashSet<>();
		Deque<Address> work = new ArrayDeque<>(seeds);
		while (!work.isEmpty()) {
			monitor.checkCancelled();
			Address addr = work.poll();
			if (reached.contains(addr)) {
				continue;
			}
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				// not (yet) disassembled / not code, or an address inside an instruction rather
				// than at its start -- production drops it here too
				continue;
			}
			reached.add(addr);
			for (Address flow : instr.getFlows()) {
				work.push(flow);
			}
			Address fallThrough = instr.getFallThrough();
			if (fallThrough != null) {
				work.push(fallThrough);
			}
		}
		return reached;
	}

	/** Seeds byte-for-byte the set runDataflow builds (BoardBankAnalyzer.java:568-576). */
	private Set<Address> reachableSet() throws Exception {
		Set<Address> seeds = new LinkedHashSet<>();
		AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
		while (eps.hasNext()) {
			seeds.add(eps.next());
		}
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			seeds.add(f.getEntryPoint());
		}
		return reachable(listing, seeds);
	}

	// ==================================================================
	// Bucketing
	// ==================================================================

	private Range rangeAt(long offset) {
		for (Range r : ranges) {
			if (r.covers(offset)) {
				return r;
			}
		}
		return null;
	}

	private Range homeSwitchableRange() {
		for (Range r : ranges) {
			if (r.homeKind == HomeKind.SWITCHABLE) {
				return r;
			}
		}
		return null;
	}

	/**
	 * Which population a reference SOURCE belongs to, decided by its base-space offset under
	 * the HOME mode. A source inside an overlay space buckets by the same offset (the overlay
	 * covers the same CPU addresses), and its space name is reported separately on the
	 * {@code ref} line so the two are never conflated.
	 */
	private String bucketOf(long offset) {
		Range r = rangeAt(offset);
		if (r != null) {
			if (r.homeKind == HomeKind.SWITCHABLE) {
				return "SWITCHABLE";
			}
			if (r.homeKind == HomeKind.FIXED) {
				return "FIXED";
			}
		}
		String kind = regionKindByOffset.get(offset);
		if (kind != null) {
			return kind;
		}
		try {
			MemoryBlock block = memory.getBlock(defaultSpace.getAddress(offset));
			if (block != null) {
				if (block.isVolatile()) {
					return "IO";
				}
				if (block.isWrite()) {
					return "RAM";
				}
			}
		}
		catch (AddressOutOfBoundsException e) {
			// an offset no default-space address can hold; falls through to OTHER
		}
		return "OTHER";
	}

	/**
	 * A reference source's shape, derived from {@code instr.getFlowType()} plus the reference's
	 * own {@link RefType} -- never from the mnemonic or the operand text (see the copyright
	 * posture in the file header). Flow references are classified by how control leaves the
	 * instruction; data references by direction.
	 */
	private static String srcKind(Instruction instr, RefType rt) {
		FlowType ft = instr.getFlowType();
		if (rt.isFlow()) {
			if (rt.isCall() || ft.isCall()) {
				return "CALL";
			}
			if (rt.isComputed() || ft.isComputed()) {
				return "IJUMP";
			}
			if (rt.isConditional() || ft.isConditional()) {
				return "BRANCH";
			}
			if (rt.isJump() || ft.isJump()) {
				return "JUMP";
			}
			return "OTHER";
		}
		if (rt.isWrite()) {
			return "STORE";
		}
		if (rt.isRead()) {
			return "LOAD";
		}
		return "OTHER";
	}

	// ==================================================================
	// Re-implemented production helpers (see the file header for why)
	// ==================================================================

	/** One normalized window instance; mirrors DescriptorSupport.PlannedWindow (:881-887). */
	private static final class PlannedWindow {
		String name;
		long start;
		long end;
		String expr;
		String onWrite;
		Integer mode;
	}

	/** Set by {@link #planWindows}; mirrors DescriptorSupport.LayoutPlan.modeField (:899). */
	private String plannedModeField;

	/**
	 * Mirrors DescriptorSupport.planWindows (:920-983), including its two rulings that matter
	 * here: every layout's {@code when:} must name the SAME single field (otherwise
	 * {@code layouts} are ignored wholesale, conservatively), and a window name defined
	 * IDENTICALLY in every layout is hoisted to mode-invariant (that is how MMC3's WA000/WE000
	 * become mode-invariant while its W8000/WC000 stay mode-varying).
	 */
	private List<PlannedWindow> planWindows(JsonObject map) {
		List<PlannedWindow> invariant = new ArrayList<>();
		List<PlannedWindow> varying = new ArrayList<>();
		plannedModeField = null;

		if (map.has("windows")) {
			for (JsonElement we : map.getAsJsonArray("windows")) {
				invariant.add(toPlannedWindow(we.getAsJsonObject(), null));
			}
		}
		if (!map.has("layouts")) {
			return invariant;
		}

		String modeFieldName = null;
		List<JsonObject> layouts = new ArrayList<>();
		Set<Integer> seen = new LinkedHashSet<>();
		for (JsonElement le : map.getAsJsonArray("layouts")) {
			JsonObject layout = le.getAsJsonObject();
			JsonObject when = layout.getAsJsonObject("when");
			if (when == null || when.entrySet().size() != 1) {
				println("BANKCONSUME note layouts.ignored when: must name exactly one field");
				return invariant;
			}
			Map.Entry<String, JsonElement> cond = when.entrySet().iterator().next();
			if (modeFieldName == null) {
				modeFieldName = cond.getKey();
			}
			else if (!modeFieldName.equals(cond.getKey())) {
				println("BANKCONSUME note layouts.ignored mixed mode fields '" + modeFieldName +
					"' vs '" + cond.getKey() + "'");
				return invariant;
			}
			if (!seen.add(cond.getValue().getAsInt())) {
				println("BANKCONSUME note layouts.ignored duplicate when: " + modeFieldName + "=" +
					cond.getValue().getAsInt());
				return invariant;
			}
			layouts.add(layout);
		}

		Map<String, List<JsonObject>> byName = new LinkedHashMap<>();
		for (JsonObject layout : layouts) {
			for (JsonElement lwe : layout.getAsJsonArray("windows")) {
				JsonObject w = lwe.getAsJsonObject();
				byName.computeIfAbsent(w.get("name").getAsString(), k -> new ArrayList<>()).add(w);
			}
		}
		for (Map.Entry<String, List<JsonObject>> entry : byName.entrySet()) {
			List<JsonObject> defs = entry.getValue();
			if (defs.size() == layouts.size() && allIdentical(defs)) {
				invariant.add(toPlannedWindow(defs.get(0), null));
				continue;
			}
			for (JsonObject layout : layouts) {
				int modeValue = layout.getAsJsonObject("when").get(modeFieldName).getAsInt();
				for (JsonElement lwe : layout.getAsJsonArray("windows")) {
					JsonObject w = lwe.getAsJsonObject();
					if (w.get("name").getAsString().equals(entry.getKey())) {
						varying.add(toPlannedWindow(w, modeValue));
					}
				}
			}
		}
		plannedModeField = modeFieldName;
		List<PlannedWindow> all = new ArrayList<>(invariant);
		all.addAll(varying);
		return all;
	}

	/** Mirrors DescriptorSupport.allIdentical (:986-994). */
	private static boolean allIdentical(List<JsonObject> defs) {
		JsonObject first = defs.get(0);
		for (int i = 1; i < defs.size(); i++) {
			if (!first.equals(defs.get(i))) {
				return false;
			}
		}
		return true;
	}

	/** Mirrors DescriptorSupport.toPlannedWindow (:996-1004). */
	private static PlannedWindow toPlannedWindow(JsonObject w, Integer mode) {
		PlannedWindow pw = new PlannedWindow();
		pw.name = w.get("name").getAsString();
		pw.start = w.get("start").getAsLong();
		pw.end = w.has("end") ? w.get("end").getAsLong() : pw.start + w.get("size").getAsLong() - 1;
		pw.expr = w.has("maps") ? w.getAsJsonObject("maps").get("expr").getAsString() : null;
		pw.onWrite = w.has("on_write") ? w.get("on_write").getAsString() : null;
		pw.mode = mode;
		return pw;
	}

	/**
	 * Mirrors DescriptorSupport.referencedFields (:646-659) -- deliberately as a
	 * word-boundary scan for the DECLARED {@code banking.state[]} field names rather than a
	 * general identifier scan. Production's version returns every identifier except
	 * {@code last}/{@code second_last} and then rejects an unknown one downstream
	 * (BoardBankAnalyzer.java:2444-2450); scanning for declared names reaches the same answer
	 * for every shipped descriptor and cannot mistake a future built-in for a bank field.
	 * The word boundaries are what keep {@code x4000} inside a hex literal from matching, the
	 * same job production's {@code (?<!\w)} lookbehind does.
	 */
	private Set<String> referencedFields(String expr) {
		Set<String> out = new LinkedHashSet<>();
		for (Field f : fields) {
			Matcher m = Pattern.compile("(?<!\\w)" + Pattern.quote(f.name) + "(?!\\w)").matcher(expr);
			if (m.find()) {
				out.add(f.name);
			}
		}
		return out;
	}

	/** Mirrors DescriptorSupport.OverlayNaming.parseBankValue (:1085-1091). */
	private static Integer parseBankValue(String windowName, String spaceName) {
		String prefix = windowName + "_B";
		if (!spaceName.startsWith(prefix)) {
			return null;
		}
		return parseDigits(spaceName.substring(prefix.length()));
	}

	/**
	 * Mirrors DescriptorSupport.OverlayNaming.parseModeValue (:1105-1111). The strict
	 * all-digits remainder is load-bearing: it is what makes {@code W8000_M3_B7} FAIL here, so
	 * a mode-varying SWITCHABLE instance is never miscounted as a mode-fixed one.
	 */
	private static Integer parseModeValue(String windowName, String spaceName) {
		String prefix = windowName + "_M";
		if (!spaceName.startsWith(prefix)) {
			return null;
		}
		return parseDigits(spaceName.substring(prefix.length()));
	}

	/** Mirrors DescriptorSupport.OverlayNaming.parseModeBankValue (:1118-1124); returns
	 *  {@code {mode, bank}} or null. */
	private static int[] parseModeBankValue(String windowName, String spaceName) {
		String prefix = windowName + "_M";
		if (!spaceName.startsWith(prefix)) {
			return null;
		}
		String rest = spaceName.substring(prefix.length());
		int bIdx = rest.indexOf("_B");
		if (bIdx < 0) {
			return null;
		}
		Integer mode = parseDigits(rest.substring(0, bIdx));
		Integer bank = parseDigits(rest.substring(bIdx + 2));
		if (mode == null || bank == null) {
			return null;
		}
		return new int[] { mode, bank };
	}

	/** Mirrors DescriptorSupport.OverlayNaming.parseDigits (:1128-1141). */
	private static Integer parseDigits(String s) {
		if (s.isEmpty()) {
			return null;
		}
		int v = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c < '0' || c > '9') {
				return null;
			}
			v = v * 10 + (c - '0');
		}
		return v;
	}

	/**
	 * Evaluates a {@code maps.expr} with one bank field bound to {@code value}, mirroring
	 * DescriptorSupport.ExprParser's grammar (:676-800): sum({@code +}, {@code -}) over
	 * product({@code *}, {@code >>}) over factor(parenthesized sum / decimal or {@code 0x} hex
	 * literal / identifier). {@code last} and {@code second_last} are NOT bound here -- they
	 * appear only in FIXED instances, which this probe never bank-counts -- so an expression
	 * using them returns null and the caller reports {@code agree=NO} rather than inventing a
	 * number.
	 */
	private static Long evalExpr(String expr, String fieldName, long value) {
		try {
			Eval e = new Eval(expr, fieldName, value);
			long v = e.sum();
			e.skipSpace();
			return e.pos == expr.length() ? Long.valueOf(v) : null;
		}
		catch (RuntimeException ex) {
			return null;
		}
	}

	private static final class Eval {
		private final String s;
		private final String field;
		private final long value;
		private int pos;

		Eval(String s, String field, long value) {
			this.s = s;
			this.field = field;
			this.value = value;
		}

		long sum() {
			long v = product();
			while (true) {
				skipSpace();
				if (eat('+')) {
					v += product();
				}
				else if (eat('-')) {
					v -= product();
				}
				else {
					return v;
				}
			}
		}

		long product() {
			long v = factor();
			while (true) {
				skipSpace();
				if (eat('*')) {
					v *= factor();
				}
				else if (eatShr()) {
					v >>>= factor();
				}
				else {
					return v;
				}
			}
		}

		private boolean eatShr() {
			if (pos + 1 < s.length() && s.charAt(pos) == '>' && s.charAt(pos + 1) == '>') {
				pos += 2;
				return true;
			}
			return false;
		}

		long factor() {
			skipSpace();
			if (eat('(')) {
				long v = sum();
				skipSpace();
				if (!eat(')')) {
					throw new IllegalArgumentException("unbalanced parentheses");
				}
				return v;
			}
			if (pos < s.length() && Character.isDigit(s.charAt(pos))) {
				int start = pos;
				if (s.startsWith("0x", pos) || s.startsWith("0X", pos)) {
					pos += 2;
					while (pos < s.length() && Character.digit(s.charAt(pos), 16) >= 0) {
						pos++;
					}
					return Long.parseLong(s.substring(start + 2, pos), 16);
				}
				while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
					pos++;
				}
				return Long.parseLong(s.substring(start, pos));
			}
			int start = pos;
			while (pos < s.length() && (Character.isLetterOrDigit(s.charAt(pos)) ||
				s.charAt(pos) == '_')) {
				pos++;
			}
			if (pos == start) {
				throw new IllegalArgumentException("malformed expression");
			}
			String ident = s.substring(start, pos);
			if (ident.equals(field)) {
				return value;
			}
			throw new IllegalArgumentException("unbound identifier " + ident);
		}

		void skipSpace() {
			while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
				pos++;
			}
		}

		private boolean eat(char c) {
			if (pos < s.length() && s.charAt(pos) == c) {
				pos++;
				return true;
			}
			return false;
		}
	}

	// ==================================================================
	// Descriptor
	// ==================================================================

	/** Resolved through the same bundled-data lookup DescriptorSupport.loadMap (:142-151)
	 *  uses, exactly as BankReachProbe.loadMechanisms does. */
	private JsonObject loadDescriptor(String mapPath) throws Exception {
		ResourceFile mapFile = Application.findDataFileInAnyModule(mapPath);
		if (mapFile == null) {
			throw new IOException("could not find bundled data file " + mapPath);
		}
		try (InputStreamReader reader =
			new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	private Field fieldByName(String name) {
		for (Field f : fields) {
			if (f.name.equals(name)) {
				return f;
			}
		}
		return null;
	}

	// ==================================================================
	// Formatting
	// ==================================================================

	/** 6502 is a 16-bit CPU; every offset fits in 4 hex digits. Space identity, where it
	 *  matters, is printed alongside. Mirrors RealRomDump.fmt / BankReachProbe.fmt. */
	private static String fmt(Address addr) {
		return String.format("%04x", addr.getOffset());
	}

	/** {@link #fmt} for a bare offset that has no Address (a range bound, a target offset). */
	private static String off(long offset) {
		return String.format("%04x", offset);
	}

	private static String yn(boolean value) {
		return value ? "YES" : "NO";
	}
}
