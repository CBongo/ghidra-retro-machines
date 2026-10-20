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
// Helpers shared BETWEEN the diagnostic probes BankReachProbe.java, HelperShapeProbe.java and
// BankConsumerProbe.java (bead grm-rx1i.16). NOT a GhidraScript: it has no run() and is never
// named on a -postScript line. It lives beside the probes in tools/banktest/, which
// realrom-test.sh passes as -scriptPath, and Ghidra's script bundle compiles every .java in a
// script directory together, so the probes reference it as an ordinary class (the same
// arrangement as RealRomDumpSupport.java for the dump scripts).
//
// THE RULE THIS FILE LIVES UNDER: INDEPENDENT OF PRODUCTION, SHARED ONLY BY PROBES.
// The probes exist to re-derive production's rules from the bytes and the descriptor, so that a
// probe-vs-analyzer DISAGREEMENT is itself a finding rather than a silent shared bug. That
// independence is from PRODUCTION (retromachines.StoredValueScanner, LoopIdioms,
// DescriptorSupport, HelperDiscovery/findHelpers, BankDataflowEngine, ...), several of which
// are package-private and must never be widened to public for the sake of a diagnostic. Sharing
// code between the PROBES does not weaken that: they all depend on this file, and this file
// depends on no production class. (This replaces the earlier convention, "helpers are
// DUPLICATED rather than extracted", which protected the wrong boundary -- it kept the probes
// independent of each other, which nobody needed.)
//
// CONSEQUENCE, enforced by review: this file must NEVER import or call a retromachines.*
// production class. It uses the Ghidra API and gson only, exactly what the probes already
// imported. A change here moves every probe at once, which is what "shared" means; if a probe
// needs a behaviour the others must not see, give the method a parameter (see loadMechanisms'
// note sink) instead of forking the logic.
//
// Each method keeps the note of which production method it mirrors, where it has one.
//@category RetroMachines.Test

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

final class ProbeSupport {

	private ProbeSupport() {
	}

	/** The one memory-latch strategy name, kept as a constant because several columns are
	 *  meaningful only on it (addr_mask decode, and the mirror BankReachProbe cross-checks
	 *  with). */
	static final String MEMORY_LATCH = "memory-latch";

	/**
	 * The strategies whose write range is fully described by {@code start}/{@code end}, and so
	 * by {@link Mech}. Every other strategy (register-write, ...) decides its range differently
	 * and would be mis-modelled, so the probes report it as unsupported rather than silently
	 * probing it.
	 */
	static final List<String> ACCEPTED_STRATEGIES =
		List.of(MEMORY_LATCH, "serial-shift", "select-data");

	// ------------------------------------------------------------------
	// Model
	// ------------------------------------------------------------------

	/**
	 * One configured mechanism of an {@link #ACCEPTED_STRATEGIES accepted} strategy.
	 * {@code start}/{@code end} are read identically by all three
	 * (MemoryLatchBankSwitchStrategy.configure :129-137, SerialShiftBankSwitchStrategy.configure
	 * :180-181, SelectDataBankSwitchStrategy.configure :106-107). {@code addrMask}/
	 * {@code addrMatch} exist ONLY on memory-latch; on the other two they are absent from the
	 * schema entirely and stay 0 here, which is why {@link #memoryLatch()} gates every column
	 * derived from them rather than letting "mask 0 always matches" read as a real MATCH.
	 * <p>
	 * {@code index} is the mechanism's position in the descriptor's {@code banking.mechanisms[]}
	 * array (NOT its position among accepted ones), so {@code mech=<i>} points straight at the
	 * JSON.
	 * <p>
	 * BankReachProbe uses every field; HelperShapeProbe only needs the start/end range match
	 * (its former private copy was a trimmed Mech without the addr_mask fields) and simply
	 * never reads {@code addrMask}/{@code addrMatch}/{@link #matchesDecode}, so carrying them
	 * changes nothing it prints.
	 */
	static final class Mech {
		final int index;
		final String strategy;
		final long start;
		final long end;
		final long addrMask;
		final long addrMatch;

		Mech(int index, String strategy, long start, long end, long addrMask, long addrMatch) {
			this.index = index;
			this.strategy = strategy;
			this.start = start;
			this.end = end;
			this.addrMask = addrMask;
			this.addrMatch = addrMatch;
		}

		/** Whether the addr_mask decode and the re-implemented mirror apply to this mechanism. */
		boolean memoryLatch() {
			return MEMORY_LATCH.equals(strategy);
		}

		boolean inRange(long offset) {
			return offset >= start && offset <= end;
		}

		/** Verbatim MemoryLatchBankSwitchStrategy.matchesDecode (:211-213). Callers must gate on
		 *  {@link #memoryLatch()}: elsewhere there is no mask to satisfy, so a "true" here means
		 *  "not applicable", not "matched". */
		boolean matchesDecode(long offset) {
			return addrMask == 0 || (offset & addrMask) == addrMatch;
		}
	}

	// ------------------------------------------------------------------
	// Instruction-shape helpers
	// ------------------------------------------------------------------

	/** Mirrors MosOperands.storeRegister (:255-261): 'A'/'X'/'Y' for STA/STX/STY, else
	 *  null. Read-modify-write stores (INC/ASL/...) are excluded there and here. */
	static Character storeRegister(Instruction instr) {
		String mnem = instr.getMnemonicString().toUpperCase();
		if (mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY")) {
			return mnem.charAt(2); // 'A' | 'X' | 'Y'
		}
		return null;
	}

	/** Mirrors MosOperands.plainAbsoluteTarget (:341-355): the single constant address
	 *  an operand names, or null when any register participates (indexed/indirect) or when the
	 *  operand names none or several. */
	static Address plainAbsoluteTarget(Instruction instr) {
		Address addr = null;
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Register) {
				return null; // indexed -- runtime-dependent target
			}
			if (obj instanceof Address a) {
				if (addr != null) {
					return null;
				}
				addr = a;
			}
		}
		return addr;
	}

	/** Mirrors LoopIdioms.indexedBase (:82-111): the base of an indexed operand (abs,X /
	 *  abs,Y / zp,X), built in the EXECUTING instruction's space -- which for an out-of-overlay
	 *  offset already resolves back to the base space (see that method's javadoc, :69-81). */
	static Address indexedBase(Instruction instr) {
		Long base = null;
		boolean indexed = false;
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Register) {
				indexed = true;
			}
			else if (obj instanceof Address a) {
				if (base != null) {
					return null;
				}
				base = a.getOffset();
			}
			else if (obj instanceof Scalar s) {
				if (base != null) {
					return null;
				}
				base = s.getUnsignedValue();
			}
		}
		if (!indexed || base == null) {
			return null;
		}
		try {
			return instr.getMinAddress().getAddressSpace().getAddress(base);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Deliberately LOOSER than production: any write reference whose OFFSET falls in the
	 * mechanism's latch range, in any address space and ignoring the decode predicate. A site
	 * that is {@code write=YES today=NO} has a perfectly good write reference that production
	 * throws away -- which localizes the failure to the space test (or the decode), not to the
	 * absence of a reference. HelperShapeProbe uses it only to measure mechsites.rmwSkipped:
	 * stores that write a mechanism range without being STA/STX/STY, which
	 * {@link #storeRegister} intentionally excludes just as MosOperands.storeRegister
	 * does in production.
	 */
	static boolean writesRangeAnySpace(Instruction instr, Mech mech) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && mech.inRange(to.getOffset())) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Reachability
	// ------------------------------------------------------------------

	/**
	 * The set of instruction addresses runDataflow would ever dequeue, with the bank state
	 * removed: seeds, then {@code instr.getFlows()} + {@code getFallThrough()} to fixpoint
	 * (BankDataflowEngine.java:266-273), dropping any address with no instruction exactly as
	 * {@code mergeAndEnqueue} does (BankDataflowEngine.java:323-326). Dropping the state is
	 * sound for this question -- state affects the VALUE a switch produces, never which
	 * addresses are visited.
	 * <p>
	 * BankReachProbe and BankConsumerProbe both call this one copy, so they must answer
	 * {@code reach=} identically: a cross-reading of their output is meaningless otherwise.
	 */
	static Set<Address> reachable(Listing listing, Set<Address> seeds, TaskMonitor monitor)
			throws Exception {
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

	// ------------------------------------------------------------------
	// Descriptor
	// ------------------------------------------------------------------

	/**
	 * The descriptor's mechanisms whose strategy is one of {@link #ACCEPTED_STRATEGIES},
	 * resolved through the same bundled-data lookup DescriptorResources.loadMap (:142-151) uses.
	 * A malformed or partial mechanism is skipped rather than fatal -- one bad entry should not
	 * blind the whole probe. Every strategy name encountered, accepted or not, is appended to
	 * {@code declared} so the caller's bail-out can name what the board actually is.
	 * <p>
	 * {@code skipNote} is the one place the two former copies differed: BankReachProbe printed
	 * a {@code BANKREACH error mechanism N has no params; skipped} line for a mechanism missing
	 * {@code params} or {@code start}/{@code end}, HelperShapeProbe skipped silently. A
	 * non-null sink receives the text after "BANKREACH error " (e.g. "mechanism 1 has no
	 * params; skipped") and the caller adds its own prefix; null skips silently.
	 */
	static List<Mech> loadMechanisms(String mapPath, List<String> declared,
			Consumer<String> skipNote) throws Exception {
		ResourceFile mapFile = Application.findDataFileInAnyModule(mapPath);
		if (mapFile == null) {
			throw new IOException("could not find bundled data file " + mapPath);
		}
		JsonObject root;
		try (InputStreamReader reader =
			new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
			root = JsonParser.parseReader(reader).getAsJsonObject();
		}
		List<Mech> out = new ArrayList<>();
		JsonObject banking = root.has("banking") ? root.getAsJsonObject("banking") : null;
		if (banking == null || !banking.has("mechanisms")) {
			return out;
		}
		JsonArray mechanisms = banking.getAsJsonArray("mechanisms");
		int index = 0;
		for (JsonElement element : mechanisms) {
			int here = index++;
			if (!element.isJsonObject()) {
				continue;
			}
			JsonObject mech = element.getAsJsonObject();
			if (!mech.has("strategy")) {
				continue;
			}
			String strategy = mech.get("strategy").getAsString();
			if (!declared.contains(strategy)) {
				declared.add(strategy);
			}
			if (!ACCEPTED_STRATEGIES.contains(strategy)) {
				continue; // range not described by start/end -- would be mis-modelled here
			}
			if (!mech.has("params")) {
				if (skipNote != null) {
					skipNote.accept("mechanism " + here + " has no params; skipped");
				}
				continue;
			}
			JsonObject params = mech.getAsJsonObject("params");
			if (!params.has("start") || !params.has("end")) {
				if (skipNote != null) {
					skipNote.accept("mechanism " + here + " lacks start/end; skipped");
				}
				continue;
			}
			// addr_mask/addr_match are read unconditionally but are memory-latch-only in the
			// schema; on the other two strategies they are absent and stay 0, which every
			// consumer gates behind Mech.memoryLatch() rather than reading as "mask of 0".
			out.add(new Mech(here, strategy, params.get("start").getAsLong(),
				params.get("end").getAsLong(),
				params.has("addr_mask") ? params.get("addr_mask").getAsLong() : 0,
				params.has("addr_match") ? params.get("addr_match").getAsLong() : 0));
		}
		return out;
	}
}
