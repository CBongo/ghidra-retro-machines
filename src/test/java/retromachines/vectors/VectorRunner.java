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
package retromachines.vectors;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

import retromachines.vectors.VectorCase.RamByte;

/**
 * Executes one {@link VectorCase} at a time against Ghidra's interpreted {@link PcodeEmulator}
 * and reports every register/memory mismatch against the case's expected final state (bead
 * grm-c9d.2).
 *
 * <p><b>Interpreted, never JIT.</b> Mirrors {@code retromachines.EmulationRecovery}'s documented
 * rejection of {@code JitPcodeEmulator}: {@code PcodeEmulator}'s {@code SleighInstructionDecoder}
 * re-reads memory on every fetch, which is also exactly what single-instruction step-then-verify
 * needs -- there is no block caching to invalidate between cases.
 *
 * <p><b>Language-agnostic.</b> Nothing here knows SPC700, 6502, or any other processor. A caller
 * supplies the {@link Language}, a map from the vector JSON's register field names to the
 * {@link Register}s that hold them, which field name is the program counter, and (optionally)
 * per-register {@link FlagLayout}s for decomposing packed status bytes in mismatch reports. Bead
 * grm-o9k (65x02 ADC/RRA flag verification) reuses this exact class against a different register
 * map and language id.
 *
 * <p><b>One shared emulator, reset per case -- but periodically REBUILT (grm-c9d.3 increment
 * 10).</b> Constructing a fresh {@code PcodeEmulator} per vector is what makes an exhaustive
 * 256,000-vector SPC700 run (or a 65x02 equivalent) impractical time-wise; see {@link #reset()}
 * for the per-case thread hazard that a fresh {@code PcodeEmulator} sidesteps for free. But NEVER
 * rebuilding one for the emulator's whole life means {@code AbstractPcodeMachine}'s thread
 * registry (see {@link #reset()}) grows by one entry per case for the run's entire duration --
 * measured to need a 9 GB heap for a full 256,000-case exhaustive SPC700 run, more than half this
 * project's dev machine's 16 GB, which the project owner ruled unacceptable for what is meant to
 * be routine local verification (grm-c9d.3 increment 9's report). So the emulator itself is
 * rebuilt every {@link #rebuildInterval} cases -- bounding the thread registry to at most that
 * many entries at a time -- while STILL constructing a fresh {@link PcodeThread} every single
 * case, because that part of the reset is fixing a different hazard (the decoder's stale-cache
 * bug, {@link #reset()}) that periodic rebuild alone does not touch.
 */
public final class VectorRunner {

	/** The result of running one {@link VectorCase}. */
	public record CaseResult(String name, boolean pass, List<String> mismatches) {

		/** One-line summary, e.g. {@code "00 0000: PASS"} or the case name plus every mismatch. */
		@Override
		public String toString() {
			if (pass) {
				return name + ": PASS";
			}
			return name + ": FAIL (" + String.join("; ", mismatches) + ")";
		}
	}

	/**
	 * Default emulator-rebuild interval (grm-c9d.3 increment 10), chosen by measuring wall time
	 * and the minimum passing heap across candidate values (500/2000/10000) against the full
	 * 256,000-case SPC700 exhaustive suite -- see the increment's report for the measured table.
	 * Wall time was flat (~12-13s) across all three, i.e. rebuilding an emulator is cheap enough
	 * that this interval is chosen for memory, not speed: 2000 measured reliably passing at a
	 * 128m heap (OOMing at 64m) and comfortably under {@code spc700VectorTest}'s committed 512m
	 * (4x margin); 10000 needed more than 128m for the same run.
	 */
	public static final int DEFAULT_REBUILD_INTERVAL = 2000;

	private final Language language;
	private final Map<String, Register> registerMap;
	private final String pcField;
	private final Map<String, FlagLayout> flagLayouts;
	private final int rebuildInterval;

	private PcodeEmulator emulator;
	private PcodeArithmetic<byte[]> arithmetic;
	private final AddressSpace defaultSpace;
	private int casesSinceRebuild;

	// Not final: reset() below replaces these every case. See reset()'s doc for why a plain
	// register/memory clear on a REUSED thread is not sufficient here.
	private PcodeThread<byte[]> thread;
	private PcodeExecutorState<byte[]> state;

	/**
	 * @param language        the processor language to emulate
	 * @param registerMap     vector JSON register field name (e.g. {@code "a"}, {@code "psw"}) ->
	 *                        the {@link Register} holding it. Must contain an entry for
	 *                        {@code pcField}.
	 * @param pcField         the register field name that is the program counter (typically
	 *                        {@code "pc"})
	 * @param flagLayouts     optional register field name -> {@link FlagLayout}, for decomposing
	 *                        a packed status register into named flags in mismatch reports. A
	 *                        register with no entry here is reported as a plain scalar diff.
	 * @param rebuildInterval construct a fresh {@code PcodeEmulator} every this many cases (see
	 *                        the class doc); must be positive.
	 */
	public VectorRunner(Language language, Map<String, Register> registerMap, String pcField,
			Map<String, FlagLayout> flagLayouts, int rebuildInterval) {
		this.language = Objects.requireNonNull(language, "language");
		this.registerMap = Map.copyOf(registerMap);
		this.pcField = Objects.requireNonNull(pcField, "pcField");
		this.flagLayouts = Map.copyOf(flagLayouts);
		if (!this.registerMap.containsKey(pcField)) {
			throw new IllegalArgumentException(
				"registerMap has no entry for pcField '" + pcField + "'");
		}
		if (rebuildInterval <= 0) {
			throw new IllegalArgumentException("rebuildInterval must be positive, got " +
				rebuildInterval);
		}
		this.rebuildInterval = rebuildInterval;

		this.defaultSpace = language.getAddressFactory().getDefaultAddressSpace();
		rebuildEmulator();
		reset();
	}

	/** Convenience constructor: {@link #DEFAULT_REBUILD_INTERVAL}. */
	public VectorRunner(Language language, Map<String, Register> registerMap, String pcField,
			Map<String, FlagLayout> flagLayouts) {
		this(language, registerMap, pcField, flagLayouts, DEFAULT_REBUILD_INTERVAL);
	}

	/** Convenience constructor with no flag decomposition and {@code pcField = "pc"}. */
	public VectorRunner(Language language, Map<String, Register> registerMap) {
		this(language, registerMap, "pc", Map.of());
	}

	/**
	 * Runs one case: resets emulator state, seeds registers and RAM from {@code initial}, steps
	 * exactly one instruction, then compares every {@code final} register and RAM byte.
	 */
	public CaseResult run(VectorCase c) {
		reset();
		seed(c);
		try {
			thread.stepInstruction();
		}
		catch (RuntimeException e) {
			return new CaseResult(c.name(), false,
				List.of("execution failed: " + e));
		}
		List<String> mismatches = compare(c);
		return new CaseResult(c.name(), mismatches.isEmpty(), mismatches);
	}

	/**
	 * Resets to a blank slate for the next case: a fresh {@link PcodeThread} (registers, unique
	 * space, and -- critically -- its own {@code SleighInstructionDecoder}), plus a cleared
	 * shared (memory) state.
	 *
	 * <p><b>Why a fresh thread, not just cleared state on a reused one.</b> The first
	 * implementation of this class reused one {@link PcodeThread} across every case and reset it
	 * by clearing its register/unique state (via {@link PcodeExecutorState#clear()}) and the
	 * shared memory state, exactly as the class javadoc originally promised. That is wrong:
	 * {@code SleighInstructionDecoder} (verified against {@code Emulation-src.zip}'s copy for
	 * this project's targeted Ghidra version) caches the last-decoded {@code InstructionBlock} on
	 * the THREAD, keyed only by address, and only invalidates it when a taken branch executes
	 * (via {@code PcodeThread.branched()} on the decoder) -- {@link PcodeThread#overrideCounter}
	 * does NOT invalidate it. So when case N+1 reuses the same starting {@code pc} value as case
	 * N (a real hazard: SPC700/6502 vector suites draw {@code pc} from the full 16-bit space, so
	 * a same-address collision across ~256,000 cases is not vanishingly rare), the reused thread
	 * silently re-executes the STALE cached instruction from case N instead of decoding the freshly
	 * seeded bytes for case N+1 -- confirmed directly: a hand-written two-case repro (INX at
	 * $1000, then TAX at $1000) reused the cached INX and produced X=1, not the TAX result. A
	 * fresh {@link PcodeThread} carries a brand-new decoder with no cached block, which sidesteps
	 * the hazard entirely rather than trying to out-guess the cache. Since a fresh thread's local
	 * state also starts empty, only the shared (memory) state needs an explicit
	 * {@link PcodeExecutorState#clear()} here.
	 *
	 * <p><b>Cost and thread-count growth, measured (bead grm-c9d.2):</b> see the bead's dev notes
	 * for the exact numbers this repo's own dev loop produced; in short, {@code newThread()} was
	 * measured well under a millisecond per call, and {@code AbstractPcodeMachine}'s per-machine
	 * thread registry (which this project's targeted Ghidra version has no public API to shrink)
	 * grows by one small entry per case for the life of a {@link VectorRunner} -- acceptable for
	 * a bounded ~256,000-case exhaustive run in a short-lived JVM (one gradle test task), not
	 * something to hold open indefinitely.
	 */
	private void reset() {
		if (casesSinceRebuild >= rebuildInterval) {
			rebuildEmulator();
		}
		thread = emulator.newThread();
		state = thread.getState();
		emulator.getSharedState().clear();
		casesSinceRebuild++;
	}

	/**
	 * Constructs a fresh {@link PcodeEmulator}, discarding the old one (and, with it, its
	 * accumulated {@code AbstractPcodeMachine} thread registry -- see the class doc). Does NOT by
	 * itself replace {@code thread}/{@code state}; callers (the constructor and {@link #reset()})
	 * do that afterward via the normal per-case path.
	 */
	private void rebuildEmulator() {
		emulator = new PcodeEmulator(language);
		arithmetic = emulator.getSharedState().getArithmetic();
		casesSinceRebuild = 0;
	}

	/** Seeds registers and RAM from {@code c.initialRegs()}/{@code c.initialRam()}. */
	private void seed(VectorCase c) {
		for (Map.Entry<String, Integer> entry : c.initialRegs().entrySet()) {
			if (entry.getKey().equals(pcField)) {
				continue; // handled below via overrideCounter, which also syncs the decoder
			}
			Register reg = requireRegister(entry.getKey());
			state.setVar(reg, arithmetic.fromConst(entry.getValue(), reg.getMinimumByteSize()));
		}
		for (RamByte rb : c.initialRam()) {
			state.setByte(defaultSpace.getAddress(Integer.toUnsignedLong(rb.address())),
				(byte) rb.value());
		}
		Integer pcValue = c.initialRegs().get(pcField);
		if (pcValue == null) {
			throw new IllegalArgumentException(
				"case '" + c.name() + "' initial state has no '" + pcField + "' field");
		}
		Address pcAddr = defaultSpace.getAddress(Integer.toUnsignedLong(pcValue));
		thread.overrideCounter(pcAddr);
		thread.overrideContextWithDefault();
	}

	/** Compares every {@code final} register and RAM byte against actual post-step state. */
	private List<String> compare(VectorCase c) {
		List<String> mismatches = new ArrayList<>();
		for (Map.Entry<String, Integer> entry : c.finalRegs().entrySet()) {
			String field = entry.getKey();
			Register reg = requireRegister(field);
			int expected = (int) (entry.getValue() & mask(reg.getMinimumByteSize()));
			int actual = (int) (arithmetic.toLong(state.getVar(reg, Reason.INSPECT), Purpose.INSPECT)
				& mask(reg.getMinimumByteSize()));
			if (expected == actual) {
				continue;
			}
			FlagLayout layout = flagLayouts.get(field);
			if (layout != null) {
				mismatches.addAll(layout.diff(field.toUpperCase(), expected, actual));
			}
			else {
				mismatches.add(field.toUpperCase() + " 0x" + Integer.toHexString(actual) +
					" != 0x" + Integer.toHexString(expected));
			}
		}
		for (RamByte rb : c.finalRam()) {
			Address addr = defaultSpace.getAddress(Integer.toUnsignedLong(rb.address()));
			int expected = rb.value() & 0xFF;
			int actual = state.inspectByte(addr) & 0xFF;
			if (expected != actual) {
				mismatches.add("$" + Integer.toHexString(rb.address()) + " 0x" +
					Integer.toHexString(actual) + " != 0x" + Integer.toHexString(expected));
			}
		}
		return mismatches;
	}

	private Register requireRegister(String field) {
		Register reg = registerMap.get(field);
		if (reg == null) {
			throw new IllegalArgumentException(
				"no Register mapped for vector field '" + field + "' in language " +
					language.getLanguageID());
		}
		return reg;
	}

	private static long mask(int byteSize) {
		return byteSize >= 8 ? -1L : (1L << (byteSize * 8)) - 1;
	}
}
