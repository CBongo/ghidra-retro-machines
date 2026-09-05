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
import java.util.function.Function;

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

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
 * map and language id. A caller may also opt into a per-case decoding CONTEXT via
 * {@link #withContextProvider}, for a language (e.g. the 65816) whose decode itself depends on
 * more than the register/RAM state seeded above -- see that method's doc. A caller whose counter
 * is not fully captured by one vector field (again the 65816: the real fetch address is
 * {@code pbr<<16 | pc}, two separate fields) may also opt into {@link #withCounterAddressProvider}
 * -- see that method's doc.
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

	/**
	 * The result of running one {@link VectorCase}.
	 *
	 * @param decodeBoundary true iff this case did not run at all because the decoder's
	 *        lookahead ran off the end of the address space (see {@link #isDecodeBoundaryCase}) --
	 *        a harness artifact, not a semantic verdict either way. Callers that tally PASS/FAIL
	 *        counts must exclude these cases rather than counting {@link #pass} for them.
	 */
	public record CaseResult(String name, boolean pass, List<String> mismatches,
			boolean decodeBoundary) {

		/** One-line summary, e.g. {@code "00 0000: PASS"} or the case name plus every mismatch. */
		@Override
		public String toString() {
			if (decodeBoundary) {
				return name + ": DECODE-BOUNDARY (excluded)";
			}
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

	/**
	 * Disables {@code DecodePcodeExecutionException} boundary classification (see
	 * {@link #isDecodeBoundaryCase}): every such exception is then reported as an ordinary
	 * failure, exactly as before this classification existed. The default, so existing callers
	 * (e.g. {@code VectorHarness6502Test}) are unaffected unless they opt in.
	 */
	public static final int NO_DECODE_BOUNDARY_DETECTION = 0;

	private final Language language;
	private final Map<String, Register> registerMap;
	private final String pcField;
	private final Map<String, FlagLayout> flagLayouts;
	private final int rebuildInterval;
	private final int decodeBoundaryWindowBytes;

	// Not final: withContextProvider() below is a builder-style setter rather than a
	// constructor parameter, precisely so it does not disturb the existing constructor overload
	// chain (see its own doc). Absent (the default) reproduces today's exact
	// overrideContextWithDefault() behaviour for every existing caller.
	private Function<VectorCase, RegisterValue> contextProvider;

	// Not final: withCounterAddressProvider() below is the sibling of withContextProvider() above
	// (bead grm-9nxj.3), same builder-style shape and same "absent reproduces today's exact
	// behaviour" contract. See that method's doc for why a caller ever needs this.
	private Function<VectorCase, Address> counterAddressProvider;

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
	 * @param decodeBoundaryWindowBytes see {@link #isDecodeBoundaryCase}; pass
	 *                        {@link #NO_DECODE_BOUNDARY_DETECTION} to disable (every
	 *                        {@code DecodePcodeExecutionException} is then an ordinary failure).
	 */
	public VectorRunner(Language language, Map<String, Register> registerMap, String pcField,
			Map<String, FlagLayout> flagLayouts, int rebuildInterval,
			int decodeBoundaryWindowBytes) {
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
		if (decodeBoundaryWindowBytes < 0) {
			throw new IllegalArgumentException("decodeBoundaryWindowBytes must be >= 0, got " +
				decodeBoundaryWindowBytes);
		}
		this.decodeBoundaryWindowBytes = decodeBoundaryWindowBytes;

		this.defaultSpace = language.getAddressFactory().getDefaultAddressSpace();
		rebuildEmulator();
		reset();
	}

	/** Convenience constructor: no decode-boundary classification (see
	 *  {@link #NO_DECODE_BOUNDARY_DETECTION}). */
	public VectorRunner(Language language, Map<String, Register> registerMap, String pcField,
			Map<String, FlagLayout> flagLayouts, int rebuildInterval) {
		this(language, registerMap, pcField, flagLayouts, rebuildInterval,
			NO_DECODE_BOUNDARY_DETECTION);
	}

	/** Convenience constructor: {@link #DEFAULT_REBUILD_INTERVAL}, no decode-boundary
	 *  classification. */
	public VectorRunner(Language language, Map<String, Register> registerMap, String pcField,
			Map<String, FlagLayout> flagLayouts) {
		this(language, registerMap, pcField, flagLayouts, DEFAULT_REBUILD_INTERVAL);
	}

	/** Convenience constructor with no flag decomposition and {@code pcField = "pc"}. */
	public VectorRunner(Language language, Map<String, Register> registerMap) {
		this(language, registerMap, "pc", Map.of());
	}

	/**
	 * Supplies a per-case processor CONTEXT (bead grm-wrmf), for a language whose decode depends
	 * on it -- e.g. the 65816, where {@code p}'s M/X bits and the case's scalar {@code e} select
	 * an 8- or 16-bit decode of the very same opcode byte. Without this, {@link #seed} falls back
	 * to {@code overrideContextWithDefault()}, which resolves the language's STATIC default
	 * context at the counter address -- the same fixed mode for every case regardless of what the
	 * case actually specifies. That is harmless for SPC700 and stock 6502 (neither has a
	 * meaningful context register, so the default call is a no-op per
	 * {@code DefaultPcodeThread.overrideContextWithDefault}'s own doc) but would be quietly wrong
	 * for a language where it is not: every case would decode in one fixed mode, an
	 * {@code M=0} case would step the wrong-width instruction, and the run would report plausible
	 * per-opcode PASS/FAIL ratios that read as language defects rather than as the harness feeding
	 * every case the wrong context.
	 *
	 * <p>Builder-style rather than a constructor parameter so the existing overload chain above
	 * -- and every caller using it ({@code Spc700VectorSampleTest}, {@code
	 * Spc700VectorExhaustiveTest}, {@code VectorHarness6502Test}, {@code
	 * Spc700VectorHarnessSupport}) -- is untouched.
	 *
	 * @param contextProvider given a case, returns the {@link RegisterValue} to install as that
	 *        case's decode context, or {@code null} to fall back to
	 *        {@code overrideContextWithDefault()} for that one case. Pass {@code null} itself to
	 *        clear a previously set provider and restore today's default behaviour entirely.
	 * @return this, for chaining onto the constructor call
	 */
	public VectorRunner withContextProvider(Function<VectorCase, RegisterValue> contextProvider) {
		this.contextProvider = contextProvider;
		return this;
	}

	/**
	 * Supplies a per-case STARTING COUNTER ADDRESS (bead grm-9nxj.3), for a language whose
	 * executing address is not fully captured by {@code pcField} alone -- e.g. the 65816, where
	 * the real fetch address is {@code pbr<<16 | pc} but the vector suite's {@code pc} field
	 * carries only the 16-bit offset within the bank, and {@code pbr} is a separate field the
	 * corpus randomizes independently. Without this, {@link #seed} falls back to its long-
	 * standing behaviour: {@code defaultSpace.getAddress(pcField value)}, i.e. treating
	 * {@code pcField} as if it were the WHOLE address -- correct for SPC700 and 6502, whose
	 * program counter fits in one field, but silently wrong for a banked counter: every case
	 * would decode from bank 0 regardless of what {@code pbr} says, which is wrong whenever
	 * {@code pbr != 0} (i.e. almost always, since the corpus randomizes it across the full
	 * range) and would corrupt the executed bytes for essentially every case rather than merely
	 * misreport a register.
	 *
	 * <p>Same shape and the same "absent reproduces today's behaviour" contract as
	 * {@link #withContextProvider}, and for the identical reason: existing callers
	 * ({@code Spc700VectorSampleTest}, {@code Spc700VectorExhaustiveTest}, {@code
	 * VectorHarness6502Test}, {@code Spc700VectorHarnessSupport}) are untouched.
	 *
	 * @param counterAddressProvider given a case, returns the starting {@link Address} to install
	 *        as that case's program counter, or {@code null} to fall back to the {@code pcField}-
	 *        only computation for that one case. Pass {@code null} itself to clear a previously
	 *        set provider and restore today's default behaviour entirely.
	 * @return this, for chaining onto the constructor call
	 */
	public VectorRunner withCounterAddressProvider(Function<VectorCase, Address> counterAddressProvider) {
		this.counterAddressProvider = counterAddressProvider;
		return this;
	}

	/** The language this runner decodes with -- callers that build per-case context need it. */
	Language language() {
		return language;
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
		catch (DecodePcodeExecutionException e) {
			if (isDecodeBoundaryCase(c)) {
				return new CaseResult(c.name(), true, List.of(), true);
			}
			return new CaseResult(c.name(), false, List.of("execution failed: " + e), false);
		}
		catch (RuntimeException e) {
			return new CaseResult(c.name(), false, List.of("execution failed: " + e), false);
		}
		List<String> mismatches = compare(c);
		return new CaseResult(c.name(), mismatches.isEmpty(), mismatches, false);
	}

	/**
	 * True iff {@code c}'s initial PC sits in the top {@link #decodeBoundaryWindowBytes} bytes of
	 * the address space -- the narrow, precise condition (bead grm-c9d.3 increment 12) under
	 * which a {@link DecodePcodeExecutionException} is a harness artifact rather than a semantic
	 * failure.
	 *
	 * <p><b>Why this exists at all.</b> {@code SleighInstructionDecoder.parseNewBlock} needs a
	 * lookahead window past the current instruction to decode it, and that lookahead can run off
	 * the end of a 16-bit (or any bounded) address space even for a real, one-byte instruction
	 * that hardware executes normally -- e.g. a one-byte {@code EI} at {@code $FFF9} is seven
	 * bytes from the top of SPC700's space and decodes fine on real hardware. This is a Ghidra
	 * decoder-lookahead limitation, not anything {@code spc700ops.sinc} can fix, and is NOT the
	 * same thing as a genuinely undefined hardware behaviour.
	 *
	 * <p><b>Deliberately narrow, matching {@link DecodePcodeExecutionException}'s call site's own
	 * javadoc warning against becoming a blanket "exceptions don't count":</b> both this specific
	 * exception type (not any {@code RuntimeException}) AND initial PC within the top-of-space
	 * window must hold. Measured directly against the full 256,000-case SPC700 exhaustive suite
	 * (grm-c9d.3 increment 12): exactly 30 cases throw this exception, every one with initial PC
	 * in {@code $FFF9}-{@code $FFFF} (histogram: fff9x5, fffbx10, fffcx2, fffdx3, fffex4, ffffx6 --
	 * {@code $FFFA} never appears, so this is length-dependent per case, not a flat address band).
	 * An 8-byte window ({@code $FFF8}-{@code $FFFF}) comfortably covers the observed range with
	 * one byte of margin. See {@link Spc700VectorHarnessSupport#DECODE_BOUNDARY_CAP} for the guard
	 * that keeps this classification from silently absorbing an unrelated regression.
	 */
	private boolean isDecodeBoundaryCase(VectorCase c) {
		if (decodeBoundaryWindowBytes <= 0) {
			return false;
		}
		Address addr = resolveCounterAddress(c);
		if (addr == null) {
			return false;
		}
		long pc = addr.getOffset();
		long maxAddr = defaultSpace.getMaxAddress().getOffset();
		return pc > maxAddr - decodeBoundaryWindowBytes;
	}

	/**
	 * The starting counter {@link Address} for {@code c}: {@link #counterAddressProvider} if one
	 * is set, else {@code pcField}'s value interpreted directly as an offset into
	 * {@link #defaultSpace} (today's long-standing behaviour -- see
	 * {@link #withCounterAddressProvider}'s doc for why that is not always the whole address).
	 * Shared by {@link #seed} and {@link #isDecodeBoundaryCase} so the two never disagree about
	 * where a case actually starts. Returns {@code null} only when there is no provider AND
	 * {@code c} has no {@code pcField} entry -- callers decide how to react (an error in
	 * {@link #seed}, "not a boundary case" in {@link #isDecodeBoundaryCase}).
	 */
	private Address resolveCounterAddress(VectorCase c) {
		if (counterAddressProvider != null) {
			return counterAddressProvider.apply(c);
		}
		Integer pcValue = c.initialRegs().get(pcField);
		if (pcValue == null) {
			return null;
		}
		return defaultSpace.getAddress(Integer.toUnsignedLong(pcValue));
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
		Address pcAddr = resolveCounterAddress(c);
		if (pcAddr == null) {
			throw new IllegalArgumentException(
				"case '" + c.name() + "' initial state has no '" + pcField + "' field");
		}
		thread.overrideCounter(pcAddr);
		RegisterValue context = contextProvider == null ? null : contextProvider.apply(c);
		if (context != null) {
			thread.overrideContext(context);
		}
		else {
			thread.overrideContextWithDefault();
		}
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
