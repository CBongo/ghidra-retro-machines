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

import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

import ghidra.pcode.emu.EmulatorUtilities;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * Shared bounded p-code emulation core for recovering self-modified code -- decrypt-on-
 * the-fly payloads, ROM-to-RAM copies, cross-processor uploads. Given an entry address,
 * {@link StopConditions}, and an {@link IoPolicy}, it runs the interpreted
 * {@link PcodeEmulator} over the current program image, accumulates every memory write
 * into a dirty set, reads the resulting bytes back out of emulator state, and returns a
 * {@link RecoveryResult}. Callers decide how to materialize the bytes (patch, overlay,
 * byte-mapped block, or a new program).
 *
 * <p><b>Interpreted, not JIT.</b> This uses {@code ghidra.pcode.emu.PcodeEmulator}, whose
 * {@code SleighInstructionDecoder} re-reads memory on every instruction fetch and so
 * observes the code's own writes -- the property that makes it correct for self-modifying
 * code. {@code JitPcodeEmulator} caches decoded blocks and does not implement
 * invalidation-on-write in this Ghidra version; it must not be used here.
 *
 * <p><b>Every run is bounded</b> on instruction count and wall-clock (see
 * {@link StopConditions}), so a runaway routine cannot hang analysis. A run also stops
 * early on a caller exit address or when a watched target range is fully written.
 *
 * <p><b>Honest about what it cannot know.</b> Reads of hardware I/O ({@link IoPolicy}) or
 * of never-written RAM are answered with a policy value (zero) and recorded in the
 * {@link ProvenanceLog}; {@link ProvenanceLog#suspect()} then tells a caller the recovered
 * bytes depended on state the emulator did not model.
 */
public class EmulationRecovery {

	/** Sanity cap on a single readback range (16 MiB) -- larger implies a runaway dirty set. */
	private static final long MAX_READBACK = 0x1000000L;

	private final Program program;

	/**
	 * @param program the loaded program to emulate over; its language selects the processor
	 *                and its memory blocks are the emulator's initial image
	 */
	public EmulationRecovery(Program program) {
		this.program = Objects.requireNonNull(program, "program");
	}

	/**
	 * Run recovery with the descriptor-derived I/O policy and no cancellation monitor.
	 *
	 * @param entry the address at which emulation starts
	 * @param stop  the run bounds (null uses all defaults)
	 * @return the recovery outcome
	 */
	public RecoveryResult recover(Address entry, StopConditions stop) {
		return recover(entry, stop, IoPolicy.volatileBlocks(program), TaskMonitor.DUMMY);
	}

	/**
	 * Run recovery.
	 *
	 * @param entry   the address at which emulation starts (program counter seed)
	 * @param stop    the run bounds; null uses all defaults
	 * @param io      the I/O policy for classifying uninitialized reads; null treats none as I/O
	 * @param monitor cancellation monitor; null uses {@link TaskMonitor#DUMMY}
	 * @return the recovery outcome; never null
	 */
	public RecoveryResult recover(Address entry, StopConditions stop, IoPolicy io,
			TaskMonitor monitor) {
		Objects.requireNonNull(entry, "entry address");
		StopConditions bounds = stop != null ? stop : StopConditions.builder().build();
		IoPolicy policy = io != null ? io : IoPolicy.none();
		TaskMonitor mon = monitor != null ? monitor : TaskMonitor.DUMMY;

		AddressSet dirty = new AddressSet();
		ProvenanceLog log = new ProvenanceLog();
		RecoveryCallbacks callbacks = new RecoveryCallbacks(dirty, log, policy);

		// Callbacks are a constructor argument -- they must be attached before loadProgram so
		// the same instance sees every write, but capture is gated off until after the image
		// and registers are seeded so the initial load does not pollute the dirty set.
		PcodeEmulator emu = new PcodeEmulator(program.getLanguage(), callbacks);
		try {
			EmulatorUtilities.loadProgram(emu, program);
		}
		catch (MemoryAccessException e) {
			log.add(ProvenanceLog.Kind.WARNING, entry, 0, "loadProgram failed: " + e.getMessage());
			return new RecoveryResult(dirty, new TreeMap<>(), StopReason.LOAD_FAILED, log, 0);
		}

		PcodeThread<byte[]> thread = emu.newThread();
		EmulatorUtilities.initializeRegisters(thread, program, entry);
		callbacks.setCapturing(true);

		long steps = 0;
		StopReason reason;
		final long fuel = bounds.instructionFuel();
		final long deadline = System.currentTimeMillis() + bounds.wallClockMillis();
		final AddressSetView exit = bounds.exitAddresses();
		final AddressSetView watch = bounds.dirtyWatch();
		final boolean hasExit = exit != null && !exit.isEmpty();
		final boolean hasWatch = watch != null && !watch.isEmpty();

		while (true) {
			if (mon.isCancelled()) {
				reason = StopReason.CANCELLED;
				break;
			}
			Address pc = thread.getCounter();
			if (hasExit && exit.contains(pc)) {
				reason = StopReason.EXIT_RANGE;
				break;
			}
			if (hasWatch && dirty.contains(watch)) {
				reason = StopReason.DIRTY_WATCH;
				break;
			}
			if (steps >= fuel) {
				reason = StopReason.FUEL;
				break;
			}
			if (System.currentTimeMillis() >= deadline) {
				reason = StopReason.WALLCLOCK;
				break;
			}
			try {
				thread.stepInstruction();
				steps++;
			}
			catch (DecodePcodeExecutionException e) {
				// Decode into uninitialized memory: the code branched somewhere the image did not
				// populate. Usually the natural end of a recovered routine, so not an error.
				log.add(ProvenanceLog.Kind.INFO, safeCounter(thread, entry), 0,
					"decode into uninitialized memory: " + e.getMessage());
				reason = StopReason.DECODE_FAULT;
				break;
			}
			catch (PcodeExecutionException e) {
				log.add(ProvenanceLog.Kind.WARNING, safeCounter(thread, entry), 0,
					"pcode execution aborted: " + e.getMessage());
				reason = StopReason.ERROR;
				break;
			}
			catch (RuntimeException e) {
				log.add(ProvenanceLog.Kind.WARNING, safeCounter(thread, entry), 0,
					"emulation error: " + e);
				reason = StopReason.ERROR;
				break;
			}
		}
		callbacks.setCapturing(false);

		NavigableMap<Address, byte[]> recovered = readBack(emu, dirty, log);
		return new RecoveryResult(dirty, recovered, reason, log, steps);
	}

	/** Read the post-run bytes for each coalesced dirty range out of shared emulator state. */
	private NavigableMap<Address, byte[]> readBack(PcodeEmulator emu, AddressSet dirty,
			ProvenanceLog log) {
		NavigableMap<Address, byte[]> out = new TreeMap<>();
		PcodeExecutorState<byte[]> state = emu.getSharedState();
		for (AddressRange range : dirty.getAddressRanges()) {
			long len = range.getLength();
			if (len <= 0 || len > MAX_READBACK) {
				log.add(ProvenanceLog.Kind.WARNING, range.getMinAddress(), 0,
					"dirty range too large to read back: " + len + " bytes");
				continue;
			}
			try {
				byte[] bytes = state.getVar(range.getMinAddress(), (int) len, false, Reason.INSPECT);
				out.put(range.getMinAddress(), bytes);
			}
			catch (RuntimeException e) {
				log.add(ProvenanceLog.Kind.WARNING, range.getMinAddress(), (int) len,
					"readback failed: " + e);
			}
		}
		return out;
	}

	private static Address safeCounter(PcodeThread<byte[]> thread, Address fallback) {
		try {
			Address pc = thread.getCounter();
			return pc != null ? pc : fallback;
		}
		catch (RuntimeException e) {
			return fallback;
		}
	}

	/**
	 * Emulator callbacks that accumulate the dirty set and log uninitialized reads. The
	 * concrete byte[] state invokes the {@code Address}-based {@code dataWritten} and the
	 * {@code AddressSetView}-based {@code readUninitialized} (verified against the 12.1.2
	 * {@code BytesPcodeExecutorStateSpace} / {@code PcodeEmulationCallbacks.Wrapper}); those
	 * are the two overrides here. Writes to the shared state arrive with a null thread.
	 */
	private static final class RecoveryCallbacks implements PcodeEmulationCallbacks<byte[]> {

		private final AddressSet dirty;
		private final ProvenanceLog log;
		private final IoPolicy io;
		// Gated off until the initial program/register load is done, so setup writes and
		// reads are not mistaken for the emulated code's own activity. Single-threaded with
		// the step loop, so a plain field is sufficient.
		private boolean capturing = false;

		RecoveryCallbacks(AddressSet dirty, ProvenanceLog log, IoPolicy io) {
			this.dirty = dirty;
			this.log = log;
			this.io = io;
		}

		void setCapturing(boolean capturing) {
			this.capturing = capturing;
		}

		@Override
		public <A, U> void dataWritten(PcodeThread<byte[]> thread,
				PcodeExecutorStatePiece<A, U> piece, Address address, int length, U value) {
			if (!capturing || address == null || length <= 0) {
				return;
			}
			// Registers/uniques live in non-memory spaces; keep only real memory writes -- those
			// are the recovered bytes (decrypted payload, copied block, uploaded image).
			if (!address.getAddressSpace().isMemorySpace()) {
				return;
			}
			try {
				dirty.addRange(address, address.add(length - 1));
			}
			catch (RuntimeException e) {
				// Length ran past the end of the space; record at least the base address.
				dirty.add(address);
			}
		}

		@Override
		public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> thread,
				PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason) {
			if (capturing && set != null && !set.isEmpty()) {
				for (AddressRange range : set.getAddressRanges()) {
					Address addr = range.getMinAddress();
					if (!addr.getAddressSpace().isMemorySpace()) {
						continue;
					}
					int size = (int) Math.min(range.getLength(), Integer.MAX_VALUE);
					ProvenanceLog.Kind kind =
						io.isIo(addr) ? ProvenanceLog.Kind.IO_READ : ProvenanceLog.Kind.UNINIT_RAM_READ;
					log.add(kind, addr, size, "reason=" + reason);
				}
			}
			// Return the set unchanged: nothing is initialized here, so data reads see the
			// state's default zeros and an instruction decode into this region faults cleanly
			// (a natural stop). Per the callback contract, the given set must not be modified.
			return set;
		}
	}
}
