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

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decodes the code after a 65816 far call made by hand (bead grm-9nxj.42): {@code PHK / PER r /
 * JML f} pushes a return address ({@code PBR}, then {@code r}) and jumps; {@code f}'s {@code RTL}
 * pulls it and continues at {@code r + 1}. F-Zero ({@code $00:8EAA}, {@code $00:9D76}) uses it to
 * call bank-3 routines. The language sees only a jump, so nothing ever decodes the bytes after
 * it, and every routine making such a call has an exit nobody can see (the DBR analyzer's
 * {@code pushedCall} needs the continuation decoded to walk it). {@code PEA r / JMP f} into an
 * {@code RTS} routine, with or without the {@code PHK}, is the same call.
 *
 * <p><b>Guard rails</b>, every one required:
 * <ul>
 * <li>the push immediately precedes the jump and its value is a constant in the instruction
 * ({@code PER} displacement or {@code PEA} operand), and {@code r + 1} is exactly the jump's
 * fall-through: the code returns to itself, the canonical shape, not to some other address;</li>
 * <li>with {@code PHK} before it the return is three bytes and the callee must return by
 * {@code RTL}; without it two, by {@code RTS}, and the callee must be in the jump's own bank
 * (an RTS returns in the bank it runs in);</li>
 * <li>{@link W65816ReturnProof} proves every path of the callee returns by that instruction with
 * the stack it found;</li>
 * <li>the continuation is in initialized, non-writable memory (ROM), holds no instruction or
 * defined data, and is no function's entry.</li>
 * </ul>
 *
 * <p><b>Width.</b> The continuation runs with the flags the callee returns with, not the
 * caller's. {@link W65816WidthEffects} summarizes the callee: a flag it preserves is the jump's,
 * a flag it sets to one value on every return is that value, and anything else (mixed, unknown,
 * no return) declines the site -- a wrong width decodes wrong code, which is worse than none.
 * The call must be in native mode ({@code E=0}); {@link W65816ReturnProof} refuses {@code XCE},
 * so the callee cannot have changed it. The decimal-decode flag is carried from the jump, as for
 * jump-table targets (grm-hf5h.31).
 *
 * <p>Runs with the other 65816 decoders, early, so function creation and the DP / DBR analyzers
 * see the new code. The continuation stays outside any function body (the jump is terminal); the
 * DBR analyzer walks into it through the pushed return address.
 */
public class W65816FarCallContinuationAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 Far Call Continuations";
	private static final String DESCRIPTION =
		"Decodes the code after a hand-made 65816 far call (PHK / PER / JML, PEA / JMP), at the " +
			"width the callee returns with (grm-9nxj.42).";
	static final String COMMENT = "65816 far-call continuation: ";

	public W65816FarCallContinuationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program);
	}

	/** A recognized far call: where it continues, and the context to decode it under. */
	record Site(Address cont, Map<Register, Integer> ctx, String kind, Address callee) {
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		W65816WidthEffects fx = new W65816WidthEffects(program);
		int decoded = 0;
		int instructions = 0;
		for (Instruction in : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			Site s = recognize(program, fx, in);
			if (s == null) {
				continue;
			}
			if (!stamp(program, s)) {
				continue;
			}
			DisassembleCommand cmd = new DisassembleCommand(s.cont(), null, true);
			cmd.applyTo(program, monitor);
			if (listing.getInstructionAt(s.cont()) == null) {
				continue;
			}
			AddressSetView got = cmd.getDisassembledAddressSet();
			InlineJumpTableDispatchAnalyzer.followDroppedFlows(program, listing, got, monitor);
			decoded++;
			instructions += got == null ? 0 : count(listing, got);
			String note = "returned to by " + s.kind() + " from " + s.callee() + " (call at " +
				in.getMinAddress() + "), decoded at " + W65816JumpTableAnalyzer.describe(s.ctx());
			listing.setComment(s.cont(), CommentType.EOL, COMMENT + note);
			AnalyzerLog.info(this, "far-call continuation " + s.cont() + " " + note + ", " +
				(got == null ? 0 : count(listing, got)) + " instructions");
			fx.invalidate();
		}
		if (decoded > 0) {
			AnalyzerLog.info(this, "decoded " + decoded + " far-call continuations, " +
				instructions + " instructions");
		}
		return true;
	}

	private static int count(Listing listing, AddressSetView set) {
		int n = 0;
		for (var it = listing.getInstructions(set, true); it.hasNext(); it.next()) {
			n++;
		}
		return n;
	}

	private static boolean stamp(Program program, Site s) {
		for (Map.Entry<Register, Integer> c : s.ctx().entrySet()) {
			try {
				program.getProgramContext().setValue(c.getKey(), s.cont(), s.cont(),
					BigInteger.valueOf(c.getValue()));
			}
			catch (ContextChangeException e) {
				return false;
			}
		}
		return true;
	}

	/** The far call ending at {@code jmp}, when every guard rail holds; null otherwise. */
	static Site recognize(Program program, W65816WidthEffects fx, Instruction jmp) {
		String mn = jmp.getMnemonicString().toUpperCase(Locale.ROOT);
		if (!(mn.equals("JML") || mn.equals("JMP")) || jmp.getFlowType().isComputed() ||
			jmp.getFlows().length != 1) {
			return null;
		}
		Listing listing = program.getListing();
		Address fall = jmp.getMaxAddress().next();
		Instruction push = adjacentBefore(listing, jmp);
		if (fall == null || push == null) {
			return null;
		}
		int pushed = pushedWord(push);
		if (pushed < 0 || ((pushed + 1) & 0xffff) != (fall.getOffset() & 0xffff)) {
			return null;
		}
		Instruction phk = adjacentBefore(listing, push);
		boolean far = phk != null && phk.getMnemonicString().equalsIgnoreCase("PHK");
		Address callee = jmp.getFlows()[0];
		long bank = jmp.getMinAddress().getOffset() & 0xff0000L;
		if (!far && (callee.getOffset() & 0xff0000L) != bank) {
			return null;   // an RTS returns in the callee's bank, not to this one
		}
		if ((fall.getOffset() & 0xff0000L) != bank) {
			return null;   // the jump ends on a bank boundary
		}
		String kind = far ? "RTL" : "RTS";
		if (!kind.equals(W65816ReturnProof.provenReturn(program, callee))) {
			return null;
		}
		if (fx.emulation(jmp) || fx.flag(jmp, fx.eRegister()) != 0) {
			return null;
		}
		W65816WidthEffects.Effect e = fx.effect(callee);
		int m = after(fx.flag(jmp, fx.mRegister()), e.m().exit());
		int x = after(fx.flag(jmp, fx.xRegister()), e.x().exit());
		if (m < 0 || x < 0) {
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(fall);
		if (block == null || !block.isInitialized() || block.isWrite() ||
			listing.getInstructionAt(fall) != null || listing.getDefinedDataContaining(fall) != null ||
			program.getFunctionManager().getFunctionAt(fall) != null) {
			return null;
		}
		Map<Register, Integer> ctx = new LinkedHashMap<>();
		ctx.put(fx.eRegister(), 0);
		ctx.put(fx.mRegister(), m);
		ctx.put(fx.xRegister(), x);
		if (fx.dRegister() != null && fx.flag(jmp, fx.dRegister()) >= 0) {
			ctx.put(fx.dRegister(), fx.flag(jmp, fx.dRegister()));
		}
		return new Site(fall, ctx, kind, callee);
	}

	/** The flag after the callee: the caller's when preserved, the callee's constant, else -1. */
	private static int after(int before, int exit) {
		if (exit == W65816WidthEffects.INHERITED) {
			return before == 0 || before == 1 ? before : -1;
		}
		return exit == 0 || exit == 1 ? exit : -1;
	}

	private static Instruction adjacentBefore(Listing listing, Instruction in) {
		Instruction p = listing.getInstructionBefore(in.getMinAddress());
		return p != null && p.getMaxAddress().next() != null &&
			p.getMaxAddress().next().equals(in.getMinAddress()) ? p : null;
	}

	/** The word a {@code PER} or {@code PEA} pushes, or -1. */
	private static int pushedWord(Instruction push) {
		String mn = push.getMnemonicString().toUpperCase(Locale.ROOT);
		if (push.getLength() != 3 || !(mn.equals("PER") || mn.equals("PEA"))) {
			return -1;
		}
		try {
			int w = (push.getByte(1) & 0xff) | (push.getByte(2) & 0xff) << 8;
			if (mn.equals("PEA")) {
				return w;
			}
			return (int) ((push.getMinAddress().getOffset() + 3 + (short) w) & 0xffff);
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}
}
