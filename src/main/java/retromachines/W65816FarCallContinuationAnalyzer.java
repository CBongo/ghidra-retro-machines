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
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
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
 * a flag it sets to one value on every return is that value, a flag some returns preserve and
 * the rest set to the jump's own value is that value, and anything else (mixed, unknown,
 * no return) declines the site -- a wrong width decodes wrong code, which is worse than none.
 * The call must be in native mode ({@code E=0}); {@link W65816ReturnProof} refuses {@code XCE},
 * so the callee cannot have changed it. The decimal-decode flag is carried from the jump, as for
 * jump-table targets (grm-hf5h.31).
 *
 * <p>Runs with the other 65816 decoders, early, so function creation and the DP / DBR analyzers
 * see the new code. Once the continuation is decoded the jump is overridden into a call
 * ({@link FlowOverride#CALL}, grm-9nxj.48): its default fall-through is the continuation, so the
 * continuation joins the caller's function body, the decompiler follows the call and carries on
 * there, and the DP / DBR analyzers stamp it with the rest of the body. The stack walkers read
 * the overridden jump through {@link W65816FarCall}.
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
		int joined = 0;
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
			if (overrideToCall(program, in, s, monitor)) {
				joined++;
			}
			String note = "returned to by " + s.kind() + " from " + s.callee() + " (call at " +
				in.getMinAddress() + "), decoded at " + W65816JumpTableAnalyzer.describe(s.ctx());
			listing.setComment(s.cont(), CommentType.EOL, COMMENT + note);
			AnalyzerLog.info(this, "far-call continuation " + s.cont() + " " + note + ", " +
				(got == null ? 0 : count(listing, got)) + " instructions");
			fx.invalidate();
		}
		if (decoded > 0) {
			AnalyzerLog.info(this, "decoded " + decoded + " far-call continuations, " +
				instructions + " instructions; " + joined + " jumps made calls (grm-9nxj.48)");
		}
		return true;
	}

	/**
	 * Turns the far-call jump into a call whose fall-through is the continuation just decoded
	 * (grm-9nxj.48), and re-fits the body of the function holding it so the continuation joins
	 * it. {@link FlowOverride#CALL} on a {@code JML}/{@code JMP} is an {@code UNCONDITIONAL_CALL}
	 * (Ghidra 12.2 {@code FlowOverride.getModifiedFlowType}), whose default fall-through is the
	 * next address: exactly {@code r + 1}, which {@link W65816FarCall#shape} proved. No
	 * fall-through override is set: it would add a second, user-defined flow reference to the
	 * same address for nothing. A function created later follows the call's fall-through when it
	 * is created; one created already is fitted here. True when the override took.
	 */
	private static boolean overrideToCall(Program program, Instruction jmp, Site s,
			TaskMonitor monitor) throws CancelledException {
		Address at = jmp.getMinAddress();
		jmp.setFlowOverride(FlowOverride.CALL);
		Instruction now = program.getListing().getInstructionAt(at);
		if (now == null || !s.cont().equals(now.getFallThrough())) {
			jmp.setFlowOverride(FlowOverride.NONE);   // not the flow shape the walkers expect
			return false;
		}
		Function f = program.getFunctionManager().getFunctionContaining(at);
		if (f != null) {
			CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
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
		if (jmp.getFlowOverride() == FlowOverride.CALL) {
			return null;   // already a call: this analyzer made it one (grm-9nxj.48)
		}
		Listing listing = program.getListing();
		W65816FarCall.Shape shape = W65816FarCall.shape(listing, jmp);
		if (shape == null) {
			return null;
		}
		Address fall = shape.fall();
		boolean far = shape.far();
		Address callee = jmp.getFlows()[0];
		String kind = far ? "RTL" : "RTS";
		String proven = W65816ReturnProof.provenReturn(program, callee);
		if (!kind.equals(proven)) {
			return decline(jmp, "callee " + callee + " proven " + proven + ", need " + kind);
		}
		if (fx.emulation(jmp) || fx.flag(jmp, fx.eRegister()) != 0) {
			return decline(jmp, "not native mode at the jump");
		}
		W65816WidthEffects.Effect e = fx.effect(callee);
		int m = after(fx.flag(jmp, fx.mRegister()), e.m());
		int x = after(fx.flag(jmp, fx.xRegister()), e.x());
		if (m < 0 || x < 0) {
			return decline(jmp, "width after callee unknown: m=" + m + " x=" + x + " (" + e + ")");
		}
		MemoryBlock block = program.getMemory().getBlock(fall);
		if (block == null || !block.isInitialized() || block.isWrite() ||
			listing.getInstructionAt(fall) != null || listing.getDefinedDataContaining(fall) != null ||
			program.getFunctionManager().getFunctionAt(fall) != null) {
			return decline(jmp, "continuation " + fall + " not free ROM (block " + block +
				", data " + listing.getDefinedDataContaining(fall) + ")");
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

	/**
	 * Env-gated diagnostic (grm-9nxj.52): {@code GRM_FARCALL_TRACE=1} prints why a site with the
	 * far-call shape was declined, so a missing continuation is attributed to its guard.
	 */
	private static final boolean TRACE = System.getenv("GRM_FARCALL_TRACE") != null;

	private static Site decline(Instruction jmp, String why) {
		if (TRACE) {
			System.out.println("FARCALL declined at " + jmp.getMinAddress() + ": " + why);
		}
		return null;
	}

	/**
	 * The flag after the callee, or -1: the one value its returns can leave given the caller's
	 * known width at the jump (grm-9nxj.54: some returns preserving M and the rest setting it to
	 * the caller's value is one value, not a mixed exit).
	 */
	private static int after(int before, W65816WidthEffects.Flag callee) {
		if (before != 0 && before != 1) {
			return -1;
		}
		return callee.knownAfter(before);
	}
}
