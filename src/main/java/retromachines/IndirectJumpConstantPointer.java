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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Pure(ish) logic for grm-v60.1: resolve a {@code JMP (P)} whose pointer cell {@code P} is
 * proven constant on a straight-line path from RESET (or any other reachable entry), by walking
 * forward as a static constant tracker -- not an emulator -- from every provable start.
 *
 * <p>See the bead and {@code JumpTableBoundAnalyzer} (the model this class's plumbing mirrors)
 * for the broader picture. This class does the analysis; {@link IndirectJumpConstantPointerAnalyzer}
 * is the thin {@code AbstractAnalyzer} wrapper that finds sites in a program and applies results.
 *
 * <p><b>Placement assumption.</b> A resolved target is always constructed in the {@code JMP}
 * instruction's OWN address space -- exactly what a direct {@code JMP $xxxx} at the same address
 * would get. Bank retargeting (moving that reference into the correct overlay) is deliberately
 * left to the existing machinery (grm-v60); this class does not attempt it.
 *
 * @see <a href="urn:bead:grm-v60.1">grm-v60.1</a>
 */
final class IndirectJumpConstantPointer {

	/** Backward walk-start search cap ("about 12 instructions", per the design). */
	private static final int BACKWARD_STEP_CAP = 12;

	/** Forward walk instruction budget ("about 256 instructions"). */
	private static final int FORWARD_BUDGET = 256;

	/** Maximum inline JSR nesting depth. */
	private static final int MAX_CALL_DEPTH = 4;

	private IndirectJumpConstantPointer() {
	}

	/**
	 * Whether {@code instr} is a "site" this class cares about: {@code JMP} with the plain
	 * absolute-indirect operand ({@code JMP ($nnnn)}), i.e. exactly one operand object --
	 * excluding the 65C02 {@code JMP (abs,X)} form, which carries a {@link Register} operand
	 * object too (opcode {@code 0x7C}, not modeled here at all). Classified by raw opcode byte,
	 * not {@link Instruction#getOpObjects}, whose runtime object type for a 6502 operand
	 * (plain {@link Address} vs bare {@link ghidra.program.model.scalar.Scalar}) turns out to
	 * depend on the addressing mode in a way that is not a reliable signal on its own -- see
	 * {@link #classifyMode} and its javadoc.
	 */
	static boolean isIndirectJumpSite(Instruction instr) {
		if (!"JMP".equals(instr.getMnemonicString())) {
			return false;
		}
		FlowType ft = instr.getFlowType();
		if (!ft.isJump() || !ft.isComputed()) {
			return false;
		}
		return opcodeByte(instr) == 0x6c;
	}

	/** The pointer cell address {@code P} a {@link #isIndirectJumpSite} instruction dereferences,
	 *  in the instruction's own address space -- the raw 16-bit absolute operand, same byte
	 *  layout as {@link #directAddress}. */
	static Address pointerCell(Instruction instr) {
		return directAddress(instr);
	}

	/**
	 * Resolves every distinct target this indirect jump's pointer cell can be proven to hold,
	 * one per distinct straight-line walk-start that reaches {@code siteAddr} with both pointer
	 * bytes known. Returns an empty set if none resolve.
	 */
	static Set<Address> resolveTargets(Program program, Address siteAddr, Address pointerAddr,
			TaskMonitor monitor) throws CancelledException {
		AddressSpace space = siteAddr.getAddressSpace();
		Address pointerAddr1 = nextByte(pointerAddr);

		List<Address> starts = findWalkStarts(program, space, pointerAddr, pointerAddr1, monitor);
		Set<Address> targets = new LinkedHashSet<>();
		for (Address start : starts) {
			monitor.checkCancelled();
			Address target = walk(program, start, siteAddr, pointerAddr, pointerAddr1, monitor);
			if (target != null) {
				targets.add(target);
			}
		}
		return targets;
	}

	/** {@code addr + 1}, wrapping within {@code addr}'s own address space. */
	private static Address nextByte(Address addr) {
		AddressSpace space = addr.getAddressSpace();
		long mask = space.getMaxAddress().getOffset();
		long next = (addr.getOffset() + 1) & mask;
		return space.getAddress(next);
	}

	// ---------------------------------------------------------------------
	// Walk starts: every STA/STX/STY in the site's own address space whose direct (non-indexed)
	// operand is P or P+1, backed up to the head of its straight-line run.
	// ---------------------------------------------------------------------

	private static List<Address> findWalkStarts(Program program, AddressSpace space,
			Address p, Address p1, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		AddressSet spaceSet = new AddressSet(space.getMinAddress(), space.getMaxAddress());
		List<Address> starts = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(spaceSet, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			if (isDirectStoreTo(instr, p, p1)) {
				starts.add(headOfRun(program, listing, instr.getMinAddress(), monitor));
			}
		}
		return starts;
	}

	private static boolean isDirectStoreTo(Instruction instr, Address p, Address p1) {
		String mn = instr.getMnemonicString();
		if (!("STA".equals(mn) || "STX".equals(mn) || "STY".equals(mn))) {
			return false;
		}
		if (classifyMode(instr) != Mode.DIRECT) {
			return false; // indexed, or some other shape -- not a "direct" operand
		}
		Address addr = directAddress(instr);
		return addr != null && (addr.equals(p) || addr.equals(p1));
	}

	/**
	 * Backs {@code storeAddr} up to the head of its straight-line run: step to the immediately
	 * preceding instruction as long as it plainly falls through into the current position and is
	 * not itself a conditional branch, jump, call or return; stop (keep the current position)
	 * before any such instruction, and stop AT (but not past) a position something else flows
	 * into.
	 */
	private static Address headOfRun(Program program, Listing listing, Address storeAddr,
			TaskMonitor monitor) throws CancelledException {
		Address head = storeAddr;
		for (int i = 0; i < BACKWARD_STEP_CAP; i++) {
			monitor.checkCancelled();
			Instruction prev = listing.getInstructionBefore(head);
			if (prev == null) {
				break;
			}
			Address fallThrough = prev.getFallThrough();
			if (fallThrough == null || !fallThrough.equals(head)) {
				break; // prev does not plainly fall through into head
			}
			FlowType prevFlow = prev.getFlowType();
			if (prevFlow.isJump() || prevFlow.isCall() || prevFlow.isTerminal()) {
				break; // stop BEFORE a conditional branch, jump, call or return
			}
			head = prev.getMinAddress();
			if (isReferencedLabel(program, head)) {
				break; // stop AT a position something else flows into
			}
		}
		return head;
	}

	private static boolean isReferencedLabel(Program program, Address addr) {
		ReferenceManager refMgr = program.getReferenceManager();
		ReferenceIterator refs = refMgr.getReferencesTo(addr);
		while (refs.hasNext()) {
			if (refs.next().getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	// ---------------------------------------------------------------------
	// Forward walk: a static constant tracker, not an emulator.
	// ---------------------------------------------------------------------

	/** Tracked state: exact-or-unknown A/X/Y, and exact byte values for written RAM addresses. */
	private static final class WalkState {
		Integer a;
		Integer x;
		Integer y;
		final Map<Address, Integer> ram = new HashMap<>();
		/** Set by any store to non-writable memory: on a mapper board that is a register write
		 *  that may have switched banks, so from here on the base-space listing is only trusted
		 *  where every bank holds the same bytes (see {@link #bankInvariant}). */
		boolean mayHaveSwitched;
	}

	private enum Reg {
		A, X, Y
	}

	/**
	 * Walks forward from {@code start} until it reaches {@code siteAddr} with both pointer bytes
	 * known (returns the resolved target address, in {@code siteAddr}'s own space), or until the
	 * path is proven not to resolve (returns null): budget exhausted, a conditional branch, an
	 * unresolvable indirect jump (including reaching {@code siteAddr} with an unknown byte, or
	 * any OTHER computed jump), a return with an empty inline-call stack, or a JSR nested past
	 * {@link #MAX_CALL_DEPTH}.
	 */
	private static Address walk(Program program, Address start, Address siteAddr,
			Address pointerAddr, Address pointerAddr1, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		WalkState st = new WalkState();
		Deque<Address> callStack = new ArrayDeque<>();
		Address pc = start;

		for (int steps = 0; steps < FORWARD_BUDGET; steps++) {
			monitor.checkCancelled();
			Instruction instr = listing.getInstructionAt(pc);
			if (instr == null) {
				return null;
			}
			if (st.mayHaveSwitched && !bankInvariant(program, instr)) {
				return null; // after a possible bank switch this may not be the code that runs
			}
			FlowType ft = instr.getFlowType();
			boolean computedJump = "JMP".equals(instr.getMnemonicString()) && ft.isJump() &&
				ft.isComputed();
			if (computedJump) {
				if (pc.equals(siteAddr)) {
					Integer lo = st.ram.get(pointerAddr);
					Integer hi = st.ram.get(pointerAddr1);
					if (lo == null || hi == null) {
						return null;
					}
					long target = (lo & 0xff) | ((hi & 0xff) << 8);
					AddressSpace space = siteAddr.getAddressSpace();
					long mask = space.getMaxAddress().getOffset();
					return space.getAddress(target & mask);
				}
				return null; // some other indirect jump -- decision point, walk stops either way
			}
			if (ft.isConditional()) {
				return null; // any conditional branch stops the walk
			}
			String mn = instr.getMnemonicString();
			if ("JSR".equals(mn)) {
				Address target = singleFlowTarget(instr);
				if (target == null || callStack.size() >= MAX_CALL_DEPTH) {
					return null;
				}
				Address ret = instr.getFallThrough();
				if (ret == null) {
					return null;
				}
				callStack.push(ret);
				pc = target;
				continue;
			}
			if ("RTS".equals(mn) || "RTI".equals(mn)) {
				if (callStack.isEmpty()) {
					return null; // empty stack -- this path exits the walk's own frame
				}
				pc = callStack.pop();
				continue;
			}
			if (ft.isJump()) {
				// Unconditional JMP abs (a computed jump was already handled above).
				Address target = singleFlowTarget(instr);
				if (target == null) {
					return null;
				}
				pc = target;
				continue;
			}
			if (ft.isTerminal() || ft.isCall()) {
				return null; // any other call/terminal shape this walk does not model
			}

			applyInstruction(program, instr, st);

			Address fallThrough = instr.getFallThrough();
			if (fallThrough == null) {
				return null;
			}
			pc = fallThrough;
		}
		return null; // budget exhausted
	}

	private static Address singleFlowTarget(Instruction instr) {
		Address[] flows = instr.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	// ---------------------------------------------------------------------
	// Instruction semantics.
	// ---------------------------------------------------------------------

	private static void applyInstruction(Program program, Instruction instr, WalkState st) {
		switch (instr.getMnemonicString()) {
			case "LDA":
				st.a = loadValue(instr, st);
				return;
			case "LDX":
				st.x = loadValue(instr, st);
				return;
			case "LDY":
				st.y = loadValue(instr, st);
				return;
			case "STA":
				applyStore(program, instr, st, Reg.A);
				return;
			case "STX":
				applyStore(program, instr, st, Reg.X);
				return;
			case "STY":
				applyStore(program, instr, st, Reg.Y);
				return;
			case "TAX":
				st.x = st.a;
				return;
			case "TAY":
				st.y = st.a;
				return;
			case "TXA":
				st.a = st.x;
				return;
			case "TYA":
				st.a = st.y;
				return;
			case "INX":
				st.x = step(st.x, 1);
				return;
			case "DEX":
				st.x = step(st.x, -1);
				return;
			case "INY":
				st.y = step(st.y, 1);
				return;
			case "DEY":
				st.y = step(st.y, -1);
				return;
			case "ASL":
				if (classifyMode(instr) == Mode.ACCUMULATOR) {
					st.a = st.a == null ? null : ((st.a << 1) & 0xff);
					return;
				}
				break;
			case "LSR":
				if (classifyMode(instr) == Mode.ACCUMULATOR) {
					st.a = st.a == null ? null : ((st.a >> 1) & 0xff);
					return;
				}
				break;
			case "AND":
				st.a = applyLogic(instr, st, 0);
				return;
			case "ORA":
				st.a = applyLogic(instr, st, 1);
				return;
			case "EOR":
				st.a = applyLogic(instr, st, 2);
				return;
			default:
				break;
		}
		// Everything else (ROL/ROR, memory-operand ASL/LSR, NOP, flag-only ops, TXS/TSX,
		// PHA/PHP/PLA/PLP, CMP/BIT/ADC/SBC, illegal opcodes, ...): conservatively, via p-code.
		applyGeneric(program, instr, st);
	}

	private static Integer step(Integer v, int delta) {
		return v == null ? null : ((v + delta) & 0xff);
	}

	/**
	 * The addressing mode of an instruction's memory/immediate operand, classified from the raw
	 * opcode byte -- not {@link Instruction#getOpObjects}. The 6502 sleigh's runtime object type
	 * for operand 0 is not a reliable mode signal on its own: a NON-indexed direct load/store
	 * (e.g. {@code STA $17}) renders as a plain {@link Address}, while an IMMEDIATE value
	 * ({@code LDA #$08}), an indirect jump's pointer ({@code JMP ($0017)}), and an indexed
	 * operand's base ({@code STA $9600,Y}) all render as a bare
	 * {@link ghidra.program.model.scalar.Scalar} -- the same Java type for three semantically
	 * different things. Classifying by the instruction's own opcode byte, exactly as {@code
	 * MosConstantReferenceAnalyzer.classify} does for the same underlying reason, sidesteps that
	 * ambiguity entirely.
	 */
	private enum Mode {
		IMMEDIATE, DIRECT, INDEXED_X, INDEXED_Y, ACCUMULATOR, OTHER
	}

	private static int opcodeByte(Instruction instr) {
		try {
			return instr.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/** Classifies the small, fixed set of opcodes this class models precisely; every opcode not
	 *  listed here (including every (zp,X)/(zp),Y indirect form) is {@link Mode#OTHER}. */
	private static Mode classifyMode(Instruction instr) {
		int opcode = opcodeByte(instr);
		if (opcode < 0) {
			return Mode.OTHER;
		}
		return switch (instr.getMnemonicString()) {
			case "LDA" -> switch (opcode) {
				case 0xa9 -> Mode.IMMEDIATE;
				case 0xa5, 0xad -> Mode.DIRECT;
				case 0xb5, 0xbd -> Mode.INDEXED_X;
				case 0xb9 -> Mode.INDEXED_Y;
				default -> Mode.OTHER;
			};
			case "LDX" -> switch (opcode) {
				case 0xa2 -> Mode.IMMEDIATE;
				case 0xa6, 0xae -> Mode.DIRECT;
				case 0xb6, 0xbe -> Mode.INDEXED_Y;
				default -> Mode.OTHER;
			};
			case "LDY" -> switch (opcode) {
				case 0xa0 -> Mode.IMMEDIATE;
				case 0xa4, 0xac -> Mode.DIRECT;
				case 0xb4, 0xbc -> Mode.INDEXED_X;
				default -> Mode.OTHER;
			};
			case "STA" -> switch (opcode) {
				case 0x85, 0x8d -> Mode.DIRECT;
				case 0x95, 0x9d -> Mode.INDEXED_X;
				case 0x99 -> Mode.INDEXED_Y;
				default -> Mode.OTHER;
			};
			case "STX" -> switch (opcode) {
				case 0x86, 0x8e -> Mode.DIRECT;
				case 0x96 -> Mode.INDEXED_Y;
				default -> Mode.OTHER;
			};
			case "STY" -> switch (opcode) {
				case 0x84, 0x8c -> Mode.DIRECT;
				case 0x94 -> Mode.INDEXED_X;
				default -> Mode.OTHER;
			};
			case "AND" -> switch (opcode) {
				case 0x29 -> Mode.IMMEDIATE;
				case 0x25, 0x2d -> Mode.DIRECT;
				default -> Mode.OTHER; // indexed AND not modeled precisely (imm/zp/abs only)
			};
			case "ORA" -> switch (opcode) {
				case 0x09 -> Mode.IMMEDIATE;
				case 0x05, 0x0d -> Mode.DIRECT;
				default -> Mode.OTHER;
			};
			case "EOR" -> switch (opcode) {
				case 0x49 -> Mode.IMMEDIATE;
				case 0x45, 0x4d -> Mode.DIRECT;
				default -> Mode.OTHER;
			};
			case "ASL" -> opcode == 0x0a ? Mode.ACCUMULATOR : Mode.OTHER;
			case "LSR" -> opcode == 0x4a ? Mode.ACCUMULATOR : Mode.OTHER;
			default -> Mode.OTHER;
		};
	}

	/** The raw 16-bit-or-8-bit address operand a {@link Mode#DIRECT}, {@link Mode#INDEXED_X},
	 *  {@link Mode#INDEXED_Y} instruction (or an indirect {@code JMP}) encodes -- a zero-page
	 *  byte for a 2-byte instruction, an absolute little-endian word for a 3-byte one -- read
	 *  straight from the instruction's own bytes, in its own address space. Returns null if the
	 *  bytes cannot be read or the instruction is neither 2 nor 3 bytes long. */
	private static Address directAddress(Instruction instr) {
		try {
			int len = instr.getLength();
			AddressSpace space = instr.getMinAddress().getAddressSpace();
			if (len == 2) {
				return space.getAddress(instr.getByte(1) & 0xff);
			}
			if (len == 3) {
				int lo = instr.getByte(1) & 0xff;
				int hi = instr.getByte(2) & 0xff;
				return space.getAddress((hi << 8) | lo);
			}
		}
		catch (MemoryAccessException e) {
			// fall through
		}
		return null;
	}

	/** The immediate value an {@link Mode#IMMEDIATE} instruction encodes, or null if unreadable. */
	private static Integer immediateValue(Instruction instr) {
		try {
			return instr.getByte(1) & 0xff;
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	/** {@link #directAddress}'s base, offset by a known index register, with 16-bit wrap. Returns
	 *  null if the index is unknown or the base is unreadable. */
	private static Address indexedAddress(Instruction instr, Integer index) {
		if (index == null) {
			return null;
		}
		Address base = directAddress(instr);
		if (base == null) {
			return null;
		}
		AddressSpace space = base.getAddressSpace();
		long mask = space.getMaxAddress().getOffset();
		long offset = (base.getOffset() + index) & mask;
		return space.getAddress(offset);
	}

	private static Integer loadValue(Instruction instr, WalkState st) {
		return switch (classifyMode(instr)) {
			case IMMEDIATE -> immediateValue(instr);
			case DIRECT -> {
				Address a = directAddress(instr);
				yield a == null ? null : st.ram.get(a);
			}
			default -> null; // indexed, or any other shape -- unknown
		};
	}

	/** {@code op}: 0 = AND, 1 = ORA, 2 = EOR. Immediate or direct (zp/abs) operand only. */
	private static Integer applyLogic(Instruction instr, WalkState st, int op) {
		Integer operand = switch (classifyMode(instr)) {
			case IMMEDIATE -> immediateValue(instr);
			case DIRECT -> {
				Address a = directAddress(instr);
				yield a == null ? null : st.ram.get(a);
			}
			default -> null;
		};
		Integer a = st.a;
		if (a == null || operand == null) {
			return null;
		}
		int result = switch (op) {
			case 0 -> a & operand;
			case 1 -> a | operand;
			default -> a ^ operand;
		};
		return result & 0xff;
	}

	private static void applyStore(Program program, Instruction instr, WalkState st, Reg reg) {
		Integer value = switch (reg) {
			case A -> st.a;
			case X -> st.x;
			case Y -> st.y;
		};
		Address addr = switch (classifyMode(instr)) {
			case DIRECT -> directAddress(instr);
			case INDEXED_X -> indexedAddress(instr, st.x);
			case INDEXED_Y -> indexedAddress(instr, st.y);
			default -> null; // (zp,X)/(zp),Y or unreadable -- not modeled; conservative below
		};
		if (addr == null) {
			st.ram.clear(); // unknown index, unresolvable, or an unmodeled shape -- clobbers anything
			st.mayHaveSwitched = true; // ...including, possibly, a mapper register
			return;
		}
		if (!isWritable(program, addr)) {
			// ROM, a mapper register, or unmapped: no RAM effect, but possibly a bank switch.
			st.mayHaveSwitched = true;
			return;
		}
		if (value == null) {
			st.ram.remove(addr);
		}
		else {
			st.ram.put(addr, value & 0xff);
		}
	}

	/**
	 * Whether every byte of {@code instr} is identical in its own block and in every overlay
	 * block covering the same offsets of the same base space -- i.e. whichever bank is mapped
	 * there, this is the instruction that executes. Refuses on any uninitialized or unreadable
	 * copy (a bank slot the image does not fill is unknown, not equal). Mirrors
	 * {@code MemoryLatchBankSwitchStrategy.contentInvariantByte} (grm-e7v), per instruction.
	 */
	private static boolean bankInvariant(Program program, Instruction instr) {
		Memory memory = program.getMemory();
		Address min = instr.getMinAddress();
		AddressSpace physical = min.getAddressSpace().getPhysicalSpace();
		byte[] bytes;
		try {
			bytes = instr.getBytes();
		}
		catch (MemoryAccessException e) {
			return false;
		}
		for (MemoryBlock b : memory.getBlocks()) {
			AddressSpace bs = b.getStart().getAddressSpace();
			if (bs.equals(min.getAddressSpace()) || !bs.getPhysicalSpace().equals(physical)) {
				continue; // the instruction's own copy, or a different base space entirely
			}
			long lo = b.getStart().getOffset();
			long hi = b.getEnd().getOffset();
			long first = min.getOffset();
			long last = first + bytes.length - 1;
			if (last < lo || first > hi) {
				continue;
			}
			if (!b.isInitialized() || first < lo || last > hi) {
				return false;
			}
			for (int i = 0; i < bytes.length; i++) {
				try {
					if (memory.getByte(bs.getAddress(first + i)) != bytes[i]) {
						return false;
					}
				}
				catch (MemoryAccessException | RuntimeException e) {
					return false;
				}
			}
		}
		return true;
	}

	private static boolean isWritable(Program program, Address addr) {
		MemoryBlock block = program.getMemory().getBlock(addr);
		return block != null && block.isWrite();
	}

	/**
	 * Conservative fallback for any instruction not precisely modeled above: any register (of
	 * A/X/Y) the instruction's p-code writes becomes unknown; a p-code {@code STORE} kills the
	 * exact tracked address when its address is a plain constant, else clears the whole map
	 * (mirrors an indexed store with an unknown index). If the instruction's p-code cannot be
	 * obtained at all, conservatively clears everything.
	 */
	private static void applyGeneric(Program program, Instruction instr, WalkState st) {
		PcodeOp[] ops;
		try {
			ops = instr.getPcode();
		}
		catch (RuntimeException e) {
			ops = null;
		}
		if (ops == null) {
			st.mayHaveSwitched = true;
			st.a = null;
			st.x = null;
			st.y = null;
			st.ram.clear();
			return;
		}
		for (PcodeOp op : ops) {
			Varnode out = op.getOutput();
			if (out != null) {
				Register r = safeGetRegister(program, out);
				if (r != null) {
					switch (r.getName().toUpperCase()) {
						case "A":
							st.a = null;
							break;
						case "X":
							st.x = null;
							break;
						case "Y":
							st.y = null;
							break;
						default:
							break; // flags or anything else -- not tracked
					}
				}
			}
			if (op.getOpcode() == PcodeOp.STORE) {
				Address constAddr = constantStoreAddress(program, op.getInput(1));
				if (constAddr != null) {
					st.ram.remove(constAddr);
					if (!isWritable(program, constAddr)) {
						st.mayHaveSwitched = true;
					}
				}
				else {
					st.ram.clear();
					st.mayHaveSwitched = true; // an unknown address may be a mapper register
				}
			}
		}
	}

	private static Address constantStoreAddress(Program program, Varnode addrVn) {
		if (addrVn.isAddress()) {
			return addrVn.getAddress();
		}
		if (addrVn.isConstant()) {
			AddressFactory factory = program.getAddressFactory();
			AddressSpace defaultSpace = factory.getDefaultAddressSpace();
			try {
				return defaultSpace.getAddress(addrVn.getOffset());
			}
			catch (RuntimeException e) {
				return null;
			}
		}
		return null; // register/unique -- a computed address this fallback does not resolve
	}

	private static Register safeGetRegister(Program program, Varnode vn) {
		try {
			return program.getRegister(vn);
		}
		catch (RuntimeException e) {
			return null;
		}
	}
}
