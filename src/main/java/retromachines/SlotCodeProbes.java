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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

/**
 * The byte-level probes behind {@link JumpTableBound#boundBySlotCode} and its leading analog
 * (grm-c9d.8.8). Bytes only, via the pseudo disassembler, never the listing, so analysis order
 * cannot move the answer. CPU-agnostic: calls, jumps and terminators are classified by Ghidra's
 * {@link FlowType}, not by mnemonic (only {@code BRK} is named, as the other decode checks here do).
 */
final class SlotCodeProbes {

	/** Instructions decoded before a run is accepted as having reached its cap. A real handler
	 *  routine at a table's tail has returned or jumped well inside this; a longer run of legal
	 *  opcodes with two outside calls is already far past coincidence. */
	static final int MAX_STEPS = 32;

	private SlotCodeProbes() {
	}

	static JumpTableBound.SlotCodeProbe of(Program program, AddressSpace space) {
		PseudoDisassembler dis = new PseudoDisassembler(program);
		return new JumpTableBound.SlotCodeProbe(offset -> run(dis, space, offset),
			offset -> isCode(program, dis, space, offset));
	}

	private static Address addr(AddressSpace space, long offset) {
		try {
			return space.getAddress(offset);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	static JumpTableBound.CodeRun run(PseudoDisassembler dis, AddressSpace space, long offset) {
		Address at = addr(space, offset);
		List<Long> calls = new ArrayList<>();
		long end = offset;
		for (int i = 0; i < MAX_STEPS; i++) {
			ghidra.program.model.listing.Instruction instr;
			try {
				instr = at == null ? null : dis.disassemble(at);
			}
			catch (Exception e) {
				instr = null; // undefined opcode, or bytes run out mid-instruction
			}
			if (instr == null || "BRK".equals(instr.getMnemonicString())) {
				return new JumpTableBound.CodeRun(false, false, end, calls);
			}
			end = at.getOffset() + instr.getLength();
			FlowType flow = instr.getFlowType();
			boolean uncondJump = flow.isJump() && !flow.isConditional();
			if ((flow.isCall() || uncondJump) && !flow.isComputed()) {
				for (Address f : instr.getFlows()) {
					if (f != null && f.getAddressSpace().equals(space)) {
						calls.add(f.getOffset());
					}
				}
			}
			if (flow.isTerminal() || uncondJump) {
				return new JumpTableBound.CodeRun(true, true, end, calls);
			}
			at = instr.getFallThrough();
			if (at == null) {
				return new JumpTableBound.CodeRun(true, true, end, calls);
			}
		}
		return new JumpTableBound.CodeRun(true, false, end, calls);
	}

	private static boolean isCode(Program program, PseudoDisassembler dis, AddressSpace space,
			long offset) {
		Address a = addr(space, offset);
		if (a == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(a);
		if (block == null || !block.isInitialized() || block.isVolatile()) {
			return false;
		}
		try {
			return dis.disassemble(a) != null;
		}
		catch (Exception e) {
			return false;
		}
	}
}
