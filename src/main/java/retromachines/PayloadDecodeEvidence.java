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

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

/**
 * The third and weakest form of evidence that a copy loop moves code (grm-k5m): the payload's
 * own bytes, read where they sit in the initialized source image, decode as a self-contained
 * subroutine.
 *
 * <p>{@link CopyLoopAnalyzer}'s evidence gate wants a jump into the destination. On Wizards
 * &amp; Warriors that evidence exists in the ROM -- the three bank-switch stubs copied to
 * {@code $0300/$032d/$033d} are called from four banks -- but none of the callers is ever
 * disassembled, because the callers live in the banks those very stubs select. The first bank
 * value the analysis could recover is inside a stub it refuses to look at for want of a caller
 * it cannot reach without that value. Something has to break the circle, and the only thing
 * available without a caller is the payload itself.
 *
 * <p>The test is deliberately stricter than Ghidra's own
 * {@link PseudoDisassembler#isValidSubroutine}, whose notion of "terminates" admits {@code BRK}
 * (a computed flow) and so passes a run of zero bytes behind a non-zero lead. Walking from the
 * source start with fall-through and in-range branches followed, every instruction must decode,
 * every instruction must lie inside the payload, no computed flow may occur (a {@code BRK} or
 * {@code JMP (ind)} in a copied stub is data, not a dispatcher), and the walk must reach a real
 * return or an unconditional jump out of the payload. Calls are not followed -- a stub calling
 * a ROM routine, or a sibling stub whose RAM home is still uninitialized, is normal -- and
 * neither is a branch whose target leaves the payload, which counts as an exit. The payload
 * need not be covered end to end: a stub may carry a local table after its {@code RTS}.
 *
 * <p>Why this does not reopen the door grm-1.7.6 closed: the data copies that rule was written
 * for -- runtime buffers, a stack page, sprite/palette tables -- fail on their first bytes on
 * every real cartridge checked (the six data copies wizwarr's boot routine makes all fail: zero
 * runs, undefined opcodes, {@code BRK}s). It is a weak signal by construction, and it is applied
 * only after both jump-based tests have found nothing, so it never changes the outcome of a
 * loop the stronger evidence already decided.
 */
final class PayloadDecodeEvidence {

	/** Fewer instructions than this is not a subroutine, whatever the bytes say. */
	private static final int MIN_INSTRUCTIONS = 2;

	private PayloadDecodeEvidence() {
	}

	/** Whether the {@code len} bytes at {@code src} decode as a self-contained subroutine. */
	static boolean decodesAsSubroutine(Program program, Address src, int len) {
		Address end;
		try {
			end = src.add(len - 1);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(src);
		if (block == null || !block.isInitialized() || !block.contains(end)) {
			return false;
		}
		AddressSet range = new AddressSet(src, end);
		PseudoDisassembler dis = new PseudoDisassembler(program);

		Deque<Address> work = new ArrayDeque<>();
		Set<Address> seen = new HashSet<>();
		work.push(src);
		boolean exited = false;
		int count = 0;
		while (!work.isEmpty()) {
			Address at = work.pop();
			if (!seen.add(at)) {
				continue;
			}
			PseudoInstruction instr;
			try {
				instr = dis.disassemble(at);
			}
			catch (Exception e) {
				return false; // undefined opcode, or bytes run out mid-instruction
			}
			if (instr == null || !range.contains(instr.getMinAddress(), instr.getMaxAddress())) {
				return false;
			}
			FlowType flow = instr.getFlowType();
			if (flow.isComputed()) {
				return false;
			}
			count++;
			if (flow.isTerminal() && !flow.isJump()) {
				exited = true; // RTS / RTI
				continue;
			}
			if (flow.isJump()) {
				for (Address target : instr.getFlows()) {
					if (range.contains(target)) {
						work.push(target);
					}
					else if (!flow.isConditional()) {
						exited = true; // JMP out of the payload: a tail call
					}
				}
			}
			// Calls contribute only their fall-through; the callee is someone else's code.
			if (flow.hasFallthrough() && instr.getFallThrough() != null) {
				work.push(instr.getFallThrough());
			}
		}
		return exited && count >= MIN_INSTRUCTIONS;
	}
}
