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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;

/**
 * A 65816 routine that drops its caller's stack arguments on the way out (bead grm-9nxj.46):
 * it copies its return address over the top of the arguments, pulls the arguments, and
 * returns. FF3 {@code $C2:5864}, called as {@code PEA ; PEA ; JSR}:
 *
 * <pre>
 *   LDA $01,S     ; 16-bit: the return address
 *   STA $05,S     ; over the two argument words' top
 *   PLA
 *   PLA           ; drop four bytes
 *   SEP #$20
 *   RTS           ; returns through the moved address, four bytes higher
 * </pre>
 *
 * A stack walker that does not know this sees the routine pull below its entry and the caller
 * return with four bytes still pushed. Recognized only as that straight-line tail: a 16-bit
 * {@code LDA $01,S}, a 16-bit {@code STA $(P+1),S}, then pulls of known width totalling P bytes,
 * with only flag instructions between, no branch into the tail, and the {@code RTS}. The caller
 * of a routine with this tail sees its stack drop P bytes over the call.
 */
final class W65816CalleePop {

	private static final int RTS = 0x60;
	private static final int LDA_SR = 0xa3;
	private static final int STA_SR = 0x83;
	private static final int PLA = 0x68;
	private static final int PLX = 0xfa;
	private static final int PLY = 0x7a;

	/** The tail's pulled byte count and the {@code STA $(P+1),S} that moved the return address. */
	record Tail(int bytes, Address store) {
	}

	private W65816CalleePop() {
	}

	/** The argument-dropping tail ending at {@code rts}, or null if it is not one. */
	static Tail tailAt(Program program, Instruction rts) {
		if (rts == null || op(rts) != RTS) {
			return null;
		}
		Register m = program.getRegister("ctx_MF");
		Register x = program.getRegister("ctx_XF");
		Listing listing = program.getListing();
		int pulled = 0;
		Instruction cur = rts;
		while (true) {
			Instruction prev = fallingInto(listing, cur);
			if (prev == null || branchedInto(program, cur.getAddress())) {
				return null;
			}
			int o = op(prev);
			if (o == PLA || o == PLX || o == PLY) {
				int w = width(prev, o == PLA ? m : x);
				if (w == 0) {
					return null;
				}
				pulled += w;
			}
			else if (o == STA_SR) {
				if (pulled == 0 || width(prev, m) != 2 || operandByte(prev) != pulled + 1) {
					return null;
				}
				return loadsReturnAddress(program, listing, prev, m) ?
					new Tail(pulled, prev.getAddress()) : null;
			}
			else if (!isFlagOp(o)) {
				return null;
			}
			cur = prev;
		}
	}

	/** Walks back from {@code store} over flag ops to a 16-bit {@code LDA $01,S}. */
	private static boolean loadsReturnAddress(Program program, Listing listing, Instruction store,
			Register m) {
		Instruction cur = store;
		while (true) {
			Instruction prev = fallingInto(listing, cur);
			if (prev == null || branchedInto(program, cur.getAddress())) {
				return false;
			}
			int o = op(prev);
			if (o == LDA_SR) {
				return width(prev, m) == 2 && operandByte(prev) == 1;
			}
			if (!isFlagOp(o) || o == 0xe2 || o == 0xc2) {
				return false;   // a width change between the load and the store
			}
			cur = prev;
		}
	}

	/** REP, SEP, CLC, SEC, NOP: no stack or A effect. */
	private static boolean isFlagOp(int o) {
		return o == 0xc2 || o == 0xe2 || o == 0x18 || o == 0x38 || o == 0xea;
	}

	private static Instruction fallingInto(Listing listing, Instruction ins) {
		Instruction prev = listing.getInstructionBefore(ins.getAddress());
		return prev != null && ins.getAddress().equals(prev.getFallThrough()) ? prev : null;
	}

	/** True when some flow other than a fall-through reaches {@code a}. */
	private static boolean branchedInto(Program program, Address a) {
		for (Reference r : program.getReferenceManager().getReferencesTo(a)) {
			if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	/** Bytes the register is wide at {@code ins}: 2 at flag 0, 1 at flag 1, 0 when unknown. */
	private static int width(Instruction ins, Register flag) {
		BigInteger v = flag == null ? null : ins.getValue(flag, false);
		return v == null ? 0 : v.signum() == 0 ? 2 : 1;
	}

	private static int op(Instruction ins) {
		try {
			return ins.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	private static int operandByte(Instruction ins) {
		try {
			return ins.getLength() == 2 ? ins.getByte(1) & 0xff : -1;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}
}
