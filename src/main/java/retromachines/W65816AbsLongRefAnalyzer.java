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

import java.util.Locale;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Data references for 65816 absolute-long operands (grm-9nxj.35). The vendored language exports
 * every data operand as a packed REF_EXPORT value rather than an address, so Ghidra adds no data
 * references for them. The long forms (ORA/AND/EOR/ADC/STA/LDA/CMP/SBC {@code $bbhhll} and
 * {@code $bbhhll,X}, opcodes {@code $xF} and {@code $1F..$FF}) name all 24 bits, so this needs no
 * DBR or DP state: a primary reference from operand 0 to the written address (the base for
 * {@code ,X}, as for abs,X), WRITE for STA and READ otherwise. A target outside every memory block
 * gets none. Mirrors are byte-mapped blocks, so the address is referenced as written.
 */
public class W65816AbsLongRefAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 Absolute-Long References";
	private static final String DESCRIPTION =
		"Adds data references for 65816 absolute-long and absolute-long,X operands (grm-9nxj.35).";

	public W65816AbsLongRefAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		for (Instruction in : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			reference(program, in);
		}
		return true;
	}

	/** Adds the reference for {@code in} if it is an absolute-long data operand; true if added. */
	static boolean reference(Program program, Instruction in) {
		if (in.getLength() != 4 || in.getNumOperands() < 1) {
			return false;
		}
		try {
			int op = in.getByte(0) & 0x1f;
			if (op != 0x0f && op != 0x1f) {
				return false;
			}
			long target = (in.getByte(1) & 0xffL) | (in.getByte(2) & 0xffL) << 8 |
				(in.getByte(3) & 0xffL) << 16;
			Address to = program.getAddressFactory().getDefaultAddressSpace().getAddress(target);
			if (!program.getMemory().contains(to)) {
				return false;
			}
			for (Reference r : in.getReferencesFrom()) {
				if (r.isMemoryReference() && !r.getReferenceType().isFlow() &&
					r.getToAddress().equals(to)) {
					return false;
				}
			}
			RefType type = W65816DirectPageAnalyzer.typeOf(
				in.getMnemonicString().toUpperCase(Locale.ROOT));
			program.getReferenceManager().addMemoryReference(in.getMinAddress(), to, type,
				SourceType.ANALYSIS, 0);
			return true;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}
}
