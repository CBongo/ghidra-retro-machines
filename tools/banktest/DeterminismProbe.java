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
// Read-only diagnostic for the flaky-golden bead grm-g73: megaman's real-ROM dump is
// BISTABLE, flipping run-to-run between refs.intoOverlay 1704 / instrs.inOverlay 7429 and
// 1703 / 7431 -- one FEWER reference alongside TWO MORE instructions, always in opposite
// directions, on the same ROM against the same build.
//
// WHY THIS EXISTS. RealRomDump.java (the golden) emits COUNTS plus a bounded 25-entry sample
// of the LOWEST-addressed annotations. So when the counts move, the golden can say THAT the
// run diverged but not WHERE -- and megaman's sample is identical in both outcomes, which
// pins the difference somewhere above the sample window and nowhere more precise than that.
// Every investigation of this bead so far has been stuck at that resolution. This script
// removes the bound: it emits EVERY overlay instruction and EVERY reference into an overlay,
// sorted, so two runs' output diffed gives the exact addresses where the outcomes part.
//
// WHAT THE DIFF IS EXPECTED TO LOOK LIKE, if the working hypothesis holds. 6502 instruction
// alignment is 1, so every byte is a legal instruction start, and Ghidra's constant-propagation
// workers commit disassembly INLINE from two threads with a non-atomic check-then-act
// (ConstantPropagationContextEvaluator :228-234 -> Disassembler :489). Two seeds a byte or two
// apart therefore yield two different, self-consistent decodings of the same bytes, and
// whichever thread arrives first wins permanently. That predicts a SINGLE SMALL CLUSTER in the
// diff -- a few instr lines replaced by a few others at shifted offsets, plus the one ref that
// hung off an instruction that no longer exists -- NOT a scatter across the image. A scatter
// would falsify the hypothesis and point at something global instead.
//
// Emits a bounded-by-nothing block between
//   === DETERMINISM BEGIN ===  /  === DETERMINISM END ===
// with every line prefixed "DETERMINISM ".
//
// COPYRIGHT POSTURE -- follows RealRomDump.java's rule (its header, ~:16-30): no ROM bytes and
// no disassembled instruction text. An instruction is described by its ADDRESS and LENGTH only;
// a reference by its endpoints and type. Those are the same class of derived metadata the
// committed golden already carries, just unbounded. Even so this output is diagnostic-only and
// is never committed: realrom-test.sh's awk carve extracts ONLY the REALROM block, so nothing
// here can reach a golden even when this runs on the same import.
//
// USAGE -- rides along on a routine check, costing no second import (~7s median per row,
// worst ~52s; see docs/testing.md "How long the gates actually take", bead grm-yfma):
//   REALROM_EXTRA_POSTSCRIPT=DeterminismProbe.java \
//     bash tools/banktest/realrom-test.sh check --only megaman H:/emulators/nes/roms
// then diff two runs' carved blocks. Note realrom_cache_key() hashes RealRomDump.java only, so
// a `bless` may reuse a cached dump and never run this at all -- give it its own invocation.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

public class DeterminismProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		List<String> instrLines = new ArrayList<>();
		List<String> refLines = new ArrayList<>();

		InstructionIterator instrs = currentProgram.getListing().getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			Address at = instr.getMinAddress();

			// Mirrors RealRomDump's instrs.inOverlay predicate exactly, so the counts below are
			// directly comparable to the golden's. Length is included because it is precisely
			// what an alignment divergence changes: the same bytes decoded from a different
			// start produce a different length sequence.
			if (at.getAddressSpace().isOverlaySpace()) {
				instrLines.add("instr " + qual(at) + " len=" + instr.getLength());
			}

			// Mirrors RealRomDump's refs.intoOverlay predicate: every reference FROM an
			// instruction whose target lands in an overlay space, counted once per reference.
			// The FROM address is space-qualified here (RealRomDump prints the bare offset),
			// because a reference can originate inside an overlay too and the bare offset
			// would silently merge sources that live in different banks.
			for (Reference r : instr.getReferencesFrom()) {
				Address to = r.getToAddress();
				if (to.getAddressSpace().isOverlaySpace()) {
					refLines.add("ref " + qual(at) + " -> " + qual(to) + " " +
						r.getReferenceType().getName() + " primary=" + r.isPrimary());
				}
			}
		}

		Collections.sort(instrLines);
		Collections.sort(refLines);

		println("=== DETERMINISM BEGIN ===");
		// Emitted FIRST and cross-checkable against the golden's own count lines: if these two
		// disagree with RealRomDump on the same import, the probe's predicates have drifted from
		// the golden's and every conclusion drawn from the listing below is suspect.
		println("DETERMINISM count instrs.inOverlay " + instrLines.size());
		println("DETERMINISM count refs.intoOverlay " + refLines.size());
		for (String line : instrLines) {
			println("DETERMINISM " + line);
		}
		for (String line : refLines) {
			println("DETERMINISM " + line);
		}
		println("=== DETERMINISM END ===");
	}

	// Space-qualified address. Unlike RealRomDump.fmt (bare 4 hex digits), the space name is
	// always included: this listing's whole job is to be diffed line-by-line, and two banks'
	// $8000 are different places.
	private String qual(Address addr) {
		return addr.getAddressSpace().getName() + "::" + String.format("%04x", addr.getOffset());
	}
}
