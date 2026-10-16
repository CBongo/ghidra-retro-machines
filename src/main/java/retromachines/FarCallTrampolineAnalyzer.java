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

import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Places the target of a restoring far-call trampoline in its DESTINATION bank's overlay
 * (grm-v60; logic in {@link FarCallTrampoline}, which has the full account of the idiom and of
 * the write-once-constant rule's corroboration).
 *
 * <p><b>Where the reference goes.</b> A {@link RefType#COMPUTED_CALL} mnemonic reference from the
 * trampoline's {@code JMP (P)} to each distinct resolved target, exactly as
 * {@link IndirectJumpConstantPointerAnalyzer} does for a constant pointer (and by its code: the
 * same {@code applyTarget} disassembles the target in the overlay and schedules its function).
 * The {@code JMP (P)} is the one instruction every far call funnels through and the one whose
 * target set this actually is; putting references on the call sites instead would hang a second
 * CALL reference off every {@code JSR} to the BIT-skip stubs, doubling what a caller's call graph
 * and the function-boundary logic see for one call. A call site that cannot be resolved is
 * declined with a NOTE bookmark (category "Far-call trampoline") saying why.
 *
 * <p><b>When it runs.</b> The call sites that make a target resolvable are disassembled all
 * through analysis, so this runs late (after reference analysis, before the bank analyzer's own
 * fixpoint rounds begin) and rescans the whole program each time it is handed new code; the
 * placement is idempotent. Gated on the program being a banked-board import.
 */
public class FarCallTrampolineAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Far-Call Trampoline";
	private static final String DESCRIPTION =
		"Places the target of a far-call trampoline (JMP (P) with Y/A set by each caller and a " +
			"write-once pointer high byte) in the destination bank's overlay (grm-v60).";

	static final String BOOKMARK_CATEGORY = "Far-call trampoline";

	public FarCallTrampolineAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().supportsPcode() && BankContext.isBankedImport(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		BankContext ctx = BankContext.forProgram(program);
		if (ctx == null) {
			return false;
		}
		FarCallTrampoline.Index index = FarCallTrampoline.buildIndex(program, monitor);
		Listing listing = program.getListing();
		int placed = 0;
		int declined = 0;
		for (Instruction site : index.sites) {
			monitor.checkCancelled();
			FarCallTrampoline.Outcome outcome =
				FarCallTrampoline.resolve(program, ctx, index, site, monitor);
			Set<Address> targets = new LinkedHashSet<>();
			for (FarCallTrampoline.Placement p : outcome.placed()) {
				targets.add(p.target());
			}
			for (FarCallTrampoline.Placement p : outcome.placed()) {
				AnalyzerLog.debug(this, "far call at " + p.callSite().getMinAddress() + " -> " +
					p.target());
			}
			for (Address target : targets) {
				if (!hasReference(site, target)) {
					IndirectJumpConstantPointerAnalyzer.applyTarget(program, listing, site, target,
						monitor);
					placed++;
				}
			}
			for (FarCallTrampoline.Declined d : outcome.declined()) {
				if (program.getBookmarkManager().getBookmark(d.callSite().getMinAddress(),
					BookmarkType.NOTE, BOOKMARK_CATEGORY) == null) {
					program.getBookmarkManager().setBookmark(d.callSite().getMinAddress(),
						BookmarkType.NOTE, BOOKMARK_CATEGORY,
						"declined as a far call through " + site.getMinAddress() + ": " +
							d.reason());
					declined++;
				}
			}
		}
		if (placed > 0 || declined > 0) {
			AnalyzerLog.info(this, "placed " + placed + " far-call target(s), declined " +
				declined + " call site(s)");
		}
		return placed > 0;
	}

	private static boolean hasReference(Instruction site, Address target) {
		for (Reference ref : site.getReferencesFrom()) {
			if (ref.getToAddress().equals(target) && ref.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}
}
