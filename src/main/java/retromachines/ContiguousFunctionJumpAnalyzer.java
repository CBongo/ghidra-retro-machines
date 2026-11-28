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

import java.util.HashSet;
import java.util.Set;

import ghidra.app.cmd.analysis.SharedReturnAnalysisCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Stock Shared Return Calls' "Assume Contiguous Functions Only" jump scan, with the re-analysis
 * loop its multi-flow source bug causes fixed (grm-q83o). {@link RetroAnalysisDefaults} switches the stock option off for
 * every program this extension loads, and this analyzer runs the scan in its place.
 *
 * <p><b>The bug.</b> {@code SharedReturnAnalysisCmd.applyTo} (Ghidra 12.2) means to ignore a
 * source with several flow references ("ignore points with multiple flows"), but it
 * {@code break}s out of the reference loop AFTER taking the first one, so the source is kept
 * with that reference. A switch ({@code JMP (abs,X)}, {@code COMPUTED_JUMP}, which is a jump and
 * unconditional) is therefore read as an unconditional jump to its FIRST case. When that case
 * lies past the next function's entry, and the 65816 jump table analyzer grows a switch's handlers
 * into the dispatcher's body exactly like that, the scan queues {@code createFunction} at the case.
 * On w_ff3 FUN_c25ada (switch c25ade, handlers past FUN_c25b06) that create shrinks FUN_c25ada,
 * then fails on an overlap and restores the body. That is two FUNCTION_BODY_CHANGED events, which
 * queue FUN_c25ada's function analyzers again, and those queue the same create again: the GUI's
 * auto-analysis never ends ("Stack FUN_c25ada"). Headless runs analysis once and never sees it.
 *
 * <p><b>The fix is narrow on purpose.</b> A multi-flow source is skipped only when that first
 * destination already lies in the body of the function containing the source, the one shape in
 * which the create carves its own caller and loops. Stock's first-ref reading is otherwise kept,
 * because it is load-bearing: skipping every multi-flow source (the first version of this fix)
 * lost wizwarr's bank-retargeted JMP thunks and the bank functions behind them (581 overlay
 * instructions), and ff1's bounded {@code b174} switch. Where the case lies outside the
 * dispatcher's body, stock may still split it off as a function, exactly as before.
 *
 * <p><b>Everything else is stock.</b> The scan set, the forward/backward test against the
 * neighbouring function entries, the {@code .cold} skip, the conditional-branch filter
 * (GP-6976, governed by the stock "Allow Conditional Jumps" option, which this reads), and the
 * fall-through guard are copied unchanged. When the destination already is a function, the
 * call-return work goes to the stock command with the contiguous scan off, so its flow-override
 * rules, and {@link ConditionalTailCallNarrowingAnalyzer}'s pins, apply as before.
 *
 * <p>Two halves, as in stock: this function analyzer (new function entries) and
 * {@link ContiguousFunctionJumpInstructionAnalyzer}, an instruction analyzer (new jumps to
 * existing functions), both one priority step after the matching stock half. If the stock option
 * is still on (a program imported before this change, or a user's choice), stock runs the scan,
 * so this does nothing.
 */
public class ContiguousFunctionJumpAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Contiguous Function Jumps";
	private static final String DESCRIPTION =
		"Shared Return Calls' 'Assume Contiguous Functions Only' jump scan, without its " +
			"never-ending re-analysis when a switch's first case lies in the dispatcher's own " +
			"body (grm-q83o). Runs only while that stock " +
			"option is off, which this extension's loaders set.";

	/** The stock option this replaces; {@link RetroAnalysisDefaults} turns it off. */
	static final String STOCK_ASSUME_CONTIGUOUS =
		"Shared Return Calls.Assume Contiguous Functions Only";

	private static final Set<String> SUPPORTED_PROCESSORS = Set.of("6502", "6510", "65816");

	public ContiguousFunctionJumpAnalyzer() {
		this(AnalyzerType.FUNCTION_ANALYZER);
		setSupportsOneTimeAnalysis();
	}

	protected ContiguousFunctionJumpAnalyzer(AnalyzerType type) {
		super(NAME, DESCRIPTION, type);
		// The same priority as stock Shared Return Calls, whose task ran this scan.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return processor != null && SUPPORTED_PROCESSORS.contains(processor.toString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		if (options.getBoolean(STOCK_ASSUME_CONTIGUOUS, true)) {
			return false; // stock runs the scan itself
		}
		boolean considerConditional =
			options.getBoolean(RetroAnalysisDefaults.ALLOW_CONDITIONAL_TAIL_CALLS, false);
		scan(program, set, considerConditional, monitor);
		return true;
	}

	/** Stock {@code SharedReturnAnalysisCmd.applyTo}'s contiguous-functions block, fixed. */
	// Address.NO_ADDRESS is an identity sentinel and address spaces compare by identity, as in stock.
	@SuppressWarnings("ReferenceEquality")
	static void scan(Program program, AddressSetView set, boolean considerConditionalBranches,
			TaskMonitor monitor) throws CancelledException {
		SymbolTable symbolTable = program.getSymbolTable();
		AddressSetPropertyMap coldMap =
			program.getAddressSetPropertyMap(Program.COLD_ENTRY_MAP_NAME);
		Set<Address> conditionalJumpTargets = new HashSet<>();
		Set<Address> onlyUnconditionalJumpTargets = new HashSet<>();

		AddressSet jumpScanSet = new AddressSet();
		SymbolIterator fnSymbols = symbolTable.getSymbols(set, SymbolType.FUNCTION, true);
		while (fnSymbols.hasNext()) {
			monitor.checkCancelled();
			Symbol s = fnSymbols.next();
			checkAboveFunction(s, jumpScanSet);
			checkBelowFunction(s, jumpScanSet);
		}

		// Cached forward/backward function lookups as we move forward through jump references
		Address functionAfterSrc = null;
		Address functionBeforeSrc = null;

		ReferenceManager refMgr = program.getReferenceManager();
		AddressIterator refSrcIter = refMgr.getReferenceSourceIterator(jumpScanSet, true);
		while (refSrcIter.hasNext()) {
			monitor.checkCancelled();
			Address srcAddr = refSrcIter.next();
			RefType flow = null;
			Address destAddr = null;
			boolean multipleFlows = false;
			for (Reference ref : refMgr.getReferencesFrom(srcAddr)) {
				RefType refType = ref.getReferenceType();
				if (refType.isFlow()) {
					if (flow != null) {
						multipleFlows = true; // the fix: stock breaks here and keeps the first
						break;
					}
					flow = refType;
					destAddr = ref.getToAddress();
				}
			}
			if (destAddr == null || flow == null || !flow.isJump() || !flow.isUnConditional()) {
				continue;
			}
			// The fix, deliberately narrow: stock keeps the FIRST ref of a multi-flow source, and
			// that is load-bearing elsewhere (wizwarr's bank-retargeted JMPs make their per-bank
			// thunks and functions that way; ff1 loses a bounded switch without it). It only
			// loops when that ref lands in the source's OWN function: the create then carves the
			// function it is called from (shrink, fail on overlap, restore, re-queue).
			if (multipleFlows) {
				Function owner = program.getFunctionManager().getFunctionContaining(srcAddr);
				if (owner != null && owner.getBody().contains(destAddr)) {
					continue;
				}
			}
			if (srcAddr.getAddressSpace() != destAddr.getAddressSpace()) {
				continue; // can't handle flows between different spaces/overlays
			}
			if (coldMap != null && coldMap.contains(destAddr)) {
				continue; // skip .cold targets
			}

			if (!considerConditionalBranches) {
				if (conditionalJumpTargets.contains(destAddr)) {
					continue; // destAddr is a conditional jump target, skip
				}
				if (!onlyUnconditionalJumpTargets.contains(destAddr)) {
					ReferenceIterator refIter = refMgr.getReferencesTo(destAddr);
					boolean conditionalRef = false;
					while (refIter.hasNext()) {
						RefType refType = refIter.next().getReferenceType();
						if (refType.isFlow() && refType.isConditional()) {
							conditionalRef = true;
							break;
						}
					}
					if (conditionalRef) {
						conditionalJumpTargets.add(destAddr);
						continue;
					}
					onlyUnconditionalJumpTargets.add(destAddr);
				}
			}

			// Reset cached functions if we transition to a different space/overlay
			if (functionAfterSrc != null &&
				functionAfterSrc.getAddressSpace() != srcAddr.getAddressSpace()) {
				functionAfterSrc = null;
			}
			if (functionBeforeSrc != null &&
				functionBeforeSrc.getAddressSpace() != srcAddr.getAddressSpace()) {
				functionBeforeSrc = null;
			}

			if (srcAddr.compareTo(destAddr) < 0) {
				// forward jump
				if (functionAfterSrc == Address.NO_ADDRESS) {
					continue; // no function after srcAddr
				}
				if (functionAfterSrc == null || functionAfterSrc.compareTo(srcAddr) <= 0) {
					Function nextFunction = getFunctionAfter(program, srcAddr);
					if (nextFunction != null) {
						functionAfterSrc = nextFunction.getEntryPoint();
					}
					else {
						functionAfterSrc = Address.NO_ADDRESS;
						continue; // no function after srcAddr
					}
				}
				if (destAddr.compareTo(functionAfterSrc) >= 0) {
					createFunction(program, destAddr, considerConditionalBranches, monitor);
				}
			}
			else {
				// prime functionAfterSrc if not previously set
				if (functionAfterSrc == null) {
					Function nextFunction = getFunctionAfter(program, srcAddr);
					functionAfterSrc =
						nextFunction != null ? nextFunction.getEntryPoint() : Address.NO_ADDRESS;
				}

				// backward jump
				if (functionBeforeSrc == Address.NO_ADDRESS) {
					if (functionAfterSrc == Address.NO_ADDRESS) {
						continue; // no functions exist - rare
					}
					if (srcAddr.compareTo(functionAfterSrc) < 0) {
						continue; // not past the next function - no function before
					}
					functionBeforeSrc = null; // re-query - functionAfterSrc is also invalid
					Function nextFunction = getFunctionAfter(program, srcAddr);
					functionAfterSrc =
						nextFunction != null ? nextFunction.getEntryPoint() : Address.NO_ADDRESS;
				}

				// not past functionAfterSrc: functionBeforeSrc is unchanged
				if (functionBeforeSrc == null || (functionAfterSrc != Address.NO_ADDRESS &&
					srcAddr.compareTo(functionAfterSrc) >= 0)) {
					Function prevFunction = getFunctionBefore(program, srcAddr);
					if (prevFunction != null) {
						functionBeforeSrc = prevFunction.getEntryPoint();
					}
					else {
						functionBeforeSrc = Address.NO_ADDRESS;
						continue; // no function before srcAddr
					}
				}

				if (destAddr.compareTo(functionBeforeSrc) < 0) {
					createFunction(program, destAddr, considerConditionalBranches, monitor);
				}
			}
		}
	}

	private static void checkAboveFunction(Symbol functionSymbol, AddressSet jumpScanSet) {
		Program program = functionSymbol.getProgram();
		Address fnAddr = functionSymbol.getAddress();
		Function prevFunction = getFunctionBefore(program, fnAddr);
		if (prevFunction != null) {
			// Must scan everything from previous function down to functionSymbol
			jumpScanSet.addRange(prevFunction.getEntryPoint(), fnAddr);
			return;
		}
		// Must scan everything above function
		jumpScanSet.addRange(fnAddr.getAddressSpace().getMinAddress(), fnAddr);
	}

	private static void checkBelowFunction(Symbol functionSymbol, AddressSet jumpScanSet) {
		Function function = (Function) functionSymbol.getObject();
		AddressSetView body = function.getBody();
		if (body.getNumAddressRanges() > 1) {
			jumpScanSet.add(body);
		}
		Program program = functionSymbol.getProgram();
		Address fnAddr = functionSymbol.getAddress();
		Function nextFunction = getFunctionAfter(program, fnAddr);
		if (nextFunction != null) {
			// Must scan everything from this function down to the next one; omit a
			// single-range body
			jumpScanSet.addRange(fnAddr, nextFunction.getEntryPoint().subtract(1));
			if (body.getNumAddressRanges() <= 1) {
				jumpScanSet.delete(body);
			}
			return;
		}
		// Must scan everything below function; omit a single-range body
		jumpScanSet.addRange(fnAddr, fnAddr.getAddressSpace().getMaxAddress());
		if (body.getNumAddressRanges() <= 1) {
			jumpScanSet.delete(body);
		}
	}

	private static Function getFunctionBefore(Program program, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		if (addr.equals(space.getMinAddress())) {
			return null;
		}
		FunctionIterator it;
		try {
			it = program.getListing()
					.getFunctions(new AddressSet(space.getMinAddress(), addr.subtractNoWrap(1)),
						false);
		}
		catch (AddressOverflowException e) {
			throw new AssertException(e);
		}
		return it.hasNext() ? it.next() : null;
	}

	private static Function getFunctionAfter(Program program, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		if (addr.equals(space.getMaxAddress())) {
			return null;
		}
		FunctionIterator it;
		try {
			it = program.getListing()
					.getFunctions(new AddressSet(addr.addNoWrap(1), space.getMaxAddress()), true);
		}
		catch (AddressOverflowException e) {
			throw new AssertException(e);
		}
		return it.hasNext() ? it.next() : null;
	}

	/**
	 * Stock's {@code createFunction}: an existing function gets the stock call-return pass (the
	 * stock command with the contiguous scan off runs exactly {@code processFunctionJumpReferences}
	 * for it); otherwise a function is created unless code could fall through to the entry.
	 */
	private static void createFunction(Program program, Address entry,
			boolean considerConditionalBranches, TaskMonitor monitor) {
		if (program.getFunctionManager().getFunctionAt(entry) != null) {
			new SharedReturnAnalysisCmd(new AddressSet(entry), false, considerConditionalBranches)
					.applyTo(program, monitor);
			return;
		}
		if (couldHaveFallThruTo(program, entry)) {
			return; // if there could be, even later in analysis, don't create the function
		}
		AutoAnalysisManager.getAnalysisManager(program).createFunction(entry, false);
	}

	@SuppressWarnings("ReferenceEquality") // RefType.TERMINATOR is a singleton, compared as in stock
	private static boolean couldHaveFallThruTo(Program program, Address location) {
		Instruction instr = program.getListing().getInstructionAt(location);
		if (instr == null) {
			return true;
		}
		Address fallFrom = instr.getFallFrom();
		if (fallFrom != null) {
			Instruction fallInstr = program.getListing().getInstructionContaining(fallFrom);
			if (fallInstr != null && location.equals(fallInstr.getFallThrough())) {
				return true; // if there is no instruction yet, function may not be created yet
			}
		}
		// a single terminal instruction is considered as having a possible future fall-through
		FlowType flow = instr.getFlowType();
		return flow == RefType.TERMINATOR;
	}
}
