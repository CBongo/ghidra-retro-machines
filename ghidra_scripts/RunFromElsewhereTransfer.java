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
// Materializes a run-from-elsewhere transfer by hand: copies a range of bytes to the address a
// program copies them to at run time, so the copied code/data is visible where the CPU executes
// it (bead grm-1.7.1.1). This is the manual front-end for the long tail of copies no recognizer
// sees -- an indirect-indexed pointer walk, a copy performed by a KERNAL routine, a copy the
// loader never disassembled -- all of which retromachines.CopyLoopAnalyzer's indexed-loop idiom
// misses by construction. All the logic lives behind retromachines.RunFromElsewhere; this script
// only collects arguments.
//
// Interactive: run with no arguments and answer the prompts.
//
// Headless: pass whitespace-free key:value tokens as script arguments, e.g.
//
//   -preScript RunFromElsewhereTransfer.java src:200e dst:c800 len:8 disassemble:false
//
//   Required: src, dst, len
//   Optional: transform (IDENTITY|CONSTANT_XOR|ROLLING_XOR)
//             target    (SAME_SPACE|SAME_SPACE_INPLACE|SAME_SPACE_OVERLAY|SEPARATE_PROGRAM)
//             disassemble (true|false), function (true|false)
//             entry (address inside the destination range to disassemble from)
//             site  (the copy instruction to anchor provenance to)
//             jump  (the JMP/JSR that enters the copy)
//   Numbers accept $hex, 0xhex, or decimal; addresses are hex, optionally SPACE:offset.
//
//@category RetroMachines
//@menupath Tools.Retro Machines.Run From Elsewhere Transfer

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;

import retromachines.RunFromElsewhere;
import retromachines.TransferTarget;
import retromachines.TransferTransform;

public class RunFromElsewhereTransfer extends GhidraScript {

	/** Bookmark category for provenance, per RunFromElsewhere.apply's contract: the front-end's
	 *  own name, so a manual transfer is distinguishable from CopyLoopAnalyzer's. */
	private static final String CATEGORY = "RunFromElsewhere";
	private static final String TITLE = "Run From Elsewhere Transfer";

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no program is open");
			return;
		}

		// The whole reason this branch exists rather than one uniform ask*-driven path:
		// GhidraScript.loadAskValue (GhidraScript.java:1963-1966) consumes ONE POSITIONAL script
		// argument per ask* call whenever any arguments are present, matching by call order and
		// never by name. Optional fields and the conditional "make a function?" prompt below would
		// therefore silently shift the argument stream out of alignment -- src landing in len, and
		// so on. So the headless path parses named tokens itself and calls no ask* method at all.
		RunFromElsewhere.Request request =
			getScriptArgs().length == 0 ? askForRequest() : parseArgs(getScriptArgs());
		if (request == null) {
			return; // parseArgs already reported the reason
		}

		// No start()/end() here: GhidraScript.executeNormal (GhidraScript.java:457-466) wraps
		// run() in start()/end(true), so the transaction RunFromElsewhere.apply requires is
		// already open. Opening a second one would nest a redundant undo entry.
		MessageLog log = new MessageLog();
		RunFromElsewhere.Result result =
			RunFromElsewhere.apply(currentProgram, request, CATEGORY, monitor, log);

		// One stable, greppable line, in both environments: the headless regression fixture
		// asserts on it and a GUI user reads it in the console.
		println("RFE placement " + result.placement() + " block " +
			(result.blockName() == null ? "<none>" : result.blockName()) +
			(result.alreadyPresent() ? " (already present)" : ""));
		if (!result.satisfied()) {
			printerr("RFE transfer not materialized: " + result.detail());
		}
		if (log.hasMessages()) {
			printerr(log.toString());
		}
	}

	// ------------------------------------------------------------------
	// Interactive front-end
	// ------------------------------------------------------------------

	/**
	 * Prompt for the transfer. Only reachable with an empty argument array, which is what makes
	 * the optional prompts (and the conditional function prompt) safe here: with no script args,
	 * loadAskValue falls through to the dialog/.properties path and nothing is consumed
	 * positionally.
	 */
	private RunFromElsewhere.Request askForRequest() throws CancelledException {
		// The 3-arg askAddress parses its default through the address factory, so a null
		// currentAddress (no listing location, e.g. run from the Script Manager on a freshly
		// imported program) must select the 2-arg overload rather than pass "null" through.
		Address src = currentAddress == null
				? askAddress(TITLE, "Source: first byte to copy")
				: askAddress(TITLE, "Source: first byte to copy", currentAddress.toString());
		Address dst = askAddress(TITLE, "Destination: where the bytes are run from");
		long len = askLong(TITLE, "Length in bytes");
		if (len <= 0 || len > Integer.MAX_VALUE) {
			printerr("length must be between 1 and " + Integer.MAX_VALUE + ", got " + len);
			return null;
		}

		// askChoice matches the typed/selected text against each choice's toString(), which for an
		// enum is its constant name -- so the values below round-trip verbatim.
		TransferTransform transform = askChoice(TITLE, "Transform applied to the bytes",
			List.of(TransferTransform.values()), TransferTransform.IDENTITY);
		TransferTarget target = askChoice(TITLE, "Where to place the copy",
			List.of(TransferTarget.values()), TransferTarget.SAME_SPACE);
		boolean disassemble = askYesNo(TITLE, "Disassemble the copy at the destination?");
		// Legal only in this branch: a conditional prompt would desynchronize the positional
		// argument stream headless. askYesNo does not throw CancelledException -- a dismissed
		// dialog is simply "no".
		boolean function = disassemble && askYesNo(TITLE, "Create a function at the entry point?");

		return RunFromElsewhere.request(src, dst, (int) len)
				.transform(transform)
				.target(target)
				.disassemble(disassemble)
				.makeFunction(function)
				.originLabel("manual transfer");
	}

	// ------------------------------------------------------------------
	// Headless front-end
	// ------------------------------------------------------------------

	/**
	 * Parse {@code key:value} tokens into a request, or return null after reporting why. Fails
	 * loud on anything unrecognized: the argument list is the headless user's only feedback
	 * channel, and a typo'd key that is quietly ignored would materialize a transfer at defaults
	 * the user never asked for.
	 */
	private RunFromElsewhere.Request parseArgs(String[] args) {
		Address src = null;
		Address dst = null;
		long len = -1;
		TransferTransform transform = TransferTransform.IDENTITY;
		TransferTarget target = TransferTarget.SAME_SPACE;
		Address entry = null;
		Address site = null;
		Address jump = null;
		boolean disassemble = false;
		boolean function = false;

		for (String arg : args) {
			// split(":", 2) is mandatory, not stylistic: an overlay-space address is itself
			// SPACE:offset (src:W8000_M3_B1:a500 on a banked NES board), so an unbounded split
			// would truncate the value at the space separator and parse the wrong address.
			String[] kv = arg.split(":", 2);
			if (kv.length != 2 || kv[0].isEmpty() || kv[1].isEmpty()) {
				printerr("malformed argument '" + arg + "'; expected key:value with no whitespace");
				return null;
			}
			String key = kv[0];
			String value = kv[1];
			try {
				switch (key) {
					case "src" -> src = address(value);
					case "dst" -> dst = address(value);
					case "len" -> len = number(value);
					case "transform" -> transform = TransferTransform
							.valueOf(value.toUpperCase());
					case "target" -> target = TransferTarget.valueOf(value.toUpperCase());
					case "entry" -> entry = address(value);
					case "site" -> site = address(value);
					case "jump" -> jump = address(value);
					case "disassemble" -> disassemble = flag(key, value);
					case "function" -> function = flag(key, value);
					default -> {
						printerr("unknown key '" + key + "' in argument '" + arg + "'; expected " +
							"one of src, dst, len, transform, target, entry, site, jump, " +
							"disassemble, function");
						return null;
					}
				}
			}
			catch (IllegalArgumentException e) {
				printerr("bad value in argument '" + arg + "': " + e.getMessage());
				return null;
			}
		}

		if (src == null || dst == null || len < 0) {
			printerr("src, dst and len are all required (got src=" + src + " dst=" + dst +
				" len=" + (len < 0 ? "<missing>" : Long.toString(len)) + ")");
			return null;
		}
		if (len <= 0 || len > Integer.MAX_VALUE) {
			printerr("len must be between 1 and " + Integer.MAX_VALUE + ", got " + len);
			return null;
		}

		return RunFromElsewhere.request(src, dst, (int) len)
				.transform(transform)
				.target(target)
				.provenanceSite(site)
				.entryPoint(entry)
				.jumpSite(jump)
				.disassemble(disassemble)
				.makeFunction(function)
				.originLabel("manual transfer");
	}

	/**
	 * An address token. Addresses are always hex, and {@code parseAddress} already accepts a
	 * {@code 0x} prefix and a {@code SPACE:offset} qualifier (AbstractAddressSpace.java:203-232);
	 * only the assembler-style {@code $} needs stripping first.
	 */
	private Address address(String text) {
		return parseAddress(text.startsWith("$") ? text.substring(1) : text);
	}

	/** A count. Unlike an address this defaults to DECIMAL, so {@code len:8} means eight. */
	private static long number(String text) {
		if (text.startsWith("$")) {
			return Long.parseLong(text.substring(1), 16);
		}
		if (text.startsWith("0x") || text.startsWith("0X")) {
			return Long.parseLong(text.substring(2), 16);
		}
		return Long.parseLong(text);
	}

	/** A strict boolean: anything but true/false is a typo worth failing on, not a false. */
	private static boolean flag(String key, String value) {
		if (value.equalsIgnoreCase("true")) {
			return true;
		}
		if (value.equalsIgnoreCase("false")) {
			return false;
		}
		throw new IllegalArgumentException(key + " must be true or false, got '" + value + "'");
	}
}
