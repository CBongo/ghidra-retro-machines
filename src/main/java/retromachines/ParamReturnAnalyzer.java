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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Writes the parameters and return value {@link ParamReturnEvidence} proves into each 6502/6510
 * function's signature (bead grm-etbh, stage E2).
 * <p>
 * Only COMPLETE proposals with at least one parameter or a return are committed. A function with
 * neither is left alone: an {@code ANALYSIS}-source signature is LOCKED, so committing "void" would
 * stop the decompiler's own A/X/Y trials, which the 6502 prototype models already run. Parameters
 * and a confirmed return use explicit register storage (custom variable storage under the compiler
 * spec's default calling convention, named explicitly so its {@code <unaffected>} list still applies
 * and the decompiler does not flag an unknown convention). A proposal
 * with parameters but no confirmed return leaves the return type {@code undefined} (unlocked).
 * <p>
 * A function is written only when its signature source is {@code DEFAULT}, or it carries the
 * {@link #TAG} function tag (this analyzer wrote it earlier and may rewrite it). A
 * {@code USER_DEFINED}/{@code IMPORTED} signature, or an {@code ANALYSIS} one written by someone
 * else, is never touched. The proposal's comment lines (second results, carry status, zero-page
 * inputs, Z/N use) go into ONE plate-comment segment this analyzer replaces on re-run; zero-page
 * inputs are also recorded as {@code zp_in:$NN} function tags (comment/tag only, owner ruling).
 */
public class ParamReturnAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 6502 Parameter and Return Inference";
	private static final String DESCRIPTION =
		"Writes register parameters and a register or carry-flag return value, proven from the " +
			"function's own p-code and confirmed by its callers, into 6502/6510 function " +
			"signatures (grm-etbh).";

	/** Function tag marking a signature this analyzer wrote. */
	static final String TAG = "grm_param_return";
	static final String ZP_TAG_PREFIX = "zp_in:";
	static final String COMMENT_PREFIX = "Param/return inference:";

	private static final Map<Program, Long> DONE = new WeakHashMap<>();

	public ParamReturnAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		// GRM_NO_PARAM_RETURN: A/B knob for the real-ROM tier (analyze as if this analyzer did not
		// exist); never set it in normal use.
		return AnalyzerGates.is8BitPcode(program) && !W65816WidthEffects.applies(program) &&
			System.getenv("GRM_NO_PARAM_RETURN") == null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		synchronized (DONE) {
			Long seen = DONE.get(program);
			if (seen != null && seen == program.getModificationNumber()) {
				return true;
			}
		}
		int n = apply(program, ParamReturnEvidence.analyze(program), monitor);
		AnalyzerLog.info(this, "committed parameter/return signatures on " + n + " function(s)");
		synchronized (DONE) {
			DONE.put(program, program.getModificationNumber());
		}
		return true;
	}

	/** Applies every committable proposal; returns the number of functions written. */
	static int apply(Program program, ParamReturnEvidence.Result res, TaskMonitor monitor)
			throws CancelledException {
		if (!res.supported() || res.is65816()) {
			return 0;
		}
		int n = 0;
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			monitor.checkCancelled();
			ParamReturnEvidence.FnEvidence e = res.get(f.getEntryPoint());
			if (e == null || !e.analyzed || f.isThunk() || f.isExternal() || f.hasNoReturn()) {
				continue;
			}
			ParamReturnEvidence.Proposal p = ParamReturnEvidence.propose(e, false);
			if (!p.complete() || (p.params().isEmpty() && p.ret() == null)) {
				continue;
			}
			if (!mayWrite(f)) {
				continue;
			}
			if (commit(program, f, e, p)) {
				n++;
			}
		}
		return n;
	}

	private static boolean ours(Function f) {
		return f.getTags().stream().anyMatch(t -> TAG.equals(t.getName()));
	}

	private static boolean mayWrite(Function f) {
		SourceType src = f.getSignatureSource();
		return src == SourceType.DEFAULT || (src == SourceType.ANALYSIS && ours(f));
	}

	private static boolean commit(Program program, Function f, ParamReturnEvidence.FnEvidence e,
			ParamReturnEvidence.Proposal p) {
		CpuRegs regs = CpuRegs.of(program.getLanguage());
		Register[] byName = { regs.acc(), regs.x(), regs.y() };
		List<Variable> params = new ArrayList<>();
		String[] names = { "inA", "inX", "inY" };
		for (int i = 0; i < 3; i++) {
			if ((e.inMask & (1 << i)) == 0) {
				continue;
			}
			try {
				params.add(new ParameterImpl(names[i], Undefined1DataType.dataType,
					new VariableStorage(program, byName[i]), program, SourceType.ANALYSIS));
			}
			catch (RuntimeException | ghidra.util.exception.InvalidInputException ex) {
				return false;
			}
		}
		Variable ret;
		try {
			ret = returnVariable(program, regs, p.ret());
		}
		catch (RuntimeException ex) {
			return false;
		}
		if (!settled(f, ret, params)) {
			try {
				f.updateFunction(defaultConvention(program), ret, params,
					FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
			}
			catch (ghidra.util.exception.DuplicateNameException |
					ghidra.util.exception.InvalidInputException | RuntimeException ex) {
				return false;
			}
		}
		if (!ours(f)) {
			f.addTag(TAG);
		}
		Set<String> want = new HashSet<>();
		if (e.zpSetBefore) {
			for (int cell : e.zpIn) {
				want.add(String.format("%s$%02X", ZP_TAG_PREFIX, cell));
			}
		}
		for (FunctionTag t : new ArrayList<>(f.getTags())) {
			if (t.getName().startsWith(ZP_TAG_PREFIX) && !want.remove(t.getName())) {
				f.removeTag(t.getName());
			}
		}
		for (String w : want) {
			f.addTag(w);
		}
		if (!p.comments().isEmpty()) {
			AnalyzerCommentRecord.replaceOwn(program, f.getEntryPoint(), CommentType.PLATE,
				COMMENT_PREFIX + " " + String.join("; ", p.comments()), COMMENT_PREFIX);
		}
		return true;
	}

	/**
	 * The compiler spec's default calling convention name. DEFAULT-signature functions carry the
	 * "unknown" convention, and the decompiler warns about that once the prototype is locked; the
	 * default model has the same effects (its unaffected / killedbycall lists).
	 */
	private static String defaultConvention(Program program) {
		var cc = program.getCompilerSpec().getDefaultCallingConvention();
		return cc == null ? null : cc.getName();
	}

	/** Whether {@code f} already carries exactly this signature (a settled rerun writes nothing). */
	private static boolean settled(Function f, Variable ret, List<Variable> params) {
		if (!ours(f) || !f.hasCustomVariableStorage() || f.getParameterCount() != params.size() ||
			!java.util.Objects.equals(f.getCallingConventionName(),
				defaultConvention(f.getProgram()))) {
			return false;
		}
		for (int i = 0; i < params.size(); i++) {
			Parameter have = f.getParameter(i);
			if (!have.getVariableStorage().equals(params.get(i).getVariableStorage()) ||
				!have.getDataType().isEquivalent(params.get(i).getDataType())) {
				return false;
			}
		}
		Variable r = f.getReturn();
		return r.getVariableStorage().equals(ret.getVariableStorage()) &&
			r.getDataType().isEquivalent(ret.getDataType());
	}

	private static Variable returnVariable(Program program, CpuRegs regs, String ret) {
		try {
			if (ret == null) {
				return new ReturnParameterImpl(DataType.DEFAULT,
					VariableStorage.UNASSIGNED_STORAGE, program);
			}
			if ("carry".equals(ret)) {
				return new ReturnParameterImpl(BooleanDataType.dataType,
					new VariableStorage(program, regs.carry().reg()), program);
			}
			Register r = "A".equals(ret) ? regs.acc() : "X".equals(ret) ? regs.x() : regs.y();
			return new ReturnParameterImpl(Undefined1DataType.dataType,
				new VariableStorage(program, r), program);
		}
		catch (ghidra.util.exception.InvalidInputException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/** For tests: the parameters of {@code f} as register names. */
	static List<String> parameterRegisters(Function f) {
		List<String> out = new ArrayList<>();
		for (Parameter pr : f.getParameters()) {
			out.add(pr.getRegister() == null ? "?" : pr.getRegister().getName());
		}
		return out;
	}
}
