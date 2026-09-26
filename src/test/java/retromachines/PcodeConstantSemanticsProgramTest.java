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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.EnumSet;
import java.util.Set;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import retromachines.BoardBankAnalyzer.ConstantSemanticsMode;
import retromachines.ConstantSemantics.Inputs;
import retromachines.ConstantSemantics.Loc;

/**
 * Focused tests for {@link PcodeConstantSemantics} (bead grm-4wqd) that call
 * {@link ConstantSemantics#after} directly with a hand-built {@link Inputs}, bypassing
 * {@link StoredValueScanner}'s backward walk entirely. That is deliberate here: these pin
 * properties of the INTERPRETER itself (what it forces, what a {@code LOAD} accepts or
 * declines) that are easiest to state against a fixed, known set of "before" answers rather
 * than through fixtures that must additionally be shaped to make the walk resolve them. The
 * walk-integrated behavior (the option selecting this class, agreement with the table
 * evaluator) is covered by {@link PcodeConstantSemanticsDifferentialTest} and the option test
 * below.
 */
public class PcodeConstantSemanticsProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	private void build(String languageId) throws Exception {
		builder = new ProgramBuilder("Test", languageId);
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/** An {@link Inputs} with fixed answers for {@link Loc#A}/{@link Loc#C}, {@code null}
	 * (unknown) for everything else, and no memory/effective-target support -- used to pin the
	 * interpreter's demand-driven property: it must never need to ask this stub for anything
	 * beyond what the queried location actually depends on. */
	private static final class RecordingInputs implements Inputs {
		final Set<Loc> queried = EnumSet.noneOf(Loc.class);
		private final Integer a;
		private final Integer c;

		RecordingInputs(Integer a, Integer c) {
			this.a = a;
			this.c = c;
		}

		@Override
		public Integer before(Loc loc) {
			queried.add(loc);
			return switch (loc) {
				case A -> a;
				case C -> c;
				default -> null; // X, Y, D: unknown -- would decline if actually forced
			};
		}

		@Override
		public Integer memoryOperand() {
			return null;
		}

		@Override
		public Address effectiveTarget() {
			return null;
		}
	}

	// ------------------------------------------------------------------
	// Demand-driven: an unrelated register is never forced.
	// ------------------------------------------------------------------

	/** {@code ADC #$01} on stock {@code 6502:LE:16:default} (no {@code D} branch): asking for
	 *  {@code A} needs {@code before(A)} and {@code before(C)} (the carry-in) -- and nothing
	 *  else. In particular it must never call {@code before(X)} or {@code before(Y)}: those
	 *  registers are not read anywhere in {@code ADC}'s p-code, and a demand-driven interpreter
	 *  that built its answer eagerly (forcing every register read as it walked, rather than
	 *  only the ones the final forced value actually depends on) would still not need them --
	 *  this pins that the interpreter does not ask regardless, as a regression guard against a
	 *  future refactor away from lazy thunks. */
	@Test
	public void queryingADoesNotForceUnrelatedRegisters() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "69 01", true); // ADC #$01
		Instruction adc = instructionAt("0x8000");

		RecordingInputs in = new RecordingInputs(0x05, 1);
		Integer result = PcodeConstantSemantics.INSTANCE.after(adc, Loc.A, in);

		assertEquals(Integer.valueOf(0x07), result); // 5 + 1 + 1
		assertFalse("X should never be queried computing A", in.queried.contains(Loc.X));
		assertFalse("Y should never be queried computing A", in.queried.contains(Loc.Y));
	}

	// ------------------------------------------------------------------
	// Memory reads: resolve at the effective target, decline elsewhere.
	// ------------------------------------------------------------------

	/** {@code AND $9000}: for a compile-time-fixed absolute address Ghidra's raw p-code names
	 *  the memory location directly as {@code INT_AND}'s operand ({@code (RAM, 0x9000, 1)}) --
	 *  no {@code LOAD} op at all; only a register- or unique-computed (indexed/indirect)
	 *  address needs one. That direct address matches {@link Inputs#effectiveTarget}, so
	 *  {@link Inputs#memoryOperand} is trusted for the byte: {@code $F0 & $3C = $30}. */
	@Test
	public void loadAtEffectiveTargetResolves() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "2d 00 90", true); // AND $9000
		Instruction and = instructionAt("0x8000");
		Address target = builder.addr("0x9000");

		Inputs in = new Inputs() {
			@Override
			public Integer before(Loc loc) {
				return loc == Loc.A ? 0xF0 : null;
			}

			@Override
			public Integer memoryOperand() {
				return 0x3C;
			}

			@Override
			public Address effectiveTarget() {
				return target;
			}
		};

		assertEquals(Integer.valueOf(0x30), PcodeConstantSemantics.INSTANCE.after(and, Loc.A, in));
	}

	/** Same {@code AND $9000}, but {@link Inputs#effectiveTarget} answers a DIFFERENT address
	 *  than the one the instruction's own p-code actually reads -- the read declines rather
	 *  than trusting {@link Inputs#memoryOperand} for the wrong address. */
	@Test
	public void loadAtDifferentAddressDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "2d 00 90", true); // AND $9000
		Instruction and = instructionAt("0x8000");
		Address wrongTarget = builder.addr("0x9999");

		Inputs in = new Inputs() {
			@Override
			public Integer before(Loc loc) {
				return loc == Loc.A ? 0xF0 : null;
			}

			@Override
			public Integer memoryOperand() {
				return 0x3C; // would be trusted only if the address matched
			}

			@Override
			public Address effectiveTarget() {
				return wrongTarget;
			}
		};

		assertNull(PcodeConstantSemantics.INSTANCE.after(and, Loc.A, in));
	}

	// ------------------------------------------------------------------
	// LAX: an undocumented opcode, evaluated because the language's own p-code covers it.
	// ------------------------------------------------------------------

	/**
	 * {@code LAX $10} on the bundled {@code 6502:LE:16:undoc} language: {@code X} folds to the
	 * resolved load, exactly as {@code A} does, since the p-code is {@code A = *:1 ea; X = A;}.
	 * <p>
	 * {@link Inputs#effectiveTarget} is supplied directly here rather than through
	 * {@link StoredValueScanner#effectiveOperandTarget} (as {@link PcodeConstantSemanticsDifferentialTest}'s
	 * {@code agreeingLaxDespiteAResolvingHook} goes through) because it CANNOT resolve for
	 * {@code LAX}: the opcode's hand-rolled addressing (measured -- {@code LAX}'s zero-page and
	 * absolute forms both bypass the {@code OP1}/{@code OP2} addressing subtables the rest of
	 * the instruction set routes through, so {@code instr.getOpObjects(0)} never yields an
	 * {@code Address}) means {@link StoredValueScanner#plainAbsoluteTarget} always declines for
	 * it, walk or no walk -- and so does {@code WalkInputs.memoryOperand()}, which uses that
	 * same resolution to decide what address to hand a strategy's hook, for TABLE exactly as
	 * much as for PCODE. That is a real, structural limit on undocumented opcodes with
	 * non-standard addressing, but it belongs to the SHARED {@code memoryOperand()} plumbing,
	 * not to this evaluator's own {@code LOAD} handling -- see that other test and
	 * {@link PcodeConstantSemantics}'s class javadoc.
	 */
	@Test
	public void undocumentedOpcodeEvaluatesViaPcode() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "a7 10", true); // LAX $10
		Instruction lax = instructionAt("0x8000");
		Address target = builder.addr("0x10");

		Inputs in = new Inputs() {
			@Override
			public Integer before(Loc loc) {
				return null;
			}

			@Override
			public Integer memoryOperand() {
				return 0x7A;
			}

			@Override
			public Address effectiveTarget() {
				return target;
			}
		};

		assertEquals(Integer.valueOf(0x7A), PcodeConstantSemantics.INSTANCE.after(lax, Loc.X, in));
	}

	// ------------------------------------------------------------------
	// D: assumed binary when unestablished, but a resolved writer still wins.
	// ------------------------------------------------------------------

	/** {@code CLD} within the window: {@link Inputs#before} answers {@code 0} for {@link Loc#D}
	 *  (a resolved value, not a decline), and the bundled language's {@code ADC} takes the
	 *  binary path because of that ESTABLISHED value -- not because of the assumed default. */
	@Test
	public void establishedDStillWinsOverTheAssumption() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "69 01", true); // ADC #$01
		Instruction adc = instructionAt("0x8000");

		Inputs in = new Inputs() {
			@Override
			public Integer before(Loc loc) {
				return switch (loc) {
					case A -> 0x05;
					case C -> 0;
					case D -> 0; // established, not unknown
					default -> null;
				};
			}

			@Override
			public Integer memoryOperand() {
				return null;
			}

			@Override
			public Address effectiveTarget() {
				return null;
			}
		};

		assertEquals(Integer.valueOf(0x06), PcodeConstantSemantics.INSTANCE.after(adc, Loc.A, in));
	}

	/** No {@code D} writer anywhere: {@link Inputs#before} answers {@code null} for
	 *  {@link Loc#D} (a genuine decline from the walk), and the interpreter falls back to the
	 *  assumed value (binary, {@code 0}) rather than declining the whole instruction. */
	@Test
	public void unestablishedDAssumesBinary() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "69 01", true); // ADC #$01
		Instruction adc = instructionAt("0x8000");

		Inputs in = new Inputs() {
			@Override
			public Integer before(Loc loc) {
				return switch (loc) {
					case A -> 0x05;
					case C -> 0;
					case D -> null; // unestablished
					default -> null;
				};
			}

			@Override
			public Integer memoryOperand() {
				return null;
			}

			@Override
			public Address effectiveTarget() {
				return null;
			}
		};

		assertEquals(Integer.valueOf(0x06), PcodeConstantSemantics.INSTANCE.after(adc, Loc.A, in));
	}

	// ------------------------------------------------------------------
	// The analyzer option: selects the implementation, defaults to TABLE.
	// ------------------------------------------------------------------

	@Test
	public void optionDefaultsToTable() throws Exception {
		build("6502:LE:16:default");
		assertEquals(ConstantSemanticsMode.TABLE, BoardBankAnalyzer.constantSemanticsMode(program));
	}

	@Test
	public void optionSelectsPcodeUnderEitherAnalyzerName() throws Exception {
		build("6502:LE:16:default");
		int tx = program.startTransaction("set option");
		try {
			program.getOptions(Program.ANALYSIS_PROPERTIES)
					.getOptions(C64BankingAnalyzer.NAME)
					.setEnum(BoardBankAnalyzer.CONSTANT_SEMANTICS_OPTION, ConstantSemanticsMode.PCODE);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertEquals(ConstantSemanticsMode.PCODE, BoardBankAnalyzer.constantSemanticsMode(program));
	}

	/** {@link BoardBankAnalyzer#registerOptions} actually registers the option under
	 *  {@code TABLE} default, on either concrete subclass. */
	@Test
	public void registerOptionsRegistersTableDefault() throws Exception {
		build("6502:LE:16:default");
		ghidra.framework.options.Options options =
			program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(NesBankingAnalyzer.NAME);
		int tx = program.startTransaction("register options");
		try {
			new NesBankingAnalyzer().registerOptions(options, program);
		}
		finally {
			program.endTransaction(tx, true);
		}
		// Passing PCODE as getEnum's own fallback here: if registerOptions had NOT seeded
		// TABLE as the option's actual default/current value, this would come back PCODE.
		assertEquals(ConstantSemanticsMode.TABLE,
			options.getEnum(BoardBankAnalyzer.CONSTANT_SEMANTICS_OPTION, ConstantSemanticsMode.PCODE));
	}
}
