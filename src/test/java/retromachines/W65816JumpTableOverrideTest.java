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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

/**
 * grm-hf5h.3: {@link W65816JumpTableAnalyzer} writes a {@code JumpTable} override (the
 * {@code override/jmp_<addr>} namespace with one {@code case} label per destination) on the
 * function holding a {@code JMP (abs,X)} dispatch it resolved -- at once when the function
 * exists, via {@link JumpTableOverrideRelocatorAnalyzer} when it is created later -- and never
 * for a {@code JSR (abs,X)} call.
 */
public class W65816JumpTableOverrideTest extends AbstractProgramTest {

	private static final long[] HANDLERS = { 0x8200, 0x8210, 0x8220, 0x8230 };

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		MemoryBlock rom = builder.createMemory(".rom", "0x8000", 0x1000);
		program = builder.getProgram();
		setWritable(rom, false);
		inTx(program, "rom executable", () -> rom.setExecute(true));
		setContext("ctx_EF", 0);
		setContext("ctx_MF", 1);
		setContext("ctx_XF", 1);
		for (long t : HANDLERS) {
			builder.setBytes(hex(t), "60", false);
		}
		builder.setBytes("0x8100", "00 82 10 82 20 82 30 82 00 00", false);
	}

	private void setContext(String field, int value) throws Exception {
		Register register = program.getLanguage().getRegister(field);
		assertNotNull("no context field named " + field, register);
		inTx(program, "set " + field, () -> program.getProgramContext()
				.setValue(register, addr("0x8000"), addr("0x8fff"), BigInteger.valueOf(value)));
	}

	private void analyze(String site) throws Exception {
		Address s = addr(site);
		inTx(program, "analyze", () -> new W65816JumpTableAnalyzer().added(program,
			new AddressSet(s, s.add(2)), TaskMonitor.DUMMY, new MessageLog()));
	}

	private Function createFunction(String entry, String lastByte) throws Exception {
		Function[] out = new Function[1];
		inTx(program, "function", () -> {
			try {
				out[0] = program.getFunctionManager().createFunction("disp", addr(entry),
					new AddressSet(addr(entry), addr(lastByte)), SourceType.USER_DEFINED);
			}
			catch (Exception e) {
				throw new AssertionError(e);
			}
		});
		assertNotNull(out[0]);
		return out[0];
	}

	private Set<Address> overrideDests(Function f, String site) {
		Namespace overrideSpace = HighFunction.findOverrideSpace(f);
		if (overrideSpace == null) {
			return null;
		}
		SymbolTable symtab = program.getSymbolTable();
		Namespace jmpSpace =
			HighFunction.findNamespace(symtab, overrideSpace, "jmp_" + addr(site));
		if (jmpSpace == null) {
			return null;
		}
		List<Symbol> cases = new ArrayList<>();
		for (Symbol sym : symtab.getSymbols(jmpSpace)) {
			if (sym.getName().startsWith("case")) {
				cases.add(sym);
			}
		}
		cases.sort(Comparator.comparing(Symbol::getAddress));
		Set<Address> out = new LinkedHashSet<>();
		for (Symbol sym : cases) {
			out.add(sym.getAddress());
		}
		return out;
	}

	private Set<Address> handlers(int n) {
		Set<Address> out = new LinkedHashSet<>();
		for (int i = 0; i < n; i++) {
			out.add(addr(HANDLERS[i]));
		}
		return out;
	}

	@Test
	public void writesTheOverrideAtOnceWhenAFunctionHoldsTheJmp() throws Exception {
		builder.setBytes("0x8000", "7c 00 81", false);
		builder.disassemble("0x8000", 3, false);
		Function f = createFunction("0x8000", "0x8002");
		analyze("0x8000");
		assertEquals(handlers(4), overrideDests(f, "0x8000"));
	}

	@Test
	public void defersTheOverrideUntilTheFunctionIsCreated() throws Exception {
		builder.setBytes("0x8000", "7c 00 81", false);
		builder.disassemble("0x8000", 3, false);
		analyze("0x8000");
		Function f = createFunction("0x8000", "0x8002");
		assertNull(overrideDests(f, "0x8000"));
		inTx(program, "relocate", () -> new JumpTableOverrideRelocatorAnalyzer().added(program,
			f.getBody(), TaskMonitor.DUMMY, new MessageLog()));
		assertEquals(handlers(4), overrideDests(f, "0x8000"));
		// idempotent
		inTx(program, "relocate", () -> new JumpTableOverrideRelocatorAnalyzer().added(program,
			f.getBody(), TaskMonitor.DUMMY, new MessageLog()));
		assertEquals(handlers(4), overrideDests(f, "0x8000"));
	}

	@Test
	public void aCallDispatchGetsNoOverride() throws Exception {
		builder.setBytes("0x8000", "fc 00 81", false);   // JSR ($8100,X)
		builder.disassemble("0x8000", 3, false);
		Function f = createFunction("0x8000", "0x8002");
		analyze("0x8000");
		assertNull(overrideDests(f, "0x8000"));
		inTx(program, "relocate", () -> new JumpTableOverrideRelocatorAnalyzer().added(program,
			f.getBody(), TaskMonitor.DUMMY, new MessageLog()));
		assertNull(overrideDests(f, "0x8000"));
	}

	/** grm-hf5h.5: the handlers become part of the dispatcher's body; a handler that already is
	 *  another function's entry stays that function's. */
	@Test
	public void theOwnerBodyGainsTheHandlersExceptExistingFunctions() throws Exception {
		builder.setBytes("0x8000", "7c 00 81", false);
		builder.disassemble("0x8000", 3, false);
		builder.disassemble("0x8210", 1, false);
		Function other = createFunction("0x8210", "0x8210");
		Function f = createFunction("0x8000", "0x8002");
		analyze("0x8000");
		assertEquals(handlers(4), overrideDests(f, "0x8000"));
		assertEquals(true, f.getBody().contains(addr(0x8200)));
		assertEquals(true, f.getBody().contains(addr(0x8220)));
		assertEquals(true, f.getBody().contains(addr(0x8230)));
		assertEquals(false, f.getBody().contains(addr(0x8210)));
		assertEquals(other, program.getFunctionManager().getFunctionAt(addr(0x8210)));
	}

	/** A later dispatch cuts the table; the override is rewritten from the surviving references. */
	@Test
	public void aShortenedTableRewritesItsOverride() throws Exception {
		builder.setBytes("0x8000", "7c 00 81", false);
		builder.disassemble("0x8000", 3, false);
		Function f = createFunction("0x8000", "0x8002");
		analyze("0x8000");
		assertEquals(handlers(4), overrideDests(f, "0x8000"));
		builder.setBytes("0x8010", "7c 04 81", false);
		builder.disassemble("0x8010", 3, false);
		analyze("0x8010");
		assertEquals(handlers(2), overrideDests(f, "0x8000"));
	}
}
