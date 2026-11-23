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
package ghidra.program.emulation;

import java.io.Reader;
import java.nio.file.*;
import java.util.*;

import org.junit.Assume;
import org.junit.Test;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * NOT an upstream test -- a measurement harness kept in this repo under tools/upstream/
 * (bead grm-0xl1; it replaces the lost C02Vec.java used for ghidra#10087 / grm-4ixu).
 *
 * Runs SingleStepTests/65x02 vector files through a Ghidra checkout's OWN compiled 6502-family
 * language with PcodeEmulator, one instruction per case, comparing PC, A, X, Y, S, the N V D I Z C
 * flags and every final RAM byte. Copy it into the checkout at
 * Ghidra/Processors/6502/src/test/java/ghidra/program/emulation/ (untracked; never commit it to
 * the PR), then from this repo's root:
 *
 *   GRM_VEC_DIR=$GRM_6502_VECTORS/wdc65c02/v1 GRM_VEC_OPS=b2,12,32,52,72,92,d2,f2 \
 *   GRM_VEC_LANG=65C02:LE:16:default ./gradlew -p <checkout> \
 *     -I <checkout>/gradle/support/fetchDependencies.gradle \
 *     :6502:test --tests ghidra.program.emulation.W65C02ZpVectorProbe
 *
 * Set GRM_VEC_OUT=<file> to also write the report there. Results go to stdout lines "VEC <op> pass/total" (see the test's XML report / --info), plus up
 * to 3 "VECFAIL" samples per opcode. Stock-vs-patched: run once, stash the .slaspec change, run
 * again. Cycle/bus traces are ignored. Skips (Assume) when GRM_VEC_DIR is unset.
 */
public class W65C02ZpVectorProbe extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void runVectors() throws Exception {
		String dir = System.getenv("GRM_VEC_DIR");
		Assume.assumeTrue("GRM_VEC_DIR unset", dir != null && !dir.isEmpty());
		String ops = Objects.requireNonNullElse(System.getenv("GRM_VEC_OPS"), "b2");
		String langId = Objects.requireNonNullElse(System.getenv("GRM_VEC_LANG"),
			"65C02:LE:16:default");
		SleighLanguage lang = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID(langId));
		StringBuilder report = new StringBuilder();
		for (String op : ops.split(",")) {
			report.append(runFile(lang, Paths.get(dir, op.trim() + ".json"), op.trim()));
		}
		System.out.print(report);
		String outFile = System.getenv("GRM_VEC_OUT");
		if (outFile != null && !outFile.isEmpty()) {
			Files.writeString(Paths.get(outFile), report.toString());
		}
	}

	private static String runFile(SleighLanguage lang, Path file, String op) throws Exception {
		int pass = 0;
		int total = 0;
		int shown = 0;
		int unmodelled = 0;
		StringBuilder out = new StringBuilder();
		// ONE emulator per file: an emulator per case exhausts the test JVM's heap. Reuse is
		// sound because each case sets every register compared and every RAM byte it touches.
		PcodeEmulator emu = new PcodeEmulator(lang);
		PcodeThread<byte[]> t = emu.newThread();
		// streamed: a whole 10,000-case file parsed at once exhausts the heap too
		try (Reader r = Files.newBufferedReader(file);
				JsonReader jr = new JsonReader(r)) {
			jr.beginArray();
			while (jr.hasNext()) {
				JsonObject c = JsonParser.parseReader(jr).getAsJsonObject();
				total++;
				JsonObject init = c.getAsJsonObject("initial");
				int pc0 = init.get("pc").getAsInt();
				int op0 = Integer.parseInt(op, 16);
				// unmodelled, counted in the open: decode at pc > $fff7 (the decoder reads ahead
				// past $FFFF; the same exclusion the grm-4ixu harness made),
				// and decimal-mode ADC/SBC (Ghidra's 6502 family has no BCD)
				if (pc0 > 0xfff7 ||
					((op0 & 0x1f) == 0x12 && (op0 >> 5 == 3 || op0 >> 5 == 7) &&
						(init.get("p").getAsInt() & 0x08) != 0)) {
					unmodelled++;
					continue;
				}
				String diff =
					runCase(lang, emu, t, c.getAsJsonObject("initial"),
						c.getAsJsonObject("final"));
				if (diff.isEmpty()) {
					pass++;
				}
				else if (shown++ < 3) {
					out.append("VECFAIL ").append(op).append(' ')
							.append(c.get("name").getAsString()).append(": ").append(diff)
							.append('\n');
				}
			}
			jr.endArray();
		}
		return "VEC " + op + " " + pass + "/" + (total - unmodelled) + " (" + unmodelled +
			" unmodelled; " + lang.getLanguageID() + ")\n" + out;
	}

	private static final String[] FLAGS = { "N", "V", "D", "I", "Z", "C" };
	private static final int[] FLAG_BITS = { 7, 6, 3, 2, 1, 0 };

	private static String runCase(SleighLanguage lang, PcodeEmulator emu, PcodeThread<byte[]> t,
			JsonObject in, JsonObject fin) {
		PcodeArithmetic<byte[]> ar = t.getArithmetic();
		AddressSpace ram = lang.getDefaultSpace();
		for (JsonElement m : in.getAsJsonArray("ram")) {
			JsonArray p = m.getAsJsonArray();
			emu.getSharedState().setVar(ram, p.get(0).getAsLong(), 1, true,
				new byte[] { (byte) p.get(1).getAsInt() });
		}
		set(t, lang, "A", in.get("a").getAsInt());
		set(t, lang, "X", in.get("x").getAsInt());
		set(t, lang, "Y", in.get("y").getAsInt());
		set(t, lang, "SP", 0x100 | in.get("s").getAsInt());
		int p = in.get("p").getAsInt();
		set(t, lang, "B", (p >> 4) & 1);
		for (int i = 0; i < FLAGS.length; i++) {
			set(t, lang, FLAGS[i], (p >> FLAG_BITS[i]) & 1);
		}
		t.overrideCounter(ram.getAddress(in.get("pc").getAsLong()));
		t.overrideContextWithDefault();
		try {
			t.stepInstruction();
		}
		catch (Exception ex) {
			return "exception " + ex.getMessage();
		}
		StringBuilder d = new StringBuilder();
		cmp(d, "PC", get(t, ar, lang, "PC"), fin.get("pc").getAsInt());
		cmp(d, "A", get(t, ar, lang, "A"), fin.get("a").getAsInt());
		cmp(d, "X", get(t, ar, lang, "X"), fin.get("x").getAsInt());
		cmp(d, "Y", get(t, ar, lang, "Y"), fin.get("y").getAsInt());
		cmp(d, "S", get(t, ar, lang, "SP") & 0xff, fin.get("s").getAsInt());
		int fp = fin.get("p").getAsInt();
		for (int i = 0; i < FLAGS.length; i++) {
			cmp(d, FLAGS[i], get(t, ar, lang, FLAGS[i]) != 0 ? 1 : 0, (fp >> FLAG_BITS[i]) & 1);
		}
		for (JsonElement m : fin.getAsJsonArray("ram")) {
			JsonArray q = m.getAsJsonArray();
			long a = q.get(0).getAsLong();
			int got = emu.getSharedState().getVar(ram, a, 1, true, Reason.INSPECT)[0] & 0xff;
			cmp(d, String.format("[%04x]", a), got, q.get(1).getAsInt());
		}
		return d.toString();
	}

	private static void set(PcodeThread<byte[]> t, SleighLanguage lang, String name, long v) {
		Register r = lang.getRegister(name);
		t.getState().setVar(r, t.getArithmetic().fromConst(v, r.getMinimumByteSize()));
	}

	private static long get(PcodeThread<byte[]> t, PcodeArithmetic<byte[]> ar,
			SleighLanguage lang, String name) {
		return ar.toLong(t.getState().getVar(lang.getRegister(name), Reason.INSPECT),
			Purpose.INSPECT);
	}

	private static void cmp(StringBuilder d, String what, long got, long want) {
		if (got != want) {
			d.append(String.format("%s got %x want %x; ", what, got, want));
		}
	}
}
