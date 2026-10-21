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
package retromachines.vectors;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Language;

/**
 * Helpers shared verbatim by {@code Spc700VectorHarnessSupport}, {@code Mos6502VectorHarnessSupport}
 * and {@code W65816VectorHarnessSupport} (bead grm-rx1i.18). Anything that differs per language
 * (language id, instruction-length cap, decode-boundary cap) is an explicit parameter.
 */
final class VectorHarnessCommon {

	private VectorHarnessCommon() {
	}

	/** Resolves {@code languageId} via a {@link ProgramBuilder}, throwing if unavailable. */
	static Language resolveLanguage(String languageId) throws Exception {
		return new ProgramBuilder("Test", languageId).getProgram().getLanguage();
	}

	/**
	 * Fails loudly if the total decode-boundary case count across {@code rows} exceeds the
	 * ESTIMATED {@code cap} (the 6502 and 65816 harnesses, whose caps were not measured).
	 */
	static void assertEstimatedDecodeBoundaryCapNotExceeded(List<OpcodeBaseline> rows, int cap) {
		int total = rows.stream().mapToInt(OpcodeBaseline::decodeBoundaryCount).sum();
		if (total > cap) {
			throw new AssertionError("decode-boundary case count (" + total + ") exceeds the " +
				"ESTIMATED cap (" + cap + ", see that constant's doc) -- " +
				"investigate what started throwing DecodePcodeExecutionException before raising " +
				"this cap");
		}
	}

	/**
	 * The contiguous run of bytes in {@code c.initialRam()} starting at {@code start}, at most
	 * {@code maxLength} long; stops at the first gap.
	 */
	static byte[] contiguousBytes(VectorCase c, long start, int maxLength) {
		Map<Long, Integer> byAddress = new HashMap<>();
		for (VectorCase.RamByte rb : c.initialRam()) {
			byAddress.put(Integer.toUnsignedLong(rb.address()), rb.value());
		}
		List<Byte> out = new ArrayList<>();
		long addr = start;
		while (out.size() < maxLength && byAddress.containsKey(addr)) {
			out.add((byte) (int) byAddress.get(addr));
			addr++;
		}
		byte[] result = new byte[out.size()];
		for (int i = 0; i < result.length; i++) {
			result[i] = out.get(i);
		}
		return result;
	}

	static String toHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			if (sb.length() > 0) {
				sb.append(' ');
			}
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	/** The register/address token a {@link VectorRunner} mismatch message leads with, e.g.
	 *  {@code "PSW.C 1 != 0"} -> {@code "PSW"}, {@code "$10 0x99 != 0x42"} -> {@code "$10"}. */
	static String fieldNameOf(String mismatch) {
		String head = mismatch.split(" ", 2)[0];
		int dot = head.indexOf('.');
		return dot < 0 ? head : head.substring(0, dot);
	}

	/** Every {@code *.json} file directly under {@code dir}, sorted by name. */
	static List<File> opcodeFilesIn(File dir) {
		File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
		if (files == null) {
			return List.of();
		}
		List<File> list = new ArrayList<>(List.of(files));
		list.sort((a, b) -> a.getName().compareTo(b.getName()));
		return list;
	}
}
