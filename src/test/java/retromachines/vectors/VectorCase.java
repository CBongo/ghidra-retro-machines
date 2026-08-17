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

import java.util.List;
import java.util.Map;

/**
 * One SingleStepTests-style single-instruction test case (bead grm-c9d.2): a named case with
 * an {@code initial} and {@code final} machine state, each a set of named scalar registers plus
 * a sparse list of RAM bytes.
 *
 * <p>Deliberately schema-agnostic on register names: the SPC700 suite
 * (github.com/SingleStepTests/spc700) uses {@code pc,a,x,y,sp,psw}; the 65x02 suites that
 * bead grm-o9k needs use a different register set with the same shape. {@link VectorParser}
 * captures whatever scalar fields a case JSON object has (everything except {@code ram}), so
 * this model -- and everything downstream of it, including {@link VectorRunner} -- never
 * hardcodes a register name. The {@code cycles} field of the upstream JSON is a bus trace with
 * no p-code analogue and is intentionally never parsed; {@code final.ram} already carries every
 * write a case makes.
 *
 * @param name       the case's upstream name (e.g. {@code "00 0000"})
 * @param initialRegs register name -> value, before executing the one instruction
 * @param initialRam sparse (address, byte value) pairs to seed before executing
 * @param finalRegs  register name -> expected value, after executing
 * @param finalRam   sparse (address, byte value) pairs expected after executing
 */
public record VectorCase(String name, Map<String, Integer> initialRegs, List<RamByte> initialRam,
		Map<String, Integer> finalRegs, List<RamByte> finalRam) {

	/** One sparse RAM entry from a vector's {@code ram} array: {@code [address, value]}. */
	public record RamByte(int address, int value) {}
}
