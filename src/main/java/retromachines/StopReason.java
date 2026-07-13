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

/**
 * Why an {@link EmulationRecovery} run stopped. Callers use this to decide whether the
 * recovered bytes are trustworthy: {@link #DIRTY_WATCH} and {@link #EXIT_RANGE} are the
 * "we reached the intended end" outcomes, while {@link #FUEL}, {@link #WALLCLOCK},
 * {@link #DECODE_FAULT}, and {@link #ERROR} mean the run was cut short and the result may
 * be partial.
 */
public enum StopReason {
	/** The dirty-watch target range became fully written -- the intended completion for a
	 *  bounded transform (decrypt loop, block copy) whose output range is known up front. */
	DIRTY_WATCH,
	/** Execution reached an address in the caller-supplied exit set. */
	EXIT_RANGE,
	/** The instruction-count budget was exhausted before any completion condition. */
	FUEL,
	/** The wall-clock budget was exhausted before any completion condition. */
	WALLCLOCK,
	/** Instruction decode ran into uninitialized memory -- a natural stop when the emulated
	 *  code branches somewhere the image did not populate (often the end of recovery). */
	DECODE_FAULT,
	/** The supplied {@code TaskMonitor} was cancelled. */
	CANCELLED,
	/** {@code loadProgram} could not copy the program image into the emulator. */
	LOAD_FAILED,
	/** Any other emulation exception aborted the run; see the provenance log for detail. */
	ERROR;
}
