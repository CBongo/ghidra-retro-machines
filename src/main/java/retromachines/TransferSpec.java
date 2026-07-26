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

import ghidra.program.model.address.Address;

/**
 * The neutral description of a recovered code/data transfer -- the common currency of the
 * run-from-elsewhere subsystem (grm-1.7.x). Something is copied from {@link #srcStart} to
 * {@link #dstStart} for {@link #len} bytes, optionally passed through a {@link #transform},
 * and lands in a {@link #target} of the given kind. The recognizer (or, in a later
 * increment, a manual command or a descriptor {@code copied_from} hint) builds one of these;
 * a single materializer consumes it. No front-end knows about the others; they reach the
 * materializer through {@link RunFromElsewhere}.
 *
 * <p>The <b>disassembly directive</b> ({@link #disassemble}, {@link #makeFunction},
 * {@link #entryPoint}) is the key seam: a copy can carry <em>data or code</em>, so
 * materializing the bytes and disassembling them are decoupled. The auto recognizer
 * <em>infers</em> the directive (disassemble only when a call/jump into the range proves the
 * bytes run as code; entry at the block start); a descriptor front-end will <em>state</em> it
 * explicitly (the author knows it is code, and knows the entry may sit mid-block). The
 * materializer merely honors it.
 *
 * <p>This is the subsystem's <em>internal</em> currency and is deliberately package-private:
 * it has grown a field per front-end and will grow more, so publishing it would make every such
 * addition a source-breaking change. {@link RunFromElsewhere} is the public entry point, and its
 * builder is what external callers construct. If a thirteenth component is ever needed, convert
 * this record to a package-private builder rather than adding another positional argument.
 *
 * @param srcStart      first source byte (the master the copy mirrors)
 * @param dstStart      first destination byte (where the copy runs)
 * @param len           number of bytes transferred
 * @param transform     how source bytes map to destination bytes
 * @param target        where the recovered bytes are materialized
 * @param provenanceSite the instruction the provenance bookmark/comment anchor to (the copy
 *                       loop's counter init, for the auto recognizer); <b>null</b> when the
 *                       front-end has no instruction to annotate, as a descriptor
 *                       {@code copied_from} directive does not
 * @param confidence    AUTO (code proven -> disassemble) vs CANDIDATE (materialize as data)
 * @param disassemble   whether to disassemble the destination after materializing
 * @param makeFunction  whether to create a function at {@link #entryPoint} after disassembly
 * @param entryPoint    the destination address to disassemble from (defaults to dstStart; may
 *                       be mid-block when a descriptor front-end says so)
 * @param jumpSite       the call/jump instruction that enters the range, for the cross-space
 *                       reference bridge; null when there is none (data / CANDIDATE)
 * @param originLabel   what produced this transfer, as it should read in provenance text
 *                       ("copy loop", "descriptor copied_from hint", "manual transfer") -- three
 *                       front-ends now share the materializer, and only one of them has a loop
 */
record TransferSpec(Address srcStart, Address dstStart, int len, TransferTransform transform,
		TransferTarget target, Address provenanceSite, Confidence confidence, boolean disassemble,
		boolean makeFunction, Address entryPoint, Address jumpSite, String originLabel) {

	/** Recovery confidence, which gates auto-disassembly. */
	enum Confidence {
		/** A call/jump into the destination proves it runs as code. */
		AUTO,
		/** No such evidence: materialize the bytes but do not disassemble. */
		CANDIDATE;
	}
}
