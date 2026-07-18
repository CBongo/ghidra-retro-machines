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

import ghidra.app.util.bin.ByteProvider;

/**
 * Conservative loader opinion for C128 native-mode BASIC PRGs.
 * <p>
 * A raw CBM PRG contains only a load address, not a machine identity. This initial C128
 * opinion therefore claims only a structurally valid BASIC line chain at the native BASIC
 * text start, wholly within the CR=$00 native CPU view (stopping before the always-visible
 * MMU-shadow controls at $FF00). The descriptor's RAM-under-ROM targets preserve placement
 * across the visible ROM windows, but MMU-selected alternate maps are deliberately outside
 * this loader's scope.
 */
public class C128PrgLoader extends AbstractCbmPrgLoader {
	public static final String NAME = "Commodore 128 Native BASIC PRG";
	private static final long BASIC_START = 0x1c01;
	private static final long NATIVE_PRG_END_EXCLUSIVE = 0xff00;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	protected String getMapPath() {
		return "machines/c128.map";
	}

	@Override
	protected String getMachineId() {
		return "c128";
	}

	@Override
	protected boolean recognizesPrg(ByteProvider provider, long loadAddress, long payloadLength) {
		// Do not claim arbitrary machine-code PRGs or a BASIC image which would overlap the
		// MMU-shadow control registers. The shared structural sniff is intentionally dialect-neutral:
		// BASIC 7's CE/FE prefixed tokens are payload bytes as far as line-link validation is
		// concerned, and dialect-specific detokenization is a later analyzer concern.
		return loadAddress == BASIC_START &&
			payloadLength <= NATIVE_PRG_END_EXCLUSIVE - BASIC_START &&
			looksLikeBasicStart(provider, loadAddress, payloadLength);
	}
}
