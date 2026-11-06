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
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import retromachines.CbmKernalLoad.Config;
import retromachines.CbmKernalLoad.Result;
import retromachines.CbmKernalLoad.Run;

/** Pure-JUnit coverage of {@link CbmKernalLoad} (bead grm-t3n.5); no Ghidra runtime. */
public class CbmKernalLoadTest {

	private static final String C64 = """
		{ "kernal_load": { "pointer": 174, "verify": 147,
		    "port": { "ddr": 0, "data": 1 },
		    "io": { "start": 53248, "end": 57343, "mask": 4, "any": 3,
		            "drop_before_port_write": false },
		    "initial": [ { "addr": 0, "value": 47 }, { "addr": 1, "value": 55 },
		                 { "addr": 147, "value": 0 } ] } }
		""";

	private static Config c64() {
		JsonObject map = JsonParser.parseString(C64).getAsJsonObject();
		return CbmKernalLoad.fromMap(map);
	}

	private static byte[] bytes(int... v) {
		byte[] b = new byte[v.length];
		for (int i = 0; i < v.length; i++) {
			b[i] = (byte) v[i];
		}
		return b;
	}

	@Test
	public void noSectionIsContiguousAndWraps() {
		assertTrue(CbmKernalLoad.fromMap(new JsonObject()).isEmpty());
		Result r = CbmKernalLoad.load(Config.NONE, 0xFFFE, bytes(1, 2, 3, 4));
		assertEquals(1, r.image()[0xFFFE]);
		assertEquals(2, r.image()[0xFFFF]);
		assertEquals(3, r.image()[0]);
		assertEquals(4, r.image()[1]);
		assertEquals(1, r.source()[0xFFFF]);
		assertEquals(List.of(new Run(0, 0xFFFE, 4)), r.runs());
		assertTrue(r.notes().isEmpty());
	}

	@Test
	public void declaredModelMatchesContiguousWhenPointerUntouched() {
		byte[] payload = new byte[0x300];
		for (int i = 0; i < payload.length; i++) {
			payload[i] = (byte) (i * 7);
		}
		Result plain = CbmKernalLoad.load(Config.NONE, 0x0800, payload);
		Result model = CbmKernalLoad.load(c64(), 0x0800, payload);
		assertTrue(Arrays.equals(plain.image(), model.image()));
		assertTrue(Arrays.equals(plain.source(), model.source()));
		assertTrue(model.notes().isEmpty());
		// The pointer cells themselves are only "written" if the file stored there.
		assertEquals(-1, model.image()[0xAE]);
	}

	@Test
	public void fileCoveringThePointerRedirectsItself() {
		// Same layout as the kloadredirecttest fixture.
		Result r = CbmKernalLoad.load(c64(), 0x00AC,
			bytes(0x11, 0x12, 0xAC, 0x13, 0xAE, 0x03, 0xA9, 0x07, 0x60));
		assertEquals(0x11, r.image()[0xAC]);
		assertEquals(0x13, r.image()[0xAD]); // the later store wins over +1
		assertEquals(0xAE, r.image()[0xAE]);
		assertEquals(0x03, r.image()[0xAF]);
		assertEquals(3, r.source()[0xAD]);
		assertEquals(0xA9, r.image()[0x3B0]);
		assertEquals(0x60, r.image()[0x3B2]);
		assertEquals(6, r.source()[0x3B0]);
		assertEquals(-1, r.image()[0xB0]);
		assertTrue(r.notes().stream().anyMatch(n -> n.contains("redirected")));
	}

	@Test
	public void verifyFlagStopsStores() {
		// +0 stores $FF at $93 (verify on); everything after it is compared, not stored.
		Result r = CbmKernalLoad.load(c64(), 0x0093, bytes(0xFF, 5, 6));
		assertEquals(0xFF, r.image()[0x93]);
		assertEquals(-1, r.image()[0x94]);
		assertEquals(2, r.verifySkipped());
	}

	@Test
	public void ioWindowDropsOnlyOncePortWasWritten() {
		// Untouched port: the project convention keeps RAM-under-I/O images.
		Result plain = CbmKernalLoad.load(c64(), 0xD000, bytes(1, 2));
		assertEquals(1, plain.image()[0xD000]);
		assertEquals(0, plain.ioDropped());
		// A load that writes $00/$01 = DDR 0x2F, data 0x37 maps I/O in, then reaches $D000.
		byte[] payload = new byte[0xD002];
		payload[0] = 0x2F;
		payload[1] = 0x37;
		payload[0xAE] = (byte) 0xAE; // keep the store pointer moving sequentially
		payload[0xD000] = 9;
		Result r = CbmKernalLoad.load(c64(), 0x0000, payload);
		assertEquals(0x2F, r.image()[0]);
		assertEquals(-1, r.image()[0xD000]);
		assertTrue(r.ioDropped() >= 2);
		// Same file with the port set to all-RAM ($01 = 4: LORAM/HIRAM clear) stores normally.
		payload[1] = 0x04;
		Result ram = CbmKernalLoad.load(c64(), 0x0000, payload);
		assertEquals(9, ram.image()[0xD000]);
		assertEquals(0, ram.ioDropped());
	}
}
