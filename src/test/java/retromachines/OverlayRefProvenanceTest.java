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

import java.util.Set;
import java.util.TreeSet;

import org.junit.Test;

import retromachines.OverlayRefProvenance.Placed;
import retromachines.OverlayRefProvenance.Placements;

/**
 * Pure coverage of {@link OverlayRefProvenance}'s ownership rule and record encoding (bead
 * grm-if81). The ProgramBuilder half -- retraction, base restore, the sweep -- is in
 * {@link BaseReferenceRetirementProgramTest}.
 */
public class OverlayRefProvenanceTest {

	private static final Placed B1 = new Placed(0, "PRG_LO_B1", 0x8010);
	private static final Placed B2 = new Placed(0, "PRG_LO_B2", 0x8010);
	private static final Placed OTHER = new Placed(1, "W8000_M0_B12", 0x9314);

	private static Set<Placed> set(Placed... ps) {
		Set<Placed> s = new TreeSet<>(Placed.ORDER);
		s.addAll(java.util.List.of(ps));
		return s;
	}

	@Test
	public void recordedButNotPlacedIsStale() {
		Placements now = new Placements();
		now.create(B2);
		assertEquals(set(B1), OverlayRefProvenance.stale(set(B1), now));
		assertEquals(set(B2), OverlayRefProvenance.owned(set(B1), now));
	}

	@Test
	public void confirmingARecordedReferenceKeepsIt() {
		Placements now = new Placements();
		now.confirm(B1);
		assertTrue(OverlayRefProvenance.stale(set(B1), now).isEmpty());
		assertEquals(set(B1), OverlayRefProvenance.owned(set(B1), now));
	}

	/** Confirming a reference nobody recorded does not adopt it -- it is another pass's. */
	@Test
	public void confirmingAnUnrecordedReferenceDoesNotAdoptIt() {
		Placements now = new Placements();
		now.confirm(B1);
		assertTrue(OverlayRefProvenance.owned(set(), now).isEmpty());
	}

	@Test
	public void encodingRoundTrips() {
		Set<Placed> entries = set(B2, OTHER, B1);
		String encoded = OverlayRefProvenance.encode(entries);
		assertEquals("0|PRG_LO_B1|8010,0|PRG_LO_B2|8010,1|W8000_M0_B12|9314", encoded);
		assertEquals(entries, OverlayRefProvenance.decode(encoded));
	}

	@Test
	public void malformedEntriesAreDropped() {
		assertEquals(set(B1), OverlayRefProvenance.decode("0|PRG_LO_B1|8010,junk,x|Y|1,2||5"));
		assertTrue(OverlayRefProvenance.decode(null).isEmpty());
		assertTrue(OverlayRefProvenance.decode("").isEmpty());
	}
}
