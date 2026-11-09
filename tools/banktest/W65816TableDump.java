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
// Lists every word-array jump/dispatch table the 65816 analyzers laid (a word array whose first
// entry carries an ANALYSIS data reference), one line each:
//   TBL <addr> n=<entries> refs=<entries with a data reference> readers=<instructions referring to it>
// For A/B-ing a change to table sizing across a collection (written for grm-gipk.16.11/.12):
//   bash tools/banktest/snes-rom-sweep.sh --analysis --script W65816TableDump.java --list FILE
// and diff the TBL lines between two builds. Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class W65816TableDump extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (!currentProgram.getLanguageID().getIdAsString().startsWith("65816")) {
			println("TBL skip language " + currentProgram.getLanguageID());
			return;
		}
		DataIterator it = currentProgram.getListing().getDefinedData(true);
		int tables = 0;
		while (it.hasNext()) {
			Data d = it.next();
			if (!(d.getDataType() instanceof Array a) || !(a.getDataType() instanceof WordDataType)) {
				continue;
			}
			boolean ours = false;
			for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(d.getMinAddress())) {
				ours |= r.getSource() == SourceType.ANALYSIS && r.getReferenceType().isData();
			}
			if (!ours) {
				continue;
			}
			int refs = 0;
			for (int i = 0; i < a.getNumElements(); i++) {
				refs += currentProgram.getReferenceManager()
						.getReferencesFrom(d.getMinAddress().add(2L * i)).length > 0 ? 1 : 0;
			}
			int readers = currentProgram.getReferenceManager().getReferenceCountTo(d.getMinAddress());
			println("TBL " + d.getMinAddress() + " n=" + a.getNumElements() + " refs=" + refs +
				" readers=" + readers);
			tables++;
		}
		println("TBL summary tables=" + tables);
	}
}
