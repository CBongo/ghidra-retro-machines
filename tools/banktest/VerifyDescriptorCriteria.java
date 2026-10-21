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
// Per-fixture criteria for the game-descriptor fixtures (descoverlay*, descbankhint*)
// (VerifyBankTest.java sections, bead grm-rx1i.17). See VerifyBase.java.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class VerifyDescriptorCriteria extends VerifyBase {

	VerifyDescriptorCriteria(GhidraScript script, Verdict verdict) {
		super(script, verdict);
	}

	// ------------------------------------------------------------------
	// descoverlaytest / descoverlayctltest criteria (user-directory overlay, bead grm-hb6.15)
	// ------------------------------------------------------------------

	protected static final String GAME_DESCRIPTOR_PROPERTY = "Retro Machines.Game Descriptor";

	// ------------------------------------------------------------------
	// descbankhinttest / descbankhintmmc3test criteria (switch_sites bank: value hints,
	// beads grm-hb6.20, grm-hb6.22, grm-hb6.23) -- see mkdescbankhinttest.py's listings
	// ------------------------------------------------------------------

	/** SwitchSiteHints.VALUE_HINT_CATEGORY / HINT_COMMENT_SUFFIX, restated (scripts see no
	 *  package-private API). */
	protected static final String VALUE_HINT_CATEGORY = "Game descriptor bank hint";
	protected static final String HINT_SUFFIX = "(game descriptor hint)";

	protected String valueHintWarning(long offset) {
		Bookmark bm = currentProgram.getBookmarkManager().getBookmark(addr(offset),
			BookmarkType.WARNING, VALUE_HINT_CATEGORY);
		return bm == null ? null : bm.getComment();
	}

	protected void checkDescBankHint() {
		String path = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(GAME_DESCRIPTOR_PROPERTY, null);
		criterion("BH0:overlay-resolved", path != null &&
			path.replace('\\', '/').endsWith("/retro-machines/games/descbankhinttest.yaml"),
			"Game Descriptor property = " + path);

		// H1: RAM-fed store, nothing recoverable -- the hint supplies bank 2, says so, no warning.
		String c = eol(0xC002);
		criterion("BH1:hint-fills", c.contains("bank -> 2 (") && c.endsWith(HINT_SUFFIX) &&
			valueHintWarning(0xC002) == null,
			"c002: \"" + c + "\" warning=" + valueHintWarning(0xC002));
		criterionPrimaryCall("BH1:retarget", findOverlayRef(0xC005, "PRG_LO_B2", 0x8000),
			"JSR $8000 retargeted to PRG_LO_B2, primary: ");

		// H2: dataflow recovers 1 (LDA #1); the hint's 5 WINS and the warning names both.
		c = eol(0xC00A);
		String w = valueHintWarning(0xC00A);
		criterion("BH2:hint-wins", c.contains("bank -> 5 (") && c.endsWith(HINT_SUFFIX),
			"c00a: \"" + c + "\"");
		criterion("BH2:warns-both", w != null && w.contains("5") && w.contains("(1)") &&
			w.contains("descbankhinttest.yaml"), "c00a warning: " + w);
		criterionPrimaryCall("BH2:retarget", findOverlayRef(0xC00D, "PRG_LO_B5", 0x8000),
			"JSR $8000 retargeted to PRG_LO_B5 (the hint's bank, not dataflow's 1), primary: ");

		// H3: bank 9 of 8 is not applied: dataflow's 3 stands, unsuffixed, and it warns.
		c = eol(0xC012);
		w = valueHintWarning(0xC012);
		criterion("BH3:invalid-not-applied", c.contains("bank -> 3 (") && !c.contains("hint") &&
			w != null && w.contains("not applied"), "c012: \"" + c + "\" warning=" + w);
	}

	protected void checkDescBankHintMmc3() {
		// M1 (grm-hb6.22): the $8001 data write after select 6 takes the hint for R6 alone.
		String c = eol(0xE007);
		// A multi-field board renders every field: "bank -> select=6,prg_mode=0,r6=5,r7=1 [...]".
		criterion("BHM1:r6-hinted", c.contains("r6=5") && c.endsWith(HINT_SUFFIX) &&
			valueHintWarning(0xE007) == null,
			"e007: \"" + c + "\" warning=" + valueHintWarning(0xE007));
		criterionPrimaryCall("BHM1:retarget", findOverlayRef(0xE00A, "W8000_M0_B5", 0x8000),
			"JSR $8000 retargeted to R6's bank 5, primary: ");
	}

	/**
	 * The same MMC1 image imported with ({@code overlay}) and without a planted overlay
	 * descriptor hinting {@code prg_mode: 0}. The hint is visible in the home layout: mode 0
	 * is one 32 KiB base window W8000 at $8000-$FFFF, the t=0 default (mode 3) is W8000 at
	 * $8000-$BFFF plus WC000. The recorded descriptor path must name the overlay (not a
	 * curated .gmap) and, on the control, the property must be absent.
	 */
	protected void checkDescOverlay(boolean overlay) {
		String tag = overlay ? "OV" : "OVC";
		String path = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(GAME_DESCRIPTOR_PROPERTY, null);
		String norm = path == null ? null : path.replace('\\', '/');
		MemoryBlock w8000 = currentProgram.getMemory().getBlock("W8000");
		MemoryBlock wc000 = currentProgram.getMemory().getBlock("WC000");
		String layout = "W8000=" + (w8000 == null ? "<none>" : w8000.getStart() + "-" +
			w8000.getEnd()) + " WC000=" + (wc000 == null ? "<none>" : "present");
		if (overlay) {
			criterion(tag + "1:overlay-resolved",
				norm != null && norm.endsWith("/retro-machines/games/descoverlaytest.yaml"),
				"Game Descriptor property = " + path);
			criterion(tag + "2:not-curated", norm != null && !norm.endsWith(".gmap"),
				"Game Descriptor property = " + path);
			criterion(tag + "3:hint-applied-mode0",
				w8000 != null && w8000.getStart().getOffset() == 0x8000 &&
					w8000.getEnd().getOffset() == 0xFFFF && !w8000.isOverlay() && wc000 == null,
				layout);
		}
		else {
			criterion(tag + "1:no-descriptor", path == null,
				"Game Descriptor property = " + path + " (overlay must not outlive its fixture)");
			criterion(tag + "2:default-mode3",
				w8000 != null && w8000.getStart().getOffset() == 0x8000 &&
					w8000.getEnd().getOffset() == 0xBFFF && wc000 != null,
				layout);
		}
	}
}
