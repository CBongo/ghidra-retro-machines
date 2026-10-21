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
// Per-fixture criteria for the NES board fixtures (nesbanktest, nesmmc*test, nesfork*, ...)
// (VerifyBankTest.java sections, bead grm-rx1i.17). See VerifyBase.java.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public abstract class VerifyNesCriteria extends VerifyDescriptorCriteria {

	// ------------------------------------------------------------------
	// nesbanktest.nes criteria (NesRomLoader + NesBankingAnalyzer, bead grm-5tl.17)
	// ------------------------------------------------------------------

	protected void checkNesBanktest() {
		// N1: the fixed window (PRG_HI) and the switchable window's home bank (PRG_LO,
		// un-suffixed -- bank 0 is the home/initial state) both land as base-space blocks.
		MemoryBlock prgHi = currentProgram.getMemory().getBlock("PRG_HI");
		criterion("N1a", prgHi != null && !prgHi.isOverlay(),
			"PRG_HI fixed block exists in base space: " + describeBlock(prgHi));
		MemoryBlock prgLo = currentProgram.getMemory().getBlock("PRG_LO");
		criterion("N1b", prgLo != null && !prgLo.isOverlay(),
			"PRG_LO home-bank block exists un-suffixed in base space: " + describeBlock(prgLo));

		// N2: every non-home bank (1, 2, 3 -- the fixture's PRG has 4 x 16 KiB banks) gets
		// an overlay block named <window>_B<bank>.
		MemoryBlock b1 = currentProgram.getMemory().getBlock("PRG_LO_B1");
		MemoryBlock b2 = currentProgram.getMemory().getBlock("PRG_LO_B2");
		MemoryBlock b3 = currentProgram.getMemory().getBlock("PRG_LO_B3");
		criterion("N2", b1 != null && b1.isOverlay() && b2 != null && b2.isOverlay() &&
			b3 != null && b3.isOverlay(),
			"PRG_LO_B1/_B2/_B3 overlay blocks exist: " + describeBlock(b1) + ", " +
				describeBlock(b2) + ", " + describeBlock(b3));

		// N3: empirical no-mangling check -- each overlay block's AddressSpace name equals
		// the block name (no Ghidra-side suffixing/renaming of the overlay space).
		for (MemoryBlock b : new MemoryBlock[] { b1, b2, b3 }) {
			if (b == null) {
				continue;
			}
			String blockName = b.getName();
			String spaceName = b.getStart().getAddressSpace().getName();
			criterion("N3:" + blockName, spaceName.equals(blockName),
				"overlay space name equals block name: block=\"" + blockName + "\" space=\"" +
					spaceName + "\"");
		}

		// N4: the mapper-latch write (LDA #$02 / STA $FFF0) at $C002 gets a fully-known
		// "bank -> 2" comment -- exercises MemoryLatchBankSwitchStrategy's bus-conflict path
		// (the STA's target $FFF0 is a bank-invariant ROM byte this fixture set to 0x02, so
		// the AND is a faithful no-op on the driven value).
		String c = eol(0xC002);
		criterionEolKnown("N4", c, "bank -> 2 (",
			"fully known bank -> 2 comment at c002: \"");

		// N5: the JSR $8005 at $C005, taken with bank=2 in effect (non-home -- PRG_LO's
		// home bank is 0), retargets into the PRG_LO_B2 overlay space.
		Reference r = findOverlayRef(0xC005, "PRG_LO_B2", 0x8005);
		criterionPrimaryCall("N5", r,
			"JSR $8005 in bank 2 retargeted to PRG_LO_B2 overlay, primary: ");

		// N6 (grm-bfb): the synthetic twin of the smb3 witnesses -- a cross-bank JSR whose
		// stock base-space CALL ref pointed at the HOME bank's bytes at $8005. With the
		// overlay ref in place that base ref is retired, so the call graph and references-to
		// at base:8005 no longer carry a call that never reaches it.
		criterion("N6", baseRefCount(0xC005, 0x8005) == 0,
			"JSR $8005 in bank 2 keeps no base-space ref to $8005 (" +
				baseRefCount(0xC005, 0x8005) + " found)");
	}

	// ------------------------------------------------------------------
	// nesbandaitest.nes criteria (Bandai FCG/LZ93D50 register-file decode, bead grm-9ty)
	// ------------------------------------------------------------------

	protected void checkNesBandaitest() {
		// D1: same UxROM-shaped block layout -- fixed PRG_HI and home PRG_LO in base space,
		// non-home banks 1/2/3 as PRG_LO_B<bank> overlays.
		MemoryBlock prgHi = currentProgram.getMemory().getBlock("PRG_HI");
		criterion("D1a", prgHi != null && !prgHi.isOverlay(),
			"PRG_HI fixed block exists in base space: " + describeBlock(prgHi));
		MemoryBlock prgLo = currentProgram.getMemory().getBlock("PRG_LO");
		criterion("D1b", prgLo != null && !prgLo.isOverlay(),
			"PRG_LO home-bank block exists un-suffixed in base space: " + describeBlock(prgLo));
		MemoryBlock b1 = currentProgram.getMemory().getBlock("PRG_LO_B1");
		MemoryBlock b2 = currentProgram.getMemory().getBlock("PRG_LO_B2");
		MemoryBlock b3 = currentProgram.getMemory().getBlock("PRG_LO_B3");
		criterion("D1c", b1 != null && b1.isOverlay() && b2 != null && b2.isOverlay() &&
			b3 != null && b3.isOverlay(),
			"PRG_LO_B1/_B2/_B3 overlay blocks exist: " + describeBlock(b1) + ", " +
				describeBlock(b2) + ", " + describeBlock(b3));

		// D2: the PRG-register write (LDA #$02 / STA $8008, register $8) at $C002 gets a
		// fully-known "bank -> 2" comment. FCG has no bus conflict, so the recovered value
		// is just the driven immediate (no ROM-byte AND).
		String c002 = eol(0xC002);
		criterionEolKnown("D2", c002, "bank -> 2 (",
			"fully known bank -> 2 comment at c002 (STA $8008): \"");

		// D3/D4: THE address-decode proof. The intervening writes to register $0 (STA $8000,
		// CHR, decoy value 1) at $C007 and register $A (STA $800A, IRQ, decoy value 3) at
		// $C00C are in the same $8000-$FFFF latch range but must NOT be treated as PRG-bank
		// latches -- so neither carries a "bank ->" comment. If the addr_mask/addr_match
		// predicate were absent, one of these decoys would have re-latched prg_bank.
		String c007 = eol(0xC007);
		criterion("D3", !c007.contains("bank ->"),
			"CHR register write (STA $8000) at c007 is NOT a prg_bank latch: \"" + c007 + "\"");
		String c00c = eol(0xC00C);
		criterion("D4", !c00c.contains("bank ->"),
			"IRQ register write (STA $800A) at c00c is NOT a prg_bank latch: \"" + c00c + "\"");

		// D5: the JSR $8005 at $C00F, taken with prg_bank still 2 (the decoys did not move
		// it), retargets into the PRG_LO_B2 overlay -- the positive counterpart to D3/D4.
		Reference r = findOverlayRef(0xC00F, "PRG_LO_B2", 0x8005);
		criterionPrimaryCall("D5", r,
			"JSR $8005 in bank 2 retargeted to PRG_LO_B2 overlay, primary: ");
	}

	// ------------------------------------------------------------------
	// nesmmc2test.nes criteria (MMC2 PRG bank select + address decode, bead grm-tas)
	// ------------------------------------------------------------------

	protected void checkNesMmc2test() {
		// M1: home-bank block layout -- W8000 (home = prg_bank 0) unqualified in base
		// space, non-home bank 2 realized as the W8000_B2 overlay. The three fixed
		// windows (WA000/WC000/WE000) don't reference bank state, so they never get a
		// _B<n> overlay of their own -- just the one base-space block each.
		MemoryBlock w8000 = currentProgram.getMemory().getBlock("W8000");
		criterion("M1a", w8000 != null && !w8000.isOverlay(),
			"W8000 home-bank block exists un-suffixed in base space: " + describeBlock(w8000));
		MemoryBlock w8000B2 = currentProgram.getMemory().getBlock("W8000_B2");
		criterion("M1b", w8000B2 != null && w8000B2.isOverlay(),
			"W8000_B2 overlay block exists: " + describeBlock(w8000B2));
		MemoryBlock wa000 = currentProgram.getMemory().getBlock("WA000");
		MemoryBlock wc000 = currentProgram.getMemory().getBlock("WC000");
		MemoryBlock we000 = currentProgram.getMemory().getBlock("WE000");
		criterion("M1c", wa000 != null && !wa000.isOverlay() && wc000 != null &&
			!wc000.isOverlay() && we000 != null && !we000.isOverlay(),
			"WA000/WC000/WE000 fixed blocks exist in base space: " + describeBlock(wa000) +
				", " + describeBlock(wc000) + ", " + describeBlock(we000));

		// M2: the PRG-register write (LDA #$02 / STA $A005, non-canonical address inside
		// $A000-$AFFF) at $E002 gets a fully-known "bank -> 2" comment. MMC2 has no bus
		// conflict, so the recovered value is just the driven immediate.
		String e002 = eol(0xE002);
		criterionEolKnown("M2", e002, "bank -> 2 (",
			"fully known bank -> 2 comment at e002 (STA $A005): \"");

		// M3: THE address-decode proof. The decoy write to $B000 (the CHR0 register,
		// immediately past the PRG register's $A000-$AFFF range) at $E007 must NOT be
		// treated as a prg_bank latch -- if the mechanism's start/end decode were wrong
		// (claiming the whole $A000-$FFFF register-mirrored range instead of just
		// $A000-$AFFF), this decoy's value (5) would have re-latched prg_bank.
		String e007 = eol(0xE007);
		criterion("M3", !e007.contains("bank ->"),
			"CHR0 register write (STA $B000) at e007 is NOT a prg_bank latch: \"" + e007 + "\"");

		// M4: the JSR $8005 at $E00A, taken with prg_bank still 2 (the decoy did not move
		// it), retargets into the W8000_B2 overlay -- the positive counterpart to M3.
		Reference r = findOverlayRef(0xE00A, "W8000_B2", 0x8005);
		criterionPrimaryCall("M4", r,
			"JSR $8005 in bank 2 retargeted to W8000_B2 overlay, primary: ");

		// M5: the phase-2 disassembly cascade actually produced an instruction at the
		// overlay target -- without this, M4's ref couldn't exist, but this checks the
		// disassembly (not just the reference) landed where expected.
		criterion("M5", hasInstructionAt("W8000_B2", 0x8005),
			"instruction exists at W8000_B2::8005");
	}

	// ------------------------------------------------------------------
	// nesmmc5test.nes criteria (bead grm-fxm, machines/nes-mmc5.yaml)
	// ------------------------------------------------------------------

	protected void checkNesMmc5test() {
		// M0: the IMAGE-RELATIVE initial_state seed (bead grm-y0ml) actually resolved.
		// machines/nes-mmc5.yaml seeds bank_5117 as "(image_size >> 13) - 1"; against this
		// fixture's 64 KiB PRG that is bank 7, so the mode-3 $E000 window's HOME instance --
		// the base-space block, where the vector table is read from -- must be bank 7 at file
		// offset 0xe000, not bank 0 at offset 0. The block comment is the loader's own record
		// of which slice it placed there.
		MemoryBlock we000 = currentProgram.getMemory().getBlock("WE000");
		String we000Comment = we000 == null ? "<no WE000 block>" : we000.getComment();
		criterion("M0:home", we000Comment != null && we000Comment.contains("bank_5117=7") &&
			we000Comment.contains("offset 0xe000"),
			"WE000 base block holds the image's last 8 KiB bank (resolved initial_state): \"" +
				we000Comment + "\"");

		// M0:property -- the loader published the resolved packed state for the analyzer,
		// which has no image size of its own. Field order is prg_mode(2), bank_5114(7),
		// bank_5115(7), bank_5116(7), bank_5117(7), so bank_5117 sits at bit 23:
		// (7 << 23) | 3 = 58720259.
		String resolved = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString("Retro Machines.Initial State", null);
		criterion("M0:property", "58720259".equals(resolved),
			"loader published resolved initial state (7 << 23 | 3): " + resolved);

		// M1: RESET's JSR $8000 at $E005, taken with bank_5114=1 in mode 3 (home mode,
		// matching initial_state), retargets into the mode-3/bank-1 overlay.
		Reference r = findOverlayRef(0xE005, "W8000_M3_B1", 0x8000);
		criterionPrimaryCall("M1", r,
			"JSR $8000 (mode3/bank_5114=1) retargeted to W8000_M3_B1 overlay, primary: ");

		// M2: the JMP $8100 at $E00D, taken right after the prg_mode 3 -> 0 switch,
		// retargets into mode 0's 32 KiB window arrangement -- the PRG MODE CHANGE
		// criterion. bank_5117 is untouched by that switch, so it still holds the RESOLVED
		// image-relative seed (7), and the overlay named must be _B4: mode 0's W8000 is
		// PRG[(bank_5117 >> 2) * 0x8000], so field value 7 is the ODD twin of canonical value 4
		// and selects the same 32 KiB image (grm-5dgx: only the canonical value is realized,
		// every aliasing value retargets into it). A build that dropped the resolved seed on
		// the way to the analyzer would land in _B0 instead, which makes this criterion the
		// end-to-end check on grm-y0ml as well as on the mode change.
		r = findOverlayRef(0xE00D, "W8000_M0_B4", 0x8100);
		criterionPrimaryCall("M2", r,
			"JMP $8100 (mode change 3->0) retargeted to W8000_M0_B4 overlay (7 aliases 4), primary: ");

		// M5 (grm-5dgx): no twin overlay is realized. Mode 0's W8000 decodes bank_5117 bits 2-6
		// (quads), modes 1/2 decode bits 1-6 (pairs) and mode 1's WC000 likewise: only the
		// lowest value per image has a space. The aliasing values must not.
		String twins = "";
		for (String twin : new String[] { "W8000_M0_B1", "W8000_M0_B2", "W8000_M0_B3",
			"W8000_M0_B5", "W8000_M0_B6", "W8000_M0_B7", "W8000_M1_B1", "W8000_M1_B3",
			"W8000_M2_B1", "W8000_M2_B7", "WC000_M1_B1", "WC000_M1_B7" }) {
			if (currentProgram.getAddressFactory().getAddressSpace(twin) != null) {
				twins += " " + twin;
			}
		}
		criterion("M5:noTwinOverlays", twins.isEmpty(),
			"no byte-identical twin overlay is realized (found:" + twins + ")");
		criterion("M5:canonicalOverlays",
			currentProgram.getAddressFactory().getAddressSpace("W8000_M0_B4") != null &&
				currentProgram.getAddressFactory().getAddressSpace("W8000_M1_B2") != null &&
				currentProgram.getAddressFactory().getAddressSpace("W8000_M2_B6") != null &&
				currentProgram.getAddressFactory().getAddressSpace("WC000_M1_B6") != null,
			"the canonical (lowest) value of each image keeps its overlay");

		// M3: bank-switch comments at the two latch-write sites -- each write is
		// recognized by a mechanism owning only ONE state field (bank_5114 or prg_mode),
		// so per the multi-mechanism engine's per-switch-effect annotation these are
		// partial comments: the acted-on field is "known", the others fall back to
		// "assumed from initial" -- except prg_mode, the layout-mode field, which a bank
		// write's comment shows whenever the dataflow knows it (grm-dos9.3; nesmodetest's F4).
		String e002 = eol(0xE002);
		criterion("M3:e002", e002.contains("bank_5114 -> 1") || e002.contains("bank_5114=1"),
			"bank_5114 latch -> 1 at e002: \"" + e002 + "\"");
		String e00a = eol(0xE00A);
		criterion("M3:e00a", e00a.contains("prg_mode -> 0") || e00a.contains("prg_mode=0"),
			"prg_mode latch -> 0 at e00a: \"" + e00a + "\"");

		// M4: the phase-2 disassembly cascade actually produced instructions at both
		// overlay targets reached above.
		criterion("M4:W8000_M3_B1_8000", hasInstructionAt("W8000_M3_B1", 0x8000),
			"instruction exists at W8000_M3_B1::8000");
		criterion("M4:W8000_M0_B4_8100", hasInstructionAt("W8000_M0_B4", 0x8100),
			"instruction exists at W8000_M0_B4::8100");
	}

	// ------------------------------------------------------------------
	// nesmmc5wraptest.nes criteria (bead grm-p25h, banking.bank_wrap: image)
	// ------------------------------------------------------------------

	/**
	 * MMC5 bank-number wrapping end to end. An MMC5 bank register is 7 bits wide on every
	 * cartridge, and a cart with fewer banks lacks the high PRG address lines, so the ASIC
	 * truncates -- rtk2's init writes 96/97/126 to a 32-bank cart meaning banks 0/1/30, and
	 * before {@code banking.bank_wrap} those values named banks with no image slice, so the
	 * title retargeted nothing at all. This image has 8 banks, so the mask is {@code & 7}.
	 * <p>
	 * See make_prg_mmc5wrap() in mknesbanktest.py for the byte layout. W1/W2 are the wrap
	 * itself; W3/W4 are the in-range control that keeps this from reading as "rewrite every
	 * bank"; W5 is the disassembly cascade both targets depend on.
	 */
	protected void checkNesMmc5Wraptest() {
		// W1: LDA #$29 / STA $5114 -- bank_5114 = 41 on an 8-bank image. The following
		// JSR $8000 must retarget into the CANONICAL overlay (41 & 7 = 1), not into a
		// nonexistent W8000_M3_B41. This is the criterion that fails on every build
		// before grm-p25h, with no reference placed at all.
		Reference r = findOverlayRef(0xE005, "W8000_M3_B1", 0x8000);
		criterionPrimaryCall("W1", r,
			"JSR $8000 after an out-of-range bank_5114=41 retargeted to the canonical " +
				"W8000_M3_B1 overlay (41 & 7 = 1), primary: ");

		// W2: and the annotation says it wrapped, showing BOTH numbers. Printing 1 alone
		// would hide that the code wrote 41, which is exactly how a genuine value-recovery
		// bug would be laundered into a plausible answer. The site must annotate, not warn:
		// a bank the hardware truncates into range is not an impossible bank.
		String e002 = eol(0xE002);
		criterion("W2:raw", e002.contains("bank_5114=41"),
			"annotation keeps the RAW recovered bank at e002: \"" + e002 + "\"");
		criterion("W2:wrapped", e002.contains("wraps to 1"),
			"annotation names the canonical bank at e002: \"" + e002 + "\"");
		criterion("W2:nowarn", !hasWarningBookmark(0xE002),
			"a wrapped bank is not an impossible bank, so no warning at e002");

		// W3: the in-range control. bank_5115 = 3 is a real bank on this image, so
		// canonicalization is the identity and the comment carries no wrap text at all --
		// the property that keeps every in-range site (and every board without bank_wrap)
		// byte-identical.
		String e00a = eol(0xE00A);
		criterion("W3:value", e00a.contains("bank_5115=3"),
			"in-range bank_5115=3 annotated at e00a: \"" + e00a + "\"");
		criterion("W3:nowrap", !e00a.contains("wraps to"),
			"an in-range bank says nothing about wrapping at e00a: \"" + e00a + "\"");

		// W4: and it retargets to its own bank's overlay, unchanged.
		r = findOverlayRef(0xE00D, "WA000_M3_B3", 0xA000);
		criterionPrimaryCall("W4", r,
			"JSR $A000 with in-range bank_5115=3 retargeted to WA000_M3_B3, primary: ");

		// W5: the phase-2 disassembly cascade reached both overlay targets.
		criterion("W5:W8000_M3_B1_8000", hasInstructionAt("W8000_M3_B1", 0x8000),
			"instruction exists at W8000_M3_B1::8000");
		criterion("W5:WA000_M3_B3_a000", hasInstructionAt("WA000_M3_B3", 0xA000),
			"instruction exists at WA000_M3_B3::a000");
	}

	// ------------------------------------------------------------------
	// nesbanktest2.nes criteria (3-deep overlay-bank JSR chain, bead grm-5tl.13.3)
	// ------------------------------------------------------------------

	protected void checkNesBanktest2() {
		// F1: RESET's JSR $8005 at $C005, taken with bank=2 in effect, retargets into the
		// PRG_LO_B2 overlay space -- round 1 evidence.
		Reference r = findOverlayRef(0xC005, "PRG_LO_B2", 0x8005);
		criterionPrimaryCall("F1", r,
			"JSR $8005 in bank 2 retargeted to PRG_LO_B2 overlay, primary: ");

		// F2: trampoline1's JSR $8010 at $C015 retargets into PRG_LO_B1 -- this instruction
		// is only disassembled at all once round 1's flow-follow from PRG_LO_B2::8005's own
		// JSR $C010 reaches it, and is only analyzed in round 2, so a resolved ref here is
		// round-2 evidence.
		r = findOverlayRef(0xC015, "PRG_LO_B1", 0x8010);
		criterionPrimaryCall("F2", r,
			"JSR $8010 in bank 1 (trampoline1, round-2 evidence) retargeted to PRG_LO_B1 " +
				"overlay, primary: ");

		// F3: trampoline2's JSR $8030 at $C025 retargets into PRG_LO_B3 -- reachable only
		// through trampoline1's JSR $C020, itself only disassembled by round 2's flow-follow
		// and only analyzed in round 3. This is the deepest reference in the chain, and its
		// resolution is direct proof that at least 3 full analyzer rounds ran to convergence
		// -- the load-bearing criterion for bead grm-5tl.13.3's fingerprint-skip guard.
		r = findOverlayRef(0xC025, "PRG_LO_B3", 0x8030);
		criterionPrimaryCall("F3", r,
			"JSR $8030 in bank 3 (trampoline2, round-3/deepest evidence -- proves >= 3 " +
				"analyzer rounds converged) retargeted to PRG_LO_B3 overlay, primary: ");

		// F4: fully-known bank-switch comments at the five latch-write sites (the two
		// forward selects at c002/c012/c022, and the two restores at c01a/c02a).
		String c = eol(0xC002);
		criterionEolKnown("F4:c002", c, "bank -> 2 (",
			"fully known bank -> 2 comment at c002: \"");
		c = eol(0xC012);
		criterionEolKnown("F4:c012", c, "bank -> 1 (",
			"fully known bank -> 1 comment at c012: \"");
		c = eol(0xC022);
		criterionEolKnown("F4:c022", c, "bank -> 3 (",
			"fully known bank -> 3 comment at c022: \"");
		c = eol(0xC01A);
		criterionEolKnown("F4:c01a", c, "bank -> 2 (",
			"fully known bank -> 2 (restore) comment at c01a: \"");
		c = eol(0xC02A);
		criterionEolKnown("F4:c02a", c, "bank -> 1 (",
			"fully known bank -> 1 (restore) comment at c02a: \"");

		// F5: the phase-2 disassembly cascade actually produced instructions at all three
		// deepest overlay targets -- without this, F1-F3's refs couldn't exist, but this
		// checks the disassembly (not just the reference) landed where expected.
		criterion("F5:PRG_LO_B2_8005", hasInstructionAt("PRG_LO_B2", 0x8005),
			"instruction exists at PRG_LO_B2::8005");
		criterion("F5:PRG_LO_B1_8010", hasInstructionAt("PRG_LO_B1", 0x8010),
			"instruction exists at PRG_LO_B1::8010");
		criterion("F5:PRG_LO_B3_8030", hasInstructionAt("PRG_LO_B3", 0x8030),
			"instruction exists at PRG_LO_B3::8030");
	}

	// ------------------------------------------------------------------
	// nesuxhelpertest.nes criteria (bank-switch helper ARGUMENT recovery, bead grm-hum)
	// ------------------------------------------------------------------

	/**
	 * Both real-cartridge idioms grm-3x1 made visible but could not recover a value from.
	 * See {@code mknesbanktest.py}'s {@code make_prg_uxhelper()} for the full listing; the
	 * shapes come from Contra (U) $C13F and Mega Man (U) FUN_d846, with SHA-256s pinned in
	 * {@code realrom/manifest.tsv}.
	 * <p>
	 * The load-bearing pair is <b>U1 vs U3</b>. U1 proves an argument passed in Y is
	 * recovered even though the mechanism write is an {@code STA} (before grm-hum the
	 * argument register was read off the store, so the engine hunted for an {@code LDA #imm}
	 * that had nothing to do with the bank -- a latent WRONG-answer risk, not merely a
	 * missing annotation). U3 proves the honest half stayed honest: an argument that really
	 * does come from RAM must NOT resolve. Anything that "fixes" the remaining warnings by
	 * guessing passes U1 and fails U3.
	 */
	protected void checkNesUxHelpertest() {
		// U1: LDY #$02 / JSR $C140 -- the Contra idiom. The bank argument is in Y; the
		// helper's own mechanism write is STA $FFD0,Y.
		String c = eol(0xC002);
		criterion("U1", c.contains("bank -> 2 (") && !c.contains("?") && c.contains("via"),
			"Y-passed helper argument recovered at c002: \"" + c + "\"");

		// U2: and the recovery is load-bearing -- the following JSR $8005 retargets into
		// bank 2's overlay. Without U1 there is no bank state to retarget against.
		Reference r = findOverlayRef(0xC005, "PRG_LO_B2", 0x8005);
		criterionPrimaryCall("U2", r,
			"JSR $8005 retargeted to PRG_LO_B2 overlay, primary: ");
		criterion("U2:disasm", hasInstructionAt("PRG_LO_B2", 0x8005),
			"instruction exists at PRG_LO_B2::8005");

		// U3: LDY $10 / JSR $C140 -- same helper, argument from zero-page RAM. ANTI-OVERREACH:
		// this must stay unresolved. Do not "fix" it; see the class comment above.
		criterion("U3", hasWarningBookmark(0xC00A) && !eol(0xC00A).contains("bank ->"),
			"RAM-sourced helper argument stays unresolved at c00a: warning=" +
				hasWarningBookmark(0xC00A) + " eol=\"" + eol(0xC00A) + "\"");

		// U4: STA $FFD0,Y at $C12D -- a refless INDEXED store whose index resolves through
		// TAY <- LDA $D81E,X <- TAX <- ASL A <- LDA #$00. Increment 1 alone: no helper
		// machinery involved, and the bus-conflict AND against $FFD1 is what pins it.
		c = eol(0xC12D);
		criterionEolKnown("U4", c, "bank -> 1 (",
			"indexed store with resolved index at c12d: \"");

		// U5: JSR $C120 -- the helper has TWO switch sites that disagree (bank 3 then bank 1),
		// so the constState model cannot describe it; the call must resolve to the bank that
		// actually survives the RTS. This is Mega Man FUN_d846's exact shape, and the reason
		// its pre-grm-3x1 golden was confidently wrong.
		c = eol(0xC00D);
		criterion("U5", c.contains("bank -> 1 (") && !c.contains("?") && c.contains("via"),
			"two-switch helper resolves to the LAST switch at c00d: \"" + c + "\"");

		// U6: and again load-bearing -- JSR $8010 lands in bank 1, not bank 3. Note this
		// holds despite U3 having poisoned the tracked state two calls earlier: the helper's
		// deposit owns the whole field regardless of what the caller knew.
		r = findOverlayRef(0xC010, "PRG_LO_B1", 0x8010);
		criterionPrimaryCall("U6", r,
			"JSR $8010 retargeted to PRG_LO_B1 overlay (switch #2 beat switch #1), primary: ");
		criterion("U6:disasm", hasInstructionAt("PRG_LO_B1", 0x8010),
			"instruction exists at PRG_LO_B1::8010");

		// U7: switch #1 inside the same helper does not regress now that switch #2 is visible.
		c = eol(0xC122);
		criterionEolKnown("U7", c, "bank -> 3 (",
			"first switch still resolved at c122: \"");

		// U8: LDA #$09 / STA $FFD9 on a 4-bank image. $FFD9 holds 0x09 so the bus-conflict AND
		// does NOT launder the value into a legal bank first -- the guard has to fire on a
		// bank the hardware really would have latched. Warn, and do not annotate or retarget.
		criterion("U8", hasWarningBookmark(0xC01E) && !eol(0xC01E).contains("bank ->"),
			"impossible bank 9 of 4 warns and does not annotate at c01e: warning=" +
				hasWarningBookmark(0xC01E) + " eol=\"" + eol(0xC01E) + "\"");

		// U9: TAIL CALL. FUN_c160's own highest-address switch says bank 3, but it does not
		// return -- it JMPs to FUN_c170, which latches bank 2 and returns to FUN_c160's caller.
		// A helper summarized by the last switch in its OWN body answers 3 here, confidently and
		// wrongly. This is Mega Man's FUN_d846 -> FUN_c3b3 shape (also FUN_d131, FUN_c55d), and
		// the wrong answer is what ships today for those.
		c = eol(0xC016);
		criterion("U9", c.contains("bank -> 2 (") && !c.contains("?"),
			"tail-calling helper resolves to the TAIL-CALLEE's bank, not its own last switch, " +
				"at c016: \"" + c + "\"");

		// U10: and load-bearing -- the following JSR $8020 must land in bank 2's overlay. If the
		// composition were skipped this retargets into PRG_LO_B3 instead, so the two banks are
		// distinguishable rather than coincidentally equal.
		r = findOverlayRef(0xC019, "PRG_LO_B2", 0x8020);
		criterionPrimaryCall("U10", r,
			"JSR $8020 after the tail-call helper retargeted to PRG_LO_B2 overlay, primary: ");

		// U11: TAIL-CALL DECLINE (bead grm-432), the only one of composeTailCalls' four decline
		// branches with dump-level coverage. FUN_c180 and FUN_c190 tail-jump to each other, so
		// composing either one's exit effect has no fixpoint -- exitEffect's cycle guard refuses
		// rather than guessing, and BOTH call sites must WARN instead of annotating. The shipped
		// analogue is Mega Man's FUN_f105, which tail-jumps to ITSELF at $F10F; that literal
		// self-jump is unreachable here because Ghidra will not retype it as a call (see
		// make_prg_uxhelper's docstring), so it is pinned at Tier 2 instead, alongside the other
		// three branches, by TailCallCompositionProgramTest.
		criterion("U11a", hasWarningBookmark(0xC021) && !eol(0xC021).contains("bank ->"),
			"tail-call cycle declines and warns at c021: warning=" +
				hasWarningBookmark(0xC021) + " eol=\"" + eol(0xC021) + "\"");
		criterion("U11b", hasWarningBookmark(0xC024) && !eol(0xC024).contains("bank ->"),
			"the cycle's other half declines and warns at c024: warning=" +
				hasWarningBookmark(0xC024) + " eol=\"" + eol(0xC024) + "\"");

		// U12: ANTI-VACUITY for U11, and the U7-shaped half of it -- the decline is about what
		// is live at the helper's RETURN, not about failing to see its write. The switch INSIDE
		// FUN_c180's body still resolves to bank 1. If this ever goes unresolved, U11 is
		// passing for the wrong reason (the site was never recognized at all, so there was no
		// helper to decline).
		c = eol(0xC182);
		criterionEolKnown("U12", c, "bank -> 1 (",
			"the declining helper's own switch site still resolves at c182: \"");
	}

	// ------------------------------------------------------------------
	// nesskiptest.nes criteria (6502 SKIP-IDIOM recovery, bead grm-pfp)
	// ------------------------------------------------------------------

	/**
	 * The only regression path {@code ghidra_scripts/FixSkipInstructions.java} has. The
	 * fixture is imported with that script as a {@code -postScript} (it MUST run after
	 * disassembly -- the conflict it repairs does not exist until then), and the criteria
	 * below assert what the repair did and, just as importantly, what it left alone. See
	 * {@code mknesbanktest.py}'s {@code make_prg_skip()} for the full listing; the shape is
	 * Wizards &amp; Warriors (U) $BC05/$BC08, whose SHA-256 is pinned in
	 * {@code realrom/manifest-gme.tsv}.
	 * <p>
	 * Three criteria carry the weight and none of them may be weakened to make a run pass.
	 * <b>S3</b> is the anti-corruption one: the repair must expose the hidden instruction
	 * WITHOUT redirecting the visible stream into it. <b>S5</b> is the anti-vacuity one:
	 * the recovered entry has to actually change the program's bank state, not merely
	 * exist. <b>S7</b> is the anti-overreach one: a structurally identical but
	 * uncorroborated carrier must be reported and left untouched.
	 */
	protected void checkNesSkiptest() {
		Listing listing = currentProgram.getListing();
		// S1: the offcut was repaired -- the bytes A9 01, previously claimed as the BIT's
		// operand, are now an instruction in their own right.
		// Matched WHOLE, not by substring: "contains 0x1" also accepts LDA #0x10 and LDA
		// #0x1f, and the operand is the entire point here -- it is the bank the recovered
		// stream asks for, and S5 turns on it being 1 rather than 2.
		Instruction hidden = listing.getInstructionAt(addr(0xC158));
		criterion("S1", hidden != null && "LDA #0x1".equals(hidden.toString()),
			"hidden entry disassembled at c158: " +
				(hidden == null ? "<no instruction>" : hidden.toString()));

		// S2: and it was repaired the upstream way -- by TRUNCATING the carrier with a
		// length override, not by clearing and re-disassembling it. The prototype stays 3
		// bytes long (which is what keeps the fallthrough honest; see S3) while the carrier
		// occupies only the one byte that is genuinely its own.
		Instruction carrier = listing.getInstructionAt(addr(0xC157));
		boolean overridden = carrier != null && carrier.isLengthOverridden();
		criterion("S2", overridden && carrier.getLength() == 1 && carrier.getParsedLength() == 3,
			"carrier truncated at c157: " + (carrier == null ? "<no instruction>"
					: carrier.getMnemonicString() + " overridden=" + carrier.isLengthOverridden() +
						" length=" + carrier.getLength() +
						" parsedLength=" + carrier.getParsedLength()));

		// S3: THE VISIBLE STREAM SURVIVED. The truncated carrier still falls through to the
		// SHARED TAIL at $C15A, not into the bytes it just exposed. If it ever falls through
		// to $C158 instead, the $C150 stream silently acquires the hidden LDA #$01 and every
		// call site reached through it reports the WRONG BANK with full confidence -- a
		// confidently wrong answer, which is strictly worse than the missing instruction the
		// script exists to recover. Ghidra gets this right because
		// InstructionDB.getDefaultFallThroughOffset returns the PROTOTYPE's length, so the
		// override does not move the default fallthrough; this criterion is what stops that
		// from silently changing under us. Do NOT relax it.
		Address fell = carrier == null ? null : carrier.getFallThrough();
		criterion("S3", fell != null && fell.equals(addr(0xC15A)),
			"truncated carrier still falls through to the shared tail c15a, not to the " +
				"hidden entry c158: fallThrough=" + (fell == null ? "<none>" : fmt(fell)));

		// S4: and the visible entry's own meaning is unchanged -- JSR $C150 still establishes
		// bank 2, from the STA $FFD2 at $C152 that belongs to the visible stream alone, and
		// the JSR right after it still retargets into bank 2's overlay. This is the
		// observable, end-to-end form of S3: the repair truncated an instruction in the
		// middle of this function's body and split a function entry out of it, and the
		// stream that was already correct came through unchanged.
		String c = eol(0xC000);
		criterionEolKnown("S4", c, "bank -> 2 (",
			"visible entry still resolves bank 2 at c000: \"");
		Reference r = findOverlayRef(0xC003, "PRG_LO_B2", 0x8005);
		criterionPrimaryCall("S4:retarget", r,
			"JSR $8005 retargeted to PRG_LO_B2 overlay, primary: ");

		// S5: THE PAYOFF, and the anti-vacuity check for S1. The recovered $C158 entry
		// establishes bank 1 (LDA #$01 into the shared latch), so the JSR that follows it in
		// RESET retargets into bank 1's overlay. This exists ONLY because the offcut was
		// repaired, given a function, and re-analyzed: without the repair, RESET's
		// JSR $C158 points at an address holding no instruction at all, nothing establishes
		// bank 1 anywhere in the image, and this reference stays in the home bank. Bank 1
		// and bank 2 are deliberately different so a repair that merged the two streams
		// (see S3) would answer this WRONGLY rather than coincidentally right.
		r = findOverlayRef(0xC009, "PRG_LO_B1", 0x8010);
		criterionPrimaryCall("S5", r,
			"JSR $8010 after the recovered entry retargeted to PRG_LO_B1 overlay, primary: ");
		criterion("S5:disasm", hasInstructionAt("PRG_LO_B1", 0x8010),
			"instruction exists at PRG_LO_B1::8010");

		// S6: the STRONG tier fired with no reference to lean on. Nothing in the image names
		// $C173 (make_prg_skip asserts that), so upstream FixOffcutInstructionScript's
		// reference gate has nothing to act on here and only this script's pattern match --
		// carrier hides an instruction that ends where the carrier ends, corroborated by the
		// LDA falling INTO it -- can reach the entry. The function is what makes the recovered
		// instruction analyzable: a loose instruction belongs to no function body, so no
		// dataflow pass ever evaluates it.
		Instruction strongEntry = listing.getInstructionAt(addr(0xC173));
		criterion("S6", hasFunctionAt(0xC173) && strongEntry != null &&
			"LDA #0x1".equals(strongEntry.toString()),
			"STRONG-tier entry recovered at c173 with a function: function=" +
				hasFunctionAt(0xC173) + " instruction=" +
				(strongEntry == null ? "<none>" : strongEntry.toString()));

		// S7: ANTI-OVERREACH -- the WEAK decoy at $C181 is untouched. BIT $10A5 hides a
		// structurally perfect LDA $10, but nothing corroborates it: SEC is not LDA and no
		// reference lands on $C182. Applying it would truncate a genuine memory read AND
		// invent an instruction inside its operand, destroying two real instructions to
		// manufacture one imaginary entry point. The script REPORTS it (see the SKIPFIX
		// summary assertion in run-banktest.sh, which pins weak=1) and does not apply it.
		// Do not "fix" this: a change that makes structural validity alone sufficient passes
		// S1/S6 and fails here, which is the entire point of the tiering.
		Instruction decoy = listing.getInstructionAt(addr(0xC181));
		criterion("S7", listing.getInstructionAt(addr(0xC182)) == null &&
			decoy != null && !decoy.isLengthOverridden(),
			"WEAK decoy left alone at c181: carrierOverridden=" +
				(decoy == null ? "<no instruction>" : String.valueOf(decoy.isLengthOverridden())) +
				" offcutDisassembled=" + (listing.getInstructionAt(addr(0xC182)) != null));

		// S8 (grm-3ou part 1): both latches' shared tails -- TAX / STA $FFD0,X at c15a/c15b and
		// c175/c176 -- store the A the CALLER supplied. The backward scan walks over the TAX and
		// lands on the helper's entry with A still undefined, which is a proof that A is live at
		// entry and so an HONEST gap: a NOTE, not a warning. The two call sites at c014/c019 are
		// where the value is actually recoverable, and they are annotated (S4's sibling comments
		// "bank -> 0 (bank=0) via FUN_c15a"/"via FUN_c175" in the dump).
		//
		// This is the case grm-3ou's HELPER_ARGUMENT category was written for, and the fixture
		// already had it by accident: it exists for the skip idiom, and the shared tail it needs
		// for that happens to be a textbook argument-taking helper body.
		criterion("S8",
			hasNoteBookmark(0xC15B) && !hasWarningBookmark(0xC15B) &&
				hasNoteBookmark(0xC176) && !hasWarningBookmark(0xC176),
			"both latch bodies' caller-supplied A is an honest gap: c15b note=" +
				hasNoteBookmark(0xC15B) + "/warning=" + hasWarningBookmark(0xC15B) +
				", c176 note=" + hasNoteBookmark(0xC176) + "/warning=" +
				hasWarningBookmark(0xC176));
	}

	// ------------------------------------------------------------------
	// nesmirrortest.nes criteria (bank-MIRROR derive/observe/consume/annotate/retarget
	// end-to-end, bead grm-mej.2 increment 2, Tier 3)
	// ------------------------------------------------------------------

	/**
	 * See {@code mknesbanktest.py}'s {@code make_prg_mirrortest()} for the full listing and
	 * the reasoning behind every address. {@code BankMirrorConsumptionProgramTest} (Tier 2)
	 * already pins the per-kind resolve/decline rules against a hand-built {@code BankMirrors}
	 * in isolation; this exercises the whole pipeline through the real analyzer -- a real
	 * derive pass, {@code observeMirrors}, consumption changing a real switch site, that
	 * changing a real overlay retarget, and (M1/M2 below) the grm-mej.2 SS2d guard that keeps
	 * an unrelated unresolved latch site from fabricating a bank-requirement violation.
	 */
	protected void checkNesMirrortest() {
		// M1: ROM_IDENTIFYING derived (from image content: byte $8200 of every realized
		// PRG_LO bank equals that bank's own number) AND consumed -- the re-latch at c008
		// reads $8200 (mirrors the live bank, currently 2) and re-commits it. Must resolve
		// to bank 2, not poison to unknown.
		String c = eol(0xC008);
		criterionEolKnown("M1", c, "bank -> 2 (",
			"ROM_IDENTIFYING mirror re-latch resolves to bank 2 at c008: \"");

		// M2: and load-bearing -- JSR $8005 right after retargets into PRG_LO_B2::8005 only
		// because c008 actually resolved.
		Reference r = findOverlayRef(0xC00B, "PRG_LO_B2", 0x8005);
		criterionPrimaryCall("M2", r,
			"JSR $8005 retargeted to PRG_LO_B2 overlay, primary: ");
		criterion("M2:disasm", hasInstructionAt("PRG_LO_B2", 0x8005),
			"instruction exists at PRG_LO_B2::8005");

		// M3: WRITE_THROUGH derived (two distinct stores into $42, corroborating each other)
		// AND consumed -- the reload at c01e must resolve to bank 3 (the second store's
		// value) from tracked state.
		c = eol(0xC01E);
		criterionEolKnown("M3", c, "bank -> 3 (",
			"WRITE_THROUGH mirror re-latch resolves to bank 3 at c01e: \"");

		// M4: H1 ordering (Castlevania 2's shape) -- a forwarded immediate (1) that
		// DISAGREES with tracked in-state (3) must win: the annotation shows the forwarded
		// value, never the stale tracked one.
		c = eol(0xC027);
		criterion("M4", c.contains("bank -> 1 (") && !c.contains("?") &&
			!c.contains("bank -> 3"),
			"forwarding outranks the stale mirror at c027: \"" + c + "\"");

		// M5: SAVE_SLOT declines. $59 was typed SAVE_SLOT by the read-back-then-restore walk
		// at c02a-c02f; a later reload inside FUN_C100 (c102) must stay UNRESOLVED --
		// warning bookmark present, no "bank ->" in the EOL comment. This is rated strictly
		// worse than no bank if it were answered wrong, per the module's own ranking.
		criterion("M5", hasWarningBookmark(0xC102) && !eol(0xC102).contains("bank ->"),
			"SAVE_SLOT reload stays unresolved at c102: warning=" + hasWarningBookmark(0xC102) +
				" eol=\"" + eol(0xC102) + "\"");

		// M6: ANTI-OVERREACH (U3-shaped) -- a RAM cell ($31) with no shadow and no store anywhere
		// in the program must ALSO stay unresolved. Since grm-rr5p it is classified an honest
		// runtime source (NOTE, not WARNING): nothing could ever have determined its content,
		// in contrast to M5's $59, which has a store and stays a WARNING. Same for the other
		// untouched cells $30 (c034) and $33 (c142).
		criterion("M6", hasNoteBookmark(0xC107) && !hasWarningBookmark(0xC107) &&
			!eol(0xC107).contains("bank ->") && eol(0xC107).contains("NOTE: runtime source") &&
			hasNoteBookmark(0xC034) && hasNoteBookmark(0xC142),
			"untouched RAM loads stay unresolved as honest NOTEs at c107/c034/c142: c107 note=" +
				hasNoteBookmark(0xC107) + " warning=" + hasWarningBookmark(0xC107) + " eol=\"" +
				eol(0xC107) + "\"");

		// M7: and load-bearing in the OTHER direction -- FUN_C100's own last switch (c10c, a
		// plain immediate) still resolves fully, proving M5/M6's declines didn't poison the
		// function's own later, unrelated site.
		c = eol(0xC10C);
		criterionEolKnown("M7", c, "bank -> 1 (",
			"FUN_C100's own trailing plain switch still resolves at c10c: \"");

		// M8: THE SS2d GUARD -- the reason this fixture exists. c037 (JSR $C100, called with
		// bank state genuinely unknown by construction) must NOT carry a bank-state
		// requirement-violation WARNING. Before the per-site effectDependsOnPriorState
		// override landed alongside cacheable()->false, M5/M6's declining sites (unresolved
		// for reasons having nothing to do with missing entry state) would each have been
		// blamed on a missing bank-known-on-entry requirement, propagating a fresh violation
		// bookmark here. c10a-c10c's plain, always-resolvable last switch keeps this call out
		// of the ordinary "helper argument could not be recovered" warning path (see the
		// module doc), so any warning landing here can only be the spurious violation this
		// guard exists to prevent.
		criterion("M8", !warningBookmarkText(0xC037).contains("requirement violated"),
			"no spurious bank-state requirement violation at c037 (JSR $C100): warning=\"" +
				warningBookmarkText(0xC037) + "\"");

		// M9 (bead grm-mlp2): THE POSITIVE DIRECTION, and until this landed the whole suite
		// had none. M8 just above, and nesmmc3test2's G11, are both NEGATIVE ("no spurious
		// violation here"); nothing asserted that a genuine bank-known-on-entry requirement
		// is ever actually REPORTED. grm-vgod removed 12 such warnings from the rcransom and
		// smb2 real-ROM rows on the argument that SelectData can never express one -- that
		// was verified against real ROMs and stands, but no synthetic criterion would have
		// caught it had it been wrong, and G2's decay into a tautology is what surfaced the
		// gap.
		//
		// THIS WAS THE ONLY BOARD WHERE THE DIAGNOSTIC WAS OBSERVABLE. A site contributes to
		// requiresOnEntry only when its strategy answers true from effectDependsOnPriorState,
		// and MemoryLatchBankSwitchStrategy:633 was the sole strategy that ever did -- it
		// re-runs evaluateLatch under a MirrorProbe and reports whether a MIRROR load was
		// actually reached and answered. SelectDataBankSwitchStrategy returned false
		// unconditionally, so on an MMC3 board ownRequires was empty board-wide and no call
		// site could carry a violation at all, however it was reshaped (that IS G11). Since
		// grm-sen5 select-data has the same per-site probe; nesmmc3mirrortest's MM12/MM13 are
		// this criterion's MMC3 counterpart.
		//
		// The chain is CallerP -> WorkerM -> MirrorLeaf. MirrorLeaf's site reads $42 -- derived
		// WRITE_THROUGH, hence a LIVE mirror -- unlike FUN_C100's SAVE_SLOT $59 and shadowless
		// $31, which is exactly why M8 demands no violation and this demands one. Those two
		// criteria are the A/B pair for the whole per-site predicate.
		//
		// ON THE MIDDLE HOP, because the reason for it changed once measured. It was added to
		// dodge the alreadyWarned interlock (:392 / :3703) that makes a direct call to a
		// requiring leaf show the helper-argument warning instead of the violation -- the trap
		// that left nesmmc3test2's G2 vacuous. On this board that dodge turns out to be
		// unnecessary: NEITHER c130 nor c145 enters the helper-argument path, and both carry
		// violations (see M10). The hop is kept for what it now proves instead -- a
		// requirement observed at c145 can only have arrived by TRANSITIVE propagation through
		// WorkerM, which is the :3654 rule itself under test. A direct call would show less.
		//
		// Assert the TEXT: presence alone over a site that can carry several kinds of warning
		// is how nesmmc3test2's G2 quietly stopped testing anything.
		criterion("M9", warningBookmarkText(0xC145).contains("requirement violated"),
			"a genuine bank-state requirement violation IS reported at CallerP's JSR $C130 " +
				"(c145), where WorkerM's inherited mirror-derived requirement is unmet: " +
				"warning=\"" + warningBookmarkText(0xC145) + "\"");

		// M10 (bead grm-mlp2): M9's load-bearing companion. Two things it pins that M9 alone
		// cannot.
		//
		// FIRST, that M9 is not passing on the WRONG violation. The warning at c145 must name
		// FUN_c130 -- the hop -- because that is what makes it a PROPAGATED requirement rather
		// than one read directly off a leaf. Naming FUN_c120 there would mean the call graph
		// collapsed and :3654 was never exercised.
		//
		// SECOND, that the leaf really is the origin: c130 carries its own violation naming
		// FUN_c120. Together the two warnings trace the requirement's whole path up the chain,
		// leaf -> hop -> caller, which is the property grm-vgod's 12 removed real-ROM warnings
		// turned on and which nothing in this suite previously asserted in the positive
		// direction.
		//
		// Both assert TEXT, never presence -- a site here can carry either of two diagnostics,
		// and presence-only over exactly that is how nesmmc3test2's G2 decayed into a
		// tautology.
		String w130 = warningBookmarkText(0xC130);
		criterion("M10",
			warningBookmarkText(0xC145).contains("call to FUN_c130") &&
				w130.contains("requirement violated") && w130.contains("call to FUN_c120"),
			"the violation propagated leaf -> hop -> caller: c145 names the hop FUN_c130 and " +
				"c130 names the leaf FUN_c120, so M9's requirement genuinely arrived through " +
				"WorkerM (BoardBankAnalyzer:3654) rather than off a direct leaf call: " +
				"c130=\"" + w130 + "\"");
	}

	// ------------------------------------------------------------------
	// nesmmc3mirrortest.nes criteria (bank-mirror read-back on a select-data board, PER
	// WINDOW, bead grm-sen5)
	// ------------------------------------------------------------------

	/**
	 * See {@code mknesbanktest.py}'s {@code make_prg_mmc3_mirror()} for the full listing.
	 * {@code SelectDataMirrorConsumptionProgramTest} (Tier 2) pins the per-window resolve and
	 * every refusal against a hand-built {@code BankMirrors}; this is the pipeline: a real
	 * derive pass attributing {@code $A100} to R7's window ({@code WA000}, the one
	 * mode-invariant switchable window on MMC3), {@code observeMirrors} reaching
	 * {@code SelectDataBankSwitchStrategy} at all (it never did before this bead), consumption
	 * at a data write and at a helper call site, retargets that only happen because of it,
	 * H2's save-slot decline on this board, a refusal for the mode-varying window, and the
	 * per-site {@code effectDependsOnPriorState} guard in BOTH directions with a non-empty
	 * mirror set (nesmmc3test2's G11 has no mirrors, so it never reaches the probe).
	 */
	/**
	 * Whether {@code field} is FULLY known in a bank comment: it is named, and no bit of it
	 * appears in the comment's "assumed from initial:" list (a comment with no '?' has no such
	 * list and every named field is known). Lets a criterion pin one field's knowledge while
	 * an unrelated field arrives partially known from elsewhere in the flow.
	 */
	protected static boolean fieldKnownIn(String eol, String field) {
		if (!eol.contains(field + "=")) {
			return false;
		}
		int i = eol.indexOf("assumed from initial:");
		if (i < 0) {
			return true;
		}
		String assumed = eol.substring(i);
		int end = assumed.indexOf(']');
		if (end >= 0) {
			assumed = assumed.substring(0, end);
		}
		return !assumed.contains(field + ".");
	}

	protected void checkNesMmc3Mirrortest() {
		// MM1: ROM_IDENTIFYING derived at $A100 (byte $100 of every realized WA000 bank == that
		// bank's number) AND consumed on a select-data board -- the re-commit at e20d reads
		// $A100 with r7 = 3 tracked and must deposit r7 = 3, fully known.
		String c = eol(0xE20D);
		criterionEolKnown("MM1", c, "r7=3",
			"identifying-byte re-commit resolves r7=3 at e20d: \"");

		// MM2: and load-bearing -- JSR $A000 right after retargets into WA000_B3::A000 only
		// because e20d resolved (an unresolved r7 would have poisoned the window).
		Reference r = findOverlayRef(0xE210, "WA000_B3", 0xA000);
		criterionPrimaryCall("MM2", r,
			"JSR $A000 retargeted to WA000_B3, primary: ");
		criterion("MM2:disasm", hasInstructionAt("WA000_B3", 0xA000),
			"instruction exists at WA000_B3::A000");

		// MM3: the same read at a HELPER CALL SITE -- LDA $A100 / JSR H -- resolves r7=3 via H
		// through SelectDataBankSwitchStrategy.callerSideHooks, the caller-side half this bead
		// adds alongside the direct-path hooks. No warning, no '?'.
		c = eol(0xE216);
		criterion("MM3", !hasWarningBookmark(0xE216) && c.contains("r7=3") && !c.contains("?"),
			"identifying byte feeds the helper argument at e216: \"" + c + "\" warning=\"" +
				warningBookmarkText(0xE216) + "\"");

		// MM4: THE PER-WINDOW PROOF. r6 = 2 and r7 = 4 are both tracked; R7's identifying byte
		// is committed through select 6. The answer must be the WINDOW's field (R7 -> 4), not
		// the TARGET's (R6 -> 2): "r6=4", and specifically never "r6=2".
		c = eol(0xE25C);
		criterion("MM4", c.contains("r6=4") && !c.contains("r6=2") && !c.contains("?"),
			"R7's byte lands in r6 as 4 (never r6's own stale 2) at e25c: \"" + c + "\"");

		// MM5: and load-bearing in the mode-varying window -- JSR $8000 retargets into
		// W8000_M0_B4 (bank 4, the copied value), not W8000_M0_B2.
		r = findOverlayRef(0xE25F, "W8000_M0_B4", 0x8000);
		criterion("MM5", r != null && r.getReferenceType().isCall() && r.isPrimary() &&
			findOverlayRef(0xE25F, "W8000_M0_B2", 0x8000) == null,
			"JSR $8000 retargeted to W8000_M0_B4 (not B2), primary: " + describe(r));

		// MM6: WA000 is R7 under prg_mode 1 too (the descriptor hoists it as mode-invariant),
		// so the identifying read still answers with r7 there: r7=5 with every r7 bit KNOWN,
		// prg_mode=1. Asserted per FIELD rather than as "no '?'": r6 arrives at this function
		// partially known through RESET's helper-summary fold of the earlier dispatch calls
		// (each callee here contains mechanism writes), which is pre-existing engine behaviour
		// and not what this criterion is about.
		c = eol(0xE28D);
		criterion("MM6", c.contains("r7=5") && c.contains("prg_mode=1") && fieldKnownIn(c, "r7"),
			"identifying read resolves r7=5 under prg_mode=1 at e28d: \"" + c + "\"");

		// MM7: retarget into the hoisted WA000_B5 (no _M suffix).
		r = findOverlayRef(0xE290, "WA000_B5", 0xA000);
		criterionPrimaryCall("MM7", r,
			"JSR $A000 retargeted to WA000_B5, primary: ");

		// MM8: the read-back-then-re-commit that establishes $59 as a SAVE_SLOT (TMNT's cec0
		// shape) itself resolves through the mirror: r7=3 at e2cf.
		c = eol(0xE2CF);
		criterion("MM8", c.contains("r7=3") && fieldKnownIn(c, "r7"),
			"re-commit after the save resolves r7=3 at e2cf (per field, as MM6): \"" + c + "\"");

		// MM9: H2's ruling on this board -- the restore THROUGH THE HELPER from the save slot
		// (LDA $59 / JSR H) must NOT be answered from in-state, which says r7=2 while the slot
		// holds 3. Since grm-mej.24 the slot proof carries the 3 forward: the crossed
		// JSR $A000 lands in the realized WA000_B2 overlay, a known bank, so its census walks
		// the lone RTS there. Round 1 (before the retarget) warns at e2dc; since grm-mej.26 the
		// end-of-round bookmark sweep retracts that WARNING once round 2 resolves the site.
		c = eol(0xE2DC);
		criterion("MM9", c.contains("r7=3") && fieldKnownIn(c, "r7") && !c.contains("r7=2") &&
			!hasWarningBookmark(0xE2DC),
			"restore from the save slot via H carries the slot's r7=3 at e2dc, no stale " +
				"WARNING: warning=" + hasWarningBookmark(0xE2DC) + " \"" + c + "\"");

		// MM10: the DIRECT restore from the slot (LDA $59 / STA $8001), same ruling: r7 wholly
		// unknown (every r7 bit "assumed from initial"), never a confident 2 or 3.
		c = eol(0xE2E1);
		criterion("MM10", c.contains("?") && c.contains("r7.0,r7.1,r7.2,r7.3,r7.4,r7.5"),
			"direct restore from the save slot leaves r7 unknown at e2e1: \"" + c + "\"");

		// MM11: REFUSE WHERE THE PROOF IS MISSING. Every W8000 bank also holds its number at
		// $100, but W8000 is mode-varying (R6 in prg_mode 0, fixed in 1) and is never
		// content-scanned, so LDA $8100 / STA $8001 must leave r7 wholly unknown -- not r6's
		// value, not anything.
		c = eol(0xE30D);
		criterion("MM11", c.contains("?") && c.contains("r7.0,r7.1,r7.2,r7.3,r7.4,r7.5"),
			"a mode-varying window's identifying-looking byte is refused at e30d: \"" + c + "\"");

		// MM12: THE SS2d GUARD, POSITIVE DIRECTION. Leaf reads the mirror with r7 unknown on
		// entry; the per-site effectDependsOnPriorState override (new on this strategy) must
		// report that as a genuine requirement, which propagates through Worker to CallerH's
		// JSR at e34b as "requirement violated" naming r7. Before this bead the strategy-wide
		// false was the only answer and this could never be reported (nesmmc3test2's G2 note).
		String w = warningBookmarkText(0xE34B);
		criterion("MM12", w.contains("requirement violated") && w.contains("r7"),
			"a mirror-derived bank-known-on-entry requirement IS reported at CallerH's JSR " +
				"Worker (e34b): warning=\"" + w + "\"");

		// MM13: and it arrived by propagation -- the warning names the hop FUN_e360, not the
		// leaf, so the :3654 rule carried it (nesmirrortest's M10 shape).
		criterion("MM13", w.contains("call to FUN_e360"),
			"the violation at e34b names the hop FUN_e360: \"" + w + "\"");

		// MM14: THE NEGATIVE CONTROL, with the mirror set NON-EMPTY. LeafQ fails for an
		// unrelated reason (an opaque load, not a mirror), so the per-site probe must answer
		// false and CallerQ's JSR at e3ab must carry NO requirement violation. This is the
		// over-reporting hazard grm-vgod removed 29 warnings for, re-guarded on the path
		// nesmmc3test2's G11 cannot reach.
		criterion("MM14", !warningBookmarkText(0xE3AB).contains("requirement violated"),
			"no spurious violation at CallerQ's JSR WorkerQ (e3ab): warning=\"" +
				warningBookmarkText(0xE3AB) + "\"");
	}

	// ------------------------------------------------------------------
	// nesmmc3idtest.nes criteria (the (bank-1)/2 identifying byte, bead grm-km4f)
	// ------------------------------------------------------------------

	/**
	 * See {@code mknesbanktest.py}'s {@code make_prg_mmc3_id()} for the full listing. Where
	 * {@code nesmmc3mirrortest} proves the IDENTITY ROM_IDENTIFYING encoding (byte == bank) is
	 * derived and consumed, this fixture proves the NON-identity SHIFT encoding grm-km4f adds:
	 * {@code BankMirrors.romIdentifyingOffsets} admitting (shift=1, low=1) at $BFF0 off rcransom's
	 * real-ROM shape (byte == (bank-1)/2 on the odd banks of a 16-bank image), with the
	 * {@code MIN_SHIFTED_IDENTIFYING_BANKS} floor cleared by seven matches and the
	 * two-highest-bank EXEMPT tolerance that keeps bank 15 (the fixed {@code PRG[last]} bank,
	 * holding junk at this offset) from vetoing the whole offset.
	 * <p>
	 * ID3 and ID7 are the positive proof (the derivation admits $BFF0 with the shift encoding,
	 * and a direct {@code LDA $BFF0 / JSR H16} recovers the pair). ID4-ID6 and ID8 pin the
	 * refusals. ID1/ID2 pin the one shape this bead does NOT reach -- the stack-carried restore
	 * across calls -- as honestly unknown, with the grm-mej.3 dependency spelled out at the
	 * criterion.
	 */
	protected void checkNesMmc3Idtest() {
		// ID1: the RESTORE, rcransom's fa43 trampoline shape -- read the mirror while r7=3, PHA,
		// switch away through H16, call into the bank, PLA, feed the byte back into H16. This
		// now RESOLVES (grm-mej.3 increment 3, "call-crossing PHA/PLA pairing"):
		// CrossBlockStackPairing.findMatchingPush steps OVER a call while pairing the PLA to its PHA
		// (the depth counter stays exact across JSR/RTS, which are balanced by construction --
		// see findMatchingPush's javadoc), and the walk that resumes from the located PHA
		// resolves the mirror read against the tracked state AT THAT PUSH (r7=3), via
		// BankDataflowEngine's StateOracle, rather than against the state at the call site
		// itself (r7=5, the confidently WRONG bank the switch through H16 already moved to).
		// rcransom's own c08e/c0f4/c7db/cd57/ef85 restores were named as this shape but did NOT
		// move when this landed (real-ROM tier, 2026-09-21) -- either their entry bank is
		// unknown (then the answer is grm-yflf's relational one) or the local shape differs; a
		// listing read is filed in docs/human-research-todo.md section 1. Never a junk-derived
		// pair: this must land on the true r6=2,r7=3, not on some other value an unsound
		// implementation could have manufactured.
		String c = eol(0xE212);
		criterion("ID1", c.contains("r6=2") && c.contains("r7=3") && !c.contains("?") &&
			!hasWarningBookmark(0xE212),
			"H16 restore at e212 (PLA across two calls) resolves r6=2,r7=3 fully known " +
				"(grm-mej.3 increment 3): \"" + c + "\"");

		// ID2: consequently the JSR $A000 after the restore IS retargeted into WA000_B3 -- the
		// direct payoff of ID1 now resolving. Flip together with ID1.
		Reference r = findOverlayRef(0xE215, "WA000_B3", 0xA000);
		criterion("ID2", r != null,
			"JSR $A000 after the now-resolved restore carries a WA000_B3 retarget " +
				"(grm-mej.3 increment 3): " + describe(r));

		// ID3: the same read/restore with no intervening switch -- the mirror byte feeds H16
		// straight from the accumulator, no stack round-trip needed to prove the shape resolves.
		c = eol(0xE248);
		criterion("ID3", c.contains("r6=2") && c.contains("r7=3") && !c.contains("?"),
			"Direct's H16 call at e248 resolves r6=2,r7=3 fully known: \"" + c + "\"");

		// ID4: an INCONGRUENT bank (r7=4, even, committed by direct writes). r7's low bit is
		// known and 0, which does not match this offset's low=1, so the mirror byte cannot be
		// answered at all -- and, critically, that refusal must not degrade into a confident
		// junk-derived pair when the (still-unknown) byte reaches H16: never r6=0xd6/r7=0xd7,
		// the pair H16(0xeb) would compute if the junk byte were ever treated as a real index.
		c = eol(0xE28D);
		criterion("ID4", !fieldKnownIn(c, "r7") && !c.contains("r6=0xd6") && !c.contains("r7=0xd7"),
			"Even's H16 call at e28d leaves r7 (and the H16-derived pair) unknown, no " +
				"junk-derived r6=0xd6/r7=0xd7: \"" + c + "\"");

		// ID5: a CONGRUENT bank (r7=15, odd) that is nonetheless UNVERIFIED -- bank 15 is one
		// of the two EXEMPT top banks, so its junk byte ($F1, rcransom's own) did not veto the
		// offset, but an exempt bank enters `verified` only when its byte happens to agree, and
		// this one's does not. The coverage check must refuse even though low-bit congruence
		// alone would pass; never a confident pair computed by H16 from the junk byte.
		c = eol(0xE2CD);
		criterion("ID5", !fieldKnownIn(c, "r7"),
			"Exempt's H16 call at e2cd (r7=15, exempt and unverified) leaves r7 unknown: \"" +
				c + "\"");

		// ID6: r7 genuinely OPAQUE (an indexed load from an unresolvable address) before the
		// mirror is even read -- the original, engine-wide reason to refuse, with a warning
		// live at the H16 call site (the unresolvable-argument warning; the opaque commit at
		// e30a itself carries no warning of its own -- r7 there is merely unknown, not a call
		// whose argument could not be recovered).
		c = eol(0xE310);
		criterion("ID6", !fieldKnownIn(c, "r7") && hasWarningBookmark(0xE310),
			"Unknown's H16 call at e310 leaves r7 unknown, warning live at the call site: \"" +
				c + "\"");

		// ID7: the derivation itself. A label bank_id_bff0 at $BFF0 (WA000's base) with an EOL
		// comment naming ROM_IDENTIFYING and the non-identity encoding (matched loosely against
		// "bank-1", since the exact wording is IdentifyingEncoding.describe()'s to choose).
		boolean hasLabel = hasSymbol(0xBFF0, "bank_id_bff0");
		String bffComment = eol(0xBFF0);
		criterion("ID7", hasLabel && bffComment.contains("bank mirror:") &&
			bffComment.contains("ROM_IDENTIFYING") && bffComment.contains("bank-1"),
			"bank_id_bff0 label=" + hasLabel + " eol=\"" + bffComment + "\"");

		// ID8: no bank_id_ label exists at any OTHER address -- in particular not at offset 0
		// (broken by the RTS targets) and not at any of the junk-byte offsets. bank_id_9ff0 is
		// allowed (grm-mej.18): RESET locks prg_mode 0, so the mode-0 W8000 window is
		// content-scanned too, and it maps the same 8K images through R6 -- $9FF0 is the very
		// same identity byte (bank offset $1FF0) as $BFF0, read through the other window.
		boolean extraLabel = false;
		String extraLabelDetail = "";
		for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(false)) {
			if (sym.getName().startsWith("bank_id_") && !"bank_id_bff0".equals(sym.getName()) &&
				!"bank_id_9ff0".equals(sym.getName())) {
				extraLabel = true;
				extraLabelDetail = sym.getName() + "@" + sym.getAddress();
				break;
			}
		}
		criterion("ID8", !extraLabel, "no bank_id_ label anywhere else: " + extraLabelDetail);
	}

	// ------------------------------------------------------------------
	// nesnmitest.nes criteria (interrupt-entry bank state, bead grm-913)
	// ------------------------------------------------------------------

	/**
	 * See {@code mknesbanktest.py}'s {@code make_prg_nmi()} for the full listing. The claim
	 * under test: an NMI/IRQ handler entry must NOT be seeded with {@code banking.initial_state}
	 * fully known, because an interrupt fires from arbitrary mainline context and leaves the
	 * interrupted code's bank live on entry.
	 * <p>
	 * IRQ1 is the control and IRQ2 is the fix, and neither is meaningful without the other. Both
	 * sites are the same instruction pair -- read the write-through shadow $42 back, re-commit
	 * it to a latch -- differing only in which entry they are reached from. IRQ1 (RESET path, bank
	 * genuinely known from flow) must still resolve; IRQ2 (interrupt path) must not. A change that
	 * weakened every entry, or that broke shadow read-back outright, passes IRQ2 and fails IRQ1.
	 * <p>
	 * IRQ3 pins the loader-side half against the shape that made this fixture necessary: every
	 * OTHER NES fixture here points NMI and IRQ at the same bare-RTI stub as each other, so a
	 * handler that is a distinct function with real code in it is a thing only this fixture has.
	 */
	protected void checkNesNmitest() {
		// IRQ1 (CONTROL): the RESET-path read-back at c010 still resolves. The bank is known
		// here by FLOW -- c00b latched 1 -- not by the entry seed, so weakening interrupt
		// entries must leave it untouched.
		String c = eol(0xC010);
		criterion("IRQ1", c.contains("bank -> ") && c.contains("1") && !c.contains("?"),
			"CONTROL: RESET-path shadow read-back still resolves bank 1 at c010: \"" + c + "\"");

		// IRQ2 (THE FIX): the same read-back inside the NMI/IRQ handler must claim no bank.
		// Pre-grm-913 this read "bank -> 0", inheriting the entry seed's false confidence --
		// the megaman d571 / wizwarr ffa6 defect, in miniature.
		c = eol(0xC022);
		criterion("IRQ2", !c.contains("bank -> "),
			"interrupt-exit restore at c022 claims NO bank (entry state is unknown): \"" +
				c + "\"");

		// IRQ3: the handler really is its own function reached only through the vectors -- i.e.
		// the fixture exercises an interrupt entry rather than ordinary mainline code.
		criterion("IRQ3", hasFunctionAt(0xC020) && !hasFunctionAt(0xC022),
			"NMI/IRQ handler is a function entry at c020 (and c022 is inside it, not an " +
				"entry of its own)");
	}

	// ------------------------------------------------------------------
	// nesforktest.nes / nesforkhometest.nes / nesforkbudgettest.nes criteria (path forking,
	// bead grm-wul; nesforkhometest's survival-rule criteria are bead grm-bfb)
	// ------------------------------------------------------------------

	/**
	 * See {@code mknesbanktest.py}'s {@code make_prg_fork()}. Two constants (X = 1 / X = 2)
	 * merge at c008 BEFORE the latch write there. Single-valued dataflow folds that merge to
	 * unknown; path forking must resolve BOTH arms, annotate both, and retarget every reference
	 * downstream of the switch to both banks -- the first arm's reference primary, the second's
	 * secondary.
	 */
	protected void checkNesForktest() {
		// F1: the merge site annotates both arms, in arm order, with the fork vocabulary.
		String c = eol(0xC008);
		criterion("F1", c.contains("bank -> 1 (bank=1) | 2 (bank=2)") &&
			c.contains("[path fork: 2 arms]"),
			"merge site c008 annotates both arms: \"" + c + "\"");

		// F2: no warning at the merge site -- it RESOLVED, to two values.
		criterion("F2", warningBookmarkText(0xC008).isEmpty(),
			"no WARNING at the forked merge site c008 (got: \"" + warningBookmarkText(0xC008) + "\")");

		// F3/F4: the JSR after the switch reaches BOTH overlays, bank 1 primary.
		Reference j1 = findOverlayRef(0xC00B, "PRG_LO_B1", 0x8010);
		Reference j2 = findOverlayRef(0xC00B, "PRG_LO_B2", 0x8010);
		criterion("F3", j1 != null && j1.isPrimary() && j1.getReferenceType().isCall(),
			"JSR at c00b retargeted to PRG_LO_B1::8010 as the primary call: " + describe(j1));
		criterion("F4", j2 != null && !j2.isPrimary() && j2.getReferenceType().isCall(),
			"JSR at c00b ALSO retargeted to PRG_LO_B2::8010 (secondary): " + describe(j2));

		// F5: both call targets were disassembled and made functions -- the retarget kicked
		// analysis in each overlay, not only the primary one.
		criterion("F5", hasInstructionAt("PRG_LO_B1", 0x8010) && hasInstructionAt("PRG_LO_B2", 0x8010),
			"the forked JSR's target is code in BOTH overlays");

		// F6/F7: the data read after the switch likewise reaches both banks.
		Reference d1 = findOverlayRef(0xC00E, "PRG_LO_B1", 0x8020);
		Reference d2 = findOverlayRef(0xC00E, "PRG_LO_B2", 0x8020);
		criterion("F6", d1 != null && d1.isPrimary(),
			"LDA at c00e retargeted to PRG_LO_B1::8020 (primary): " + describe(d1));
		criterion("F7", d2 != null && !d2.isPrimary(),
			"LDA at c00e ALSO retargeted to PRG_LO_B2::8020 (secondary): " + describe(d2));

		// F8: exactly two overlay references per site -- the fork carried two states, not more.
		criterion("F8", overlayRefCount(0xC00B) == 2 && overlayRefCount(0xC00E) == 2,
			"exactly two overlay references at c00b and c00e (got " + overlayRefCount(0xC00B) +
				"/" + overlayRefCount(0xC00E) + ")");

		// F9 (grm-bfb): BOTH arms resolved away from home (bank 0), so the stock base-space
		// refs at both sites are retired -- retirement is per site across all arms, not per
		// arm. The complementary case, one arm resolving TO home so the base ref must stay,
		// is nesforkhometest's H-criteria.
		criterion("F9", baseRefCount(0xC00B, 0x8010) == 0 && baseRefCount(0xC00E, 0x8020) == 0,
			"no base-space refs remain at c00b/c00e once both arms retargeted (got " +
				baseRefCount(0xC00B, 0x8010) + "/" + baseRefCount(0xC00E, 0x8020) + ")");
	}

	/**
	 * See {@code mknesbanktest.py}'s {@code make_prg_intrawin()} (bead grm-fj4m). Base-space
	 * window code at $8000 switches itself to bank 2 and then calls $8010 INSIDE its own window.
	 * grm-bfb keeps that call's base-space reference beside the overlay one, so the helper
	 * lookup used to see the HOME copy of $8010 (a helper selecting bank 1) even though the
	 * pinned bank 2's copy (a bare RTS) is what runs. Resolved through the overlay the call has
	 * no bank effect, so the read after it stays in bank 2.
	 */
	protected void checkNesIntrawintest() {
		// W1: the intra-window call keeps its base reference (grm-bfb) AND gains the overlay one.
		Reference j2 = findOverlayRef(0x8005, "PRG_LO_B2", 0x8010);
		criterion("W1", baseRefCount(0x8005, 0x8010) == 1 && j2 != null && j2.getReferenceType().isCall(),
			"JSR at 8005 keeps base::8010 and is retargeted to PRG_LO_B2::8010: " + describe(j2));

		// W2: the bank-2 copy of the callee was disassembled (the precondition for resolving it).
		criterion("W2", hasInstructionAt("PRG_LO_B2", 0x8010),
			"the pinned bank's copy of the callee is code");

		// W3 (the point): the read after the call reaches bank 2 -- the overlay callee is no
		// helper. The old base-space lookup says bank 1 and never produces this reference.
		Reference d2 = findOverlayRef(0x8008, "PRG_LO_B2", 0x8020);
		criterion("W3", d2 != null,
			"LDA at 8008 reaches PRG_LO_B2::8020 (the pinned bank, overlay callee is no helper): " +
				describe(d2));

		// W5 (grm-if81): the FIRST round runs before the overlay callee exists as a function,
		// falls back to base (a bank-1 helper) and places PRG_LO_B1 references at 8008/800b. The
		// overlay-reference provenance record retracts them once a later round concludes bank 2.
		Reference d1 = findOverlayRef(0x8008, "PRG_LO_B1", 0x8020);
		Reference j1 = findOverlayRef(0x800b, "PRG_LO_B1", 0x800b);
		criterion("W5", d1 == null && j1 == null,
			"round one's stale PRG_LO_B1 references at 8008/800b are retracted: " +
				describe(d1) + " / " + describe(j1));

		// W4: the JSR carries no helper-derived bank comment -- the base callee's "via FUN_8010"
		// claim is wrong at this site and the provenance sweep retracts the first round's copy.
		String c = eol(0x8005);
		criterion("W4", !c.contains("via "),
			"JSR at 8005 carries no helper-derived bank comment: \"" + c + "\"");
	}

	/**
	 * See {@code mknesbanktest.py}'s {@code make_prg_forkhome()}. Same two-armed merge shape
	 * as {@code nesforktest}, but arm A selects the HOME bank (X = 0) instead of a second
	 * non-home constant. This pins grm-bfb's SURVIVAL rule: the stale base-space reference at
	 * a retargeted site is retired only when EVERY live arm resolved away from home. Here arm
	 * A resolves TO home, so the base ref at each site genuinely describes that arm's reality
	 * and must survive -- as the PRIMARY reference, since it was already there (and primary)
	 * for the un-forked home case, and the overlay ref path forking places for arm B is added
	 * with makePrimary=false.
	 */
	protected void checkNesForkHometest() {
		// H1: the merge site annotates both arms (home first, in arm order), with the fork
		// vocabulary.
		String c = eol(0xC008);
		criterion("H1", c.contains("bank -> 0 (bank=0) | 2 (bank=2)") &&
			c.contains("[path fork: 2 arms]"),
			"merge site c008 annotates both arms: \"" + c + "\"");

		// H2: no warning at the merge site -- it RESOLVED, to two values.
		criterion("H2", warningBookmarkText(0xC008).isEmpty(),
			"no WARNING at the forked merge site c008 (got: \"" + warningBookmarkText(0xC008) + "\")");

		// H3: the JSR after the switch reaches the non-home overlay, as a NON-primary call --
		// arm A (home) placed nothing, so it never had primacy to give up, and arm B's overlay
		// ref is added secondary per grm-wul's established convention.
		Reference j2 = findOverlayRef(0xC00B, "PRG_LO_B2", 0x8010);
		criterion("H3", j2 != null && !j2.isPrimary() && j2.getReferenceType().isCall(),
			"JSR at c00b retargeted to PRG_LO_B2::8010 as a secondary call: " + describe(j2));

		// H4 (grm-bfb): the base-space ref at c00b SURVIVES -- arm A resolves to home, so the
		// stock base-space reference is genuinely correct for that arm and must not be
		// retired. This is the criterion the fixture exists to pin.
		criterion("H4", baseRefCount(0xC00B, 0x8010) == 1,
			"base-space ref at c00b::8010 survives because arm A resolves to home (got " +
				baseRefCount(0xC00B, 0x8010) + ")");

		// H5: the surviving base ref is PRIMARY -- it was already there (and primary) for the
		// home case, and nothing about the fork should have displaced it.
		Reference baseJ = null;
		{
			Instruction instr = currentProgram.getListing().getInstructionAt(addr(0xC00B));
			AddressSpace base = currentProgram.getAddressFactory().getDefaultAddressSpace();
			if (instr != null) {
				for (Reference r : instr.getReferencesFrom()) {
					if (r.getToAddress().getAddressSpace().equals(base) &&
						r.getToAddress().getOffset() == 0x8010) {
						baseJ = r;
						break;
					}
				}
			}
		}
		criterion("H5", baseJ != null && baseJ.isPrimary(),
			"surviving base ref at c00b is primary: " + describe(baseJ));

		// H6: exactly one overlay reference per site -- only arm B (non-home) placed one.
		criterion("H6", overlayRefCount(0xC00B) == 1 && overlayRefCount(0xC00E) == 1,
			"exactly one overlay reference at c00b and c00e (got " + overlayRefCount(0xC00B) +
				"/" + overlayRefCount(0xC00E) + ")");

		// H7: the data read's base ref survives too, and its overlay ref to bank 2 is
		// secondary, mirroring H3/H4 for the second site.
		criterion("H7a", baseRefCount(0xC00E, 0x8020) == 1,
			"base-space ref at c00e::8020 survives (got " + baseRefCount(0xC00E, 0x8020) + ")");
		Reference d2 = findOverlayRef(0xC00E, "PRG_LO_B2", 0x8020);
		criterion("H7b", d2 != null && !d2.isPrimary(),
			"LDA at c00e retargeted to PRG_LO_B2::8020 (secondary): " + describe(d2));
	}

	/**
	 * See {@code make_prg_forkbudget()}: the same merge with FIVE arms, one over
	 * {@code BankDataflowEngine.MAX_LIVE_FORKS_PER_BLOCK}. Every arm resolves, the fork is
	 * denied, and the site must say so in the {@code MULTI_VALUED_AT_MERGE} vocabulary -- a
	 * WARNING (ours), naming the count and the constants -- while retargeting nothing.
	 */
	protected void checkNesForkBudgettest() {
		String w = warningBookmarkText(0xC026);
		criterion("B1", w != null && w.contains("one of 5 constants") &&
			w.contains("{1, 2, 3, 4, 5}") && w.contains("MULTI_VALUED_AT_MERGE"),
			"merge site c026 carries the budget-exhausted WARNING naming 5 arms and their " +
				"values: \"" + w + "\"");
		criterion("B2", w != null && w.contains("4 live forks per block") &&
			w.contains("16 per function"),
			"the warning names both fork caps: \"" + w + "\"");
		criterion("B3", !eol(0xC026).contains("bank -> "),
			"no bank comment at the denied merge site c026: \"" + eol(0xC026) + "\"");
		criterion("B4", overlayRefCount(0xC029) == 0,
			"the JSR after the denied merge is NOT retargeted (bank unknown -> home): " +
				overlayRefCount(0xC029) + " overlay ref(s)");
	}

	// ------------------------------------------------------------------
	// nesmodetest.nes criteria (memory.layouts[] mode-varying windows, bead grm-qvi)
	// ------------------------------------------------------------------

	// ------------------------------------------------------------------
	// nesnromsubtest.nes criteria (sub-window PRG image mirrors to fill its window,
	// bead grm-7e5o)
	// ------------------------------------------------------------------

	/**
	 * An 8 KiB NROM PRG is smaller than either of the board's 16 KiB windows, so the chip's
	 * unconnected high address lines make it appear FOUR times across $8000-$FFFF. Before
	 * grm-7e5o both windows were skipped and the import produced no memory blocks at all.
	 * <p>
	 * The criteria are ordered from cheapest to strongest: the blocks exist (X1/X2), they
	 * carry the right BYTES rather than merely the right extents (X3 -- the thing the
	 * real-ROM dump format cannot see, cf. grm-9nxj.19), and the mirror is live enough to
	 * disassemble and to read the vector table through (X4/X5). Every executable address in
	 * this fixture deliberately lives in a mirror, so X4/X5 cannot pass by accident.
	 */
	protected void checkNesNromSubtest() {
		Memory mem = currentProgram.getMemory();

		// X1: each window's FIRST copy is the real, FileBytes-backed block, named for the
		// window and 8 KiB long -- the image size, not the 16 KiB window size.
		MemoryBlock prgLo = mem.getBlock("PRG_LO");
		MemoryBlock prgHi = mem.getBlock("PRG_HI");
		criterion("X1a", prgLo != null && !prgLo.isOverlay() && prgLo.isInitialized() &&
			prgLo.getSize() == 0x2000 && prgLo.getStart().getOffset() == 0x8000,
			"PRG_LO is an 8 KiB initialized base-space block at $8000: " + describeBlock(prgLo));
		criterion("X1b", prgHi != null && !prgHi.isOverlay() && prgHi.isInitialized() &&
			prgHi.getSize() == 0x2000 && prgHi.getStart().getOffset() == 0xC000,
			"PRG_HI is an 8 KiB initialized base-space block at $C000: " + describeBlock(prgHi));

		// X2: the second copy of each window is a byte-mapped view of the first. Byte-mapped
		// blocks report isInitialized() == false -- their bytes belong to the block they map
		// onto -- which is exactly what distinguishes them from a duplicated slice here.
		MemoryBlock loMirror = mem.getBlock("PRG_LO_mirror_a000");
		MemoryBlock hiMirror = mem.getBlock("PRG_HI_mirror_e000");
		criterion("X2a", loMirror != null && !loMirror.isInitialized() &&
			loMirror.getSize() == 0x2000 && loMirror.getStart().getOffset() == 0xA000,
			"PRG_LO_mirror_a000 is an 8 KiB byte-mapped block at $A000: " +
				describeBlock(loMirror));
		criterion("X2b", hiMirror != null && !hiMirror.isInitialized() &&
			hiMirror.getSize() == 0x2000 && hiMirror.getStart().getOffset() == 0xE000,
			"PRG_HI_mirror_e000 is an 8 KiB byte-mapped block at $E000: " +
				describeBlock(hiMirror));

		// X3: the BYTES, at both markers, at all four addresses each. Extents alone would pass
		// with the mirrors backed by the wrong file offsets, which is the failure mode this
		// whole fixture exists to exclude. Read through addresses, not blocks: a byte-mapped
		// block cannot be read via readByte().
		boolean lda = true;
		boolean marker = true;
		StringBuilder seen = new StringBuilder();
		for (long base = 0x8000; base < 0x10000; base += 0x2000) {
			int a = readByteAt(base);
			int m = readByteAt(base + 0x1000);
			lda &= a == 0xA9;
			marker &= m == 0xC3;
			seen.append(" $").append(Long.toHexString(base)).append("=").append(hx(a))
					.append("/$").append(Long.toHexString(base + 0x1000)).append("=")
					.append(hx(m));
		}
		criterion("X3", lda && marker,
			"the 8 KiB image reads back at all four copies (expect a9/c3 each):" + seen);

		// X4: RESET's target $E000 is inside PRG_HI_mirror_e000, so a labelled, disassembled
		// entry point there proves the loader read the vector table through the mirror (its
		// slots at $FFFA-$FFFF are themselves only reachable modulo the image) AND that a
		// byte-mapped mirror is disassemblable, the property SnesRomLoader relies on too.
		Instruction reset = currentProgram.getListing().getInstructionAt(addr(0xE000));
		criterion("X4", reset != null && reset.getMnemonicString().equals("LDA"),
			"instruction disassembled at $e000 inside the mirror: " +
				(reset == null ? "<none>" : reset.toString()));

		// X5: the vector label itself, which only exists if fileOffsetOf() reduced $FFFC
		// modulo the image rather than running off the end of it.
		criterion("X5", hasSymbol(0xE000, "RESET"),
			"RESET label at $e000, read from the vector slot at $fffc through the mirror");
	}

	protected void checkNesModetest() {
		// F1: RESET's JSR $8000 at $C005, taken with bank=1 in effect (mode still 0/home),
		// retargets into the home layout's non-home-bank overlay W8000_M0_B1.
		Reference r = findOverlayRef(0xC005, "W8000_M0_B1", 0x8000);
		criterionPrimaryCall("F1", r,
			"JSR $8000 (mode0/bank1) retargeted to W8000_M0_B1 overlay, primary: ");

		// F2: RESET's JMP $8040 at $C00D, taken after the mode latch write (prg_mode -> 1),
		// retargets into the mode-1 FIXED instance of W8000 (W8000_M1) -- proves the mode
		// field alone (no bank field) drives a fixed-window instance's retargeting. The
		// reference type is CALL, not JUMP: the W8000_M1 routine's only exit is its own
		// self-loop (JMP $8048, never RTS), so Ghidra's stock non-returning-function
		// analysis marks FUN_W8000_M1__8040 non-returning and reclassifies this tail-JMP
		// as a call terminator -- a default Ghidra behavior orthogonal to bank retargeting,
		// evidenced by the "via FUN_W8000_M1__8040" wording this also adds to c00d's
		// bank-switch comment (see the F4 checks below, which do not depend on it).
		r = findOverlayRef(0xC00D, "W8000_M1", 0x8040);
		criterionPrimaryCall("F2", r,
			"JMP $8040 (mode1) retargeted to W8000_M1 overlay (as a CALL -- Ghidra's " +
				"non-returning-function reclassification), primary: ");

		// F3: the JSR $C030 at (overlay-relative) 8045 -- physically inside the W8000_M1
		// overlay -- retargets into WC000_M1_B2. This is the load-bearing criterion: mode=1
		// is known only because clampToResidence pins it from the instruction's own overlay
		// (W8000_M1 exists only under prg_mode=1), and bank=2 comes from the latch write at
		// 8042 inside that same overlay; the two-level mode -> window -> bank lookup then
		// finds WC000's mode-1 switchable instance at bank 2. Structurally impossible before
		// residence-clamping understood mode-qualified overlays.
		r = findOverlayRefFrom(overlayAddr("W8000_M1", 0x8045), "WC000_M1_B2", 0xC030);
		criterionPrimaryCall("F3", r,
			"JSR $C030 in W8000_M1 (mode1/bank2) retargeted to WC000_M1_B2 overlay, primary: ");

		// F4: bank-switch comments at the three latch-write sites. Each write is recognized
		// by a mechanism that owns only ONE of the two state fields (bank / prg_mode). The
		// BANK writes now also show prg_mode, because it is the board's layout-mode field and
		// decides which window the bank feeds (grm-dos9.3): fully known, no "?". Before that
		// bead these rendered prg_mode as "assumed from initial" -- and at 8042, inside the
		// mode-1 overlay, that assumption was WRONG (it read prg_mode=0). The MODE write at
		// c00a is unchanged: bank is not the layout field, so it stays "assumed from initial".
		String c = eol(0xC002);
		criterionEolKnown("F4:c002", c, "bank=1,prg_mode=0",
			"bank latch -> 1, prg_mode 0 known from the reset seed, at c002: \"");
		c = eol(0xC00A);
		criterion("F4:c00a", c.contains("prg_mode=1") && c.contains("known: prg_mode"),
			"mode latch -> 1 (prg_mode field known, bank assumed) at c00a: \"" + c + "\"");
		c = eol("W8000_M1", 0x8042);
		criterionEolKnown("F4:8042", c, "bank=2,prg_mode=1",
			"bank latch -> 2 inside the mode-1 overlay, prg_mode 1 known, at 8042: \"");

		// F5: the phase-2 disassembly cascade actually produced instructions at all three
		// overlay targets reached above.
		criterion("F5:W8000_M0_B1_8000", hasInstructionAt("W8000_M0_B1", 0x8000),
			"instruction exists at W8000_M0_B1::8000");
		criterion("F5:W8000_M1_8040", hasInstructionAt("W8000_M1", 0x8040),
			"instruction exists at W8000_M1::8040");
		criterion("F5:WC000_M1_B2_C030", hasInstructionAt("WC000_M1_B2", 0xC030),
			"instruction exists at WC000_M1_B2::C030");
	}

	// ------------------------------------------------------------------
	// nesmmc3test.nes criteria (SelectDataBankSwitchStrategy, bead grm-6a7.1)
	// ------------------------------------------------------------------

	protected void checkNesMmc3test() {
		// F1: RESET's JSR $8000 at $E00A, with r6=2/prg_mode=0 in effect (just latched by
		// the select=6/data=2 write pair), retargets into the mode-0 switchable instance's
		// non-home-bank overlay W8000_M0_B2.
		Reference r = findOverlayRef(0xE00A, "W8000_M0_B2", 0x8000);
		criterionPrimaryCall("F1", r,
			"JSR $8000 (mode0/r6=2) retargeted to W8000_M0_B2 overlay, primary: ");

		// F2: RESET's second JSR $8000 at $E017 -- issued AFTER a select=0 (CHR)/data=$AA
		// write pair in between -- retargets to the SAME W8000_M0_B2 overlay, proving r6
		// SURVIVED the CHR write (SelectDataBankSwitchStrategy's no-poison contract).
		r = findOverlayRef(0xE017, "W8000_M0_B2", 0x8000);
		criterionPrimaryCall("F2", r,
			"JSR $8000 after a CHR-register write still retargets to W8000_M0_B2 (r6 " +
				"survived the CHR write, no-poison contract holds): ");

		// F3: RESET's JSR $A000 at $E024, with r7=3 in effect, retargets into WA000_B3 --
		// WA000 is INVARIANT-HOISTED (identical across both prg_mode layouts), so the
		// overlay name carries no _M qualifier at all.
		r = findOverlayRef(0xE024, "WA000_B3", 0xA000);
		criterionPrimaryCall("F3", r,
			"JSR $A000 (r7=3) retargeted to hoisted WA000_B3 overlay (no _M qualifier), " +
				"primary: ");

		// F4: RESET's JSR $C000 at $E02C, issued AFTER the mode-flip write (select=6,
		// prg_mode=1, co-emitted from ONE byte), retargets into WC000's mode-1 switchable
		// instance at the still-known r6=2 -- proves the mode bit and the select index
		// were correctly split out of the same recovered byte, and that r6 survived every
		// intervening write (including the CHR write at $E014).
		r = findOverlayRef(0xE02C, "WC000_M1_B2", 0xC000);
		criterionPrimaryCall("F4", r,
			"JSR $C000 after the mode flip (prg_mode=1, r6=2) retargeted to WC000_M1_B2 " +
				"overlay, primary: ");

		// F5: bank-switch comments exist at the mechanism write sites -- the two select
		// writes that flip prg_mode (home 0 stays known throughout, then the flip to 1)
		// and the two data writes that set r6/r7.
		String c = eol(0xE002);
		criterion("F5:e002", c.contains("bank ->"),
			"bank-switch comment at the select=6 write (e002): \"" + c + "\"");
		c = eol(0xE007);
		criterion("F5:e007", c.contains("bank ->"),
			"bank-switch comment at the r6=2 data write (e007): \"" + c + "\"");
		c = eol(0xE021);
		criterion("F5:e021", c.contains("bank ->"),
			"bank-switch comment at the r7=3 data write (e021): \"" + c + "\"");
		c = eol(0xE029);
		criterion("F5:e029", c.contains("bank ->") && c.contains("prg_mode=1"),
			"bank-switch comment at the mode-flip select write (e029) shows prg_mode=1: \"" +
				c + "\"");

		// F6: the phase-2 disassembly cascade actually produced instructions at all three
		// overlay targets reached above (the dual-mapped bank-2 RTS routine, referenced from
		// two different overlay names, plus the bank-3 routine).
		criterion("F6:W8000_M0_B2_8000", hasInstructionAt("W8000_M0_B2", 0x8000),
			"instruction exists at W8000_M0_B2::8000");
		criterion("F6:WC000_M1_B2_C000", hasInstructionAt("WC000_M1_B2", 0xC000),
			"instruction exists at WC000_M1_B2::C000");
		criterion("F6:WA000_B3_A000", hasInstructionAt("WA000_B3", 0xA000),
			"instruction exists at WA000_B3::A000");
	}

	// ------------------------------------------------------------------
	// nesmmc3test2.nes criteria (function-level requires-on-entry, bead grm-6a7.2)
	// ------------------------------------------------------------------

	protected void checkNesMmc3test2() {
		// G1: CallerA establishes select=6 itself before JSR $E140 (H, the bare data-write
		// helper) -- requiresOnEntry(H) is satisfied at that call site, so no violation
		// WARNING bookmark lands on CallerA's JSR at $E107.
		criterion("G1", !hasWarningBookmark(0xE107),
			"no requirement-violation WARNING at CallerA's JSR $E140 (E107) -- select " +
				"known there");

		// G2: CallerB poisons select via an unresolvable load right before its own JSR
		// $E140 at $E128, so the call's OWN argument recovery comes up empty and the
		// HELPER-ARGUMENT warning fires there.
		//
		// READ THE NEXT PARAGRAPH BEFORE "FIXING" THIS TO SAY "requirement violated"
		// (bead grm-mlp2). Both diagnostics are live at this site and only one can ever
		// appear: the helper-argument loop bookmarks E128 and adds it to `alreadyWarned`
		// (BoardBankAnalyzer.java:392), and the violation scan then skips any site in that
		// set (BoardBankAnalyzer.java:3703). The helper-argument warning therefore always
		// wins here, and has since grm-snu added the routed-deposit helper path. From then
		// until grm-mlp2 this criterion read `hasWarningBookmark(0xE128)` with a comment
		// claiming it proved the requirement violation -- a presence-only assertion over a
		// site that can carry several kinds of warning, which is how it decayed into a
		// tautology passing on an unrelated diagnostic. Assert TEXT, not presence.
		//
		// THERE IS NO POSITIVE TEST FOR THE REQUIREMENT-VIOLATION DIAGNOSTIC IN THIS
		// FIXTURE. Measured while fixing grm-mlp2: SelectDataBankSwitchStrategy returned false
		// from effectDependsOnPriorState() unconditionally and did not override the per-site
		// overload, so BoardBankAnalyzer's ownRequires gate never fired at any select-data
		// site; with ownRequires empty board-wide the propagation had nothing to carry, so NO
		// call site on an MMC3 board could hold a violation bookmark -- which is exactly what
		// G11 asserts. Since grm-sen5 the strategy DOES override the per-site form (a site
		// that consulted a bank mirror and came up empty), but this fixture has no mirrors, so
		// the probe short-circuits and G11's claim stands here unchanged. The positive MMC3
		// test lives on nesmmc3mirrortest (MM12/MM13), alongside nesmirrortest's M9/M10; see
		// grm-mlp2 for the three-level caller/worker/leaf chain that gets a call site past
		// the alreadyWarned interlock.
		criterion("G2",
			warningBookmarkText(0xE128).contains("bank argument could not be recovered"),
			"helper-argument WARNING (not the requirement violation -- see comment) at " +
				"CallerB's JSR $E140 (E128) -- select unknown there: warning=\"" +
				warningBookmarkText(0xE128) + "\"");

		// G3: the poisoning load/select-write pair itself does not ALSO trip the
		// pre-existing "genuinely undeterminable switch value" WARNING path (that would
		// indicate the new violation warning is riding on/duplicating the old one instead
		// of being independently derived) -- SelectDataBankSwitchStrategy's select write
		// still recovers a byte-shaped (if unknown) deposit, not a null computeSwitch, so
		// $E123 itself gets no bookmark; the interesting one is purely at the call site.
		criterion("G3", !hasWarningBookmark(0xE123),
			"no WARNING at the select write itself (E123) -- only the call site (E128) " +
				"is flagged, confirming the new warning is call-site-specific, not a " +
				"restatement of an existing switch-site warning");

		// G4 (bead grm-snu): CallerA's call to the bare data-write helper H at $E107 now
		// routes through SelectDataBankSwitchStrategy's own depositHelperArgument override
		// instead of the interface default -- select=6 was tracked at the call site, so
		// the data byte (2) lands in r6 alone, leaving select/prg_mode untouched. The
		// resulting comment must be FULLY known (no '?'): select=6, r6=2.
		String c4 = eol(0xE107);
		criterion("G4", c4.contains("select=6") && c4.contains("r6=2") && !c4.contains("?"),
			"routed deposit at CallerA's JSR (E107) fully known, select=6/r6=2: \"" + c4 +
				"\"");

		// G5 (bead grm-snu): CallerB's call at $E128 has select genuinely unknown at the
		// call site, so the routed deposit honestly poisons r6+r7 ONLY -- it must NOT
		// fabricate a known select value out of the data byte the way the pre-fix DEFAULT
		// deposit did (the old bug: data byte 3 misread as select=3).
		String c5 = eol(0xE128);
		criterion("G5", !c5.contains("select=3"),
			"routed deposit at CallerB's JSR (E128) does not fabricate select from the " +
				"data byte: \"" + c5 + "\"");

		// G6 (bead grm-snu): CallerC establishes select=0 (CHR, untracked) before calling
		// H -- select IS known (no requirement violation -> no WARNING), but the routed
		// deposit's ownedMask is 0 (verified no-op on every tracked field), so the call
		// site also gets NO bank-> comment at all.
		criterion("G6", !hasWarningBookmark(0xE167) && eol(0xE167).isEmpty(),
			"CallerC's JSR (E167, untracked CHR select) is a verified no-op -- no " +
				"WARNING and no bank-> comment");

		// G7 (bead grm-snu): CallerD mirrors CallerA but selects R7 instead of R6,
		// proving the routing genuinely reads the tracked select value rather than being
		// hardcoded to one target -- data byte 4 lands in r7, select=7/prg_mode=0 known.
		String c7 = eol(0xE187);
		criterion("G7", c7.contains("select=7") && c7.contains("r7=4") && !c7.contains("?"),
			"routed deposit at CallerD's JSR (E187) fully known, select=7/r7=4: \"" + c7 +
				"\"");

		// G8 (bead grm-67g): CallerE ($E220) is the inbound-argument-cell POSITIVE case --
		// smb3's FUN_ffc2 transcribed byte for byte as H2 ($E210: LDA #$47 / STA $0721 /
		// STA $8000 / LDA $0720 / STA $8001). CallerE establishes select=7/prg_mode=1
		// itself (LDA #$47 / STA $8000, the fixture idiom) before storing $1B (27) to
		// $0720 immediately before the JSR, so HelperArgumentRecovery#inboundArgumentCell
		// proves H2 consumes a cell it never writes, and
		// LocalStoreForwarding#callerCellValue reads CallerE's own $1B at the call site.
		// Right before the JSR, CallerE loads A with a DECOY ($3F/63) distinct from the
		// cell's value -- present so that r7=3 in the comment would expose the strategy
		// (wrongly) register-sourcing the bank from A, while r7=5 proves it is genuinely
		// cell-sourced. Expect r7=5 (not the decoy's 3, and not r6), fully known, no
		// warning at the JSR $E210 (E22C).
		String c8 = eol(0xE22C);
		criterion("G8", !hasWarningBookmark(0xE22C) && c8.contains("select=7") &&
			c8.contains("prg_mode=1") && c8.contains("r7=5") && !c8.contains("r7=3") &&
			!c8.contains("?"),
			"inbound-argument-cell call resolves select=7/prg_mode=1/r7=5 (never the " +
				"decoy r7=3 left in A) via H2's caller-side $0720, no warning, at " +
				"CallerE's JSR (E22C): \"" + c8 + "\" warning=\"" +
				warningBookmarkText(0xE22C) + "\"");

		// G9 (bead grm-67g): CallerF ($E240) is the intervening-call CONTROL -- establishes
		// select=7/prg_mode=1 itself like CallerE, then is otherwise identical except a JSR
		// to a harmless subroutine ($E230) sits between the store to $0720 and the JSR to
		// H2. A JSR may write anywhere (LocalStoreForwarding#forwardedStoreValue's call-
		// abort), so the caller-side forward scan cannot attribute the $0720 store across
		// it. This is the control that proves G8 is not merely pattern-matching H2's shape:
		// without a provable store reaching the call, the ONLY sound answer is a warning,
		// and specifically not a confident r7=5 that CallerE's OWN value happens to equal.
		criterion("G9", hasWarningBookmark(0xE24D) && !eol(0xE24D).contains("r7=5"),
			"an intervening call between the store and the JSR to H2 blocks caller-side " +
				"attribution -- warning, no r7=5 claim, at CallerF's JSR (E24D): warning=" +
				hasWarningBookmark(0xE24D) + " comment=\"" + eol(0xE24D) + "\"");

		// G10 (bead grm-67g): H3/CallerG ($E260/$E280) is the SELF-WRITTEN-CELL control --
		// H3 is byte-identical to H2 except its decoy write lands on $0720 ITSELF (not the
		// off-by-one $0721), so H3 both writes and reads the same cell. CallerG establishes
		// select=7/prg_mode=1 itself (like CallerE/F) and otherwise mirrors CallerE's exact
		// caller-side shape (LDA #$1B / STA $0720 / JSR), so the ONLY variable between G8
		// and this criterion is H2 vs. H3, which is what makes any difference in outcome
		// attributable to the self-write rather than to the caller.
		//
		// WHAT MUST NOT HAPPEN IS r7=5, NOT r7=7. H3 really does put $47 into $8001, so
		// r7 = $47 & $3F = 7 is the TRUTH here and reporting it -- fully known, no warning --
		// is correct; HelperArgumentRecovery#valueSuppliedInsideHelper recovers it by forwarding
		// H3's own STA $0720 to its own LDA $0720. CallerG's $1B is a DEAD store, and
		// attributing it would ship r7=5: a confident wrong bank sourced from a caller whose
		// byte the helper threw away. That is precisely what inboundArgumentCell's `written`
		// set exists to prevent, and G8 vs. G10 is the A/B pair that proves it -- same caller
		// bytes, same call shape, 5 where the cell is inbound and 7 where it is not. Note 5
		// is a REAL bank in this 8-bank image, so a wrong attribution here would be ANNOTATED
		// rather than suppressed by the out-of-range value-recovery guard -- which is what
		// makes this a control and not a formality (bead grm-hum).
		//
		// Note this is a DIFFERENT defect from the one that shipped: smb3's r7=7 was wrong
		// because it was read at the $8000 SELECT site instead of the $8001 bank site, which
		// BankSwitchStrategy#suppliesHelperValueAtFirstSite fixed in increment 1. Reading a
		// helper's own value is not the error; reading it from the wrong site was.
		String c10 = eol(0xE28A);
		criterion("G10", !hasWarningBookmark(0xE28A) && c10.contains("r7=7") &&
			!c10.contains("r7=5") && !c10.contains("?"),
			"a helper that overwrites its own argument cell reports ITS OWN $47 (r7=7), not " +
				"the caller's dead $05 (r7=5), at CallerG's JSR (E28A): warning=" +
				hasWarningBookmark(0xE28A) + " comment=\"" + c10 + "\"");

		// ------------------------------------------------------------------
		// G11/G12 (bead grm-vgod): the MMC3 analogue of nesmirrortest's M8 guard.
		// ------------------------------------------------------------------

		// G11: THE GUARD. H4 ($E2A0) writes r6 from an opaque load (unrecoverable value)
		// and then r7 from a plain immediate. Worker ($E2D0) is an ordinary function that
		// reaches H4 by a call, and CallerH ($E2C0) calls Worker with r6 unknown on entry
		// -- CallerB poisoned it and nothing since re-established it. That two-step
		// topology is rcransom's own: all 12 real-ROM violations landed on calls to plain
		// functions reaching a failing switch, never on direct calls to the helper. Before
		// grm-vgod, SelectDataBankSwitchStrategy inherited effectDependsOnPriorState() ==
		// !cacheable() == true, so H4's FAILED r6 write declared a bank-known-on-entry
		// requirement it never had (knowing r6 on entry would not have helped -- the write
		// overwrites r6 regardless) and warned here. That is the same conflation grm-mej.2
		// sec 2d fixed on MemoryLatchBankSwitchStrategy, and it produced all 12 of the
		// requirement-violation warnings on the rcransom and smb2 real-ROM rows -- every
		// one of which named r6,r7 and none of which named select, the signature of the
		// mask being read off a field the write does not consume.
		criterion("G11", !warningBookmarkText(0xE2CB).contains("requirement violated"),
			"no spurious bank-state requirement violation at CallerH's JSR $E2D0 (E2CB), " +
				"whose callee's r6 write fails for want of a VALUE, not of entry state: " +
				"warning=\"" + warningBookmarkText(0xE2CB) + "\"");

		// G12: and load-bearing -- G11 must not pass merely because the site is masked.
		// annotateBankRequirementViolations skips any call site that already carries a
		// warning (alreadyWarned, BoardBankAnalyzer:3703), so a call site in the ordinary
		// "helper argument could not be recovered" path would satisfy G11 vacuously no
		// matter what the requirement derivation did -- which is exactly how CallerB's
		// $E128 stopped testing anything (grm-mlp2). Routing through Worker keeps this
		// call out of that path (the helper-argument warning lands on Worker's own JSR at
		// $E2D0 instead), so the site must carry NO warning at all; if a warning ever
		// appears here, G11 has stopped being a test and this says so. This is not
		// hypothetical: the first draft of this fixture had CallerH call H4 directly, and
		// G12 caught G11 passing vacuously on the helper-argument warning.
		criterion("G12", !hasWarningBookmark(0xE2CB),
			"CallerH's JSR (E2CB) carries no warning at all, so G11 is not passing " +
				"vacuously through the alreadyWarned mask: warning=\"" +
				warningBookmarkText(0xE2CB) + "\"");

		// G13 (bead grm-qd0u): THE HELPER'S OWN SELECT BEATS THE CALLER'S STALE ONE, and this
		// fixture discriminates the two by construction. At Worker's JSR $E2A0 (E2D0) the
		// TRACKED select is 6 -- CallerH wrote $06 to $8000 at E2C2 before calling -- while H4
		// establishes select=7 for itself (LDA #$07 / STA $8000 at E2AB/E2AD) on the
		// straight-line path into its own final data write at E2B2. Those route to DIFFERENT
		// registers, so the answer names which select was used:
		//   r7=2  -> H4's own select 7 won                     (correct)
		//   r6=2  -> the caller's stale select 6 was used      (the grm-qd0u defect)
		// smb3's FUN_ffc2 is the shipped instance of exactly this: its callers leave select at
		// 0 (CHR R0, UNTRACKED), so before grm-qd0u the deposit returned ownedMask = 0 -- a
		// "verified no-op" that silently discarded a fully recovered constant bank, with
		// neither annotation nor warning. Measured 172 such evaluations on that title against
		// 70 poisons and 12 correct resolutions.
		//
		// NOTE THIS REPLACED AN EARLIER G13 and why, because it looks like a weakened guard and
		// is not. That one asserted the helper-argument warning at E2D0 still EXISTED, as proof
		// G12 could not pass vacuously through the alreadyWarned mask. grm-qd0u legitimately
		// removed that warning -- E2D0 now resolves instead of warning -- so the premise is
		// simply no longer true here. G11's real proof was never G13: it is that G11 was
		// CONFIRMED to fail on the pre-grm-vgod strategy ("call to FUN_e2d0 requires r6 known
		// on entry"). G12 remains live as the detector if a warning ever returns to E2CB.
		String c13 = eol(0xE2D0);
		criterion("G13", c13.contains("r7=2") && !c13.contains("r6=2"),
			"H4's own select=7 routes its data write to r7, beating the caller's tracked " +
				"select=6 at Worker's JSR (E2D0): \"" + c13 + "\" warning=\"" +
				warningBookmarkText(0xE2D0) + "\"");

		// G14 (bead grm-qd0u): THE SHAPE THAT HAD NO SYNTHETIC COVERAGE AT ALL. H5 ($E300)
		// establishes its own constant select=6 then writes data $03; CallerJ ($E320) calls it
		// WITHOUT establishing any select of its own. That is what real smb3 callers of
		// FUN_ffc2 do, and it is exactly what the CallerE/F/G trio deliberately avoids -- each
		// of those writes select itself precisely because the pre-grm-qd0u deposit required it.
		// So this fixture could not previously express the shipped defect. Expect r6=3, fully
		// known, no warning.
		//
		// TOGETHER WITH G13 THIS COVERS BOTH PRE-FIX FAILURE BRANCHES, which is why both exist:
		// at E2D0 the caller's select was known-but-STALE (6, routing to the wrong register),
		// while here it is genuinely UNKNOWN, which pre-fix took the poison branch. smb3 shows
		// both (172 stale-untracked evaluations, 70 poisons).
		//
		// THE "?" IS CORRECT HERE, so this deliberately does NOT assert full knownness the way
		// G4/G7 do. A data-write deposit owns its TARGET FIELD ALONE -- never select/prg_mode,
		// which a data write cannot touch -- so those stay at the caller's own (here unknown)
		// value and the comment says so. Asserting no "?" would be asserting that the deposit
		// fabricates select knowledge it has no right to, which is the grm-snu defect G5 guards
		// against. r6=3 is the whole claim.
		String c14 = eol(0xE320);
		criterion("G14", !hasWarningBookmark(0xE320) && c14.contains("r6=3"),
			"a helper supplying its OWN select resolves for a caller that establishes none, " +
				"at CallerJ's JSR (E320): \"" + c14 + "\" warning=\"" +
				warningBookmarkText(0xE320) + "\"");

		// G15 (bead grm-qd0u): THE DECLINE CONTROL, and the one that matters most. H6 ($E340)
		// reaches its select write at $E34A by two paths carrying DIFFERENT constants ($06 and
		// $07), so neither "select is 6 on every path" nor "select is 7 on every path" holds.
		// selectSuppliedInsideHelper must abandon at that control-flow join and fall back to
		// the caller's in-state rather than pick whichever constant it meets walking backward.
		//
		// WHY THIS IS A CONTROL AND NOT A FORMALITY: select 6 vs 7 is the difference between
		// two DIFFERENT tracked registers, so an over-eager walk does not lose an annotation,
		// it ships a confident wrong bank -- the failure mode this analyzer treats as its
		// worst. H6's data byte $05 is a real bank in this 8-bank image, so a wrong claim
		// would be ANNOTATED rather than suppressed by the out-of-range value guard. Neither
		// r6=5 nor r7=5 may appear.
		String c15 = eol(0xE360);
		criterion("G15", !c15.contains("r6=5") && !c15.contains("r7=5"),
			"an ambiguous own-select (two paths, $06 vs $07) makes H6 decline rather than " +
				"pick, at CallerK's JSR (E360): \"" + c15 + "\" warning=\"" +
				warningBookmarkText(0xE360) + "\"");

	}

	// ------------------------------------------------------------------
	// nesserialtest.nes criteria (SerialShiftBankSwitchStrategy, bead grm-hsv.1)
	// ------------------------------------------------------------------

	protected void checkNesSerialtest() {
		// F-reset: the bit-7-set write at $C002 (LDA #$80 / STA $8000) forces prg_mode=3
		// known -- idempotent re-assertion of the seeded initial state (this board's home
		// mode already is prg_mode=3), but the comment must show it as known, not "?".
		String c = eol(0xC002);
		criterionEolKnown("F-reset", c, "prg_mode=3",
			"bit-7 reset -> prg_mode=3 known at c002: \"");

		// F-unrolled: the 5th write of the canonical-address ($E000) chain at $C017
		// commits prg_bank=5; the JSR $8000 right after it at $C01A retargets into the
		// mode-3 (this board's home mode), non-home-bank overlay W8000_M3_B5.
		c = eol(0xC017);
		criterion("F-unrolled:comment", c.contains("prg_bank=5"),
			"unrolled chain commits prg_bank=5 at c017: \"" + c + "\"");
		Reference r = findOverlayRef(0xC01A, "W8000_M3_B5", 0x8000);
		criterionPrimaryCall("F-unrolled:jsr", r,
			"JSR $8000 (prg_bank=5) retargeted to W8000_M3_B5 overlay, primary: ");

		// Writes 1-4 of the unrolled chain (c007-c013) deposit NOTHING: the state flows
		// through unchanged and the commit is deferred entirely to write 5 (c017, checked
		// above). So the listing must say nothing at all about them -- no bank comment and no
		// warning (bead grm-pdd6, ValueStop.NO_DEPOSIT).
		//
		// This criterion used to assert the OPPOSITE half of that: that c007 carried a comment
		// echoing the unchanged prg_bank=0. That was the pre-grm-pdd6 contract, and it was
		// wrong in both directions -- a "bank ->" comment at a site that sets no bank credits
		// this write with the PREVIOUS site's knowledge, and the same site with nothing known
		// (the state grm-913 leaves it in on a real ROM) raised a "genuinely undeterminable
		// value" WARNING about a recovery that never ran. Both are now suppressed, which is
		// what the two clauses below pin.
		c = eol(0xC007);
		criterion("F-unrolled:echo-deposits-nothing",
			c.isEmpty() && !hasWarningBookmark(0xC007),
			"write 1 of the chain (c007) deposits nothing, so it is neither commented nor " +
				"warned: comment=\"" + c + "\" warning=" + hasWarningBookmark(0xC007));

		// F-noncanonical: the 5th write of the $FFF9 chain (same 8K window as $E000,
		// bits 14:13 both decode to target 3/PRG) at $C02F commits prg_bank=6 via a
		// non-canonical address -- FF1's exact trick ($9FFF/$BFFF/$DFFF/$FFF9). The JSR
		// $8000 at $C032 retargets into W8000_M3_B6.
		c = eol(0xC02F);
		criterion("F-noncanonical:comment", c.contains("prg_bank=6"),
			"non-canonical-address chain commits prg_bank=6 at c02f: \"" + c + "\"");
		r = findOverlayRef(0xC032, "W8000_M3_B6", 0x8000);
		criterionPrimaryCall("F-noncanonical:jsr", r,
			"JSR $8000 (prg_bank=6, non-canonical commit) retargeted to W8000_M3_B6 " +
				"overlay, primary: ");

		// F-chr-discard: the chain to $A000 (CHR0, target 1 -- no `targets` entry in the
		// board's serial-shift mechanism) is recognized but discarded: prg_bank must
		// SURVIVE untouched, proven by the JSR $8000 at $C04A still retargeting to
		// W8000_M3_B6 (bank 6, set by F-noncanonical above, not clobbered by the CHR
		// write in between).
		r = findOverlayRef(0xC04A, "W8000_M3_B6", 0x8000);
		criterionPrimaryCall("F-chr-discard", r,
			"JSR $8000 after a CHR0 chain still retargets to W8000_M3_B6 (prg_bank " +
				"survived the discarded CHR commit): ");

		// F-loop: the counted-loop idiom (LDA #$03 / LDY #$05 / loop: STA $E000 / LSR A /
		// DEY / BNE loop). The commit attaches to the BNE at $C056 (the secondary
		// recognizer claims the branch in computeSwitch -- no engine hook; see
		// SerialShiftBankSwitchStrategy's javadoc), fully known since every field was
		// known coming in.
		c = eol(0xC056);
		criterionEolKnown("F-loop:comment", c, "prg_bank=3",
			"counted loop commits prg_bank=3 at its BNE (c056): \"");

		// The in-loop STA at $C051 must be suppressed (echo, not poison): no WARNING
		// bookmark, and no CONFIDENT early commit of prg_bank=3. Its comment is the
		// honest MERGE of its two predecessors -- the loop entry (pre-loop prg_bank=6)
		// and the BNE's back edge (which carries the committed prg_bank=3, by design --
		// see SerialShiftBankSwitchStrategy's javadoc on the back-edge flow) -- so the
		// agreeing bits stay known and the disagreeing prg_bank bits degrade to "?",
		// exactly what BankState.merge produces at any other join.
		c = eol(0xC051);
		criterion("F-loop:body-suppressed",
			!hasWarningBookmark(0xC051) && !(c.contains("prg_bank=3") && !c.contains("?")),
			"in-loop STA (c051) suppressed -- no warning, no confident early commit " +
				"(merge of pre-loop 6 and back-edge 3): warning=" +
				hasWarningBookmark(0xC051) + " comment=\"" + c + "\"");

		// The JSR $8000 on the loop's exit edge at $C058 retargets into W8000_M3_B3.
		r = findOverlayRef(0xC058, "W8000_M3_B3", 0x8000);
		criterionPrimaryCall("F-loop:jsr", r,
			"JSR $8000 after the counted loop (prg_bank=3) retargeted to W8000_M3_B3 " +
				"overlay, primary: ");

		// F-unresolvable: write 1 of the chain seeded from an opaque indexed load
		// (LDX #$00 / LDA $C200,X) at $C060 can't have its own bit 7 resolved -> honest
		// poison -> WARNING bookmark, no false "bank ->" claim. The chain's 5th write
		// (c070) also degrades (target known from the address, value unresolvable) --
		// neither site may claim a definite bank value.
		criterion("F-unresolvable:write1",
			hasWarningBookmark(0xC060) && !eol(0xC060).contains("bank ->"),
			"unresolvable chain seed warns, no false comment, at c060: warning=" +
				hasWarningBookmark(0xC060) + " comment=\"" + eol(0xC060) + "\"");
		criterion("F-unresolvable:commit", !eol(0xC070).contains("prg_bank=6") &&
			!eol(0xC070).contains("prg_bank=5") && !eol(0xC070).contains("prg_bank=3"),
			"unresolvable chain's commit at c070 makes no false prg_bank claim: \"" +
				eol(0xC070) + "\"");

		// F-partial-bit7: an isolated (non-chained) write to $8000 whose stored value is
		// unresolvable (LDX #$01 / LDA $C200,X / STA $8000, no preceding/following
		// LSR/STA) at $C078 -- bit 7 unknown must poison, and critically must NOT be
		// misclassified as a confident reset (no false prg_mode=3 claim).
		criterion("F-partial-bit7",
			hasWarningBookmark(0xC078) && !eol(0xC078).contains("prg_mode=3"),
			"unresolvable isolated write warns, no false reset claim, at c078: warning=" +
				hasWarningBookmark(0xC078) + " comment=\"" + eol(0xC078) + "\"");

		// F-rmw-reset (bead grm-4kc): the self-modifying reset idiom at $C07B --
		// "INC $C07B", an INC on its own opcode byte, transcribed in shape from bionic's
		// RESET ($FFE1: EE E1 FF  INC $FFE1). A read-modify-write into the register range
		// used to poison unconditionally, because MosOperands.storeRegister knows
		// only STA/STX/STY. It is in fact exactly determinable: the byte read is this
		// instruction's own $EE opcode, known by SELF-REFERENCE rather than by any
		// memory-map argument -- whichever bank is mapped, the byte at that address is the
		// one the CPU just fetched to get here. $EE has bit 7 set, so the shifter resets
		// and prg_mode is forced to 3.
		//
		// The placement is what makes this criterion mean something: F-partial-bit7
		// immediately above poisons all three fields, so prg_mode arrives here UNKNOWN and
		// this write restores it to a known 3. Anywhere else in this fixture prg_mode is
		// already 3 and the assertion would pass without the feature.
		c = eol(0xC07B);
		criterion("F-rmw-reset",
			c.contains("prg_mode=3") && !hasWarningBookmark(0xC07B),
			"self-modifying INC resets the shifter -> prg_mode=3, no warning, at c07b: " +
				"warning=" + hasWarningBookmark(0xC07B) + " comment=\"" + c + "\"");

		// Disassembly sanity: the three JSR-target overlay instructions actually exist.
		criterion("F5:W8000_M3_B3_8000", hasInstructionAt("W8000_M3_B3", 0x8000),
			"instruction exists at W8000_M3_B3::8000");
		criterion("F5:W8000_M3_B5_8000", hasInstructionAt("W8000_M3_B5", 0x8000),
			"instruction exists at W8000_M3_B5::8000");
		criterion("F5:W8000_M3_B6_8000", hasInstructionAt("W8000_M3_B6", 0x8000),
			"instruction exists at W8000_M3_B6::8000");
	}

	// ------------------------------------------------------------------
	// nesmmc1test.nes criteria (REAL machines/nes-mmc1.yaml board, bead grm-hsv.2)
	// ------------------------------------------------------------------
	//
	// DESIGN NOTE (bug found by this fixture, since fixed): helper call-site argument
	// recovery (HelperArgumentRecovery.recoverCallArgument) originally positioned the
	// recovered register value with the MECHANISM-wide (effectMask, lsb) -- correct only
	// for single-field mechanisms (register-write, memory-latch), wrong for serial-shift,
	// whose ONE mechanism spans multiple disjoint targets (mirroring+prg_mode via target
	// 0, prg_bank via target 3): LDA #$02 / JSR SwitchBank deposited 2 at the window's
	// bit 0 (mirroring=2) instead of through prg_bank's field list. The fix gives the
	// STRATEGY ownership of the deposit: BankSwitchStrategy.depositHelperArgument
	// (default = historical verbatim-byte behavior, owning the whole field-local width)
	// takes the helper's own recognized switch-site instruction -- HelperModel now
	// carries the matched strategy and that site's address -- and SerialShift's override
	// decodes the site's target (write-5 STA address bits 14:13, or a counted loop's STA
	// via the BNE matcher) and deposits only through that target's TargetField list,
	// returning an ownedMask so unowned sibling fields are left untouched (not poisoned;
	// a CHR-target site owns nothing and the call is treated as a verified no-op).
	// Helper-call EOL comments render from the mechanism-window post-call state (in-state
	// echo narrowed to the helper's effectMask, like a direct computeSwitch result), while
	// the WARNING decision still keys off the call's own recovered effect -- M9's honest
	// warning is unchanged.

	protected void checkNesMmc1test() {
		// Addresses per tools/banktest/mknesbanktest.py's make_prg_mmc1() label dump:
		// switch_bank=$C200, shadow_entry=$C250, shadow_midbody=$C252,
		// relay_to_entry=$C280, relay_to_midbody=$C286, mode2_target=$C300, reset=$C000,
		// f_reset=$C002, call1_imm=$C005, call1_jsr=$C007, call1_use_jsr=$C00A,
		// chr_commit=$C01F, call2_imm=$C022, call2_jsr=$C024, call2_use_jsr=$C027,
		// relay_to_shadow=$C283, relay_entry_imm=$C02A, relay_entry_jsr=$C02C,
		// relay_entry_use_jsr=$C02F, shadow_jsr=$C032, relay_mid_imm=$C035,
		// relay_mid_jsr=$C037, relay_mid_use_jsr=$C03A, call3_imm=$C03D,
		// call3_jsr=$C03F, mode_commit=$C054,
		// mode2_jsr=$C057, unresolvable_load=$C05C, unresolvable_jsr=$C05F, idle=$C062,
		// rti=$C065.

		// M1: the reset dance (LDA #$80 / STA $8000) at $C002 forces prg_mode=3 known --
		// idempotent re-assertion of the seeded home mode, comment must show it known.
		String c = eol(0xC002);
		criterionEolKnown("M1", c, "prg_mode=3",
			"reset dance -> prg_mode=3 known at c002: \"");

		// M2: call site 1's JSR $C200 (SwitchBank) at $C007 -- the LOAD-BEARING check for
		// this bead: findHelpers/recoverCallArgument must recognize $C200 as a bank-switch
		// helper function (argReg='A', recovered from the helper's own chain-write-1
		// register) and resolve THIS call's argument via a backward scan from the JSR
		// itself (LDA #$02 immediately precedes it) -- fully known, no "?", carrying a
		// "via <helper>" annotation (same shape as banktest3's B1 criterion).
		c = eol(0xC007);
		criterion("M2", c.contains("bank -> ") && c.contains("prg_bank=2") &&
			!c.contains("?") && c.contains("via"),
			"helper call site 1 resolves prg_bank=2 via SwitchBank, no '?', at c007: \"" +
				c + "\"");

		// M3: the JSR $8000 right after it, at $C00A, retargets to W8000_M3_B2 (mode 3 is
		// this board's home mode; bank 2 is non-home -> the _M3_B2 overlay).
		Reference r = findOverlayRef(0xC00A, "W8000_M3_B2", 0x8000);
		criterionPrimaryCall("M3", r,
			"JSR $8000 (prg_bank=2) retargeted to W8000_M3_B2 overlay, primary: ");

		// M4: call site 2's JSR $C200 at $C024 -- issued AFTER the CHR0 chain to $A000
		// (target 1, no `targets` entry) sandwiched between the two PRG switches --
		// resolves prg_bank=5 via the SAME helper, proving prg_bank survived the
		// discarded CHR write (SerialShiftBankSwitchStrategy's no-poison contract).
		c = eol(0xC024);
		criterion("M4", c.contains("bank -> ") && c.contains("prg_bank=5") &&
			!c.contains("?") && c.contains("via"),
			"helper call site 2 resolves prg_bank=5 via SwitchBank (survived the CHR " +
				"chain), no '?', at c024: \"" + c + "\"");

		// M5: the JSR $8000 after it, at $C027, retargets to W8000_M3_B5.
		r = findOverlayRef(0xC027, "W8000_M3_B5", 0x8000);
		criterionPrimaryCall("M5", r,
			"JSR $8000 (prg_bank=5) retargeted to W8000_M3_B5 overlay, primary: ");

		// M11 (bead grm-nju): call site 5's JSR $C280 at $C02C resolves prg_bank=3. $C280
		// is a 3-byte relay slot -- JMP $C200 -- whose target is the helper's ENTRY, so
		// Ghidra types it thunk_FUN_c200. The thunk is a different Function than the
		// helper, so calledHelper's getFunctionAt + helper-map lookup used to miss it and
		// return null, which runDataflow folds as a call that touches no bank state: a
		// SILENT miss, neither annotation nor warning. Measured on real cartridges this
		// was the whole story for Final Fantasy (all 59 of its bank call sites route
		// through one such thunk) and half of it for Bionic Commando.
		c = eol(0xC02C);
		criterion("M11", c.contains("bank -> ") && c.contains("prg_bank=3") &&
			!c.contains("?") && c.contains("via"),
			"relay-to-entry call site resolves prg_bank=3 through a thunk, no '?', at " +
				"c02c: \"" + c + "\"");

		// M11b: and the resolved bank is load-bearing -- the JSR $8000 at $C02F retargets
		// to W8000_M3_B3. A recovered value nothing retargets against would not be worth
		// much.
		r = findOverlayRef(0xC02F, "W8000_M3_B3", 0x8000);
		criterionPrimaryCall("M11b", r,
			"JSR $8000 (prg_bank=3, via thunk relay) retargeted to W8000_M3_B3 overlay, " +
				"primary: ");

		// M12 (bead grm-nju): call site 7's JSR $C286 at $C037 resolves prg_bank=4. This
		// is the harder half. $C286 is JMP $C252, and $C252 is MID-BODY of FUN_c250 --
		// the shadow helper's chain write 1, past the $C250 `LDA $65` prologue that would
		// have clobbered the argument. Ghidra cannot type this slot a thunk (its target
		// is not a function entry), so it stays an ordinary one-instruction function that
		// is neither the helper nor contains a switch site. Resolving it requires reading
		// "an address with incoming flow that is not its function's entry" as a distinct
		// entry with its own argument convention -- which is exactly what the backward
		// value scan's join-refusal at that address was already detecting and discarding.
		// Bionic Commando's $D6E2 -> $DCAA, byte for byte in shape.
		// M12a: FIXTURE INTEGRITY, and it must be checked rather than assumed. Whether
		// $C252 stays mid-body is Ghidra's decision, not the fixture's: thunk analysis
		// creates a function at each thunk destination, so if it reached $C252 before
		// $C250 there would be no mid-body entry left and M12 below would quietly be
		// testing the thunk path a second time. The fixture stacks the deck by ordering
		// the relay slots and their call sites the way bionic's are; this asserts the
		// deck actually came out that way.
		criterion("M12a", !isFunctionEntry(0xC252) && isFunctionEntry(0xC250),
			"fixture models a mid-body entry: c252 is inside a function but not its " +
				"entry (functionAt(c252)=" + isFunctionEntry(0xC252) + ", functionAt(c250)=" +
				isFunctionEntry(0xC250) + ")");

		c = eol(0xC037);
		criterion("M12", c.contains("bank -> ") && c.contains("prg_bank=4") &&
			!c.contains("?") && c.contains("via"),
			"relay-to-mid-body call site resolves prg_bank=4, no '?', at c037: \"" + c +
				"\"");

		// M12b: likewise load-bearing -- JSR $8000 at $C03A retargets to W8000_M3_B4.
		r = findOverlayRef(0xC03A, "W8000_M3_B4", 0x8000);
		criterionPrimaryCall("M12b", r,
			"JSR $8000 (prg_bank=4, via mid-body relay) retargeted to W8000_M3_B4 " +
				"overlay, primary: ");

		// M13 (bead grm-nju): call site 6's JSR $C283 at $C032 -- reaching the shadow
		// helper's OWN entry, where the bank is loaded from $65 and A is stale. The
		// mid-body work must NOT make this one resolve: reaching a helper is not the same
		// as knowing its argument, and attributing a stale register here would ship a
		// wrong bank. No "bank ->" claim. Recovering the CALLER'S argument still needs
		// cross-function store-to-load forwarding through the RAM shadow -- grm-mej.3.
		// This one declines because A is UNKNOWN; M14 below is its twin that declines
		// with A known, which is what actually pins the prologue check (grm-mu7).
		//
		// UPDATED, bead grm-yflf: this call's helper ($C250, LDA $65 / <chain>) is now a
		// recognized no-argument RESTORE ENTRY -- the same shape as zelda2's FUN_ffc9 --
		// so the honest form at this site is a RESTORED_BANK note naming $65, not a
		// WARNING. What this criterion has ALWAYS actually pinned is "declines honestly,
		// no fabricated bank claim"; a WARNING was simply the only honest vocabulary that
		// existed when this criterion was written. Accept either bookmark kind, and
		// require the note (when present) to actually name the cell rather than just
		// happening to contain the word.
		String m13Note = noteBookmarkText(0xC032);
		criterion("M13",
			(hasWarningBookmark(0xC032) || (m13Note.contains("RESTORED") && m13Note.contains("0065"))) &&
				!eol(0xC032).contains("bank ->"),
			"shadow-entry call declines honestly (warning or restored-bank note naming $65) " +
				"at c032: warning=" + hasWarningBookmark(0xC032) + " note=\"" + m13Note +
				"\" comment=\"" + eol(0xC032) + "\"");

		// M14 (bead grm-mu7): call site 8's JSR $C283 at $C03F -- the shadow helper's own
		// entry AGAIN, but reached with a KNOWN bank in A (LDA #$06 at $C03D). This is
		// M13's A/B twin and the only one of the pair that pins the PROLOGUE guard:
		// M13's argument register is unknown, so its decline is equally explained by the
		// backward scan finding nothing (M9's reason), whereas here the scan succeeds and
		// the sole remaining reason to decline is that $C250's `LDA $65` clobbers A
		// before the chain reads it. Without the guard this reported a confident
		// prg_bank=6 -- findHelpers takes argReg='A' from the chain's STA and cannot see
		// that the prologue got there first, so recoverCallArgument handed the caller's
		// stale A to a strategy that deposits it verbatim.
		//
		// The check is deliberately in two parts. The warning + no-"bank ->" half is the
		// honest-decline shape M9/M13 share; the explicit !prg_bank=6 half is what would
		// have caught the bug even if the deposit had been rendered some other way, and
		// it names the exact wrong answer this call site is built to provoke.
		// M15 (bead grm-mu7, second increment): call site 9's JSR $C2A0 at $C03F -- the
		// SAVE/RESTORE helper (PHA / LDA #$01 / STA $0103 / PLA / chain). Its prologue
		// clobbers A and then puts it back across the stack, so the argument really does
		// reach the chain and this MUST resolve to prg_bank=1.
		//
		// This is M14's opposite number, and the pair is the point: both helpers write A
		// between entry and the first switch site, and the ONLY difference is whether the
		// value comes back. A guard that asks merely "was argReg written" cannot tell them
		// apart and gets this one wrong -- which is precisely what shipped in the first
		// grm-mu7 increment, costing kicarus all 215 of its overlay instructions, dodge
		// 10692, and cv2 both its bank comments, while every synthetic golden stayed green
		// because not one of them saved and restored. Castlevania 2's FUN_c187 is this
		// shape byte for byte.
		c = eol(0xC03F);
		criterion("M15", c.contains("bank -> ") && c.contains("prg_bank=1") &&
			!c.contains("?") && c.contains("via") && !hasWarningBookmark(0xC03F),
			"save/restore helper call resolves prg_bank=1 -- a restored clobber is not a " +
				"loss -- at c03f: warning=" + hasWarningBookmark(0xC03F) + " comment=\"" + c +
				"\"");

		// M15b: load-bearing, like M11b/M12b -- the JSR $8000 at $C042 retargets to
		// W8000_M3_B1. A recovered value nothing retargets against would not be worth much.
		r = findOverlayRef(0xC042, "W8000_M3_B1", 0x8000);
		criterionPrimaryCall("M15b", r,
			"JSR $8000 (prg_bank=1, via save/restore helper) retargeted to W8000_M3_B1 " +
				"overlay, primary: ");

		// UPDATED, bead grm-yflf: as with M13 above, $C250's shadow-entry helper is now a
		// recognized no-argument RESTORE ENTRY, so the honest form at this call site is a
		// RESTORED_BANK note naming $65, not a WARNING. What this criterion has always
		// actually pinned is "declines honestly despite a KNOWN caller argument -- no
		// fabricated bank, and specifically not the wrong prg_bank=6 the un-guarded bug
		// shipped" (see the big comment above M15). Accept either bookmark kind for the
		// "declines honestly" half; the !bank-> and !prg_bank=6 halves are unconditional
		// either way, since those are the actual regression guard.
		c = eol(0xC047);
		String m14Note = noteBookmarkText(0xC047);
		criterion("M14",
			(hasWarningBookmark(0xC047) || (m14Note.contains("RESTORED") && m14Note.contains("0065"))) &&
				!c.contains("bank ->") && !c.contains("prg_bank=6"),
			"prologue-clobbered helper call declines despite a known argument (warning or " +
				"restored-bank note naming $65), at c047: warning=" + hasWarningBookmark(0xC047) +
				" note=\"" + m14Note + "\" comment=\"" + c + "\"");

		// M14b: INVERTED BY grm-izu -- this criterion used to REQUIRE a warning bookmark at
		// $C04C, and now requires its absence. Read it as the regression guard against the
		// bug it once pinned.
		//
		// What used to happen. The poison M14 deposits leaves prg_bank UNKNOWN across the
		// next direct helper call (M6's JSR $C200 at $C04C), and the bank-requirement scan
		// reported that as "call to FUN_c200 requires prg_bank known on entry". That is the
		// requirement scan's signature and NOT the helper-call warning, which fires only
		// when a call's own recovery pinned down nothing (annotateOrWarn's knownMask == 0
		// branch) -- $C04C's recovery SUCCEEDED, and M6 below asserts a fully known
		// prg_bank=7 comment at this very address. So the golden carried a site with a
		// resolved annotation and a "you don't know the bank here" warning at once, which
		// is self-contradictory on its face.
		//
		// Why it was wrong. FUN_c200 is the plain SwitchBank shape: a 5x STA/LSR serial
		// chain that OVERWRITES prg_bank and reads nothing back. Analyzed standalone its
		// argument register is unknown, so its effect came out unknown from an unknown
		// in-state -- which the M3 known-ness heuristic read as "the dispatch needed this
		// bit". It did not; it needed its ARGUMENT, which is not board state at all. The
		// fix is at strategy level rather than a special case here: serial-shift answers
		// BankSwitchStrategy.effectDependsOnPriorState() false (MMC1's shift register is
		// write-only and this mechanism never resolves a load back to tracked state), so
		// its sites no longer contribute to requiresOnEntry on any branch -- commit, reset,
		// echo, or poison. A masked-RMW mechanism, which genuinely does consume its prior
		// value, still answers true and still gets the requirement.
		//
		// Note what did NOT change: the poison itself still propagates through the tracked
		// state exactly as M14 establishes -- only the false INFERENCE drawn from it is
		// gone. And the relay call sites ($C032/$C03F) never carried this warning either
		// way, since the scan walks DIRECT calls and those resolve to one-instruction relay
		// functions that reach the helper by JMP, never inheriting its requiresOnEntry.
		criterion("M14b", !hasWarningBookmark(0xC04C) && eol(0xC04C).contains("prg_bank=7"),
			"a full-overwrite helper call is NOT flagged as requiring the bank it " +
				"overwrites, while still resolving its own argument, at c04c: " +
				"warning=" + hasWarningBookmark(0xC04C) + " comment=\"" + eol(0xC04C) + "\"");

		// M6: call site 3's JSR $C200 at $C044 resolves prg_bank=7 via the same helper --
		// this is the commit that stages prg_bank=7 for the mode-2 transition below (bank
		// 7 == `last`, matching WC000's fixed-last home content, so the transition doesn't
		// move the ground out from under the running code -- see the fixture's module
		// doc). Unlike M2/M5 there is no follow-up JSR $8000 (bank 7 IS this running
		// code, not a separate routine).
		c = eol(0xC04C);
		criterion("M6", c.contains("bank -> ") && c.contains("prg_bank=7") &&
			!c.contains("?") && c.contains("via"),
			"helper call site 3 resolves prg_bank=7 via SwitchBank, no '?', at c04c: \"" +
				c + "\"");

		// M7: the mode-2 transition chain's commit (5th write of the inline Control chain
		// to $8000) at $C059 shows prg_mode=2 (fix-first) fully known -- mirroring stays
		// 0, prg_bank stays 7 (survived every write above, including M14's honest poison,
		// which M6's call site overwrote), so the WHOLE state is known, no '?'.
		c = eol(0xC061);
		criterionEolKnown("M7", c, "prg_mode=2",
			"mode-2 transition commits prg_mode=2, fully known, at c061: \"");

		// M8: the JSR $C300 right after the transition, at $C05C, retargets to
		// WC000_M2_B7 -- WC000 just became the switchable window (mode 2), at the
		// current prg_bank=7; this is the "post-switch control flow survives" check: the
		// JSR instruction itself sits in the SAME physical bytes (bank 7) before and
		// after the flip, only the symbolic window name changes.
		r = findOverlayRef(0xC064, "WC000_M2_B7", 0xC300);
		criterionPrimaryCall("M8", r,
			"JSR $C300 after the mode-2 transition retargeted to WC000_M2_B7 overlay, " +
				"primary: ");

		// M9: call site 4's JSR $C200 at $C064 -- an opaque indexed load (LDX #$00 / LDA
		// $C400,X) feeds the same helper's argReg='A'; recoverCallArgument's backward
		// scan cannot resolve an indexed load (same limitation nesserialtest's
		// F-unresolvable exercises for an inline chain's seed) -> honest WARNING
		// bookmark at the JSR itself, no false "bank ->" claim. This is the Metroid-
		// mailbox analog for the HELPER call-site value-recovery path specifically.
		criterion("M9", hasWarningBookmark(0xC06C) && !eol(0xC06C).contains("bank ->"),
			"unresolvable helper call warns, no false comment, at c06c: warning=" +
				hasWarningBookmark(0xC06C) + " comment=\"" + eol(0xC06C) + "\"");

		// M11 (grm-3ou part 1, increment 3): this fixture builds THREE helpers with three
		// different argument conventions, which makes it the sharpest available test that the
		// honest/ours split actually discriminates rather than just downgrading everything.
		//
		//   $C200 SwitchBank   LDA #imm / JSR -- the argument arrives in A. Its two scanned
		//                      sites are write 1 (c200, the bit-7 gate) and the write-5 commit
		//                      (c210, which scans the PRE-CHAIN load). Both reach the entry with
		//                      A undefined => HONEST, a NOTE.
		//   $C2A0 saver        PHA / LDA #$01 / STA $0103 / PLA then the chain -- Castlevania 2's
		//                      FUN_c187 byte for byte. The argument still arrives in A, and the
		//                      scan follows it THROUGH the prologue because grm-mej.3 pairs the
		//                      PLA to its PHA; it then lands on the entry => NOTE as well. This
		//                      is the half most likely to regress silently, since a lost PHA
		//                      pairing would turn it into an ordinary analyzer limit.
		//   $C250 shadow       LDA $65 then the chain -- Bionic Commando's FUN_dca8. Its chain
		//                      head c252 is a JOIN: the c250 restore falls into it, and the
		//                      $C286 thunk enters it mid-body with the caller's bank in A. Until
		//                      grm-dos9.14 this was the CONTROL that stayed a WARNING. It is now
		//                      ENTRY_SUPPLIED -- a NOTE of its own kind, not HELPER_ARGUMENT,
		//                      whose "the caller supplied it" is false on the restore arm --
		//                      because EVERY arm is judged at its entry's call sites: c250 is a
		//                      proven restore reached only by calls (via the $C283 thunk), and
		//                      $C286 is a thunk only calls reach. Owner ruling 2026-10-16. The
		//                      guard against grm-rr5p's over-broad rule ("any unresolved value
		//                      inside a helper is honest") moved with it: an arm whose own code
		//                      sets A keeps the WARNING (ModeLockSerialShiftProgramTest
		//                      .anArmThatSetsTheRegisterItselfKeepsTheWarning). Still no bank claim.
		//
		// The call sites keep their own warnings regardless -- see M9 at c06c.
		boolean argHelperNoted = hasNoteBookmark(0xC200) && hasNoteBookmark(0xC210) &&
			!hasWarningBookmark(0xC200) && !hasWarningBookmark(0xC210);
		boolean saverNoted = hasNoteBookmark(0xC2A7) && hasNoteBookmark(0xC2B7) &&
			!hasWarningBookmark(0xC2A7) && !hasWarningBookmark(0xC2B7);
		boolean shadowEntrySupplied = hasNoteBookmark(0xC252) && hasNoteBookmark(0xC262) &&
			!hasWarningBookmark(0xC252) && !hasWarningBookmark(0xC262) &&
			eol(0xC252).contains("entry-supplied") && eol(0xC262).contains("entry-supplied") &&
			!eol(0xC252).contains("bank ->") && !eol(0xC262).contains("bank ->");
		criterion("M11", argHelperNoted && saverNoted && shadowEntrySupplied,
			"argument helpers noted, RAM-shadow helper's join entry-supplied: SwitchBank(c200/c210)=" +
				argHelperNoted + " saver(c2a7/c2b7)=" + saverNoted +
				" shadow-entry-supplied(c252/c262)=" + shadowEntrySupplied + " [c252 \"" +
				eol(0xC252) + "\"]");

		// M10: disassembly sanity -- the JSR-target overlay instructions actually exist.
		criterion("M10:W8000_M3_B2_8000", hasInstructionAt("W8000_M3_B2", 0x8000),
			"instruction exists at W8000_M3_B2::8000");
		criterion("M10:W8000_M3_B5_8000", hasInstructionAt("W8000_M3_B5", 0x8000),
			"instruction exists at W8000_M3_B5::8000");
		criterion("M10:W8000_M3_B3_8000", hasInstructionAt("W8000_M3_B3", 0x8000),
			"instruction exists at W8000_M3_B3::8000");
		criterion("M10:W8000_M3_B4_8000", hasInstructionAt("W8000_M3_B4", 0x8000),
			"instruction exists at W8000_M3_B4::8000");
		criterion("M10:WC000_M2_B7_C300", hasInstructionAt("WC000_M2_B7", 0xC300),
			"instruction exists at WC000_M2_B7::C300");
	}

	// ------------------------------------------------------------------
	// nesrelaytest.nes criteria (REAL machines/nes-mmc1.yaml board, bead grm-2dr
	// increment 2: call-edge-wrapper recognition)
	// ------------------------------------------------------------------
	//
	// DESIGN NOTE: a call-edge wrapper is a function that (a) writes no mechanism itself,
	// (b) reaches a real bank-switch helper by an interior JSR rather than by falling
	// through into it, (c) makes exactly ONE such call, and (d) reaches that call
	// unconditionally with the caller's argument register intact. blmaster's FUN_e61b is
	// the real-ROM shape: `STA $DB` on entry, A reloaded from that shadow, then
	// `$e627 JSR $e63c` into the MMC1 chain -- twelve call sites, none of them recovered
	// before this increment.
	//
	// ADMISSION TAKES TWO GATES AND R6/R7 PIN THEM SEPARATELY, because neither subsumes
	// the other. The structural gate (isPassThroughInto over the prefix) proves the relay
	// is reached UNCONDITIONALLY; the value gate (argumentSurvivesPrologue over two
	// segments) proves the caller's byte is still in the argument register when the
	// helper reads it. R6 in particular is the case that is easy to get wrong: a branch
	// does NOT make argumentSurvivesPrologue decline -- a nonzero getFlows() only clears
	// its straight-line state and the walk continues -- so branch_pred passes the VALUE
	// gate and must be rejected by the STRUCTURAL one.
	//
	// Separate fixture from neswrappertest.nes on purpose: THAT golden staying
	// byte-identical is the proof increment 2 left increment 1's pass-through
	// recognition alone.
	protected void checkNesRelayTest() {
		// Addresses per tools/banktest/mknesbanktest.py's make_prg_relay() label dump:
		// relay_wrapper=$C100, relay_wrapper_jsr=$C104, two_call_pred=$C120,
		// nonhelper_pred=$C140, branch_pred=$C160, branch_pred_ldx=$C162,
		// branch_pred_jsr=$C164, clobber_pred=$C180, clobber_pred_jsr=$C182,
		// harmless_target=$C1A0, relay_helper=$C200, helper_b=$C214,
		// helper_branch=$C228, helper_clobber=$C23C, reset=$C000, f_reset=$C002,
		// r1_imm=$C005, r1_jsr=$C007, r1_use_jsr=$C00A, r2_imm=$C00D, r2_jsr=$C00F,
		// r2_use_jsr=$C012, r3_imm=$C015, r3_jsr=$C017, r4_imm=$C01A, r4_jsr=$C01C,
		// r5_imm=$C01F, r5_jsr=$C021, r6_imm=$C024, r6_jsr=$C026, direct1_imm=$C029,
		// direct1_jsr=$C02B, direct2_imm=$C02E, direct2_jsr=$C030, direct3_imm=$C033,
		// direct3_jsr=$C035, direct4_imm=$C038, direct4_jsr=$C03A, idle=$C03D,
		// rti=$C040.

		// R1: the reset dance (LDA #$80 / STA $8000) at $C002 forces prg_mode=3 known --
		// sanity-checks the fixture's own base state before anything relay-specific.
		String c = eol(0xC002);
		criterionEolKnown("R1", c, "prg_mode=3",
			"reset dance -> prg_mode=3 known at c002: \"");

		// R2: THE LOAD-BEARING CHECK for this increment. Call site R1's JSR $C100 at
		// $C007 lands on relay_wrapper -- `STA $22` / `LDA $22` / `JSR relay_helper`,
		// which writes no mechanism and reaches the real helper by a CALL, not a
		// fallthrough. The argument (prg_bank=3, from the immediate at $C005) must
		// resolve through the relay, carrying a "via" annotation.
		c = eol(0xC007);
		criterion("R2", c.contains("bank -> ") && c.contains("prg_bank=3") &&
			!c.contains("?") && c.contains("via"),
			"call-edge-wrapper call resolves prg_bank=3 via the wrapper, no '?', at " +
				"c007: \"" + c + "\"");

		// R2b: load-bearing -- the JSR $8000 right after it, at $C00A, retargets to
		// W8000_M3_B3 (bank 3 is non-home). A recovered value nothing retargets against
		// would not be worth much.
		Reference r = findOverlayRef(0xC00A, "W8000_M3_B3", 0x8000);
		criterionPrimaryCall("R2b", r,
			"JSR $8000 (prg_bank=3, via call-edge wrapper) retargeted to W8000_M3_B3 " +
				"overlay, primary: ");

		// R3: the SAME wrapper with a distinct immediate (prg_bank=6), proving the
		// resolution tracks each call site's own argument rather than caching the first.
		c = eol(0xC00F);
		criterion("R3", c.contains("bank -> ") && c.contains("prg_bank=6") &&
			!c.contains("?") && c.contains("via"),
			"call-edge-wrapper call (2nd, distinct immediate) resolves prg_bank=6 via " +
				"the wrapper, no '?', at c00f: \"" + c + "\"");

		// R3b: load-bearing -- the JSR $8000 at $C012 retargets to W8000_M3_B6.
		r = findOverlayRef(0xC012, "W8000_M3_B6", 0x8000);
		criterionPrimaryCall("R3b", r,
			"JSR $8000 (prg_bank=6, via call-edge wrapper) retargeted to W8000_M3_B6 " +
				"overlay, primary: ");

		// R4: negative control -- two_call_pred makes TWO known-helper calls, so the
		// effect at its return is not either helper's and it must not be admitted. This
		// is the same rule that keeps blmaster's FUN_eb98 out.
		c = eol(0xC017);
		criterion("R4", !c.contains("bank -> "),
			"two-helper-call predecessor is NOT admitted as a wrapper at c017: \"" + c +
				"\"");

		// R5: negative control -- nonhelper_pred's only call is to a lone RTS, so there
		// is no relay to key on and the call stays ordinary.
		c = eol(0xC01C);
		criterion("R5", !c.contains("bank -> "),
			"non-helper-call predecessor is NOT admitted as a wrapper at c01c: \"" + c +
				"\"");

		// R6: THE STRUCTURAL GATE, and the case the value gate cannot catch. branch_pred
		// is `BNE +2` / `LDX #$00` / `JSR helper_branch`: nothing writes A, so
		// argumentSurvivesPrologue ACCEPTS the prefix, but the relay is only conditionally
		// reached and admitting it would rest every claim about the wrapper's effect on a
		// call that might not run.
		c = eol(0xC021);
		criterion("R6", !c.contains("bank -> "),
			"branching predecessor is NOT admitted (structural gate; the value gate " +
				"accepts it) at c021: \"" + c + "\"");

		// R7: THE VALUE GATE. clobber_pred is structurally a perfect pass-through into
		// its relay, but `LDA #$01` eats the caller's argument first, so the caller's
		// byte is not this helper's argument and must not be deposited.
		c = eol(0xC026);
		criterion("R7", !c.contains("bank -> "),
			"argument-clobbering predecessor is NOT admitted (value gate) at c026: \"" +
				c + "\"");

		// R7b: anti-vacuity for R7 -- clobber_pred's OWN inner call at $C182 carries the
		// value it supplied (prg_bank=1) and must still resolve. Without this, R7 would
		// pass just as well if helper_clobber were simply broken.
		c = eol(0xC182);
		criterion("R7b", c.contains("bank -> ") && c.contains("prg_bank=1") &&
			!c.contains("?"),
			"clobber_pred's own inner call still resolves prg_bank=1 at c182: \"" + c +
				"\"");

		// R8-R11: fixture integrity. Every helper is also called directly, so each gets
		// its own Ghidra Function and resolves as an ordinary helper call. This is what
		// makes R4-R7 evidence about the PREDECESSORS' shapes rather than about their
		// helpers being broken.
		int[][] directs = { { 0xC02B, 2 }, { 0xC030, 5 }, { 0xC035, 1 }, { 0xC03A, 4 } };
		for (int i = 0; i < directs.length; i++) {
			c = eol(directs[i][0]);
			criterion("R" + (8 + i),
				c.contains("bank -> ") && c.contains("prg_bank=" + directs[i][1]) &&
					!c.contains("?"),
				"direct helper call resolves prg_bank=" + directs[i][1] + " at " +
					Integer.toHexString(directs[i][0]) + ": \"" + c + "\"");
		}
	}

	// ------------------------------------------------------------------
	// neswrappertest.nes criteria (REAL machines/nes-mmc1.yaml board, bead grm-2dr
	// increment 1: pass-through-wrapper recognition)
	// ------------------------------------------------------------------
	//
	// DESIGN NOTE: a pass-through wrapper is a function that (a) writes no mechanism
	// itself, (b) is a straight run of plain fall-through instructions -- no branch, no
	// jump, no JSR, not terminal -- and (c) whose LAST instruction falls through exactly
	// into the ENTRY of a real bank-switch helper (or of another such wrapper). Calls
	// landing on the wrapper must resolve their bank argument, because the argument
	// register survives across the wrapper body into the helper's prologue. Two real-ROM
	// shapes motivate this (see make_prg_wrapper()'s docstring): Castlevania 2's
	// FUN_c183/FUN_c185/FUN_c187 stack, and TMNT's FUN_cea5/FUN_cea7. This fixture is
	// deliberately separate from nesmmc1test.nes (which contains no fallthrough-wrapper
	// shape at all) so that fixture's golden stays byte-identical -- a prior helper
	// change (grm-mu7) regressed three real ROMs while all 45 synthetic goldens stayed
	// green, precisely because none of them exercised this shape.
	protected void checkNesWrapperTest() {
		// Addresses per tools/banktest/mknesbanktest.py's make_prg_wrapper() label dump:
		// single_wrapper=$C100, single_helper=$C102, outer_wrapper=$C140,
		// inner_wrapper=$C142, helper2=$C144, harmless_target=$C1F0, jsr_pred=$C180,
		// helper3=$C183, rts_pred=$C200, rts_pred_rts=$C202, helper4=$C203, reset=$C000,
		// f_reset=$C002, w1a_imm=$C005, w1a_jsr=$C007, w1a_use_jsr=$C00A, w1b_imm=$C00D,
		// w1b_jsr=$C00F, w1b_use_jsr=$C012, w2_imm=$C015, w2_jsr=$C017,
		// w2_use_jsr=$C01A, w3_jsr=$C01D, w4_imm=$C020, w4_jsr=$C022, w5_imm=$C025,
		// w5_jsr=$C027, direct1_imm=$C02A, direct1_jsr=$C02C, direct2_imm=$C02F,
		// direct2_jsr=$C031, direct3_imm=$C034, direct3_jsr=$C036, direct4_imm=$C039,
		// direct4_jsr=$C03B, idle=$C03E, rti=$C041.

		// W1: the reset dance (LDA #$80 / STA $8000) at $C002 forces prg_mode=3 known,
		// same shape as nesmmc1test's M1 -- sanity-checks the fixture's own base state
		// before anything wrapper-specific is asserted.
		String c = eol(0xC002);
		criterionEolKnown("W1", c, "prg_mode=3",
			"reset dance -> prg_mode=3 known at c002: \"");

		// W2: the LOAD-BEARING check for this increment. Call site W1a's JSR $C100 at
		// $C007 lands on single_wrapper -- a bare `STA $20` (writes no mechanism, A
		// untouched) that falls straight through into single_helper's chain5 entry at
		// $C102. The call's argument (prg_bank=3, from the immediate at $C005) must now
		// resolve THROUGH the wrapper, carrying a "via" annotation.
		c = eol(0xC007);
		criterion("W2", c.contains("bank -> ") && c.contains("prg_bank=3") &&
			!c.contains("?") && c.contains("via"),
			"single-wrapper call resolves prg_bank=3 via the wrapper, no '?', at c007: \"" +
				c + "\"");

		// W2b: load-bearing -- the JSR $8000 right after it, at $C00A, retargets to
		// W8000_M3_B3 (bank 3 is non-home). A recovered value nothing retargets against
		// would not be worth much.
		Reference r = findOverlayRef(0xC00A, "W8000_M3_B3", 0x8000);
		criterionPrimaryCall("W2b", r,
			"JSR $8000 (prg_bank=3, via single wrapper) retargeted to W8000_M3_B3 " +
				"overlay, primary: ");

		// W3: call site W1b's JSR $C100 at $C00F -- the SAME wrapper, a distinct
		// immediate (prg_bank=6), proving the resolution genuinely tracks each call
		// site's own argument rather than caching the first one seen.
		c = eol(0xC00F);
		criterion("W3", c.contains("bank -> ") && c.contains("prg_bank=6") &&
			!c.contains("?") && c.contains("via"),
			"single-wrapper call (2nd, distinct immediate) resolves prg_bank=6 via the " +
				"wrapper, no '?', at c00f: \"" + c + "\"");

		// W3b: load-bearing -- the JSR $8000 at $C012 retargets to W8000_M3_B6.
		r = findOverlayRef(0xC012, "W8000_M3_B6", 0x8000);
		criterionPrimaryCall("W3b", r,
			"JSR $8000 (prg_bank=6, via single wrapper) retargeted to W8000_M3_B6 " +
				"overlay, primary: ");

		// W4: the Castlevania 2 stacked shape, and the only real test of the fixpoint (a
		// wrapper falling into ANOTHER wrapper). Call site W2's JSR $C140 at $C017 lands
		// on outer_wrapper (`STA $21`), which falls into inner_wrapper (`LDA $21`), which
		// falls into helper2's chain. `STA $21` then `LDA $21` of the SAME cell is a
		// save/restore the prologue guard already models (the memory analog of grm-mu7's
		// stack-based PHA/PLA case), so the argument (prg_bank=4) survives the round trip
		// and must resolve.
		c = eol(0xC017);
		criterion("W4", c.contains("bank -> ") && c.contains("prg_bank=4") &&
			!c.contains("?") && c.contains("via"),
			"stacked-wrapper OUTER call resolves prg_bank=4 (same-cell save/restore), " +
				"no '?', at c017: \"" + c + "\"");

		// W4b: load-bearing -- the JSR $8000 at $C01A retargets to W8000_M3_B4.
		r = findOverlayRef(0xC01A, "W8000_M3_B4", 0x8000);
		criterionPrimaryCall("W4b", r,
			"JSR $8000 (prg_bank=4, via stacked outer wrapper) retargeted to " +
				"W8000_M3_B4 overlay, primary: ");

		// W5: the stacked pair's INNER call -- JSR $C142 at $C01D, entering DIRECTLY at
		// `LDA $21` with no immediate beforehand (and no visibility into outer_wrapper's
		// `STA $21` -- that instruction is not part of this entry's own function). From
		// this entry point the body is just an opaque read of an untracked zero-page
		// shadow, the same category as nesmmc1test's `LDA $65` shadow helper (M13/M14).
		// Must decline honestly: no fabricated "bank ->" claim.
		//
		// UPDATED, bead grm-yflf: exactly like M13/M14, this entry point (a bare,
		// single-instruction reload of $21 immediately feeding the mechanism) is now a
		// recognized no-argument RESTORE ENTRY, so the honest form is a RESTORED_BANK note
		// naming $21, not a WARNING. Accept either bookmark kind; the note, when present,
		// must actually name the cell.
		String w5Note = noteBookmarkText(0xC01D);
		criterion("W5",
			(hasWarningBookmark(0xC01D) || (w5Note.contains("RESTORED") && w5Note.contains("0021"))) &&
				!eol(0xC01D).contains("bank ->"),
			"stacked-wrapper INNER call declines honestly (untracked shadow; warning or " +
				"restored-bank note naming $21) at c01d: warning=" + hasWarningBookmark(0xC01D) +
				" note=\"" + w5Note + "\" comment=\"" + eol(0xC01D) + "\"");

		// W6 (negative control 1): call site W4's JSR $C180 at $C022 lands on jsr_pred,
		// whose body is `JSR harmless_target` before it falls through into helper3's
		// entry. The JSR disqualifies it as a pass-through wrapper -- a body containing a
		// call is not "plain fall-through" -- so this call must NOT resolve a bank at
		// all, despite jsr_pred sitting immediately above a real helper. This is the
		// boundary the increment does NOT cover: blmaster's FUN_e61b reaches its helper
		// via JSR rather than fallthrough and stays out of scope.
		criterion("W6", !eol(0xC022).contains("bank ->"),
			"JSR-bodied predecessor does not resolve a bank at c022: \"" + eol(0xC022) +
				"\"");

		// W7 (negative control 2): call site W5's JSR $C200 at $C027 lands on rts_pred
		// (`LDA #imm` / `RTS`), which sits immediately adjacent to helper4 in address --
		// contiguous, exactly like the positive cases -- but is TERMINAL, so it never
		// falls through into helper4. Adjacency alone must not be mistaken for the
		// fallthrough shape: this call must NOT resolve a bank.
		criterion("W7", !eol(0xC027).contains("bank ->"),
			"RTS-terminal predecessor does not resolve a bank at c027: \"" + eol(0xC027) +
				"\"");

		// W8-W11: fixture integrity for the ordinary (non-wrapper) call sites -- direct
		// JSRs straight to each helper's own entry, bypassing the wrapper/negative-control
		// predecessor above it. These must resolve normally like any other helper call,
		// proving each helper is a genuine bank-switch helper on its own; the negative
		// controls above fail only because THEY are not recognized as wrappers, not
		// because the helpers they sit next to are broken.
		c = eol(0xC02C);
		criterion("W8", c.contains("bank -> ") && c.contains("prg_bank=2") &&
			!c.contains("?") && c.contains("via"),
			"direct call to single_helper resolves prg_bank=2, no '?', at c02c: \"" + c +
				"\"");
		c = eol(0xC031);
		criterion("W9", c.contains("bank -> ") && c.contains("prg_bank=5") &&
			!c.contains("?") && c.contains("via"),
			"direct call to helper2 resolves prg_bank=5, no '?', at c031: \"" + c + "\"");
		c = eol(0xC036);
		criterion("W10", c.contains("bank -> ") && c.contains("prg_bank=1") &&
			!c.contains("?") && c.contains("via"),
			"direct call to helper3 resolves prg_bank=1 (helper3 itself is a genuine " +
				"helper; only jsr_pred fails to forward into it), no '?', at c036: \"" + c +
				"\"");
		c = eol(0xC03B);
		criterion("W11", c.contains("bank -> ") && c.contains("prg_bank=7") &&
			!c.contains("?") && c.contains("via"),
			"direct call to helper4 resolves prg_bank=7 (helper4 itself is a genuine " +
				"helper; only rts_pred fails to forward into it), no '?', at c03b: \"" + c +
				"\"");

		// W12: FIXTURE INTEGRITY, and it must be checked rather than assumed -- the whole
		// design depends on getFunctionAt(wrapperEntry)/getFunctionAt(helperEntry) being
		// non-null for every wrapper and every helper (each is reached by at least one
		// direct JSR of its own; see make_prg_wrapper()'s docstring).
		criterion("W12",
			isFunctionEntry(0xC100) && isFunctionEntry(0xC102) &&
				isFunctionEntry(0xC140) && isFunctionEntry(0xC142) &&
				isFunctionEntry(0xC144) && isFunctionEntry(0xC180) &&
				isFunctionEntry(0xC183) && isFunctionEntry(0xC200) &&
				isFunctionEntry(0xC203),
			"every wrapper and helper entry is its own Ghidra function: " +
				"single_wrapper=" + isFunctionEntry(0xC100) +
				" single_helper=" + isFunctionEntry(0xC102) +
				" outer_wrapper=" + isFunctionEntry(0xC140) +
				" inner_wrapper=" + isFunctionEntry(0xC142) +
				" helper2=" + isFunctionEntry(0xC144) +
				" jsr_pred=" + isFunctionEntry(0xC180) +
				" helper3=" + isFunctionEntry(0xC183) +
				" rts_pred=" + isFunctionEntry(0xC200) +
				" helper4=" + isFunctionEntry(0xC203));

		// W13: disassembly sanity -- the JSR-target overlay instructions actually exist,
		// so the retargeted references above point at real code (same style as
		// nesmmc1test's M10).
		criterion("W13:W8000_M3_B3_8000", hasInstructionAt("W8000_M3_B3", 0x8000),
			"instruction exists at W8000_M3_B3::8000");
		criterion("W13:W8000_M3_B6_8000", hasInstructionAt("W8000_M3_B6", 0x8000),
			"instruction exists at W8000_M3_B6::8000");
		criterion("W13:W8000_M3_B4_8000", hasInstructionAt("W8000_M3_B4", 0x8000),
			"instruction exists at W8000_M3_B4::8000");
	}

	protected void checkNesMmc1Override() {
		// Addresses per tools/banktest/mknesbanktest.py's make_prg_mmc1_override() label dump:
		// reset=$C000, f_reset=$C002, opaque_load=$C007, unknown_commit=$C01A,
		// override_jsr=$C01D, known_commit=$C032, flow_jsr=$C035, idle=$C038, rti=$C03B.
		// Loaded with -loader-placement W8000:5 (window:bank; see run-banktest.sh).

		// O1: the reset dance at $C002 recovers the whole state from dataflow (prg_mode=3
		// known, no '?', same as nesmmc1test's M1) and now carries the provenance tag that
		// distinguishes a flow-recovered switch from an override placement.
		String c = eol(0xC002);
		criterion("O1", c.contains("prg_mode=3") && !c.contains("?") &&
			c.contains("[switch-value flow]"),
			"reset dance -> flow-recovered, tagged [switch-value flow], at c002: \"" + c + "\"");

		// O2: the inline chain commit at $C01A has a genuinely unrecoverable value (opaque
		// LDA $C400,X seed) -> honest WARNING bookmark, no false "bank ->" claim (same rule as
		// nesmmc1test's M9). prg_bank is unknown downstream from here -- which is exactly what
		// makes the override load-bearing at the next reference (O3).
		criterion("O2", hasWarningBookmark(0xC01A) && !eol(0xC01A).contains("bank ->"),
			"unresolvable inline commit warns, no false comment, at c01a: warning=" +
				hasWarningBookmark(0xC01A) + " comment=\"" + eol(0xC01A) + "\"");

		// O3 (OVERRIDE FIRES): the JSR $8000 at $C01D, where prg_bank is unknown, retargets
		// into W8000_M3_B5 -- the bank pinned by the override, NOT the home-bank fallback.
		Reference r = findOverlayRef(0xC01D, "W8000_M3_B5", 0x8000);
		criterionPrimaryCall("O3", r,
			"JSR $8000 with unknown prg_bank retargeted to the override's W8000_M3_B5, " +
				"primary: ");

		// O4: the override site carries "[user override]" provenance in the listing/dump.
		c = eol(0xC01D);
		criterion("O4", c.contains("bank -> 5") && c.contains("[user override]"),
			"override site tagged [user override] at c01d: \"" + c + "\"");

		// O5: the known commit at $C032 recovers prg_bank=3 from dataflow. prg_mode/mirroring
		// knownness was degraded by the unresolvable chain above (so the whole state carries a
		// '?'), but prg_bank itself is known -- which is what drives placement -- and the
		// switch is flow-sourced, so it is tagged [switch-value flow].
		c = eol(0xC032);
		criterion("O5", c.contains("prg_bank=3") && c.contains("known: prg_bank") &&
			c.contains("[switch-value flow]"),
			"known commit -> prg_bank=3 recovered, flow-tagged, at c032: \"" + c + "\"");

		// O6 (FLOW WINS): the JSR $8000 at $C035, where prg_bank=3 IS known, retargets into
		// W8000_M3_B3 -- dataflow beats the override (which pins W8000 to bank 5); no
		// "[user override]" tag here, and no ref into B5.
		r = findOverlayRef(0xC035, "W8000_M3_B3", 0x8000);
		criterion("O6", r != null && r.getReferenceType().isCall() && r.isPrimary() &&
			findOverlayRef(0xC035, "W8000_M3_B5", 0x8000) == null &&
			!eol(0xC035).contains("[user override]"),
			"JSR $8000 with known prg_bank=3 retargeted to W8000_M3_B3 (flow wins over " +
				"override), primary: " + describe(r));

		// O7: disassembly sanity -- both retargeted overlay targets exist.
		criterion("O7:W8000_M3_B5_8000", hasInstructionAt("W8000_M3_B5", 0x8000),
			"instruction exists at W8000_M3_B5::8000");
		criterion("O7:W8000_M3_B3_8000", hasInstructionAt("W8000_M3_B3", 0x8000),
			"instruction exists at W8000_M3_B3::8000");
	}

	protected void checkNesMmc3Override() {
		// Addresses per tools/banktest/mknesbanktest.py's make_prg_mmc3_override() label dump:
		// reset=$E000, select7=$E002, known_commit=$E007, flow_jsr=$E00A, opaque_load=$E00F,
		// partial_ora=$E012, partial_commit=$E014, partial_jsr=$E017, opaque_load2=$E01A,
		// unknown_commit=$E01D, unknown_jsr=$E020, idle=$E023, rti=$E026.
		// Loaded with -loader-placement WA000:5 (bead grm-iqq). The point of this fixture is
		// Q3/Q4: the INTERIOR of the knowledge lattice, which nesmmc1overridetest cannot reach
		// (its serial-shift strategy collapses a clobbered chain to fully unknown). Under the
		// pre-grm-v6o "intersects" predicate a partial r7 counted as known and Q4's JSR stayed
		// in base (effective r7 backfilled to the home bank 1); the "contains" predicate lets
		// the override fire.

		// Q1: the known data write at $E007 recovers r7=3 from dataflow through a known
		// select=7, no '?', flow-tagged -- the same shape as nesmmc3test's e021.
		String c = eol(0xE007);
		criterion("Q1", c.contains("select=7") && c.contains("r7=3") && !c.contains("?") &&
			c.contains("[switch-value flow]"),
			"known data write -> r7=3 flow-recovered at e007: \"" + c + "\"");

		// Q2 (FLOW WINS, known endpoint): the JSR $A000 at $E00A retargets into WA000_B3 --
		// dataflow beats the override (which pins WA000 to bank 5); no ref into B5, no tag.
		Reference r = findOverlayRef(0xE00A, "WA000_B3", 0xA000);
		criterion("Q2", r != null && r.getReferenceType().isCall() && r.isPrimary() &&
			findOverlayRef(0xE00A, "WA000_B5", 0xA000) == null &&
			!eol(0xE00A).contains("[user override]"),
			"JSR $A000 with known r7=3 retargeted to WA000_B3 (flow wins over override), " +
				"primary: " + describe(r));

		// Q3 (THE INTERIOR): the data write at $E014 deposits a PARTIAL r7 -- ORA #$01 over
		// an opaque indexed load pins bit 0 = 1 and nothing else -- so the comment carries a
		// '?', names r7.0 as known, and names at least one other r7 bit as assumed. This is the
		// state no other fixture constructs; if it ever collapses to fully unknown (no comment,
		// warning instead) or to fully known, Q4 stops testing what it claims to.
		c = eol(0xE014);
		criterion("Q3", c.contains("?") && c.contains("r7.0=1") &&
			c.contains("assumed from initial:") && c.contains("r7.1") &&
			!c.contains("[user override]"),
			"partial data write -> r7 partially known (r7.0=1, rest assumed) at e014: \"" +
				c + "\"");

		// Q4 (OVERRIDE FIRES ON PARTIAL KNOWLEDGE -- grm-v6o's E2E regression test): the JSR
		// $A000 at $E017 retargets into WA000_B5, the override's bank, tagged [user override].
		// The old predicate would have left this JSR in base with no overlay reference.
		r = findOverlayRef(0xE017, "WA000_B5", 0xA000);
		criterionPrimaryCall("Q4", r,
			"JSR $A000 with PARTIALLY-known r7 retargeted to the override's WA000_B5, " +
				"primary: ");
		c = eol(0xE017);
		criterion("Q4:tag", c.contains("bank -> 5") && c.contains("[user override]"),
			"partial-knowledge override site tagged [user override] at e017: \"" + c + "\"");

		// Q5: the bare opaque data write at $E01D leaves r7 FULLY unknown. Unlike MMC1's
		// unresolvable chain (nesmmc1overridetest's O2, a warning and no comment), MMC3's packed
		// tuple still has known select/r6 bits, so the honest annotation is a '?' comment that
		// lists every r7 bit as assumed and names none of them as known.
		c = eol(0xE01D);
		criterion("Q5", c.contains("?") && c.contains("assumed from initial: r7.0,r7.1,r7.2,r7.3,r7.4,r7.5") &&
			!c.matches(".*known:[^;]*r7\\.[0-5]=.*"),
			"opaque data write -> r7 fully unknown (all six bits assumed) at e01d: \"" + c + "\"");

		// Q6 (OVERRIDE FIRES, unknown endpoint): the JSR $A000 at $E020 with r7 fully unknown
		// retargets into WA000_B5, tagged -- the endpoint nesmmc1overridetest's O3/O4 already
		// cover, kept here as the control that Q4's partial case is not merely this case.
		r = findOverlayRef(0xE020, "WA000_B5", 0xA000);
		c = eol(0xE020);
		criterion("Q6", r != null && r.getReferenceType().isCall() && r.isPrimary() &&
			c.contains("bank -> 5") && c.contains("[user override]"),
			"JSR $A000 with unknown r7 retargeted to WA000_B5, tagged, at e020: " +
				describe(r) + " \"" + c + "\"");

		// Q7: disassembly sanity -- both retargeted overlay targets exist.
		criterion("Q7:WA000_B5_A000", hasInstructionAt("WA000_B5", 0xA000),
			"instruction exists at WA000_B5::A000");
		criterion("Q7:WA000_B3_A000", hasInstructionAt("WA000_B3", 0xA000),
			"instruction exists at WA000_B3::A000");
	}
}
