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
// Per-fixture criteria for the C64/PET/C128/SNES/BASIC/decrypt/copy/nestbl fixture families
// (VerifyBankTest.java sections, bead grm-rx1i.17). See VerifyBase.java.

import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import retromachines.AbstractCbmPrgLoader;
import retromachines.C64BasicAnalyzer;
import retromachines.C64BankingAnalyzer;
import retromachines.EmulationRecovery;
import retromachines.IoPolicy;
import retromachines.RecoveryResult;
import retromachines.StopConditions;
import retromachines.StopReason;

public class VerifyCbmCriteria extends VerifyBase {

	VerifyCbmCriteria(GhidraScript script, Verdict verdict) {
		super(script, verdict);
	}

	// ------------------------------------------------------------------
	// EmulationRecovery harness check (bead grm-edg)
	// ------------------------------------------------------------------

	// Fixture contract from mkemutest.py: a constant-EOR (#$AA) in-place decrypt loop at
	// $2000 rewriting the 8-byte payload at $2010..$2017; decrypted plaintext is $01..$08.
	// Load address is inside RAM_MAIN so the loader carves the PRG into the base space.
	protected static final long EMU_ENTRY = 0x2000;
	protected static final long EMU_PAYLOAD = 0x2010;
	protected static final int EMU_LEN = 8;

	protected void checkEmuRecovery() {
		Address payloadStart = addr(EMU_PAYLOAD);
		AddressSet target = new AddressSet(payloadStart, addr(EMU_PAYLOAD + EMU_LEN - 1));

		RecoveryResult result = verifyEmuRecovery("emu", EMU_ENTRY, EMU_PAYLOAD, EMU_LEN);

		byte[] recovered = result.recoveredBytes(payloadStart, EMU_LEN);

		StringBuilder dirtySb = new StringBuilder();
		for (AddressRange r : result.dirty().getAddressRanges()) {
			if (dirtySb.length() > 0) {
				dirtySb.append(" ");
			}
			dirtySb.append(fmt(r.getMinAddress())).append("-").append(fmt(r.getMaxAddress()));
		}

		println("=== BANKDUMP BEGIN ===");
		println("STOPREASON " + result.stopReason());
		println("STEPS " + result.stepsExecuted());
		println("DIRTY " + dirtySb);
		println("RECOVERED " + hex(recovered));
		println("SUSPECT " + result.provenance().suspect());
		println("=== BANKDUMP END ===");
	}

	/** Shared EmulationRecovery harness check (bead grm-w8a): runs the emulator to a
	 *  dirty-watch stop condition over the payload range and asserts stop reason, recovered
	 *  plaintext ($01..$len), non-suspect provenance, and dirty-coverage of the target range.
	 *  Callers print their own BANKDUMP section (the two fixtures' dump shapes differ) using
	 *  the returned RecoveryResult; this only emits CRITERION lines, which sit outside the
	 *  BANKDUMP markers and so cannot move a golden. */
	protected RecoveryResult verifyEmuRecovery(String idPrefix, long entryAddr, long payloadAddr,
			int len) {
		Address entry = addr(entryAddr);
		Address payloadStart = addr(payloadAddr);
		AddressSet target = new AddressSet(payloadStart, addr(payloadAddr + len - 1));

		// Dirty-watch on the payload range is the intended completion condition; fuel is a
		// safety bound in case the watch never trips (the fixture's trailing JMP-self spins).
		StopConditions stop = StopConditions.builder()
				.dirtyWatch(target)
				.instructionFuel(10_000)
				.build();

		RecoveryResult result = new EmulationRecovery(currentProgram)
				.recover(entry, stop, IoPolicy.volatileBlocks(currentProgram), monitor);

		byte[] recovered = result.recoveredBytes(payloadStart, len);
		byte[] expected = new byte[len];
		for (int i = 0; i < len; i++) {
			expected[i] = (byte) (i + 1);
		}

		StringBuilder dirtySb = new StringBuilder();
		for (AddressRange r : result.dirty().getAddressRanges()) {
			if (dirtySb.length() > 0) {
				dirtySb.append(" ");
			}
			dirtySb.append(fmt(r.getMinAddress())).append("-").append(fmt(r.getMaxAddress()));
		}

		criterion(idPrefix + "-stopreason", result.stopReason() == StopReason.DIRTY_WATCH,
			"stop=" + result.stopReason());
		criterion(idPrefix + "-recovered", Arrays.equals(recovered, expected),
			"bytes=" + hex(recovered));
		criterion(idPrefix + "-not-suspect", !result.provenance().suspect(),
			"suspect=" + result.provenance().suspect());
		criterion(idPrefix + "-dirty-covers-target", result.dirty().contains(target),
			"dirty=" + dirtySb);

		return result;
	}

	// ------------------------------------------------------------------
	// Arbitrary-address C64 PRG loading (bead grm-dvx)
	// ------------------------------------------------------------------

	protected void checkPrgPlacement() {
		MemoryBlock a = blockAt("RAM_A000", 0xa000);
		MemoryBlock c = currentProgram.getMemory().getBlock(addr(0xc000));
		MemoryBlock d = blockAt("RAM_D000", 0xd000);
		MemoryBlock e = blockAt("RAM_E000", 0xe000);
		MemoryBlock basic = currentProgram.getMemory().getBlock(addr(0xa000));
		MemoryBlock io = currentProgram.getMemory().getBlock(addr(0xd000));
		MemoryBlock kernal = currentProgram.getMemory().getBlock(addr(0xe000));

		println("=== BANKDUMP BEGIN ===");
		println("A000 " + describeBlock(a) + " BYTES " + bytesAt("RAM_A000", 0xa000, 4));
		println("C000 " + describeBlock(c) + " BYTES " + bytesAt(null, 0xc000, 4));
		println("D000 " + describeBlock(d) + " BYTES " + bytesAt("RAM_D000", 0xd000, 4));
		println("E000 " + describeBlock(e) + " BYTES " + bytesAt("RAM_E000", 0xe000, 4));
		println("HOME " + names(basic, io, kernal));
		println("=== BANKDUMP END ===");

		criterion("placement-a000", initializedOverlay(a, "RAM_A000") &&
			"41 30 30 30".equals(bytesAt("RAM_A000", 0xa000, 4)), describeBlock(a));
		criterion("placement-c000", c != null && c.isInitialized() && !c.isOverlay() &&
			"43 30 30 30".equals(bytesAt(null, 0xc000, 4)), describeBlock(c));
		criterion("placement-d000", initializedOverlay(d, "RAM_D000") &&
			"44 30 30 30".equals(bytesAt("RAM_D000", 0xd000, 4)), describeBlock(d));
		criterion("placement-e000", initializedOverlay(e, "RAM_E000") &&
			"45 30 30 30".equals(bytesAt("RAM_E000", 0xe000, 4)), describeBlock(e));
		criterion("placement-file-offsets", fileOffset(a) == 2 && fileOffset(c) == 0x2002 &&
			fileOffset(d) == 0x3002 && fileOffset(e) == 0x4002,
			"offsets=" + fileOffset(a) + "," + fileOffset(c) + "," + fileOffset(d) + "," +
				fileOffset(e));
		criterion("placement-home-in-base", basic != null && "BASIC".equals(basic.getName()) &&
			io != null && !io.isOverlay() && kernal != null && "KERNAL".equals(kernal.getName()),
			names(basic, io, kernal));
	}

	protected void checkPrgWrap() {
		MemoryBlock high = blockAt("RAM_E000", 0xfffc);
		MemoryBlock p6510 = currentProgram.getMemory().getBlock(addr(0));
		MemoryBlock zeroPage = currentProgram.getMemory().getBlock(addr(2));
		MemoryBlock vectors = currentProgram.getMemory().getBlock(addr(0x300));

		println("=== BANKDUMP BEGIN ===");
		println("HIGH " + describeBlock(high) + " BYTES " + bytesAt("RAM_E000", 0xfffc, 4));
		println("P6510 " + describeBlock(p6510) + " BYTES " + bytesAt(null, 0, 2));
		println("LOW " + describeBlock(zeroPage) + " BYTES " + bytesAt(null, 2, 2));
		println("VECTOR " + describeBlock(vectors) + " BYTES " + bytesAt(null, 0x300, 4));
		println("=== BANKDUMP END ===");

		criterion("wrap-high", initializedOverlay(high, "RAM_E000") &&
			"fc fd fe ff".equals(bytesAt("RAM_E000", 0xfffc, 4)), describeBlock(high));
		criterion("wrap-p6510", p6510 != null && p6510.isInitialized() &&
			"d0 d1".equals(bytesAt(null, 0, 2)), describeBlock(p6510));
		criterion("wrap-low", zeroPage != null && zeroPage.isInitialized() &&
			"02 03".equals(bytesAt(null, 2, 2)), describeBlock(zeroPage));
		criterion("wrap-vector", vectors != null && vectors.isInitialized() &&
			"56 45 43 54".equals(bytesAt(null, 0x300, 4)), describeBlock(vectors));
		criterion("wrap-file-offsets", fileOffset(high) == 2 && fileOffset(p6510) == 6 &&
			fileOffset(zeroPage) == 8 && fileOffset(vectors, 0x300) == 0x306,
			"offsets=" + fileOffset(high) + "," + fileOffset(p6510) + "," +
				fileOffset(zeroPage) + "," + fileOffset(vectors, 0x300));
	}

	// grm-gea: dedicated size/wrap-boundary coverage, following up grm-dvx. The
	// implementation already enforces every one of these limits (AbstractCbmPrgLoader.load());
	// these fixtures close the acceptance-test coverage gap.
	// The wrap flag is DERIVED from the persisted slice list, not read from a property of
	// its own (grm-hap item 4): AbstractCbmPrgLoader used to persist "Retro Machines.CBM
	// PRG Wrapped" alongside the slices, and this harness read it. Asserting the derived
	// value instead means these criteria check the number the analyzer actually acts on.
	protected boolean prgWrapped() {
		return AbstractCbmPrgLoader.getPrgPlacement(currentProgram).wrapped();
	}

	// Load $FFFE + 2 payload bytes: ends exactly at $FFFF, no wrap.
	protected void checkPrgNoWrap() {
		MemoryBlock high = blockAt("RAM_E000", 0xfffe);
		MemoryBlock lowBlock = currentProgram.getMemory().getBlock(addr(0));
		boolean wrappedProperty = prgWrapped();

		println("=== BANKDUMP BEGIN ===");
		println("HIGH " + describeBlock(high) + " BYTES " + bytesAt("RAM_E000", 0xfffe, 2));
		println("LOWBLOCK " + describeBlock(lowBlock));
		println("WRAPPED " + wrappedProperty);
		println("=== BANKDUMP END ===");

		criterion("nowrap-high", initializedOverlay(high, "RAM_E000") &&
			"10 11".equals(bytesAt("RAM_E000", 0xfffe, 2)), describeBlock(high));
		criterion("nowrap-property-false", !wrappedProperty, "wrapped=" + wrappedProperty);
		criterion("nowrap-file-offsets", fileOffset(high) == 2, "offset=" + fileOffset(high));
	}

	// Load $FFFE + 3 payload bytes: the 3rd byte wraps 1 byte into $0000 (P6510 DDR) --
	// the minimal wrap case, one byte over checkPrgNoWrap's boundary.
	protected void checkPrgWrap1() {
		MemoryBlock high = blockAt("RAM_E000", 0xfffe);
		MemoryBlock p6510 = currentProgram.getMemory().getBlock(addr(0));
		boolean wrappedProperty = prgWrapped();

		println("=== BANKDUMP BEGIN ===");
		println("HIGH " + describeBlock(high) + " BYTES " + bytesAt("RAM_E000", 0xfffe, 2));
		println("P6510 " + describeBlock(p6510) + " BYTES " + bytesAt(null, 0, 1));
		println("WRAPPED " + wrappedProperty);
		println("=== BANKDUMP END ===");

		criterion("wrap1-high", initializedOverlay(high, "RAM_E000") &&
			"10 11".equals(bytesAt("RAM_E000", 0xfffe, 2)), describeBlock(high));
		criterion("wrap1-p6510", p6510 != null && p6510.isInitialized() && !p6510.isOverlay() &&
			"12".equals(bytesAt(null, 0, 1)), describeBlock(p6510));
		criterion("wrap1-property-true", wrappedProperty, "wrapped=" + wrappedProperty);
		criterion("wrap1-file-offsets", fileOffset(high) == 2 && fileOffset(p6510) == 4,
			"offsets=" + fileOffset(high) + "," + fileOffset(p6510));
	}

	// Exactly 65536 (0x10000) payload bytes loaded at $0000: the largest a 16-bit CBM image
	// can hold, fills the whole address space with no wrap. mkprgloadtest.py's
	// full_space_payload() sets byte i to (i>>8)&0xFF, so with load_addr==0 (source offset ==
	// address) the byte at any address directly encodes that address's own high byte --
	// "source offsets preserved" is then just reading a handful of addresses back correctly.
	protected void checkPrgFull() {
		MemoryBlock a000 = blockAt("RAM_A000", 0xa000);
		MemoryBlock c000 = currentProgram.getMemory().getBlock(addr(0xc000));
		MemoryBlock e000 = blockAt("RAM_E000", 0xe000);
		boolean wrappedProperty = prgWrapped();

		println("=== BANKDUMP BEGIN ===");
		println("A000 " + describeBlock(a000) + " BYTES " + bytesAt("RAM_A000", 0xa000, 1));
		println("C000 " + describeBlock(c000) + " BYTES " + bytesAt(null, 0xc000, 1));
		println("E000 " + describeBlock(e000) + " BYTES " + bytesAt("RAM_E000", 0xe000, 1));
		println("LOW " + bytesAt(null, 0, 1));
		println("HIGH " + bytesAt("RAM_E000", 0xffff, 1));
		println("WRAPPED " + wrappedProperty);
		println("=== BANKDUMP END ===");

		criterion("full-a000", initializedOverlay(a000, "RAM_A000") &&
			"a0".equals(bytesAt("RAM_A000", 0xa000, 1)), describeBlock(a000));
		criterion("full-c000", c000 != null && c000.isInitialized() && !c000.isOverlay() &&
			"c0".equals(bytesAt(null, 0xc000, 1)), describeBlock(c000));
		criterion("full-e000", initializedOverlay(e000, "RAM_E000") &&
			"e0".equals(bytesAt("RAM_E000", 0xe000, 1)), describeBlock(e000));
		criterion("full-low-byte", "00".equals(bytesAt(null, 0, 1)), bytesAt(null, 0, 1));
		criterion("full-high-byte", "ff".equals(bytesAt("RAM_E000", 0xffff, 1)),
			bytesAt("RAM_E000", 0xffff, 1));
		criterion("full-property-false", !wrappedProperty, "wrapped=" + wrappedProperty);
		criterion("full-file-offsets", fileOffset(a000) == 2 + 0xa000 &&
			fileOffset(c000) == 2 + 0xc000 && fileOffset(e000) == 2 + 0xe000,
			"offsets=" + fileOffset(a000) + "," + fileOffset(c000) + "," + fileOffset(e000));
	}

	// grm-z15.2: a 0x101-byte payload at $FF00 wraps 1 byte to $0000, so the P6510 R6510
	// struct straddles a carved memory-block boundary -- DDR@$0000 lands in an initialized
	// 1-byte wrap block, PORT@$0001 in a separate uninitialized block. The grm-z15 review
	// flagged this (item #3, PLAUSIBLE) as a case where whole-struct createData might fail
	// and leave the port registers untyped; this fixture verifies it does NOT: in Ghidra
	// 12.1.2 Listing.createData spans the boundary fine as long as every address is backed
	// by some block, so the full R6510 struct is typed across the two blocks. Kept as a
	// permanent guard that this non-bug stays a non-bug.
	protected void checkPrgStraddle() {
		MemoryBlock ddrBlock = currentProgram.getMemory().getBlock(addr(0));
		MemoryBlock portBlock = currentProgram.getMemory().getBlock(addr(1));
		Data ddrData = currentProgram.getListing().getDefinedDataAt(addr(0));

		println("=== BANKDUMP BEGIN ===");
		println("DDRBLOCK " + describeBlock(ddrBlock));
		println("PORTBLOCK " + describeBlock(portBlock));
		println("DDRDATA " +
			(ddrData == null ? "<none>" : ddrData.getDataType().getName() + " len=" + ddrData.getLength()));
		println("BYTES " + bytesAt(null, 0, 1));
		println("=== BANKDUMP END ===");

		criterion("straddle-ddr-block-initialized", ddrBlock != null && ddrBlock.isInitialized(),
			describeBlock(ddrBlock));
		criterion("straddle-port-block-uninitialized",
			portBlock != null && !portBlock.isInitialized(), describeBlock(portBlock));
		criterion("straddle-distinct-blocks",
			ddrBlock != null && portBlock != null && ddrBlock != portBlock,
			"ddr=" + describeBlock(ddrBlock) + " port=" + describeBlock(portBlock));
		// The whole R6510 struct (len 2) must come back typed at $0000, spanning the
		// initialized DDR block and the uninitialized PORT block -- neither field silently
		// dropped.
		criterion("straddle-struct-typed",
			ddrData != null && "R6510".equals(ddrData.getDataType().getName()) &&
				ddrData.getLength() == 2,
			ddrData == null ? "<none>" :
				ddrData.getDataType().getName() + " len=" + ddrData.getLength());
		criterion("straddle-ddr-byte", "dd".equals(bytesAt(null, 0, 1)), bytesAt(null, 0, 1));
	}

	// grm-z15.1: load address $0000 lands in the non-executable P6510 io block --
	// an external entry point must still be recorded there (the label was already
	// unconditional), but no function should be marked on non-executable memory.
	protected void checkPrgEntry() {
		MemoryBlock block = currentProgram.getMemory().getBlock(addr(0));
		boolean isEntryPoint = currentProgram.getSymbolTable().isExternalEntryPoint(addr(0));
		boolean hasFunction = hasFunctionAt(0);
		boolean nonExecutable = block != null && !block.isExecute();
		boolean hasLabel = hasAnySymbol(0);

		println("=== BANKDUMP BEGIN ===");
		println("BLOCK " + describeBlock(block));
		println("ENTRYPOINT " + isEntryPoint);
		println("FUNCTION " + hasFunction);
		println("LABEL " + hasLabel);
		println("=== BANKDUMP END ===");

		criterion("prgentry-external-entry-point", isEntryPoint,
			"isExternalEntryPoint(0000)=" + isEntryPoint);
		criterion("prgentry-no-function", !hasFunction, "function@0000=" + hasFunction);
		criterion("prgentry-non-executable", nonExecutable, describeBlock(block));
		criterion("prgentry-label-exists", hasLabel, "symbols@0000 present=" + hasLabel);
	}

	// grm-z15.1: a 2-byte PRG (load-address header, zero payload) must still import --
	// the full memory map/symbols get built, but no PRG bytes are placed anywhere.
	protected void checkPrgEmpty() {
		MemoryBlock kernal = currentProgram.getMemory().getBlock("KERNAL");
		MemoryBlock prgBlock = currentProgram.getMemory().getBlock("PRG");
		boolean mapBuilt = kernal != null && kernal.isInitialized();
		boolean hasLabel = hasAnySymbol(0x0801);
		boolean noPrgBlock = prgBlock == null;

		println("=== BANKDUMP BEGIN ===");
		println("KERNAL " + describeBlock(kernal));
		println("LABEL@0801=" + hasLabel);
		println("PRGBLOCK " + describeBlock(prgBlock));
		println("=== BANKDUMP END ===");

		criterion("prgempty-map-built", mapBuilt, describeBlock(kernal));
		criterion("prgempty-label-exists", hasLabel, "symbols@0801 present=" + hasLabel);
		criterion("prgempty-no-prg-block", noPrgBlock, describeBlock(prgBlock));
	}

	protected void checkC000EmuRecovery() {
		long entryAddr = 0xc000;
		long payloadAddr = 0xc010;
		Address entry = addr(entryAddr);
		Address payload = addr(payloadAddr);

		RecoveryResult result = verifyEmuRecovery("c000-emu", entryAddr, payloadAddr, 8);

		byte[] recovered = result.recoveredBytes(payload, 8);
		MemoryBlock block = currentProgram.getMemory().getBlock(entry);

		println("=== BANKDUMP BEGIN ===");
		println("BLOCK " + describeBlock(block));
		println("STOPREASON " + result.stopReason());
		println("RECOVERED " + hex(recovered));
		println("=== BANKDUMP END ===");

		criterion("c000-base", block != null && block.isInitialized() && !block.isOverlay(),
			describeBlock(block));
	}

	// ------------------------------------------------------------------
	// C64DecryptLoopAnalyzer check (bead grm-1.7.2)
	// ------------------------------------------------------------------

	// Fixture contract from mkdecrypttest.py: constant-EOR (#$AA) in-place decrypt loop at
	// $2000 over $2010..$2017 with a JMP into the range, so the analyzer auto-applies and
	// creates the DECRYPTED_2010 overlay holding the plaintext $01..$08.
	protected static final String DECRYPT_CATEGORY = "C64DecryptLoopAnalyzer";
	protected static final long DECRYPT_ENTRY = 0x2000;
	protected static final String DECRYPT_OVERLAY = "DECRYPTED_2010";
	protected static final int DECRYPT_LEN = 8;

	// Tier 1 (constant key): the analyzer decrypts inline.
	protected void checkDecryptLoop() {
		verifyDecryptRecovery("decrypt", DECRYPT_ENTRY, DECRYPT_OVERLAY, DECRYPT_LEN);
	}

	// Tier 2 (rolling key): the analyzer routes to the EmulationRecovery harness (grm-yxn).
	// Fixture from mkrollingtest.py: EOR $2011,X rolling key over ciphertext at $2019.
	protected void checkRollingDecrypt() {
		verifyDecryptRecovery("rolling", 0x2000, "DECRYPTED_2019", 8);
	}

	/** Shared assertions for a recovered decrypt loop: the DECRYPTED overlay holds the
	 *  expected plaintext ($01..$08), a provenance bookmark sits at the decryptor entry, and
	 *  an EOL comment cross-links the two. Constant (inline) and rolling (emulated) recovery
	 *  converge on this same result, so one check covers both. */
	protected void verifyDecryptRecovery(String idPrefix, long entry, String overlayName, int len) {
		MemoryBlock overlay = currentProgram.getMemory().getBlock(overlayName);
		byte[] recovered = null;
		if (overlay != null) {
			try {
				byte[] buf = new byte[len];
				overlay.getBytes(overlay.getStart(), buf);
				recovered = buf;
			}
			catch (Exception e) {
				// leave recovered null -> criterion fails with a visible dump
			}
		}

		Bookmark mark = null;
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(entry))) {
			if (DECRYPT_CATEGORY.equals(bm.getCategory())) {
				mark = bm;
				break;
			}
		}
		String comment = eol(entry);
		byte[] expected = {1, 2, 3, 4, 5, 6, 7, 8};

		println("=== BANKDUMP BEGIN ===");
		println("OVERLAY " + (overlay == null ? "<missing>"
				: overlay.getName() + " " + fmt(overlay.getStart()) + "-" + fmt(overlay.getEnd())));
		println("DECRYPTED " + hex(recovered));
		println("BOOKMARK " + (mark == null ? "<none>"
				: mark.getTypeString() + " @" + fmt(mark.getAddress())));
		println("COMMENT " + comment);
		println("=== BANKDUMP END ===");

		criterion(idPrefix + "-overlay-exists", overlay != null, "block=" + overlayName);
		criterion(idPrefix + "-recovered", Arrays.equals(recovered, expected),
			"bytes=" + hex(recovered));
		criterion(idPrefix + "-note-bookmark", mark != null,
			"bm=" + (mark == null ? "<none>" : mark.getTypeString()));
		criterion(idPrefix + "-comment-links-overlay", comment.contains(overlayName),
			"eol=" + comment);
		boolean disassembled = overlay != null &&
			currentProgram.getListing().getInstructionAt(overlay.getStart()) != null;
		criterion(idPrefix + "-overlay-disassembled", disassembled, "instr@overlay=" + disassembled);
	}

	// Tier 2 SUSPECT case (grm-yxn): the key is read from a CIA register (EOR $DC00,X), which
	// the emulator answers with a policy value and logs as an IO read. Recovery still happens
	// (bytes = ciphertext, since the key reads as 0) but is downgraded to a WARNING bookmark.
	protected void checkSuspectDecrypt() {
		final long entry = 0x2000;
		final String overlayName = "DECRYPTED_2011";
		final int len = 8;
		byte[] expectedCipher = {(byte) 0xC1, (byte) 0xC2, (byte) 0xC3, (byte) 0xC4,
			(byte) 0xC5, (byte) 0xC6, (byte) 0xC7, (byte) 0xC8};

		MemoryBlock overlay = currentProgram.getMemory().getBlock(overlayName);
		byte[] recovered = null;
		if (overlay != null) {
			try {
				byte[] buf = new byte[len];
				overlay.getBytes(overlay.getStart(), buf);
				recovered = buf;
			}
			catch (Exception e) {
				// leave null -> criterion fails visibly
			}
		}

		Bookmark mark = null;
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(entry))) {
			if (DECRYPT_CATEGORY.equals(bm.getCategory())) {
				mark = bm;
				break;
			}
		}
		String type = mark == null ? "<none>" : mark.getTypeString();
		String comment = eol(entry);

		println("=== BANKDUMP BEGIN ===");
		println("OVERLAY " + (overlay == null ? "<missing>"
				: overlay.getName() + " " + fmt(overlay.getStart()) + "-" + fmt(overlay.getEnd())));
		println("RECOVERED " + hex(recovered));
		println("BOOKMARK " + type + (mark == null ? "" : " @" + fmt(mark.getAddress())));
		println("COMMENT " + comment);
		println("=== BANKDUMP END ===");

		criterion("suspect-overlay-exists", overlay != null, "block=" + overlayName);
		criterion("suspect-recovered-ciphertext", Arrays.equals(recovered, expectedCipher),
			"bytes=" + hex(recovered));
		criterion("suspect-warning-bookmark", "Warning".equals(type), "bm=" + type);
		criterion("suspect-comment-links-overlay", comment.contains(overlayName), "eol=" + comment);
		boolean disassembled = overlay != null &&
			currentProgram.getListing().getInstructionAt(overlay.getStart()) != null;
		criterion("suspect-overlay-disassembled", disassembled, "instr@overlay=" + disassembled);
	}

	// ------------------------------------------------------------------
	// CopyLoopAnalyzer / TransferMaterializer placement check (bead grm-1.7.1, grm-chu)
	// ------------------------------------------------------------------

	// Fixture contract from mkcopytest.py: a verbatim indexed copy loop whose counter init
	// (the provenance anchor) is always at $2000. copyloop.prg copies $200E -> $C000 (RAM_C000
	// wholly uninitialized -> carved IN PLACE at the block's own start) and ends with a JMP into
	// the range (AUTO -> disassembled); copydata.prg copies $200C -> $C100 (interior of RAM_C000
	// -> carved IN PLACE with a leftover fragment on each side) with no jump (CANDIDATE -> data,
	// not disassembled); copyoverlay.prg copies $2016 -> $200E, a destination that sits inside
	// this PRG's own already-initialized image, so the in-place precondition fails and the
	// materializer falls back to a byte-mapped OVERLAY (with a JMP into range, same as copyloop,
	// so bridgeJump gets exercised too).
	// Renamed with the analyzer in grm-1.7.6: the recognizer is not C64-specific, it is gated on
	// the descriptor plus a 6502/6510 language, so the NES boards get it too.
	protected static final String COPY_CATEGORY = "CopyLoopAnalyzer";
	protected static final long COPY_ENTRY = 0x2000;

	/** A carved leftover fragment expected to survive a carve: name, range, and (always)
	 *  uninitialized -- see {@code TransferMaterializer.carveInPlace}'s fragment naming. */
	protected static final class Neighbor {
		final String name;
		final long start;
		final long end;
		/** Overlay space the fragment lives in, or null for the default (base) space. A banked
		 *  carve (grm-bqs) splits its leftovers inside the occupant's overlay, not the base. */
		final String space;

		Neighbor(String name, long start, long end) {
			this(name, start, end, null);
		}

		Neighbor(String name, long start, long end, String space) {
			this.name = name;
			this.start = start;
			this.end = end;
			this.space = space;
		}
	}

	/** Where a {@link Neighbor} should be looked up: its overlay space, or the base space. */
	protected Address neighborAddr(Neighbor n) {
		return n.space == null ? addr(n.start) : overlayAddr(n.space, n.start);
	}

	/**
	 * grm-bqs: a copy loop landing under the KERNAL window. Run against both {@code copybanked}
	 * (no ROM dump) and {@code copybankedrom} (dump supplied), which must agree on everything but
	 * whether KERNAL holds bytes -- where a write lands is a hardware fact, not a fallback for an
	 * uninitialized ROM block, and the pre-fix code only misbehaved in the no-dump case precisely
	 * because it keyed on that.
	 *
	 * <p>The regression guard proper is {@code kernal-intact}: before the fix the no-dump import
	 * carved the ROM occupant, leaving the copy at base {@code $E000} with KERNAL shredded into
	 * {@code KERNAL / COPY_... / KERNAL_E008}.
	 *
	 * <p>The block is named {@code COPY_RAM_E000_e000}, not {@code COPY_e000}: this destination
	 * lives in the {@code RAM_E000} overlay, and grm-0p7 qualifies a recovered block's name with
	 * its address space whenever that space is not the default one, since the name doubles as the
	 * idempotence key and an offset alone is not unique across spaces
	 * ({@code retromachines.RecoveredBlockNames}).
	 */
	protected void checkCopyBanked() {
		boolean romSupplied = currentProgram.getName().contains("copybankedrom");

		verifyCopy("copybanked", "COPY_RAM_E000_e000", 0xe000, 0x200e,
			new byte[] {(byte) 0xa1, (byte) 0xa2, (byte) 0xa3, (byte) 0xa4, (byte) 0xa5,
				(byte) 0xa6, (byte) 0xa7, (byte) 0xa8},
			true, false, true,
			new Neighbor[] {new Neighbor("RAM_E000_E008", 0xe008, 0xffff, "RAM_E000")},
			addr(COPY_ENTRY), null);

		MemoryBlock copy = currentProgram.getMemory().getBlock("COPY_RAM_E000_e000");
		criterion("copybanked-copyblock-space",
			copy != null && "RAM_E000".equals(copy.getStart().getAddressSpace().getName()),
			"space=" + (copy == null ? "<missing>"
					: copy.getStart().getAddressSpace().getName()) + " expected=RAM_E000");

		// The ROM occupant must be whole, still named KERNAL, and initialized iff a dump was given.
		MemoryBlock kernal = currentProgram.getMemory().getBlock(addr(0xe000));
		boolean intact = kernal != null && "KERNAL".equals(kernal.getName()) &&
			kernal.getStart().equals(addr(0xe000)) && kernal.getEnd().equals(addr(0xffff)) &&
			kernal.isInitialized() == romSupplied;
		criterion("copybanked-kernal-intact", intact,
			"kernal=" + (kernal == null ? "<missing>"
					: kernal.getName() + " " + fmt(kernal.getStart()) + "-" + fmt(kernal.getEnd()) +
						" init=" + kernal.isInitialized()) +
				" expectedInit=" + romSupplied);

		// Belt-and-braces on the same point from the other side: no carve fragment of the ROM
		// block may exist anywhere, under any name.
		String strays = "";
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (b.getName().startsWith("KERNAL_")) {
				strays += (strays.isEmpty() ? "" : ",") + b.getName();
			}
		}
		criterion("copybanked-kernal-not-split", strays.isEmpty(),
			"strayFragments=" + (strays.isEmpty() ? "<none>" : strays));

		// The entering JMP must reach the copy. Deliberately "a reference", not "the primary
		// one": CopyLoopAnalyzer's bridgeJump and BoardBankAnalyzer's addOverlayRef both call
		// setPrimary, so which one wins is not a contract worth pinning here.
		Reference bridged = findOverlayRef(0x200b, "RAM_E000", 0xe000);
		criterion("copybanked-callref-reaches-copy",
			bridged != null &&
				currentProgram.getListing().getInstructionAt(bridged.getToAddress()) != null,
			"ref=" + (bridged == null ? "<none>"
					: bridged.getToAddress().getAddressSpace().getName() + ":" +
						fmt(bridged.getToAddress()) + " " + bridged.getReferenceType()));

		// grm-phv: MosConstantReferenceAnalyzer's whole reason for existing (bead grm-bqs) is
		// that the STA $E000,X at $2005 must reference the addressing mode's BASE, $E000, not
		// whichever address the symbolic propagator's loop walk happened to compute
		// ($E006/$E007 under stock ConstantPropagationAnalyzer -- see that class's javadoc).
		// findOverlayRef already re-homes through BoardBankAnalyzer's overlay retargeting, so
		// this is the same "did the write land in RAM_E000" check as callref-reaches-copy
		// above, aimed at the STA instead of the entering JMP.
		Reference indexedWrite = findOverlayRef(0x2005, "RAM_E000", 0xe000);
		criterion("copybanked-indexed-write-base", indexedWrite != null,
			"ref=" + (indexedWrite == null ? "<none>"
					: indexedWrite.getToAddress().getAddressSpace().getName() + ":" +
						fmt(indexedWrite.getToAddress()) + " " + indexedWrite.getReferenceType()));
	}

	/**
	 * grm-9a0: the mirror of {@link #checkCopyBanked} -- a copy loop whose SOURCE is a banked,
	 * NON-HOME occupant. The fixture (mkcopytest.py {@code copybankedsrc.prg}) pins the bank state
	 * itself with {@code LDA #$33 / STA $01} (CHAREN=0), which banks the character ROM in over
	 * {@code $D000}, then copies 8 bytes of it down to {@code $C000} -- an ordinary base-space RAM
	 * destination, outside every window, so the read is the only banked thing in the fixture and
	 * the source half is isolated. Loop top (the {@code LDA}) is {@code $2006}, the counter init
	 * and provenance anchor is the {@code LDX} at {@code $2004}, the entering {@code JMP} is
	 * {@code $200F}.
	 *
	 * <p>Run against both {@code copybankedsrc} (no dump) and {@code copybankedsrcrom}
	 * ({@code -loader-chargenRom}), and unlike the copybanked pair these two MUST DIFFER: an
	 * unreadable source materializes nothing (TransferMaterializer gate 0), a readable one
	 * materializes the character ROM's own bytes. That difference is the regression guard. Before
	 * the fix {@code LoopIdioms.indexedBase} named base-space {@code $D000} -- the {@code CHARIO}
	 * window's HOME occupant, which is IO -- in both runs, so supplying the dump changed nothing
	 * and the character ROM was never read.
	 *
	 * <p>{@code srcref-resolved} is the mechanism check proper and holds in BOTH runs, since where
	 * a read lands is a hardware fact independent of whether the user supplied an image.
	 */
	protected void checkCopyBankedSrc() {
		boolean romSupplied = currentProgram.getName().contains("copybankedsrcrom");
		final long srcEntry = 0x2004;    // the LDX -- provenance anchor, not $2000 here
		final long ldaSite = 0x2006;     // the loop top, whose READ reference carries the answer

		if (romSupplied) {
			// mkromtest.py's chargen.bin is byte[i] = (i & 0xFF) ^ 0xAA, so $D000..$D007 reads
			// AA AB A8 A9 AE AF AC AD -- bytes that exist nowhere in the PRG image, so seeing them
			// at the destination proves the character ROM itself was the source.
			verifyCopy("copybankedsrc", "COPY_c000", 0xc000, 0xd000,
				new byte[] {(byte) 0xaa, (byte) 0xab, (byte) 0xa8, (byte) 0xa9, (byte) 0xae,
					(byte) 0xaf, (byte) 0xac, (byte) 0xad},
				true, true, true,
				new Neighbor[] {new Neighbor("RAM_C000_C008", 0xc008, 0xcfff)},
				addr(srcEntry), addr(0x200f));
		}
		else {
			checkCopyBankedSrcRefused(srcEntry);
		}

		// The banked-source resolution itself: BoardBankAnalyzer must have re-homed the LDA's READ
		// reference into the CHARGEN overlay, which is what LoopIdioms.overlayAccessTarget reads.
		// Asserted in both runs -- the pre-fix code had no such consumer, not no such reference.
		Reference srcRef = findOverlayRef(ldaSite, "CHARGEN", 0xd000);
		criterion("copybankedsrc-srcref-resolved",
			srcRef != null && srcRef.getReferenceType().isRead(),
			"ref=" + (srcRef == null ? "<none>"
					: srcRef.getToAddress().getAddressSpace().getName() + ":" +
						fmt(srcRef.getToAddress()) + " " + srcRef.getReferenceType()));

		// The CHARGEN occupant must be a whole 4K overlay block either way, initialized iff a dump
		// was supplied. Nothing in this fixture may carve or split the source.
		MemoryBlock chargen = currentProgram.getMemory().getBlock("CHARGEN");
		boolean chargenOk = chargen != null &&
			chargen.getStart().getAddressSpace().isOverlaySpace() &&
			chargen.getStart().getOffset() == 0xd000 && chargen.getEnd().getOffset() == 0xdfff &&
			chargen.isInitialized() == romSupplied;
		criterion("copybankedsrc-chargen-intact", chargenOk,
			"chargen=" + (chargen == null ? "<missing>"
					: chargen.getName() + " " + fmt(chargen.getStart()) + "-" +
						fmt(chargen.getEnd()) + " init=" + chargen.isInitialized()) +
				" expectedInit=" + romSupplied);
	}

	/**
	 * The no-dump half of {@link #checkCopyBankedSrc}: the recognizer resolved the source into the
	 * CHARGEN overlay, which holds no bytes, so TransferMaterializer's gate 0 must refuse and place
	 * nothing -- and say so at the copy site rather than silently. RAM_C000 must also survive whole,
	 * the same collateral-damage check {@link #checkCopyData} makes.
	 */
	protected void checkCopyBankedSrcRefused(long srcEntry) {
		MemoryBlock copy = currentProgram.getMemory().getBlock("COPY_c000");
		MemoryBlock ram = currentProgram.getMemory().getBlock(addr(0xc000));
		String ramLine = ram == null ? "<none>"
				: ram.getName() + " " + fmt(ram.getStart()) + "-" + fmt(ram.getEnd()) +
					" init=" + ram.isInitialized();
		boolean intact = ram != null && "RAM_C000".equals(ram.getName()) &&
			ram.getStart().getOffset() == 0xc000 && ram.getEnd().getOffset() == 0xcfff &&
			!ram.isInitialized();

		Bookmark mark = null;
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(srcEntry))) {
			if (COPY_CATEGORY.equals(bm.getCategory())) {
				mark = bm;
				break;
			}
		}
		String note = mark == null ? "<none>" : mark.getComment();

		// The refusal note reads "copy <space:offset> -> <space:offset> not materialized: ...", so
		// the source token it names is the ONLY place this run records which occupant the
		// recognizer resolved to. Without it the no-dump run's dump is bit-identical before and
		// after the fix (both refuse, for different reasons), and only the dump-supplied run would
		// guard the regression. Pre-fix this read "RAM:d000" -- the IO home occupant.
		String declinedSource = "<none>";
		int arrow = note.indexOf(" -> ");
		if (note.startsWith("copy ") && arrow > 0) {
			declinedSource = note.substring("copy ".length(), arrow);
		}

		println("=== BANKDUMP BEGIN ===");
		println("COPYBLOCK " + (copy == null ? "<none>" : copy.getName()));
		println("SOURCE " + declinedSource);
		println("NEIGHBORS " + ramLine);
		println("BOOKMARK " + (mark == null ? "<none>" : mark.getTypeString()));
		println("DECLINED " + (note.contains("source bytes are uninitialized") ? "yes" : "no"));
		println("=== BANKDUMP END ===");

		criterion("copybankedsrc-norom-not-materialized", copy == null,
			"block=" + (copy == null ? "<none>" : copy.getName()));
		criterion("copybankedsrc-norom-destination-unsplit", intact, "ram=" + ramLine);
		criterion("copybankedsrc-norom-refusal-recorded",
			mark != null && "Warning".equals(mark.getTypeString()) &&
				note.contains("source bytes are uninitialized"),
			"bm=" + (mark == null ? "<none>" : mark.getTypeString() + " " + note));
		criterion("copybankedsrc-norom-source-resolved", "CHARGEN:d000".equals(declinedSource),
			"declinedSource=" + declinedSource + " expected=CHARGEN:d000");
	}

	/**
	 * grm-cpj: the SAME-BASE cross-occupant copy. The fixture (mkcopytest.py
	 * {@code copybankedinplace.prg}) is {@code LDA $A000,X / STA $A000,X} -- load and store share
	 * a base address, which {@code CopyLoopAnalyzer.tryRecognize} used to reject outright as an
	 * in-place transform. It is a copy because the two sides reach DIFFERENT occupants: the read
	 * is the BASIC ROM (the LOROM window's home occupant, base space), the write lands in the
	 * RAM_A000 overlay underneath it. Loop top {@code $2002}, counter init and provenance anchor
	 * the {@code LDX} at {@code $2000}, entering {@code JMP} at {@code $200B}.
	 *
	 * <p>Run against both {@code copybankedinplace} (no dump) and {@code copybankedinplacerom}
	 * ({@code -loader-basicRom}); like copybankedsrc the two MUST DIFFER -- gate 0 refuses an
	 * uninitialized BASIC, the dump materializes BASIC's own bytes inside RAM_A000. Before the
	 * fix neither run recognized the loop at all, so the no-dump run's refusal bookmark is itself
	 * regression evidence: it only exists because the same-base loop was admitted.
	 */
	protected void checkCopyBankedInPlace() {
		boolean romSupplied = currentProgram.getName().contains("copybankedinplacerom");
		final long ldaSite = 0x2002;
		final long staSite = 0x2005;

		if (romSupplied) {
			// mkromtest.py's basic.bin is byte[i] = (i & 0xFF) ^ 0x55, so $A000..$A007 reads
			// 55 54 57 56 51 50 53 52 -- bytes that exist nowhere in the PRG image.
			verifyCopy("copybankedinplace", "COPY_RAM_A000_a000", 0xa000, 0xa000,
				new byte[] {0x55, 0x54, 0x57, 0x56, 0x51, 0x50, 0x53, 0x52},
				true, false, true,
				new Neighbor[] {new Neighbor("RAM_A000_A008", 0xa008, 0xbfff, "RAM_A000")},
				addr(COPY_ENTRY), null);
			MemoryBlock copy = currentProgram.getMemory().getBlock("COPY_RAM_A000_a000");
			criterion("copybankedinplace-copyblock-space",
				copy != null && "RAM_A000".equals(copy.getStart().getAddressSpace().getName()),
				"space=" + (copy == null ? "<missing>"
						: copy.getStart().getAddressSpace().getName()) + " expected=RAM_A000");
			// The entering JMP $A000 at $200B must reach the copy inside RAM_A000 (same
			// deliberately-loose "a reference, not the primary one" as copybanked's check).
			Reference bridged = findOverlayRef(0x200b, "RAM_A000", 0xa000);
			criterion("copybankedinplace-callref-reaches-copy",
				bridged != null &&
					currentProgram.getListing().getInstructionAt(bridged.getToAddress()) != null,
				"ref=" + (bridged == null ? "<none>"
						: bridged.getToAddress().getAddressSpace().getName() + ":" +
							fmt(bridged.getToAddress())));
		}
		else {
			MemoryBlock copy = currentProgram.getMemory().getBlock("COPY_RAM_A000_a000");
			MemoryBlock ram = currentProgram.getMemory().getBlock("RAM_A000");
			String ramLine = ram == null ? "<none>"
					: ram.getName() + " " + fmt(ram.getStart()) + "-" + fmt(ram.getEnd()) +
						" init=" + ram.isInitialized();
			boolean intact = ram != null && ram.getStart().getOffset() == 0xa000 &&
				ram.getEnd().getOffset() == 0xbfff;
			Bookmark mark = null;
			for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(COPY_ENTRY))) {
				if (COPY_CATEGORY.equals(bm.getCategory())) {
					mark = bm;
					break;
				}
			}
			String note = mark == null ? "<none>" : mark.getComment();
			println("=== BANKDUMP BEGIN ===");
			println("COPYBLOCK " + (copy == null ? "<none>" : copy.getName()));
			println("NEIGHBORS " + ramLine);
			println("BOOKMARK " + (mark == null ? "<none>" : mark.getTypeString()));
			println("DECLINED " + (note.contains("source bytes are uninitialized") ? "yes" : "no"));
			println("=== BANKDUMP END ===");
			criterion("copybankedinplace-norom-not-materialized", copy == null,
				"block=" + (copy == null ? "<none>" : copy.getName()));
			criterion("copybankedinplace-norom-destination-unsplit", intact, "ram=" + ramLine);
			// The loop WAS recognized (the pre-fix code rejected it before reaching the
			// materializer), and refused only because BASIC holds no bytes without a dump.
			criterion("copybankedinplace-norom-recognized-then-refused",
				mark != null && "Warning".equals(mark.getTypeString()) &&
					note.contains("source bytes are uninitialized"),
				"bm=" + (mark == null ? "<none>" : mark.getTypeString() + " " + note));
		}

		// The occupancy split that makes this a copy, asserted in both runs: the STA's write
		// reference was re-homed into RAM_A000 while the LDA's read reference stayed on the
		// base-space BASIC block. This is exactly the pair tryRecognize compares.
		Reference writeRef = findOverlayRef(staSite, "RAM_A000", 0xa000);
		criterion("copybankedinplace-write-rehomed",
			writeRef != null && writeRef.getReferenceType().isWrite(),
			"ref=" + (writeRef == null ? "<none>"
					: writeRef.getToAddress().getAddressSpace().getName() + ":" +
						fmt(writeRef.getToAddress()) + " " + writeRef.getReferenceType()));
		boolean readInBase = false;
		String readLine = "<none>";
		for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(addr(ldaSite))) {
			if (r.getReferenceType().isRead()) {
				readInBase = !r.getToAddress().getAddressSpace().isOverlaySpace();
				readLine = r.getToAddress().getAddressSpace().getName() + ":" + fmt(r.getToAddress());
				break;
			}
		}
		criterion("copybankedinplace-read-in-base", readInBase,
			"read ref=" + readLine + " expected base space (BASIC, the home occupant)");

		// The ROM occupant must be whole, still named BASIC, initialized iff a dump was given.
		MemoryBlock basic = currentProgram.getMemory().getBlock("BASIC");
		boolean basicOk = basic != null && basic.getStart().getOffset() == 0xa000 &&
			basic.getEnd().getOffset() == 0xbfff && basic.isInitialized() == romSupplied;
		criterion("copybankedinplace-basic-intact", basicOk,
			"basic=" + (basic == null ? "<missing>"
					: fmt(basic.getStart()) + "-" + fmt(basic.getEnd()) + " init=" +
						basic.isInitialized()) + " expectedInit=" + romSupplied);
	}

	protected void checkCopyLoop() {
		verifyCopy("copyloop", "COPY_c000", 0xc000, 0x200e,
			new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, true, true, true,
			new Neighbor[] {new Neighbor("RAM_C000_C008", 0xc008, 0xcfff)},
			addr(COPY_ENTRY), addr(0x200b));
	}

	/**
	 * The evidence gate: this fixture's loop ends in RTS with nothing jumping into $C100, so the
	 * recognizer must place NOTHING and say why. It used to assert the opposite -- a materialized
	 * COPY_c100 left undisassembled -- until real NES cartridges showed that materializing on the
	 * loop shape alone snapshots ordinary runtime buffers (Ironsword over the stack page, Mega Man
	 * in work RAM). What is asserted here is therefore the absence of a block AND the absence of
	 * collateral damage: RAM_C000 must still be one whole uninitialized block, not split around a
	 * carve that should never have happened.
	 */
	protected void checkCopyData() {
		MemoryBlock copy = currentProgram.getMemory().getBlock("COPY_c100");
		MemoryBlock ram = currentProgram.getMemory().getBlock(addr(0xc000));
		String ramLine = ram == null ? "<none>"
				: ram.getName() + " " + fmt(ram.getStart()) + "-" + fmt(ram.getEnd()) +
					" init=" + ram.isInitialized();
		boolean intact = ram != null && "RAM_C000".equals(ram.getName()) &&
			ram.getStart().getOffset() == 0xc000 && ram.getEnd().getOffset() == 0xcfff &&
			!ram.isInitialized();

		Bookmark mark = null;
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(COPY_ENTRY))) {
			if (COPY_CATEGORY.equals(bm.getCategory())) {
				mark = bm;
				break;
			}
		}
		String note = mark == null ? "<none>" : mark.getComment();

		println("=== BANKDUMP BEGIN ===");
		println("COPYBLOCK " + (copy == null ? "<none>" : copy.getName()));
		println("NEIGHBORS " + ramLine);
		println("BOOKMARK " + (mark == null ? "<none>" : mark.getTypeString()));
		println("DECLINED " + (note.contains("NOT materialized") ? "yes" : "no"));
		println("=== BANKDUMP END ===");

		criterion("copydata-not-materialized", copy == null,
			"block=" + (copy == null ? "<none>" : copy.getName()));
		criterion("copydata-destination-block-unsplit", intact, "ram=" + ramLine);
		// Recognized-but-declined must still be visible to the analyst, or a real run-from-
		// elsewhere copy the recognizer saw and skipped would vanish without trace.
		criterion("copydata-declined-bookmark",
			mark != null && note.contains("NOT materialized"), "bm=" + note);
	}

	protected void checkCopyOverlay() {
		verifyCopy("copyoverlay", "COPY_200e", 0x200e, 0x2016,
			new byte[] {(byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95,
				(byte) 0x96, (byte) 0x97, (byte) 0x98},
			true, false, false, new Neighbor[0], addr(COPY_ENTRY), addr(0x200b));
	}

	/**
	 * The evidence gate's program-wide half (grm-k5m): the only flow into $C000 is a JSR at
	 * $2003, BEFORE the loop and far outside its lookahead. Same assertions as copyloop, with
	 * the loop's counter init at $2007 and the call site as the jump site -- the copy must be
	 * carved, disassembled and reachable exactly as if the jump had been adjacent.
	 */
	protected void checkCopyFar() {
		verifyCopy("copyfar", "COPY_c000", 0xc000, 0x2015,
			new byte[] {(byte) 0xA9, 0x42, 0x60, (byte) 0xEA, (byte) 0xEA, (byte) 0xEA,
				(byte) 0xEA, (byte) 0xEA},
			true, true, true, new Neighbor[] {new Neighbor("RAM_C000_C008", 0xc008, 0xcfff)},
			addr(0x2007), addr(0x2003));
	}

	/**
	 * The late-evidence case (grm-k5m): loop B ($2000 -> $C100) is declined on first sight -- its
	 * payload starts with two zero bytes, so the decode leg fails too -- loop A ($200B -> $C000)
	 * is proven by its adjacent JMP, and A's copied code is the JSR $C102 that re-admits B on the
	 * analyzer's next round, entering it MID-RANGE. Both copies must end up carved; A is
	 * disassembled from its start, B from $C102 (the call target, which the recognizer hands the
	 * materializer as the entry point) with $C100-$C101 left as data. RAM_C000's leftovers are
	 * the gap between the two carves and the tail after the second.
	 */
	protected void checkCopyChain() {
		verifyCopy("copychain-a", "COPY_c000", 0xc000, 0x2019,
			new byte[] {0x20, 0x02, (byte) 0xC1, 0x60, (byte) 0xEA, (byte) 0xEA, (byte) 0xEA,
				(byte) 0xEA},
			true, true, true, new Neighbor[] {new Neighbor("RAM_C000_C008", 0xc008, 0xc0ff)},
			addr(0x200b), addr(0x2016));

		MemoryBlock b = currentProgram.getMemory().getBlock("COPY_c100");
		MemoryBlock tail = currentProgram.getMemory().getBlock(addr(0xc108));
		Listing listing = currentProgram.getListing();
		Instruction entry = listing.getInstructionAt(addr(0xc102));
		boolean headIsData = listing.getInstructionAt(addr(0xc100)) == null &&
			listing.getInstructionAt(addr(0xc101)) == null;
		Function fn = currentProgram.getFunctionManager().getFunctionAt(addr(0xc102));
		Reference callref = primaryReferenceFrom(addr(0xc000));
		String c = listing.getComment(CommentType.EOL, addr(COPY_ENTRY));
		String comment = c == null ? "" : c;
		Bookmark declined = null;
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(COPY_ENTRY))) {
			if (COPY_CATEGORY.equals(bm.getCategory()) &&
				bm.getComment().startsWith("copy-shaped loop")) {
				declined = bm;
			}
		}
		String bytes;
		try {
			byte[] buf = new byte[8];
			b.getBytes(b.getStart(), buf);
			bytes = hex(buf);
		}
		catch (Exception e) {
			bytes = "<unreadable>";
		}

		println("=== BANKDUMP BEGIN ===");
		println("COPYBLOCK " + (b == null ? "<missing>"
				: b.getName() + " " + fmt(b.getStart()) + "-" + fmt(b.getEnd()) + " init=" +
					b.isInitialized()));
		println("NEIGHBORS " + (tail == null ? "<none>"
				: tail.getName() + " " + fmt(tail.getStart()) + "-" + fmt(tail.getEnd()) +
					" init=" + tail.isInitialized()));
		println("COPIED " + bytes);
		println("ENTRY " + (entry == null ? "<none>" : fmt(entry.getAddress()) + " " + entry));
		println("HEADDATA " + headIsData);
		println("FUNCTION " + (fn == null ? "<none>" : fn.getName()));
		println("CALLREF " + (callref == null ? "<none>" : fmt(callref.getToAddress())));
		println("DECLINEDNOTE " + (declined == null ? "gone" : "still present"));
		println("COMMENT " + comment);
		println("=== BANKDUMP END ===");

		criterion("copychain-b-copyblock-exists", b != null && b.getStart().getOffset() == 0xc100,
			"block=" + (b == null ? "<missing>" : fmt(b.getStart())));
		criterion("copychain-b-copied-bytes", "00 00 a9 42 60 ea ea ea".equals(bytes),
			"bytes=" + bytes);
		criterion("copychain-b-entered-mid-range", entry != null && fn != null,
			"entry=" + entry + " fn=" + fn);
		criterion("copychain-b-head-left-as-data", headIsData, "headIsData=" + headIsData);
		criterion("copychain-b-callref-hits-entry",
			callref != null && callref.getToAddress().equals(addr(0xc102)),
			"callref=" + (callref == null ? "<none>" : fmt(callref.getToAddress())));
		criterion("copychain-b-declined-note-retracted", declined == null,
			"declined=" + (declined == null ? "gone" : declined.getComment()));
		criterion("copychain-b-comment-links-block", comment.contains("COPY_c100"),
			"eol=" + comment);
		criterion("copychain-b-neighbors", tail != null &&
			"RAM_C000_C008_C108".equals(tail.getName()) && tail.getEnd().getOffset() == 0xcfff &&
			!tail.isInitialized(), "tail=" + (tail == null ? "<none>" : tail.getName()));
	}

	// ------------------------------------------------------------------
	// CopyLoopAnalyzer on an NES ROM with bank overlays (bead grm-1.7.6)
	// ------------------------------------------------------------------

	// Fixture contract from mknescopytest.py (nescopytest.nes, MMC1 / iNES mapper 1): RESET
	// runs in the fixed WC000 window, commits prg_bank=1 through the unrolled serial-shift
	// chain, and JMPs into $8000 -- which BoardBankAnalyzer retargets into the bank-1 overlay
	// W8000_B1. The copy loop therefore EXECUTES inside a bank overlay:
	//   W8000_B1::8000  LDX #$04 / LDA $8010,X / STA $6C90,X / DEX / BPL / JMP $6C90
	// Its source ($8010) is inside that same overlay, but its destination ($6C90) is the
	// base-space PRG_RAM block nes-mmc1.yaml declares at $6000-$7FFF -- an offset OUTSIDE the
	// executing overlay's own $8000-$BFFF range. This fixture is the only automated coverage
	// of grm-1.7.6's widened CopyLoopAnalyzer gate (a descriptor + a 6502/6510 language rather
	// than "the C64 loader ran"), and the only place the destination address of a recognized
	// copy has to cross out of an overlay space at all.
	//
	// That crossing re-homes itself, which is why no code here does it: Ghidra's
	// OverlayAddressSpace.getAddress(long) (:128-134) falls back to the overlayed base space
	// whenever contains(offset) is false, and ProgramOverlayAddressSpace.contains (:90-98) tests
	// the overlay's defined block set -- so LoopIdioms.indexedBase already yields RAM:6c90. The
	// "nescopy-in-base-space" criterion below is the regression guard for that contract: if the
	// destination ever stayed in the executing overlay, canCarve would refuse it (dstStart in an
	// overlay space) and the copy would silently degrade to a byte-mapped overlay instead of the
	// in-place carve asserted here.
	protected static final String NESCOPY_OVERLAY = "W8000_B1";
	protected static final long NESCOPY_ENTRY = 0x8000;   // the LDX #imm -- provenance anchor
	protected static final long NESCOPY_JUMP = 0x800b;    // the JMP into the copied range
	protected static final long NESCOPY_SRC = 0x8010;
	protected static final long NESCOPY_DST = 0x6c90;

	protected void checkNesCopyLoop() {
		// PRG_RAM ($6000-$7FFF) is uninitialized and the destination sits in its interior, so
		// carveInPlace splits a leftover fragment off each side: the lower piece keeps the
		// original name, the upper one is renamed "<orig>_<start>".
		verifyCopy("nescopy", "COPY_6c90", NESCOPY_DST, NESCOPY_SRC,
			new byte[] {(byte) 0xa9, (byte) 0x5a, (byte) 0x85, (byte) 0x10, (byte) 0x60},
			true, true, true,
			new Neighbor[] {new Neighbor("PRG_RAM", 0x6000, 0x6c8f),
				new Neighbor("PRG_RAM_6C95", 0x6c95, 0x7fff)},
			overlayAddr(NESCOPY_OVERLAY, NESCOPY_ENTRY),
			overlayAddr(NESCOPY_OVERLAY, NESCOPY_JUMP));

		// The recognizer only ever sees this loop if the retargeted JMP $8000 actually put
		// disassembled instructions in the bank-1 overlay; assert that directly so a
		// regression there fails as "the loop never ran from an overlay" rather than as a
		// confusing cascade of missing-copy failures.
		Address loopTop = overlayAddr(NESCOPY_OVERLAY, NESCOPY_ENTRY);
		Instruction ldx = currentProgram.getListing().getInstructionAt(loopTop);
		criterion("nescopy-loop-runs-from-overlay",
			ldx != null && loopTop.getAddressSpace().isOverlaySpace(),
			"space=" + loopTop.getAddressSpace().getName() + " instr=" +
				(ldx == null ? "<none>" : ldx.getMnemonicString()));
	}

	/** Shared assertions for a recovered verbatim copy under the grm-chu placement policy: the
	 *  COPY_xxxx block holds the source bytes (read directly for an in-place carve, through the
	 *  1:1 map for an overlay), its recorded provenance points back at the source, a NOTE
	 *  provenance bookmark + EOL comment cross-link the copy loop, any carved leftover fragments
	 *  are present and still uninitialized, the payload is disassembled only when the copy is
	 *  proven code (AUTO), and -- the point of grm-chu -- the entering JMP's primary reference
	 *  actually resolves into the materialized copy, wherever it landed.
	 *
	 *  <p>{@code entry} (the loop-counter init the provenance bookmark/comment hang off) and
	 *  {@code jumpSite} are full {@link Address}es, not base-space offsets: on the NES fixture
	 *  the loop executes inside a bank overlay, so both live in an overlay space (grm-1.7.6).
	 *  {@code srcStart} stays an offset -- {@code recordedSource} already strips the space
	 *  prefix off the recorded provenance, which is what makes the same comparison work for an
	 *  overlay source. */
	protected void verifyCopy(String idPrefix, String blockName, long dstStart, long srcStart,
			byte[] expected, boolean expectDisassembled, boolean expectInBaseSpace,
			boolean expectBlockInitialized, Neighbor[] expectedNeighbors, Address entry,
			Address jumpSite) {
		MemoryBlock block = currentProgram.getMemory().getBlock(blockName);
		boolean inBaseSpace = block != null && block.getStart().getAddressSpace()
				.equals(currentProgram.getAddressFactory().getDefaultAddressSpace());
		String placementLabel = block == null ? "<missing>"
				: block.getType() == MemoryBlockType.BYTE_MAPPED ? "overlay"
				: inBaseSpace ? "inplace" : "banked";

		byte[] recovered = null;
		String copiedLine;
		if (block == null) {
			copiedLine = "<none>";
		}
		else {
			try {
				byte[] buf = new byte[expected.length];
				block.getBytes(block.getStart(), buf);
				recovered = buf;
				copiedLine = hex(buf);
			}
			catch (Exception e) {
				copiedLine = "<unreadable>";
			}
		}

		String source = recordedSource(block, inBaseSpace);

		Bookmark mark = null;
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(entry)) {
			if (COPY_CATEGORY.equals(bm.getCategory())) {
				mark = bm;
				break;
			}
		}
		String c = currentProgram.getListing().getComment(CommentType.EOL, entry);
		String comment = c == null ? "" : c;
		boolean disassembled =
			block != null && currentProgram.getListing().getInstructionAt(block.getStart()) != null;

		Reference callref = jumpSite == null ? null : primaryReferenceFrom(jumpSite);
		String callrefLine = callref == null ? "<none>"
				: callref.getToAddress().getAddressSpace().getName() + ":" +
					fmt(callref.getToAddress());

		println("=== BANKDUMP BEGIN ===");
		println("COPYBLOCK " + (block == null ? "<missing>"
				: block.getName() + " " + fmt(block.getStart()) + "-" + fmt(block.getEnd()) +
					" init=" + block.isInitialized()));
		println("PLACEMENT " + placementLabel);
		println("SPACE " + (block == null ? "<none>" : block.getStart().getAddressSpace().getName()));
		println("SOURCE " + source);
		if (expectedNeighbors.length == 0) {
			println("NEIGHBORS <none>");
		}
		else {
			for (Neighbor n : expectedNeighbors) {
				MemoryBlock nb = currentProgram.getMemory().getBlock(neighborAddr(n));
				println("NEIGHBORS " + (nb == null ? n.name + " <missing>"
						: nb.getName() + " " + fmt(nb.getStart()) + "-" + fmt(nb.getEnd()) +
							" init=" + nb.isInitialized()));
			}
		}
		println("COPIED " + copiedLine);
		println("DISASM " + disassembled);
		println("CALLREF " + callrefLine);
		println("BOOKMARK " + (mark == null ? "<none>"
				: mark.getTypeString() + " @" + fmt(mark.getAddress())));
		println("COMMENT " + comment);
		println("=== BANKDUMP END ===");

		criterion(idPrefix + "-copyblock-exists",
			block != null && block.getStart().getOffset() == dstStart,
			"block=" + blockName + " start=" + (block == null ? "<missing>" : fmt(block.getStart())));
		criterion(idPrefix + "-in-base-space", inBaseSpace == expectInBaseSpace,
			"inBaseSpace=" + inBaseSpace + " expected=" + expectInBaseSpace);
		criterion(idPrefix + "-block-initialized",
			block != null && block.isInitialized() == expectBlockInitialized,
			"initialized=" + (block == null ? "<missing>" : block.isInitialized()) +
				" expected=" + expectBlockInitialized);
		criterion(idPrefix + "-source-recorded", source.equals(String.format("%04x", srcStart)),
			"source=" + source);
		criterion(idPrefix + "-copied-bytes", Arrays.equals(recovered, expected),
			"bytes=" + copiedLine);
		criterion(idPrefix + "-note-bookmark", mark != null && "Note".equals(mark.getTypeString()),
			"bm=" + (mark == null ? "<none>" : mark.getTypeString()));
		criterion(idPrefix + "-comment-links-block", comment.contains(blockName),
			"eol=" + comment);
		criterion(idPrefix + "-disassembly", disassembled == expectDisassembled,
			"disassembled=" + disassembled + " expected=" + expectDisassembled);

		boolean neighborsOk = true;
		for (Neighbor n : expectedNeighbors) {
			MemoryBlock nb = currentProgram.getMemory().getBlock(neighborAddr(n));
			neighborsOk &= nb != null && n.name.equals(nb.getName()) &&
				nb.getStart().equals(neighborAddr(n)) &&
				nb.getEnd().equals(neighborAddr(n).getNewAddress(n.end)) &&
				!nb.isInitialized();
		}
		criterion(idPrefix + "-neighbors", neighborsOk,
			expectedNeighbors.length == 0 ? "none expected" : "see NEIGHBORS lines above");

		boolean callrefOk = jumpSite == null ? callref == null
				: callref != null && block != null && callref.getToAddress().equals(block.getStart()) &&
					currentProgram.getListing().getInstructionAt(callref.getToAddress()) != null;
		criterion(idPrefix + "-callref-hits-code", callrefOk, "callref=" + callrefLine);
	}

	// ------------------------------------------------------------------
	// Manual run-from-elsewhere front-end (bead grm-1.7.1.1)
	// ------------------------------------------------------------------

	// Fixture: copyloop.prg under the name rfemanual.prg, imported with
	// ghidra_scripts/RunFromElsewhereTransfer.java as a -preScript
	// ("src:200e dst:c800 len:8 disassemble:false"). So the SAME image produces two copies from
	// two different front-ends: the script's hand-specified $200E -> $C800 (this check) and, once
	// auto-analysis runs, CopyLoopAnalyzer's recognized $200E -> $C000 (checkCopyLoop's subject).
	// This is the only coverage the manual front-ends have; the GUI plugin adapter cannot be
	// tested at all (docs/testing.md: no AbstractGuiTest/TestEnv, and this harness is headless),
	// which is why everything testable lives behind RunFromElsewhere.
	protected static final String MANUAL_CATEGORY = "RunFromElsewhere";

	// Deliberately NOT verifyCopy(): that helper asserts a provenance bookmark and EOL comment at
	// the copy site ($2000) and a resolved entering call reference, and a manual transfer has
	// neither -- it is specified by a human with no instruction to anchor to, so
	// TransferMaterializer.recordProvenance emits only the destination bookmark. Contorting
	// verifyCopy to make those optional would weaken it for the three fixtures it does fit.
	protected void checkRfeManual() {
		final String blockName = "COPY_c800";
		final long dstStart = 0xc800;
		byte[] expected = {1, 2, 3, 4, 5, 6, 7, 8};   // copyloop.prg's $200E payload

		MemoryBlock block = currentProgram.getMemory().getBlock(blockName);
		boolean inBaseSpace = block != null && block.getStart().getAddressSpace()
				.equals(currentProgram.getAddressFactory().getDefaultAddressSpace());

		byte[] recovered = null;
		String copiedLine = "<none>";
		if (block != null) {
			try {
				byte[] buf = new byte[expected.length];
				block.getBytes(block.getStart(), buf);
				recovered = buf;
				copiedLine = hex(buf);
			}
			catch (Exception e) {
				copiedLine = "<unreadable>";
			}
		}

		// Provenance for a manual transfer is the destination bookmark alone, filed under the
		// category the script passes ("RunFromElsewhere") -- which is what distinguishes it from
		// the recognizer's copy in the very same program.
		Bookmark mark = null;
		for (Bookmark bm : currentProgram.getBookmarkManager().getBookmarks(addr(dstStart))) {
			if (MANUAL_CATEGORY.equals(bm.getCategory())) {
				mark = bm;
				break;
			}
		}
		boolean disassembled =
			block != null && currentProgram.getListing().getInstructionAt(block.getStart()) != null;

		// The auto recognizer's own copy, carved out of what the manual carve left of RAM_C000.
		MemoryBlock autoBlock = currentProgram.getMemory().getBlock("COPY_c000");

		println("=== BANKDUMP BEGIN ===");
		println("MANUALBLOCK " + (block == null ? "<missing>"
				: block.getName() + " " + fmt(block.getStart()) + "-" + fmt(block.getEnd()) +
					" init=" + block.isInitialized()));
		println("SPACE " + (block == null ? "<none>" : block.getStart().getAddressSpace().getName()));
		println("SOURCE " + recordedSource(block, inBaseSpace));
		println("COPIED " + copiedLine);
		println("DISASM " + disassembled);
		println("BOOKMARK " + (mark == null ? "<none>"
				: mark.getTypeString() + " @" + fmt(mark.getAddress())));
		// $2000's EOL comment belongs to the RECOGNIZER's copy (-> COPY_c000), not this one: a
		// manual transfer names no provenance site, so it writes no site comment at all. Dumped
		// to keep that visible -- if this line ever mentions COPY_c800, the manual front-end has
		// started annotating an instruction it was never told about.
		println("SITECOMMENT " + eol(COPY_ENTRY));
		println("AUTOBLOCK " + (autoBlock == null ? "<missing>"
				: autoBlock.getName() + " " + fmt(autoBlock.getStart()) + "-" +
					fmt(autoBlock.getEnd()) + " init=" + autoBlock.isInitialized()));
		println("=== BANKDUMP END ===");

		criterion("rfemanual-block-exists",
			block != null && block.getStart().getOffset() == dstStart,
			"block=" + blockName + " start=" + (block == null ? "<missing>" : fmt(block.getStart())));
		criterion("rfemanual-block-initialized", block != null && block.isInitialized(),
			"initialized=" + (block == null ? "<missing>" : block.isInitialized()));
		criterion("rfemanual-in-base-space", inBaseSpace, "inBaseSpace=" + inBaseSpace);
		criterion("rfemanual-copied-bytes", Arrays.equals(recovered, expected),
			"bytes=" + copiedLine);
		criterion("rfemanual-note-bookmark", mark != null && "Note".equals(mark.getTypeString()),
			"bm=" + (mark == null ? "<none>" : mark.getTypeString()));
		// disassemble:false was passed, and a manual transfer supplies no jump site, so the
		// payload must stay data -- the script must not quietly upgrade it.
		criterion("rfemanual-not-disassembled", !disassembled, "disassembled=" + disassembled);
		// Both front-ends materialized into the same program without stepping on each other.
		criterion("rfemanual-auto-copy-coexists",
			autoBlock != null && autoBlock.isInitialized() &&
				autoBlock.getStart().getOffset() == 0xc000,
			"auto=" + (autoBlock == null ? "<missing>" : fmt(autoBlock.getStart())));
	}

	/** The source address a materialized copy recorded, however it recorded it: an overlay's
	 *  byte-map points straight back at it ({@link MemoryBlockSourceInfo#getMappedRange()}); an
	 *  in-place carve has no such map, so {@code TransferMaterializer.carveInPlace} records the
	 *  source in the block's own {@code sourceName} field as "<space>:<offset>". Returns a bare
	 *  "%04x" offset (no space prefix) either way, or "<none>" if it cannot be recovered. */
	protected String recordedSource(MemoryBlock block, boolean inBaseSpace) {
		if (block == null) {
			return "<none>";
		}
		// sourceName first, byte-map second -- NOT keyed on inBaseSpace, because a banked carve
		// (grm-bqs) is an in-place carve that lives in an overlay: it records sourceName like any
		// other carve and has no byte-map at all. createOverlay never sets sourceName, so the
		// byte-mapped fallback still reaches its own branch below.
		String sourceName = block.getSourceName();
		if ((sourceName == null || sourceName.isBlank()) && !block.getSourceInfos().isEmpty()) {
			java.util.Optional<AddressRange> r = block.getSourceInfos().get(0).getMappedRange();
			if (r.isPresent()) {
				return fmt(r.get().getMinAddress());
			}
			return "<none>";
		}
		if (sourceName == null || sourceName.isBlank()) {
			return "<none>";
		}
		int colon = sourceName.indexOf(':');
		return colon >= 0 ? sourceName.substring(colon + 1) : sourceName;
	}

	/** The primary reference out of the instruction at {@code from}, or null if there is no
	 *  instruction there or none of its references is primary. */
	protected Reference primaryReferenceFrom(Address from) {
		Instruction instr = currentProgram.getListing().getInstructionAt(from);
		if (instr == null) {
			return null;
		}
		for (Reference r : instr.getReferencesFrom()) {
			if (r.isPrimary()) {
				return r;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Descriptor copied_from boot-copy hint (bead grm-1.7.1.2)
	// ------------------------------------------------------------------

	// Both fixtures are romload.prg re-imported under another name; what differs is the ROM
	// options. machines/c64.yaml declares ZEROPAGE.copied_from CHRGET = 0x18 bytes of KERNAL
	// $E3A2 -> $0073, and mkromtest.py's synthetic kernal.bin is byte[i] = i & 0xFF, so $E3A2
	// reads $A2 and the copied run is the deterministic $A2..$B9. (A copyright-safe stand-in;
	// never a real ROM.) copyhinttest supplies the ROM and must materialize the copy in the base
	// space; copyhintnorom supplies none and must materialize NOTHING -- the ROM-gated rule of
	// docs/smc-inplace-vs-overlay.md section 6, and the more important of the two.
	protected static final String COPY_HINT_BLOCK = "COPY_0073";
	protected static final int CHRGET_LEN = 0x18;

	protected void checkCopyHint() {
		MemoryBlock copy = currentProgram.getMemory().getBlock(COPY_HINT_BLOCK);
		boolean inBaseSpace = copy != null && copy.getStart().getAddressSpace()
				.equals(currentProgram.getAddressFactory().getDefaultAddressSpace());
		boolean initialized = copy != null && copy.isInitialized();
		boolean range = copy != null && copy.getStart().getOffset() == 0x0073 &&
			copy.getEnd().getOffset() == 0x008a;

		byte[] expected = new byte[CHRGET_LEN];
		for (int i = 0; i < CHRGET_LEN; i++) {
			expected[i] = (byte) (0xA2 + i);
		}
		byte[] recovered = null;
		if (initialized) {
			try {
				byte[] buf = new byte[CHRGET_LEN];
				copy.getBytes(copy.getStart(), buf);
				recovered = buf;
			}
			catch (Exception e) {
				recovered = null;
			}
		}

		println("=== BANKDUMP BEGIN ===");
		println("COPYBLOCK " + (copy == null ? "<missing>"
				: copy.getName() + " " + fmt(copy.getStart()) + "-" + fmt(copy.getEnd()) +
					" init=" + copy.isInitialized()));
		println("SPACE " + (copy == null ? "<none>" : copy.getStart().getAddressSpace().getName()));
		println("SOURCE " + recordedSource(copy, inBaseSpace));
		println("BYTES " + hex(recovered));
		println("=== BANKDUMP END ===");

		criterion("copyhint-block-present", copy != null, "block=" + COPY_HINT_BLOCK);
		criterion("copyhint-initialized", initialized, "init=" + initialized);
		criterion("copyhint-in-base-space", inBaseSpace,
			"space=" + (copy == null ? "<none>" : copy.getStart().getAddressSpace().getName()));
		criterion("copyhint-range", range, "range=" + (copy == null ? "<none>"
				: fmt(copy.getStart()) + "-" + fmt(copy.getEnd())));
		criterion("copyhint-bytes", Arrays.equals(expected, recovered),
			"bytes=" + hex(recovered));
	}

	protected void checkCopyHintNoRom() {
		MemoryBlock copy = currentProgram.getMemory().getBlock(COPY_HINT_BLOCK);
		MemoryBlock kernal = currentProgram.getMemory().getBlock("KERNAL");
		MemoryBlock zeropage = currentProgram.getMemory().getBlock(addr(0x0073));

		println("=== BANKDUMP BEGIN ===");
		println("COPYBLOCK " + (copy == null ? "<missing>" : describeBlock(copy)));
		println("KERNAL init=" + (kernal != null && kernal.isInitialized()));
		println("ZP0073 " + describeBlock(zeropage));
		println("=== BANKDUMP END ===");

		// The whole rule: with no readable source the directive is ignored outright -- no block of
		// any kind, and specifically no overlay fallback.
		criterion("copyhint-norom-no-block", copy == null,
			"block=" + (copy == null ? "<none>" : copy.getName()));
		criterion("copyhint-norom-kernal-uninitialized",
			kernal != null && !kernal.isInitialized(),
			"kernal=" + describeBlock(kernal));
		// And the destination region is left exactly as the loader made it: one unsplit,
		// uninitialized ZEROPAGE block.
		criterion("copyhint-norom-zeropage-intact",
			zeropage != null && "ZEROPAGE".equals(zeropage.getName()) &&
				!zeropage.isInitialized() && zeropage.getStart().getOffset() == 0x0002 &&
				zeropage.getEnd().getOffset() == 0x00ff,
			"zp=" + describeBlock(zeropage));
	}

	// ------------------------------------------------------------------
	// Optional user-supplied ROM loading (bead grm-mbm)
	// ------------------------------------------------------------------

	// Fixture from mkromtest.py: romload.prg imported with -loader-{kernal,basic,chargen}Rom
	// pointing at synthetic ROMs whose bytes are kernal[i]=i&0xFF, basic[i]=(i&0xFF)^0x55,
	// chargen[i]=(i&0xFF)^0xAA. So each ROM block should come back initialized with a
	// distinct, position-dependent pattern (proving each path landed in the right block).
	protected void checkRomLoad() {
		MemoryBlock kernal = currentProgram.getMemory().getBlock("KERNAL");
		MemoryBlock basic = currentProgram.getMemory().getBlock("BASIC");
		MemoryBlock chargen = currentProgram.getMemory().getBlock("CHARGEN");

		int kB0 = readByte(kernal, 0);          // kernal[0]      = 0x00
		int kChrget = readByte(kernal, 0x3A2);  // kernal[0x3A2]  = 0xA2 (where CHRGET lives)
		int bB0 = readByte(basic, 0);           // basic[0]       = 0x55
		int cB0 = readByte(chargen, 0);         // chargen[0]     = 0xAA

		boolean kInit = kernal != null && kernal.isInitialized();
		boolean bInit = basic != null && basic.isInitialized();
		boolean cInit = chargen != null && chargen.isInitialized();

		println("=== BANKDUMP BEGIN ===");
		println("KERNAL init=" + kInit + " b0=" + hx(kB0) + " b3A2=" + hx(kChrget));
		println("BASIC init=" + bInit + " b0=" + hx(bB0));
		println("CHARGEN init=" + cInit + " b0=" + hx(cB0));
		println("=== BANKDUMP END ===");

		criterion("rom-kernal-initialized", kInit, "");
		criterion("rom-kernal-bytes", kB0 == 0x00 && kChrget == 0xA2,
			"b0=" + hx(kB0) + " b3A2=" + hx(kChrget));
		criterion("rom-basic-initialized", bInit, "");
		criterion("rom-basic-bytes", bB0 == 0x55, "b0=" + hx(bB0));
		criterion("rom-chargen-initialized", cInit, "");
		criterion("rom-chargen-bytes", cB0 == 0xAA, "b0=" + hx(cB0));
	}

	// ------------------------------------------------------------------
	// PET 4032 fixed-map descriptor and shared CBM PRG loader (grm-1.8)
	// ------------------------------------------------------------------

	protected void checkPet4032() {
		MemoryBlock prg = currentProgram.getMemory().getBlock(addr(0x0401));
		MemoryBlock screen = currentProgram.getMemory().getBlock("SCREEN_RAM");
		MemoryBlock screenMirror = currentProgram.getMemory().getBlock("SCREEN_MIRROR");
		MemoryBlock basic = currentProgram.getMemory().getBlock("BASIC");
		MemoryBlock editor = currentProgram.getMemory().getBlock("EDITOR");
		MemoryBlock kernal = currentProgram.getMemory().getBlock("KERNAL");
		MemoryBlock rom9 = currentProgram.getMemory().getBlock("ROM9");
		MemoryBlock roma = currentProgram.getMemory().getBlock("ROMA");
		MemoryBlock pia1 = currentProgram.getMemory().getBlock("PIA1");
		MemoryBlock via = currentProgram.getMemory().getBlock("VIA");
		MemoryBlock crtc = currentProgram.getMemory().getBlock("CRTC");

		String mapPath = currentProgram.getOptions(currentProgram.PROGRAM_INFO)
			.getString("Retro Machine Map", "");
		boolean format = "Commodore PET 4032 PRG".equals(currentProgram.getExecutableFormat());
		boolean prgPlaced = prg != null && prg.isInitialized() &&
			prg.getStart().getOffset() == 0x0401 && fileOffset(prg) == 2 &&
			readByte(prg, 0) == 0x0c && readByte(prg, 1) == 0x04;
		boolean screenShape = screen != null && screen.getStart().getOffset() == 0x8000 &&
			screen.getEnd().getOffset() == 0x83ff && !screen.isOverlay();
		boolean screenMirrorShape = screenMirror != null &&
			screenMirror.getStart().getOffset() == 0x8400 &&
			screenMirror.getEnd().getOffset() == 0x87ff && !screenMirror.isOverlay() &&
			screenMirror.getComment() != null &&
			screenMirror.getComment().toLowerCase().contains("alias");
		boolean fixedRoms = basic != null && basic.isInitialized() &&
			editor != null && editor.isInitialized() && kernal != null && kernal.isInitialized() &&
			readByte(basic, 0) == 0x40 && readByte(editor, 0) == 0x60 &&
			readByte(kernal, 0) == 0x80;
		boolean expansionEmpty = rom9 != null && !rom9.isInitialized() &&
			roma != null && !roma.isInitialized();
		boolean ioVolatile = pia1 != null && pia1.isVolatile() && via != null && via.isVolatile() &&
			crtc != null && crtc.isVolatile();
		boolean types = dataTypeAt(0xe810, "MOS6520_PIA") &&
			dataTypeAt(0xe840, "MOS6522_VIA") && dataTypeAt(0xe880, "MOS6545_CRTC");
		boolean reset = hasSymbol(0xfffc, "RESET_VEC");
		boolean noBasicFunction = currentProgram.getFunctionManager().getFunctionAt(addr(0x0401)) == null;

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT pet4032=" + format + " map=" + mapPath);
		println("PRG " + describeBlock(prg) + " fileOffset=" + fileOffset(prg) +
			" bytes=" + hx(readByte(prg, 0)) + " " + hx(readByte(prg, 1)));
		println("SCREEN " + describeBlock(screen));
		println("SCREEN_MIRROR " + describeBlock(screenMirror) +
			" aliasDocumented=" + screenMirrorShape);
		println("ROMS basic=" + describeBlock(basic) + " editor=" + describeBlock(editor) +
			" kernal=" + describeBlock(kernal));
		println("EXPANSION rom9=" + describeBlock(rom9) + " roma=" + describeBlock(roma));
		println("IO volatile=" + ioVolatile + " types=" + types);
		println("RESET_VEC=" + reset + " basicFunction=" + !noBasicFunction);
		println("=== BANKDUMP END ===");

		criterion("pet-format-map", format && "machines/pet4032.map".equals(mapPath), mapPath);
		criterion("pet-prg-placement", prgPlaced, describeBlock(prg));
		criterion("pet-screen-layout", screenShape, describeBlock(screen));
		criterion("pet-screen-mirror", screenMirrorShape,
			"$8400-$87ff mirror represented as documented alias-limitation block");
		criterion("pet-fixed-roms", fixedRoms, "basic/editor/kernal initialized with fixture bytes");
		criterion("pet-expansion-empty", expansionEmpty, "ROM9/ROMA stay copyright-safe empty slots");
		criterion("pet-io-volatile", ioVolatile, "PIA1/VIA/CRTC volatile");
		criterion("pet-io-types", types, "PIA/VIA/CRTC structs applied");
		criterion("pet-reset-symbol", reset, "RESET_VEC@fffc");
		criterion("pet-basic-no-function", noBasicFunction, "no function at BASIC line link $0401");
	}

	/**
	 * SNES cartridge loader (bead grm-9nxj.9). What this fixture is actually testing is
	 * unusual for this suite: NO overlays and NO banked windows -- the 65816's 24-bit space
	 * holds everything at once, so the loader lays out a static map and represents the
	 * hardware's address mirrors as byte-mapped views of one canonical block. The criteria
	 * below check exactly that shape, plus the two things a wrong header read would break
	 * first (where ROM landed, and where the entry point is).
	 *
	 * <p>The copier-headered twin runs the same checks: it is the same cartridge behind 512
	 * extra bytes, so anything that differs between the two is a copier-detection bug.
	 */
	protected void checkSnes() {
		MemoryBlock romHome = currentProgram.getMemory().getBlock(addr(0x008000));
		MemoryBlock romMirror = currentProgram.getMemory().getBlock(addr(0x808000));
		MemoryBlock wram = currentProgram.getMemory().getBlock("WRAM");
		MemoryBlock lowRam = currentProgram.getMemory().getBlock(addr(0x000000));
		MemoryBlock ppuIo = currentProgram.getMemory().getBlock(addr(0x002100));

		String mapPath = currentProgram.getOptions(currentProgram.PROGRAM_INFO)
			.getString("Retro Machine Map", "");
		boolean format = "SNES ROM (LoROM/HiROM)".equals(currentProgram.getExecutableFormat());
		boolean language = currentProgram.getLanguageID().getIdAsString()
			.equals("65816:LE:24:retro");

		// LoROM puts the first 32 KiB chunk at $00:8000, initialized from file offset 0.
		boolean romPlaced = romHome != null && romHome.isInitialized() &&
			romHome.getStart().getOffset() == 0x008000 && !romHome.isOverlay() &&
			readByte(romHome, 0) == 0x18 && readByte(romHome, 1) == 0xfb;

		// The high half is the SAME bytes, as a byte-mapped view -- not a second copy, and
		// not an overlay.
		// NB: read through the ADDRESS, not readByte(block, ...). A byte-mapped block reports
		// isInitialized() == false -- it owns no bytes of its own -- so the usual helper's
		// guard returns -1 for it and would fail this criterion on a perfectly good mirror.
		// What actually matters is that reading $80:8000 yields the ROM byte at $00:8000.
		boolean mirrorIsMapped = romMirror != null && !romMirror.isOverlay() &&
			romMirror.getType() == MemoryBlockType.BYTE_MAPPED &&
			readByteAt(0x808000) == 0x18 && readByteAt(0x808001) == 0xfb;
		boolean noOverlays = countOverlayBlocks() == 0;

		boolean wramShape = wram != null && wram.getStart().getOffset() == 0x7e0000 &&
			wram.getEnd().getOffset() == 0x7fffff && !wram.isInitialized();
		boolean lowRamMirror = lowRam != null && lowRam.getType() == MemoryBlockType.BYTE_MAPPED;
		boolean ioVolatile = ppuIo != null && ppuIo.isVolatile();
		boolean ioNamed = hasSymbol(0x002100, "INIDISP") && hasSymbol(0x004200, "NMITIMEN");
		boolean entry = currentProgram.getSymbolTable().isExternalEntryPoint(addr(0x008000));
		String vectors = describeSnesVectors();

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT snes=" + format + " language=" + language + " map=" + mapPath);
		println("ROM_HOME " + describeBlock(romHome) + " fileOffset=" + fileOffset(romHome) +
			" bytes=" + hx(readByte(romHome, 0)) + " " + hx(readByte(romHome, 1)));
		println("ROM_MIRROR " + describeBlock(romMirror) +
			" type=" + (romMirror == null ? "<none>" : romMirror.getType()) +
			" bytesThroughMirror=" + hx(readByteAt(0x808000)) + " " +
			hx(readByteAt(0x808001)) + " ok=" + mirrorIsMapped);
		println("OVERLAYS " + countOverlayBlocks() + " (a static map needs none)");
		println("WRAM " + describeBlock(wram));
		println("LOWRAM_MIRROR " + describeBlock(lowRam) + " byteMapped=" + lowRamMirror);
		println("IO ppu=" + describeBlock(ppuIo) + " volatile=" + ioVolatile +
			" named=" + ioNamed);
		println("ENTRY reset=" + entry);
		println("VECTORS " + vectors);
		println("=== BANKDUMP END ===");

		checkSnesVectors(0x008000, vectors);
		criterion("snes-format-language", format && language,
			currentProgram.getExecutableFormat() + " / " +
				currentProgram.getLanguageID().getIdAsString());
		criterion("snes-rom-placement", romPlaced, describeBlock(romHome));
		criterion("snes-mirror-byte-mapped", mirrorIsMapped, describeBlock(romMirror));
		criterion("snes-no-overlays", noOverlays,
			"a 24-bit static map needs no overlay blocks; found " + countOverlayBlocks());
		criterion("snes-wram", wramShape, describeBlock(wram));
		criterion("snes-lowram-mirror", lowRamMirror, describeBlock(lowRam));
		criterion("snes-io-volatile", ioVolatile, "PPU/APU IO volatile");
		criterion("snes-io-named", ioNamed, "INIDISP@2100 and NMITIMEN@4200 from the descriptor");
		criterion("snes-entry-point", entry, "reset vector target $008000 is an entry point");
	}

	/**
	 * Interleaved HiROM (bead grm-9nxj.19): the file stores each 64 KiB unit's 32 KiB halves
	 * swapped, so the loader must (a) find the header at logical $FFC0 although it is stored at
	 * $7FC0, and (b) cut each unit into TWO 32 KiB blocks whose file offsets are the real,
	 * swapped ones -- provenance, not copied bytes. The reset code is stored at FILE offset 0
	 * and lives at logical $8000, i.e. block ROM_C0_8000.
	 */
	protected void checkSnesInterleaved() {
		MemoryBlock c00000 = currentProgram.getMemory().getBlock(addr(0xC00000));
		MemoryBlock c08000 = currentProgram.getMemory().getBlock(addr(0xC08000));
		MemoryBlock c10000 = currentProgram.getMemory().getBlock(addr(0xC10000));
		MemoryBlock c18000 = currentProgram.getMemory().getBlock(addr(0xC18000));
		MemoryBlock wram = currentProgram.getMemory().getBlock("WRAM");

		boolean format = "SNES ROM (LoROM/HiROM)".equals(currentProgram.getExecutableFormat());
		boolean language = currentProgram.getLanguageID().getIdAsString()
			.equals("65816:LE:24:retro");
		boolean twoPerUnit = c00000 != null && c08000 != null && c10000 != null &&
			c18000 != null && c00000.getSize() == 0x8000 && c08000.getSize() == 0x8000 &&
			c10000.getSize() == 0x8000 && c18000.getSize() == 0x8000;
		boolean provenance = twoPerUnit && fileOffset(c00000) == 0x8000 &&
			fileOffset(c08000) == 0 && fileOffset(c10000) == 0x18000 &&
			fileOffset(c18000) == 0x10000;
		boolean resetCode = c08000 != null && readByte(c08000, 0) == 0x18 &&
			readByte(c08000, 1) == 0xfb;
		// HiROM system banks show the upper half of the linear view; $80 as well.
		boolean mirrors = readByteAt(0x008000) == 0x18 && readByteAt(0x008001) == 0xfb &&
			readByteAt(0x808000) == 0x18 && readByteAt(0x808001) == 0xfb;
		boolean noOverlays = countOverlayBlocks() == 0;
		boolean wramShape = wram != null && wram.getStart().getOffset() == 0x7e0000;
		boolean entry = currentProgram.getSymbolTable().isExternalEntryPoint(addr(0x008000));
		String vectors = describeSnesVectors();

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT snes=" + format + " language=" + language);
		println("ROM_C0_0000 " + describeBlock(c00000) + " fileOffset=" + fileOffset(c00000));
		println("ROM_C0_8000 " + describeBlock(c08000) + " fileOffset=" + fileOffset(c08000) +
			" bytes=" + hx(readByte(c08000, 0)) + " " + hx(readByte(c08000, 1)));
		println("ROM_C1_0000 " + describeBlock(c10000) + " fileOffset=" + fileOffset(c10000));
		println("ROM_C1_8000 " + describeBlock(c18000) + " fileOffset=" + fileOffset(c18000));
		println("MIRRORS bytesAt008000=" + hx(readByteAt(0x008000)) + " " +
			hx(readByteAt(0x008001)) + " bytesAt808000=" + hx(readByteAt(0x808000)) + " " +
			hx(readByteAt(0x808001)));
		println("OVERLAYS " + countOverlayBlocks());
		println("ENTRY reset=" + entry);
		println("VECTORS " + vectors);
		println("=== BANKDUMP END ===");

		checkSnesVectors(0x008000, vectors);
		criterion("snes-il-format-language", format && language,
			currentProgram.getExecutableFormat());
		criterion("snes-il-two-blocks-per-unit", twoPerUnit,
			"each 64 KiB HiROM unit is two 32 KiB blocks");
		criterion("snes-il-provenance", provenance,
			"block file offsets are the true (swapped) ones: C0:0000<-$8000, C0:8000<-$0, " +
				"C1:0000<-$18000, C1:8000<-$10000");
		criterion("snes-il-reset-code", resetCode, "18 fb (CLC XCE) at C0:8000, from file offset 0");
		criterion("snes-il-mirrors", mirrors, "$00:8000 and $80:8000 show C0:8000");
		criterion("snes-il-no-overlays", noOverlays, "static map");
		criterion("snes-il-wram", wramShape, describeBlock(wram));
		criterion("snes-il-entry-point", entry, "reset vector target $008000 is an entry point");
	}

	/**
	 * The vector table and its handlers, as the SNES loader leaves them (bead grm-9nxj.5.2): one
	 * token per slot naming what the slot is typed as, then one per handler entry with its
	 * function, decoded instruction and stamped E/M/X context. Shared by every snestest fixture,
	 * whose vector tables are written by mksnestest.write_vectors.
	 */
	protected String describeSnesVectors() {
		StringBuilder sb = new StringBuilder();
		for (int slot : new int[] { 0xFFE4, 0xFFE6, 0xFFE8, 0xFFEA, 0xFFEE, 0xFFF4, 0xFFF8,
			0xFFFA, 0xFFFC, 0xFFFE }) {
			Data d = currentProgram.getListing().getDefinedDataAt(addr(slot));
			sb.append(String.format("%04x=%s ", slot, d == null ? "<none>"
					: d.getDataType().getName() + "/" + d.getLength()));
		}
		for (long target : new long[] { 0x008000, 0x008020, 0x008030 }) {
			sb.append(String.format("| %06x %s ", target, describeSnesHandler(target)));
		}
		sb.append("| vectorTableCode=" +
			(currentProgram.getListing().getInstructions(
				new ghidra.program.model.address.AddressSet(addr(0xFFE0), addr(0xFFFF)), true)
				.hasNext()));
		sb.append(" async=").append(currentProgram.getOptions(Program.PROGRAM_INFO)
			.getString("Retro Machines.Async Entry Points", "<none>"));
		return sb.toString();
	}

	private String describeSnesHandler(long target) {
		Address a = addr(target);
		Function f = currentProgram.getFunctionManager().getFunctionAt(a);
		Instruction i = currentProgram.getListing().getInstructionAt(a);
		return "fn=" + (f == null ? "<none>" : f.getName()) +
			" entry=" + currentProgram.getSymbolTable().isExternalEntryPoint(a) +
			" instr=" + (i == null ? "<none>" : i.toString().replace(' ', '_')) +
			" ctx=E" + ctxBit(a, "ctx_EF") + "M" + ctxBit(a, "ctx_MF") + "X" + ctxBit(a, "ctx_XF");
	}

	private String ctxBit(Address a, String name) {
		java.math.BigInteger v = currentProgram.getProgramContext()
			.getValue(currentProgram.getRegister(name), a, false);
		return v == null ? "?" : v.toString();
	}

	/**
	 * The vector criteria (bead grm-9nxj.5.2): every slot typed as a 2-byte pointer, so the
	 * table is never decoded as code; RESET, the native NMI and the emulation IRQ each a
	 * function and entry point decoded in its own mode; the $FFFF-filled slots seeding nothing;
	 * NMI and the emulation IRQ published as asynchronous entries.
	 */
	protected void checkSnesVectors(long reset, String vectors) {
		boolean slotsTyped = !vectors.contains("<none>/") &&
			vectors.split("=pointer16/2 ", -1).length == 11;
		boolean noTableCode = vectors.contains("vectorTableCode=false");
		criterion("snes-vector-slots-typed", slotsTyped && noTableCode,
			"all ten slots pointer16/2, no instruction in $FFE0-$FFFF");
		criterion("snes-vector-reset-handler",
			vectors.contains(String.format("%06x fn=RESET entry=true instr=SEI", reset)) ||
				vectors.contains(String.format("%06x fn=RESET entry=true instr=CLC", reset)),
			"RESET is a function, an entry point, and decoded");
		criterion("snes-vector-native-nmi",
			vectors.contains("008020 fn=NMI entry=true instr=REP_#$0x30 ctx=E0M1X1"),
			"native NMI at $8020 is a function decoded in native mode (E=0)");
		criterion("snes-vector-emulation-irq",
			vectors.contains("008030 fn=IRQ_EMU entry=true instr=RTI ctx=E1M1X1"),
			"emulation IRQ at $8030 is a function decoded in emulation mode (E=1)");
		criterion("snes-vector-unused-skipped",
			!hasFunctionNamed("COP") && !hasFunctionNamed("BRK") && !hasFunctionNamed("COP_EMU") &&
				!hasFunctionNamed("NMI_EMU"),
			"$FFFF-filled vectors (into the vector area) seed nothing");
		String async = vectors.substring(vectors.indexOf(" async=") + 7);
		criterion("snes-vector-async", async.contains("008020") && async.contains("008030") &&
			async.trim().split(" ").length == 2,
			"NMI and IRQ_EMU targets published as asynchronous entry points");
	}

	private boolean hasFunctionNamed(String name) {
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Call-width repair (bead grm-9nxj.5.3), on mksnestest.width_cartridge: the code after
	 * {@code JSR $8040} (which leaves M=1) and the callee {@code $8050} (reached only at M=1) are
	 * decoded with an 8-bit accumulator, so {@code LDA #$12} and {@code CMP #$73} are two bytes.
	 */
	protected void checkSnesWidth() {
		String cont = describeWidthSite(0x00800A);
		String needs = describeWidthSite(0x008050);
		String after = describeWidthSite(0x00800C);
		String eolCont = currentProgram.getListing().getComment(CommentType.EOL, addr(0x008007));
		String eolNeeds = currentProgram.getListing().getComment(CommentType.EOL, addr(0x008050));

		println("=== BANKDUMP BEGIN ===");
		println("WIDTH 800a " + cont);
		println("WIDTH 800c " + after);
		println("WIDTH 8050 " + needs);
		println("WIDTH eol 8007 " + eolCont);
		println("WIDTH eol 8050 " + eolNeeds);
		println("=== BANKDUMP END ===");

		criterion("snes-width-continuation",
			cont.startsWith("LDA #$0x12 len=2 M=1") && after.startsWith("STA"),
			"code after JSR $8040 (SEP #$20 / RTS) decodes 8-bit: " + cont);
		criterion("snes-width-callee-entry", needs.startsWith("CMP #$0x73 len=2 M=1"),
			"callee $8050, reached only at M=1, decodes 8-bit: " + needs);
		// $8050 needs no note of its own: Clear Flow from $8007 also clears it (nothing else
		// reaches it), so the continuation's re-decode lays it down at M=1 directly. The
		// entry-consensus path is exercised on the real-ROM rows (CT $C1:104E), not here.
		criterion("snes-width-notes", eolCont != null && eolCont.contains("M=1"),
			"the re-decoded continuation carries an EOL note saying why");
	}

	private String describeWidthSite(long offset) {
		Instruction i = currentProgram.getListing().getInstructionAt(addr(offset));
		if (i == null) {
			return "<none>";
		}
		return i + " len=" + i.getLength() + " M=" + ctxBit(addr(offset), "ctx_MF");
	}

	protected int countOverlayBlocks() {
		int overlays = 0;
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (b.isOverlay()) {
				overlays++;
			}
		}
		return overlays;
	}

	protected boolean dataTypeAt(long offset, String expected) {
		Data data = currentProgram.getListing().getDefinedDataAt(addr(offset));
		return data != null && expected.equals(data.getDataType().getName());
	}

	// ------------------------------------------------------------------
	// BASIC 2/4/7 dialect-detokenizer fixtures (grm-1.6.1)
	// ------------------------------------------------------------------

	protected void checkC64Basic2Dialect() throws Exception {
		String line = preComment(0x0801);
		String expressionSys = preComment(0x080f);
		boolean format = "Commodore 64 PRG".equals(currentProgram.getExecutableFormat());
		boolean typed = basicLineWordsTyped(0x0801) && basicLineWordsTyped(0x080f);
		boolean noLoadFunction = !hasFunctionAt(0x0801);
		boolean expressionSysNote = hasSysNoteBookmark(0x080f);
		boolean noPrefixSysFunction = !hasFunctionAt(0x0810);

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT c64basic2=" + format);
		println("PRE 0801=" + line);
		println("PRE 080f=" + expressionSys);
		println("TYPED=" + typed + " loadFunction=" + !noLoadFunction);
		println("INVALID_SYS expressionNote=" + expressionSysNote + " functionAt0810=" +
			!noPrefixSysFunction);
		boolean covered = dumpBasicRegion(0x0801, true);
		println("=== BANKDUMP END ===");
		criterion("basic2-region-defined", covered, "no undefined bytes in the BASIC region");

		criterion("basic2-format", format, currentProgram.getExecutableFormat());
		criterion("basic2-cc-plus-raw",
			"10 {$cc} {$d5} {$ce}{CTRL-B} {$fe}{CTRL-B}".equals(line), line);
		criterion("basic2-line-typed", typed, "link/line-number words at $0801");
		criterion("basic2-expression-sys",
			"20 SYS 2064+1".equals(expressionSys) && expressionSysNote && noPrefixSysFunction,
			expressionSys + " note=" + expressionSysNote + " function@0810=" +
			!noPrefixSysFunction);
		criterion("basic2-no-load-function", noLoadFunction, "BASIC link data at $0801");
	}

	protected void checkC64BasicOverflowDialect() throws Exception {
		String line = preComment(0x0801);
		boolean format = "Commodore 64 PRG".equals(currentProgram.getExecutableFormat());
		boolean typed = basicLineWordsTyped(0x0801);
		boolean invalidSysNote = hasSysNoteBookmark(0x0801);
		boolean noLoadFunction = !hasFunctionAt(0x0801);
		boolean noWrappedSysFunction = !hasFunctionAt(0x0000);

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT c64basicoverflow=" + format);
		println("PRE 0801=" + line);
		println("TYPED=" + typed + " loadFunction=" + !noLoadFunction);
		println("INVALID_SYS note=" + invalidSysNote + " functionAt0000=" +
			!noWrappedSysFunction);
		boolean covered = dumpBasicRegion(0x0801, true);
		println("=== BANKDUMP END ===");
		criterion("basic2-overflow-region-defined", covered,
			"no undefined bytes in the BASIC region");

		criterion("basic2-overflow-format", format, currentProgram.getExecutableFormat());
		criterion("basic2-overflow-line", "10 SYS 65536".equals(line), line);
		criterion("basic2-overflow-line-typed", typed, "link/line-number words at $0801");
		criterion("basic2-overflow-sys", invalidSysNote && noWrappedSysFunction,
			"note=" + invalidSysNote + " function@0000=" + !noWrappedSysFunction);
		criterion("basic2-overflow-no-load-function", noLoadFunction, "BASIC link data at $0801");
	}

	protected void checkPetBasic4Dialect() throws Exception {
		String line10 = preComment(0x0401);
		String line20 = preComment(0x040b);
		String line30 = preComment(0x0416);
		String line40 = preComment(0x041f);
		boolean format = "Commodore PET 4032 PRG".equals(currentProgram.getExecutableFormat());
		boolean typed = basicLineWordsTyped(0x0401) && basicLineWordsTyped(0x040b) &&
			basicLineWordsTyped(0x0416) && basicLineWordsTyped(0x041f);
		boolean sysFunction = hasFunctionAt(0x042c);
		boolean noLoadFunction = !hasFunctionAt(0x0401);

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT petbasic4=" + format);
		println("PRE 0401=" + line10);
		println("PRE 040b=" + line20);
		println("PRE 0416=" + line30);
		println("PRE 041f=" + line40);
		println("TYPED=" + typed + " sysFunction=" + sysFunction +
			" loadFunction=" + !noLoadFunction);
		boolean covered = dumpBasicRegion(0x0401, true);
		println("=== BANKDUMP END ===");

		criterion("basic4-region-defined", covered, "no undefined bytes in the BASIC region");
		criterion("basic4-format", format, currentProgram.getExecutableFormat());
		criterion("basic4-disk-tokens", "10 CONCAT DOPEN DIRECTORY".equals(line10), line10);
		criterion("basic4-quoted-raw", "20 PRINT\"{$cc}{$cd}{$da}\"".equals(line20), line20);
		criterion("basic4-rem-raw", "30 REM{$cc}\"{$ce}".equals(line30), line30);
		criterion("basic4-sys", "40 SYS 1068".equals(line40) && sysFunction,
			line40 + " function@042c=" + sysFunction);
		criterion("basic4-lines-typed", typed, "all line link/number words typed");
		criterion("basic4-no-load-function", noLoadFunction, "BASIC link data at $0401");
	}

	protected void checkC128Basic7Dialect() throws Exception {
		String line10 = preComment(0x1c01);
		String line20 = preComment(0x1c0b);
		String line30 = preComment(0x1c12);
		String line40 = preComment(0x1c19);
		String line50 = preComment(0x1c23);
		String line60 = preComment(0x1c29);
		String line70 = preComment(0x1c36);
		String line80 = preComment(0x1c42);
		boolean format = "Commodore 128 Native BASIC PRG".equals(
			currentProgram.getExecutableFormat());
		boolean typed = basicLineWordsTyped(0x1c01) && basicLineWordsTyped(0x1c0b) &&
			basicLineWordsTyped(0x1c12) && basicLineWordsTyped(0x1c19) &&
			basicLineWordsTyped(0x1c23) && basicLineWordsTyped(0x1c29) &&
			basicLineWordsTyped(0x1c36) && basicLineWordsTyped(0x1c42);
		boolean sysFunction = hasFunctionAt(0x1c4f);
		boolean noLoadFunction = !hasFunctionAt(0x1c01);

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT c128basic7=" + format);
		println("PRE 1c01=" + line10);
		println("PRE 1c0b=" + line20);
		println("PRE 1c12=" + line30);
		println("PRE 1c19=" + line40);
		println("PRE 1c23=" + line50);
		println("PRE 1c29=" + line60);
		println("PRE 1c36=" + line70);
		println("PRE 1c42=" + line80);
		println("TYPED=" + typed + " sysFunction=" + sysFunction +
			" loadFunction=" + !noLoadFunction);
		boolean covered = dumpBasicRegion(0x1c01, true);
		println("=== BANKDUMP END ===");

		criterion("basic7-region-defined", covered, "no undefined bytes in the BASIC region");
		criterion("basic7-format", format, currentProgram.getExecutableFormat());
		criterion("basic7-base-tokens", "10 RGR ELSE DSAVE".equals(line10), line10);
		criterion("basic7-ce-prefix", "20 POT".equals(line20), line20);
		criterion("basic7-fe-prefix", "30 BANK".equals(line30), line30);
		criterion("basic7-invalid-prefixes",
			"35 {$ce}{lgrn} {$fe}{lgrn}".equals(line40) && !line40.contains("PRINT"), line40);
		criterion("basic7-truncated-prefix", "37 {$ce}".equals(line50), line50);
		criterion("basic7-quoted-raw",
			"40 PRINT\"{$ce}{CTRL-B}{$fe}{CTRL-B}{$cc}\"".equals(line60), line60);
		criterion("basic7-rem-raw",
			"50 REM{$ce}{CTRL-B}{$fe}{CTRL-B}{$cc}\"".equals(line70), line70);
		criterion("basic7-sys", "60 SYS 7247".equals(line80) && sysFunction,
			line80 + " function@1c4f=" + sysFunction);
		criterion("basic7-lines-typed", typed, "all line link/number words typed");
		criterion("basic7-no-load-function", noLoadFunction, "BASIC link data at $1c01");
	}

	protected boolean basicLineWordsTyped(long lineAddr) {
		Data number = currentProgram.getListing().getDefinedDataAt(addr(lineAddr + 2));
		return dataTypeAt(lineAddr, "pointer16") && dataTypeAt(lineAddr + 2, "word") &&
			number != null && number.getDefaultValueRepresentation().matches("\\d+") &&
			"line link".equals(eol(lineAddr)) && "line number".equals(eol(lineAddr + 2));
	}

	/** Address just past a BASIC program's terminating $0000 link, following the line
	 *  links from {@code start} (grm-td4). */
	protected long basicRegionEnd(long start) throws Exception {
		long at = start;
		while (true) {
			int link = (currentProgram.getMemory().getByte(addr(at)) & 0xff) |
				((currentProgram.getMemory().getByte(addr(at + 1)) & 0xff) << 8);
			if (link == 0) {
				return at + 2;
			}
			at = link;
		}
	}

	/** Emits one DATA line per code unit of the BASIC region and returns whether every
	 *  byte is covered by defined data (no undefined bytes), grm-td4. */
	protected boolean dumpBasicRegion(long start, boolean print) throws Exception {
		long end = basicRegionEnd(start);
		boolean allDefined = true;
		long at = start;
		while (at < end) {
			Data d = currentProgram.getListing().getDataContaining(addr(at));
			if (d == null || !d.isDefined()) {
				if (print) {
					println("DATA " + String.format("%04x", at) + " UNDEFINED");
				}
				allDefined = false;
				at++;
				continue;
			}
			if (print) {
				println("DATA " + String.format("%04x", d.getAddress().getOffset()) + " " +
					d.getDataType().getName() + " len=" + d.getLength() + " " +
					d.getDefaultValueRepresentation());
			}
			at = d.getAddress().getOffset() + d.getLength();
		}
		return allDefined;
	}

	// ------------------------------------------------------------------
	// C128 native BASIC fixed-map descriptor and shared CBM PRG loader
	// ------------------------------------------------------------------

	// Fixture from mkc128test.py: a native-mode BASIC program begins at $1C01,
	// with a well-formed linked line whose text preserves raw BASIC 7 CE/FE
	// prefixed-token pairs.  The initial C128 map deliberately models only the
	// static power-up arrangement; $FF00-$FF04 are KERNAL-resident MMU-shadow
	// controls represented by symbols rather than a physically-overlapping block.
	protected void checkC128NativeBasic7() {
		MemoryBlock prg = currentProgram.getMemory().getBlock(addr(0x1c01));
		MemoryBlock ram4000 = blockAt("RAM_4000", 0x4000);
		MemoryBlock basicLo = currentProgram.getMemory().getBlock("BASIC_LO");
		MemoryBlock basicHi = currentProgram.getMemory().getBlock("BASIC_HI");
		MemoryBlock editor = currentProgram.getMemory().getBlock("EDITOR");
		MemoryBlock kernal = currentProgram.getMemory().getBlock("KERNAL");
		MemoryBlock mmu = currentProgram.getMemory().getBlock("MMU");

		String mapPath = currentProgram.getOptions(currentProgram.PROGRAM_INFO)
			.getString("Retro Machine Map", "");
		boolean format = "Commodore 128 Native BASIC PRG".equals(
			currentProgram.getExecutableFormat());
		boolean prgPlaced = prg != null && prg.isInitialized() &&
			prg.getStart().getOffset() == 0x1c01 && prg.getEnd().getOffset() == 0x3fff &&
			fileOffset(prg, 0x1c01) == 2 && readByte(prg, 0) == 0x0b &&
			readByte(prg, 1) == 0x1c;
		boolean spansRamUnderBasicLo = initializedOverlay(ram4000, "RAM_4000") &&
			ram4000.getStart().getOffset() == 0x4000 && ram4000.getEnd().getOffset() == 0x7fff &&
			fileOffset(ram4000) == 0x2401;
		String prefixes = bytesAt(null, 0x1c06, 4);
		boolean prefixBytes = "ce 02 fe 03".equals(prefixes);
		boolean noBasicFunction = currentProgram.getFunctionManager().getFunctionAt(addr(0x1c01)) == null;
		boolean fixedRoms = initializedBlock(basicLo, 0x4000, 0x7fff, 0x10) &&
			initializedBlock(basicHi, 0x8000, 0xbfff, 0x20) &&
			initializedBlock(editor, 0xc000, 0xcfff, 0x30) &&
			initializedBlock(kernal, 0xe000, 0xffff, 0x40);
		boolean mmuVolatile = mmu != null && mmu.isVolatile() &&
			mmu.getStart().getOffset() == 0xd500 && mmu.getEnd().getOffset() == 0xd50b;
		boolean ioTypes = dataTypeAt(0x0000, "MOS8502_PORT") &&
			dataTypeAt(0xd000, "MOS_VICIIE") &&
			dataTypeAt(0xd400, "MOS6581_SID") &&
			dataTypeAt(0xd500, "MOS8722_MMU") &&
			dataTypeAt(0xd600, "MOS8563_VDC_PORTS") &&
			dataTypeAt(0xdc00, "MOS6526_CIA") && dataTypeAt(0xdd00, "MOS6526_CIA");
		boolean shadowSymbols = hasSymbol(0xff00, "MMU_CR_SHADOW") &&
			hasSymbol(0xff01, "MMU_LCRA") && hasSymbol(0xff02, "MMU_LCRB") &&
			hasSymbol(0xff03, "MMU_LCRC") && hasSymbol(0xff04, "MMU_LCRD");
		boolean staticCr00 = basicLo != null && !basicLo.isOverlay() && basicHi != null &&
			!basicHi.isOverlay() && editor != null && !editor.isOverlay() && kernal != null &&
			!kernal.isOverlay() && mmu != null && !mmu.isOverlay();

		println("=== BANKDUMP BEGIN ===");
		println("FORMAT c128=" + format + " map=" + mapPath);
		println("PRG " + describeBlock(prg) + " fileOffset=" + fileOffset(prg, 0x1c01) +
			" bytes=" + hx(readByte(prg, 0)) + " " + hx(readByte(prg, 1)) +
			" prefixes=" + prefixes);
		println("SPAN " + describeBlock(ram4000) + " fileOffset=" + fileOffset(ram4000));
		println("ROMS basicLo=" + describeBlock(basicLo) + " basicHi=" + describeBlock(basicHi) +
			" editor=" + describeBlock(editor) + " kernal=" + describeBlock(kernal));
		println("MMU " + describeBlock(mmu) + " volatile=" + mmuVolatile +
			" types=" + ioTypes + " shadowSymbols=" + shadowSymbols);
		println("SCOPE staticCr00=" + staticCr00 + " dynamicMmu=false");
		println("basicFunction=" + !noBasicFunction);
		println("=== BANKDUMP END ===");

		criterion("c128-format-map", format && "machines/c128.map".equals(mapPath), mapPath);
		criterion("c128-prg-placement", prgPlaced, describeBlock(prg));
		criterion("c128-prg-spans-basic-lo", spansRamUnderBasicLo,
			"payload crosses $4000 into RAM_4000 beneath BASIC_LO");
		criterion("c128-basic7-prefixes", prefixBytes, "bytes@1c06=" + prefixes);
		criterion("c128-basic-no-function", noBasicFunction,
			"no function at BASIC line link $1c01");
		criterion("c128-fixed-roms", fixedRoms,
			"BASIC_LO/BASIC_HI/EDITOR/KERNAL initialized with fixture bytes");
		criterion("c128-mmu-volatile", mmuVolatile, "$d500-$d50b MMU is volatile I/O");
		criterion("c128-io-types", ioTypes,
			"8502/VIC-IIe/MMU/VDC/CIA register types applied");
		criterion("c128-mmu-shadow-symbols", shadowSymbols,
			"MMU shadow controls represented at $ff00-$ff04");
		criterion("c128-static-cr00", staticCr00,
			"home blocks model only the CR=$00 native startup map; MMU switching is deferred");
	}

	protected boolean initializedBlock(MemoryBlock block, long start, long end, int firstByte) {
		return block != null && block.isInitialized() && block.getStart().getOffset() == start &&
			block.getEnd().getOffset() == end && readByte(block, 0) == firstByte;
	}

	// ------------------------------------------------------------------
	// Symbol-set toggle checkboxes (bead grm-zlj)
	// ------------------------------------------------------------------

	// Fixture imported with -loader-symbols-basic-zeropage true (enable the off-by-default
	// BASIC zero-page set) while leaving kernal-zeropage off. Asserts the checkbox applied
	// exactly that set: TXTTAB $002B present (basic-zp on via checkbox), no symbol at $0090
	// (kernal-zp still off), CHROUT $FFD2 present (kernal-api default on).
	protected void checkSymToggle() {
		boolean txttab = hasSymbol(0x002B, "TXTTAB");
		boolean statusSym = hasAnySymbol(0x0090);
		boolean chrout = hasSymbol(0xFFD2, "CHROUT");

		println("=== BANKDUMP BEGIN ===");
		println("TXTTAB@2B=" + txttab);
		println("SYM@90=" + statusSym);
		println("CHROUT@FFD2=" + chrout);
		println("=== BANKDUMP END ===");

		criterion("symtoggle-basic-zp-enabled", txttab, "TXTTAB@2B=" + txttab);
		criterion("symtoggle-kernal-zp-skipped", !statusSym, "sym@90=" + statusSym);
		criterion("symtoggle-kernal-api-on", chrout, "CHROUT@FFD2=" + chrout);
	}

	// ------------------------------------------------------------------
	// banktest.prg criteria (basic overlay retargeting)
	// ------------------------------------------------------------------

	protected void checkBanktest() {
		// C1: LDA $A000 in state 5 -> overlay READ ref RAM_A000::a000, primary
		Reference r = findOverlayRef(0x080F, "RAM_A000", 0xA000);
		criterion("C1", r != null && r.getReferenceType().isRead() && r.isPrimary(),
			"read of $A000 in bank 5 retargeted to RAM_A000 overlay, primary: " + describe(r));

		// C2: STA $E000 in state 5 -> overlay WRITE ref RAM_E000::e000
		r = findOverlayRef(0x0812, "RAM_E000", 0xE000);
		criterion("C2", r != null && r.getReferenceType().isWrite(),
			"write of $E000 in bank 5 retargeted to RAM_E000 overlay: " + describe(r));

		// C3: STA $A000 in home state 7 -> write-under-ROM overlay WRITE ref, primary
		r = findOverlayRef(0x0805, "RAM_A000", 0xA000);
		criterion("C3", r != null && r.getReferenceType().isWrite() && r.isPrimary(),
			"write under BASIC ROM in bank 7 retargeted to RAM_A000 overlay, primary: " +
				describe(r));

		// C4: JSR $FFD2 in state 7 -> KERNAL is home, no overlay ref from this instruction
		criterion("C4", overlayRefCount(0x0808) == 0,
			"JSR $FFD2 in bank 7 left untouched (" + overlayRefCount(0x0808) +
				" overlay refs)");

		// C5/C6: fully-known bank-switch comments at the two STA $01 sites
		String c = eol(0x0803);
		criterionEolKnown("C5", c, "bank -> 7 (",
			"fully known bank -> 7 comment at 0803: \"");
		c = eol(0x080D);
		criterionEolKnown("C6", c, "bank -> 5 (",
			"fully known bank -> 5 comment at 080d: \"");

		// C8 (grm-nip): the narrow unit check for the structural predicate used to
		// distinguish a changing phase-2 round from its stable follow-on round.
		//
		// C7:lifecycle-completed WAS REMOVED BY grm-6jfp AND MUST NOT BE RESTORED. It
		// asserted that a stable run persisted the "Retro Machines: initial run completed
		// v2: <class>" option, which existed only to gate routine logging to the FIRST run
		// (AnalyzerRunLog, bead grm-olp). grm-6jfp deleted that policy outright -- routine
		// diagnostics now go to Msg on every run and genuine warnings go to both Msg and
		// the MessageLog -- so there is no marker left to persist and nothing writes that
		// option. Saved Programs may still carry an orphaned copy; nothing reads it.
		// The lifecycle invariant that actually still matters is C8's, plus the
		// LAST_COMPLETED stamp ordering pinned by BoardBankAnalyzerCacheProgramTest.
		criterion("C8:lifecycle-fixpoint",
			!BankLifecycleProbe.stable(17, 18) && BankLifecycleProbe.stable(18, 18),
			"changing structural fingerprint stays initial; stable follow-on completes");

		// C9 (grm-bfb): once an overlay reference replaces the stock base-space one, the
		// base-space reference is RETIRED, not left as a secondary -- at a resolved site the
		// base block is only the window's home occupant, so the stock reference is a known-
		// wrong answer there (and on smb3 lands in an instruction interior). C1's read and
		// C3's write-under-ROM store both resolved away from home, so their base refs go;
		// C4's JSR $FFD2 resolved TO home, so its base ref is the right one and stays.
		criterion("C9a", baseRefCount(0x080F, 0xA000) == 0,
			"LDA $A000 in bank 5 keeps no base-space ref to $A000 (" +
				baseRefCount(0x080F, 0xA000) + " found)");
		criterion("C9b", baseRefCount(0x0805, 0xA000) == 0,
			"STA $A000 under BASIC ROM keeps no base-space ref to $A000 (" +
				baseRefCount(0x0805, 0xA000) + " found)");
		criterion("C9c", baseRefCount(0x0808, 0xFFD2) == 1,
			"JSR $FFD2 in bank 7 keeps its base-space ref to home KERNAL (" +
				baseRefCount(0x0808, 0xFFD2) + " found)");
	}

	protected static final class BankLifecycleProbe extends C64BankingAnalyzer {
		private static boolean stable(long entryFingerprint, long exitFingerprint) {
			return reachedFixpoint(entryFingerprint, exitFingerprint);
		}
	}

	// ------------------------------------------------------------------
	// banktest2.prg criteria (masked-RMW, partial knowledge, warnings, merge)
	// ------------------------------------------------------------------

	protected void checkBanktest2() {
		// C1: LDA $01 / AND #$FE / STA $01 with in-state 5 resolves exactly to bank 4
		String c = eol(0x0809);
		criterionEolKnown("C1", c, "bank -> 4 (",
			"in-state fallback resolves AND #$FE exactly at 0809: \"");

		// C2: LDA $01 / AND #$F8 / ORA #$05 / STA $01 resolves by mask algebra alone
		c = eol(0x0811);
		criterionEolKnown("C2", c, "bank -> 5 (",
			"mask algebra alone resolves bank 5 at 0811: \"");

		// C3: LDA $0400 / STA $01 is undeterminable. Nothing in the image stores to $0400, so
		// it is an untouched RAM cell: an HONEST gap (grm-rr5p) -- NOTE bookmark, no warning,
		// no resolved bank.
		criterion("C3", hasNoteBookmark(0x0816) && !hasWarningBookmark(0x0816) &&
			!eol(0x0816).contains("bank ->") && eol(0x0816).contains("NOTE: runtime source"),
			"undeterminable store at 0816 (untouched RAM $0400): note=" + hasNoteBookmark(0x0816) +
				" warning=" + hasWarningBookmark(0x0816) + " comment=\"" + eol(0x0816) + "\"");

		// C4: LDA $01 / ORA #$04 / STA $01 with unknown in-state -> partial (CHAREN known)
		c = eol(0x081C);
		criterion("C4",
			c.contains("bank -> 7? (") &&
				c.contains("[known: CHAREN=1; assumed from initial: LORAM,HIRAM]") &&
				!hasWarningBookmark(0x081C),
			"partial-knowledge comment, no warning, at 081c: \"" + c + "\"");

		// C5: LDA #$35 / JSR sub / STA $01. `sub` is a bare RTS, so CalleeRegisterSummary proves A
		// preserved and the immediate survives the call -> bank -> 5 (grm-mej.13; before that any
		// call was assumed to clobber the register and this was a WARNING).
		criterion("C5", !hasWarningBookmark(0x0823) && eol(0x0823).contains("bank -> 5 ("),
			"preserving-call store at 0823: warning=" + hasWarningBookmark(0x0823) +
				" comment=\"" + eol(0x0823) + "\"");

		// C6: backward scan from the STA at 082d crosses the intervening STX $01, so the
		// base must NOT inherit in-state (which would yield fully-known "bank -> 6 (");
		// only the ORA #$02 bit (HIRAM) is known, the rest is assumed from initial.
		c = eol(0x082D);
		criterion("C6",
			c.contains("? (") && c.contains("[known: HIRAM=1;") && !c.contains("bank -> 6 ("),
			"crossing-mechanism-write abort yields partial comment at 082d: \"" + c + "\"");

		// C7: merge of states 5 and 4 keeps agreeing bits (HIRAM=0, CHAREN=1); effective
		// state 5 -> the LDA $A000 at the join gets an overlay READ ref
		Reference r = findOverlayRef(0x083F, "RAM_A000", 0xA000);
		criterion("C7", r != null && r.getReferenceType().isRead(),
			"join-point read of $A000 retargeted to RAM_A000 overlay: " + describe(r));
	}

	// ------------------------------------------------------------------
	// banktest3.prg criteria (the two P1 value-recovery fixes)
	// ------------------------------------------------------------------

	protected void checkBanktest3() {
		// B1 (grm-5tl.1): the JSR at 0805 calls a helper that takes its bank argument in
		// X (STX $01). The caller loads an unrelated immediate into A (LDA #$AA -> bank 2)
		// and the real bank into X (LDX #$34 -> bank 4). The recovered bank must come from
		// the register the helper actually reads (X = 4), not the old A-first guess (2).
		String c = eol(0x0805);
		criterion("B1",
			c.contains("bank -> 4 (") && c.contains("via") && !c.contains("bank -> 2"),
			"helper call recovers X argument (bank 4), not A (bank 2), at 0805: \"" + c + "\"");

		// A1 (grm-5tl.2): the STA $01 at 080F is a branch-join target -- reached by
		// fall-through from LDA #$36 (A=$36) and by the BEQ at 080B (A undetermined). The
		// backward value scan must not confidently fold $36 at the join; the store is
		// ambiguous -> WARNING bookmark, no "bank ->" comment.
		criterion("A1",
			hasWarningBookmark(0x080F) && !eol(0x080F).contains("bank ->"),
			"join-target store is ambiguous at 080f: warning=" + hasWarningBookmark(0x080F) +
				" comment=\"" + eol(0x080F) + "\"");

		// B2 (grm-3ou part 1): the helper BODY's own store at 0812 (STX $01) can never resolve
		// -- the value is the caller's X, which is what B1 above recovers per CALL SITE. That is
		// an HONEST gap, not an analyzer limit, so it is a NOTE and must not inflate the warning
		// count. Contrast A1 directly above, where the value plausibly IS static and we simply
		// could not attribute it across a join: that stays a WARNING.
		criterion("B2",
			hasNoteBookmark(0x0812) && !hasWarningBookmark(0x0812),
			"helper body's caller-supplied X is an honest gap at 0812: note=" +
				hasNoteBookmark(0x0812) + " warning=" + hasWarningBookmark(0x0812));
	}

	// ------------------------------------------------------------------
	// banktest4.prg criteria (READ_WRITE reference split, bead grm-5tl.16)
	// ------------------------------------------------------------------

	protected void checkBanktest4() {
		// D1: INC $A000 in home state 7 is a read-modify-write across the write-under-ROM
		// boundary: it reads BASIC (the LOROM home occupant in state 7) and writes RAM_A000
		// (BASIC's on_write target, not home). The write side must get a primary WRITE
		// overlay ref to RAM_A000; the pre-fix bug pointed the *whole* RMW (including the
		// read) at the write target via a single overlay ref.
		Reference w = findOverlayRef(0x0805, "RAM_A000", 0xA000);
		criterion("D1", w != null && w.getReferenceType().isWrite() && w.isPrimary(),
			"INC $A000 in bank 7 gets a primary WRITE overlay ref to RAM_A000: " + describe(w));

		// D2: the read side must NOT be redirected to RAM_A000 (or any overlay space) --
		// BASIC is the home occupant for LOROM in state 7, so the read is already correctly
		// resolved by the original base-space reference and needs no overlay ref. A READ
		// overlay ref to RAM_A000 here is exactly the pre-fix misdirection bug.
		Reference readOverlay = null;
		Instruction instr = currentProgram.getListing().getInstructionAt(addr(0x0805));
		if (instr != null) {
			for (Reference r : instr.getReferencesFrom()) {
				if (r.getReferenceType().isRead() && r.getToAddress().getAddressSpace().isOverlaySpace()) {
					readOverlay = r;
					break;
				}
			}
		}
		criterion("D2", readOverlay == null,
			"no READ overlay ref at 0805 (read resolves via base-space ref to home BASIC): " +
				describe(readOverlay));

		// D3: exactly one overlay reference total from this instruction -- the primary WRITE
		// ref -- confirming the read side was left alone rather than also redirected.
		criterion("D3", overlayRefCount(0x0805) == 1,
			"exactly one overlay ref (the WRITE) at 0805 (" + overlayRefCount(0x0805) +
				" found)");

		// D4 (grm-bfb): the base-space ref must SURVIVE here. Retirement requires every side
		// of the access to resolve away from home, and D2 just established the read side
		// resolves to home BASIC through exactly this reference -- deleting it would leave
		// the read with no target at all. It stays, as a secondary to D1's primary WRITE.
		criterion("D4", baseRefCount(0x0805, 0xA000) == 1,
			"INC $A000 keeps its base-space ref for the home-BASIC read side (" +
				baseRefCount(0x0805, 0xA000) + " found)");
	}

	// ------------------------------------------------------------------
	// c64basictest.prg criteria (C64PrgLoader + C64BasicAnalyzer, bead grm-odt.1)
	// ------------------------------------------------------------------

	protected void checkC64Basictest() throws Exception {
		// B1: exact petcat-compatible detokenized line comments (PRE comment at each
		// line's link-word address). Line addresses/text mirror mkbasictest.py.
		criterion("B1:0801", "10 FOR I=1 TO 10".equals(preComment(0x0801)),
			"line 10 detokenizes exactly: \"" + preComment(0x0801) + "\"");
		criterion("B1:0810", "20 PRINT\"{clr}HI{$a0}\"".equals(preComment(0x0810)),
			"line 20 detokenizes exactly: \"" + preComment(0x0810) + "\"");
		criterion("B1:081c", "30 REM{lgrn}\" OK".equals(preComment(0x081C)),
			"line 30 detokenizes exactly: \"" + preComment(0x081C) + "\"");
		criterion("B1:0827", "40 DATA 1,2{lgrn}:PRINT 3".equals(preComment(0x0827)),
			"line 40 detokenizes exactly: \"" + preComment(0x0827) + "\"");
		criterion("B1:0836", "50 SYS 2115".equals(preComment(0x0836)),
			"line 50 detokenizes exactly: \"" + preComment(0x0836) + "\"");

		// B2: the REM body's token-lookalike byte ($99, PRINT's token value elsewhere)
		// rendered as its raw PETSCII control-code escape, not as the word "PRINT" --
		// already implied by the exact-match B1:081c above, but check explicitly so a
		// future accidental token-decode-inside-REM regression fails its own criterion.
		String rem = preComment(0x081C);
		criterion("B2", rem.contains("{lgrn}") && !rem.contains("PRINT"),
			"REM body not token-decoded (raw {lgrn} escape, no \"PRINT\"): \"" + rem + "\"");

		// B3: the quoted control byte in line 20 renders as {clr} (PetsciiMapper's name
		// for $93), not as a token.
		String pr = preComment(0x0810);
		criterion("B3", pr.contains("{clr}"),
			"quoted control byte renders as {clr}: \"" + pr + "\"");

		// B7 (grm-td4): every byte of the BASIC region carries defined data.
		criterion("B7:regionDefined", dumpBasicRegion(0x0801, false),
			"no undefined bytes in the BASIC region at 0x0801");

		// B4: the SYS target (2115, from line 50) is a real function, and the loader's
		// usual load-address function mark did NOT happen for this BASIC-start PRG.
		criterion("B4:funcAtSys", hasFunctionAt(0x0843),
			"function exists at SYS target 0x0843");
		criterion("B4:noFuncAtLoad", !hasFunctionAt(0x0801),
			"no function at the load address 0x0801 (BASIC line data, not code)");

		// B5: the wrapped-PRG no-op reports success, a run whose descriptor cannot be
		// loaded reports failure, and a later retry with the descriptor property restored
		// succeeds again. This exercises C64BasicAnalyzer's lifecycle wrapper directly:
		// first force its wrapped-PRG no-op, then point the descriptor property at a
		// missing map for the failure path. Because that retry's inputs (map path,
		// load address/length,
		// slices) end up identical to the Program's already-completed initial analysis,
		// it now also exercises the session-local redundant-re-run gate (grm-52z): the
		// retry completes via a same-inputs SKIP, not by re-walking/re-detokenizing, which
		// this now observes as "the program was not modified" (see the retry below).
		Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
		String mapProperty = "Retro Machine Map";
		// Forcing the analyzer's wrapped-PRG no-op used to mean setting a "Retro Machines.
		// CBM PRG Wrapped" property. That property is gone (grm-hap item 4) -- wrapped is
		// derived from the slice list -- so the lever moves to the slice list itself: one
		// slice of 2 bytes starting at $FFFF runs one byte past the top of the address
		// space, which is exactly what "wrapped" means. Restored from the original JSON in
		// the finally block below, same as before.
		String slicesProperty = "Retro Machines.CBM PRG Slices";
		String wrappedSlices =
			"[{\"file_offset\":2,\"length\":2,\"space\":\"RAM\",\"start\":65535}]";
		String originalMap = info.getString(mapProperty, "");
		String originalSlices = info.getString(slicesProperty, "[]");
		boolean noOpReturn;
		boolean failedReturn;
		boolean retryReturn;
		boolean retrySkippedAsRedundant;
		boolean mapWasPresent = info.contains(mapProperty);
		boolean slicesWasPresent = info.contains(slicesProperty);
		try {
			info.setString(slicesProperty, wrappedSlices);
			noOpReturn = new C64BasicAnalyzer().added(currentProgram, new AddressSet(), monitor,
				new MessageLog());

			info.setString(slicesProperty, originalSlices);
			info.setString(mapProperty, "machines/missing-lifecycle-test.map");
			failedReturn = new C64BasicAnalyzer().added(currentProgram, new AddressSet(), monitor,
				new MessageLog());

			info.setString(mapProperty, originalMap);
			// grm-52z: same map path/load address/length/slices as the Program's original
			// completed run, so the session-local gate short-circuits before the walk/GDT/
			// PETSCII work.
			//
			// THIS USED TO BE OBSERVED BY MATCHING THE SKIP MESSAGE IN retryLog. grm-6jfp
			// moved routine analyzer diagnostics off the MessageLog and onto Msg (so they
			// stop popping AutoAnalysisPlugin's "warnings/errors" dialog), so that text is
			// no longer in any MessageLog to match. Observe the gate's ACTUAL PROMISE
			// instead -- that the analysis body did not run -- which is strictly stronger
			// than a log-text match and does not depend on message wording: the walk writes
			// comments and data, so a real run moves getModificationNumber() and a skipped
			// one cannot.
			long modBeforeRetry = currentProgram.getModificationNumber();
			retryReturn = new C64BasicAnalyzer().added(currentProgram, new AddressSet(), monitor,
				new MessageLog());
			retrySkippedAsRedundant = currentProgram.getModificationNumber() == modBeforeRetry;
		}
		finally {
			if (mapWasPresent) {
				info.setString(mapProperty, originalMap);
			}
			else {
				info.removeOption(mapProperty);
			}
			if (slicesWasPresent) {
				info.setString(slicesProperty, originalSlices);
			}
			else {
				info.removeOption(slicesProperty);
			}
		}
		// B5 (grm-6jfp): the completion-MARKER half of this criterion is gone with the
		// policy it tested. It asserted that a successful/no-op run persisted "Retro
		// Machines: initial run completed v2: <class>" and that a FAILED run did not (plus
		// that a stale pre-fix "v1" marker was ignored). That option existed only to gate
		// routine logging to the first run; grm-6jfp deleted it, so nothing writes or reads
		// it and there is nothing left to assert. DO NOT REINSTATE those checks.
		//
		// What survives is the analyzer's LIFECYCLE CONTRACT, which never depended on the
		// marker and is what this criterion is now about: the wrapped-PRG no-op reports
		// success, a run whose descriptor cannot be loaded reports failure, and a retry
		// with the original inputs both succeeds AND short-circuits on the grm-52z
		// same-inputs gate rather than re-walking.
		criterion("B5", noOpReturn && !failedReturn && retryReturn && retrySkippedAsRedundant,
			"wrapped-PRG no-op succeeds; a run with a missing map fails; the retry succeeds " +
				"via the same-inputs redundant-re-run gate without touching the program " +
				"(noOpReturn=" + noOpReturn + ", failedReturn=" + failedReturn +
				", retryReturn=" + retryReturn + ", retrySkippedAsRedundant=" +
				retrySkippedAsRedundant + ")");

		// B6 (golden byte-identical dump) is enforced by run-banktest.sh's diff against
		// expected/c64basictest.dump; nothing further to check here.
	}

	// ------------------------------------------------------------------
	// petsciistringtest.prg criteria (C64PrgLoader + PetsciiStringAnalyzer, bead grm-1.4.4)
	// ------------------------------------------------------------------

	// Label addresses mirror mkpetsciistringtest.py's build() layout exactly.
	protected static final long PST_STR_A = 0x2001; // "TEST", null-terminated, len 4
	protected static final long PST_STR_B = 0x2006; // "ABCD", unterminated, len 4
	protected static final long PST_STR_C = 0x200B; // "HI!", 3 bytes, below min_length
	protected static final long PST_STR_D = 0x200F; // 0x61-0x64, outside PETSCII range
	protected static final long PST_STR_E = 0x2014; // "1,2;3", unterminated, len 5

	protected void checkPetsciiStringTest() {
		Data a = currentProgram.getListing().getDefinedDataAt(addr(PST_STR_A));
		Data b = currentProgram.getListing().getDefinedDataAt(addr(PST_STR_B));
		Data c = currentProgram.getListing().getDefinedDataAt(addr(PST_STR_C));
		Data d = currentProgram.getListing().getDefinedDataAt(addr(PST_STR_D));
		Data e = currentProgram.getListing().getDefinedDataAt(addr(PST_STR_E));

		println("=== BANKDUMP BEGIN ===");
		println("STR_A " + describeData(a));
		println("STR_B " + describeData(b));
		println("STR_C " + describeData(c));
		println("STR_D " + describeData(d));
		println("STR_E " + describeData(e));
		println("=== BANKDUMP END ===");

		// P1: null-terminated run typed TerminatedPetsciiString over run+terminator.
		criterion("P1:terminated", a != null &&
			"TerminatedPetsciiString".equals(a.getDataType().getName()) && a.getLength() == 5,
			describeData(a));

		// P2: unterminated run typed PetsciiString over exactly the run (no terminator).
		criterion("P2:fixed-unterminated", b != null &&
			"PetsciiString".equals(b.getDataType().getName()) && b.getLength() == 4,
			describeData(b));

		// P3: below-min_length decoy stays untyped.
		criterion("P3:decoy-untyped", c == null, describeData(c));

		// P4: graphics/control bytes outside the recognizer's range never match.
		criterion("P4:graphics-untyped", d == null, describeData(d));

		// P5: ASCII-range punctuation/digits count as PETSCII text too.
		criterion("P5:ascii-punct-typed", e != null &&
			"PetsciiString".equals(e.getDataType().getName()) && e.getLength() == 5,
			describeData(e));
	}

	// ------------------------------------------------------------------
	// nestbltest.nes criteria (NesRomLoader -loader-tblFile + TblStringAnalyzer, bead grm-pqk)
	// ------------------------------------------------------------------

	// Addresses mirror mknestbltest.py's make_prg() layout exactly.
	protected static final String TBL_NODE = "Retro Text Table";
	protected static final String TBL_CATEGORY = "TblStringAnalyzer";
	protected static final long[] TBL_ALL = { 0x9000, 0x9020, 0x9040, 0x9060, 0x9080, 0x90A0,
		0x90C0, 0x90E0 };

	/**
	 * @param label dump tag (nes, nes16, snes)
	 * @param mirrorDelta offset from each canonical string address to its byte-mapped mirror, or
	 *            0 when the image has no mirror of the string region
	 * @param tblName expected stored source file name
	 */
	protected void checkTblTest(String label, long mirrorDelta, String tblName) {
		Options node = currentProgram.getOptions(TBL_NODE);
		String source = node.getString("Source File", "");
		String text = node.getString("Table Text", "");

		println("=== BANKDUMP BEGIN ===");
		println("TBLSOURCE " + source);
		println("TBLTEXT length=" + text.length() + " crlf=" + text.contains("\r\n"));
		for (long a : TBL_ALL) {
			Address at = addr(a);
			String pre = currentProgram.getListing().getComment(CommentType.PRE, at);
			Bookmark bm = currentProgram.getBookmarkManager().getBookmark(at,
				BookmarkType.NOTE, TBL_CATEGORY);
			println(fmt(at) + " PRE " + (pre == null ? "<none>" : pre) + " | BOOKMARK " +
				(bm == null ? "<none>" : bm.getComment()));
		}
		int bookmarks = 0;
		Iterator<Bookmark> it =
			currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.NOTE);
		while (it.hasNext()) {
			if (TBL_CATEGORY.equals(it.next().getCategory())) {
				bookmarks++;
			}
		}
		println("TBLBOOKMARKS " + bookmarks);
		boolean mirrorClean = true;
		if (mirrorDelta != 0) {
			MemoryBlock mirrorBlock =
				currentProgram.getMemory().getBlock(addr(TBL_ALL[0] + mirrorDelta));
			println("TBLMIRROR block=" + (mirrorBlock == null ? "<none>" : mirrorBlock.getName()) +
				" mapped=" + (mirrorBlock != null && mirrorBlock.isMapped()));
			for (long a : TBL_ALL) {
				Address at = addr(a + mirrorDelta);
				String pre = currentProgram.getListing().getComment(CommentType.PRE, at);
				Bookmark bm = currentProgram.getBookmarkManager().getBookmark(at,
					BookmarkType.NOTE, TBL_CATEGORY);
				println(fmt(at) + " MIRROR PRE " + (pre == null ? "<none>" : pre) +
					" | BOOKMARK " + (bm == null ? "<none>" : bm.getComment()));
				mirrorClean &= pre == null && bm == null;
			}
			MemoryBlock home = currentProgram.getMemory().getBlock(addr(TBL_ALL[0]));
			criterion("T5:mirror-exists", mirrorBlock != null && home != null &&
				mirrorBlock != home, "mirror of " + fmt(addr(TBL_ALL[0])) +
				" is a distinct block (home=" + (home == null ? "<none>" : home.getName()) + ")");
			criterion("T6:mirror-unannotated", mirrorClean,
				"mirrored strings must not get a duplicate comment/bookmark");
		}
		println("=== BANKDUMP END ===");

		criterion("T1:table-stored", tblName.equals(source) &&
			text.contains("/FF=<end>") && text.contains("F001=QU"),
			"source=" + source + " textLen=" + text.length());

		String[][] expected = { { "9000", "TBL: HELLO WORLD!<end>" },
			{ "9020", "TBL: QUITE<end>" }, { "9040", "TBL: GAME<end2>" },
			{ "90A0", "TBL: A<br>BCD<end>" }, { "90E0", "TBL: ABCD<end>" } };
		for (String[] e : expected) {
			Address at = addr(Long.parseLong(e[0], 16));
			String pre = currentProgram.getListing().getComment(CommentType.PRE, at);
			Bookmark bm = currentProgram.getBookmarkManager().getBookmark(at,
				BookmarkType.NOTE, TBL_CATEGORY);
			criterion("T2:decoded-" + e[0], e[1].equals(pre) && bm != null, "pre=" + pre);
		}

		// Decoys: below minimum length (9060 "AB", 90C0 "NOW") and unterminated (9080).
		for (long a : new long[] { 0x9060, 0x9080, 0x90C0 }) {
			Address at = addr(a);
			criterion("T3:decoy-" + Long.toHexString(a),
				currentProgram.getListing().getComment(CommentType.PRE, at) == null &&
					currentProgram.getBookmarkManager().getBookmark(at, BookmarkType.NOTE,
						TBL_CATEGORY) == null,
				"decoy at " + fmt(at) + " must stay unannotated");
		}
		criterion("T4:exactly-five", bookmarks == 5, "bookmarks=" + bookmarks);
	}
}
