# Community disassembly survey (grm-hb6.6)

Preliminary survey of public NES and SNES disassemblies that `grm-hb6.6` could harvest into per-game
symbol sets. Two agent passes, 2026-10-04. **It records facts only.** Licenses are quoted as stated,
and anything unverified is `?`. The **redistributable?** column is the owner's to fill in.

**Priority (owner, 2026-10-04):** titles in the pinned real-ROM manifests come first. Other titles
are catalogued because other users may want them eventually, but harvesting them is lower priority.

**Spot-checked by the orchestrator against the GitHub API:**
- **Matched:** z2disassembly (CC0-1.0), zelda1-disassembly (none), smb3 (none), nes-contra-us (none),
  yoshisisland-disassembly (none), ct_disassembly (CC0-1.0), usdasm (GPL-3.0), and the GPL-3.0 side
  of the Yoshifanatic1 conflict.
- **sm_disassembly:** the API reports `NOASSERTION`, but its `LICENSE.txt` is the 0BSD text verbatim.
- **Not re-checked:** the Yoshifanatic1 "public domain" readme quote.

**Data Crystal** pages could not be fetched directly (403/429), so those URLs come from search results.

Fill-in convention: replace a `?` in **redistributable?** with your ruling, and date it.

---


Facts only. "?" = not verified / owner to decide. "No LICENSE file" means I probed LICENSE / LICENSE.md / LICENSE.txt / COPYING / UNLICENSE on the default branch (raw.githubusercontent) and the GitHub API reported `license: null`; I also read the README for any licensing sentence. "Stars" are approximate and as of the search date.

## NES: Tier 1 (priority)

| title | project | URL | license (as stated) | redistributable? | format / bank layout | completeness / ROM rev | maintenance |
|---|---|---|---|---|---|---|---|
| Legend of Zelda | aldonunez/zelda1-disassembly | https://github.com/aldonunez/zelda1-disassembly | No LICENSE file, nothing in README [1] | ? | ca65. `src/Z_00.asm`..`Z_07.asm` = one file per 16KB bank; `src/Z.cfg` ld65 config with segments `BANK_nn_xxx`; shared `*Vars.inc` | "A complete disassembly". Rebuilds byte-identical; README: build "expects Original.nes ... must be the "(U) (PRG0) [!]" version". Matches our pin. No hash quoted | last commit 2021-02-20; ~274 stars; not archived |
| Legend of Zelda | aldonunez/zelda1-disasm-labels | https://github.com/aldonunez/zelda1-disasm-labels | No LICENSE file, no README read (?) | ? | Mesen .MLB label export (the input to the tool above); format not inspected | companion to above; PRG0 presumably ? | 2021-02-20; 3 stars |
| Zelda II | FiendsOfTheElements/z2disassembly | https://github.com/FiendsOfTheElements/z2disassembly | `LICENSE` = CC0 1.0 Universal (GitHub SPDX CC0-1.0). README gives no separate sentence [2] | likely yes (CC0 as stated; but see note 2) | ca65. `src/prg0.asm`..`prg7.asm` one per 16KB bank; `src/variables.asm`; `nes.cfg` has MEM0-MEM7 + segments PRG0..PRG7 + VECTORS; plus `ram-map.txt`, `inc/` | Builds a ROM; CHR NOT shipped (`rip-chr.sh` extracts it from your ROM). No checksum or revision stated in README (?). Origin da65 output; "Originally pulled from lemmy.neocities.org/zelda2/zelda2 / Original disassembly by Trax" | last commit 2023-01-18, last push 2023-04-16; ~30 stars; active-ish |
| Zelda II | cwr-creative/z2disassembly-main | https://github.com/cwr-creative/z2disassembly-main | not checked | ? | appears to be a copy of above | duplicate | 2026-02; 0 stars. Ignore |
| Metroid | nmikstas/metroid-disassembly | https://github.com/nmikstas/metroid-disassembly | No LICENSE file, nothing in README [3] | ? | **Ophis** (bundled `Ophis/`). `Source_Files/Bank00.asm`..`Bank07.asm` + `Header.asm`, `Metroid_Defines.asm`; each bank starts `.org $8000`; forward `.alias` for fixed-bank labels. README bank names: 00 Intro/End, 01 Brinstar, 02 Norfair, 03 Tourian, 04 Kraid, 05 Ridley, 06 Graphics, 07 Engine | Rebuild: `build_script` assembles 8 bank binaries and compares md5 of each bank to the originals (hashes not quoted in README). Revision not stated; 6502disassembly.com page says "Metroid (USA)" for a different project. `Completion_Map/` png shows coverage: README calls the old version "a mess"; completeness ? (not claimed finished) | last push 2025-02-04; ~31 stars |
| Metroid | SourceGen project on 6502disassembly.com | https://6502disassembly.com/nes-metroid | Page: "Metroid is copyright 1986 Nintendo, Inc." (no license for the project file stated) | ? | SourceGen project file (no ROM), single ROM | Page: "This is not a finished disassembly." USA | not a repo (?) |
| Mega Man (1) | plasticsmoke/megaman1-disassembly-ca65 | https://github.com/plasticsmoke/megaman1-disassembly-ca65 | `LICENSE` = MIT, "Copyright (c) 2026 plasticsmoke" [4] | likely yes (MIT; but see note 4) | ca65 + Makefile. UNROM, 8 x 16KB PRG; README bank table: $00-$03 stage data, $04 Elec Man+sound, $05 main code, $06 sprite/anim data, $07 fixed. `cfg/nes.cfg`. Per-bank file naming not inspected (?) | "byte-perfect", every line commented. Checksums stated: CRC32 5DED683E, MD5 4d4ffdfe7979b5f06dec2cf3563440ad, SHA-1 2f88381557339a14c20428455f6991c1eb902c99. USA. ROM needed as `mm1.nes` (not shipped) | created 2026-07-27, last push 2026-07-29; 0 stars; new, single author, AI-assisted |
| Mega Man (1) | lsmmega/mm1 | https://github.com/lsmmega/mm1 | No LICENSE file; README names Bisqwit and nesdev as thanks only | ? | ca65 (cc65 + Makefile, `mm1.cfg`); source split by topic dirs (`engine/ home/ data/ stages/ ram/ ...`), bank placement via cfg (not inspected in detail) | Builds against `Megaman (U) [!].nes` SHA1 2F88381557339A14C20428455F6991C1EB902C99; completeness ? | last push 2026-09-25; 5 stars |
| Mega Man 2 | plasticsmoke/megaman2-disassembly-ca65 | https://github.com/plasticsmoke/megaman2-disassembly-ca65 | `LICENSE` = MIT, "Copyright (c) 2026 plasticsmoke" [4] | likely yes (MIT; see note 4) | ca65 + Makefile. MMC1; README: banks $0B-$0F engine (labeled), $00-$0A stage/data tables | "byte-perfect", US release PRG1; checksum table in README (values not copied; read it in repo). Also builds an NSFe | created 2026-02-23, last push 2026-07-18; 2 stars; AI-assisted, says so |
| Mega Man 2 | lsmmega/mm2 | https://github.com/lsmmega/mm2 | No LICENSE file | ? | ca65 + Makefile, `mm2.cfg`, topic dirs like mm1 | builds on `Megaman II (U) [!].nes` SHA1 6B5B9235C3F630486ED8F07A133B044EAA2E22B2 (revision PRG0/PRG1 not stated, ?) | last push 2026-09-25; 5 stars |
| Mega Man 3 | refreshing-lemonade/megaman3-disassembly | https://github.com/refreshing-lemonade/megaman3-disassembly | No LICENSE file, nothing in README [5] | ? | **xkas-plus** (`xkas.exe` bundled, 2.9MB). `assemble.asm` has `banksize $2000` and `incsrc bank00.asm`..; files `bank00.asm`..`bank1F` with `bank1A_1B`, `bank1C_1D`, `bank1E_1F` as combined 16KB pairs. 32 x 8KB PRG, MMC3 | README: "Disassembly is 100% finished, including code and data. Assembles to 100% clean ROM under xkas-plus"; "not all code is documented yet". Version "NTSC-U (United States)". Repo ships `chr_banks.asm` (934KB, CHR data as source) and `mm3.nes` (16 bytes = header only) | last push 2020-12-23; ~51 stars; same author has MM4/5/6 |
| Super Mario Bros. | threecreepio/smb-disassembly | https://github.com/threecreepio/smb-disassembly | No LICENSE file. `src/smb.asm` header: "This amazing disassembly was created by doppelganger (doppelheathen@gmail.com) here https://www.romhacking.net/documents/344/ / Ported to CC65 by threecreepio" [6] | ? | ca65 + Makefile. `src/main.asm`, `src/smb.asm` (single 32KB PRG, NROM, so no bank issue). `layout/` ld65 config. Needs "Super Mario Bros. (World).nes" for CHR extraction | ca65 port of doppelganger's complete disassembly; "(World)" = the JU PRG0 ROM we pin. Hash not quoted | last push 2021-05-16; ~27 stars |
| Super Mario Bros. | doppelganger SMBDIS v2.1 (original) | https://www.romhacking.net/documents/344/ ; gist https://gist.github.com/1wErt3r/4048722 | RHDN page: "No explicit license or usage terms are provided" (my paraphrase of absence; nothing quoted) | ? | single raw text listing `SMBDIS.ASM` (asm6-style); NROM, single PRG | "A comprehensive disassembly of the program ROM"; v2.1 dated 2015-01-26; author doppelganger | no longer updated (?) |
| Super Mario Bros. | SourceGen port of doppelganger's | https://6502disassembly.com/nes-smb | Page: "Super Mario Bros. is copyright 1985 Nintendo, Inc." (no license for the project file) | ? | SourceGen (v1.8+) project; ROM "Super Mario Bros. (Japan, USA).nes" 40,976 bytes CRC-32 3337ec46 | substantially complete, labels not substantially modified from the original | not a repo (?) |
| Super Mario Bros. | oranguthang/smb1_src | https://github.com/oranguthang/smb1_src | No LICENSE file. `docs/licensing.md`: "No license to Nintendo's original game code, graphics, music, characters, ROM images, disk images, or FDS BIOS is granted by this repository." and tools/docs "currently have no separate repository-wide license grant." [7] | NO per its own statement | ca65 + Makefile; `src/{audio,data,game,memory,rendering,system}/`, `src/main.asm`; linker contracts in `config/linker/`; Python build/validation scripts; bundles ca65.exe/ld65.exe (zlib) | Byte-identical reconstruction of 7 official releases (NES, Vs., FDS). Target ROM `Super Mario Bros. (JU) [!].nes` SHA-1 `ea343f4e445a9050d4b4fbac2c77d0693b1d0922`. Heavily semantic renames (`config/reconstruction/label_renames.json`) | created 2026-01-05, last push 2026-09-10; 1 star; heavy tooling, likely AI-assisted (?) |
| SMB3 | captainsouthbird/smb3 | https://github.com/captainsouthbird/smb3 | No LICENSE file, nothing in README about license [8] | ? | **NESASM** (`nesasm.exe` bundled; README links camsaul/nesasm). `smb3.asm` main with `.inesprg 16 / .inesmap 4`; `PRG/prg000.asm`..`prg031.asm` = one file per 8KB MMC3 bank, plus `PRG/levels`, `maps`, `objects`; `CHR/`. Labels follow `PRGnnn_Xxxx` pattern | README: "reassemble into a byte-for-byte perfect clone of Super Mario Bros. 3 US (PRG1)". Matches our pin. Widely commented | last push 2025-05-01; ~244 stars; the canonical one (author of the disassembly) |
| SMB3 | (others) | - | - | - | none found on GitHub search besides the above | - | - |

Notes
1. Zelda: the README credits Disch's FF disassembly and doppelganger's SMB disassembly as inspiration. The listing was generated by a custom tool from a Mesen .MLB file + ROM. Contact given: aldonunez1@gmail.com.
2. Z2: CC0 is stated by the repo, but the content is derivative of Trax's disassembly (README: "Original disassembly by Trax (99.9% of his work)", header of prg0.asm), and the CC0 dedication is presumably by the repo owner, not necessarily Trax; underlying Nintendo copyright of the game code is not addressed. Owner should judge.
3. Metroid: README says it began as Kent Hansen's engine disassembly "many years ago"; sources metroid-database.com / nicholasmikstas.com are dead (from search snippet, ?).
4. plasticsmoke repos: MIT notice is the repo owner's; both README say annotated with Claude Code (MM2 README states it; MM1 README I read does not). MIT covers the annotation only; it says nothing about Capcom's code that the source necessarily contains.
5. MM3 ships a bundled binary (xkas.exe, 2.9MB) and 934KB chr_banks.asm (CHR bytes as source text). Redistribution of the extracted CHR is an obvious concern. Mega Man 4/5/6 by same author: refreshing-lemonade/megaman{4,5,6}-disassembly (see Tier 3).
6. Many forks of doppelganger's work exist; threecreepio's is the best-known ca65 port.
7. smb1_src: only project found that carries an explicit "no license granted" document. Treat as a stated negative.
8. SMB3 repo bundles `nesasm.exe` and level-editor files (game.xml, icons).

Sources I checked for competing disassemblies: for Zelda, `njgreb/zelda1-disassembly-master` surfaced in a web search (not examined; probably a fork/copy, ?).

## NES: Tier 2 (rest of pinned set)

| title | project | URL | license (as stated) | redistributable? | format / bank layout | completeness / ROM rev | maintenance |
|---|---|---|---|---|---|---|---|
| Contra | vermiceli/nes-contra-us | https://github.com/vermiceli/nes-contra-us | No LICENSE file. README: thanks Trax "initial disassembly" | ? | ca65 + `contra.cfg` (UxROM). `src/bank0.asm`..`bank7.asm`, `constants.asm`, `ram.asm`, `ines_header.asm`. Does NOT ship graphics/audio data: needs `baserom.nes` to extract assets (`assets.txt`) | "annotated disassembly ... byte-for-byte match". MD5 of baserom `7BDAD8B4A7A56A634C9649D20BD3011B` (US). Also builds Probotector | last push 2026-06-07; ~231 stars; canonical. Sibling: vermiceli/nes-super-c |
| Contra (J) | ZReC/contraj-disasm | https://github.com/ZReC/contraj-disasm | No LICENSE file | ? | asm6, `prg/` dir | "wannabe complete"; first iteration; Japan release (not our pin) | last push 2022-05; 4 stars |
| Ironsword / Wizards & Warriors 1/2 | none found | | | | | | |
| TMNT 1 / 3 | none found | | | | | | |
| Romance of the Three Kingdoms 2 | none found | | | | | | |
| Dragon Power | none found | | | | | | |
| Bionic Commando | none found | | | | | | |
| Blaster Master | MetaFight/blaster-master-disasm-public | https://github.com/MetaFight/blaster-master-disasm-public | No LICENSE file; README has no licensing sentence (read first ~1800 chars; ? beyond that) | ? | `disasm/` = "ca65-compatible listings + MLB labels for emulators" (not a rebuild-from-source? ?); `wiki/` knowledge base | "Blaster Master (US)"; README progress table: 146 / 793 subroutines "verified" (18%). README states done "with limited Claude Code assistance" and labels reviewed by a human | last push 2026-09-23; 1 star |
| Castlevania 1 | josephstevenspgh/Castlevania-Labelled-Disassembly | https://github.com/josephstevenspgh/Castlevania-Labelled-Disassembly | No LICENSE file | ? | single file `cvclean.asm.txt` (raw text listing); assembler ? | "Incomplete labelling"; revision ? | last push 2018-02; 8 stars |
| Castlevania 2 | none found | | | | | | |
| Castlevania 3 | `vinheim3/castlevania3-disasm` was named on Data Crystal per a web-search snippet; I could not confirm the repo or its contents (rate-limited / README I fetched looked like a different game) | ? | ? | ? | ? | ? | ? |
| Super Dodge Ball | none found | | | | | | |
| Dr. Mario | brianhuffman/drmario | https://github.com/brianhuffman/drmario | No LICENSE file; README no license sentence | ? | ca65 + Makefile; flat files `drmario.a65`, `drmario_a.a65`, `audio.a65`, `macros.a65`; `drmario.cfg`, `rom32k.cfg`. Needs original ROM for art | builds both original NTSC (`drmario.nes`) and Rev A (`drmario_a.nes`), md5 files in repo. 32KB NROM-ish, no banking | last push 2025-03-02; 12 stars |
| Dr. Mario | Nostaljipi/dr-mario-disassembly | https://github.com/Nostaljipi/dr-mario-disassembly | No LICENSE file | ? | asm6f (bundled `asm6f.exe`); `drmario.asm`, dirs `prg/ data/ defines/ header/ samples/ unused/` | "builds Dr. Mario (Japan, USA) (Rev A).nes" | last push 2021-11; 20 stars |
| Final Fantasy 1 | BenWenger/FinalFantasyDisassembly (Disch's) | https://github.com/BenWenger/FinalFantasyDisassembly | No LICENSE file. readme.txt: "This can be used for whatever means you want, but the goal was for it to allow for a ridiculous easy way to perform ASM hacks and bugfixes to the game." (Disch, v1.0) | ? (informal grant; owner to judge) | ca65 + ld65 bundled, `nes.cfg`. Dir `Final Fantasy Disassembly/`: `bank_00.dat`..`bank_0F` (`.asm` for 01, 09, 0B-0F; `.dat` for the rest = raw data banks); `Constants.inc`, `variables.inc`, `macros.inc`, `nesheader.bin` | readme: "fully commented and documented, reassemblable disassembly of the US release". v1.0 "Complete". Revision ? | last push 2019-10-05; ~19 stars; canonical |
| Kid Icarus | none found (only a Game Boy "kid-icarus-omm" repo, not NES) | | | | | | |
| Life Force | none found | | | | | | |
| Legendary Wings | none found | | | | | | |
| SMB2 (USA) | Xkeeper0/smb2 (via pepperpow/smb2 mirror/fork) | https://github.com/pepperpow/smb2 ; upstream per README https://github.com/Xkeeper0/smb2 | No LICENSE file seen on pepperpow/smb2 (upstream ? not checked); README no license sentence read | ? | asm6f (binaries bundled). README: `build` = PRG0, `build -dREV_A` = PRG1; prints SHA-256 of PRG0, PRG1 and ROM; docs site xkeeper0.github.io/smb2 | "intended to fully disassemble, comment ... everything"; completeness ?. Builds both revisions (PRG0/PRG1) | not checked |
| RC Pro-Am | none found | | | | | | |
| River City Ransom | none found | | | | | | |
| Tetris (NES, Nintendo) | CelestialAmber/TetrisNESDisasm | https://github.com/CelestialAmber/TetrisNESDisasm | No LICENSE file; README no license sentence | ? | ca65 (cc65 as submodule), `tetris.asm`, `main.asm`, `tetris.nes.cfg`, `tetris-ram.asm`, dirs `audio/ data/ gfx/ tools/` | builds "Tetris (U) [!].nes md5: ec58574d96bee8c8927884ae6e7a2508" (also `tetris-pal.sha1`). Derived from ejona86/taus | last push 2024-03-28; ~107 stars; canonical. Also a Tengen version (Tier 3) |
| Ultima IV | none found | | | | | | |
| Dragon Ball titles (4) | none found | | | | | | |

## NES: Tier 3: General interest (not pinned), found in passing, lightly checked

| title | project | URL | license (as stated) | redistributable? | format / bank layout | completeness / ROM rev | maintenance |
|---|---|---|---|---|---|---|---|
| Dragon Warrior (1) | nmikstas/dragon-warrior-disassembly | https://github.com/nmikstas/dragon-warrior-disassembly | not verified (LICENSE probe found nothing; API rate-limited so README unread) | ? | ? (same author as Metroid, so probably Ophis, ?) | ? | last push 2023-08; 88 stars |
| Dragon Warrior II | Nathan-R-Og/dq2 | https://github.com/Nathan-R-Og/dq2 | ? | ? | ? | ? | 2026-04 |
| Dragon Warrior IV | TheAnsarya/dragon-warrior-4-info | https://github.com/TheAnsarya/dragon-warrior-4-info | ? | ? | disassembly + asset extraction + editors | "complete" per description | 2026-02; 2 stars |
| Mega Man 4/5/6 | refreshing-lemonade/megaman{4,5,6}-disassembly | https://github.com/refreshing-lemonade/megaman4-disassembly (and 5, 6) | No LICENSE file on MM4/5/6 (probe) | ? | same author/format as MM3 (xkas, per-bank files, ? not inspected) | "Full disassembly" per description | pushes 2026-07..09; 20-34 stars |
| Mega Man 2 | (see Tier 1: lsmmega, plasticsmoke) | | | | | | |
| Super C | vermiceli/nes-super-c | https://github.com/vermiceli/nes-super-c | No LICENSE file (probe) | ? | same author/format as Contra | annotated; US + Probotector | 2026-07; 26 stars |
| Final Fantasy II / III | everything8215/ff2, ff3 | https://github.com/everything8215/ff2 | ? | ? | ? | "Disassembly and ROM info" | 2022; 22-24 stars |
| Crystalis | crystalisdisassembly/crystalisdisassembly | https://github.com/crystalisdisassembly/crystalisdisassembly | ? | ? | ca65 per search snippet | reassemblable | 2019; 14 stars |
| Kirby's Adventure | Nathan-R-Og/kirbyadventure ; yay58/Kirby-s-Adventure-Disassembly | https://github.com/Nathan-R-Og/kirbyadventure | ? | ? | WIP (first); x816 (second) | WIP | 2026-09 / 2025-09 |
| Tetris (Tengen) | zohassadar/TengenTetrisDisasm | https://github.com/zohassadar/TengenTetrisDisasm | ? | ? | ? | ? | 2024-12; 15 stars |
| SMB2J (Lost Levels) | threecreepio/smb2j-disassembly | https://github.com/threecreepio/smb2j-disassembly | ? | ? | ca65 port of doppelganger's | ? | 2021; 15 stars |
| Duck Tales | none found | | | | | | |

## NES: Data Crystal (priority-1 titles)

Site-wide license, quoted from https://datacrystal.tcrf.net/wiki/Main_Page: "Content is available under GNU Free Documentation License 1.2 unless otherwise noted." (site footer also links the GFDL 1.2 logo). Footer pages: Privacy policy, About Data Crystal, Disclaimers. Note GFDL for per-address data tables is itself something for the owner to weigh.

Direct HTTP fetches return 403/429 (anti-bot), so URLs below come from search results, not from my opening the page. Confirm each before citing.

| title | RAM map | ROM map | notes |
|---|---|---|---|
| Legend of Zelda | https://datacrystal.tcrf.net/wiki/The_Legend_of_Zelda/RAM_map | https://datacrystal.tcrf.net/wiki/The_Legend_of_Zelda/ROM_map | revision coverage ? |
| Zelda II | https://datacrystal.tcrf.net/wiki/Zelda_II:_The_Adventure_of_Link/RAM_map | https://datacrystal.tcrf.net/wiki/Zelda_II:_The_Adventure_of_Link/ROM_map | |
| Metroid | https://datacrystal.tcrf.net/wiki/Metroid/RAM_map | https://datacrystal.tcrf.net/wiki/Metroid:ROM_map | ROM map is mostly room/map data and offsets |
| Mega Man | https://datacrystal.tcrf.net/wiki/Mega_Man_(NES)/RAM_map | https://datacrystal.tcrf.net/wiki/Mega_Man_(NES)/ROM_map | |
| Mega Man 2 | https://datacrystal.tcrf.net/wiki/Mega_Man_2/RAM_map | https://datacrystal.tcrf.net/wiki/Mega_Man_2:ROM_map | ROM map is gameplay constants |
| Mega Man 3 | https://datacrystal.tcrf.net/wiki/Mega_Man_3_(NES)/RAM_map | ROM map ? (not seen) | |
| Super Mario Bros. | https://datacrystal.tcrf.net/wiki/Super_Mario_Bros.:RAM_map | https://datacrystal.tcrf.net/wiki/Super_Mario_Bros./ROM_map | RAM map covers "Super Mario Bros. (JU) (PRG0)" per search summary |
| Super Mario Bros. 3 | https://datacrystal.tcrf.net/wiki/Super_Mario_Bros._3/RAM_map | https://datacrystal.tcrf.net/wiki/Super_Mario_Bros._3/ROM_map | revision (PRG0/PRG1) ? |

Also: Z2 repo ships its own `ram-map.txt` (19KB) in the repo (license CC0 per repo).

## NES: Open questions for the owner

1. Most community disassemblies (Zelda, Metroid, MM1 lsmmega, MM2 lsmmega, MM3, SMB ca65 port, SMB3, Contra, Dr. Mario x2, Tetris, FF1, Castlevania) have NO LICENSE file and no licensing sentence. Only explicit grants found: Z2 (CC0), plasticsmoke MM1/MM2 (MIT), FF1 readme.txt ("whatever means you want"). Only explicit denial: oranguthang/smb1_src ("No license to Nintendo's original game code..." ). Policy needed: harvest label names/addresses only (facts) vs. need a license; consider asking authors (aldonunez gives an email in README).
2. Even for CC0/MIT repos, the code is derivative of Nintendo/Capcom code and (Z2) of Trax's disassembly. Is a symbol-name+address table (no code, no bytes) acceptable? Probably the same question for all.
3. Competing sources: MM1 and MM2 each have two (plasticsmoke MIT, AI-assisted, very new; lsmmega, no license, builds on same ROMs). SMB: threecreepio ca65 port vs original doppelganger text vs oranguthang (explicitly unlicensed, most semantic names) vs SourceGen. Zelda II: only z2disassembly. Metroid: nmikstas (not finished) only.
4. AI-assisted repos (plasticsmoke MM1/MM2, oranguthang SMB, MetaFight Blaster Master) have names that may be unverified; MetaFight itself marks only 18% verified. Consider a trust tier.
5. PRG revision pins: Zelda (PRG0 USA) and SMB3 (PRG1 USA) match; SMB (World) = JU PRG0 per threecreepio; MM2 plasticsmoke = PRG1 (lsmmega revision unstated); Z2, Metroid, MM1 (USA single rev) revision not stated by READMEs.
6. Bank mapping: Zelda/Z2/Contra/Metroid/SMB3/MM3/FF1 have per-bank files or segments (easy). MM1/MM2 repos use topic directories with banking in the ld65 cfg (needs the map). Metroid uses Ophis per-bank `.org $8000` files with forward-declared fixed-bank aliases. SMB3 and MM3 use 8KB banks (MMC3); the others 16KB.
7. Data Crystal: GFDL 1.2 license; direct fetch blocked so page contents (and revision applicability) not verified by me. Human check for Metroid ROM/RAM map revision.
8. Unchecked: Zelda "njgreb/zelda1-disassembly-master"; Xkeeper0/smb2 upstream license; vinheim3 Castlevania 3; READMEs/licenses for tier 3. GitHub unauthenticated rate limit hit toward the end.

---


Surveyed 2026-10-04 via GitHub API / READMEs / web search. "?" = not verified. Licenses are AS STATED; no inference from neighbouring repos. "Last push" is GitHub `pushed_at`. NES not covered (parallel agent).

## SNES: Tier 1: pinned real-ROM set

| title | project | URL | license (as stated) | redistributable? | format / bank layout | completeness / ROM rev | maintenance |
|---|---|---|---|---|---|---|---|
| Super Mario RPG (USA) (SA-1) | Yoshifanatic1/Super-Mario-RPG-Disassembly | https://github.com/Yoshifanatic1/Super-Mario-RPG-Disassembly | `LICENSE` = GPL-3.0 text; but "Framework Readme.txt" says "this framework and all compatible disassemblies are public domain" [1] | ? (conflicting statements) | asar; framework; `SMRPG/RomMap`, RAM_Map/BWRAM_Map .asm, `SPC700/`, `Tables/`; no per-bank file split seen at top level (layout in RomMap?). Assets extracted from user ROM, not shipped [1] | WIP ("Upload WIP SMRPG Script Disassembly Scripts" last commit); rev/hash ? ; SA-1 code coverage ? (BWRAM map present, `Firmware/` dir exists) | last push 2021-05-04, 48 stars, not archived |
| Super Mario RPG | wenzy21/SMRPG | https://github.com/wenzy21/SMRPG | no license file listed? ; not inspected | ? | ? | "Super Mario RPG Disassembly Level"; likely empty/stub | 2024, 0 stars |
| Kirby Super Star (USA) | Ankouno/KSS-disassembly | https://github.com/Ankouno/KSS-disassembly | no license file, no README | ? | asar-style (`org $008000`); only `Bank00.asm`, `Bank01.asm`, `Bank16.asm` + Graphics/CharMaps/.editorconfig; per-bank files, comments carry `$BBAAAA` addresses | PARTIAL (3 banks); rev ? | last push 2023-10-07, 12 stars |
| Kirby Super Star (USA) | Nathan-R-Og/kirbysuperstar | https://github.com/Nathan-R-Og/kirbysuperstar | no license file; README has no licensing sentence | ? | WLA-DX; `./configure` splits banks from user's ROM; builds new ROM | "Still incredibly WIP"; US only | created 2026-04, 0 stars |
| Kirby Super Star | yay58/Kirby-Super-Star-Kirby-Fun-Pak-Disassembly | https://github.com/yay58/Kirby-Super-Star-Kirby-Fun-Pak-Disassembly | not inspected (no README) | ? | "Might require some assembler" | ? (likely low quality) | 2025-09, 1 star |
| Star Fox (USA) (GSU) | SpyderTL/StarFoxDisassembly | https://github.com/SpyderTL/StarFoxDisassembly | no license file, README: "(NOT READY TO BE ASSEMBLED YET!)" | ? | ? (not inspected) | "US version 1.2" (= Rev 2?); partial; GSU coverage ? | last push 2020-10-26, 18 stars |
| Star Fox (USA/JP/EU) | themabus/StarFoxMasterBuilder | https://github.com/themabus/StarFoxMasterBuilder | no license file. README: "Upload will be a diff patch file for you to apply on your SG.LZH/MAPS.LZH content - so no dodgy source files hosted here." [2] | ? (repo ships NO source; patch against Nintendo's leaked SDK source) | Restored original (leaked-SDK-based) source, 1:1 retail build; GSU is part of it (original source is GSU+65816+SPC) | USA crc32 0bae0941 / md5 9dce6a9d... (Rev 0); USA/JP Rev1, Rev2 "working on", not done (SGSOUND source separately below) | last push 2022-01-20, 8 stars. NOTE: derived from leaked Nintendo SDK material; owner to judge |
| Star Fox | phonymike/starfox_spc_driver | https://github.com/phonymike/starfox_spc_driver | no license file | ? | SPC700 sound driver only (see SPC table) | 1:1 sha1 84a3411c5c64... for SGSOUND0.BIN | pushed 2026-10-01 |
| Super Mario World 2: Yoshi's Island (USA) (GSU) | brunovalads/yoshisisland-disassembly (Raidenthequick/TheGreekBrit, "canonical") | https://github.com/brunovalads/yoshisisland-disassembly | no license file, README has no licensing sentence | ? | asar; `disassembly/bank00..` + `assemble.asm`; README: 65816 + Super FX + SPC-700 + data; GSU labels prefixed `gsu_`; `docs/` ; wiki exists. Graphics extracted separately | README: "100% finished, assembles under asar and produces a fully clean ROM", "Not all code is documented". V1.0 NTSC-US; MD5 CB472164C5A71CCD3739963390EC6A50, SHA1 C807F2856F44FB84326FAC5B462340DCDD0471F8 | last push 2026-08-15, 161 stars |
| Yoshi's Island (USA 1.0 + 1.1) | Yoshifanatic1/Yoshi-s-Island-Disassembly | https://github.com/Yoshifanatic1/Yoshi-s-Island-Disassembly | `LICENSE` GPL-3.0 text; framework readme claims public domain [1] | ? (conflict) | asar framework; `YI/RomMap`, `YI/SuperFX/`, `YI/SPC700/`, RAM_Map/ExRAM_Map; assets extracted from ROM | V1.0 and V1.1 (md5 bb9c2f667ced16a2e605b385c041c744 / ce1e3e33b6e39d37b43d7de599f9e785); GSU dir present, completeness ? | last push 2021-06-21, 11 stars |
| Stunt Race FX (USA Rev 1) (GSU) | none found | - | - | - | - | Only partial original-dev files (Elmar Krieger: PIXSPLI1-1, VARDEF-1.INC) at https://github.com/sttng/gb-stuff (krieger/); not a disassembly; license ? | - |
| Pilotwings (USA) (DSP-1) | none found | - | - | - | - | - | - |
| Super Mario Kart (USA) (DSP-1) | Yoshifanatic1/Super-Mario-Kart-Disassembly | https://github.com/Yoshifanatic1/Super-Mario-Kart-Disassembly | `LICENSE` GPL-3.0; framework readme: public domain [1] | ? (conflict) | asar framework; `SMK/RomMap`, RAM_Map/SRAM_Map, `SPC700/`, `TrackData/`, `Tilemaps/`; `Firmware/` dir (DSP-1 firmware?) | completeness ?; DSP-1 microcode covered? ? | last push 2021-01-11, 14 stars |
| Super Mario Kart (USA) | jvipond/super_mario_kart_disassembly | https://github.com/jvipond/super_mario_kart_disassembly | `LICENSE` = MIT, "Copyright (c) 2019 jvipond" | likely yes (MIT), but repo ships `super_mario_kart.asm` + `labels.txt` derived from an instruction trace; ROM bytes in the asm? ? | asar; Python script generates `bank00.asm..bank07.asm` from snes9x instruction trace (LoROM? ?); ships `labels.txt`, `jumpTablePCToFuncName.txt`, `hardware_registers.asm` | "produces a fully clean ROM" (USA .sfc); labels are auto/partial | last push 2020-03-06, 5 stars |
| Super Mario Kart | MrL314/smk-spc700-disassembly | https://github.com/MrL314/smk-spc700-disassembly | no license file; README mentions annotation-patch system "to be distributed without containing proprietary code" | ? | SPC700 audio driver only (see SPC table) | USA/JPN/PAL driver | last push 2023-05-17 (updated 2026-07), 13 stars |
| Street Fighter Alpha 2 (USA) | none found | - | - | - | - | - | - |
| Mega Man X3 (USA) (Cx4) | none found as disassembly. mstan/MegamanX3SNESRecomp is a static recompilation (C), not labels | https://github.com/mstan/MegamanX3SNESRecomp | `LICENSE` = PolyForm Noncommercial 1.0.0, "Copyright (c) 2026 Matthew Stanley" | likely NO for general redistribution (noncommercial); owner to confirm | C recompiler on snesrecomp; has `docs/WIDESCREEN.md` with addresses. ROM CRC32 0xFA0FE671, SHA-256 65b03268... | boots, partial coverage | last push 2026-10-03 |
| Tales of Phantasia (SFC, JP, fan-translated) (S-DD1) | none found | - | - | - | - | Data Crystal page exists (see DC table) | - |
| Mario's Early Years: Fun with Numbers | none found | - | - | - | - | - | - |

[1] Yoshifanatic1 "SNES-ROM-Framework" readme (included in every one of his repos) states: "this framework and all compatible disassemblies are public domain. You're free to edit, copy, etc. this framework and any disassemblies made with no strings attached." Yet each repo ships GPL-3.0 `LICENSE` (GitHub detects GPL-3.0). Both verified verbatim/by API. Assets are NOT shipped (extracted from user ROM via `ExtractAssets.bat`; the readme says it is "safer to distribute ... by not including the copyrighted assets"). Repos bundle exe tools (asar.exe, decomp.exe, brr tools). Other Yoshifanatic1 SNES repos (not pinned): SMW-SMAS-SMASW, DKC1/2/3, EarthBound, Mega-Man-7, Kirby's Dream Land 3, Mario Paint, Super Punch-Out, SimCity, TMNT IV, Jurassic Park, Goof Troop, etc. (all under https://github.com/Yoshifanatic1).
[2] StarFoxMasterBuilder: even the repo owner flags this as derived from SDK source files that the user must supply; very likely not harvestable for symbols without those files.

Coprocessor summary: GSU is covered by brunovalads/YI (`gsu_` routines) and Yoshifanatic1/YI (`SuperFX/`). SA-1 (SMRPG), DSP-1 (SMK, Pilotwings), Cx4 (MMX3), S-DD1 (Tales) coverage: none confirmed; `?`.

## SNES: Tier 2: general interest (not pinned)

| title | project | URL | license (as stated) | redistributable? | format / bank layout | completeness / ROM rev | maintenance |
|---|---|---|---|---|---|---|---|
| Super Mario World | galaxyhaxz/smw-src | https://github.com/galaxyhaxz/smw-src | no license file; README: archived "for historical purposes, as-is" | ? | WLA-DX (old modified), assembles `Super Mario World (U) [!].smc` binary exact | full, based on SMWCentral all.log | 2021, 57 stars (author says no more work) |
| Super Mario World | gnaghi/SMWDisC ("all.log++") | https://github.com/gnaghi/SMWDisC | no license file seen (has `license` dir? ; contents not read) | ? | WLA, `src/`, `include/`; also raw all.log | commented; ROM rev U presumably ? | 2015, 24 stars |
| Super Mario World | Yoshifanatic1/SMW-SMAS-SMASW-Disassembly | https://github.com/Yoshifanatic1/SMW-SMAS-SMASW-Disassembly | GPL-3.0 (+ public domain claim [1]) | ? | asar framework | SMW + SMAS variants | 2021, 28 stars (pushed 2021-03) |
| Super Mario World | SMWDisX (SMW Central) | not found on GitHub; likely on SMWCentral | ? | ? | ? | ? (owner/human: check smwcentral.net resource) | ? |
| Super Mario World (C reimplementation) | snesrev/smw | https://github.com/snesrev/smw | `LICENSE.txt` (GitHub: NOASSERTION; contents not read) | ? | C reimplementation, not asm; ROM needed for assets | playable start to end; different kind of source | last push 2024-01, 634 stars |
| Zelda: ALttP (US) | spannerisms/usdasm ("Kan"; canonical) | https://github.com/spannerisms/usdasm | `LICENSE` = GPL-3.0 | ? (likely yes GPL; binaries not included) | Futaba assembler (`alttp.futaba`); `bank_00.asm`..`bank_1E.asm` + rooms/overworlds/text/spc/sound; binaries from user ROM | "compiles exactly to the US version" CRC32 777AAC2F, MD5 608C22B8FF930C62DC2DE54BCD6EBA72, SHA1 6D4F10A8B10E10DBE624CB23CF03B88BB8252973; built from JP1.0 dasm, not kept in sync | last push 2026-09-15, ~3 stars |
| ALttP (JP1.0) | spannerisms/jpdasm | https://github.com/spannerisms/jpdasm | `LICENSE` GPL-3.0 | ? | same layout, `bin/` extracted by Makefile/`binextract.py`; Futaba | exact JP1.0: CRC32 3322EFFC, MD5 03A63945398191337E896E5771F77173; "Raw binaries not included ... due to voiced concerns of potential copyright issues" | 2026-09-15, 37 stars |
| ALttP (US) | walkingeyerobot/alttp-disassembly (MathOnNapkins) | https://github.com/walkingeyerobot/alttp-disassembly | no license file; README only title | ? | raw listings `BankNN.asm`, ancilla_*.asm, RAM/ROM/SRM/VRAM .log docs; not rebuildable | older, labelled; the foundational reference | 2018, 18 stars |
| ALttP (US) | JaredBrian/AsarUSALTTPDisassembly | https://github.com/JaredBrian/AsarUSALTTPDisassembly | no license file | ? | asar; `Bank00..1F.asm` + APU/Ancilla/Data folders | README: WIP, "CANNOT currently build on its own" | active (2026-10-02), 7 stars |
| ALttP (C reimplementation) | snesrev/zelda3 | https://github.com/snesrev/zelda3 | `LICENSE.txt` = MIT, "Copyright (c) 2022 snesrev / Copyright (c) 2021 elzo_d" | likely yes (MIT) for the C code; function/variable names derived from spannerisms' disassembly | C, ~70-80kLOC; names map to original routines but addresses must be recovered via comments/tables ? | full game, not a byte-matching asm | very active, ~4.8k stars |
| Zelda (GBA ALttP/Four Swords) | camthesaxman/zeldaalttp | https://github.com/camthesaxman/zeldaalttp | no license | n/a (GBA, not SNES) | - | - | - |
| Super Metroid | InsaneFirebat/sm_disassembly (mirror metroidret/sm) ("canonical") | https://github.com/InsaneFirebat/sm_disassembly | `LICENSE.txt`: "Zero-Clause BSD" (0BSD) | likely yes (0BSD); content copied "with permission" from P.JBoy bank logs per `info.txt` | asar 1.81; `src/bank_80.asm`..; LoROM (banks $80+); relocatable; extracts data from user ROM via `create_data.*` (NTSC and PAL) | based on P.JBoy bank logs; "address column will be removed once all labels accounted for" | active 2026-10-03, 19 stars |
| Super Metroid | strager/supermetroid | https://github.com/strager/supermetroid | no license file seen | ? | WLA-DX, `src/bank80.asm`..; Makefile | produces `supermetroid-ntsc.sfc` SHA-1 da957f0d63d14cb441d215462904c4fa8519c613 | last push 2021-12, 157 stars |
| Super Metroid (C reimpl.) | snesrev/sm | https://github.com/snesrev/sm | `LICENSE.txt` (NOASSERTION; contents not read) | ? | C | early version; sha1 da957f0d... | 2023-08, 554 stars |
| Super Metroid | P.JBoy bank logs | https://patrickjohnston.org/bank/index.html | stated on site ? (not fetched); `info.txt` of sm_disassembly says comments copied "with permission" | ? | raw per-bank listings, with RAM map | very complete | ? |
| Chrono Trigger (US 1.0) | dscotton/ct_disassembly | https://github.com/dscotton/ct_disassembly | `LICENSE` file; GitHub: CC0-1.0. README: "contains only the disassembled code and structure -- no copyrighted images, sound, or text" | likely yes (CC0) | asar; `bank_C0.asm`..`bank_FF`; HiROM (banks C0+); `data/*.asm` equates + incbin from ROM | byte-identical build verified; CRC32 2D206BF7; labelled with LLM assistance (README says so) | 2026-07, 2 stars |
| Chrono Trigger | DocDamage/chronotrigger_disassembly | https://github.com/DocDamage/chronotrigger_disassembly | ? | ? | Python | ? | 2026-03, 1 star |
| EarthBound | Herringway/ebsrc (canonical) | https://github.com/Herringway/ebsrc | no license file seen (API: none); not inspected further | ? | ca65 + spcasm; `ebbinex` extracts from user ROM; US retail, 1995-03-27 proto, Mother 2 | disassembly -> decomp aim | active 2026-10-04, 180 stars |
| EarthBound | Yoshifanatic1/EarthBound-Disassembly | https://github.com/Yoshifanatic1/EarthBound-Disassembly | GPL-3.0 (+ public domain [1]) | ? | asar framework | ? | 2021 |
| EarthBound | tripped/ebasm | https://github.com/tripped/ebasm | no license | ? | Python split disassembly | old | 2011 |
| Final Fantasy VI / III US | everything8215/ff6 | https://github.com/everything8215/ff6 | `LICENSE` = GPL-3.0 text | ? (likely yes GPL) | ca65-style Makefile, `src/`, `assets/` and `vanilla/` dirs (?: does vanilla hold ROM data? check) | builds FF6 1.0 (J) (not byte-identical: CRC32 059728E2 vs 45EF5AC8), FF3 1.0 (U) CRC32 A27F1C7A, 1.1 (U) C0FA0464 | active 2026-09, 86 stars. Same author: ff4, ff5 repos |
| Secret of Mana | none found (only a graphics decompressor) | - | - | - | - | - | - |
| Mega Man X (1), X2 | none found as disassembly (mstan/MegaManX2Recomp: C recomp, not surveyed for license) | - | - | - | - | - | - |
| Donkey Kong Country 1 | Yoshifanatic1/Donkey-Kong-Country-1-Disassembly (also DKC2, DKC3) | https://github.com/Yoshifanatic1/Donkey-Kong-Country-1-Disassembly | GPL-3.0 (+ public domain [1]) | ? | asar framework | ? | 2021 push, repo updated 2026-10 |
| Donkey Kong Country | DKC-Recomp/DKC-disassembly | https://github.com/DKC-Recomp/DKC-disassembly | GPL-3.0 (GitHub); README: "Assets are proprietary and copyrighted by Nintendo Ltd, you will not find any of these here." | ? (likely yes GPL) | based on snes2asm output; SNES US v1.0; mostly game and audio code | WIP | 2026-06, 2 stars |
| Other seen in passing | LIJI32/superbomberman (https://github.com/LIJI32/superbomberman, 108 stars); spannerisms/smt1dasm (Shin Megami Tensei J1.0); Yoshifanatic1 many titles (see [1]); Neo-Desktop/SNES-CIC-Disassembly (SNES CIC lock chip, archived); SteveMaddison/super_disc_bios (prototype SFX-100 BIOS); gingerbeardman/canoe-disassembly (SNES Classic emulator, not a SNES game) | github.com | licenses not checked | ? | - | - | - |

## SNES: Data Crystal pages (from web search results; not individually opened due to 403/429 on direct fetch)

| title | pages found |
|---|---|
| Super Mario RPG | https://datacrystal.tcrf.net/wiki/Super_Mario_RPG:_Legend_of_the_Seven_Stars (ROM map: .../Super_Mario_RPG:_Legend_of_the_Seven_Stars/ROM_map ; RAM map: ...:RAM_map) |
| Kirby Super Star | https://datacrystal.tcrf.net/wiki/Kirby_Super_Star/ROM_map ; RAM map ? |
| Star Fox | https://datacrystal.tcrf.net/wiki/Star_Fox , https://datacrystal.tcrf.net/wiki/Star_Fox/ROM_map ; RAM map ? |
| Yoshi's Island | https://datacrystal.tcrf.net/wiki/Super_Mario_World_2:_Yoshi's_Island/RAM_map and .../ROM_map |
| Stunt Race FX | not found |
| Pilotwings | not found |
| Super Mario Kart | https://datacrystal.tcrf.net/wiki/Super_Mario_Kart/ROM_map , https://datacrystal.tcrf.net/wiki/Super_Mario_Kart/RAM_map |
| Street Fighter Alpha 2 | not found (only SFA3 CPS2) |
| Mega Man X3 | not found (Mega Man X exists: .../Mega_Man_X/RAM_map , .../Mega_Man_X:ROM_map) |
| Tales of Phantasia | https://datacrystal.tcrf.net/wiki/Tales_of_Phantasia (page exists; map subpages ?) |
| Mario's Early Years | not found |
| Super Mario World | https://datacrystal.tcrf.net/wiki/Super_Mario_World_(SNES)/RAM_map , .../ROM_map , .../SRAM_map |
| ALttP | https://datacrystal.tcrf.net/wiki/The_Legend_of_Zelda:_A_Link_to_the_Past (page carries VRAM/SRAM/RAM/ROM info; whether separate subpages ?) |
| Super Metroid | https://datacrystal.tcrf.net/wiki/Super_Metroid/RAM_map ; ROM map ? |
| Chrono Trigger | https://datacrystal.tcrf.net/wiki/Chrono_Trigger_(SNES) (cited by dscotton README) |

"not found" = not surfaced by search; may exist under another name. Direct re-check with a browser is cheap for a human.

## SNES: SPC700 sound driver disassemblies

| driver | project | URL | license (as stated) | notes |
|---|---|---|---|---|
| Star Fox (N-SPC/Kankichi-kun variant) | phonymike/starfox_spc_driver | https://github.com/phonymike/starfox_spc_driver | none | asar; 1:1 build SGSOUND0.BIN sha1 84a3411c...; comments from SNES SDK KAN.ASM; active 2026-10 |
| Super Mario Kart | MrL314/smk-spc700-disassembly (AuDism) | https://github.com/MrL314/smk-spc700-disassembly | none | Python scripts extract/disassemble from user ROM (USA/JPN/PAL); annotation-patch system |
| Yoshi's Island / SMW N-SPC | KungFuFurby/vgm-disasm (loveemu YI driver .s), KungFuFurby/SNESSoundDriverDocViewer | https://github.com/KungFuFurby/vgm-disasm ; https://github.com/KungFuFurby/SNESSoundDriverDocViewer | ? | cited by phonymike README; not inspected |
| N-SPC engine general | sneslab wiki | https://sneslab.net/wiki/N-SPC_Engine | ? | documentation |
| Yoshi's Island, SMRPG, SMK, EB | included in the whole-game disassemblies (YI: GSU+SPC700 in brunovalads; `SPC700/` dirs in Yoshifanatic1 repos; spcasm in ebsrc; ALttP `spc.asm` in usdasm) | see above | see above | - |
| Squaresoft driver | none found in this pass (ff6 repo likely contains SPC source; not verified) | - | - | ? |

## SNES: Open questions for the owner

1. Yoshifanatic1 repos: LICENSE is GPL-3.0 but the framework readme says public domain. Which governs? Those repos cover SMRPG, SMK, YI (3 of our pinned titles) so this matters.
2. The pinned titles with real labelled sources are thin: YI (strong, brunovalads), SMRPG/SMK (Yoshifanatic1 WIP), Kirby Super Star (partial, 3 banks), Star Fox (SDK-derived/patch-only; owner to judge provenance). Stunt Race FX, Pilotwings, SFA2, MMX3, Tales of Phantasia, Mario's Early Years: nothing found.
3. Is a C reimplementation/recomp (snesrev/zelda3 MIT, mstan MMX3 PolyForm-NC) in scope as a symbol source? Names are not tied to ROM addresses.
4. No-license-file repos (YI brunovalads, KSS, strager/supermetroid, SMW smw-src): treat as not redistributable until the author is asked?
5. dscotton/ct_disassembly says labels were LLM-generated (Claude); is that acceptable provenance?
6. SMWDisX could not be located (SMWCentral hosts it); SMWCentral.net resource pages were not fetched. Human lookup suggested.
7. Data Crystal pages could not be opened directly (403/429); map-page existence is from search results only.
8. Coprocessor coverage (SA-1, DSP-1, Cx4) unconfirmed for SMRPG/SMK; need a look inside `Firmware/` dirs.
