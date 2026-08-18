#!/usr/bin/env python3
"""Extract an SPC700 upload stream from a SNES ROM (bead grm-uy9s / grm-ced).

Nearly every SNES driver hands the SPC700 its code and samples as a stream of
length/address-prefixed blocks, which the boot ROM's own uploader consumes:

    word  length          (little-endian)
    word  target address  (SPC700 address space)
    byte  data[length]
    ...
    word  0               terminator: length zero
    word  execution address

This walks that stream from a given ROM address and writes it out VERBATIM, byte for
byte including the headers and the terminator. That is deliberately the same shape as
the ``*spc.bin`` files already in the game-music-extraction tree -- ``somspc.bin``
opens ``98 13 00 02``, i.e. length $1398 at $0200, and is exactly 4 + $1398 + 4 bytes
long -- so an extraction here is directly comparable to one done by hand in 2001, and
feeds the same tools. Use ``--image`` when you want the flat 64K SPC memory image
instead, which is what a disassembler or a Ghidra import wants.

The stream is self-describing, so this needs only its start address: the block count,
sizes, targets and execution address all fall out of the walk. Supply the start from
the game's own notes -- FF2's ``work.txt`` records "send blocks 04/8683 - 04/BBCF" --
and check the printed map against them.

A wrong start address is caught, but not instantly, and it is worth knowing how: the
walk simply reads whatever bytes are there as headers, so the first few "blocks" can
look entirely plausible. What kills it is that a block must fit in the SPC700's 64K
address space, and random data violates that within a handful of blocks. Pointed at
FF2's ``04/8000`` instead of ``04/8683``, the walk produces three believable blocks and
then dies on a fourth claiming ``$FFFF`` bytes at ``$FFFF``. So: **check the map against
the game's notes rather than trusting that it parsed.** The strongest independent check
available is to compare the extracted image against a hand disassembly's byte column,
which is how ff2's extraction was verified here (4,521 bytes, zero disagreements).

Examples:

    # FF2 (FF4 US), LoROM, per snes/ff2/work.txt
    python3 tools/spc700/extract-upload-blocks.py ff2.smc 04/8683 -o ff2spc.bin
    python3 tools/spc700/extract-upload-blocks.py ff2.smc 04/8683 --image -o ff2spc-image.bin
"""

import argparse
import sys

# An SPC700 upload block cannot exceed the 64K address space, and a length wildly
# beyond that is the signature of a wrong start address rather than an exotic driver.
MAX_BLOCK = 0x10000
# A stream of more blocks than this is likewise a walk that has lost the plot; the
# largest in the corpus is FF2's eight.
MAX_BLOCKS = 64


def parse_address(text, rom_size, has_header, mapping):
    """Accept a bare file offset (0x1234 / 4660) or a SNES bank/address (04/8683)."""
    if "/" in text:
        bank_text, addr_text = text.split("/", 1)
        bank = int(bank_text, 16)
        addr = int(addr_text, 16)
        if mapping == "lorom":
            if not 0x8000 <= addr <= 0xFFFF:
                raise SystemExit(
                    f"{text}: a LoROM address must be $8000-$FFFF (got ${addr:04X}); "
                    "banks map the upper half only"
                )
            offset = (bank & 0x7F) * 0x8000 + (addr - 0x8000)
        else:
            offset = (bank & 0x3F) * 0x10000 + addr
    else:
        offset = int(text, 0)
    if has_header:
        offset += 512
    if not 0 <= offset < rom_size:
        raise SystemExit(
            f"{text} resolves to file offset {offset:#x}, outside the {rom_size:#x}-byte ROM"
        )
    return offset


def walk(rom, start):
    """Yield (target, data) per block; returns the execution address and end offset."""
    blocks = []
    pos = start
    while True:
        if pos + 4 > len(rom):
            raise SystemExit(
                f"ran off the end of the ROM at {pos:#x} without finding a terminator -- "
                "the start address is probably wrong"
            )
        length = int.from_bytes(rom[pos:pos + 2], "little")
        target = int.from_bytes(rom[pos + 2:pos + 4], "little")
        pos += 4
        if length == 0:
            return blocks, target, pos
        if target + length > MAX_BLOCK:
            # The load has to land somewhere in the SPC700's 64K, so this is a hard invariant
            # rather than a heuristic -- and it is what actually catches a wrong start address,
            # since random bytes violate it within a few blocks while a bare length check does
            # not (a "$FFFF bytes at $FFFF" header passes any length-only test).
            raise SystemExit(
                f"block {len(blocks)} at {pos - 4:#x} loads {length:#x} bytes to ${target:04X}, "
                f"running past the SPC700's ${MAX_BLOCK - 1:04X} -- the start address is "
                "probably wrong. (A driver that genuinely wrapped the 16-bit load pointer would "
                "also land here; none in this corpus does.)"
            )
        if len(blocks) >= MAX_BLOCKS:
            raise SystemExit(
                f"more than {MAX_BLOCKS} blocks and still no terminator -- the start address is "
                "probably wrong"
            )
        if pos + length > len(rom):
            raise SystemExit(
                f"block {len(blocks)} at {pos - 4:#x} runs past the end of the ROM"
            )
        blocks.append((target, rom[pos:pos + length]))
        pos += length


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rom", help="the SNES ROM file")
    ap.add_argument("start", help="where the block stream starts: 'bb/aaaa' or a file offset")
    ap.add_argument("-o", "--output", help="write here (default: report the map only)")
    ap.add_argument("--image", action="store_true",
        help="write the flat 64K SPC memory image instead of the raw upload stream")
    ap.add_argument("--mapping", choices=("lorom", "hirom"), default="lorom",
        help="how bb/aaaa maps to a file offset (default: lorom)")
    ap.add_argument("--header", choices=("auto", "yes", "no"), default="auto",
        help="whether the ROM carries a 512-byte copier header (default: auto, by file size)")
    args = ap.parse_args(argv)

    with open(args.rom, "rb") as fh:
        rom = fh.read()
    has_header = len(rom) % 1024 == 512 if args.header == "auto" else args.header == "yes"
    start = parse_address(args.start, len(rom), has_header, args.mapping)

    blocks, exec_address, end = walk(rom, start)

    print(f"{args.rom}: {len(rom):#x} bytes, "
          f"{'512-byte copier header' if has_header else 'no copier header'}")
    print(f"stream {start:#x}-{end - 1:#x} ({end - start:#x} bytes), "
          f"{len(blocks)} blocks, execution address ${exec_address:04X}")
    for index, (target, data) in enumerate(blocks):
        print(f"  Block {index:02d}: start ${target:04X} length ${len(data):04X}  "
              f"to ${target + len(data) - 1:04X}")

    if not args.output:
        return 0
    if args.image:
        image = bytearray(0x10000)
        for target, data in blocks:
            if target + len(data) > 0x10000:
                raise SystemExit(
                    f"block at ${target:04X} of ${len(data):04X} bytes wraps past $FFFF; "
                    "a flat image cannot represent it (the raw stream still can)"
                )
            image[target:target + len(data)] = data
        payload = bytes(image)
    else:
        payload = rom[start:end]
    with open(args.output, "wb") as fh:
        fh.write(payload)
    print(f"wrote {len(payload):#x} bytes to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
