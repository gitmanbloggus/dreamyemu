#!/usr/bin/env python3
"""Generate a raw NAND image for Dreamyemu's HTC Dream (MSM7201A) bring-up.

Layout source: disassembly of tests/spl/.../spl.bin (VA = file + 0x88000000;
objdump prints ARM immediates in DECIMAL -- "#20" means 0x14, "#68" means
0x44 -- every offset below was converted, double-check before touching).

Whitelist table base VA 0x8806F404 (pool VA 0x8801FCF4), stride 0x44, 15
entries. Per-entry field meanings, each with the using instruction:
  +0x00 name ptr      (memcpy'd; printed via method +0x00, VA 0x88008498,
                       format "DEVICE NAME=%s" VA 0x88073990)
  +0x04 total blocks  (stored to device struct+0x78, VA 0x8801FCDC
                       "str r3,[r7,#196]"; printed via method +0x0C,
                       VA 0x88008510, "BLOCK COUNT=0x%x" VA 0x880739F0;
                       name<->capacity cross-checks all 15 entries,
                       e.g. k9k2g08 0x800 blocks * 64 * 2048 = 256 MiB)
  +0x08 pages/block   (printed via method +0x10, VA 0x8800852C,
                       "BLOCK PAGE=0x%x" VA 0x88073A04; used as the divide/
                       modulo divisor for page-in-block, VA 0x88009810)
  +0x0C page data bytes (printed via method +0x14, VA 0x880084E4,
                       "PAGE SIZE=0x%x" VA 0x880739C8)
  +0x10 page+spare bytes (printed via method +0x18, VA 0x88008500,
                       "TOTAL PAGE SIZE=0x%x" VA 0x880739D8; raw-read loop
                       advances dest by 0x840, VA 0x880089C8 "addeq r8,#2112")
  +0x14 maker byte    (matcher VA 0x8801FC60 "ldr r3,[r2,#20]" vs arg)
  +0x18 device byte   (matcher VA 0x8801FC6C "ldr r3,[r2,#24]" vs arg)
  +0x1C bus width     (struct+0x98 feeds channel config VA 0x88009754
                       "LoadNandToRam_Old: width=%d", 1->x8 else x16 path)
  +0x20..+0x43 reserved, all zero in blob -- UNKNOWN, emitted as zero.
ID protocol: probe VA 0x8801ED8C "ldr r4,[r7]" reads a 32-bit word from the
buffer pointed to by [0x882F4564]; maker = byte0, device = byte1
(VA 0x8801ED94 "and r5,r4,#255" / 0x8801ED98 "lsr r4,#8").
The 0x90 command itself is composed in the DMA descriptor path
(bl 0x88020AD4 / 0x8802179C), not visible as an immediate -- UNKNOWN detail.
The ID is a controller response, NOT flash content: this image carries no ID
bytes; use the stdout ID line to answer READ ID in the emulator.
Bad blocks: read-fail path VA 0x880097C0 prints "bad=0x%x" (VA 0x88073960),
remap helper VA 0x88007988; remap==same prints "R:NO bad block reversed for
block ID 0x%x" (VA 0x880738D0, pools VA 0x88008460/0x88009970). Observed
spare check: buffer byte at data+2064 (spare+16 for 2K pages, VA 0x88008630)
vs 0xFC prints "BLOCK %d (0x%x) is reversed block" (VA 0x88073A58).
Marker convention below (spare[0]=0x00 on bad blocks) is the industry
standard, NOT directly observed -- clearly marked DEFAULT where used.
Boot: MSFL/NBH check VA 0x88007AB8 (sector0 tag E9 FD FF at +0, fail string
VA 0x88073674; sector1 tag "MSFL" at +0x808, fail string VA 0x880736B4);
"HTCIMAGE" 8-byte memcmp VA 0x88018FC4 (pool VA 0x88019014) with
"NBH header correct/incorrect" prints (VA 0x88076B6C/0x88076B44); partition
walk prints "Partition[%d], type=0x%x, start=0x%x, total=0x%x"
(VA 0x88073A94, loaded VA 0x88008744). Full NBH field layout and the post-
load jump target are UNKNOWN, so NO NBH is emitted: zero-filled data area
(= failed MSFL check = normal boot attempt).
Read addressing: linear page = block*ppb + page-in-block via divide/modulo
(VA 0x880065D4C div, 0x880065DF8 mod); large-page loops also shift block<<6
(VA 0x88007CC4 "lsl r6,r0,#6" = 64 pages/block baked in -- small-page
devices would disagree; live-validation item).
"""
import argparse
import os
import sys

# (name, blocks, pages/block, page bytes, page+spare, maker, device, width)
TABLE = [
    ("samsung_k9f2808", 0x400, 0x20, 0x200, 0x210, 0xEC, 0x73, 1),
    ("samsung_k9f2808", 0x400, 0x20, 0x200, 0x210, 0xEC, 0x33, 1),
    ("samsung_k9f5608", 0x800, 0x20, 0x200, 0x210, 0xEC, 0x35, 1),
    ("samsung_k9f1208", 0x1000, 0x20, 0x200, 0x210, 0xEC, 0x76, 1),
    ("samsung_k9f1208", 0x1000, 0x20, 0x200, 0x210, 0xEC, 0x36, 1),
    ("samsung_k91g08", 0x2000, 0x20, 0x200, 0x210, 0xEC, 0x79, 1),
    ("samsung_k9k1216", 0x1000, 0x20, 0x200, 0x210, 0xEC, 0x46, 2),
    ("samsung_k9k1208", 0x1000, 0x20, 0x200, 0x210, 0xEC, 0x36, 1),
    ("samsung_k9k2g08", 0x800, 0x40, 0x800, 0x840, 0xEC, 0xAA, 1),
    ("samsung_k9k1g08", 0x400, 0x40, 0x800, 0x840, 0xEC, 0xA1, 1),
    ("micron_mt29f1g08", 0x400, 0x40, 0x800, 0x840, 0x2C, 0xA1, 1),
    ("micron_mt29f1g16", 0x400, 0x40, 0x800, 0x840, 0x2C, 0xB1, 2),
    ("micron_mt29c2g12", 0x800, 0x40, 0x800, 0x840, 0x2C, 0xBA, 2),
    ("hynix_hyc0sqg0mf3", 0x400, 0x40, 0x800, 0x840, 0xAD, 0xB1, 2),
    ("hynix_hyh0ssj0mf3p", 0x800, 0x40, 0x800, 0x840, 0xAD, 0xBA, 2),
]
DEFAULT_ENTRY = 8  # 2 Gbit Samsung: 2048*64*2048 = 256 MiB data.
DEFAULT_BAD = (7, 100, 1000)  # kept clear of blocks 0-1 (SPL/MISC area).
SPARE_BAD_MARK = 0x00  # DEFAULT convention (see docstring): spare[0].
SPARE_GOOD = 0xFF  # erased OOB; bad-block checks look for non-0xFF.


def geometry(entry):
    name, blocks, ppb, page, total, maker, device, width = TABLE[entry]
    return {"name": name, "blocks": blocks, "ppb": ppb, "page": page,
            "spare": total - page, "total": total, "maker": maker,
            "device": device, "width": width}


def parse_bad(text):
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if part:
            out.append(int(part, 0))
    return tuple(out)


def build(geo, nblocks, fill, bad):
    page, spare, total, ppb = geo["page"], geo["spare"], geo["total"], geo["ppb"]
    if not (0 <= fill <= 0xFF):
        raise ValueError("fill must be a byte")
    for blk in bad:
        if not 0 <= blk < nblocks:
            raise ValueError(f"bad block {blk} outside 0..{nblocks - 1}")
    data_fill = bytes((fill,)) * page
    spare_fill = bytes((SPARE_GOOD,)) * spare
    good_page = data_fill + spare_fill
    img = bytearray(good_page * (nblocks * ppb))
    for blk in sorted(set(bad)):
        first = (blk * ppb) * total
        img[first + page] = SPARE_BAD_MARK  # DEFAULT: spare byte 0.
    return bytes(img)


def check(path, geo, nblocks, bad):
    errs = []
    size = os.path.getsize(path)
    want = nblocks * geo["ppb"] * geo["total"]
    if size != want:
        errs.append(f"size {size} != geometry {want}")
    with open(path, "rb") as f:
        img = f.read()
    if len(img) != size:
        errs.append("short read")
        return errs, {"pages": 0, "bad_found": []}
    page, spare, total, ppb = geo["page"], geo["spare"], geo["total"], geo["ppb"]
    npages = size // total
    bad_found = []
    for blk in range(nblocks):
        mark = img[(blk * ppb) * total + page]
        if mark != SPARE_GOOD:
            bad_found.append(blk)
    if sorted(bad_found) != sorted(set(bad)):
        errs.append(f"markers {bad_found} != requested {sorted(set(bad))}")
    # spot-check: first data page zeros/fill vs spare 0xFF outside markers.
    return errs, {"pages": npages, "bad_found": bad_found}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate raw NAND image for Dream SPL bring-up")
    ap.add_argument("-o", "--output", default="nand.img", help="output file")
    ap.add_argument("--entry", type=int, default=DEFAULT_ENTRY,
                    help=f"whitelist entry 0..{len(TABLE) - 1} (default %(default)s)")
    ap.add_argument("--size", type=float, default=256,
                    help="data capacity in MiB (default %(default)s)")
    ap.add_argument("--bad", default=",".join(map(str, DEFAULT_BAD)),
                    help="comma-separated bad block list (default %(default)s)")
    ap.add_argument("--fill", type=lambda s: int(s, 0), default=0,
                    help="data-area fill byte (default 0x00); spare stays 0xFF")
    ap.add_argument("--check", metavar="FILE",
                    help="self-check an existing file instead of generating")
    ap.add_argument("--list", action="store_true", help="print whitelist table and exit")
    args = ap.parse_args(argv)
    if args.list:
        for i, (n, b, p, pg, t, m, d, w) in enumerate(TABLE):
            print(f"{i:2d} {n:22s} blocks={b:#7x} ppb={p:#4x} page={pg:#6x} "
                  f"total={t:#6x} id={m:#04x}/{d:#04x} x{w}")
        return 0
    if not 0 <= args.entry < len(TABLE):
        print(f"entry must be 0..{len(TABLE) - 1}", file=sys.stderr)
        return 2
    geo = geometry(args.entry)
    bad = parse_bad(args.bad)
    block_bytes = geo["ppb"] * geo["page"]
    nblocks = round(args.size * 0x100000 / block_bytes)
    if args.check:
        errs, info = check(args.check, geo, nblocks, bad)
        print(f"check {args.check}: {info['pages']} pages, "
              f"bad markers at {info['bad_found']}")
        print("SELF-CHECK: " + ("PASS" if not errs else "FAIL: " + "; ".join(errs)))
        return 1 if errs else 0
    if nblocks != geo["blocks"]:
        print(f"note: --size gives {nblocks} blocks, table BLOCK COUNT "
              f"is {geo['blocks']} (SPL prints the table value)", file=sys.stderr)
    img = build(geo, nblocks, args.fill, bad)
    with open(args.output, "wb") as f:
        f.write(img)
    errs, info = check(args.output, geo, nblocks, bad)
    data_mib = nblocks * block_bytes / 0x100000
    print(f"wrote {args.output}: {len(img)} bytes "
          f"(data {data_mib:g} MiB + OOB)")
    print(f"geometry: {geo['name']} blocks={nblocks} ppb={geo['ppb']} "
          f"page={geo['page']} spare={geo['spare']} total={geo['total']}")
    print(f"ID bytes: maker=0x{geo['maker']:02x} device=0x{geo['device']:02x} "
          f"(width x{geo['width']}; answer READ ID with these, not from file)")
    print(f"bad blocks: {sorted(set(bad)) or 'none'} "
          f"(DEFAULT spare[0]=0x00 convention)")
    print("SELF-CHECK: " + ("PASS" if not errs else "FAIL: " + "; ".join(errs)))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
