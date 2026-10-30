"""Patch real Linux content into a NAND image copy for the Dream SPL's
kernel handoff: the BOOT image (kernel + ramdisk) from the RUU NBH is
written over the *recovery* NAND blocks, because the SPL's default path
loads its header from 0x502C0000 (guest block 0x136) and jumps to the
physical link address with the MMU off.

Guest block numbering is the SPL's own (bloco = 0x126 + (addr -
0x500C0000) // 0x20000 on the 0x50 region), entry-8 geometry (64
pages/block, 2048+64 bytes/page) — same as ferramentas/nand_conteudo.py.

Layout (NBH = assets/DREAIMG/DREAIMG-RC29.zip, boot item @ file 0x22F300):
  NAND 0x502C0000 (blk 0x136 p0) <- boot.img header (ANDROID!, 2048 B)
  NAND 0x502C0800 ...           <- kernel 0x153004 B (676 pages + 4 B)
  NAND 0x50414000 ...           <- ramdisk 0x228D7 B (68 pages + 2007 B)

The NBH also carries the stock RECOVERY image (file 0x80300): its kernel
is byte-identical to boot's (checked: same 0x153004 B), only the ramdisk
differs (0x5A831 B, with /sbin/recovery + res/images, no Dalvik/binder).
`--recovery` writes that one instead, so the fb0 path (minui opens
/dev/graphics/fb0 directly) can be exercised without zygote/system_server.
The ramdisk lands at the same 0x50414000; its end 0x5046E831 still sits
inside the recovery partition.

Stock (1.0-era) recovery with no arguments draws nothing and reboots
(observed: black fb0, then finish_recovery writes /cache/recovery/log).
`--misc-update` also plants a bootloader_message in MISC (linux mtd0 @
0x024C0000 == NAND 0x500C0000, block 0x126; struct = command[32],
status[32], recovery[1024]) asking for SDCARD:update.zip. Without an SD
image the install fails, so recovery shows its error icon and waits in
prompt_and_wait — a stable screen. Written to MISC pages 0 and 1: later
recovery reads page 1 (MISC_COMMAND_PAGE), not verified for this build.

Usage:
    python3 ferramentas/nand_linux.py [--recovery [--misc-update]] [nand_in] [nand_out]
Defaults: tests/spl/nand.img -> tests/spl/nand_linux.img
(tests/spl/nand_recovery.img with --recovery).
Self-checks by reading back header magic + first/last bytes.
"""

import struct
import sys
import zipfile

PAGE = 2048
PPB = 64
RECORD = 2112
BASE = 0x500C0000
BASE_BLOCO = 0x126


def off_block_page(block, page):
    return block * PPB * RECORD + page * RECORD


def off_addr(addr):
    """Image offset of a NAND byte address (0x50 region, entry-8)."""
    assert BASE <= addr < 0x51000000, hex(addr)
    bloco = BASE_BLOCO + (addr - BASE) // 0x20000
    base_bloco = BASE + (bloco - BASE_BLOCO) * 0x20000
    pagina = (addr - base_bloco) // PAGE
    resto = (addr - base_bloco) % PAGE
    return off_block_page(bloco, pagina) + resto


def patch_range(img, addr, data):
    """Write data bytes at NAND byte addr (may span pages/blocks)."""
    for i in range(0, len(data), PAGE):
        chunk = data[i:i + PAGE]
        o = off_addr(addr + i)
        img[o:o + len(chunk)] = chunk


# (NBH file offset, ramdisk size) per item; kernel size/page are shared.
ITENS = {"boot": (0x22F300, 0x228D7), "recovery": (0x80300, 0x5A831)}


def main(argv):
    item = "recovery" if "--recovery" in argv else "boot"
    misc = "--misc-update" in argv
    argv = [a for a in argv if a not in ("--recovery", "--misc-update")]
    nand_in = argv[1] if len(argv) > 1 else "tests/spl/nand.img"
    nand_out = argv[2] if len(argv) > 2 else (
        "tests/spl/nand_recovery.img" if item == "recovery"
        else "tests/spl/nand_linux.img")
    origem, rd_esperado = ITENS[item]
    with zipfile.ZipFile("assets/DREAIMG/DREAIMG-RC29.zip") as z:
        info = next(i for i in z.infolist() if i.filename.endswith(".nbh"))
        nbh = z.read(info.filename)
    boot = nbh[origem:origem + 0x800 * (1 + 0x2A7) + rd_esperado]
    assert boot[:8] == b"ANDROID!", boot[:8]
    kernel_size = struct.unpack_from("<I", boot, 8)[0]
    ramdisk_size = struct.unpack_from("<I", boot, 16)[0]
    page_size = struct.unpack_from("<I", boot, 36)[0]
    assert (kernel_size, ramdisk_size, page_size) == (0x153004, rd_esperado, 2048), \
        (hex(kernel_size), hex(ramdisk_size), page_size)
    kernel = boot[0x800:0x800 + kernel_size]
    ramdisk = boot[0x154000:0x154000 + ramdisk_size]
    assert len(kernel) == kernel_size and len(ramdisk) == ramdisk_size

    img = bytearray(open(nand_in, "rb").read())
    patch_range(img, 0x502C0000, boot[:PAGE])          # header
    patch_range(img, 0x502C0800, kernel)                # kernel
    patch_range(img, 0x50414000, ramdisk)               # ramdisk
    if misc:
        msg = (b"boot-recovery".ljust(32, b"\0") + b"".ljust(32, b"\0")
               + b"recovery\n--update_package=SDCARD:update.zip\n".ljust(1024, b"\0"))
        for pagina in (0, 1):
            patch_range(img, 0x500C0000 + pagina * PAGE, msg.ljust(PAGE, b"\0"))
    # Self-checks.
    assert bytes(img[off_addr(0x502C0000):off_addr(0x502C0000) + 8]) == b"ANDROID!"
    assert bytes(img[off_addr(0x502C0800):off_addr(0x502C0800) + 4]) == kernel[:4]
    klast = off_addr(0x502C0800 + kernel_size - 4)
    assert bytes(img[klast:klast + 4]) == kernel[-4:]
    assert bytes(img[off_addr(0x50414000):off_addr(0x50414000) + 4]) == ramdisk[:4]
    rlast = off_addr(0x50414000 + ramdisk_size - 4)
    assert bytes(img[rlast:rlast + 4]) == ramdisk[-4:]
    with open(nand_out, "wb") as f:
        f.write(img)
    print(f"patched {nand_out}: {item}.img header+kernel+ramdisk "
          f"over recovery blocks; self-check PASS")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
