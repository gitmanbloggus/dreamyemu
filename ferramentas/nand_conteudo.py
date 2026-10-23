"""Populate a generated NAND image with the content the Dream SPL needs
to reach the framebuffer: a valid Android boot header for the recovery
load and the stock RGB565 splash for both splash loads.

Guest block numbering is the SPL's own (bloco = 0x126 + (src -
0x500C0000) / 0x20000 on the 0x50 region, verified live on five points),
NOT physical math. Entry-8 geometry: 64 pages/block, 2048+64 bytes/page.

Usage (after ferramentas/cria_nand.py):
    python3 ferramentas/nand_conteudo.py tests/spl/nand.img assets/Default_US.raw565

Idempotent: re-running rewrites the same bytes. Self-checks by reading
back every patched page.
"""

import struct
import sys

PAGE = 2048
PPB = 64
RECORD = 2112  # data + spare


def off(block, page):
    return block * PPB * RECORD + page * RECORD


def patch_recovery_header(img):
    """Guest block 0x136 page 0: the Load Recoveryimg header the SPL
    memcmps against b'ANDROID!' (0x88073CDC), then loads kernel_size
    bytes from NAND to dst = kernel_addr + 0x70000000."""
    hdr = bytearray(PAGE)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, 0x800)        # kernel_size: 1 page
    struct.pack_into("<I", hdr, 12, 0x10008000)  # kernel_addr -> 0x80008000
    struct.pack_into("<I", hdr, 20, 0x11000000)  # ramdisk_addr
    struct.pack_into("<I", hdr, 32, 0x10000100)  # tags_addr
    struct.pack_into("<I", hdr, 36, 2048)         # page_size
    img[off(0x136, 0):off(0x136, 0) + PAGE] = hdr


def patch_splash(img, splash, first_block):
    """150 RGB565 pages (0x4B000 = 320x480x2) across three consecutive
    guest blocks. First image: 0x12A (NAND src 0x50140000); second
    image: 0x130 (NAND src 0x50200000) — the SPL blits the second one
    over the first, so both need real pixels."""
    assert len(splash) == 150 * PAGE, len(splash)
    for page in range(150):
        blk = first_block + page // PPB
        dst = off(blk, page % PPB)
        img[dst:dst + PAGE] = splash[page * PAGE:(page + 1) * PAGE]


def main(argv):
    img_path, splash_path = argv[1], argv[2]
    with open(img_path, "r+b") as f:
        img = bytearray(f.read())
        splash = open(splash_path, "rb").read()
        patch_recovery_header(img)
        patch_splash(img, splash, 0x12A)
        patch_splash(img, splash, 0x130)
        # Self-check: read back the header magic and one page per image.
        assert bytes(img[off(0x136, 0):off(0x136, 0) + 8]) == b"ANDROID!"
        assert bytes(img[off(0x12A, 0):off(0x12A, 0) + 2048]) == splash[:2048]
        assert bytes(img[off(0x132, 21):off(0x132, 21) + 2048]) == splash[149 * 2048:]
        assert bytes(img[off(0x130, 0):off(0x130, 0) + 2048]) == splash[:2048]
        f.seek(0)
        f.write(img)
    print(f"patched {img_path}: recovery header @ block 0x136, "
          f"splash @ blocks 0x12a-0x12c and 0x130-0x132; self-check PASS")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
