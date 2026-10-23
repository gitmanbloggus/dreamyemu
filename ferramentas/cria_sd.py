"""Build a FAT32 SD-card image carrying the real DREAIMG.nbh for the
Dream SPL's HBOOT SD-flash path (SDFATChkIfNeedUpdate @ 0x8801ACC8).

The SPL's FAT reader (RhOpenFile @ 0x8801C2F8) requires: sector 0 = MBR
with 0x55AA and a partition of a FAT32 type (0x0B works; 1/4/6/0x0E are
REJECTED at 0x8801C7F8 — FAT12/16 only); the partition VBR holds
the 8-byte string b'FAT32   '; the root directory holds the 8.3 entry
b'DREAIMG  NBH' (upper-cased by 0x8801BDA8 before compare). The driver
reads sectors through 0x8801BF68 -> 0x8800D644, which the emulator
serves straight from this image, so the layout must be self-consistent
BPB/FAT/dir math (verified by reading it back below).

Usage:
    python3 ferramentas/cria_sd.py [-o tests/spl/sd.img]

Reads the NBH from assets/DREAIMG/DREAIMG-RC29.zip (never extracted into
the repo). Idempotent: same input -> byte-identical image.
"""

import hashlib
import struct
import sys
import zipfile

BYTES_SECTOR = 512
SECTORES_CLUSTER = 8  # 4 KiB clusters
RESERVADOS = 32
N_FATS = 2
PART_LBA = 2048
NOME_NBH = b"DREAIMG NBH"  # 8.3 padded, upper case (as the SPL compares)
ROTULO = b"DREAMSD    "


def monta(nbh_bytes, total_setores=None):
    n_clusters_dados = (len(nbh_bytes) + 4095) // 4096
    # clusters 0,1 reservados; 2 = root; 3.. = ficheiro
    fat_entradas = n_clusters_dados + 3
    fat_setores = (fat_entradas * 4 + BYTES_SECTOR - 1) // BYTES_SECTOR
    dados_lba = PART_LBA + RESERVADOS + N_FATS * fat_setores
    fim_dados = dados_lba + n_clusters_dados * SECTORES_CLUSTER
    if total_setores is None:
        # arredonda ao MiB seguinte
        total_setores = (fim_dados + 2047) // 2048 * 2048
    assert fim_dados <= total_setores
    img = bytearray(total_setores * BYTES_SECTOR)

    def poe(lba, off, buf):
        img[lba * BYTES_SECTOR + off:lba * BYTES_SECTOR + off + len(buf)] = buf

    # --- MBR no sector 0 ---
    # Tipo 0x0B (FAT32): o RhOpenFile REJEITA 1/4/6/0x0E (FAT12/16) em
    # 0x8801C7F8 e só lê o VBR para os outros tipos (provado ao vivo:
    # 0x0E morre após o MBR, 0x0B caminha MBR -> VBR -> root dir).
    part = struct.pack(
        "<B3sB3sII",
        0x00, b"\x00\x00\x00", 0x0B, b"\x00\x00\x00",
        PART_LBA, total_setores - PART_LBA,
    )
    poe(0, 446, part)
    poe(0, 510, b"\x55\xaa")

    # --- VBR ---
    vbr = bytearray(BYTES_SECTOR)
    vbr[0:3] = b"\xeb\x58\x90"
    vbr[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", vbr, 0x0B, BYTES_SECTOR)
    vbr[0x0D] = SECTORES_CLUSTER
    struct.pack_into("<H", vbr, 0x0E, RESERVADOS)
    vbr[0x10] = N_FATS
    struct.pack_into("<H", vbr, 0x11, 0)  # entradas root (0 em FAT32)
    struct.pack_into("<H", vbr, 0x13, 0)  # total16
    vbr[0x15] = 0xF8
    struct.pack_into("<H", vbr, 0x18, 0)  # reservado: pistas/sector
    struct.pack_into("<H", vbr, 0x1A, 0)
    struct.pack_into("<I", vbr, 0x1C, PART_LBA)  # sectores ocultos
    struct.pack_into("<I", vbr, 0x20, total_setores - PART_LBA)
    struct.pack_into("<I", vbr, 0x24, fat_setores)
    struct.pack_into("<H", vbr, 0x28, 0)  # espelho/ext flags
    struct.pack_into("<H", vbr, 0x2A, 0)  # versao
    struct.pack_into("<I", vbr, 0x2C, 2)  # cluster root
    struct.pack_into("<H", vbr, 0x30, 1)  # FSInfo
    struct.pack_into("<H", vbr, 0x32, 6)  # backup boot
    vbr[0x40] = 0x80
    vbr[0x42] = 0x29
    struct.pack_into("<I", vbr, 0x43, 0x12345678)
    vbr[0x47:0x52] = ROTULO
    vbr[0x52:0x5A] = b"FAT32   "
    vbr[510:512] = b"\x55\xaa"
    poe(PART_LBA, 0, vbr)

    # --- FSInfo ---
    fsi = bytearray(BYTES_SECTOR)
    struct.pack_into("<I", fsi, 0, 0x41615252)
    struct.pack_into("<I", fsi, 484, 0x61417272)
    struct.pack_into("<I", fsi, 488, n_clusters_dados + 3)  # prox livre
    struct.pack_into("<I", fsi, 492, 0xFFFFFFFF)  # sem contagem
    struct.pack_into("<I", fsi, 508, 0xAA550000)
    poe(PART_LBA + 1, 0, fsi)
    poe(PART_LBA + 6, 0, vbr)  # backup boot

    # --- FATs ---
    fat = bytearray(fat_setores * BYTES_SECTOR)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat, 8, 0x0FFFFFFF)  # cluster 2 (root): fim
    for c in range(3, 3 + n_clusters_dados - 1):
        struct.pack_into("<I", fat, c * 4, c + 1)
    struct.pack_into("<I", fat, (3 + n_clusters_dados - 1) * 4, 0x0FFFFFFF)
    for t in range(N_FATS):
        poe(PART_LBA + RESERVADOS + t * fat_setores, 0, fat)

    # --- dir root (cluster 2) ---
    dent = bytearray(32)
    dent[0:11] = NOME_NBH
    dent[11] = 0x20  # arquivo
    struct.pack_into("<H", dent, 20, (3 >> 16) & 0xFFFF)
    struct.pack_into("<H", dent, 26, 3 & 0xFFFF)
    struct.pack_into("<I", dent, 28, len(nbh_bytes))
    base_dir = (dados_lba) * BYTES_SECTOR  # cluster 2 = inicio dados
    img[base_dir:base_dir + 32] = dent

    # --- dados do ficheiro (clusters 3..) ---
    base_dados = base_dir + SECTORES_CLUSTER * BYTES_SECTOR
    img[base_dados:base_dados + len(nbh_bytes)] = nbh_bytes
    return bytes(img)


def verifica(caminho, resumo_zip):
    img = open(caminho, "rb").read()
    assert img[510:512] == b"\x55\xaa", "sem 0x55AA no MBR"
    # 446: status(1) chs(3) tipo(1) chs(3) lba(4) nsec(4)
    status, tipo = img[446], img[450]
    lba, nsec = struct.unpack_from("<II", img, 454)
    assert tipo == 0x0B, "tipo MBR %r" % tipo
    vbr = lba * BYTES_SECTOR
    assert img[vbr + 0x52:vbr + 0x5A] == b"FAT32   ", "sem string FAT32"
    bps, spc = struct.unpack_from("<HB", img, vbr + 0x0B)
    assert (bps, spc) == (512, SECTORES_CLUSTER)
    reserv, nfats = struct.unpack_from("<HB", img, vbr + 0x0E)
    (fat_sz,) = struct.unpack_from("<I", img, vbr + 0x24)
    (root_cl,) = struct.unpack_from("<I", img, vbr + 0x2C)
    assert (reserv, nfats, root_cl) == (RESERVADOS, N_FATS, 2)
    dados = vbr // BYTES_SECTOR + reserv + nfats * fat_sz
    dent = img[dados * BYTES_SECTOR:][:32]
    assert dent[0:11] == NOME_NBH, dent[0:11]
    cl = struct.unpack_from("<H", dent, 26)[0] | (
        struct.unpack_from("<H", dent, 20)[0] << 16
    )
    (tam,) = struct.unpack_from("<I", dent, 28)
    # caminha a FAT
    fat0 = (vbr // BYTES_SECTOR + reserv) * BYTES_SECTOR
    fora = bytearray()
    while True:
        (prox,) = struct.unpack_from("<I", img, fat0 + cl * 4)
        base = (dados + (cl - 2) * spc) * BYTES_SECTOR
        fora += img[base:base + spc * BYTES_SECTOR]
        if prox >= 0x0FFFFFF8:
            break
        assert prox == cl + 1, (hex(cl), hex(prox))
        cl = prox
    fora = bytes(fora[:tam])
    h = hashlib.sha256(fora).hexdigest()
    assert h == resumo_zip, "conteudo difere do zip"
    return h


def main():
    saida = "tests/spl/sd.img"
    for i, a in enumerate(sys.argv[1:]):
        if a == "-o" and i + 1 < len(sys.argv[1:]):
            saida = sys.argv[1:][i + 1]
    with zipfile.ZipFile("assets/DREAIMG/DREAIMG-RC29.zip") as z:
        info = next(i for i in z.infolist() if i.filename.endswith(".nbh"))
        nbh = z.read(info.filename)
    print("nbh: %d bytes sha256=%s" % (len(nbh), hashlib.sha256(nbh).hexdigest()))
    img = monta(nbh)
    with open(saida, "wb") as f:
        f.write(img)
    print("sd: %s (%d bytes)" % (saida, len(img)))
    print("readback sha256=%s" % verifica(saida, hashlib.sha256(nbh).hexdigest()))


if __name__ == "__main__":
    main()
