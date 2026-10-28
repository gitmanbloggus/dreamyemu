"""Disable init service(s) in a Dream NAND image by commenting their
`init.rc`/`init.trout.rc` blocks out, byte-for-byte (the ramdisk is a
fixed-size gzip blob inside the boot image; changing lengths would
shift every NAND offset after it).

Usage:
    python3 ferramentas/nand_sem_servico.py tests/spl/nand_fresh.img tests/spl/nand_novo.img flash_recovery akmd

Each named service has its `service <name> ...` line plus following
indented option lines replaced by `#` + spaces (same length, so the
repacked ramdisk fits the original size). Aborts without writing
anything when a name is missing or the repack grows.

Background (Dreamyemu bring-up, 2026-10): flash_recovery runs
/system/bin/flash_image on a /system/recovery.img that does not
exist in the image; it log-spams the failure and dies in a NULL+0x8A
dereference, tripping the harness abort-loop cap and stopping the
run. akmd (compass daemon, no hardware) log-spammed 9M+ logcat
lines and dominated per-slice host time. Neither is needed for boot
animation; both stay disabled until the hardware they need exists.
"""

import gzip
import os
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from nand_linux import off_addr

RAMDISK_ADDR = 0x50414000
PAGE = 2048


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 2
    src, dst = argv[1], argv[2]
    nomes = argv[3:]
    with open(src, "rb") as f:
        img = bytearray(f.read())

    # Boot image header -> ramdisk size + file location.
    o = off_addr(0x502C0000)
    assert img[o : o + 8] == b"ANDROID!", "not a boot.img NAND"
    ksz, _, rsz, _ = struct.unpack("<IIII", img[o + 8 : o + 24])

    # Read the ramdisk pages.
    rd = bytearray()
    addr = RAMDISK_ADDR
    while len(rd) < rsz:
        oo = off_addr(addr)
        take = min(PAGE, rsz - len(rd))
        rd += img[oo : oo + take]
        addr += PAGE

    with tempfile.TemporaryDirectory() as tmp:
        rdcaminho = os.path.join(tempfile.gettempdir(), "nand_sem_servico_rd.gz")
        with open(rdcaminho, "wb") as f:
            f.write(bytes(rd))
        subprocess.run(
            ["sh", "-c", f"cd {tmp} && gzip -dc {rdcaminho} | cpio -idm --quiet"],
            check=True,
        )
        editados = []
        for nome_arq in ("init.rc", "init.trout.rc"):
            p = os.path.join(tmp, nome_arq)
            if not os.path.exists(p):
                continue
            with open(p, "rb") as f:
                linhas = f.read().split(b"\n")
            mudou = False
            for nome in nomes:
                alvo = b"service " + nome.encode()
                for i, ln in enumerate(linhas):
                    if ln == alvo or ln.startswith(alvo + b" "):
                        linhas[i] = b"#" + b" " * (len(ln) - 1)
                        mudou = True
                        j = i + 1
                        while j < len(linhas) and linhas[j][:1] in (b" ", b"\t"):
                            linhas[j] = b"#" + b" " * (len(linhas[j]) - 1)
                            j += 1
            if mudou:
                editados.append(nome_arq)
                with open(p, "wb") as f:
                    f.write(b"\n".join(linhas))
        if not editados:
            print("no service block found for: " + " ".join(nomes))
            return 1
        print("commented out in: " + " ".join(sorted(editados)))
        out = subprocess.run(
            ["sh", "-c", "cd %s && find . -print0 | cpio -o -H newc --quiet -0 2>/dev/null | gzip -9" % tmp],
            check=True,
            capture_output=True,
        ).stdout
    if len(out) > rsz:
        print(f"repacked ramdisk {len(out):#x} exceeds original {rsz:#x}; aborting")
        return 1
    out = out + b"\0" * (rsz - len(out))

    addr = RAMDISK_ADDR
    pos = 0
    while pos < rsz:
        oo = off_addr(addr)
        take = min(PAGE, rsz - pos)
        img[oo : oo + take] = out[pos : pos + take]
        pos += take
        addr += PAGE
    with open(dst, "wb") as f:
        f.write(img)
    print(f"wrote {dst} ({len(out):#x} ramdisk bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
