#!/usr/bin/env python3
"""Gera o binário distribuível do dreamyemu-sdl.

Monta target/release/dreamyemu-sdl e empacota num tarball em dist/ com
README (de onde vem o SPL, como gerar o NAND, controles) e LICENSE.
Uso: python3 ferramentas/empacota_sdl.py [--saida DIR]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOME = "dreamyemu-sdl"
VERSAO = "0.4.2"

LEIAME = """dreamyemu-sdl {versao} — a tela do HTC Dream (SPL)
===============================================

Mostra o framebuffer do SPL (320x480 RGB565, 2x) numa janela SDL2 e
despeja a serial do SPL no stdout. Teclas: Esc/Q fecha.

SPL (blob de terceiros, nunca commitado):
  tests/spl/G1OrigBootloader_nocheck/spl.bin
  Coloque o spl.bin do G1 nesse caminho antes de rodar.

NAND (gerado localmente, nunca commitado):
  python3 ferramentas/cria_nand.py -o tests/spl/nand.img --fill 0xaa
  python3 ferramentas/nand_conteudo.py tests/spl/nand.img assets/Default_US.raw565

Uso:
  ./dreamyemu-sdl [spl.bin [nand.img]] [--sair]
  ./dreamyemu-sdl tests/spl/G1OrigBootloader_nocheck/spl.bin tests/spl/nand.img

Botões virtuais: clique nas caixas na parte inferior da janela (ou as
teclas de atalho) para acionar modos do SPL (HBOOT, fastboot).
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description="empacota o dreamyemu-sdl")
    ap.add_argument("--saida", default=os.path.join(RAIZ, "dist"),
                    help="diretório de saída (padrão: dist/)")
    args = ap.parse_args(argv)

    r = subprocess.run(
        ["cargo", "build", "--release", "--locked", "-p", NOME],
        cwd=RAIZ,
    )
    if r.returncode != 0:
        return r.returncode
    binario = os.path.join(RAIZ, "target", "release", NOME)
    if not os.path.isfile(binario):
        print(f"binário não gerado: {binario}", file=sys.stderr)
        return 1

    pasta = f"{NOME}-{VERSAO}-linux-x86_64"
    raiz_tmp = os.path.join(args.saida, pasta)
    shutil.rmtree(raiz_tmp, ignore_errors=True)
    os.makedirs(raiz_tmp, exist_ok=True)
    shutil.copy2(binario, os.path.join(raiz_tmp, NOME))
    with open(os.path.join(raiz_tmp, "README.txt"), "w") as f:
        f.write(LEIAME.format(versao=VERSAO))
    for lic in ("LICENSE", "LICENSE-GPL3"):
        origem = os.path.join(RAIZ, lic)
        if os.path.isfile(origem):
            shutil.copy2(origem, os.path.join(raiz_tmp, lic))
    tgz = os.path.join(args.saida, pasta + ".tar.gz")
    with tarfile.open(tgz, "w:gz") as t:
        t.add(raiz_tmp, arcname=pasta)
    print(f"pacote: {tgz}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
