//! TEMP (file-backed serve): minimal YAFFS reader over the NAND image
//! so user page faults on file-backed VMAs can be seeded with real
//! file bytes instead of stale/zero pa-alias content (proven live:
//! framework-res.apk entry data read as zeros -> inflate
//! Z_DATA_ERROR -> zygote SIGSEGV).
//!
//! Layout (validated against nand_bringup.img: framework-res.apk,
//! libdvm.so, libcutils.so all extract byte-identical): 2112-byte
//! records (2048 data + 64 spare); spare+4 = objId LE32, spare+8 =
//! chunkId LE32 (0 = header), spare+12 = nbytes LE32; header data+0
//! = type (1=file, 3=dir), data+4 = parent objId, data+10 = name
//! (NUL-terminated), data+292 = file size LE32. Data chunks are
//! numbered from 1, 2048 bytes each.
//!
//! Remove with CRASHOBJ once the serve path is re-evaluated.

use std::collections::HashMap;

const RECORD: usize = 2112;
const PAGE: usize = 2048;
const SPARE: usize = 64;

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// File entry: object id + size + ordered data pages (record indices).
struct Entrada {
    tamanho: u32,
    paginas: Vec<usize>,
}

/// objId -> entry, plus absolute-path -> objId for serving.
pub struct IndiceYaffs {
    por_nome: HashMap<String, u32>,
    por_obj: HashMap<u32, Entrada>,
}

impl IndiceYaffs {
    /// Full image scan. Skips erased (0xFFFFFFFF) and nameless records.
    pub fn constroi(img: &[u8]) -> Self {
        let mut nomes: HashMap<u32, (u8, u32, String, u32)> = HashMap::new();
        let mut blocos: HashMap<u32, Vec<(u32, usize)>> = HashMap::new();
        let n = img.len() / RECORD;
        let mut i = 0;
        while i < n {
            let base = i * RECORD;
            let spare = base + PAGE;
            if spare + SPARE > img.len() {
                break;
            }
            let obj = u32le(img, spare + 4);
            if obj == 0 || obj == 0xFFFF_FFFF {
                i += 1;
                continue;
            }
            let chunk = u32le(img, spare + 8);
            if chunk == 0 {
                let tipo = img[base];
                let pai = u32le(img, base + 4);
                let fim = img[base + 10..base + 42]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(32);
                let nome = String::from_utf8_lossy(&img[base + 10..base + 10 + fim])
                    .into_owned();
                let tam = u32le(img, base + 292);
                nomes.entry(obj).or_insert((tipo, pai, nome, tam));
            } else {
                blocos.entry(obj).or_default().push((chunk, i));
            }
            i += 1;
        }
        // Absolute paths via parent chain (root obj 1 names itself "").
        let mut por_nome = HashMap::new();
        for (&obj, &(tipo, _, ref nome, _)) in nomes.iter() {
            if tipo != 1 || nome.is_empty() {
                continue;
            }
            let mut partes = vec![nome.clone()];
            let mut pai = nomes.get(&obj).map(|&(_, p, _, _)| p).unwrap_or(1);
            let mut ok = true;
            let mut guard = 0;
            while pai != 1 && guard < 32 {
                guard += 1;
                match nomes.get(&pai) {
                    Some(&(_, pp, ref pn, _)) => {
                        if !pn.is_empty() {
                            partes.push(pn.clone());
                        }
                        pai = pp;
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            partes.reverse();
            por_nome.entry(partes.join("/")).or_insert(obj);
        }
        let mut por_obj = HashMap::new();
        for (obj, mut v) in blocos {
            v.sort_by_key(|&(c, _)| c);
            let tamanho = nomes.get(&obj).map(|&(_, _, _, t)| t).unwrap_or(0);
            por_obj.insert(
                obj,
                Entrada {
                    tamanho,
                    paginas: v.into_iter().map(|(_, p)| p).collect(),
                },
            );
        }
        IndiceYaffs { por_nome, por_obj }
    }

    /// Number of servable files (smoke metric for the build log).
    pub fn arquivos(&self) -> usize {
        self.por_nome.len()
    }

    /// Copy file bytes [desl, desl+saida.len()) into saida. Fails when
    /// the path is unknown, the range exceeds the size, or a chunk is
    /// missing (caller falls back to alias/zeros).
    ///
    /// Guest absolute paths carry the mount point (/system/...) while
    /// the image is rooted at the mount: match the longest indexed
    /// suffix instead of the full string.
    pub fn le(&self, img: &[u8], caminho: &str, desl: u32, saida: &mut [u8]) -> bool {
        let sem_barra = caminho.strip_prefix('/').unwrap_or(caminho);
        let mut obj = self.por_nome.get(sem_barra).copied();
        let mut resto = sem_barra;
        while obj.is_none() {
            match resto.find('/') {
                Some(i) => {
                    resto = &resto[i + 1..];
                    obj = self.por_nome.get(resto).copied();
                }
                None => break,
            }
        }
        let obj = match obj {
            Some(o) => o,
            None => return false,
        };
        let e = match self.por_obj.get(&obj) {
            Some(e) => e,
            None => return false,
        };
        let fim = desl as usize + saida.len();
        if fim > e.tamanho as usize {
            return false;
        }
        let mut feito = 0usize;
        while feito < saida.len() {
            let off = desl as usize + feito;
            let nch = off / PAGE;
            let dentro = off % PAGE;
            let &pg = match e.paginas.get(nch) {
                Some(p) => p,
                None => return false,
            };
            let base = pg * RECORD;
            let n = (saida.len() - feito).min(PAGE - dentro);
            if base + dentro + n > img.len() {
                return false;
            }
            saida[feito..feito + n].copy_from_slice(&img[base + dentro..base + dentro + n]);
            feito += n;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEMP (serve validation): the host fixture must resolve the exact
    // asset that crashes the guest (proves index + offsets before
    // wiring it into the fault path). Needs the NAND image next to
    // the repo (git-ignored, never committed). Remove with CRASHOBJ.
    #[test]
    fn indice_localiza_framework_res() {
        let caminho = "tests/spl/nand_bringup.img";
        let img = match std::fs::read(caminho) {
            Ok(b) => b,
            Err(_) => return,
        };
        let idx = IndiceYaffs::constroi(&img);
        assert!(idx.arquivos() > 100, "poucos arquivos: {}", idx.arquivos());
        // Entry data offset of res/xml/autotext.xml inside the apk.
        let mut central = vec![0u8; 512];
        // Local header offset comes from the zip central directory;
        // here we just verify the whole-file read path end to end.
        assert!(idx.le(&img, "/system/framework/framework-res.apk", 0, &mut central));
        assert_eq!(&central[0..4], b"PK\x03\x04", "assinatura zip ausente");
        // Byte 0xedf6b is the entry's compressed data (host-verified).
        let mut comp = vec![0u8; 16];
        assert!(idx.le(&img, "/system/framework/framework-res.apk", 0xedf6b, &mut comp));
        assert_eq!(comp, [0x8d, 0xdc, 0x0b, 0x98, 0x14, 0xd5, 0x95, 0x07, 0xf0, 0x82, 0x79, 0x22, 0x88, 0x88, 0x88, 0x08]);
    }
}
