//! Snapshots da bring-up harness do Dream (`msm7201a`).
//!
//! Pausa o mundo no topo de uma fatia e grava tudo que a retomada
//! precisa para continuar bit a bit: registradores, CPSR e bancos,
//! CP15, monitor exclusivo, todo o `GuestMemory` (regiões com RLE),
//! geração/mm, vigia, TTBR, pendências de IRQ, os rastreadores de
//! falta da harness (`mapeadas*`, `abortadas` — os caps deles mudam
//! o caminho de falta, então retomar zerado divergiria), marcas do
//! tap serial, o SerialTap e a imagem NAND inteira (264 MB brutos;
//! simples e à prova de páginas sujas perdidas).
//!
//! Formato binário próprio, versionado (`MAGIA` + `VERSAO`), sem
//! dependências novas: o que entra aqui é estado de bring-up, e o
//! projeto casa `Cargo.lock` com `THIRD-PARTY-NOTICES.txt` — nada
//! novo entra sem motivo. Detalhe de propósito: isto NÃO cobre o
//! caminho Zeebo (`save_state`); é só a harness Dream, que aquele
//! módulo nunca conheceu.
//!
//! Limites honestos: contadores `static mut` de log das traps zeram
//! na carga (linhas duplicadas, inofensivo); `historico`, `vigias`,
//! `semihosting` e `fonte_irq` do interpretador são remontados pelo
//! setup; fila RX assume-se vazia (nossas corridas nunca plantam
//! entrada); SD além de `None` é recusado em voz alta.

use std::io::Write;

/// Magia de 8 bytes no início de todo arquivo.
pub const MAGIA: &[u8; 8] = b"DREMSNAP";
/// Versão do layout; `carrega` recusa qualquer outra.
/// v3: +mm_para_mm (mapa mm->mm_struct p/ serve file-backed).
pub const VERSAO: u32 = 3;

/// Erro de leitura/escrita/validação de snapshot.
#[derive(Debug)]
pub struct Erro(pub String);

impl std::fmt::Display for Erro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot: {}", self.0)
    }
}

impl std::error::Error for Erro {}

/// Uma região do `GuestMemory`, com dono e geração (bytes já
/// descomprimidos em memória; o RLE vive só no arquivo).
#[derive(Debug, Clone)]
pub struct RegiaoFoto {
    pub nome: String,
    pub base: u32,
    pub dados: Vec<u8>,
    pub gravavel: bool,
    pub executavel: bool,
    pub dono_mm: Option<u32>,
    pub geracao: u32,
    pub semente_pa: Option<u32>,
}

/// Núcleo arquitetural do interpretador (o que o guest vê).
#[derive(Debug, Clone)]
pub struct NucleoFoto {
    pub r: [u32; 16],
    pub cpsr: u32,
    pub spsr: [u32; 6],
    pub banco: [[u32; 2]; 6],
    pub exclusivo: Option<u32>,
    pub instrucoes: u64,
    pub cp15: Vec<(u32, u32)>,
    pub esperando: bool,
    pub irq_pendente: bool,
    pub timer_sujo: bool,
    pub sondagem_irq: u32,
    pub desde_interp: u32,
}

/// Tudo que a retomada precisa (o `pc` já carrega o bit Thumb,
/// como o laço principal o mantém).
#[derive(Debug, Clone)]
pub struct Foto {
    pub fatia: u32,
    pub pc: u32,
    pub nucleo: NucleoFoto,
    pub mm_atual: u32,
    pub gens: Vec<(u32, u32)>,
    pub vigia: Option<(u32, u32)>,
    pub regioes: Vec<RegiaoFoto>,
    pub ttbr_cache: u32,
    pub ttbr_task: u32,
    pub mddi_pendente: bool,
    pub audit_latch: bool,
    pub fb_linux_mapa: (u32, u32),
    pub mapeadas: Vec<u32>,
    pub mapeadas_kern: Vec<u32>,
    pub mapeadas_usr: Vec<(u32, u32, u32)>,
    pub mm_para_mm: Vec<(u32, u32)>,
    pub abortadas: Vec<((u32, u32, u32, u32), u32)>,
    pub tap_marca: u64,
    pub tap_marca_c0: u64,
    pub saida_marca: u64,
    pub tap_canais: Vec<(u32, Vec<u8>)>,
    pub nand: Vec<u8>,
    pub spl_fora: bool,
    pub contagem_gpt: u32,
    pub contagem_dgt: u32,
    pub ultima: Option<u32>,
    pub ultimo_alvo: u32,
    pub planta_n: u32,
}

fn poe_u8(v: &mut Vec<u8>, x: u8) {
    v.push(x);
}

fn poe_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn poe_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn poe_bytes(v: &mut Vec<u8>, dados: &[u8]) {
    poe_u64(v, dados.len() as u64);
    v.extend_from_slice(dados);
}

fn poe_str(v: &mut Vec<u8>, s: &str) {
    poe_bytes(v, s.as_bytes());
}

fn poe_opt_u32(v: &mut Vec<u8>, x: Option<u32>) {
    match x {
        Some(a) => {
            poe_u8(v, 1);
            poe_u32(v, a);
        }
        None => poe_u8(v, 0),
    }
}

/// RLE simples `[valor:u8][len:u32]*`: bancos zerados colapsam;
/// páginas de kernel/tabelas passam quase intactas. Corrige pelo
/// tamanho, nunca pelo conteúdo.
fn poe_rle(v: &mut Vec<u8>, dados: &[u8]) {
    let mut corridas: Vec<(u8, u32)> = Vec::new();
    let mut i = 0;
    while i < dados.len() {
        let b = dados[i];
        let mut n: u32 = 1;
        while i + (n as usize) < dados.len()
            && dados[i + (n as usize)] == b
            && n < u32::MAX
        {
            n += 1;
        }
        corridas.push((b, n));
        i += n as usize;
    }
    poe_u64(v, dados.len() as u64);
    poe_u64(v, corridas.len() as u64);
    for (b, n) in corridas {
        poe_u8(v, b);
        poe_u32(v, n);
    }
}

struct Leitor<'a> {
    dados: &'a [u8],
    pos: usize,
}

impl<'a> Leitor<'a> {
    fn nova(dados: &'a [u8]) -> Self {
        Self { dados, pos: 0 }
    }

    fn resto(&self) -> usize {
        self.dados.len().saturating_sub(self.pos)
    }

    fn tira(&mut self, n: usize) -> Result<&'a [u8], Erro> {
        if self.resto() < n {
            return Err(Erro(format!(
                "fim prematuro aos {n} bytes (offset {})",
                self.pos
            )));
        }
        let s = &self.dados[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Erro> {
        Ok(self.tira(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Erro> {
        let b = self.tira(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, Erro> {
        let b = self.tira(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Erro> {
        let n = self.u64()? as usize;
        if n > self.resto() {
            return Err(Erro(format!("bloco de {n} bytes além do fim")));
        }
        Ok(self.tira(n)?.to_vec())
    }

    fn texto(&mut self) -> Result<String, Erro> {
        let b = self.bytes()?;
        String::from_utf8(b).map_err(|e| Erro(format!("nome inválido: {e}")))
    }

    fn opt_u32(&mut self) -> Result<Option<u32>, Erro> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u32()?)),
            x => Err(Erro(format!("opção inválida: {x}"))),
        }
    }

    fn rle(&mut self) -> Result<Vec<u8>, Erro> {
        let total = self.u64()? as usize;
        let ncor = self.u64()? as usize;
        if ncor > total + 1 {
            return Err(Erro("RLE inconsistente".to_string()));
        }
        let mut fora = Vec::with_capacity(total.min(256 * 1024 * 1024));
        for _ in 0..ncor {
            let b = self.u8()?;
            let n = self.u32()? as usize;
            if fora.len() + n > total {
                return Err(Erro("RLE além do total".to_string()));
            }
            fora.extend(std::iter::repeat(b).take(n));
        }
        if fora.len() != total {
            return Err(Erro("RLE aquém do total".to_string()));
        }
        Ok(fora)
    }
}

fn poe_tupla2(v: &mut Vec<u8>, x: (u32, u32)) {
    poe_u32(v, x.0);
    poe_u32(v, x.1);
}

fn le_tupla2(l: &mut Leitor<'_>) -> Result<(u32, u32), Erro> {
    Ok((l.u32()?, l.u32()?))
}

/// Serializa a `Foto` num arquivo.
pub fn salva(caminho: &str, foto: &Foto) -> Result<(), Erro> {
    let mut v = Vec::with_capacity(foto.nand.len() + 1024 * 1024);
    v.extend_from_slice(MAGIA);
    poe_u32(&mut v, VERSAO);
    poe_u32(&mut v, foto.fatia);
    poe_u32(&mut v, foto.pc);
    let n = &foto.nucleo;
    for r in n.r {
        poe_u32(&mut v, r);
    }
    poe_u32(&mut v, n.cpsr);
    for s in n.spsr {
        poe_u32(&mut v, s);
    }
    for b in n.banco {
        poe_u32(&mut v, b[0]);
        poe_u32(&mut v, b[1]);
    }
    poe_opt_u32(&mut v, n.exclusivo);
    poe_u64(&mut v, n.instrucoes);
    poe_u32(&mut v, n.cp15.len() as u32);
    for p in &n.cp15 {
        poe_tupla2(&mut v, *p);
    }
    poe_u8(&mut v, n.esperando as u8);
    poe_u8(&mut v, n.irq_pendente as u8);
    poe_u8(&mut v, n.timer_sujo as u8);
    poe_u32(&mut v, n.sondagem_irq);
    poe_u32(&mut v, n.desde_interp);
    poe_u32(&mut v, foto.mm_atual);
    poe_u32(&mut v, foto.gens.len() as u32);
    for g in &foto.gens {
        poe_tupla2(&mut v, *g);
    }
    match foto.vigia {
        Some((a, b)) => {
            poe_u8(&mut v, 1);
            poe_u32(&mut v, a);
            poe_u32(&mut v, b);
        }
        None => poe_u8(&mut v, 0),
    }
    poe_u32(&mut v, foto.regioes.len() as u32);
    for r in &foto.regioes {
        poe_str(&mut v, &r.nome);
        poe_u32(&mut v, r.base);
        poe_rle(&mut v, &r.dados);
        poe_u8(&mut v, r.gravavel as u8);
        poe_u8(&mut v, r.executavel as u8);
        poe_opt_u32(&mut v, r.dono_mm);
        poe_u32(&mut v, r.geracao);
        poe_opt_u32(&mut v, r.semente_pa);
    }
    poe_u32(&mut v, foto.ttbr_cache);
    poe_u32(&mut v, foto.ttbr_task);
    poe_u8(&mut v, foto.mddi_pendente as u8);
    poe_u8(&mut v, foto.audit_latch as u8);
    poe_u32(&mut v, foto.fb_linux_mapa.0);
    poe_u32(&mut v, foto.fb_linux_mapa.1);
    poe_u32(&mut v, foto.mapeadas.len() as u32);
    for m in &foto.mapeadas {
        poe_u32(&mut v, *m);
    }
    poe_u32(&mut v, foto.mapeadas_kern.len() as u32);
    for m in &foto.mapeadas_kern {
        poe_u32(&mut v, *m);
    }
    poe_u32(&mut v, foto.mapeadas_usr.len() as u32);
    for m in &foto.mapeadas_usr {
        poe_u32(&mut v, m.0);
        poe_u32(&mut v, m.1);
        poe_u32(&mut v, m.2);
    }
    poe_u32(&mut v, foto.mm_para_mm.len() as u32);
    for m in &foto.mm_para_mm {
        poe_u32(&mut v, m.0);
        poe_u32(&mut v, m.1);
    }
    poe_u32(&mut v, foto.abortadas.len() as u32);
    for a in &foto.abortadas {
        poe_u32(&mut v, (a.0).0);
        poe_u32(&mut v, (a.0).1);
        poe_u32(&mut v, (a.0).2);
        poe_u32(&mut v, (a.0).3);
        poe_u32(&mut v, a.1);
    }
    poe_u64(&mut v, foto.tap_marca);
    poe_u64(&mut v, foto.tap_marca_c0);
    poe_u64(&mut v, foto.saida_marca);
    poe_u32(&mut v, foto.tap_canais.len() as u32);
    for (c, b) in &foto.tap_canais {
        poe_u32(&mut v, *c);
        poe_bytes(&mut v, b);
    }
    poe_bytes(&mut v, &foto.nand);
    poe_u8(&mut v, foto.spl_fora as u8);
    poe_u32(&mut v, foto.contagem_gpt);
    poe_u32(&mut v, foto.contagem_dgt);
    match foto.ultima {
        Some(u) => {
            poe_u8(&mut v, 1);
            poe_u32(&mut v, u);
        }
        None => poe_u8(&mut v, 0),
    }
    poe_u32(&mut v, foto.ultimo_alvo);
    poe_u32(&mut v, foto.planta_n);
    std::fs::File::create(caminho)
        .and_then(|mut a| a.write_all(&v))
        .map_err(|e| Erro(format!("escrever {caminho}: {e}")))?;
    Ok(())
}

/// Lê e valida um arquivo de snapshot.
pub fn carrega(caminho: &str) -> Result<Foto, Erro> {
    let dados =
        std::fs::read(caminho).map_err(|e| Erro(format!("ler {caminho}: {e}")))?;
    let mut l = Leitor::nova(&dados);
    if l.tira(8)? != MAGIA {
        return Err(Erro("magia inválida".to_string()));
    }
    if l.u32()? != VERSAO {
        return Err(Erro("versão incompatível".to_string()));
    }
    let fatia = l.u32()?;
    let pc = l.u32()?;
    let mut r = [0u32; 16];
    for x in r.iter_mut() {
        *x = l.u32()?;
    }
    let cpsr = l.u32()?;
    let mut spsr = [0u32; 6];
    for x in spsr.iter_mut() {
        *x = l.u32()?;
    }
    let mut banco = [[0u32; 2]; 6];
    for b in banco.iter_mut() {
        b[0] = l.u32()?;
        b[1] = l.u32()?;
    }
    let exclusivo = l.opt_u32()?;
    let instrucoes = l.u64()?;
    let ncp = l.u32()? as usize;
    if ncp > 4096 {
        return Err(Erro("cp15 grande demais".to_string()));
    }
    let mut cp15 = Vec::with_capacity(ncp);
    for _ in 0..ncp {
        cp15.push(le_tupla2(&mut l)?);
    }
    let esperando = l.u8()? != 0;
    let irq_pendente = l.u8()? != 0;
    let timer_sujo = l.u8()? != 0;
    let sondagem_irq = l.u32()?;
    let desde_interp = l.u32()?;
    let mm_atual = l.u32()?;
    let ngen = l.u32()? as usize;
    if ngen > 1024 {
        return Err(Erro("gerações demais".to_string()));
    }
    let mut gens = Vec::with_capacity(ngen);
    for _ in 0..ngen {
        gens.push(le_tupla2(&mut l)?);
    }
    let vigia = match l.u8()? {
        0 => None,
        1 => Some((l.u32()?, l.u32()?)),
        x => return Err(Erro(format!("vigia inválida: {x}"))),
    };
    let nreg = l.u32()? as usize;
    if nreg > 1_000_000 {
        return Err(Erro("regiões demais".to_string()));
    }
    let mut regioes = Vec::with_capacity(nreg.min(65536));
    for _ in 0..nreg {
        let nome = l.texto()?;
        if nome.len() > 128 {
            return Err(Erro("nome de região longo".to_string()));
        }
        let base = l.u32()?;
        let dados = l.rle()?;
        if dados.len() > 4 * 1024 * 1024 * 1024 {
            return Err(Erro("região gigante".to_string()));
        }
        let gravavel = l.u8()? != 0;
        let executavel = l.u8()? != 0;
        let dono_mm = l.opt_u32()?;
        let geracao = l.u32()?;
        let semente_pa = l.opt_u32()?;
        regioes.push(RegiaoFoto {
            nome,
            base,
            dados,
            gravavel,
            executavel,
            dono_mm,
            geracao,
            semente_pa,
        });
    }
    let ttbr_cache = l.u32()?;
    let ttbr_task = l.u32()?;
    let mddi_pendente = l.u8()? != 0;
    let audit_latch = l.u8()? != 0;
    let fb_linux_mapa = (l.u32()?, l.u32()?);
    let nmap = l.u32()? as usize;
    if nmap > 1_000_000 {
        return Err(Erro("mapeadas demais".to_string()));
    }
    let mut mapeadas = Vec::with_capacity(nmap.min(1 << 20));
    for _ in 0..nmap {
        mapeadas.push(l.u32()?);
    }
    let nmapk = l.u32()? as usize;
    if nmapk > 1_000_000 {
        return Err(Erro("mapeadas_kern demais".to_string()));
    }
    let mut mapeadas_kern = Vec::with_capacity(nmapk.min(1 << 20));
    for _ in 0..nmapk {
        mapeadas_kern.push(l.u32()?);
    }
    let nmapu = l.u32()? as usize;
    if nmapu > 1_000_000 {
        return Err(Erro("mapeadas_usr demais".to_string()));
    }
    let mut mapeadas_usr = Vec::with_capacity(nmapu.min(1 << 20));
    for _ in 0..nmapu {
        mapeadas_usr.push((l.u32()?, l.u32()?, l.u32()?));
    }
    let nmmm = l.u32()? as usize;
    if nmmm > 1_000_000 {
        return Err(Erro("mm_para_mm demais".to_string()));
    }
    let mut mm_para_mm = Vec::with_capacity(nmmm.min(1 << 20));
    for _ in 0..nmmm {
        mm_para_mm.push((l.u32()?, l.u32()?));
    }
    let nab = l.u32()? as usize;
    if nab > 1_000_000 {
        return Err(Erro("abortadas demais".to_string()));
    }
    let mut abortadas = Vec::with_capacity(nab.min(1 << 20));
    for _ in 0..nab {
        abortadas.push(((l.u32()?, l.u32()?, l.u32()?, l.u32()?), l.u32()?));
    }
    let tap_marca = l.u64()?;
    let tap_marca_c0 = l.u64()?;
    let saida_marca = l.u64()?;
    let ncan = l.u32()? as usize;
    if ncan > 64 {
        return Err(Erro("canais demais".to_string()));
    }
    let mut tap_canais = Vec::with_capacity(ncan);
    for _ in 0..ncan {
        let c = l.u32()?;
        let b = l.bytes()?;
        if b.len() > 16 * 1024 * 1024 {
            return Err(Erro("canal gigante".to_string()));
        }
        tap_canais.push((c, b));
    }
    let nand = l.bytes()?;
    let spl_fora = l.u8()? != 0;
    let contagem_gpt = l.u32()?;
    let contagem_dgt = l.u32()?;
    let ultima = match l.u8()? {
        0 => None,
        1 => Some(l.u32()?),
        x => return Err(Erro(format!("ultima inválida: {x}"))),
    };
    let ultimo_alvo = l.u32()?;
    let planta_n = l.u32()?;
    if l.resto() != 0 {
        return Err(Erro("sobra no fim do arquivo".to_string()));
    }
    Ok(Foto {
        fatia,
        pc,
        nucleo: NucleoFoto {
            r,
            cpsr,
            spsr,
            banco,
            exclusivo,
            instrucoes,
            cp15,
            esperando,
            irq_pendente,
            timer_sujo,
            sondagem_irq,
            desde_interp,
        },
        mm_atual,
        gens,
        vigia,
        regioes,
        ttbr_cache,
        ttbr_task,
        mddi_pendente,
        audit_latch,
        fb_linux_mapa,
        mapeadas,
        mapeadas_kern,
        mapeadas_usr,
        mm_para_mm,
        abortadas,
        tap_marca,
        tap_marca_c0,
        saida_marca,
        tap_canais,
        nand,
        spl_fora,
        contagem_gpt,
        contagem_dgt,
        ultima,
        ultimo_alvo,
        planta_n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEMP (Audio-tombstone provenance): dump the frozen bytes of the
    // crashing heap page across snapshots to see when 0x388f3071
    // entered [0x41a2eaf6]. Plus: does snap570 already hold
    // system_server (0x162d4000) regions, and what seeds the Dalvik
    // stack page 0x42fd8000? Remove with CRASHOBJ.
    #[test]
    fn temp_dump_regiao_41a2e() {
        // TEMP (load shed): only the live snapshot while the box
        // is loaded. Restore the full list when the box is idle.
        for caminho in [
            "/tmp/opencode/snap582.bin",
        ] {
            let foto = match carrega(caminho) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{caminho}: pula ({e:?})");
                    continue;
                }
            };
            let mut achou = false;
            for r in &foto.regioes {
                if r.base == 0x41a2e000 {
                    achou = true;
                    eprintln!(
                        "{caminho} dono={:?} ger={} semente={:?} len={:#x}",
                        r.dono_mm, r.geracao, r.semente_pa, r.dados.len()
                    );
                    eprintln!("  af0..b00: {:02x?}", &r.dados[0xaf0..0xb00]);
                }
            }
            if !achou {
                eprintln!("{caminho}: sem regiao 0x41a2e000");
            }
            for r in &foto.regioes {
                if r.base == 0x4104a000 {
                    eprintln!(
                        "{caminho} node4104a dono={:?} semente={:?} f60..f80: {:02x?}",
                        r.dono_mm,
                        r.semente_pa,
                        &r.dados[0xf60..0xf80],
                    );
                    if caminho.ends_with("snap581.bin") {
                        eprintln!(
                            "FRAME581 f00..f20: {:02x?} f40..f60: {:02x?} f80..fa0: {:02x?}",
                            &r.dados[0xf00..0xf20],
                            &r.dados[0xf40..0xf60],
                            &r.dados[0xf80..0xfa0],
                        );
                    }
                }
            }
            // TEMP (poison census): scan every region for the wild
            // method pointer 0x41a2eaf6 to find all its homes
            // (vtable? pResMethods? frames?). Cap 20. Remove with CRASHOBJ.
            if caminho.ends_with("snap581.bin") {
                let mut achados = 0;
                let mut achados2 = 0;
                for r in &foto.regioes {
                    let n = r.dados.len() / 4;
                    for i in 0..n {
                        let w = u32::from_le_bytes([
                            r.dados[i * 4],
                            r.dados[i * 4 + 1],
                            r.dados[i * 4 + 2],
                            r.dados[i * 4 + 3],
                        ]);
                        if w == 0x41a2eaf6 {
                            eprintln!(
                                "POISONHOME {:#x}+{:#x} dono={:?} semente={:?} nome={}",
                                r.base,
                                i * 4,
                                r.dono_mm,
                                r.semente_pa,
                                r.nome
                            );
                            achados += 1;
                            if achados >= 20 {
                                break;
                            }
                        }
                        if w == 0x388f3071 {
                            eprintln!(
                                "POISON2HOME {:#x}+{:#x} dono={:?} semente={:?} nome={}",
                                r.base,
                                i * 4,
                                r.dono_mm,
                                r.semente_pa,
                                r.nome
                            );
                            achados2 += 1;
                            if achados2 >= 20 {
                                break;
                            }
                        }
                        if w == 0x41aa89a0 {
                            eprintln!(
                                "TRUEMETH {:#x}+{:#x} dono={:?} semente={:?} nome={}",
                                r.base,
                                i * 4,
                                r.dono_mm,
                                r.semente_pa,
                                r.nome
                            );
                            achados2 += 1;
                            if achados2 >= 30 {
                                break;
                            }
                        }
                        if w == 0x4104af74 {
                            eprintln!(
                                "LINK74 {:#x}+{:#x} dono={:?} semente={:?} nome={}",
                                r.base,
                                i * 4,
                                r.dono_mm,
                                r.semente_pa,
                                r.nome
                            );
                            achados2 += 1;
                            if achados2 >= 40 {
                                break;
                            }
                        }
                    }
                    if achados >= 20 && achados2 >= 20 {
                        break;
                    }
                    // Dump the receiver's class object head (clazz
                    // 0x4001b190 of receiver 0x4107fd40): vtable slots?
                    if r.base <= 0x4001b190 && 0x4001b190 < r.base + r.dados.len() as u32 {
                        let o = (0x4001b190 - r.base) as usize;
                        eprintln!(
                            "CLASSHEAD {:#x} dono={:?} semente={:?} head={:02x?}",
                            r.base,
                            r.dono_mm,
                            r.semente_pa,
                            &r.dados[o..o + 128.min(r.dados.len() - o)],
                        );
                    }
                    // Dump the kuser TLS slot (0xFFFF0FF0): pthread TLS
                    // base for pthread_getspecific (dvmThreadSelf).
                    // If stale, Thread* (0xba80) is garbage.
                    if r.base <= 0xFFFF0FF0 && 0xFFFF0FF0 < r.base + r.dados.len() as u32 {
                        let o = (0xFFFF0FF0 - r.base) as usize;
                        eprintln!(
                            "TLSKUSER {:#x} dono={:?} semente={:?} val={:02x?}",
                            r.base,
                            r.dono_mm,
                            r.semente_pa,
                            &r.dados[o..o + 4.min(r.dados.len() - o)],
                        );
                    }
                    // Dump the pthread key slot dvmThreadSelf reads:
                    // GOT[0xad07f000+0xa78] -> base, key at [base+0x2f8]
                    // (=0xad07fd70). Stale key -> wrong TLS slot.
                    if r.base == 0xad07f000 {
                        eprintln!(
                            "TLSKEYPAGE {:#x} dono={:?} semente={:?} a78={:02x?} d70={:02x?}",
                            r.base,
                            r.dono_mm,
                            r.semente_pa,
                            &r.dados[0xa78..0xa7c],
                            &r.dados[0xd70..0xd74],
                        );
                    }
                    // Scan for the Audio-init failure: the
                    // setCapabilities IOException message. Names the
                    // primary failure the walker crash masks.
                    // Remove with CRASHOBJ.
                    if caminho.ends_with("snap581.bin") {
                        for r2 in &foto.regioes {
                            if r2.dados.windows(24).any(|w| w == b"Operation not permitted") {
                                eprintln!(
                                    "EXCSTR {:#x} dono={:?} nome={}",
                                    r2.base, r2.dono_mm, r2.nome
                                );
                                break;
                            }
                        }
                    }
                    if r.base <= 0x41c041a9 && 0x41c041a9 < r.base + r.dados.len() as u32 {
                        let o = (0x41c041a9 - r.base) as usize;
                        let fim = r.dados[o..].iter().position(|&b| b == 0).unwrap_or(40);
                        eprintln!(
                            "METHNAME {:#x}+{:#x} dono={:?} nome={}",
                            r.base,
                            o,
                            r.dono_mm,
                            String::from_utf8_lossy(&r.dados[o..o + fim]),
                        );
                    }
                    // Resolve method names for the trace methods
                    // (walker array payloads): read [method+16] (name
                    // ptr), then dump the string wherever it lives.
                    // Names the Audio-init call chain. Remove with CRASHOBJ.
                    for &ma in &[0x410a4398u32, 0x410a4218, 0x410565f8, 0x410a41b8, 0x4107fd40] {
                        if r.base <= ma && ma + 20 < r.base + r.dados.len() as u32 {
                            let o = (ma - r.base) as usize;
                            let np = u32::from_le_bytes([
                                r.dados[o + 16],
                                r.dados[o + 17],
                                r.dados[o + 18],
                                r.dados[o + 19],
                            ]);
                            // find the string bytes in any region
                            let mut nome = String::from("?");
                            'fora: for r2 in &foto.regioes {
                                if r2.base <= np && np < r2.base + r2.dados.len() as u32 {
                                    let o2 = (np - r2.base) as usize;
                                    let fim = r2.dados[o2..]
                                        .iter()
                                        .position(|&b| b == 0)
                                        .unwrap_or(48);
                                    nome = String::from_utf8_lossy(
                                        &r2.dados[o2..o2 + fim.min(48)],
                                    )
                                    .into_owned();
                                    break 'fora;
                                }
                            }
                            eprintln!(
                                "TRACEMETH {:#x} dono={:?} nome={}",
                                ma, r.dono_mm, nome
                            );
                        }
                    }
                    // TEMP (classname array hunt 1): dump the bytes
                    // around the classname string in system_server heap
                    // to see if it is a char[] (length-prefixed UTF-16).
                    // Remove with CRASHOBJ.
                    if r.base == 0x41bc5000 {
                        eprintln!(
                            "CLASSARR {:#x} dono={:?} f60..f90: {:02x?}",
                            r.base,
                            r.dono_mm,
                            &r.dados[0xf60..0xf90],
                        );
                    }
                    // TEMP (string-array hunt): find plausible String[]
                    // objects in system_server heap: [heap-ptr][small]
                    // [len 1..64][heap-ptr], then chase [0] as a String
                    // and print its chars. Cap 10 hits. Remove with CRASHOBJ.
                    {
                        let mut achados2 = 0;
                        'fu: for r2 in &foto.regioes {
                            if r2.dono_mm != Some(0x162d4000) {
                                continue;
                            }
                            let n = r2.dados.len() / 4;
                            let mut i = 0usize;
                            while i + 4 < n {
                                let w0 = u32::from_le_bytes([r2.dados[i*4], r2.dados[i*4+1], r2.dados[i*4+2], r2.dados[i*4+3]]);
                                let w2 = u32::from_le_bytes([r2.dados[i*4+8], r2.dados[i*4+9], r2.dados[i*4+10], r2.dados[i*4+11]]);
                                let w3 = u32::from_le_bytes([r2.dados[i*4+12], r2.dados[i*4+13], r2.dados[i*4+14], r2.dados[i*4+15]]);
                                if (0x4000_0000..0x4200_0000).contains(&w0) && (1..=64).contains(&w2) && (0x4000_0000..0x4200_0000).contains(&w3) {
                                    // chase w3 as String: [w3+16]=array?
                                    let mut nm = String::from("?");
                                    for r3 in &foto.regioes {
                                        if r3.base <= w3 && w3 + 20 < r3.base + r3.dados.len() as u32 {
                                            let o = (w3 - r3.base) as usize;
                                            let ap = u32::from_le_bytes([r3.dados[o+16], r3.dados[o+17], r3.dados[o+18], r3.dados[o+19]]);
                                            for r4 in &foto.regioes {
                                                if r4.base <= ap && ap + 64 < r4.base + r4.dados.len() as u32 {
                                                    let o2 = (ap - r4.base) as usize;
                                                    let mut t = String::new();
                                                    let mut k = o2 + 12;
                                                    while k + 1 < o2 + 64 && t.len() < 40 {
                                                        let ch = u16::from_le_bytes([r4.dados[k], r4.dados[k+1]]);
                                                        if ch == 0 || ch > 0x7e { break; }
                                                        t.push(ch as u8 as char);
                                                        k += 2;
                                                    }
                                                    if !t.is_empty() { nm = t; }
                                                    break;
                                                }
                                            }
                                            break;
                                        }
                                    }
                                    eprintln!("STRARR {:#x}+{:#x} len={} elem0={:#x} \"{}\"", r2.base, i*4, w2, w3, nm);
                                    achados2 += 1;
                                    if achados2 >= 10 { break 'fu; }
                                }
                                i += 1;
                            }
                            if achados2 >= 10 { break; }
                        }
                    }
                    // TEMP (zygote-args hunt): find ZygoteInit argv content
                    // ("start-system-server", "--zygote") in heap to
                    // locate the real remainingArgs array. Remove with
                    // CRASHOBJ.
                    for pat in [b"start-system-server".as_slice(), b"--zygote".as_slice(), b"--runtime-init".as_slice()] {
                        let mut off = 0usize;
                        while let Some(pos) = r.dados.get(off..).and_then(|s| s.windows(pat.len()).position(|w| w == pat)) {
                            let at = off + pos;
                            eprintln!(
                                "ARGSTR {:?} at {:#x}+{:#x} dono={:?}",
                                String::from_utf8_lossy(pat),
                                r.base,
                                at,
                                r.dono_mm
                            );
                            off = at + pat.len();
                            if off >= r.dados.len() {
                                break;
                            }
                        }
                    }
                    // TEMP (invoke-site bytes): list Foto regions in
                    // 0x41aa0000-0x41ac0000 to find the odex page.
                    // Remove with CRASHOBJ.
                    if (0x41aa0000..0x41ac0000).contains(&r.base) && caminho.ends_with("snap581.bin") {
                        eprintln!(
                            "ODEXREG {:#x} dono={:?} semente={:?} len={:#x}",
                            r.base, r.dono_mm, r.semente_pa, r.dados.len()
                        );
                    }
                    if r.base == 0x41aa7000 && caminho.ends_with("snap581.bin") {
                        eprintln!(
                            "INVOKESITE {:#x} dono={:?} af0..b20: {:02x?}",
                            r.base,
                            r.dono_mm,
                            &r.dados[0xaf0..0xb20],
                        );
                    }
                    // TEMP (lr-page identity): dump Foto bytes at
                    // 0xad3498c8 (capset JNI caller) to verify which
                    // file backs 0xad349000. Remove with CRASHOBJ.
                    if r.base == 0xad349000 && caminho.ends_with("snap581.bin") {
                        eprintln!(
                            "LRPAGE {:#x} dono={:?} semente={:?} 9c8..9e8: {:02x?}",
                            r.base,
                            r.dono_mm,
                            r.semente_pa,
                            &r.dados[0x9c8..0x9e8],
                        );
                    }
                    // TEMP (missing-classname hunt): find the fork-arg
                    // classname string in every region — if zygote
                    // holds it but system_server's page is zeros, the
                    // COW serve dropped it. Remove with CRASHOBJ.
                    {
                        let agulha = b"com.android.server.SystemServer";
                        for r2 in &foto.regioes {
                            if let Some(pos) = r2.dados.windows(agulha.len()).position(|w| w == agulha) {
                                eprintln!(
                                    "CLASSNAME {:#x}+{:#x} dono={:?} semente={:?} nome={}",
                                    r2.base,
                                    pos,
                                    r2.dono_mm,
                                    r2.semente_pa,
                                    r2.nome
                                );
                            }
                        }
                    }
                    // TEMP (mterp-poison provenance): dump the fatal
                    // frame's neighborhood (0x4104af40-0x4104af70: the
                    // IGET_QUICK object local v5 at af60 holding
                    // 0x41aa8ba0). If snap570 already holds it, the
                    // poison predates the resume window (stale frame
                    // inherited via fork). Remove with CRASHOBJ.
                    if r.base == 0x4104a000 {
                        eprintln!(
                            "FRAMEAF {:#x} dono={:?} f40..f80: {:02x?}",
                            r.base,
                            r.dono_mm,
                            &r.dados[0xf40..0xf80],
                        );
                    }
                    // Dump a healthy walker node's neighborhood
                    // (0x4104af00-0x4104af40: nodes af1c/af2c with valid
                    // methods) to infer the frame layout empirically:
                    // which offsets hold fp/method/dexPC.
                    if r.base == 0x4104a000 && caminho.ends_with("snap581.bin") {
                        eprintln!(
                            "FRAME100 {:#x} dono={:?} f00..f40: {:02x?}",
                            r.base,
                            r.dono_mm,
                            &r.dados[0xf00..0xf40],
                        );
                    }
                    // Dump the poison-invoke method struct head
                    // (0x4107fd40: clazz, accessFlags, methodIndex,
                    // regsSize/outsSize/insSize) to compute its frame
                    // size and check for stale fields.
                    if r.base <= 0x4107fd40 && 0x4107fd40 < r.base + r.dados.len() as u32 {
                        let o = (0x4107fd40 - r.base) as usize;
                        eprintln!(
                            "METHODHEAD {:#x}+{:#x} dono={:?} semente={:?} head={:02x?}",
                            r.base,
                            o,
                            r.dono_mm,
                            r.semente_pa,
                            &r.dados[o..o + 32.min(r.dados.len() - o)],
                        );
                    }
                }
                eprintln!("{caminho}: {achados} homes, {achados2} homes2");
            }
            let mut n_ss = 0;
            for r in &foto.regioes {
                if r.dono_mm == Some(0x162d4000) {
                    n_ss += 1;
                    if r.base == 0x42fd8000 {
                        eprintln!(
                            "{caminho} stack42fd8 dono={:?} semente={:?} head={:02x?}",
                            r.dono_mm,
                            r.semente_pa,
                            &r.dados[0x840..0x860]
                        );
                    }
                }
            }
            eprintln!("{caminho}: regioes system_server={n_ss}");
        }
    }

    // TEMP (v10 restore): linear-time hunt for the real RuntimeInit
    // args String[] in snap582. The poisoned frame slot [0x4104af38]
    // (v10, frame 0x4104af10) must be restored to a live array whose
    // [+8] length >= 1. Single pass per needle over all regions
    // (the 581-era hunts are O(n^2) and never finish here).
    // Remove with CRASHOBJ.
    #[test]
    fn temp_caca_v10() {
        let caminho = "/tmp/opencode/snap582.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        eprintln!("mm_atual={:#x} fatia={}", foto.mm_atual, foto.fatia);
        // Dono do frame fatal + valor atual do slot v10.
        for r in &foto.regioes {
            if r.base <= 0x4104af38 && 0x4104af38 + 4 <= r.base + r.dados.len() as u32 {
                let o = (0x4104af38 - r.base) as usize;
                let slot = u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]);
                eprintln!(
                    "V10SLOT regiao={:#x} dono={:?} slot=[0x4104af38]={:#x} frame_f10..f70={:02x?}",
                    r.base, r.dono_mm, slot,
                    &r.dados[0xf10..0xf70.min(r.dados.len())],
                );
            }
            // Fonte do over-read: o slot de metodo odex +0x10.
            if r.base <= 0x41aa8ba0 && 0x41aa8ba0 + 0x40 <= r.base + r.dados.len() as u32 {
                let o = (0x41aa8ba0 - r.base) as usize;
                eprintln!(
                    "ODEXSRC regiao={:#x} dono={:?} nome={} +0x00..0x40={:02x?}",
                    r.base, r.dono_mm, r.nome, &r.dados[o..o+0x40],
                );
            }
        }
        // Agulhas ASCII numa passada por regiao (args do zygote).
        for pat in [
            b"com.android.server.SystemServer".as_slice(),
            b"start-system-server".as_slice(),
            b"--zygote".as_slice(),
            b"--runtime-init".as_slice(),
        ] {
            let mut hits = 0;
            for r in &foto.regioes {
                let mut off = 0usize;
                while let Some(pos) = r.dados.get(off..)
                    .and_then(|s| s.windows(pat.len()).position(|w| w == pat))
                {
                    let at = off + pos;
                    let va = r.base + at as u32;
                    let lo = at.saturating_sub(16);
                    let hi = (at + pat.len() + 16).min(r.dados.len());
                    eprintln!(
                        "ARGSTR {:?} va={:#x} dono={:?} ctx={:02x?}",
                        String::from_utf8_lossy(pat), va, r.dono_mm, &r.dados[lo..hi],
                    );
                    hits += 1;
                    if hits >= 6 {
                        break;
                    }
                    off = at + pat.len();
                }
                if hits >= 6 {
                    break;
                }
            }
            if hits == 0 {
                eprintln!("ARGSTR {:?}: nada", String::from_utf8_lossy(pat));
            }
        }
        // Candidatos a String[] no mm do filho (0x162D4000): o array
        // real de args existe no heap herdado do zygote; o padrao
        // [heap-ptr][?][len 1..64][heap-ptr] so vale se elem0
        // persegue ate chars ASCII (rejeita "?" sem gastar o cap).
        // Uma passada; cap 30 sucessos. Remove with CRASHOBJ.
        let busca_mm = |va: u32, len: u32, dono: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(dono)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        let soletra = |elem: u32, dono: u32| -> Option<String> {
            let so = busca_mm(elem, 20, dono)?;
            let ap = u32::from_le_bytes([so[16], so[17], so[18], so[19]]);
            if !(0x4000_0000..0x4200_0000).contains(&ap) {
                return None;
            }
            let ca = busca_mm(ap + 12, 64, dono)?;
            let mut t = String::new();
            let mut k = 0usize;
            while k + 1 < ca.len() && t.len() < 48 {
                let ch = u16::from_le_bytes([ca[k], ca[k+1]]);
                if ch == 0 || ch > 0x7e {
                    break;
                }
                t.push(ch as u8 as char);
                k += 2;
            }
            if t.is_empty() { None } else { Some(t) }
        };
        for dono_mm in [372064256u32, 371425280u32] {
        let mut ach = 0;
        let mut vistos = 0u32;
        'fora: for r in &foto.regioes {
            if r.dono_mm != Some(dono_mm) || r.dados.len() < 16 {
                continue;
            }
            let n = r.dados.len() / 4;
            let mut i = 0usize;
            while i + 4 < n {
                let w0 = u32::from_le_bytes([r.dados[i*4], r.dados[i*4+1], r.dados[i*4+2], r.dados[i*4+3]]);
                let w2 = u32::from_le_bytes([r.dados[i*4+8], r.dados[i*4+9], r.dados[i*4+10], r.dados[i*4+11]]);
                let w3 = u32::from_le_bytes([r.dados[i*4+12], r.dados[i*4+13], r.dados[i*4+14], r.dados[i*4+15]]);
                if (0x4000_0000..0x4200_0000).contains(&w0)
                    && (1..=64).contains(&w2)
                    && (0x4000_0000..0x4200_0000).contains(&w3)
                {
                    vistos += 1;
                    let cand = r.base + (i*4) as u32;
                    let len_ok = match busca_mm(cand + 8, 4, dono_mm) {
                        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == w2,
                        None => false,
                    };
                    if !len_ok {
                        i += 1;
                        continue;
                    }
                    if let Some(nm0) = soletra(w3, dono_mm) {
                        let mut todos = vec![nm0];
                        let mut ok = true;
                        for j in 1..w2.min(8) {
                            let eo = cand + 12 + j * 4;
                            let eb = match busca_mm(eo, 4, dono_mm) {
                                Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                                None => { ok = false; break; }
                            };
                            match soletra(eb, dono_mm) {
                                Some(s) => todos.push(s),
                                None => { ok = false; break; }
                            }
                        }
                        if ok {
                            eprintln!("STRARR dono={dono_mm:#x} va={cand:#x} len={w2} elems={todos:?}");
                            ach += 1;
                            if ach >= 30 {
                                break 'fora;
                            }
                        }
                    }
                }
                i += 1;
            }
        }
        eprintln!("STRARR dono={dono_mm:#x}: {ach} arrays, {vistos} padroes brutos");
        }
    }

    // TEMP (char arrays): para 3 Strings reais, despeja o vetor
    // em +8 (length + UTF-16) e decide count (A+4=1 sempre? E+20?).
    // Remove with CRASHOBJ.
    #[test]
    fn temp_charvec() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for (so, ap) in [(0x401a0210u32, 0x401a0230u32), (0x401a0320u32, 0x401a0340u32), (0x401a03a8u32, 0x40151aa0u32)] {
            match busca(ap, 48) {
                Some(b) => {
                    let len = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
                    let mut t = String::new();
                    let mut k = 12usize;
                    while k + 1 < b.len() && t.len() < 24 {
                        let ch = u16::from_le_bytes([b[k], b[k+1]]);
                        if ch == 0 || ch > 0x7e {
                            break;
                        }
                        t.push(ch as u8 as char);
                        k += 2;
                    }
                    eprintln!("CHARVEC str={so:#x} arr={ap:#x} arrlen={len} head={:02x?} \"{t}\"", &b[..24]);
                }
                None => eprintln!("CHARVEC str={so:#x}: arr ilegivel"),
            }
        }
    }
    // para calibrar count/offset/hash (o count exato endireita o
    // viveiro). Remove with CRASHOBJ.
    #[test]
    // TEMP (task mm): le task->mm (+0x1B0, calibrado no
    // caminho_arquivo) dos mortos no snap586 para identificar o
    // processo (init? zygote? filho?). Remove with CRASHOBJ.
    #[test]
    fn temp_task_mm() {
        let caminho = "/tmp/opencode/snap586.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        for t in [0xc626e800u32, 0xc6201000, 0xc6231c00, 0xc62ff000, 0xc62ff400] {
            let mm = le(t + 0x1B0);
            let mm2 = le(t + 0x1AC);
            let mm3 = le(t + 0x1B4);
            eprintln!("TASKMM task={t:#x} mm1b0={mm:?} mm1ac={mm2:?} mm1b4={mm3:?}");
        }
        eprintln!("mms conhecidos: pai=0x16238000 filho=0x162d4000 init=?");
    }
    // com +12 == task) de system_server (c626e800) + outras tasks,
    // despeja pilha do kernel (pt_regs/user pc no topo, frames p/
    // wchan) e estado/comm. Remove with CRASHOBJ.
    #[test]
    // TEMP (exiter stack): no snap587 (topo de 583005, c6201000
    // VIVO — morre DURANTE 583005), acha sua thread_info e despeja
    // a pilha (o que fazia ao sair: syscall? Java? qual?). Remove
    // with CRASHOBJ.
    #[test]
    fn temp_pilha_exiter() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca_qq = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for task in [0xc6201000u32] {
            let mut tis = Vec::new();
            let mut vistos = std::collections::HashSet::new();
            for r in &foto.regioes {
                if !(0xC000_0000..0xD000_0000).contains(&r.base) {
                    continue;
                }
                let mut b = r.base & !0x1FFF;
                for _ in 0..3 {
                    if b >= 0xC000_0000 && vistos.insert(b) {
                        if let Some(tb) = busca_qq(b + 12, 4) {
                            if u32::from_le_bytes([tb[0], tb[1], tb[2], tb[3]]) == task {
                                tis.push(b);
                            }
                        }
                    }
                    b = b.wrapping_add(0x2000);
                    if b < r.base {
                        break;
                    }
                }
            }
            eprintln!("EXITER task={task:#x} tis={tis:#x?}");
            for ti in tis.iter().take(1) {
                let st = busca_qq(task, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                eprintln!("  state={st:?}");
                let mut usr = Vec::new();
                let mut kern = Vec::new();
                for k in 0..0x200u32 {
                    let va = ti + 0x2000 - 0x800 + k * 4;
                    if let Some(w) = busca_qq(va, 4) {
                        let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                        if (0x4000_0000..0x4200_0000).contains(&v)
                            || (0xAD00_0000..0xAE00_0000).contains(&v)
                            || (0xAF00_0000..0xB000_0000).contains(&v)
                            || (0xBE00_0000..0xC000_0000).contains(&v)
                            || (0x0000_8000..0x0020_0000).contains(&v)
                        {
                            usr.push(format!("{va:#x}={v:#x}"));
                        } else if (0xC000_0000..0xC800_0000).contains(&v) && v & 3 == 0 {
                            kern.push(format!("{va:#x}={v:#x}"));
                        }
                    }
                }
                eprintln!("  usr=[{}]", usr.join(" "));
                eprintln!("  kern=[{}]", kern.join(" "));
            }
        }
    }
    fn temp_pilha_travada() {
        let caminho = "/tmp/opencode/snap586.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        eprintln!("mm_atual={:#x} fatia={} pc={:#x}", foto.mm_atual, foto.fatia, foto.pc);
        let busca_qq = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for task in [0xc626e800u32, 0xc6201000, 0xc6231c00] {
            // thread_info: bases 8K sobrepostas a qq regiao kernel,
            // com task em +12 (leitura por palavra: regioes sao 4K).
            let mut tis = Vec::new();
            let mut vistos = std::collections::HashSet::new();
            for r in &foto.regioes {
                if !(0xC000_0000..0xD000_0000).contains(&r.base) {
                    continue;
                }
                let mut b = r.base & !0x1FFF;
                for _ in 0..3 {
                    if b >= 0xC000_0000 && vistos.insert(b) {
                        if let Some(tb) = busca_qq(b + 12, 4) {
                            if u32::from_le_bytes([tb[0], tb[1], tb[2], tb[3]]) == task {
                                tis.push(b);
                            }
                        }
                    }
                    b = b.wrapping_add(0x2000);
                    if b < r.base {
                        break;
                    }
                }
            }
            eprintln!("PARK task={task:#x} tis={tis:#x?}");
            for ti in tis.iter().take(2) {
                // Estado + comm do task_struct.
                let st = busca_qq(task, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                let cm = busca_qq(task + 0x2e4, 16).map(|b| {
                    let z = b.iter().position(|&x| x == 0).unwrap_or(16);
                    String::from_utf8_lossy(&b[..z]).into_owned()
                });
                eprintln!("  task state={st:?} comm={cm:?}");
                // Topo da pilha (2 KB): pt_regs + frames (wchan chain),
                // palavra a palavra (regioes sao 4K).
                {
                    let mut usr = Vec::new();
                    let mut kern = Vec::new();
                    for k in 0..0x200u32 {
                        let va = ti + 0x2000 - 0x800 + k * 4;
                        if let Some(w) = busca_qq(va, 4) {
                            let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                            if (0x4000_0000..0x4200_0000).contains(&v)
                                || (0xAD00_0000..0xAE00_0000).contains(&v)
                                || (0xAF00_0000..0xB000_0000).contains(&v)
                                || (0xBE00_0000..0xC000_0000).contains(&v)
                            {
                                usr.push(format!("{va:#x}={v:#x}"));
                            } else if (0xC000_0000..0xC800_0000).contains(&v) && v & 3 == 0 {
                                kern.push(format!("{va:#x}={v:#x}"));
                            }
                        }
                    }
                    eprintln!("  usr=[{}]", usr.join(" "));
                    eprintln!("  kern=[{}]", kern.join(" "));
                }
            }
        }
    }
    // ASCII nas regioes do snap585; o offset contra task
    // 0xc626e800 da o .comm. Remove with CRASHOBJ.
    #[test]
    fn temp_caca_comm() {
        let caminho = "/tmp/opencode/snap585.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for pat in [b"system_server".as_slice(), b"app_process".as_slice(), b"servicemanager".as_slice(), b"mediaserver".as_slice(), b"zygote".as_slice()] {
            let mut ach = 0;
            for r in &foto.regioes {
                let mut off = 0usize;
                while let Some(pos) = r.dados.get(off..).and_then(|s| s.windows(pat.len()).position(|w| w == pat)) {
                    let at = off + pos;
                    // Contexto largo para tras: nome completo da prop.
                    let lo = at.saturating_sub(48);
                    let hi = (at + pat.len() + 4).min(r.dados.len());
                    eprintln!(
                        "COMM {:?} {:#x}+{:#x} dono={:?} ctx={:02x?}",
                        String::from_utf8_lossy(pat), r.base, at, r.dono_mm, &r.dados[lo..hi],
                    );
                    ach += 1;
                    if ach >= 8 {
                        break;
                    }
                    off = at + pat.len();
                }
                if ach >= 8 {
                    break;
                }
            }
            if ach == 0 {
                eprintln!("COMM {:?}: nada", String::from_utf8_lossy(pat));
            }
        }
    }
    // system_server?, c62ff000/400/800/c00, c6231c00, c6201000) no
    // snap585 e caca .comm ASCII. Remove with CRASHOBJ.
    #[test]
    // TEMP (tombstone dump v2): headers (chunk==0) com nome
    // tombstone_* + chunks de dados validos (1<=chunk<0x80000000)
    // do mesmo obj; desconsidera deletados. Remove with CRASHOBJ.
    #[test]
    fn temp_dump_tomb2() {
        let img = match std::fs::read("/tmp/opencode/nand-tomb.img") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sem nand-tomb.img ({e:?})");
                return;
            }
        };
        let u32le = |o: usize| -> u32 {
            u32::from_le_bytes([img[o], img[o+1], img[o+2], img[o+3]])
        };
        // Headers com nome tombstone_*.
        let mut objs = Vec::new();
        for i in 0..(img.len() / 2112) {
            let base = i * 2112;
            let spare = base + 2048;
            if u32le(spare + 8) != 0 {
                continue;
            }
            if img[base] != 1 {
                continue;
            }
            let fim = img[base + 10..base + 42].iter().position(|&b| b == 0).unwrap_or(32);
            let nome = String::from_utf8_lossy(&img[base + 10..base + 10 + fim]).into_owned();
            if nome.starts_with("tombstone") {
                let obj = u32le(spare + 4);
                let tam = u32le(base + 292);
                eprintln!("HDR rec={i} obj={obj} nome={nome:?} tam={tam}");
                objs.push(obj);
            }
        }
        // Dados validos de cada obj.
        for obj in objs {
            let mut txt = Vec::new();
            let mut nch = 0;
            for i in 0..(img.len() / 2112) {
                let base = i * 2112;
                let spare = base + 2048;
                if u32le(spare + 4) != obj {
                    continue;
                }
                let c = u32le(spare + 8);
                if c >= 1 && c < 0x80000000 {
                    nch += 1;
                    if txt.len() < 32768 {
                        txt.extend_from_slice(&img[base..base + 2048]);
                    }
                }
            }
            eprintln!("DATA obj={obj} chunks={nch}");
            for (k, ln) in String::from_utf8_lossy(&txt).lines().take(50).enumerate() {
                let t = ln.trim_end_matches('\0').trim();
                if !t.is_empty() {
                    eprintln!("T[{k}]: {t}");
                }
            }
        }
    }
    // conteudo das paginas de dados do tombstone_01.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_dump_tomb() {
        let img = match std::fs::read("/tmp/opencode/nand-tomb.img") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sem nand-tomb.img ({e:?})");
                return;
            }
        };
        let u32le = |o: usize| -> u32 {
            u32::from_le_bytes([img[o], img[o+1], img[o+2], img[o+3]])
        };
        for i in 92830..92852 {
            let base = i * 2112;
            let spare = base + 2048;
            let obj = u32le(spare + 4);
            let chunk = u32le(spare + 8);
            let tipo = img[base];
            eprintln!("REC {i} obj={obj} chunk={chunk} tipo={tipo}");
        }
        // Acha o obj do tombstone_01 (header em 92838) e despeja
        // seus chunks de dados como texto.
        let obj = u32le(92838 * 2112 + 2048 + 4);
        eprintln!("TOMB obj={obj}");
        let mut txt = Vec::new();
        for i in 0..131072 {
            let base = i * 2112;
            if base + 2112 > img.len() {
                break;
            }
            let spare = base + 2048;
            if u32le(spare + 4) == obj && u32le(spare + 8) >= 1 {
                let c = u32le(spare + 8);
                if txt.len() < 32768 {
                    txt.extend_from_slice(&img[base..base + 2048]);
                }
                eprintln!("TOMB chunk={c} rec={i}");
            }
        }
        let s = String::from_utf8_lossy(&txt);
        // Primeiras 60 linhas legiveis.
        for (k, ln) in s.lines().take(60).enumerate() {
            let t = ln.trim_end_matches('\0').trim();
            if !t.is_empty() || k < 5 {
                eprintln!("TOMB[{k}]: {t}");
            }
        }
    }
    // nand-tomb.img para achar o nome real. Remove with CRASHOBJ.
    #[test]
    fn temp_lista_tomb() {
        let img = match std::fs::read("/tmp/opencode/nand-tomb.img") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sem nand-tomb.img ({e:?})");
                return;
            }
        };
        // Varredura direta dos headers (tipo==1) por nome contendo
        // "tomb", sem depender do indice.
        let rec = img.len() / 2112;
        let mut ach = 0;
        for i in 0..rec {
            let base = i * 2112;
            if base + 42 > img.len() {
                break;
            }
            if img[base] != 1 {
                continue;
            }
            let fim = img[base + 10..base + 42].iter().position(|&b| b == 0).unwrap_or(32);
            let nome = String::from_utf8_lossy(&img[base + 10..base + 10 + fim]).into_owned();
            if nome.contains("tomb") || nome.contains("data") || nome == "system_server" || nome.contains("937") || nome.contains("37") {
                eprintln!("YAFFS rec={i} nome={nome:?}");
                ach += 1;
                if ach >= 20 {
                    break;
                }
            }
        }
        eprintln!("YAFFS: {ach} hits");
    }
    // nand-tomb.img (salvo em 583250, pos-escrita) via IndiceYaffs.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_le_tombstone() {
        let img = match std::fs::read("/tmp/opencode/nand-tomb.img") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sem nand-tomb.img ({e:?})");
                return;
            }
        };
        let idx = crate::msm7201a_yaffs::IndiceYaffs::constroi(&img);
        eprintln!("arquivos={}", idx.arquivos());
        let mut fora = vec![0u8; 65536];
        for caminho in ["data/tombstones/tombstone_01", "tombstone_01", "/data/tombstones/tombstone_01"] {
            if idx.le(&img, caminho, 0, &mut fora) {
                let fim = fora.iter().position(|&b| b == 0).unwrap_or(fora.len());
                let txt = String::from_utf8_lossy(&fora[..fim.min(8192)]);
                eprintln!("TOMBSTONE {caminho}:\n{txt}");
                return;
            }
        }
        eprintln!("TOMBSTONE: nao achado");
    }
    // TEMP (exit frames): despeja 0x4104af40-0x4104afc0 no snap587
    // (salvo no topo de 583005, fatia do exit_group(1); frames
    // af84/af94 no nstk do exit) + chase Method* para nomear quem
    // estava no caminho do exit. Remove with CRASHOBJ.
    #[test]
    fn temp_exit_frames() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        let nome_de = |pa: u32| -> Option<(String, String)> {
            let wm = busca(pa, 36)?;
            let pa_n = u32::from_le_bytes([wm[16], wm[17], wm[18], wm[19]]);
            let cl = u32::from_le_bytes([wm[0], wm[1], wm[2], wm[3]]);
            let mnb = busca(pa_n, 64)?;
            let fim = mnb.iter().position(|&b| b == 0).unwrap_or(64);
            let mn = String::from_utf8_lossy(&mnb[..fim]).into_owned();
            if mn.is_empty() || !mn.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                return None;
            }
            let mut cla = String::from("?");
            if let Some(wcl) = busca(cl, 32) {
                let pa_d = u32::from_le_bytes([wcl[24], wcl[25], wcl[26], wcl[27]]);
                if let Some(dnb) = busca(pa_d, 72) {
                    let f2 = dnb.iter().position(|&b| b == 0).unwrap_or(72);
                    let u = String::from_utf8_lossy(&dnb[..f2]).into_owned();
                    if !u.is_empty() && u.len() < 70 {
                        cla = u;
                    }
                }
            }
            Some((cla, mn))
        };
        if let Some(fr) = busca(0x4104af40, 128) {
            for (k, w) in fr.chunks_exact(4).enumerate() {
                let cand = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                if (0x4000_0000..0x4200_0000).contains(&cand) {
                    if let Some((c, m)) = nome_de(cand) {
                        eprintln!("EXITFR +{:#x}={cand:#x} \"{c}.{m}\"", k * 4);
                    }
                }
            }
            let links: Vec<u32> = fr[..32].chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
            eprintln!("EXITFR links={links:#x?}");
            let mid: Vec<u32> = fr[0x40..0x60].chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
            eprintln!("EXITFR af84={mid:#x?}");
        } else {
            eprintln!("EXITFR: sem regiao");
        }
    }
    // TEMP (stuck main): no snap587 (topo de 583005, system_server
    // VIVO (morre 584338!)), despeja a pilha nativa da main thread
    // (0xbe9b7000-0xbe9b8000, child) + frames Dalvik 0x4104a000
    // para nomear onde esta travado (futex? binder? spin?).
    // Remove with CRASHOBJ.
    #[test]
    fn temp_main_travada() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for base in [0xbe9b7000u32, 0xbe9b6000, 0xbe9b5000] {
            if let Some(b) = busca(base, 0x1000) {
                let mut cands = Vec::new();
                for (k, w) in b.chunks_exact(4).enumerate() {
                    let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                    if (0xAD00_0000..0xAE00_0000).contains(&v)
                        || (0xAF00_0000..0xB000_0000).contains(&v)
                        || (0x0000_8000..0x0020_0000).contains(&v)
                    {
                        cands.push(format!("+{:#x}={v:#x}", k * 4));
                    }
                }
                eprintln!("MAINTR base={base:#x} pcs=[{}]", cands.join(" "));
            }
        }
        for off in [0x0usize, 0x80] {
            if let Some(fr) = busca(0x4104a000 + off as u32, 128) {
                let ws: Vec<u32> = fr.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                eprintln!("MAINFR +{off:#x}={ws:#x?}");
            }
        }
    }
    fn temp_quem_morreu() {
        // c6201000 VIVO aqui (morreu em 583005); os outros ja mortos.
        let caminho = "/tmp/opencode/snap584.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca_qq = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for t in [0xc626e800u32, 0xc62ff000, 0xc62ff400, 0xc62ff800, 0xc62ffc00, 0xc6231c00, 0xc6201000] {
            match busca_qq(t, 2048) {
                Some(b) => {
                    // Caca ASCII >= 4 chars (comm tem 16).
                    let mut nomes = Vec::new();
                    let mut i = 0usize;
                    while i + 4 < b.len() {
                        if b[i].is_ascii_graphic() && b[i+1].is_ascii_graphic() && b[i+2].is_ascii_graphic() && b[i+3].is_ascii_graphic() {
                            let mut j = i;
                            while j < b.len() && j < i + 16 && (b[j].is_ascii_graphic() || b[j] == b' ' || b[j] == b'/' || b[j] == b'.' || b[j] == b'_') {
                                j += 1;
                            }
                            if j > i + 3 && (j >= b.len() || b[j] == 0) {
                                nomes.push(format!("+{:#x}=\"{}\"", i, String::from_utf8_lossy(&b[i..j])));
                                i = j;
                                continue;
                            }
                        }
                        i += 1;
                    }
                    eprintln!("TASK {t:#x}: {}", nomes.join(" "));
                }
                None => eprintln!("TASK {t:#x}: ausente"),
            }
        }
    }
    // String-candidatos no frame do findClass, INVKFR#22) no
    // snap584. Remove with CRASHOBJ.
    #[test]
    // TEMP (abort caller): despeja paginas do abortador (libc
    // 0xafe38000, linker 0xb000f000, app 0x8000) no snap585b para
    // desmontar quem chamou abort (0xafe3892c? 0xb000f55c?
    // 0x879e0?). Remove with CRASHOBJ.
    #[test]
    fn temp_quem_abortou() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for va in [0xafe38000u32, 0xb000f000, 0x8000, 0x9000] {
            let mut achou = false;
            for r in &foto.regioes {
                if r.base == va {
                    let saida = format!("/tmp/opencode/abort_{va:#x}.bin");
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("ABORTDUMP va={va:#x} dono={:?} -> {saida}", r.dono_mm);
                    achou = true;
                    break;
                }
            }
            if !achou {
                eprintln!("ABORTDUMP va={va:#x}: sem regiao base (tenta paginas vizinhas)");
            }
        }
    }
    // (lr do exit_group(1) que matou a task c6201000, FATAL#1) para
    // ver se e exit() normal ou abort(). Remove with CRASHOBJ.
    #[test]
    // TEMP (init text): despeja paginas 0x8000-0xd000 do mm do init
    // (dono 370540544) no snap585b para desmontar os call sites
    // fork (0xbe38) e kill (0xcac8). Remove with CRASHOBJ.
    #[test]
    fn temp_init_texto() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for va in [0x8000u32, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000] {
            let mut achou = false;
            for r in &foto.regioes {
                if r.base == va && r.dono_mm == Some(370540544) {
                    let saida = format!("/tmp/opencode/init_{va:#x}.bin");
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("INITDUMP va={va:#x} -> {saida}");
                    achou = true;
                    break;
                }
            }
            if !achou {
                eprintln!("INITDUMP va={va:#x}: ausente");
            }
        }
    }
    // 0xad047e87 no nstk do exit_group(1) — a fronteira JNI da
    // thread que saiu) para nomear a chamada. Remove with CRASHOBJ.
    #[test]
    // TEMP (pid scan): procura 37 (system_server) nos 256 B de
    // cada task morta para calibrar o offset de pid/tgid e separar
    // threads (mesmo tgid) de processos. Remove with CRASHOBJ.
    #[test]
    fn temp_quem_pid2() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca_qq = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for t in [0xc626e800u32, 0xc62ff000, 0xc62ff400, 0xc62ff800, 0xc62ffc00, 0xc6201000, 0xc6231c00] {
            match busca_qq(t, 256) {
                Some(b) => {
                    let mut hits = Vec::new();
                    for (k, w) in b.chunks_exact(4).enumerate() {
                        let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                        if v == 37 || v == 28 || v == 1 || v == 32 {
                            hits.push(format!("+{:#x}={v}", k * 4));
                        }
                    }
                    eprintln!("PID2 task={t:#x} petits={}", hits.join(" "));
                }
                None => eprintln!("PID2 task={t:#x}: ausente"),
            }
        }
    }
    // ficam no inicio; pid 37 = system_server) para separar
    // threads (mesmo pid) de processos. Remove with CRASHOBJ.
    #[test]
    fn temp_quem_pid() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca_qq = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for t in [0xc626e800u32, 0xc62ff000, 0xc62ff400, 0xc62ff800, 0xc62ffc00, 0xc6201000, 0xc6231c00] {
            match busca_qq(t, 128) {
                Some(b) => {
                    let ws: Vec<u32> = b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                    eprintln!("PID task={t:#x} words={ws:?}");
                }
                None => eprintln!("PID task={t:#x}: ausente"),
            }
        }
    }
    // app_process) no snap585b — o fault pos-fork em pc=0xa738
    // (ABORT#57) e de init ou app_process? Remove with CRASHOBJ.
    #[test]
    fn temp_filho_fork() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for (va, dono) in [(0xa000u32, 371425280u32), (0xa000u32, 372064256u32)] {
            for r in &foto.regioes {
                if r.base == va && r.dono_mm == Some(dono) {
                    let saida = format!("/tmp/opencode/kid_{va:#x}_{dono}.bin");
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("KIDDUMP va={va:#x} dono={dono} -> {saida}");
                    break;
                }
            }
        }
    }
    // TEMP (init text): despeja 0xa000 do mm do init (0x16160000
    // = 370440192) no snap5843x para desmontar o crash do filho
    // (pc=0xa738, far=0x18). Remove with CRASHOBJ.
    #[test]
    fn temp_init_text() {
        let caminho = "/tmp/opencode/snap5843x.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for r in &foto.regioes {
            if r.base == 0xa000 {
                eprintln!("SEED base={:#x} dono={:?} semente={:?} ger={} len={:#x}", r.base, r.dono_mm, r.semente_pa, r.geracao, r.dados.len());
            }
        }
    }
    // TEMP (exec stack strings): le a pilha do exec em 0xbe9add20
    // no snap5853x (pos-exec, pre-morte) — argv sao ponteiros
    // validos? strings legiveis? Remove with CRASHOBJ.
    #[test]
    fn temp_exec_stack() {
        let caminho = "/tmp/opencode/snap5853x.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        let le_cstr = |va: u32| -> Option<String> {
            for r in &foto.regioes {
                if r.base <= va && va < r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    let z = r.dados[o..].iter().position(|&b| b == 0).unwrap_or(0);
                    if z == 0 || z >= 128 {
                        return None;
                    }
                    let t = String::from_utf8_lossy(&r.dados[o..o+z]).into_owned();
                    if t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                        return Some(t);
                    }
                    return None;
                }
            }
            None
        };
        eprintln!("EXECSTK snap fat={} pc={:#x} mm={:#x}", foto.fatia, foto.pc, foto.mm_atual);
        for i in 0..16 {
            let va = 0xbe9add20u32 + i * 4;
            let w = le(va).unwrap_or(0xDEADDEAD);
            let s = if (0xbe00_0000..0xc000_0000).contains(&w) {
                le_cstr(w).map(|t| format!(" -> {t:?}")).unwrap_or_default()
            } else {
                String::new()
            };
            eprintln!("EXECSTK [{va:#x}]={w:#x}{s}");
        }
    }
    // TEMP (child state): estado do filho c6231c00 no snap5843x
    // (pos-fork 584323, vivo): task_struct (comm/pid/stack),
    // thread_info + pt_regs (pc/sp/lr do retorno do fork). Se o
    // pc for lixo, o fork esta quebrado; se pending tem SEGV, o
    // assassino e herança. Remove with CRASHOBJ.
    #[test]
    fn temp_child_state() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        let task = 0xc6231c00u32;
        // mm_users do mm do zygote (0xc61591c0?) em +0x28/+0x2c no
        // snap587 (main morto, 5 daemons vivos -> ~5?): confirma
        // offset para o gating da epoca (so invalida se last user).
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        for off in [0x28u32, 0x2c, 0x30, 0x24, 0x20] {
            eprintln!("CHILD zygotemm+{off:#x}={:#x}", le(0xc61591c0 + off).unwrap_or(0xDEADDEAD));
        }
        let mut comm = String::from("?");
        for off in (0..256).step_by(4) {
            let mut s = Vec::new();
            let mut ok = true;
            for k in 0..16 {
                let va = task + off as u32 + k as u32;
                let mut b = 0u8;
                let mut achou = false;
                for r in &foto.regioes {
                    if r.base <= va && va < r.base + r.dados.len() as u32 {
                        b = r.dados[(va - r.base) as usize];
                        achou = true;
                        break;
                    }
                }
                if !achou || b == 0 {
                    break;
                }
                if !(b.is_ascii_graphic() || b == b' ' || b == b'_' || b == b'/' || b == b'.') {
                    ok = false;
                    break;
                }
                s.push(b);
            }
            if ok && s.len() >= 4 {
                comm = format!("+{off:#x}={}", String::from_utf8_lossy(&s));
                break;
            }
        }
        let stack = le(task + 4).unwrap_or(0);
        let pid = le(task + 220).unwrap_or(0xDEAD);
        eprintln!("CHILD task={task:#x} comm={comm} stack={stack:#x} pidish={pid:#x}");
        // pt_regs no topo da thread_info (ARM: base+8K-...): despeja
        // ultimas 18 words (r0-r12,sp,lr,pc,cpsr?) se stack valido
        if (0xC000_0000..0xD000_0000).contains(&stack) {
            for i in 0..18 {
                let va = (stack + 0x2000 - 72) + i * 4;
                eprintln!("CHILD preg[{i}]={:#x}", le(va).unwrap_or(0xDEADDEAD));
            }
        }
    }
    // TEMP (ctx switch): despeja a pagina com 0xC0214DCC
    // (context_switch? chama finish_task_switch?) no snap5843x.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_switch_site() {
        let caminho = "/tmp/opencode/snap5843x.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for r in &foto.regioes {
            if r.base <= 0xC0214DCC && 0xC0214DCC + 4 <= r.base + r.dados.len() as u32 {
                let saida = "/tmp/opencode/ctx_c0214000.bin";
                std::fs::write(&saida, &r.dados).expect("grava");
                eprintln!("CTX base={:#x} len={:#x} -> {saida}", r.base, r.dados.len());
                break;
            }
        }
    }
    // TEMP (ksegv caller): despeja a pagina do kernel com o lr do
    // DOEXIT (0xC004A384, quem chamou do_exit com 0xb no FATAL#7)
    // no snap587 + regiao do task c6231c00 se presente.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_ksegv_caller() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for r in &foto.regioes {
            if r.base <= 0xC004A384 && 0xC004A384 + 4 <= r.base + r.dados.len() as u32 {
                let saida = "/tmp/opencode/ksegv_c004a000.bin";
                std::fs::write(&saida, &r.dados).expect("grava");
                eprintln!("KSEGV base={:#x} len={:#x} -> {saida}", r.base, r.dados.len());
                break;
            }
        }
    }
    // TEMP (libc dump): despeja todas as regioes de texto da libc
    // (VMA afe00000-afe35000) do mm pai no snap587 para varrer
    // TODOS os BL->abort/_exit (achar quem chama EF36/EF38/EEB0).
    // Remove with CRASHOBJ.
    #[test]
    fn temp_libc_dump() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let mut n = 0u32;
        for r in &foto.regioes {
            if r.dono_mm == Some(371425280) && r.base >= 0xafe00000 && r.base < 0xafe35000 {
                let saida = format!("/tmp/opencode/libcall_{:x}.bin", r.base);
                std::fs::write(&saida, &r.dados).expect("grava");
                eprintln!("LIBCALL base={:#x} len={:#x} -> {saida}", r.base, r.dados.len());
                n += 1;
            }
        }
        eprintln!("LIBCALL total={n}");
    }
    // TEMP (cena no load): a cena do abort (a8d5 em +36rel,
    // frames DVM) ja esta na pagina be9b7000 no snap584 (load)?
    // Se sim, a cena e pre-load (residuo) e a morte reusa.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_cena_load() {
        for caminho in ["/tmp/opencode/snap584.bin", "/tmp/opencode/snap582.bin"] {
            let foto = match carrega(caminho) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{caminho}: pula ({e:?})");
                    continue;
                }
            };
            let le = |va: u32| -> Option<u32> {
                for r in &foto.regioes {
                    if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                        let o = (va - r.base) as usize;
                        return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                    }
                }
                None
            };
            // varre a pagina be9b7000 por marcadores da cena
            let mut a8 = 0u32;
            let mut desta = 0u32;
            let mut ad04 = 0u32;
            for off in (0..0x2000).step_by(4) {
                if let Some(w) = le(0xbe9b7000 + off as u32) {
                    if w == 0xafe0a8d5 {
                        a8 += 1;
                    }
                    if w == 0x410a4218 {
                        desta += 1;
                    }
                    if (w & 0xFFFFF000) == 0xad040000 {
                        ad04 += 1;
                    }
                }
            }
            eprintln!("CENA {caminho} a8d5={a8} main4218={desta} ad04xxx={ad04}");
        }
    }
    // TEMP (heap hunt): procura o BK selvagem 0xb000f55c (slot
    // r4 do frame do abort) nas regioes do snap587 + despeja o
    // entorno (cabecalho de chunk dlmalloc: prev_size/size/fd/bk).
    // Diz se o smash esta no heap da morte ou se e residuo.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_heap_hunt() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let mut achados = 0u32;
        for r in &foto.regioes {
            let n = r.dados.len() / 4;
            for i in 0..n {
                let o = i * 4;
                let w = u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]);
                if w == 0xb000f55c {
                    if achados < 12 {
                        let va = r.base + o as u32;
                        let pega = |off: i32| -> String {
                            let a = va.wrapping_add(off as u32);
                            let mut s = String::new();
                            for k in 0..4 {
                                let mut b = [0u8; 4];
                                let mut ok = false;
                                for rg in &foto.regioes {
                                    let aa = a + k * 4;
                                    if rg.base <= aa && aa + 4 <= rg.base + rg.dados.len() as u32 {
                                        let oo = (aa - rg.base) as usize;
                                        b.copy_from_slice(&rg.dados[oo..oo+4]);
                                        ok = true;
                                        break;
                                    }
                                }
                                if ok {
                                    s.push_str(&format!(" {:08x}", u32::from_le_bytes(b)));
                                } else {
                                    s.push_str(" ????????");
                                }
                            }
                            s
                        };
                        eprintln!("HEAPHIT {va:#x} (regiao {base:#x} {nome}) -16:{nb} +16:{na}", base = r.base, nome = r.nome, nb = pega(-16), na = pega(16));
                    }
                    achados += 1;
                }
            }
        }
        eprintln!("HEAPHIT total={achados}");
    }
    // TEMP (metodos do frame): resolve Method* da pilha do EXITB
    // (ZygoteInit.main=0x410a4218 como controle) para achar o metodo
    // JNI que chamou dvmCreateCstrFromString. Layouts calibrados:
    // Method {clazz+0,name+16,insns+32}, Class {descriptor+24},
    // String {array+8,count+20}. Remove with CRASHOBJ.
    #[test]
    fn temp_frame_methods() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        let le_cstr = |va: u32| -> Option<String> {
            for r in &foto.regioes {
                if r.base <= va && va < r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    let z = r.dados[o..].iter().position(|&b| b == 0).unwrap_or(0);
                    if z == 0 || z >= 128 {
                        return None;
                    }
                    let t = String::from_utf8_lossy(&r.dados[o..o+z]).into_owned();
                    if t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                        return Some(t);
                    }
                    return None;
                }
            }
            None
        };
        // StringObject -> texto via array+8/count+20 (utf16)
        let le_jstr = |va: u32| -> Option<String> {
            let arr = le(va + 8)?;
            let cnt = le(va + 20)?;
            if cnt == 0 || cnt >= 256 {
                return None;
            }
            for r in &foto.regioes {
                if r.base <= arr && arr + cnt * 2 <= r.base + r.dados.len() as u32 {
                    let o = (arr - r.base) as usize;
                    let u16s: Vec<u16> = (0..cnt as usize).map(|i| u16::from_le_bytes([r.dados[o + i * 2], r.dados[o + i * 2 + 1]])).collect();
                    let s = String::from_utf16_lossy(&u16s);
                    if s.bytes().all(|b| b.is_ascii_graphic() || b == b' ' || b == b'/' || b == b';' || b == b'(') {
                        return Some(s);
                    }
                    return None;
                }
            }
            None
        };
        for met in [0x410a4218u32, 0x41049200, 0x4107fd40, 0x4107fcb0, 0x41aa8b18, 0x41bafb67, 0x41b60387, 0x41a2eaf6] {
            let cla = le(met).unwrap_or(0);
            let nome = le(met + 16).unwrap_or(0);
            let ins = le(met + 32).unwrap_or(0);
            let desc = if cla != 0 { le(cla + 24).unwrap_or(0) } else { 0 };
            let nm = le_jstr(nome).unwrap_or_else(|| format!("<?>"));
            let dc = le_jstr(desc).or_else(|| le_cstr(desc)).unwrap_or_else(|| format!("<?>"));
            eprintln!("METODO {met:#x} {dc}.{nm} ins={ins:#x}");
        }
    }
    // TEMP (vma list): lista todas as VMAs com caminho para o mm
    // pai (371425280) no snap587 — base real de libdvm (texto?),
    // libc, linker e 0x40026xxx. Remove with CRASHOBJ.
    #[test]
    fn temp_vma_lista() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        let le_str = |va: u32| -> Option<String> {
            for r in &foto.regioes {
                if r.base <= va && va < r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    let z = r.dados[o..].iter().position(|&b| b == 0).unwrap_or(0);
                    if z == 0 || z >= 64 {
                        return None;
                    }
                    let t = String::from_utf8_lossy(&r.dados[o..o+z]).into_owned();
                    if t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                        return Some(t);
                    }
                    return None;
                }
            }
            None
        };
        let mm = match foto.mm_para_mm.iter().find(|(a, _)| *a == 371425280) {
            Some((_, m)) => *m,
            None => {
                eprintln!("VMALISTA: sem mm_struct pai");
                return;
            }
        };
        let mut vma = le(mm).unwrap_or(0);
        let mut depth = 0u32;
        while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 400 {
            depth += 1;
            let ini = le(vma + 4).unwrap_or(0xFFFF_FFFF);
            let fim = le(vma + 8).unwrap_or(0);
            let arq = le(vma + 72).unwrap_or(0);
            if arq != 0 {
                let mut dent = le(arq + 12).unwrap_or(0);
                let mut guard = 0u32;
                let mut partes = Vec::new();
                while (0xC000_0000..0xD000_0000).contains(&dent) && guard < 8 {
                    guard += 1;
                    if let (Some(np), Some(pai)) = (le(dent + 0x20), le(dent + 0x14)) {
                        if let Some(nm) = le_str(np) {
                            partes.push(nm);
                        }
                        if pai == dent {
                            break;
                        }
                        dent = pai;
                    } else {
                        break;
                    }
                }
                partes.reverse();
                let p = partes.join("/");
                if p.contains("dvm") || p.contains("libc") || p.contains("linker") || p.contains("libm") {
                    eprintln!("VMALISTA [{ini:#x},{fim:#x}) /{p}");
                }
            } else if (0x40000000..0x50000000).contains(&ini) || (0xad000000..0xae000000).contains(&ini) {
                eprintln!("VMALISTA [{ini:#x},{fim:#x}) anon");
            }
            vma = le(vma + 12).unwrap_or(0);
        }
    }
    // TEMP (abort-tail caller): despeja paginas libc/linker do mm
    // pai (371425280) no snap587 para identificar quem chamou
    // 0xafe0ef37 (retorno 0xafe0a8d5 no nstk do EXITB; ponteiro
    // 0xafe35d78; 0xb000f55c). Remove with CRASHOBJ.
    #[test]
    fn temp_abort_caller() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for va in [0xafe0a000u32, 0xafe35000u32, 0xafe0e000u32, 0xb000f000u32] {
            for r in &foto.regioes {
                if r.base == va && r.dono_mm == Some(371425280) {
                    let saida = format!("/tmp/opencode/abtc_{va:#x}.bin");
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("ABTC va={va:#x} -> {saida}");
                    break;
                }
            }
        }
    }
    // TEMP (app caller): despeja 0x8000 do mm pai (371425280,
    // app_process) no snap587 + desmonta em torno de 0x8014/0x79e0
    // (retornos no nstk do exit_group). Remove with CRASHOBJ.
    #[test]
    fn temp_app_caller() {
        let caminho = "/tmp/opencode/snap587.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for va in [0x8000u32] {
            for r in &foto.regioes {
                if r.base == va && r.dono_mm == Some(371425280) {
                    let saida = format!("/tmp/opencode/appcall_{va:#x}.bin");
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("APPCALL va={va:#x} -> {saida}");
                    break;
                }
            }
        }
    }
    fn temp_quem_jni() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for va in [0xad047000u32] {
            let mut achou = false;
            for r in &foto.regioes {
                if r.base == va {
                    let saida = format!("/tmp/opencode/jni_{va:#x}_{}.bin", r.dono_mm.unwrap_or(0));
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("JNIDUMP va={va:#x} dono={:?} -> {saida}", r.dono_mm);
                    achou = true;
                }
            }
            if !achou {
                eprintln!("JNIDUMP va={va:#x}: ausente");
            }
        }
    }
    fn temp_quem_saiu() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for va in [0xafe0e000u32, 0xafe0b000] {
            for r in &foto.regioes {
                if r.base == va {
                    let saida = format!("/tmp/opencode/libc_exit_{va:#x}.bin");
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("EXITDUMP va={va:#x} dono={:?} -> {saida}", r.dono_mm);
                    break;
                }
            }
        }
    }
    fn temp_quem_falta() {
        let caminho = "/tmp/opencode/snap584.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca_qq = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for elem in [0x4001a610u32, 0x4001a6f0, 0x41074050, 0x4107f100] {
            let dono = foto.regioes.iter().find(|r| r.base <= elem && elem < r.base + r.dados.len() as u32).map(|r| (r.base, r.dono_mm));
            match busca_qq(elem, 28) {
                Some(so) => {
                    let ws: Vec<u32> = so.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                    let ap = ws[2];
                    let off = ws[4];
                    let cnt = ws[5];
                    let mut tx = String::from("?");
                    if (0x4000_0000..0x4300_0000).contains(&ap) && cnt > 0 && cnt <= 200 && off <= 200 {
                        if let Some(ca) = busca_qq(ap + 12 + off * 2, (cnt * 2).min(400)) {
                            let mut t = String::new();
                            let mut k = 0usize;
                            while k + 1 < ca.len() && (t.len() as u32) < cnt.min(120) {
                                let ch = u16::from_le_bytes([ca[k], ca[k+1]]);
                                if ch == 0 || ch > 0x7e {
                                    break;
                                }
                                t.push(ch as u8 as char);
                                k += 2;
                            }
                            if !t.is_empty() {
                                tx = t;
                            }
                        }
                    }
                    eprintln!("QUEM elem={elem:#x} {dono:?} words={ws:#x?} \"{tx}\"");
                }
                None => eprintln!("QUEM elem={elem:#x}: ausente"),
            }
        }
    }
    // LinkageError/Error/Exception/NoClassDefFoundError e soletra
    // todos os seus campos String (a mensagem nomeia a classe que
    // falta). Remove with CRASHOBJ.
    #[test]
    fn temp_msg_excecao() {
        let caminho = "/tmp/opencode/snap584.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        eprintln!("mm_atual={:#x} fatia={} pc={:#x}", foto.mm_atual, foto.fatia, foto.pc);
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        let busca_qq = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        let soletra = |elem: u32| -> Option<String> {
            let so = busca_qq(elem, 28)?;
            let ap = u32::from_le_bytes([so[8], so[9], so[10], so[11]]);
            let off = u32::from_le_bytes([so[16], so[17], so[18], so[19]]);
            let cnt = u32::from_le_bytes([so[20], so[21], so[22], so[23]]);
            if !(0x4000_0000..0x4300_0000).contains(&ap) || cnt == 0 || cnt > 300 || off > 300 {
                return None;
            }
            let ca = busca_qq(ap + 12 + off * 2, cnt * 2)?;
            let mut t = String::new();
            let mut k = 0usize;
            while k + 1 < ca.len() && (t.len() as u32) < cnt.min(120) {
                let ch = u16::from_le_bytes([ca[k], ca[k+1]]);
                if ch == 0 || ch > 0x7e {
                    break;
                }
                t.push(ch as u8 as char);
                k += 2;
            }
            if t.is_empty() { None } else { Some(t) }
        };
        let mut alvos: Vec<(String, u32)> = Vec::new();
        for r in &foto.regioes {
            if r.dono_mm != Some(372064256) || !(0x4000_0000..0x4200_0000).contains(&r.base) {
                continue;
            }
            let n = r.dados.len() / 4;
            let mut i = 0usize;
            while i + 10 < n {
                let pd = u32::from_le_bytes([r.dados[i*4+24], r.dados[i*4+25], r.dados[i*4+26], r.dados[i*4+27]]);
                if (0x4000_0000..0x4300_0000).contains(&pd) {
                    if let Some(sb) = busca(pd, 80) {
                        let fim = sb.iter().position(|&b| b == 0).unwrap_or(80);
                        let t = String::from_utf8_lossy(&sb[..fim]).into_owned();
                        if t == "Ljava/lang/LinkageError;"
                            || t == "Ljava/lang/NoClassDefFoundError;"
                            || t == "Ljava/lang/ClassNotFoundException;"
                            || t == "Ljava/lang/Exception;"
                            || t == "Ljava/lang/Error;"
                        {
                            let cl = r.base + (i * 4) as u32;
                            if !alvos.iter().any(|(_, c)| *c == cl) {
                                eprintln!("EXCCLAZ \"{t}\" obj={cl:#x}");
                                alvos.push((t, cl));
                            }
                        }
                    }
                }
                i += 1;
            }
        }
        for r in &foto.regioes {
            if r.dono_mm != Some(372064256) || !(0x4000_0000..0x4200_0000).contains(&r.base) {
                continue;
            }
            let n = r.dados.len() / 4;
            let mut i = 0usize;
            while i + 12 < n {
                let w0 = u32::from_le_bytes([r.dados[i*4], r.dados[i*4+1], r.dados[i*4+2], r.dados[i*4+3]]);
                if let Some((tn, _)) = alvos.iter().find(|(_, c)| *c == w0) {
                    let va = r.base + (i * 4) as u32;
                    let mut strs = Vec::new();
                    for k in 1..12 {
                        let wk = u32::from_le_bytes([
                            r.dados[i*4+k*4], r.dados[i*4+k*4+1],
                            r.dados[i*4+k*4+2], r.dados[i*4+k*4+3],
                        ]);
                        if (0x4000_0000..0x4200_0000).contains(&wk) {
                            if let Some(s) = soletra(wk) {
                                strs.push(format!("[+{:#x}]=\"{s}\"", k * 4));
                            }
                        }
                    }
                    eprintln!("EXCINST \"{tn}\" obj={va:#x} {}", strs.join(" "));
                }
                i += 1;
            }
        }
        eprintln!("EXCINST: fim");
    }
    fn temp_string_layout() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        let mut ach = 0;
        for r in &foto.regioes {
            if r.dono_mm != Some(372064256) || !(0x4000_0000..0x4200_0000).contains(&r.base) {
                continue;
            }
            let n = r.dados.len() / 4;
            let mut i = 0usize;
            while i + 10 < n {
                let w0 = u32::from_le_bytes([r.dados[i*4], r.dados[i*4+1], r.dados[i*4+2], r.dados[i*4+3]]);
                if w0 == 0x4000d5b0 {
                    let va = r.base + (i * 4) as u32;
                    let ob = busca(va, 28).unwrap();
                    let ws: Vec<u32> = ob.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                    // Persegue array@+16 e soletra.
                    let ap = ws[4];
                    let mut tx = String::from("?");
                    if (0x4000_0000..0x4200_0000).contains(&ap) {
                        if let Some(ca) = busca(ap + 12, 40) {
                            let mut t = String::new();
                            let mut k = 0usize;
                            while k + 1 < ca.len() && t.len() < 18 {
                                let ch = u16::from_le_bytes([ca[k], ca[k+1]]);
                                if ch == 0 || ch > 0x7e {
                                    break;
                                }
                                t.push(ch as u8 as char);
                                k += 2;
                            }
                            if !t.is_empty() {
                                tx = t;
                            }
                        }
                    }
                    eprintln!("STR obj={va:#x} words={ws:#x?} \"{tx}\"");
                    ach += 1;
                    if ach >= 8 {
                        return;
                    }
                }
                i += 1;
            }
        }
        eprintln!("STR: {ach}");
    }
    // (descritores exatos) no heap do filho para endireitar o
    // viveiro (clazz=0 causa o ArrayStoreException). Remove with
    // CRASHOBJ.
    #[test]
    fn temp_caca_clazz() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for alvo in ["Ljava/lang/String;", "[Ljava/lang/String;"] {
            let mut ach = 0;
            for r in &foto.regioes {
                if r.dono_mm != Some(372064256) || !(0x4000_0000..0x4200_0000).contains(&r.base) {
                    continue;
                }
                let n = r.dados.len() / 4;
                let mut i = 0usize;
                // ClassObject tem descritor em +24 (calibrado).
                while i + 10 < n {
                    let pd = u32::from_le_bytes([r.dados[i*4+24], r.dados[i*4+25], r.dados[i*4+26], r.dados[i*4+27]]);
                    if (0x4000_0000..0x4300_0000).contains(&pd) {
                        if let Some(sb) = busca(pd, 64) {
                            let fim = sb.iter().position(|&b| b == 0).unwrap_or(64);
                            if &sb[..fim] == alvo.as_bytes() {
                                eprintln!("CLAZZ \"{alvo}\" obj={:#x}", r.base + (i * 4) as u32);
                                ach += 1;
                                if ach >= 4 {
                                    break;
                                }
                            }
                        }
                    }
                    i += 1;
                }
                if ach >= 4 {
                    break;
                }
            }
            if ach == 0 {
                eprintln!("CLAZZ \"{alvo}\": nada");
            }
        }
    }
    // <init> cujo insns cai em 0x4150f100-0x4150f220 (o leaf da
    // cadeia INVOKE#2-4); sua clazz nomeia a excecao. Remove with
    // CRASHOBJ.
    #[test]
    fn temp_caca_leaf() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        let nome_de = |pa: u32| -> Option<String> {
            let b = busca(pa, 64)?;
            let fim = b.iter().position(|&b| b == 0).unwrap_or(64);
            let t = String::from_utf8_lossy(&b[..fim]).into_owned();
            if !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                Some(t)
            } else {
                None
            }
        };
        let mut ach = 0;
        for r in &foto.regioes {
            if r.dono_mm != Some(372064256) || !(0x4000_0000..0x4200_0000).contains(&r.base) {
                continue;
            }
            let n = r.dados.len() / 4;
            let mut i = 0usize;
            while i + 10 < n {
                let m = r.base + (i * 4) as u32;
                let insns = u32::from_le_bytes([r.dados[i*4+32], r.dados[i*4+33], r.dados[i*4+34], r.dados[i*4+35]]);
                if (0x4150f100..0x4150f220).contains(&insns) {
                    let pa_nome = u32::from_le_bytes([r.dados[i*4+16], r.dados[i*4+17], r.dados[i*4+18], r.dados[i*4+19]]);
                    let cl = u32::from_le_bytes([r.dados[i*4], r.dados[i*4+1], r.dados[i*4+2], r.dados[i*4+3]]);
                    let nm = nome_de(pa_nome).unwrap_or_else(|| "?".to_string());
                    let mut cla = "?".to_string();
                    if let Some(wcl) = busca(cl, 32) {
                        let pa_d = u32::from_le_bytes([wcl[24], wcl[25], wcl[26], wcl[27]]);
                        if let Some(t) = nome_de(pa_d) {
                            cla = t;
                        }
                    }
                    eprintln!("LEAF m={m:#x} insns={insns:#x} \"{cla}.{nm}\"");
                    ach += 1;
                    if ach >= 20 {
                        return;
                    }
                }
                i += 1;
            }
        }
        eprintln!("LEAF: {ach} candidatos");
    }
    // procurando objetos-heap com algum campo apontando para o
    // buffer de captura (0x42fda8f0..0x42fda920) E clazz cujo
    // descritor contem "Exception". Remove with CRASHOBJ.
    #[test]
    fn temp_caca_excecao() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32, dono: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(dono)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        let desc_de = |cl: u32, dono: u32| -> Option<String> {
            let cb = busca(cl, 32, dono)?;
            let pd = u32::from_le_bytes([cb[24], cb[25], cb[26], cb[27]]);
            for d2 in [dono, 371425280u32, 372064256u32] {
                if let Some(sb) = busca(pd, 96, d2) {
                    let fim = sb.iter().position(|&b| b == 0).unwrap_or(96);
                    let t = String::from_utf8_lossy(&sb[..fim]).into_owned();
                    if !t.is_empty() && t.len() < 90 {
                        return Some(t);
                    }
                }
            }
            None
        };
        for dono in [372064256u32, 371425280u32] {
            let mut ach = 0;
            for r in &foto.regioes {
                if r.dono_mm != Some(dono) || !(0x4000_0000..0x4200_0000).contains(&r.base) {
                    continue;
                }
                let n = r.dados.len() / 4;
                let mut i = 0usize;
                while i + 10 < n {
                    let w0 = u32::from_le_bytes([r.dados[i*4], r.dados[i*4+1], r.dados[i*4+2], r.dados[i*4+3]]);
                    // Candidato a objeto: clazz plausivel em +0?
                    if !(0x4000_0000..0x4200_0000).contains(&w0) {
                        i += 1;
                        continue;
                    }
                    // Algum campo em +4..+40 aponta para o buffer?
                    let mut toca = false;
                    for k in 1..10 {
                        let wk = u32::from_le_bytes([
                            r.dados[i*4+k*4], r.dados[i*4+k*4+1],
                            r.dados[i*4+k*4+2], r.dados[i*4+k*4+3],
                        ]);
                        if (0x42fda8f0..0x42fdab00).contains(&wk) {
                            toca = true;
                            break;
                        }
                    }
                    if toca {
                        let cand = r.base + (i * 4) as u32;
                        let d = desc_de(w0, dono).unwrap_or_else(|| "?".to_string());
                        eprintln!("EXC dono={dono:#x} obj={cand:#x} clazz={w0:#x} \"{d}\"");
                        // Despeja 48 B do objeto (message? cause?).
                        if let Some(ob) = busca(cand, 48, dono) {
                            eprintln!("  head={:02x?}", &ob[..48]);
                        }
                        ach += 1;
                        if ach >= 10 {
                            break;
                        }
                    }
                    i += 1;
                }
                if ach >= 10 {
                    break;
                }
            }
            if ach == 0 {
                eprintln!("EXC dono={dono:#x}: nada");
            }
        }
    }
    // (realloc 0x42fda8f0->0x42fda918; CAPBUF leu o primeiro alloc
    // com 4 pares + lixo). Le os 9 pares em 0x42fda918 e recaptura
    // quem aponta para ele. Remove with CRASHOBJ.
    #[test]
    fn temp_caparray() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32, dono: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(dono)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for dono in [372064256u32, 371425280u32] {
            if let Some(b) = busca(0x42fda918, 160, dono) {
                let ws: Vec<u32> = b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                eprintln!("CAP918 dono={dono:#x} words={ws:#x?}");
            } else {
                eprintln!("CAP918 dono={dono:#x}: ausente");
            }
        }
        // Quem aponta para a base final (stackState do Throwable?).
        for dono in [372064256u32, 371425280u32] {
            let mut ach = 0;
            for r in &foto.regioes {
                if r.dono_mm != Some(dono) || r.dados.len() < 8 {
                    continue;
                }
                let n = r.dados.len() / 4;
                let mut i = 0usize;
                while i < n {
                    let w = u32::from_le_bytes([r.dados[i*4], r.dados[i*4+1], r.dados[i*4+2], r.dados[i*4+3]]);
                    if w == 0x42fda918 {
                        eprintln!("CAPREF dono={dono:#x} {:#x}+{:#x}", r.base, i * 4);
                        ach += 1;
                        if ach >= 10 {
                            break;
                        }
                    }
                    i += 1;
                }
                if ach >= 10 {
                    break;
                }
            }
            if ach == 0 {
                eprintln!("CAPREF dono={dono:#x}: nada");
            }
        }
    }
    // 0x41aa7b5e (call site do arraycopy, INVOKE#1) e 0x41aa898c
    // (savedPc do frame af00) para ver o que zygoteInit faz com
    // argv (sget System.out? close? parse?). Remove with CRASHOBJ.
    #[test]
    fn temp_zinit_bytes() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for (base, lo, hi) in [(0x41aa7000u32, 0xa80usize, 0xc00usize), (0x41aa8000u32, 0x880usize, 0x960usize)] {
            for r in &foto.regioes {
                if r.base == base && r.dono_mm == Some(372064256) {
                    eprintln!("ZINIT {base:#x}+{lo:#x}..{hi:#x}: {:02x?}", &r.dados[lo..hi.min(r.dados.len())]);
                    break;
                }
            }
        }
    }
    // em dex 0x4150f204, INVOKE#2) para ver se ha const-string
    // (mensagem) por perto. Remove with CRASHOBJ.
    #[test]
    fn temp_newsite() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for r in &foto.regioes {
            if r.base == 0x4150f000 && r.dono_mm == Some(372064256) {
                let lo = 0x1c0usize;
                let hi = 0x260usize.min(r.dados.len());
                eprintln!("NEWSITE 0x4150f000+{lo:#x}..{hi:#x}: {:02x?}", &r.dados[lo..hi]);
                return;
            }
        }
        eprintln!("NEWSITE: sem regiao");
    }
    // sobre o snapshot (mm_para_mm + paginas do kernel) para nomear
    // o arquivo de um VA sem precisar de rerun. Remove with CRASHOBJ.
    #[test]
    // TEMP (VMA do fault): nomeia o arquivo de 0xa738 no mm pai
    // (0x16238000) no snap585b — e app_process mesmo ou outro?
    // Remove with CRASHOBJ.
    #[test]
    fn temp_vma_a738() {
        let caminho = "/tmp/opencode/snap585b.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        let le_str = |va: u32| -> Option<String> {
            for r in &foto.regioes {
                if r.base <= va && va < r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    let z = r.dados[o..].iter().position(|&b| b == 0).unwrap_or(0);
                    if z == 0 || z >= 128 {
                        return None;
                    }
                    let t = String::from_utf8_lossy(&r.dados[o..o+z]).into_owned();
                    if t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                        return Some(t);
                    }
                    return None;
                }
            }
            None
        };
        for (mm, va) in [(0x16238000u32, 0xa738u32), (0x16238000u32, 0x8000u32), (0x162d4000u32, 0xa738u32)] {
            let m = match foto.mm_para_mm.iter().find(|(a, _)| *a == mm) {
                Some((_, m)) => *m,
                None => {
                    eprintln!("VMA738 mm={mm:#x}: sem mm_struct");
                    continue;
                }
            };
            let mut vma = le(m).unwrap_or(0);
            let mut depth = 0u32;
            let mut achou = None;
            while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                depth += 1;
                let ini = le(vma + 4).unwrap_or(0xFFFF_FFFF);
                let fim = le(vma + 8).unwrap_or(0);
                if ini <= va && va < fim {
                    let arq = le(vma + 72).unwrap_or(0);
                    achou = Some((ini, fim, arq));
                    break;
                }
            }
            match achou {
                Some((ini, fim, arq)) => {
                    let mut partes = Vec::new();
                    if arq != 0 {
                        let mut dent = le(arq + 12).unwrap_or(0);
                        let mut guard = 0u32;
                        while (0xC000_0000..0xD000_0000).contains(&dent) && guard < 8 {
                            guard += 1;
                            if let (Some(np), Some(pai)) = (le(dent + 0x20), le(dent + 0x14)) {
                                if let Some(nm) = le_str(np) {
                                    partes.push(nm);
                                }
                                if pai == dent {
                                    break;
                                }
                                dent = pai;
                            } else {
                                break;
                            }
                        }
                    }
                    partes.reverse();
                    eprintln!("VMA738 mm={mm:#x} va={va:#x} [{ini:#x},{fim:#x}) /{}", partes.join("/"));
                }
                None => eprintln!("VMA738 mm={mm:#x} va={va:#x}: sem VMA", ),
            }
        }
    }
    fn temp_vma_arquivo() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let le = |va: u32| -> Option<u32> {
            for r in &foto.regioes {
                if r.base <= va && va + 4 <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(u32::from_le_bytes([r.dados[o], r.dados[o+1], r.dados[o+2], r.dados[o+3]]));
                }
            }
            None
        };
        let le_str = |va: u32| -> Option<String> {
            for r in &foto.regioes {
                if r.base <= va && va < r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    let z = r.dados[o..].iter().position(|&b| b == 0).unwrap_or(0);
                    if z == 0 || z >= 128 {
                        return None;
                    }
                    let t = String::from_utf8_lossy(&r.dados[o..o+z]).into_owned();
                    if t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                        return Some(t);
                    }
                    return None;
                }
            }
            None
        };
        for (mm, vas) in [
            (0x162d4000u32, [0x4150f204u32, 0x414e04b0, 0x414dff86, 0x41aa7b5e, 0x41bc5f76]),
        ] {
            let m = match foto.mm_para_mm.iter().find(|(a, _)| *a == mm) {
                Some((_, m)) => *m,
                None => {
                    eprintln!("VMA mm={mm:#x}: sem mm_struct");
                    continue;
                }
            };
            eprintln!("VMA mm={mm:#x} mm_struct={m:#x}");
            for va in vas {
                // Walk lista VMA a partir de M+0.
                let mut vma = match le(m) {
                    Some(v) => v,
                    None => {
                        eprintln!("VMA va={va:#x}: M ilegivel");
                        continue;
                    }
                };
                let mut achou = None;
                let mut depth = 0u32;
                while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                    depth += 1;
                    let ini = le(vma + 4).unwrap_or(0xFFFF_FFFF);
                    let fim = le(vma + 8).unwrap_or(0);
                    if ini <= va && va < fim {
                        let pgoff = le(vma + 68).unwrap_or(0);
                        let arq = le(vma + 72).unwrap_or(0);
                        achou = Some((ini, fim, pgoff, arq));
                        break;
                    }
                    vma = le(vma + 12).unwrap_or(0);
                }
                match achou {
                    Some((ini, fim, pgoff, arq)) => {
                        let mut partes = Vec::new();
                        if arq != 0 {
                            let mut dent = le(arq + 12).unwrap_or(0);
                            let mut guard = 0u32;
                            while (0xC000_0000..0xD000_0000).contains(&dent) && guard < 8 {
                                guard += 1;
                                if let (Some(np), Some(pai)) = (le(dent + 0x20), le(dent + 0x14)) {
                                    if let Some(nm) = le_str(np) {
                                        partes.push(nm);
                                    }
                                    if pai == dent {
                                        break;
                                    }
                                    dent = pai;
                                } else {
                                    break;
                                }
                            }
                        }
                        partes.reverse();
                        eprintln!("VMA va={va:#x} [{ini:#x},{fim:#x}) pgoff={pgoff:#x} arq={arq:#x} /{}", partes.join("/"));
                    }
                    None => eprintln!("VMA va={va:#x}: sem VMA"),
                }
            }
        }
    }
    // (main 0x410a4218, handleSystemServerProcess 0x410a41b8,
    // zygoteInit 0x4107f540, arraycopy 0x4105c6f8, close 0x410addf8)
    // + persegue clazz ([m+0]) ate o descritor da classe, para
    // calibrar offsets e nomear CLASSE+metodo no INVOKE.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_metodo_classe() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(372064256)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for m in [0x410a4218u32, 0x410a41b8, 0x4107f540, 0x4105c6f8, 0x410addf8, 0x4104f080] {
            let mb = match busca(m, 40) {
                Some(b) => b,
                None => {
                    eprintln!("MET m={m:#x}: ausente");
                    continue;
                }
            };
            let ws: Vec<u32> = mb.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
            eprintln!("MET m={m:#x} words={ws:#x?}");
            // clazz = [m+0]; despeja 64 B e caca descritor ASCII.
            let cl = ws[0];
            if !(0x4000_0000..0x4200_0000).contains(&cl) {
                continue;
            }
            if let Some(cb) = busca(cl, 96) {
                let cws: Vec<u32> = cb.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                eprintln!("  CLAZZ {cl:#x} words={cws:#x?}");
                // Qualquer palavra apontando para ASCII com '/' ou
                // terminando em ';' pode ser o descritor.
                for (k, w) in cws.iter().enumerate() {
                    if (0x4000_0000..0x4300_0000).contains(w) {
                        if let Some(sb) = busca(*w, 72) {
                            let fim = sb.iter().position(|&b| b == 0).unwrap_or(72);
                            let t = String::from_utf8_lossy(&sb[..fim]);
                            if !t.is_empty()
                                && t.len() < 70
                                && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                            {
                                eprintln!("    [+{:#x}] -> \"{t}\"", k * 4);
                            }
                        }
                    }
                }
            }
        }
    }
    // (pos-captura do fillInStackTrace, pre-shutdown) e disseca: o
    // buffer de captura 0x42fda8f0, os 9 frames aecc-aff0 (128 B +
    // chase de Method*), quem aponta para o buffer (dono do
    // Throwable), slot v10 e palavra do WALKERFIX. Remove with
    // CRASHOBJ.
    #[test]
    fn temp_dissec583() {
        let caminho = "/tmp/opencode/snap583.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        eprintln!("mm_atual={:#x} fatia={} pc={:#x}", foto.mm_atual, foto.fatia, foto.pc);
        let busca = |va: u32, len: u32, dono: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == Some(dono)
                    && r.base <= va
                    && va + len <= r.base + r.dados.len() as u32
                {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        // Donos provaveis do filho (0x162D4000) e do pai.
        for dono in [372064256u32, 371425280u32] {
            if let Some(b) = busca(0x42fda8f0, 256, dono) {
                let ws: Vec<u32> = b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                eprintln!("CAPBUF dono={dono:#x} words={ws:#x?}");
            }
        }
        // Quem aponta para o buffer (stackState do Throwable?).
        for dono in [372064256u32, 371425280u32] {
            let mut ach = 0;
            for r in &foto.regioes {
                if r.dono_mm != Some(dono) || r.dados.len() < 8 {
                    continue;
                }
                let n = r.dados.len() / 4;
                let mut i = 0usize;
                while i < n {
                    let w = u32::from_le_bytes([r.dados[i*4], r.dados[i*4+1], r.dados[i*4+2], r.dados[i*4+3]]);
                    if (0x42fda8f0..0x42fdab00).contains(&w) {
                        eprintln!("BUFREF dono={dono:#x} {:#x}+{:#x} -> {w:#x}", r.base, i * 4);
                        ach += 1;
                        if ach >= 10 {
                            break;
                        }
                    }
                    i += 1;
                }
                if ach >= 10 {
                    break;
                }
            }
            if ach == 0 {
                eprintln!("BUFREF dono={dono:#x}: nada");
            }
        }
        // Frames + chase de Method* (nome via +16).
        for fp in [0x4104aeccu32, 0x4104aedc, 0x4104af00, 0x4104af3c, 0x4104af64, 0x4104afa0, 0x4104afcc, 0x4104afdc, 0x4104aff0] {
            for dono in [372064256u32, 371425280u32] {
                if let Some(fr) = busca(fp, 128, dono) {
                    let mut ach = String::new();
                    let mut i = 0usize;
                    while i + 4 <= 128 {
                        let cand = u32::from_le_bytes([fr[i], fr[i+1], fr[i+2], fr[i+3]]);
                        if (0x4000_0000..0x4200_0000).contains(&cand) {
                            if let Some(wm) = busca(cand, 32, dono) {
                                let pa = u32::from_le_bytes([wm[16], wm[17], wm[18], wm[19]]);
                                for dono2 in [dono, 371425280u32, 372064256u32] {
                                    if let Some(mnb) = busca(pa, 48, dono2) {
                                        let fim = mnb.iter().position(|&b| b == 0).unwrap_or(48);
                                        let t = String::from_utf8_lossy(&mnb[..fim]);
                                        if !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                                            ach.push_str(&format!(" [+{i:#x}]={cand:#x} \"{t}\";"));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        i += 4;
                    }
                    // Palavras de controle do frame (links).
                    let links: Vec<u32> = fr[..32].chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                    eprintln!("FRAME dono={dono:#x} fp={fp:#x} links={links:#x?}{ach}");
                    break;
                }
            }
        }
        // Slot v10 + palavra do walker + nosso viveiro.
        for dono in [372064256u32] {
            for (va, tag) in [(0x4104af38u32, "V10"), (0x4104af6cu32, "WFX"), (0xe4280100u32, "ARR"), (0xe4280108u32, "ARRLEN")] {
                match busca(va, 4, dono) {
                    Some(b) => eprintln!("{tag} dono={dono:#x} [{va:#x}]={:#x}", u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
                    None => eprintln!("{tag} dono={dono:#x} [{va:#x}]: ausente"),
                }
            }
        }
    }
    // chamador em dex 0x414dff86 do INVOKE#5 fillInStackTrace e o
    // 0x414e04b0 do INVOKE#4) para decodificar o Dalvik a mao.
    // Remove with CRASHOBJ.
    #[test]
    fn temp_despeja_dex_caller() {
        let caminho = "/tmp/opencode/snap582.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for (va, nome) in [(0x414df000u32, "df"), (0x414e0000u32, "e0")] {
            for r in &foto.regioes {
                if r.base == va && r.dono_mm == Some(372064256) {
                    let saida = format!("/tmp/opencode/dex414{nome}.bin");
                    std::fs::write(&saida, &r.dados).expect("grava");
                    eprintln!("DEXDUMP va={va:#x} -> {saida} len={}", r.dados.len());
                    // Hexdump da vizinhanca do pc de interesse.
                    let alvo: usize = if va == 0x414df000 { 0xf86 } else { 0x4b0 };
                    let lo = alvo.saturating_sub(64);
                    let hi = (alvo + 32).min(r.dados.len());
                    eprintln!("DEXBYTES {va:#x}+{lo:#x}..{hi:#x}: {:02x?}", &r.dados[lo..hi]);
                    break;
                }
            }
        }
    }
    // os dex pcs do wall (0x41aa7xxx walker, 0x414dff86 chamador do
    // fillInStackTrace, 0x4150f204 invokes) — sem isso, VA->arquivo
    // e desmontagem offline sao chute. Remove with CRASHOBJ.
    #[test]
    fn temp_quem_e_o_dex() {
        let caminho = "/tmp/opencode/snap582.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        for va in [0x41aa7a94u32, 0x414dff86, 0x4150f204, 0x414e04b0, 0x41aa898c, 0x41aa8b18] {
            let mut achou = false;
            for r in &foto.regioes {
                if r.base <= va && va < r.base + r.dados.len() as u32 {
                    eprintln!(
                        "DEXVA va={va:#x} regiao={:#x} dono={:?} nome={} semente={:?} len={:#x}",
                        r.base, r.dono_mm, r.nome, r.semente_pa, r.dados.len(),
                    );
                    achou = true;
                }
            }
            if !achou {
                eprintln!("DEXVA va={va:#x}: sem regiao");
            }
        }
    }
    // TEMP (shutdown-caller): despeja as paginas do libdvm.so em
    // torno de 0xad34b334 (retorno do __android_log_write que grava
    // "Shutting down VM", LOGWR#1) para desmontar e nomear quem
    // decide o shutdown. Remove with CRASHOBJ.
    #[test]
    fn temp_despeja_libdvm_shutdown() {
        let caminho = "/tmp/opencode/snap582.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let mut fora = Vec::new();
        for va in (0xad34b000u32..0xad34c000).step_by(0x1000) {
            let mut achou = false;
            for dono in [Some(372064256u32), Some(371425280u32), None] {
                let mut hit = None;
                for r in &foto.regioes {
                    if r.dono_mm == dono && r.base == va {
                        hit = Some(r.dados.clone());
                        break;
                    }
                }
                if let Some(d) = hit {
                    eprintln!("LIBDVM va={va:#x} dono={dono:?} len={}", d.len());
                    fora.extend_from_slice(&d);
                    achou = true;
                    break;
                }
            }
            if !achou {
                eprintln!("LIBDVM va={va:#x}: ausente");
                fora.extend(vec![0; 0x1000]);
            }
        }
        std::fs::write("/tmp/opencode/libdvm_34b.bin", &fora).expect("grava");
        eprintln!("LIBDVM dump {} bytes -> /tmp/opencode/libdvm_34b.bin", fora.len());
    }
    // (v10 saudavel no mm pai 0x16238000) nos dois mms + persegue
    // os elementos como String. Se for String[] com a classname,
    // vira o valor do restore. Remove with CRASHOBJ.
    #[test]
    fn temp_confere_array_419eacc0() {
        let caminho = "/tmp/opencode/snap582.bin";
        let foto = match carrega(caminho) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{caminho}: pula ({e:?})");
                return;
            }
        };
        let busca = |va: u32, dono: Option<u32>, len: u32| -> Option<Vec<u8>> {
            for r in &foto.regioes {
                if r.dono_mm == dono && r.base <= va && va + len <= r.base + r.dados.len() as u32 {
                    let o = (va - r.base) as usize;
                    return Some(r.dados[o..o + len as usize].to_vec());
                }
            }
            None
        };
        for dono in [Some(371425280u32), Some(372064256u32)] {
            eprintln!("== dono={dono:?} ==");
            let hdr = match busca(0x419eacc0, dono, 64) {
                Some(h) => h,
                None => {
                    eprintln!("ARR419EACC0 dono={dono:?}: pagina ausente");
                    continue;
                }
            };
            eprintln!("ARR419EACC0 dono={dono:?} head={:02x?}", &hdr[..32]);
            let len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
            eprintln!("ARR419EACC0 dono={dono:?} len={len}");
            if len > 16 {
                continue;
            }
            for i in 0..len {
                let eo = 12 + (i * 4) as usize;
                if eo + 4 > hdr.len() {
                    break;
                }
                let elem = u32::from_le_bytes([hdr[eo], hdr[eo+1], hdr[eo+2], hdr[eo+3]]);
                let mut nm = String::from("?");
                if let Some(so) = busca(elem, dono, 20) {
                    let ap = u32::from_le_bytes([so[16], so[17], so[18], so[19]]);
                    if let Some(ca) = busca(ap + 12, dono, 64) {
                        let mut t = String::new();
                        let mut k = 0usize;
                        while k + 1 < ca.len() && t.len() < 48 {
                            let ch = u16::from_le_bytes([ca[k], ca[k+1]]);
                            if ch == 0 || ch > 0x7e {
                                break;
                            }
                            t.push(ch as u8 as char);
                            k += 2;
                        }
                        if !t.is_empty() {
                            nm = t;
                        }
                    }
                    eprintln!(
                        "  elem[{i}]={elem:#x} strobj={:02x?} \"{nm}\"",
                        &so[..20],
                    );
                } else {
                    eprintln!("  elem[{i}]={elem:#x} ilegivel");
                }
            }
        }
    }

    fn volta(dados: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        poe_rle(&mut v, dados);
        // pula o total (u64) e lê as corridas pelo Leitor
        let mut l = Leitor::nova(&v);
        l.rle().expect("RLE tem que voltar")
    }

    #[test]
    fn rle_ida_e_volta() {
        assert_eq!(volta(&[]), Vec::<u8>::new());
        assert_eq!(volta(&[0x7f]), vec![0x7f]);
        assert_eq!(volta(&[0u8; 4096]), vec![0u8; 4096]);
        let mut misturado = vec![0u8; 300];
        for (i, b) in misturado.iter_mut().enumerate() {
            *b = (i % 7) as u8;
        }
        misturado.extend(std::iter::repeat(0xAA).take(5000));
        misturado.extend_from_slice(&[1, 2, 3, 3, 3, 4]);
        assert_eq!(volta(&misturado), misturado);
        // zeros intercalados com uns (pior caso do RLE)
        let mut zebra = Vec::new();
        for i in 0..1000 {
            zebra.push((i % 2) as u8);
        }
        assert_eq!(volta(&zebra), zebra);
    }

    #[test]
    fn foto_ida_e_volta_minima() {
        let foto = Foto {
            fatia: 375000,
            pc: 0xad011191,
            nucleo: NucleoFoto {
                r: [1; 16],
                cpsr: 0x60000010,
                spsr: [2; 6],
                banco: [[3, 4]; 6],
                exclusivo: Some(0x40009000),
                instrucoes: 750_000_000,
                cp15: vec![(0x100, 0x16238000)],
                esperando: false,
                irq_pendente: true,
                timer_sujo: false,
                sondagem_irq: 7,
                desde_interp: 0,
            },
            mm_atual: 0x16238000,
            gens: vec![(0x16238000, 0)],
            vigia: Some((0x400090b8, 4)),
            regioes: vec![RegiaoFoto {
                nome: "teste".to_string(),
                base: 0x40009000,
                dados: vec![0u8; 4096],
                gravavel: true,
                executavel: true,
                dono_mm: Some(0x16238000),
                geracao: 0,
                semente_pa: None,
            }],
            ttbr_cache: 0x16238000,
            ttbr_task: 0xc6201000,
            mddi_pendente: false,
            audit_latch: false,
            fb_linux_mapa: (0, 0),
            mapeadas: vec![0x40009000],
            mapeadas_kern: vec![],
            mapeadas_usr: vec![(0x16238000, 0, 0x40009000)],
            mm_para_mm: vec![(0x16238000, 0xc61591c0)],
            abortadas: vec![((1, 2, 3, 4), 5)],
            tap_marca: 9,
            tap_marca_c0: 0,
            saida_marca: 10,
            tap_canais: vec![(3, b"oi\n".to_vec())],
            nand: vec![0xAA; 2112],
            spl_fora: true,
            contagem_gpt: 1234,
            contagem_dgt: 5678,
            ultima: Some(7),
            ultimo_alvo: 0x1000,
            planta_n: 2,
        };
        let caminho = "/tmp/opencode/snaptest.bin";
        salva(caminho, &foto).expect("salva");
        let volta = carrega(caminho).expect("carrega");
        assert_eq!(volta.fatia, foto.fatia);
        assert_eq!(volta.pc, foto.pc);
        assert_eq!(volta.nucleo.r, foto.nucleo.r);
        assert_eq!(volta.regioes.len(), 1);
        assert_eq!(volta.regioes[0].dados, foto.regioes[0].dados);
        assert_eq!(volta.nand, foto.nand);
        assert_eq!(volta.mapeadas_usr, foto.mapeadas_usr);
        assert_eq!(volta.mm_para_mm, foto.mm_para_mm);
        assert!(volta.spl_fora);
        assert_eq!(volta.contagem_gpt, 1234);
        assert_eq!(volta.ultima, Some(7));
        assert_eq!(volta.planta_n, 2);
        let _ = std::fs::remove_file(caminho);
    }
}
