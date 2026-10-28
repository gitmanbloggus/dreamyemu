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
