//! Initial MSM7201A map for the Dream fork.
//!
//! Zeebx emulates the Zeebo via BREW HLE: the game never touches silicon. The
//! Dream uses the same SoC (MSM7201A: app ARM1136EJ-S + modem ARM9), but the
//! target here is the opposite — the SPL (`tests/spl/.../spl.bin`, 512 KiB) is
//! bare metal and programs real silicon. Nothing under `brew/*` is reusable;
//! what transfers over is the backend (`cpu`), `GuestMemory`, and the session
//! harness.
//!
//! Everything below is **blob observation + marked hypothesis**. Source: ARM
//! disassembly of the SPL from `0x0` (reset vector `b 0x40`), `FUN_00000040`
//! (CP15 init) and `FUN_00000420` (builds the page table and enables the MMU),
//! via `arm-none-eabi-objdump -b binary -m arm` and an REA session (966
//! procedures, `sha256 2fa6827e…`). No physical address has been confirmed
//! against a datasheet or against the Dream kernel's `arch/arm/mach-msm` —
//! verify before hardening any constant.
//!
//! NOTE (language): repo convention is Portuguese comments (see AGENTS.md).
//! New notes in this file are in English per the maintainer's request;
//! identifier renaming/translation is deferred.

use crate::cpu::mem::{GuestMemory, MemError};

/// Where the SPL loads: ARM vectors live at `0x0` (`0x00: ea00000e`).
pub const SPL_BASE: u32 = 0x0000_0000;
/// On-disk blob size: exactly 512 KiB.
pub const SPL_TAMANHO: usize = 0x8_0000;
/// Version baked into the header at `0x04`: `0.95.0000`.
pub const SPL_VERSAO: &str = "0.95.0000";
/// Name baked in at `0x10`: `Dream SPL EVT`.
pub const SPL_NOME: &str = "Dream SPL EVT";

/// Scratch page table that `FUN_00000420` builds.
///
/// Observed: `mov r10, #0x84000`, zeroes `0x4000` bytes from there, then writes
/// descriptors in strides (first `str r0, [r10]`, then `r10 += 0x2000`).
/// The exact descriptor format is not decoded yet — it may be a sparse L1 +
/// L2 rather than a flat 16 KiB L1. Treat as writable scratch.
pub const TABELA_PAGINAS_BASE: u32 = 0x0008_4000;
pub const TABELA_PAGINAS_TAMANHO: usize = 0x4000;

/// Where the SPL jumps after enabling the MMU: word at `0x504`.
///
/// Observed: `mcr p15,0,r1,cr1,cr0,0` with `r1 = 0x1005`, then `cpy pc, r0`
/// with `r0 = [0x504] = 0x88000800`.
pub const ENTRADA_POS_MMU: u32 = 0x8800_0800;
/// Value written to SCTLR when enabling the MMU: bit 12 + bit 2 + bit 0.
///
/// Tentative reading (ARM1136EJ-S): I-cache + D-cache (?) + MMU. Bit 2 on
/// ARMv6 is D-cache, not "protection" — confirm against the manual before use.
pub const SCTLR_POS_MMU: u32 = 0x1005;
/// `DACR := 1` and `TTBR := 0x84000` before the jump. Observed at `0x4c4/0x4c8`.
pub const DACR_INICIAL: u32 = 1;

/// Cold/warm probe at reset: `[0x418] = 0x01f6a2a8`, tests bit `0x200`.
///
/// Warm path: `ldr pc, [0x41c]` with `[0x41c] = 0x10300000`. Whatever lives at
/// `0x01f6a2a8` (IMEM? boot status? clock register?) is unknown.
pub const SONDA_RESET: u32 = 0x01f6_a2a8;
pub const SONDA_RESET_MASCARA: u32 = 0x200;
pub const ENTRADA_QUENTE: u32 = 0x1030_0000;

/// Virtual RAM base after the MMU.
///
/// Observed: the post-MMU destination (`0x88000800`) plus hundreds of literal
/// pools `ldr rX, [pc, #off]` resolving to `0x8800xxxx–0x8830xxxx`
/// (NBH partition descriptors, `HTCIMAGE` strings, `0x882Axxxx` tables).
/// If physical RAM starts elsewhere, the page table does the folding — the
/// `0x88…` alias is virtual, not physical. Do not assert without the datasheet.
pub const RAM_VIRTUAL_BASE: u32 = 0x8800_0000;
/// Initial coverage: 8 MiB reaches every observed pool (`<= 0x88300000`).
/// The Dream has much more RAM than this; grow once the SPL walks past it.
pub const RAM_VIRTUAL_TAMANHO_INICIAL: usize = 8 * 1024 * 1024;

/// One 1 MiB section mapping, decoded from the table at file offset `0xAC`.
///
/// Each entry is three words `(virt, phys, count)`, terminated by `(0, 0, 0)`
/// at `0x40C`. `FUN_00000420` walks it as: `pte_addr = 0x84000 +
/// ((virt & 0x1FF00000) >> 18)`, descriptor `= 0x40E-ish flags | (phys &
/// 0xFFF00000)`, then `+0x100000` per section. Masks `0x1FF00000` /
/// `0xFFF00000` live in pools at `0x4FC` / `0x500`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secao {
    /// Virtual base (1 MiB aligned).
    pub virt: u32,
    /// Physical base (1 MiB aligned).
    pub phys: u32,
    /// How many consecutive 1 MiB sections.
    pub secoes_1mb: u32,
}

/// Descriptor flags observed for every section (`r0` starts at `0x40E`).
///
/// Meaning of each bit (AP/domain/TEX/C/B on ARM1136EJ-S) is NOT decoded yet.
pub const FLAGS_SECAO: u32 = 0x40E;

/// Full VA -> PA map from the SPL's own table, in blob order.
///
/// Reads as: main RAM `0x80000000 x64 -> 0x10000000`, second bank `0x84000000
/// x46 -> 0x14000000`, low RAM/SPL mirror `0x88000000 x8 -> 0x00000000`,
/// probe window `0x8A000000 -> 0x01F00000` (matches `SONDA_RESET`), RAM
/// re-aliases `0x96… -> 0x88…` etc., then peripheral aliases
/// `0x90…/0x91…/0x92…/0x93… -> 0xA…/0xB…`, `0x950… -> 0xB8…`,
/// `0x953… -> 0xC0…`. Ended by `(0,0,0)` at `0x40C`, just before the
/// reset-probe words.
pub const MAPA_SECOES: &[Secao] = &[
    Secao {
        virt: 0x8000_0000,
        phys: 0x1000_0000,
        secoes_1mb: 64,
    },
    Secao {
        virt: 0x8400_0000,
        phys: 0x1400_0000,
        secoes_1mb: 46,
    },
    Secao {
        virt: 0x8800_0000,
        phys: 0x0000_0000,
        secoes_1mb: 8,
    },
    Secao {
        virt: 0x8A00_0000,
        phys: 0x01F0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9600_0000,
        phys: 0x8800_0000,
        secoes_1mb: 2,
    },
    Secao {
        virt: 0x9800_0000,
        phys: 0x8C00_0000,
        secoes_1mb: 2,
    },
    Secao {
        virt: 0x9A00_0000,
        phys: 0x9000_0000,
        secoes_1mb: 2,
    },
    Secao {
        virt: 0x9C00_0000,
        phys: 0x9400_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9D00_0000,
        phys: 0x9800_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9E00_0000,
        phys: 0x9C00_0000,
        secoes_1mb: 2,
    },
    Secao {
        virt: 0x9F00_0000,
        phys: 0x8000_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9000_0000,
        phys: 0xAC00_0000,
        secoes_1mb: 13,
    },
    Secao {
        virt: 0x90D0_0000,
        phys: 0xA800_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x90E0_0000,
        phys: 0xA0E0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x90F0_0000,
        phys: 0xA0D0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9100_0000,
        phys: 0xA0C0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9110_0000,
        phys: 0xA0A0_0000,
        secoes_1mb: 2,
    },
    Secao {
        virt: 0x9130_0000,
        phys: 0xA080_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9140_0000,
        phys: 0xA070_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9150_0000,
        phys: 0xA060_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9160_0000,
        phys: 0xA050_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9170_0000,
        phys: 0xA040_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9180_0000,
        phys: 0xA020_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9190_0000,
        phys: 0xA030_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x91A0_0000,
        phys: 0xA010_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x91B0_0000,
        phys: 0xA000_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x91C0_0000,
        phys: 0xAA70_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x91D0_0000,
        phys: 0xAA60_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x91E0_0000,
        phys: 0xAA50_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x91F0_0000,
        phys: 0xAA40_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9200_0000,
        phys: 0xAA30_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9210_0000,
        phys: 0xA810_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9220_0000,
        phys: 0xA9D0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9230_0000,
        phys: 0xA990_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9240_0000,
        phys: 0xA870_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9250_0000,
        phys: 0xAA20_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9260_0000,
        phys: 0xA9C0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9270_0000,
        phys: 0xA9B0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9280_0000,
        phys: 0xA9A0_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9290_0000,
        phys: 0xA980_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x92A0_0000,
        phys: 0xA970_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x92B0_0000,
        phys: 0xA960_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x92C0_0000,
        phys: 0xA950_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x92D0_0000,
        phys: 0xA940_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x92E0_0000,
        phys: 0xA930_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x92F0_0000,
        phys: 0xA920_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9300_0000,
        phys: 0xA910_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9310_0000,
        phys: 0xA900_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9320_0000,
        phys: 0xA860_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9330_0000,
        phys: 0xA850_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9340_0000,
        phys: 0xA840_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9350_0000,
        phys: 0xA830_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9360_0000,
        phys: 0xA820_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9370_0000,
        phys: 0xA820_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9380_0000,
        phys: 0xA820_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9390_0000,
        phys: 0xA820_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x93A0_0000,
        phys: 0xA820_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x93B0_0000,
        phys: 0xA820_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x93C0_0000,
        phys: 0xA800_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x93D0_0000,
        phys: 0xB000_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x93E0_0000,
        phys: 0xB020_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x93F0_0000,
        phys: 0xB030_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9400_0000,
        phys: 0xB040_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9410_0000,
        phys: 0xB050_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9420_0000,
        phys: 0xB060_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9430_0000,
        phys: 0xB100_0000,
        secoes_1mb: 13,
    },
    Secao {
        virt: 0x9500_0000,
        phys: 0xB800_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9510_0000,
        phys: 0xB810_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9520_0000,
        phys: 0xB820_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9530_0000,
        phys: 0xC000_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9540_0000,
        phys: 0xC010_0000,
        secoes_1mb: 1,
    },
    Secao {
        virt: 0x9550_0000,
        phys: 0xC020_0000,
        secoes_1mb: 1,
    },
];

/// Translate a virtual address to physical via `MAPA_SECOES`.
///
/// Returns `None` for unmapped VAs (translation faults, like the MMU would).
/// Only handles 1 MiB section granularity — fine for triage, not for emulation.
pub fn traduz(virt: u32) -> Option<u32> {
    for s in MAPA_SECOES {
        let len = s.secoes_1mb.saturating_mul(0x10_0000);
        if virt >= s.virt && virt < s.virt.saturating_add(len) {
            return Some(s.phys + (virt - s.virt));
        }
    }
    None
}

/// One candidate MMIO window, behavior still unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JanelaMmio {
    /// Provisional name, logs only.
    pub nome: &'static str,
    /// Address seen in a literal pool (PC-relative `ldr`).
    pub base: u32,
}

/// Windows touched by SPL literal pools.
///
/// Criterion: distinct address resolved from an `ldr Rd, [pc, #imm]` landing
/// in one of these ranges. This is NOT the MSM7201A physical map — it is the
/// suspect list to confirm (which peripheral, size, read/write, effect).
/// `0x50…`/`0x80…` appear with no `0xA…` literal at all: they are physical
/// addresses touched pre-MMU (VA == PA that early), while post-MMU drivers
/// use the `0x90…`/`0x91…` aliases from `MAPA_SECOES`.
pub const JANELAS_MMIO: &[JanelaMmio] = &[
    JanelaMmio {
        nome: "perif_500c",
        base: 0x500c_0000,
    },
    JanelaMmio {
        nome: "perif_5010",
        base: 0x5010_0000,
    },
    JanelaMmio {
        nome: "perif_50104078",
        base: 0x5010_4078,
    },
    JanelaMmio {
        nome: "perif_502c",
        base: 0x502c_0000,
    },
    JanelaMmio {
        nome: "perif_507c",
        base: 0x507c_0000,
    },
    JanelaMmio {
        nome: "perif_50a4",
        base: 0x50a4_0000,
    },
    JanelaMmio {
        nome: "ebi_8020",
        base: 0x8020_0000,
    },
    JanelaMmio {
        nome: "ebi_80204078",
        base: 0x8020_4078,
    },
    JanelaMmio {
        nome: "ebi_8028",
        base: 0x8028_0000,
    },
    JanelaMmio {
        nome: "ebi_802a",
        base: 0x802a_0000,
    },
];

/// Initial-map build error.
#[derive(Debug)]
pub enum MapaError {
    Memoria(MemError),
    SplInvalido(&'static str),
}

impl std::fmt::Display for MapaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memoria(e) => write!(f, "{e}"),
            Self::SplInvalido(porque) => write!(f, "invalid SPL: {porque}"),
        }
    }
}

impl std::error::Error for MapaError {}

impl From<MemError> for MapaError {
    fn from(e: MemError) -> Self {
        Self::Memoria(e)
    }
}

/// Check the minimal SPL header before mapping.
///
/// Checks the reset branch, the size, and both strings. Validates no HTC/RSA
/// signature — the `_nocheck` blob already implies relaxed verification, and
/// its provenance is unknown.
pub fn confere_spl(spl: &[u8]) -> Result<(), MapaError> {
    if spl.len() != SPL_TAMANHO {
        return Err(MapaError::SplInvalido("size != 512 KiB"));
    }
    if spl.len() < 0x40 || u32::from_le_bytes(spl[0..4].try_into().unwrap()) != 0xea00_000e {
        return Err(MapaError::SplInvalido("reset vector != `b 0x40`"));
    }
    let versao = &spl[0x04..0x04 + SPL_VERSAO.len()];
    if versao != SPL_VERSAO.as_bytes() {
        return Err(MapaError::SplInvalido("version != 0.95.0000"));
    }
    let nome = &spl[0x10..0x10 + SPL_NOME.len()];
    if nome != SPL_NOME.as_bytes() {
        return Err(MapaError::SplInvalido("name != Dream SPL EVT"));
    }
    Ok(())
}

/// Build the minimal map for first SPL steps.
///
/// - `spl` at `0x0`, read-only and executable (vectors + reset);
/// - table scratch at `0x84000`, writable;
/// - virtual RAM at `0x88000000`, writable, preloaded with a mirror of the
///   SPL (the page table maps `0x88000000 x8 -> 0x00000000`, so the post-MMU
///   entry `0x88000800` executes file offset `0x800`).
///
/// MMIO stays **deliberately unmapped**: each `0x50…`/`0x80…` access faults as
/// `Unmapped`, and the fault tells which peripheral the SPL touched first.
/// Once a window is understood, it gets its own region with behavior.
/// Post-MMU code should use the `0x90…`/`0x91…` aliases from `MAPA_SECOES`,
/// never the physical `0xA…` addresses directly.
pub fn monta_mapa_inicial(spl: &[u8]) -> Result<GuestMemory, MapaError> {
    confere_spl(spl)?;
    let mut mem = GuestMemory::new();
    mem.map_com_execucao("spl", SPL_BASE, spl.to_vec(), false, true)?;
    mem.map_zeroed("tabelas", TABELA_PAGINAS_BASE, TABELA_PAGINAS_TAMANHO)?;
    mem.map_zeroed("ram", RAM_VIRTUAL_BASE, RAM_VIRTUAL_TAMANHO_INICIAL)?;
    // Alias mirror: VA 0x88000000 -> PA 0x00000000 per the section table.
    mem.write(RAM_VIRTUAL_BASE, spl)
        .map_err(MapaError::Memoria)?;
    Ok(())
}

/// Whether `addr` falls in a known candidate window.
pub fn janela_de(addr: u32) -> Option<JanelaMmio> {
    // Windows are 64 KiB bases for now: size is a hypothesis, only good for
    // triaging the first fault. Adjust per confirmed peripheral.
    const TAMANHO_SUPOSTO: u32 = 0x1_0000;
    JANELAS_MMIO
        .iter()
        .copied()
        .find(|j| addr >= j.base && addr < j.base.saturating_add(TAMANHO_SUPOSTO))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn caminho_do_spl() -> Option<PathBuf> {
        // Third-party blob, never committed; the test skips without it, in the
        // same spirit as the `ZEEBX_ROM` scan.
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/spl/G1OrigBootloader_nocheck/spl.bin");
        p.is_file().then_some(p)
    }

    #[test]
    fn mapa_minimo_monta_e_vetor_de_reset_confere() {
        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mem = monta_mapa_inicial(&spl).unwrap();
        assert_eq!(mem.read_u32(0).unwrap(), 0xea00_000e);
        // Post-MMU entry lands inside mapped RAM.
        assert!(
            ENTRADA_POS_MMU >= RAM_VIRTUAL_BASE
                && ENTRADA_POS_MMU < RAM_VIRTUAL_BASE + RAM_VIRTUAL_TAMANHO_INICIAL as u32
        );
        // MMIO still unmapped: the fault is the instrument, not an error.
        for j in JANELAS_MMIO {
            assert!(
                mem.read(j.base, 4).is_err(),
                "window {} already mapped with no behavior",
                j.nome
            );
            assert_eq!(janela_de(j.base), Some(*j));
        }
    }

    #[test]
    fn confere_spl_rejeita_blob_errado() {
        assert!(confere_spl(&[0u8; 100]).is_err());
        let mut falso = vec![0u8; SPL_TAMANHO];
        assert!(confere_spl(&falso).is_err());
        falso[0..4].copy_from_slice(&0xea00_000eu32.to_le_bytes());
        assert!(confere_spl(&falso).is_err());
    }

    #[test]
    fn janelas_nao_colidem_com_ram_nem_spl() {
        for j in JANELAS_MMIO {
            assert!(j.base >= 0x5000_0000, "window outside suspect range");
            assert!(
                !(RAM_VIRTUAL_BASE..RAM_VIRTUAL_BASE + RAM_VIRTUAL_TAMANHO_INICIAL as u32)
                    .contains(&j.base),
                "window inside RAM"
            );
            assert!(
                !(SPL_BASE..SPL_BASE + SPL_TAMANHO as u32).contains(&j.base),
                "window inside SPL"
            );
        }
    }

    #[test]
    fn tabela_de_secoes_cobre_entrada_e_sonda() {
        // Post-MMU entry VA 0x88000800 -> PA 0x800 (low-RAM mirror section).
        assert_eq!(traduz(ENTRADA_POS_MMU), Some(0x800));
        // Reset probe is a pre-MMU physical address (VA == PA there), so it
        // has no entry in the post-MMU table; its 1 MiB window is reached
        // via the 0x8A000000 -> 0x01F00000 alias instead.
        assert_eq!(traduz(SONDA_RESET), None);
        assert_eq!(traduz(0x8A00_0000), Some(0x01F0_0000));
        assert_eq!(traduz(0x8000_0000), Some(0x1000_0000));
        assert_eq!(traduz(0x91B0_0000), Some(0xA000_0000));
        // Gap between mapped regions faults, like the MMU would.
        assert_eq!(traduz(0x7000_0000), None);
    }

    #[test]
    fn secoes_nao_se_sobrepoem() {
        let mut v: Vec<(u32, u32)> = MAPA_SECOES
            .iter()
            .map(|s| {
                (
                    s.virt,
                    s.virt
                        .saturating_add(s.secoes_1mb.saturating_mul(0x10_0000)),
                )
            })
            .collect();
        v.sort();
        for w in v.windows(2) {
            assert!(w[0].1 <= w[1].0, "overlapping sections {w:?}");
        }
    }

    #[test]
    fn ram_espelha_o_spl_no_alias_pos_mmu() {
        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mem = monta_mapa_inicial(&spl).unwrap();
        // Byte at post-MMU entry equals file offset 0x800 (== PA 0x800).
        let via_va = mem.read(ENTRADA_POS_MMU, 4).unwrap().to_vec();
        assert_eq!(via_va, spl[0x800..0x804]);
    }
}
