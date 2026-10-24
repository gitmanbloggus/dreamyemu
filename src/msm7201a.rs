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
use crate::cpu::CpuBackend;

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

/// Read guest RAM by physical address through the kernel's lowmem
/// alias (VA = PA + 0xB0000000): the VA mirror holds the LIVE
/// contents — post-MMU guest writes land in the VA-mapped pages,
/// while the PA bank is only a seed source and goes stale (page
/// tables, slab objects, copied user pages). Maps + seeds the VA
/// page on demand if our map never touched it. Only for RAM
/// (0x10000000..0x20000000); device PAs return false (mirroring a
/// device as RAM would shadow the model — those stop the run).
fn le_ram_fisica(
    cpu: &mut crate::cpu::interpretador::Interpretador,
    pa: u32,
    buf: &mut [u8],
) -> bool {
    if !(0x1000_0000..0x2000_0000).contains(&pa) {
        return false;
    }
    let va = pa.wrapping_add(0xB000_0000);
    if cpu.read_mem(va, buf).is_ok() {
        return true;
    }
    // Not in our map yet: page it like the kernel-VA arm (seeded
    // from the PA bank, which may hold served content). Overlap
    // (region appeared underneath) falls back to a plain retry.
    let base = va & !0xFFF;
    if cpu.map_zeroed("usuario_ptw", base, 0x1000).is_ok() {
        let mut pg = vec![0u8; 0x1000];
        if cpu.read_mem(pa, &mut pg).is_ok() {
            let _ = cpu.write_mem(base, &pg);
        }
    }
    cpu.read_mem(va, buf).is_ok()
}

/// Read a page-TABLE word through the lowmem alias WITHOUT mapping
/// or seeding: table pages the guest built via fixmap are invisible
/// here, and seeding from the stale PA bank manufactures phantom
/// PTEs (proven live: phantom text/data mappings). Unmapped alias =
/// miss (the abort path installs the real entry, the mirror trap
/// copies it, the retry then hits). Only RAM PAs are readable.
fn le_ram_tabela(
    cpu: &mut crate::cpu::interpretador::Interpretador,
    pa: u32,
    buf: &mut [u8; 4],
) -> bool {
    if !(0x1000_0000..0x2000_0000).contains(&pa) {
        return false;
    }
    cpu.read_mem(pa.wrapping_add(0xB000_0000), buf).is_ok()
}

/// Walk the guest's ARMv6 short-descriptor page tables (TTBR0) to
/// resolve a user VA to the physical base of its containing 4 KiB
/// page. Returns None on any fault/reserved entry, missing TTBR0,
/// or unreadable tables (genuine stop — not a mappable page).
///
/// Used by the MemoryFault arm for user addresses: the ELF loader
/// maps /init's segments, stack and brk in the user pgd, which our
/// flat MMU never consulted — every user page faulted. Handles
/// page-table + small-page (the normal Linux user mapping),
/// section and large-page descriptors; supersections return None.
fn caminha_pt_usuario(
    cpu: &mut crate::cpu::interpretador::Interpretador,
    va: u32,
) -> Option<(u32, u32, u32)> {
    // TTBR0 = CP15 c2,c0,0 → key 0x100 (see arm_coproc key layout).
    let ttbr = cpu.le_cp15(0x100);
    // TEMP (PT-walk audit, cap 4): which step fails.
    static mut NPT: u32 = 0;
    macro_rules! miss {
        ($($a:tt)*) => {{
            unsafe {
                if NPT < 4 {
                    NPT += 1;
                    eprintln!($($a)*);
                }
            }
            return None;
        }};
    }
    let ttbr = match ttbr {
        Some(t) => t,
        None => miss!("PTWALK miss va={va:#x}: no TTBR0"),
    };
    // Table reads go through the lowmem alias (live contents —
    // the tables were built via VA writes; PA copies are stale).
    let l1pa = (ttbr & 0xFFFF_C000).wrapping_add((va >> 20) << 2);
    let mut be = [0u8; 4];
    // Table reads never map or seed (le_ram_tabela): seeded bytes
    // manufacture phantom PTEs from stale PA content. Unmapped
    // alias = miss; the abort installs the real entry and the
    // mirror trap copies it, so the retry hits.
    if !le_ram_tabela(cpu, l1pa & !3, &mut be) {
        miss!("PTWALK miss va={va:#x}: L1 unreadable ttbr={ttbr:#x}");
    }
    let l1e = u32::from_le_bytes(be);
    match l1e & 3 {
        0b01 => {
            // Page table: 256 L2 entries.
            let l2pa = (l1e & 0xFFFF_FC00).wrapping_add(((va >> 12) & 0xFF) << 2);
            if !le_ram_tabela(cpu, l2pa & !3, &mut be) {
                miss!("PTWALK miss va={va:#x}: L2 unreadable l1e={l1e:#x}");
            }
            let l2e = u32::from_le_bytes(be);
            match l2e & 3 {
                // Small page. Bit 0 doubles as XN (execute-never):
                // 0b10 executable, 0b11 XN (typical for .bss/data —
                // the mirror trap logged pte=0x160C305F for exactly
                // such a page). Both are present, mapped pages.
                e if e & 0b10 != 0 => Some((l2e & 0xFFFF_F000, l2e, l2pa & !0xFFF)),
                // Large page (64 KiB): containing 4 KiB subpage.
                0b01 => Some(((l2e & 0xFFFF_0000) | (va & 0xF000), l2e, l2pa & !0xFFF)),
                _ => miss!("PTWALK miss va={va:#x}: bad L2 l2e={l2e:#x}"),
            }
        }
        // Section (1 MiB): containing 4 KiB subpage. Bit 18 set
        // means supersection (16 MiB) — not expected in user space.
        0b10 if l1e & 0x40000 == 0 => Some(((l1e & 0xFFF0_0000) | (va & 0xFF000), l1e, 0)),
        _ => miss!("PTWALK miss va={va:#x}: bad L1 l1e={l1e:#x}"),
    }
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
    // Knock-on windows discovered live (each faulted once, then demand-
    // mapped): B-series device bases the per-device init loop walks.
    JanelaMmio {
        nome: "perif_b2f0",
        base: 0xB2F0_0000,
    },
    JanelaMmio {
        nome: "perif_b300",
        base: 0xB300_0000,
    },
    JanelaMmio {
        nome: "perif_b530",
        base: 0xB530_0000,
    },
    // `0xB2300010`: the NAND controller proper (`BLOCO_B23` from
    // `msm7201a_serial`; `str r3, [ip, #16]` at `0x8802E4A4`). Unlike the
    // other B-windows this one is named hardware, not an anonymous device:
    // keep it explicit even though the demand-mapper would also cover it.
    JanelaMmio {
        nome: "nand_b23",
        base: 0xB230_0000,
    },
    // `0xB3220068`: same per-device `str r1, [r3, #104]` shape at
    // `0x8802E4B8`; first seen via the demand-mapper refusing unknown
    // ground, now a named suspect like its siblings.
    JanelaMmio {
        nome: "perif_b322",
        base: 0xB322_0000,
    },
    // `0xB3200068`: same loop, different page (`str r0, [r3, #0x68]` at
    // `0x8802E4B8` is the B320 alias of the B322 device at stride +0x20000;
    // or a sibling device — either way a named suspect, not a guess).
    JanelaMmio {
        nome: "perif_b320",
        base: 0xB320_0000,
    },
    // `0xB1D0001C`: fixed magic-fill (`str r2, [r3, #28]` at `0x88017298`,
    // base pool `0xB1D00000`, constants `0x47EF4/0x3C00/...` to offsets
    // 0/4/16/20/28/36/44/52/56/68/72/76/80/84/104/108). Post-WLAN init step;
    // peripheral identity UNKNOWN (display-ish shape, unproven).
    JanelaMmio {
        nome: "perif_b1d0",
        base: 0xB1D0_0000,
    },
    // `0xA8290000`: halfword magic-fill (`strh r3, [r4]` at `0x88017B5C`,
    // base pool `0xA8290000`, sibling pool `0xA8291000` passed to
    // `bl 0x880170C0`). Post-WLAN init step, same fill shape as the WLAN
    // and B1D0 blocks; peripheral identity UNKNOWN. 64 KiB window covers
    // both literals.
    JanelaMmio {
        nome: "perif_a829",
        base: 0xA829_0000,
    },
    // `0xA8280016`: halfword store (`strh r3, [r4, #22]` at `0x88017A04`,
    // r4 = `0xA8280000`, sibling pool `0xA8281000`). Same literal-pair
    // shape as `perif_a829` (64 KiB apart), one block down — same family,
    // identity UNKNOWN. Reached via the `0x88017650`-frame FAIL path (the
    // `[0xB1D00018]` bit never sets on stubs, r4 hits 1000): the error
    // print at `0x880179F8` runs first.
    JanelaMmio {
        nome: "perif_a828",
        base: 0xA828_0000,
    },
    // `0xA8230000`: fault on a 64 KiB boundary inside the a829-fill
    // (`0x880178xx`, which references pool `0xA8240000` at `0x880179AC`).
    // No `0xA823…` literal exists anywhere in the blob, so the address is
    // computed (base `0xA8240000` minus one 64 KiB window, or a strided
    // sibling like the B-series). Reached post-wlan with no new prints;
    // the faulting pc (0x8801514C `pop`) disagrees with the history tail
    // (still in the fill loop) — pc reporting under investigation, the
    // address stands on its own as the next unknown. 64 KiB window.
    JanelaMmio {
        nome: "perif_a823",
        base: 0xA823_0000,
    },
    // `0xA8240000`: the pool literal itself (`[0x880179AC]`, referenced
    // from the a829 fill at 0x88017878/90/A8/0x88017990): live fault at
    // `strh r3, [r2]` (`0x880173AC`, r2 = pool base) right after the
    // `0xA8230000` page auto-mapped — the bit-banger at `0x88017350`
    // programs this base directly (computed bit patterns, same shape as
    // the B1D0 fill). 64 KiB window.
    JanelaMmio {
        nome: "perif_a824",
        base: 0xA824_0000,
    },
    // `0xA8000004`: 12-byte struct copy (`memcpy` head-loop `str` at
    // `0x880156E0`, dst=0xA8000004 src=`[staging]+4` len=0xC, caller
    // `lr=0x88009A40` on the NEW-loader header-parse path — the same
    // path that programs the `0xA8081xxx` peripheral from staging).
    // Literals: 0xA8000004 x6, 0xA8000000 x4, 0xA8000010, 0xA8001010,
    // 0xA8001020 — a register block spanning 0xA8000xxx-0xA8001xxx.
    // Doubly aliased in the section table (VA `0x90D00000` AND
    // `0x93C00000` -> phys `0xA8000000`, 1 MiB each; both literals x2 —
    // post-MMU drivers use the VAs). Identity UNKNOWN. 64 KiB window.
    JanelaMmio {
        nome: "perif_a800",
        base: 0xA800_0000,
    },
    // `0xAA000004`: display init (`mov r0, #0xAA000000` at `0x8802C640`,
    // `str r1, [r0, #4]` at `0x8802C6A4` with r1=2, then `str r1, [r0]`;
    // config bytes decoded from `[r2+#0x51A]` bits 0x100/0x200 select
    // 0xAA-vs-0 stores nearby). Reached only after a VALID boot image
    // passes the `ANDROID!` check — the display path is gated behind
    // boot validation, which is why no MDP alias ever appeared in
    // `mapeadas` on the shell path. Identity UNKNOWN (MDP-adjacent:
    // RE-Tools places MDP at 0xAA200000; this 0xAA000000 block with
    // +0/+4-written 2s reads like clock/power enable). 64 KiB window;
    // the fault trail from here names the register sequence.
    JanelaMmio {
        nome: "disp_aa00",
        base: 0xAA00_0000,
    },
    // `0xB2600038`: byte-read-shaped fault (the `ldrb [base+#56..59]` +
    // `bl 0x8802761C` accessor family; reported pc `0x88028F68` is a stale
    // `bl` — the fault pc lies again, trust the address). Base 0xB2600000
    // is TABLE-LISTED (device table at `0x8807CC80`), and +0x38 is exactly
    // the family's +56 byte-read offset — the accessor's r2 base comes
    // from its own pool/table ref, not a literal. Reached on the
    // VALID-boot path right after the `0xAA000000` display init starts.
    // Identity UNKNOWN (display-adjacent by path). 64 KiB window:
    // auto-map, then the guest's use (ID-compare vs config-write at
    // +0x38..0x3B) names it.
    JanelaMmio {
        nome: "disp_b260",
        base: 0xB260_0000,
    },
    // `0xAA0F3FCC`: WLAN data struct fill (`strh r3, [r2, #-51]` at
    // `0x880332E0`, base pool `0xAA0F3FFF` at `0x880332F4`). Live fault right
    // after `Initialize wlan data success` prints — the region the WLAN init
    // just configured. 64 KiB window covers the fault page `0xAA0F3000`
    // (the pre-existing `aa0f` stub page `0xAA0FC000` is untouched).
    JanelaMmio {
        nome: "wlan_aa0f",
        base: 0xAA0F_0000,
    },
    // NOTE: four `ebi_802x` suspects (`0x80200000/0x80204078/0x80280000/`
    // `0x802A0000`) used to sit here. A live run proved them RAM, not MMIO:
    // the SPL `memset`s `0x80200000` during NAND init (`0x880155E4`), and
    // `MAPA_SECOES` maps the whole `0x80000000 x64` bank to `0x10000000`.
    // They now live in the initial map as `ram_banco1`; do not re-add them
    // as windows without contradicting evidence.
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

/// Flash-driver heap (PMEM buffer) the allocator hands out.
///
/// Evidence: the SPL itself prints
/// `flash_driver_phys_buffer=0xA8780000, FLASH_DRIVER_PMEM_BUF_SIZE=0x3400`,
/// and init faults at `0xA8780020` without it. The section table maps this
/// physical range only at VA `0x92400000`, but every post-MMU driver so far
/// uses physical addresses directly (same pattern as `0xA8081000`), so the
/// flat model maps the physical address. 0x4000 covers the 0x3400 buffer.
pub const HEAP_FISICO_BASE: u32 = 0xA878_0000;
pub const HEAP_FISICO_TAMANHO: usize = 0x4000;

/// Main RAM bank 1: `0x80000000 x64 -> 0x10000000` per `MAPA_SECOES`.
///
/// Evidence: the SPL `memset`s `0x80200000` during NAND init (live fault at
/// `strb r1, [r3, r0]`, `0x880155E4`, before this window existed). This
/// proves the `ebi_802x` literal-pool suspects are RAM, not MMIO: they are
/// removed from `JANELAS_MMIO` below. Full 64 MiB per the section table.
pub const RAM_BANCO1_BASE: u32 = 0x8000_0000;
pub const RAM_BANCO1_TAMANHO: usize = 64 * 1024 * 1024;

/// Physical alias of `ram_banco1`: the section table maps VA
/// `0x80000000 x64` to PA `0x10000000` (VA = PA + 0x70000000), and the
/// SPL computes load VAs exactly that way (`dst = link_addr +
/// 0x70000000` at `0x8802DE50`) — then hands off to the kernel at the
/// PHYSICAL link address (`0x10008000`) with the MMU off (standard
/// handoff; `0x10008000` is no valid VA). The emulator cannot share
/// backing between regions, so NAND-serve writes into the VA bank are
/// mirrored here (serve hook, same bytes); general VA↔PA aliasing stays
/// OPEN. 64 MiB to match the bank.
pub const RAM_BANCO1_FIS_BASE: u32 = 0x1000_0000;
pub const RAM_BANCO1_FIS_TAMANHO: usize = 64 * 1024 * 1024;
/// Partition staging RAM: `0xA6000000 x8` (physical, used directly).///
/// Evidence: the `0x88009D30` frame computes
/// `dst = (arg & 0x0001FFFF) - 0x5A000000 + 0x740000`
/// (`bic` masks + `add r0,r4,#-0x5A000000` at `0x88009D50` + `add ... #0x740000`
/// at `0x88009D68`) and `bl 0x8801566C` word-copies into it — live fault at
/// `str r3, [ip]`, `0x88015704`, with `ip = 0xA6740000 = base + 0x740000`.
/// A second call in the same frame (`bl 0x88008F80` at `0x88009D8C`) reuses
/// the same base with size `0x20000`. Word-copy loop + sized reuse = RAM
/// semantics (same precedent as `ram_banco1`), not device registers. 8 MiB
/// covers the evidenced `+0x740000` offset; the SPL section table maps
/// nothing here, so this extends the flat model like the heap does.
pub const RAM_A600_BASE: u32 = 0xA600_0000;
pub const RAM_A600_TAMANHO: usize = 8 * 1024 * 1024;

/// Framebuffer: `0xA6C00000` x0x4B000 (320x480 RGB565).
///
/// Evidence chain (all live): the `0x88027244` loader reads NAND src
/// `0x50140000` (guest blocks 0x12A-0x12C, second image 0x50200000 =
/// blocks 0x130-0x132) into `0x80200000` via the served core loop, then
/// `memcpy`s the full 0x4B000 to `0xA6C00000` (`lr=0x88027274`, BLIT#3)
/// and calls the display init `0x8802ED68` with (fb, 3, 0, 320 + stack
/// 480) — explicit 320x480 geometry beside the fb pointer. Post-run fb
/// bytes are byte-identical to `assets/Default_US.raw565` (rendered PNG
/// shows the T-Mobile G1 splash). The SPL programs the panel (strh
/// storm to 0xA824 et al. + `0x88017350` bit-banger) but never touches
/// MDP (no 0xAA200000+/VA-alias faults on any path): pixels reach RAM,
/// the LCDC/MDP fetch is unmodeled — host rendering is future work.
/// Precedent: mapped from the original live MEMSET trap (dst/len/caller
/// `0x88002244`) before the blit role was known.
pub const RAM_A6C0_BASE: u32 = 0xA6C0_0000;
pub const RAM_A6C0_TAMANHO: usize = 0x4B000;

/// Recovery-image target: `0xA8100000` (`Load Recoveryimg header,
/// addr=0x502C0000 taget=0xA8100000` — sic, guest typo). Triple
/// evidence for RAM: the guest's own print names it a load target, the
/// word-clear loop (`str r3, [ip]` at `0x88015704`) zeroes it, and the
/// served core-loop memcpy (`0x88008360`, staging `0x882A9DEC`, 0x800
/// steps) fills it page by page. Chunked: the core-loop ENTRY
/// (`0x88008238`) shows `len=0x20000` per chunk (REC#0: src=0x502C0000,
/// dst=0xA8100000) — map the first evidenced chunk; a second chunk
/// entry (REC#1 dst=0xA8120000) extends this with its own evidence.
pub const RAM_A810_BASE: u32 = 0xA810_0000;
pub const RAM_A810_TAMANHO: usize = 0x20000;
/// NAND-model scratch: a private zeroed window for the host-side DMA
/// model (freelist node + kicked descriptor buffers). Chosen clear of the
/// section table and of the guest PMEM heap (`0xA8780000 x0x4000`): the
/// guest's own heap allocations must never collide with host-managed
/// descriptor memory. See the freelist-refill plant in the discovery run.
pub const NAND_MODELO_BASE: u32 = 0xA879_0000;
pub const NAND_MODELO_TAMANHO: usize = 0x4000;
/// Freelist node inside `NAND_MODELO_BASE` (`[node+0]` = next,
/// `[node+4]` = descriptor payload, per the `0x88024874` pop).
pub const NAND_MODELO_NO: u32 = NAND_MODELO_BASE;
/// Kicked-descriptor buffer inside `NAND_MODELO_BASE` (the `r6` the kick
/// path copies the ctl words into; ≥0x60 bytes).
pub const NAND_MODELO_DESC: u32 = NAND_MODELO_BASE + 0x100;

/// Build the minimal map for first SPL steps.
///
/// - `spl` at `0x0`, read-only and executable (vectors + reset);
/// - table scratch at `0x84000`, writable;
/// - virtual RAM at `0x88000000`, writable, preloaded with a mirror of the
///   SPL (the page table maps `0x88000000 x8 -> 0x00000000`, so the post-MMU
///   entry `0x88000800` executes file offset `0x800`).
/// - flash-driver heap at `0xA8780000`, writable (`HEAP_FISICO_*`).
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
    mem.map_zeroed("heap", HEAP_FISICO_BASE, HEAP_FISICO_TAMANHO)?;
    mem.map_zeroed("ram_banco1", RAM_BANCO1_BASE, RAM_BANCO1_TAMANHO)?;
    mem.map_zeroed("ram_banco1_fis", RAM_BANCO1_FIS_BASE, RAM_BANCO1_FIS_TAMANHO)?;
    mem.map_zeroed("ram_a600", RAM_A600_BASE, RAM_A600_TAMANHO)?;
    mem.map_zeroed("ram_a6c0", RAM_A6C0_BASE, RAM_A6C0_TAMANHO)?;
    mem.map_zeroed("ram_a810", RAM_A810_BASE, RAM_A810_TAMANHO)?;
    mem.map_zeroed("nand_modelo", NAND_MODELO_BASE, NAND_MODELO_TAMANHO)?;
    // Alias mirror: VA 0x88000000 -> PA 0x00000000 per the section table.
    mem.write(RAM_VIRTUAL_BASE, spl)
        .map_err(MapaError::Memoria)?;
    Ok(mem)
}

/// Whether `addr` falls in a known candidate window.
pub fn janela_de(addr: u32) -> Option<JanelaMmio> {
    // Windows are 64 KiB bases for now: size is a hypothesis, only good for
    // triaging the first fault. Adjust per confirmed peripheral.
    const TAMANHO_SUPOSTO: u32 = 0x1_0000;
    // Exact bases win: sub-registers like `0x50104078` sit inside the
    // `0x50100000` 64 KiB window but name a distinct suspect. Without this,
    // the window swallows its own sub-entries.
    if let Some(exata) = JANELAS_MMIO.iter().copied().find(|j| j.base == addr) {
        return Some(exata);
    }
    JANELAS_MMIO
        .iter()
        .copied()
        .find(|j| addr > j.base && addr < j.base.saturating_add(TAMANHO_SUPOSTO))
}

/// Live SPL bring-up run, shared by the discovery test and frontends.
///
/// Only compiled where the interpretador backend exists (tests, wasm32,
/// ios, or the `interpretador` feature the Dream frontends opt into):
/// the live run *is* the interpretador backend at work (Dynarmic aborts
/// on the SPL's CP15 use).
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
#[derive(Debug, PartialEq)]
pub struct VivoFim {
    pub parada: String,
    pub linhas: Vec<(u32, Vec<u8>)>,
    pub parcial: Vec<(u32, Vec<u8>)>,
    pub slots: Vec<(u32, u32)>,
    pub caminho: Vec<String>,
    pub cabeca: Vec<u8>,
    pub texto: String,
    pub limpezas: u32,
    pub leituras: Vec<(u32, u32, u32)>,
    pub objeto: u32,
    pub metodo: u32,
    pub achados: (Option<(u32, u32)>, Option<(u32, u32)>, Option<(u32, u32)>, Vec<u32>),
    /// Linux-handoff snapshot: r0-r3 at the trampoline entry
    /// (`0x88015240`) and the first 1 KiB of ATAGs at VA `0x80000100`.
    /// Empty when the run never reaches the jump (normal boot with a
    /// blank NAND still jumps — the header is fake but the trampoline
    /// runs; only early-abort paths leave these empty).
    pub regs_saida: [u32; 4],
    pub atags: Vec<u8>,
    /// Kernel serial: bytes the console UART wrote to THR
    /// (`[uart+0x0C]`) after the MMU handoff (drained per slice).
    /// Empty until the kernel's console inits.
    pub kernel_tx: Vec<u8>,
    /// Kernel printk buffer: `printk` text found in kernel RAM at
    /// the end of the run (buffered even without a console).
    /// Windows of 512 B around each hit; empty when the kernel
    /// never printed.
    pub kernel_log: Vec<u8>,
}

/// Virtual buttons: the HTC Dream samples its keys with Power held:
/// Power+Shutter = HBOOT, Power+Home = recovery, Power+Back = fastboot,
/// Power+Trackball = RADIO test. All second keys require `power`: with it
/// clear the host plants nothing (matches the hardware gate).
///
/// Provenance (all decoded from the SPL blob, `tests/spl/` untracked):
/// power is read at `[0xAA000000+0xC0]` (`0x88014B00`, waiter loop at
/// `0x88014A40`); the reset-reason register `[0xAA0FC080]` is consumed by
/// `0x88000E10` (prints `!!!dwResetReason:%d`, then maps the low byte:
/// `0x00`→ID 2, `0x02`→ID 3, anything else→ID 1, `0xEF`→RADIO test path
/// through `0x8800DBBC`); the MISC command fields (`0x882F3398` for
/// `boot-recovery`/`update-radio`/`update-hboot`, `0x882F3398-0x7F0` for
/// `EnterBootloader`/`EnterFastboot`) are consumed by `0x88011B20` and
/// stored to the mode slot `[0x882A1CD0]`, which the `0x88000F84`
/// dispatcher branches on (ID 2/6/7→wait `0x88000D74`, ID 3→flag+continue,
/// ID 4/5→updater, ID 8→`0x88000DF0`, default→continue).
///
/// Mapping status: the MISC strings/fields and the mode-slot branching
/// are PROVEN (live `MISCCK`/`MODEDISP` traces with lr). The reset-reason
/// low byte per physical key is a HYPOTHESIS (no keypad driver found in
/// the SPL static scan or RE-Tools; low bytes chosen so each combo lands
/// a distinct documented return: shutter→`0x00`/ID 2 wait,
/// home→`0x02`/ID 3 recovery, back→MISC `EnterFastboot`/ID 2 skip-wait,
/// trackball→`0xEF`/RADIO). The indexed key slots
/// (`[0xAA000000+(idx<<4)+0xD0]`, reader `0x88014B28` has no ARM `bl`
/// caller) are NOT wired: no proven consumer on this path.
///
/// Pure data (no backend dependency): available everywhere, so any
/// frontend can hold a [`Botoes`]. Only the live run that *consumes* it
/// ([`executa_spl_vivo_com_botoes`]) is `interpretador`-gated.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Botoes {
    /// Power key held.
    pub power: bool,
    /// Shutter (camera) key: HBOOT.
    pub shutter: bool,
    /// Home key: recovery.
    pub home: bool,
    /// Back key: fastboot.
    pub back: bool,
    /// Trackball: RADIO test.
    pub trackball: bool,
}

impl Botoes {
    /// MISC command the latched combo requests, if any: (field address,
    /// bytes). Priority when several second keys latch: shutter, home,
    /// back. Trackball has no MISC string (reset-reason path only).
    /// Returned bytes are the exact NUL-padded strings the SPL memcmps
    /// against (lengths 14/13/16 — the trap matches on length too).
    pub fn misc_cmd(&self) -> Option<(u32, &'static [u8])> {
        if !self.power {
            return None;
        }
        if self.shutter {
            Some((0x882F_2BA8, b"EnterBootloader\0"))
        } else if self.home {
            Some((0x882F_3398, b"boot-recovery\0"))
        } else if self.back {
            Some((0x882F_2BA8, b"EnterFastboot\0"))
        } else {
            None
        }
    }

    /// Reset-reason value (`[0xAA0FC080]`) the latched combo requests, if
    /// any. HYPOTHESIS (see struct docs): magic `0x77665500` ORed with
    /// the per-key low byte. Priority: shutter, home, back, trackball.
    pub fn reset_reason(&self) -> Option<u32> {
        if !self.power {
            return None;
        }
        if self.shutter {
            Some(0x7766_5500)
        } else if self.home {
            Some(0x7766_5502)
        } else if self.back {
            Some(0x7766_5500)
        } else if self.trackball {
            Some(0x7766_55EF)
        } else {
            None
        }
    }
}

/// TEMP/RX work (host -> guest serial RX injection): keystroke queue
/// plus the in-flight byte for the console UART.
///
/// The parked `Cmd>` shell (`0x88004BEC` -> line input `0x88004AAC` ->
/// `getc` `0x88003FA0`) polls RX-ready = `[0xB2800008]` bit 0 and reads
/// the byte from `[0xB280000C]` low byte (static decode of `0x88003FA0`;
/// live-proven: planting ready+byte echoes the char). Real silicon clears
/// the ready bit when the data register is read; the zeroed stub never
/// does, so a consume trap (armed once at setup, `0x88004034`) clears it
/// synchronously — otherwise the post-read re-check in `getc` sees a
/// stuck-ready bit and rings the same byte until the ring fills
/// (live-observed as an `h` flood: hundreds of echoes per plant). The
/// per-slice Budget arm plants the next queued byte only while no byte is
/// in flight and the ready bit is clear, so an idle run (empty queue)
/// behaves exactly as before.
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
static RX_FILA: std::sync::LazyLock<
    std::sync::Mutex<(std::collections::VecDeque<u8>, Option<u8>)>,
> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new((std::collections::VecDeque::new(), None))
});

/// Queue one host keystroke byte for the guest `Cmd>` shell (printable
/// `0x20..=0x7E`, `0x08` backspace, `0x0D` enter; anything else ignored).
/// Frontends call this on host keypress (SDL text input); the harness
/// plants queued bytes in order, one per guest `getc`. Runs with an empty
/// queue behave exactly as before (no plant, consume trap never acts).
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
pub fn rx_enfileira(byte: u8) {
    if !(0x20..=0x7E).contains(&byte) && byte != 0x08 && byte != 0x0D {
        return;
    }
    if let Ok(mut estado) = RX_FILA.lock() {
        // Cap: a stuck guest must not grow the queue without bound.
        if estado.0.len() < 64 {
            estado.0.push_back(byte);
        }
    }
}

/// Serve one SD sector range from the card image, then skip the SDCC
/// transfer (`r15 = lr`, nonzero `r0` = success: the callers `cmp r0,#0`
/// + `beq fail`). Out-of-range requests are left alone so the guest
/// runs into stub faults instead (new information, same as NAND).
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
fn serve_setor_sd(
    mem: &mut GuestMemory,
    regs: &mut [u32; 16],
    img: &[u8],
    dst: u32,
    lba: usize,
    count: usize,
) {
    let fim = lba
        .checked_mul(512)
        .and_then(|ini| ini.checked_add(count.checked_mul(512).unwrap_or(usize::MAX)));
    if let Some(fim) = fim {
        if count > 0 && count <= 256 && fim <= img.len() {
            let ini = lba * 512;
            if mem.write(dst, &img[ini..fim]).is_ok() {
                regs[0] = 1;
                regs[15] = regs[14];
            }
        }
    }
}

/// Halt traceback: what instruction stopped the run, decoded in place,
/// plus the full register file. Printed once per terminal stop,
/// Budget included: stall runs end on Budget with no fault, and the
/// parked pc + stack + pc history is exactly what names the stall
/// (this replaces the PCSAMP/SCHSTK TEMP probes).
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
fn imprime_trace(
    cpu: &crate::cpu::interpretador::Interpretador,
    pc_falta: u32,
    addr_falta: Option<u32>,
) {
    use crate::cpu::desarma::desarma;
    use crate::cpu::CpuBackend;
    if let Some(a) = addr_falta {
        eprintln!("TRACE stop pc={pc_falta:#x} addr={a:#x}");
    } else {
        eprintln!("TRACE stop pc={pc_falta:#x}");
    }
    // Disassembly window: 8 instructions back, the faulting one marked,
    // 8 forward. Unmapped words print as .word via desarma's fallback
    // only when readable; unreadable slots are marked.
    let mut alvo = pc_falta.wrapping_sub(32);
    for _ in 0..17 {
        let mut w = [0u8; 4];
        let linha = if cpu.read_mem(alvo, &mut w).is_ok() {
            let ins = u32::from_le_bytes(w);
            let seta = if alvo == pc_falta { "=>" } else { "  " };
            format!("{seta} {alvo:#010x}: {}", desarma(alvo, ins))
        } else {
            format!("   {alvo:#010x}: <unmapped>")
        };
        eprintln!("TRACE {linha}");
        alvo = alvo.wrapping_add(4);
    }
    // Full register file + CPSR decode + banked SP/LR per mode.
    let (r, cpsr, spsr, banco) = cpu.estado_completo();
    let modo = match cpsr & 0x1F {
        0x10 => "USR",
        0x11 => "FIQ",
        0x12 => "IRQ",
        0x13 => "SVC",
        0x17 => "ABT",
        0x1B => "UND",
        0x1F => "SYS",
        _ => "???",
    };
    let flags = format!(
        "{}{}{}{}",
        if cpsr & 0x20 != 0 { "T" } else { "t" },
        if cpsr & 0x40 != 0 { "F" } else { "f" },
        if cpsr & 0x80 != 0 { "I" } else { "i" },
        if cpsr & 0x100 != 0 { "A" } else { "a" },
    );
    eprintln!(
        "TRACE r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x}",
        r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]
    );
    eprintln!(
        "TRACE r8={:#x} r9={:#x} r10={:#x} r11={:#x} r12={:#x} sp={:#x} lr={:#x} pc={:#x}",
        r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]
    );
    eprintln!("TRACE cpsr={cpsr:#x} ({modo} {flags}) spsr_cur={:#x}", {
        let i = match cpsr & 0x1F {
            0x11 => 1,
            0x12 => 2,
            0x13 => 3,
            0x17 => 4,
            0x1B => 5,
            _ => 0,
        };
        spsr[i]
    });
    eprintln!(
        "TRACE banked sp/lr: fiq={:#x}/{:#x} irq={:#x}/{:#x} svc={:#x}/{:#x} abt={:#x}/{:#x} und={:#x}/{:#x}",
        banco[1][0],
        banco[1][1],
        banco[2][0],
        banco[2][1],
        banco[3][0],
        banco[3][1],
        banco[4][0],
        banco[4][1],
        banco[5][0],
        banco[5][1]
    );
    // Raw stack (16 words at sp): return addresses survive here even
    // when the frame chain is not worth unwinding.
    let mut pilha = [0u32; 16];
    for (i, s) in pilha.iter_mut().enumerate() {
        let mut w = [0u8; 4];
        *s = if cpu
            .read_mem(r[13].wrapping_add((i as u32) * 4), &mut w)
            .is_ok()
        {
            u32::from_le_bytes(w)
        } else {
            0xDEAD_u32
        };
    }
    eprintln!("TRACE stack@{:#x}={:#x?}", r[13], pilha);
    // Path tail: last executed PCs (the ring already exists for cauda).
    // TEMP widened to 200 for the 1.65s wall: distinguishes a tight
    // loop (repeating pcs = disassemble the exit condition) from a
    // long linear walk (slow progress = run longer).
    let hist = cpu.historico();
    let n = hist.len().min(200);
    eprintln!("TRACE last {} pcs:", n);
    for pc in hist.iter().skip(hist.len().saturating_sub(n)) {
        eprintln!("TRACE   {pc:#x}");
    }
}

/// Live SPL run, shared by the discovery test and frontends.
///
/// Only compiled where the interpretador backend exists (see
/// [`crate::cpu::interpretador`]).
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
pub fn executa_spl_vivo<F>(
    spl: &[u8],
    nand_img: &[u8],
    max_fatias: u32,
    instrs_por_fatia: u64,
    a_cada_fatia: F,
) -> VivoFim
where
    F: FnMut(u32, u32, &mut crate::cpu::interpretador::Interpretador, &[u8]) -> bool,
{
    let botoes = std::rc::Rc::new(std::cell::RefCell::new(Botoes::default()));
    let nand = std::rc::Rc::new(std::cell::RefCell::new(nand_img.to_vec()));
    executa_spl_vivo_com_botoes(spl, nand, None, max_fatias, instrs_por_fatia, botoes, a_cada_fatia)
}

/// Live SPL run with virtual buttons (same harness as
/// [`executa_spl_vivo`], plus the shared [`Botoes`] state the host
/// mutates — e.g. the SDL frontend's clickable keys).
///
/// `nand` is shared (not copied): HBOOT flashing writes through into it,
/// so rebooting with the same buffer boots the flashed content. `sd` is
/// the raw SD-card image (or `None` = no card); sectors are served from
/// it at the `0x8800D644` read point.
///
/// The MISC plant is applied synchronously in a `memcmp` (`0x88015B80`)
/// trap, not per slice: the guest refills the MISC fields from NAND
/// mid-slice and a per-slice plant always loses that race (proven by the
/// retired `MISCCMP` witness: it saw `0xAA` refill bytes, never the
/// plant). The trap fires before the compare executes, so overwriting
/// the field buffer there wins deterministically. Power and
/// reset-reason are plain registers (no guest refill), planted per
/// slice in the Budget arm.
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
pub fn executa_spl_vivo_com_botoes<F>(
    spl: &[u8],
    nand: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
    sd: Option<std::rc::Rc<Vec<u8>>>,
    max_fatias: u32,
    instrs_por_fatia: u64,
    botoes: std::rc::Rc<std::cell::RefCell<Botoes>>,
    mut a_cada_fatia: F,
) -> VivoFim
where
    F: FnMut(u32, u32, &mut crate::cpu::interpretador::Interpretador, &[u8]) -> bool,
{
use crate::cpu::interpretador::Interpretador;
use crate::cpu::{CpuBackend, StopReason};
use crate::msm7201a_serial::PUTC_ADDR_POS_MMU;

/// Lowest pending, enabled VIC IRQ number (LEVEL, no latch), or
/// `None`. GPT tick (IRQ 7): COUNT >= MATCH, enabled (ENSET bit 7,
/// the kernel-owned word at +0x30), unprogrammed MATCH
/// (`0xFFFFFFFF`) excluded, and the clockevent handler registered
/// (`[0xC02A43EC] != 0`, avoids a null tail-call before setup).
/// DGT (IRQ 8): same shape at +0x10/ENSET bit 8.
fn vic_nivel(mem: &GuestMemory) -> Option<u32> {
    let le = |a: u32, padrao: u32| {
        mem.read(a, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(padrao)
    };
    let gate = le(0xC02A_43EC, 0) != 0;
    let en = le(0xE000_0030, 0);
    if gate
        && en & 0x80 != 0
        && le(0xE000_1000, u32::MAX) != u32::MAX
        && le(0xE000_1004, 0) >= le(0xE000_1000, u32::MAX)
    {
        return Some(7);
    }
    if gate
        && en & 0x100 != 0
        && le(0xE000_1010, u32::MAX) != u32::MAX
        && le(0xE000_1014, 0) >= le(0xE000_1010, u32::MAX)
    {
        return Some(8);
    }
    None
}

/// Delivery gate over [`vic_nivel`]: true only for a genuinely new
/// edge. `livre` must be true only when the caller will actually
/// deliver (I==0 at the check): the MATCH one-shot advances ONLY on
/// delivering evaluations. Advancing it on a masked observation
/// consumes the edge without delivery — the 1.65s wall (live:
/// ULTIMO tracked every new MATCH while nent stayed frozen,
/// because masked WFI-block/64-poll evaluations ate each edge
/// before an unmasked check could serve it). Level tracking
/// (ULTIMA, incl. the None reset) still follows every observation.
/// One-shot per MATCH value on top: a frozen MATCH (guest never
/// reprograms after the first tick) can never refire, no matter how
/// long COUNT stays past it — this is the nested-tick BUG killer
/// (TICKH#2 186 slices after #1 with identical MATCH, I=0,
/// BUG_ON). A genuine reprogram (new MATCH value) always re-arms,
/// even if the level never dropped in between.
fn deve_entregar(mem: &GuestMemory, livre: bool) -> bool {
    static mut ULTIMA: Option<u32> = None;
    static mut ULTIMO_ALVO: u32 = 0;
    let nivel = vic_nivel(mem);
    let alvo_atual = match nivel {
        Some(7) => mem
            .read(0xE000_1000, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(u32::MAX),
        Some(8) => mem
            .read(0xE000_1010, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(u32::MAX),
        _ => u32::MAX,
    };
    unsafe {
        // TEMP (latch audit, armed by the harness at f >= 90000,
        // cap 15): nent freezes past f≈100k while unmasks continue —
        // log exactly why the gate stays shut (level, latch state,
        // MATCH, result).
        static mut NLA: u32 = 0;
        let res = match (nivel, ULTIMA) {
            (Some(n), u) if u != Some(n) || alvo_atual != ULTIMO_ALVO => {
                ULTIMA = Some(n);
                // MATCH one-shot advances ONLY on delivering
                // evaluations (livre): a masked observation must
                // never consume the edge.
                if livre {
                    ULTIMO_ALVO = alvo_atual;
                }
                true
            }
            (None, _) => {
                ULTIMA = None;
                false
            }
            _ => false,
        };
        if AUDIT_LATCH && NLA < 15 {
            NLA += 1;
            let n = NLA;
            eprintln!("LATCH#{n} f={} nivel={nivel:?} alvo={alvo_atual:#x} res={res}", unsafe { FATIA_ATUAL });
        }
        // Paradox trap: level HIGH but gate shut. Should be
        // impossible (a fresh MATCH always differs from the last
        // delivered one) — firing means the latch compares stale
        // state. Cap 10, same gate.
        static mut NPAR: u32 = 0;
        if AUDIT_LATCH && unsafe { FATIA_ATUAL } >= 100000 && matches!(nivel, Some(_)) && !res && NPAR < 200 {
            NPAR += 1;
            let n = NPAR;
            let (u_copia, alv_copia) = unsafe { (ULTIMA, ULTIMO_ALVO) };
            eprintln!("PARADOX#{n} f={} nivel={nivel:?} alvo={alvo_atual:#x} ultima={u_copia:?} ultimo={alv_copia:#x}", unsafe { FATIA_ATUAL });
        }
        res
    }
}

/// Armed by the per-slice harness at f >= 90000: start the latch
/// audit above. (A plain bool; the harness owns the slice clock.)
pub static mut AUDIT_LATCH: bool = false;

/// TTBR0 + owning task cached by the user-fault arm (which has cpu)
/// for the PTE-mirror trap (which only gets mem): update_mmu_cache
/// always runs in the faulting task's context, so a task mismatch
/// means an interleaved switch — skip rather than mirror into the
/// wrong table. Refreshed on every user walk-miss.
pub static mut TTBR_CACHE: u32 = 0;
pub static mut TTBR_TASK: u32 = 0;

    let mut mem = monta_mapa_inicial(&spl).unwrap();
    mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
    mem.map_zeroed("perif_b540_stub", 0xB540_0000, 0x1000).unwrap();
    mem.map_zeroed("perif_aa0f_stub", 0xAA0F_C000, 0x1000).unwrap();
    mem.map_zeroed("perif_a808_stub", 0xA808_1000, 0x1000).unwrap();
    mem.map_zeroed("perif_bd00_stub", 0xBD00_0000, 0x1000).unwrap();
    mem.map_zeroed("perif_b2a0_stub", 0xB2A0_0C00, 0x1000).unwrap();
    // Display/power block base page (`0xAA000000`: init writes +0/+4,
    // power-key check reads +0xC0): pre-map page 0 so host plants land
    // before the guest's early reads (a per-slice plant to an unmapped
    // page fails silently and the check passes before any fault maps
    // it — observed once as a no-op power-key plant). The window
    // `disp_aa00` still demand-maps the rest of the 64 KiB.
    mem.map_zeroed("disp_aa00_stub", 0xAA00_0000, 0x1000).unwrap();
    // Kernel console UARTs (trout static IO map: UART1/2/3 at
    // `0xE0003000/4000/5000`; `0xE0000000` = VIC, `0xE0001000` =
    // GPT/DGT timer block). `msm_putc` polls TX-ready = `[base+8]`
    // bit 2, then writes the byte to THR `[base+12]`; the ATAG
    // cmdline carries no `console=`, so plant/drain all three.
    // EXTENDED 0x6000->0x10000 (2026-10-22): kernel driver init
    // loop writes index 0..5 to [0xE0007880] (str at 0xC000E860);
    // +0x7000 page identity pending (e000_ids.md) — zeroed RAM
    // stub (writes persist, reads last-write) is the benign default.
    mem.map_zeroed("uart_nucleo_stub", 0xE000_0000, 0x1_0000).unwrap();
    // `0xE0100014` poll (kernel driver wait loop at 0xC002D690:
    // `ldr r3,[r6]; cmp r3,#1; beq done`, 10M-iteration timeout,
    // callback [sl] skipped on zeroed stub). Identity pending
    // (roadmap agents); completion-bit plant below exits it fast.
    mem.map_zeroed("kernel_e010_stub", 0xE010_0000, 0x1000).unwrap();
    // CPLD (`0xE8100000`, trout per roadmap §d.3: `strb` x4 +0/2/4/6
    // in `trout_init_cpldshadow`, write-only, no readback).
    // Pre-mapped: stub-safe per both static analyses.
    mem.map_zeroed("kernel_e810_stub", 0xE810_0000, 0x1000).unwrap();
    // MDP display controller (`0xE0010000` + `0xE0020000`, trout static
    // IO map; first hit 2026-10-23: `mdp_init` str at 0xC011C110 to
    // [0xE0010060], then [r0=0xE0020000+0x1F8]). Zeroed 64 KiB stubs
    // (RAM semantics). Display output is future work (see §MDP note);
    // if mdp_init spins on a status bit, plant it then.
    mem.map_zeroed("mdp_a_stub", 0xE001_0000, 0x1_0000).unwrap();
    mem.map_zeroed("mdp_b_stub", 0xE002_0000, 0x1_0000).unwrap();
    // MDP register table block (`0xE0050000`, 562 (addr,val) pairs in
    // `mdp_init`'s table loop at 0xC011C128; first hit 2026-10-23:
    // str to [0xE0050400]). Zeroed 64 KiB stub, same terms as above.
    mem.map_zeroed("mdp_c_stub", 0xE005_0000, 0x1_0000).unwrap();
    // Sibling MDP/MDDI window (`0xE0060000`; first hit 2026-10-23:
    // str to [0xE006FFFC] from `mdp_init` at 0xC011C198). Same stub.
    mem.map_zeroed("mdp_d_stub", 0xE006_0000, 0x1_0000).unwrap();
    // MDDI register block (`0xFFC00000`; first hit 2026-10-24:
    // `mddi_init` -> `mddi_init_registers` memset 0x140 bytes at
    // [0xFFC00000]). Zeroed 64 KiB stub, same terms.
    mem.map_zeroed("mddi_stub", 0xFFC0_0000, 0x1_0000).unwrap();
    // CAMIF PAD registers (`0xE0200000`; first hit 2026-10-24:
    // `mt9t013_camif_pad_reg_reset` str to [0xE0200000]). Zeroed
    // 64 KiB stub, same terms.
    mem.map_zeroed("camif_stub", 0xE020_0000, 0x1_0000).unwrap();
    // SDCC (SD controller) block (`0xE1000000`; first hit 2026-10-24:
    // `msmsdcc_probe` str to [0xE100003C]). Zeroed 64 KiB stub.
    mem.map_zeroed("msmsdcc_stub", 0xE100_0000, 0x1_0000).unwrap();
    // ARM exception vectors (`0xFFFF0000`, high vectors): the kernel
    // reads/copies its stubs there during trap setup (first seen as
    // a read with r0=0xFFFF0000). Zeroed page; the guest fills it.
    mem.map_zeroed("vetores_stub", 0xFFFF_0000, 0x1000).unwrap();
    // `0xC4800000` device window (kernel static IO map; probes touch
    // +0xC of successive 4K blocks: 0xC4800000, 0xC4810000, ...).
    // Identity UNKNOWN (no 0xC4800000 literal in vmlinux; MDP display
    // suspected by elimination — hypothesis, not fact). Zeroed 64 KiB
    // stub for now; behavior comes from the poll loops it parks in.
    mem.map_zeroed("disp_c480_stub", 0xC480_0000, 0x1_0000).unwrap();
    // HBOOT-wait device (`0xB1600000`, written at `0x8800D090`/`94` with
    // 3/0x100 by the Power+Shutter wait init at `0x8800D040`, then polled
    // in the same wait loop — reached live via the shutter button, which
    // faults here twice: first fault demand-maps the alias page (the SPL
    // section table covers `0xB1000000`+13 MB), the wait loop re-reads
    // the stub zeros and faults again, which stops the run as "needs
    // behavior". Peripheral identity UNKNOWN (pool `0x8806EDFC` sits in
    // a `0xB17000xx` register table); the poll bit comes next.
    mem.map_zeroed("perif_b160_stub", 0xB160_0000, 0x1000).unwrap();
    // NAND descriptor area (`0xA0A00000`, VA alias `0x91100000` per the
    // section table): the probe writes per-device addresses here
    // (`str r3, [r9]`, r9 = `0xA0A00000 + chan*16` at 0x8801EDE8).
    // Peripheral identity UNKNOWN; RAM-like stub answers "what next?".
    mem.map_zeroed("perif_a0a0_stub", 0xA0A0_0000, 0x1000).unwrap();
    // `0xB3100000` device base (slot `[0x882F2AE8]`, filled by earlier
    // init like `0xB5400000` was): the NAND read path writes
    // `[base+32]`/`[base+36]` at `0x88016DF4/0x88016DF8`. Same deal.
    mem.map_zeroed("perif_b310_stub", 0xB310_0000, 0x1000).unwrap();
    // `0xB2F00800` (same instruction, next device: the slot is a
    // "current device" pointer updated per device in a loop). B2F0 is a
    // new window (no section-table entry); same treatment for now.
    mem.map_zeroed("perif_b2f0_stub", 0xB2F0_0000, 0x1000).unwrap();
    // `0xB2E00000` (`ldr r2, [r1, #0xC00]` fault at `0x8801679C`; same
    // per-device loop shape, new base). B2E0 has no section-table entry.
    mem.map_zeroed("perif_b2e0_stub", 0xB2E0_0000, 0x1000).unwrap();
    // `0xB3000000` (same per-device loop, `str r0,[r2,#0x410]` at
    // `0x88016EF0`; base from slot `[pool 0x88017020]`).
    mem.map_zeroed("perif_b300_stub", 0xB300_0000, 0x1000).unwrap();
    // `0xB5300000` (`ldr ip,[r2,#36]` fault at `0x88016260`; RMW of
    // device regs `+36/+96/+116`, no poll — zeroed stub is harmless).
    // DMOV CMD_PTR_RDY: chan 4 init fails with "command FIFO not ready"
    // when `[0xB2A00C10] & 1 == 0`. Real silicon sets it when the command
    // FIFO accepts; the stub models "always ready".
    mem.write(0xB2A0_0C10, &1u32.to_le_bytes()).unwrap();
    // DMOV STATUS RDY: the same init then fails on `[0xB2A00E10] & 1`
    // ("reg 0x0, CMD_PTR_RDY 0x1"). Same "always ready" stub.
    mem.write(0xB2A0_0E10, &1u32.to_le_bytes()).unwrap();
    // NAND identity: the probe reads maker/device ID from a heap
    // buffer (`[0x882F4564]`) filled by the READ-ID DMA and matches
    // against the 15-entry whitelist at `0x8806F404` (stride 0x44,
    // maker at +0x14, device at +0x18). The stub bus has no IDs and
    // the image carries none (controller response, not flash content
    // — see `ferramentas/cria_nand.py`), so the host answers READ ID
    // per slice below by planting (EC, AA) once the heap slot is
    // allocated. That selects entry 8 (Samsung K9K2G08, 2048 blocks):
    // the only entry whose block range covers what the SPL actually
    // reads (block IDs 0x930+ — an entry-0 1024-block chip fails its
    // own range check, which is why the zero-everything hack that
    // selected entry 0 had to go). The whitelist stays at blob values.
    // Real NAND data (not just IDs) comes with the NAND model.
    // Per-channel instances at `+4N` (chan 5 fails next at `C14/E14`).
    // Pre-set RDY bit0 for channels 0..15 on both ranges; `RSLT_CONF`
    // (`Fxx`, reads 0) passed untouched, so it stays 0. If some channel
    // expects 0, the frontier will say so and this narrows.
    for n in 0..16u32 {
        let _ = mem.write(0xB2A0_0C00 + 4 * n, &1u32.to_le_bytes());
        let _ = mem.write(0xB2A0_0E00 + 4 * n, &1u32.to_le_bytes());
    }
    mem.map_zeroed("perif_b280_stub", 0xB280_0000, 0x1000).unwrap();
    // Second RAM bank (`0x84000000`, section-table phys `0x14000000`,
    // 46 x 1 MB): the HBOOT SD-flash path stages the whole NBH file at
    // `0x80200000` (`RhReadFile(handle, 0x80200000, len)`, cap
    // `0x6500000` = 101 MB) — past the 64 MB `ram_banco1`. Pre-mapped
    // zeroed so the 91 MB real image lands in RAM, not in faults.
    mem.map_zeroed("ram_banco2", 0x8400_0000, 46 * 1024 * 1024)
        .unwrap();
    // UART TX-ready: the channel-3 ring path spins at `0x880040E4` while
    // `[device+8] & 1 == 0`. Real silicon sets it when TX can accept;
    // the stub models "always ready". (`+20` stays 0: ring-enqueue mode,
    // not direct-TX.)
    mem.write(0xB280_0008, &1u32.to_le_bytes()).unwrap();
    let mut cpu = Interpretador::new().unwrap();
    cpu.reset(&mem).unwrap();
    // Ready-bit experiment: the `0x88028E40` check skips its write block
    // when `[0xAA0FC000+0x44] & 1 == 0`, and the null fault at `0x8801EC94`
    // smells like init skipped downstream of it. Forcing ready answers
    // behaviorally whether the write block fills the device slots.
    cpu.write_u32(0xAA0F_C044, 1).unwrap();
    // Two-phase run: phase 1 executes the BSS zero loop (~390k instrs at
    // `0x88000818`) plus early init; the intermission plants the DMOV
    // channel count (`[0x882F79EC+12]`, BSS-zeroed, read by the
    // `0x88023184` gate), which no stub can provide because BSS clears it
    // after reset. Phase 1 advances in slices until past the BSS loop
    // (`pc >= 0x88000828`), so the plant is never cleared by the zeroing
    // it follows. NOTE: a second zeroing loop at `0x88000C04` runs early
    // in phase 2 (found via `watch_dirty`); plants inside its range must
    // be verified post-run, not assumed.
    let mut pc = 0u32;
    for _ in 0..20 {
        match cpu.run(pc, 100_000).unwrap() {
            StopReason::Budget => {
                pc = cpu.read_reg(crate::cpu::Reg::Pc);
                if pc >= 0x8800_0828 {
                    break;
                }
                pc = if cpu.em_thumb() { pc | 1 } else { pc & !1 };
            }
            outra => {
                pc = cpu.read_reg(crate::cpu::Reg::Pc);
                let pc = if cpu.em_thumb() { pc | 1 } else { pc & !1 };
                panic!("fase 1 parou cedo: {outra:?} em {pc:#010x}");
            }
        }
    }
    cpu.write_u32(0x882F_79F8, 1).unwrap();
    // Emit-path experiment: the `0x880018D4` dispatch takes path B
    // (`mov r0, #3`, direct channel-3 byte output) when
    // `[0x882A1CD0] == 2`. BSS-zeroed like the count, planted together.
    // If output flows, the whole emit->PUTC->tap chain is proven and all
    // future fail prints become visible.
    // CONDITIONAL (not unconditional): the MISC boot-mode check stores
    // its command ID here too, and the mode dispatcher branches on it —
    // clobbering it to 2 every boot would wedge every mode to "2".
    // Only default to direct-TX when no mode was selected (slot still 0).
    if cpu.read_u32(0x882A_1CD0).unwrap_or(2) == 0 {
        cpu.write_u32(0x882A_1CD0, 2).unwrap();
    }
    // Ring data area is at the constant `0x882A24FC` itself (decoded from
    // `0x88003DD4`: `strb r1, [r2, r3]` with `r3` = pool constant, never
    // dereferenced). No plant needed or wanted here: an earlier revision
    // planted a bogus pointer *into* the area and the host drain read the
    // wrong buffer for it. Ch3's 4 KiB live at `0x882A24FC + 0x3000`.
    // Clear the stuck full flag (`+8`) for channel 3's slot.
    cpu.write_u32(0x882A_9534, 0).unwrap();
    // NOTE: no plant in the `0x88008238` dispatcher slot (`0x882F1EB4`):
    // the phase-2 memset zeroes it and no writer ever fills it on this
    // path (proven: planting a marker changes the fault target to
    // `[MARKER+20]`). The slot watch below catches any real writer.
    // TX-complete: channel 3's ring path only returns via `+20 & 1`
    // (direct-TX); with `+20 == 0` it re-enqueues forever. Real silicon
    // raises it when TX completes; the stub models "always complete".
    cpu.write_u32(0xB280_0014, 1).unwrap();
    // TEMP/RX work (see `rx_enfileira`): clear RX-ready synchronously when
    // `getc` loads the data byte (`ldr r3,[r4,#0xC]` at `0x88004034`,
    // `r4` = UART MMIO base). Acts only while a planted byte is in
    // flight, and only on the console UART — any other reader keeps stub
    // behavior. Without this the post-read re-check in `getc`
    // (`0x8800403C..44`) sees the stuck-ready bit and rings the same byte
    // until the ring fills (one plant -> hundreds of echoes, measured).
    cpu.trap_pc_mem(0x8800_4034, move |mem, regs| {
        if regs[4] != 0xB280_0000 {
            return;
        }
        if let Ok(mut estado) = RX_FILA.lock() {
            let Some(b) = estado.1.take() else {
                return;
            };
            if let Ok(v) = mem.read_u32(0xB280_0008) {
                let _ = mem.write_u32(0xB280_0008, v & !1);
            }
            eprintln!("RXCONSUME byte={b:#x}");
        }
    });
    let mut pc = cpu.read_reg(crate::cpu::Reg::Pc);
    pc = if cpu.em_thumb() { pc | 1 } else { pc & !1 };
    let tap = std::rc::Rc::new(std::cell::RefCell::new(
        crate::msm7201a_serial::SerialTap::new(),
    ));
    let grava = tap.clone();
    cpu.trap_pc(PUTC_ADDR_POS_MMU, move |canal, byte| {
        grava.borrow_mut().byte(canal, byte)
    });
    // Geometry plant for the per-page range check (see below): the
    // method fails every page while [+0x74]/[+0x78] stay zero.
    // (Retired on the entry-8 migration: the guest now fills
    // [+0x74]=0 / [+0x78]=0x800 (total blocks) from the selected
    // whitelist entry itself, and host-plants would only risk
    // clobbering a stale object. Kept as comment, not code.)
    // NOTE: the READ-ID plant lives in the per-slice Budget arm
    // below (with the transfer plants), NOT here: this spot runs
    // once before flashn_dm_init_structures allocates the slot,
    // so a one-shot plant would see buf==0 and never re-fire.
    // NAND serve (entry-8): the per-page method `+0x1C`
    // (`0x8801D228`) takes (obj, block) — r1 correlates 1:1 with the
    // tap's block IDs and NAND src addrs (block = 0x126 +
    // (src-0x500C0000)/0x20000 for the 0x50… region; verified on FIVE
    // live points: 0x500C0000→0x126, 0x50100000→0x128,
    // 0x50120000→0x129, 0x50140000→0x12A, 0x502C0000→0x136 — the old
    // physical-math comment claiming (src-0x4DC00000)/0x20000 was
    // WRONG and cost a mis-patched header). The
    // core-loop memcpy at `0x88008360` takes (dst, staging, len);
    // staging (`[0x8800845C]` = 0x882A9DEC) is a single-page buffer
    // refilled per page, so the serve tracks a page index per
    // 0x88008238 call, derived robustly from the memcpy dst itself:
    // idx = (dst - base_dst) / len (idempotent under retries,
    // no counting). Multi-block entries (the 0x4B000 splash spans
    // 0x12A/0x12B/0x12C): when the MET bloco changes mid-entry the
    // dst base resets to the current dst, so idx stays block-relative
    // (if MET fires once per entry instead, consecutive blocos make
    // the global idx land correctly anyway). Served range:
    // image[bloco*135168 + idx*2112 .. +len] (entry-8: 64 pages x
    // (2048+64)). Validate return `0x8801E688` is forced to 0 (its
    // stack status array is stub zeros). All copies bounds-checked;
    // anything out of range skips the serve (stub zeros, as before).
    // (Shared buffer: the caller keeps it across reboots so flashed
    // content persists; pass a fresh copy for a pristine boot.)
    // (bloco, base_dst, pagina0): pagina0 = entry's start page
    // within the block (0 for loads at the block start; 1 for the
    // kernel, whose NAND src = start + 0x800). Without it, the kernel was
    // served shifted by one page (header where code belongs —
    // proven live: 0x10008000 contained b'ANDROID!').
    let estado: std::rc::Rc<std::cell::RefCell<(u32, u32, u32)>> =
        std::rc::Rc::new(std::cell::RefCell::new((0, 0, 0)));
    let estado_a = estado.clone();
    let conta_a = std::rc::Rc::new(std::cell::RefCell::new(0u32));
    cpu.trap_pc_mem(0x8801_D228, move |_mem, regs| {
        estado_a.borrow_mut().0 = regs[1];
        let n = *conta_a.borrow();
        if n < 32 {
            *conta_a.borrow_mut() = n + 1;
            eprintln!("MET#{n} block={:#x}", regs[1]);
        }
    });
    let estado_e = estado.clone();
    let conta_d = std::rc::Rc::new(std::cell::RefCell::new(0u32));
    cpu.trap_pc_mem(0x8800_8238, move |_mem, regs| {
        {
            let e = estado_e.borrow();
            // u64: before the first MET the block is 0 and
            // `0 - 0x126` would underflow u32 in the debug profile (the
            // `spl_vivo_descobre_apos_b2a00c10` test runs without optimization).
            let ini_bloco = 0x500C_0000u64
                .wrapping_add((e.0 as u64).wrapping_sub(0x126).wrapping_mul(0x20000));
            let pagina0 = if (ini_bloco..ini_bloco + 0x20000).contains(&(regs[0] as u64)) {
                ((regs[0] as u64 - ini_bloco) / 2048) as u32
            } else {
                0
            };
            drop(e);
            let mut w = estado_e.borrow_mut();
            w.1 = regs[1];
            w.2 = pagina0;
        }
        let n = *conta_d.borrow();
        if n < 32 {
            *conta_d.borrow_mut() = n + 1;
            eprintln!(
                "ENT#{n} src={:#x} dst={:#x} len={:#x}",
                regs[0], regs[1], regs[2]
            );
        }
    });
    let nand_b = nand.clone();
    let estado_b = estado.clone();
    let conta_b = std::rc::Rc::new(std::cell::RefCell::new(0u32));
    let ultimo_bloco = std::rc::Rc::new(std::cell::Cell::new(0xFFFF_FFFFu32));
    let ultimo_bloco2 = ultimo_bloco.clone();
    let estado_c = estado.clone();
    // NOTE: flash *writes* do not come through here (verified live:
    // all callers share the single read lr `0x8801E87C`); they are
    // captured at the `0x88008F80` writer below. Re-add an lr log
    // here if a write path ever appears.
    cpu.trap_pc_mem(0x8800_8360, move |mem, regs| {
        let (dst, src, len) = (regs[0], regs[1], regs[2] as usize);
        // Multi-block entries: a MET bloco change mid-entry resets the
        // dst base so idx stays block-relative (see the serve comment
        // above for why both MET granularities land correctly).
        if estado_b.borrow().0 != ultimo_bloco2.get() {
            ultimo_bloco2.set(estado_b.borrow().0);
            let mut w = estado_c.borrow_mut();
            w.1 = dst;
            w.2 = 0;
        }
        let (bloco, base_dst, pagina0) = *estado_b.borrow();
        let n = *conta_b.borrow();
        if n < 8 {
            *conta_b.borrow_mut() = n + 1;
            eprintln!(
                "SRV#{n} block={bloco:#x} dst={dst:#x} src={src:#x} len={len:#x}",
            );
        }
        if nand_b.borrow().is_empty() || len == 0 || len > 2112 || dst < base_dst {
            return;
        }
        let indice = (dst - base_dst) as usize / len;
        let off = bloco as usize * 135168 + (pagina0 as usize + indice) * 2112;
        let img = nand_b.borrow();
        if off + len > img.len() {
            return;
        }
        let _ = mem.write(src, &img[off..off + len]);
        // Kernel-handoff mirror: loads into the VA bank
        // (`0x80000000 x64`) are also physical RAM at `VA -
        // 0x70000000` (section table), and the SPL jumps to the
        // physical link address with the MMU off. Mirror the same
        // served bytes there so the handoff lands in real content,
        // not zeros. Write errors (unmapped PA subrange — cannot
        // happen while the PA bank matches, but be safe) are
        // ignored: the VA serve already succeeded.
        if (RAM_BANCO1_BASE..RAM_BANCO1_BASE + RAM_BANCO1_TAMANHO as u32)
            .contains(&dst)
        {
            let _ = mem.write(
                dst.wrapping_sub(0x7000_0000),
                &img[off..off + len],

            );
        }
    });
    let conta_c = std::rc::Rc::new(std::cell::RefCell::new(0u32));
    cpu.trap_pc_mem(0x8801_E688, move |_mem, regs| {
        let n = *conta_c.borrow();
        if n < 4 {
            *conta_c.borrow_mut() = n + 1;
            eprintln!("VAL#{n} r7={:#x} ->0", regs[7]);
        }
        regs[0] = 0;
    });
    // NAND status plant (nand_status.md): the SPL read_page loop checks
    // each status word for (w&0x110)==0 AND tag ((w>>12)&7)==r4, where
    // r4 counts sb-1..0 and r2 points at the word ([r6,fp] from the
    // 0xA8780000 DMA buffer). Zeroed stubs fail every word (579 pages
    // of "error bad status" spam, then give-up -1). Plant the expected
    // tag at check time: MEM[r2] = r4<<12. Self-calibrating (any sb),
    // idempotent (it IS the success path), silent.
    cpu.trap_pc_mem(0x8801_E650, move |mem, regs| {
        let ptr = regs[2];
        let tag = regs[4] & 7;
        let _ = mem.write_u32(ptr, tag << 12);
    });
    // (E) new-loader entry `0x880099E0` (src, len, dst): catches loads
    // that bypass the core loop (e.g. the post-wlan jump target).
    // Cap 4.
    let conta_e = std::rc::Rc::new(std::cell::RefCell::new(0u32));
    cpu.trap_pc_mem(0x8800_99E0, move |_mem, regs| {
        let n = *conta_e.borrow();
        if n < 4 {
            *conta_e.borrow_mut() = n + 1;
            eprintln!(
                "NEW#{n} src={:#x} len={:#x} dst={:#x}",
                regs[0], regs[1], regs[2]
            );
        }
    });
    // Virtual-button MISC plant (race-free): the guest refills the MISC
    // fields from NAND during the slice, so a per-slice plant never
    // survives to the `0x88011B20` check. This trap runs before the
    // `memcmp` executes: when a latched combo wants the exact (field,
    // length) being compared, overwrite the field buffer synchronously.
    // Filtered to the MISC window + MISC lengths (13/14/16) so the
    // ANDROID! header check (different address/length) never matches.
    let botoes_misc = botoes.clone();
    cpu.trap_pc_mem(0x8801_5B80, move |mem, regs| {
        let len = regs[2] as usize;
        if len != 13 && len != 14 && len != 16 {
            return;
        }
        let campo = regs[0];
        if !(0x882F_2000..0x882F_4000).contains(&campo) {
            return;
        }
        if let Some((alvo, cmd)) = botoes_misc.borrow().misc_cmd() {
            if campo == alvo && len == cmd.len() {
                let _ = mem.write(campo, cmd);
            }
        }
    });
    // Delay fast-forward (SD/FAT path only): the calibrated delay
    // (`0x88004324`: umull count + `rsb/cmp/bhi` on the frozen
    // `[0xB5400020]` counter) never exits on stubs — the Budget-arm
    // elision only skips the tail of one delay per slice, so a 91 MB
    // file read (hundreds of delay calls, ~300 slices each) would take
    // ~10M slices. The repeater `0x88004364` loops the 1000-unit delay
    // r0 times; skip the whole repeater when ITS caller is SD/SDCC
    // (`0x8800Bxxx-0x8800Dxxx`), FAT (`0x88018xxx-0x8801Cxxx`) or the
    // SDFAT updater (`0x88019xxx-0x8801Axxx`): those use it for timing,
    // not measurement. Other callers keep the tail elision (calibration
    // at boot measures this timer — never skip it globally).
    cpu.trap_pc_mem(0x8800_4364, move |_mem, regs| {
        let lr = regs[14];
        if (0x8800_B000..0x8800_E000).contains(&lr)
            || (0x8801_8000..0x8801_D000).contains(&lr)
            || (0x8801_9000..0x8801_B000).contains(&lr)
        {
            regs[15] = lr;
        }
    });
    cpu.trap_pc_mem(0x8800_4324, move |_mem, regs| {
        let lr = regs[14];
        if (0x8800_B000..0x8800_E000).contains(&lr)
            || (0x8801_8000..0x8801_D000).contains(&lr)
            || (0x8801_9000..0x8801_B000).contains(&lr)
        {
            regs[0] = regs[0].wrapping_add(0x100_0000);
            regs[15] = lr;
        }
    });
    // TEMP (serial total): log every puts argument (the mode-gated
    // prints — Checking..., CID, FAIL — never reach the tap when the
    // mode slot != 2). Cap 300.
    let conta_puts = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let conta_putsb = conta_puts.clone();
    cpu.trap_pc_mem(0x8800_1968, move |mem, regs| {
        if conta_putsb.get() < 40 {
            let mut s = vec![0u8; 64];
            if mem.read(regs[0], 64).map(|b| s.copy_from_slice(b)).is_ok() {
                let fim = s.iter().position(|&c| c == 0).unwrap_or(64);
                eprintln!(
                    "PUTS#{n} {t:?} str={a0:#x} a1={a1:#x} a2={a2:#x} a3={a3:#x} lr={lr:#x}",
                    n = conta_putsb.get(),
                    t = String::from_utf8_lossy(&s[..fim]),
                    a0 = regs[0],
                    a1 = regs[1],
                    a2 = regs[2],
                    a3 = regs[3],
                    lr = regs[14],
                );
            }
            conta_putsb.set(conta_putsb.get() + 1);
        }
    });
    // TEMP (SDFAT item loop): logs the item type and flagB on each
    // iteration (`0x8801AB68`): check whether flagB ever reaches 1.
    cpu.trap_pc_mem(0x8801_AB68, move |mem, regs| {
        let fb = mem.read_u32(0x882A_D614).unwrap_or(0xDEAD);
        let fa = mem.read_u32(0x882A_D618).unwrap_or(0xDEAD);
        let slv = mem.read_u32(regs[10]).unwrap_or(0xDEAD);
        eprintln!(
            "ITEMB r1={:#x} r2={:#x} flagB={fb:#x} flagA={fa:#x} sl={:#x} [sl]={slv:#x} r9={:#x}",
            regs[1], regs[2], regs[10], regs[9]
        );
    });
    // blank-NAND 0xAA in the same slice as the check, so the per-slice
    // plant loses the race (same class as MISC). Overwrite it
    // synchronously at the check entry (`0x880190E8`, before the
    // first `ldrb` pair): UTF-16LE "DREA10000".
    cpu.trap_pc_mem(0x8801_90E8, move |mem, regs| {
        let modelo: &[u8] = b"D\0R\0E\0A\01\0\0\00\0\
                              \0\0\0\0\0\0\0\0\0\0\0";
        let _ = mem.write(regs[0], modelo);
    });
    // Host memset/memcpy (`0x880155D4`/`0x8801566C`, r0=dst, r1=c/src,
    // r2=len): the NBH flow memsets the whole 91 MB staging buffer and
    // copies multi-MB items through these — byte loops in the
    // interpretador burn ~500 instr/byte (~200 slices/KB). Do it
    // host-side and skip (both return dst in r0). Pure functions, no
    // device behavior; the bytes are identical.
    cpu.trap_pc_mem(0x8801_55D4, move |mem, regs| {
        let (dst, val, len) = (regs[0], regs[1] as u8, regs[2] as usize);
        if len > 0 && len <= 0x7000000 {
            let z = vec![val; len];
            if mem.write(dst, &z).is_ok() {
                regs[0] = dst;
                regs[15] = regs[14];
            }
        }
    });
    cpu.trap_pc_mem(0x8801_566C, move |mem, regs| {
        let (dst, src, len) = (regs[0], regs[1], regs[2] as usize);
        if len > 0 && len <= 0x7000000 {
            match mem.read(src, len as u32) {
                Ok(d) => {
                    let tmp = d.to_vec();
                    if mem.write(dst, &tmp).is_ok() {
                        regs[0] = dst;
                        regs[15] = regs[14];
                    }
                }
                Err(_) => {}
            }
        }
    });
    // All three sector-read entries funnel here: `0x8800D644` (FAT
    // path, (dst, lba, count)), `0x8800D488` (multi, (ctrl, lba, dst,
    // count)), `0x8800D67C` (single, (dst, lba)). The trap writes the
    // bytes and skips the SDCC PIO pump (`r15 = lr`, like forcing a
    // return: the entry `push` never ran, so the stack stays balanced).
    // D644 arity (dst=r0, lba=r1, count=r2) pinned live from the
    // `0x8801BF68` shim (`mov r3,r0; mov r0,r1; mov r1,r3`); D488's from
    // D644's own call (`r1=X, r2=Y` with X=orig r1=lba, Y=orig r0=dst).
    // A serve that misses (out of range, no card) lets the guest run
    // into stub faults instead — new information, same as NAND.
    let sd_srv = sd.clone();
    let conta_sd = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let conta_sdb = conta_sd.clone();
    cpu.trap_pc_mem(0x8800_D644, move |mem, regs| {
        // Sparse: first 6 + every 4K sectors (2 MB) — tracks a 91 MB
        // file read without flooding.
        if conta_sdb.get() < 6 || regs[1] % 4096 == 0 {
            eprintln!(
                "SDLOG#{n} r0={:#x} r1={:#x} r2={:#x} lr={:#x}",
                regs[0],
                regs[1],
                regs[2],
                regs[14],
                n = conta_sdb.get(),
            );
        }
        conta_sdb.set(conta_sdb.get() + 1);
        if let Some(img) = sd_srv.as_ref() {
            serve_setor_sd(
                mem,
                regs,
                img,
                regs[0],
                regs[1] as usize,
                regs[2] as usize,
            );
        }
    });
    let sd_srv2 = sd.clone();
    cpu.trap_pc_mem(0x8800_D488, move |mem, regs| {
        if let Some(img) = sd_srv2.as_ref() {
            serve_setor_sd(
                mem,
                regs,
                img,
                regs[2],
                regs[1] as usize,
                regs[3] as usize,
            );
        }
    });
    let sd_srv3 = sd.clone();
    cpu.trap_pc_mem(0x8800_D67C, move |mem, regs| {
        if let Some(img) = sd_srv3.as_ref() {
            serve_setor_sd(mem, regs, img, regs[0], regs[1] as usize, 1);
        }
    });
    // Card-detect HAL (`0x8802E534`): nonzero = inserted. Skipped the
    // same way; with no image the guest takes the `No card inserted`
    // path instead of jumping through a zeroed HAL vector.
    let sd_det = sd.clone();
    cpu.trap_pc_mem(0x8802_E534, move |_mem, regs| {
        regs[0] = u32::from(sd_det.is_some());
        regs[15] = regs[14];
    });
    // `sd_detect_and_init` (`0x8800D11C`): 6 = HC card, 0 = none. The
    // CMD0/CMD8/ACMD41 init sequence is skipped with it; the FAT layer
    // above only needs the type code.
    let sd_ini = sd.clone();
    cpu.trap_pc_mem(0x8800_D11C, move |_mem, regs| {
        regs[0] = if sd_ini.is_some() { 6 } else { 0 };
        regs[15] = regs[14];
    });
    // TEMP (mm list): pointer chain up to the poison + lr
    // (head). Cap 16: the loop only iterates 2x per boot (head and poison).
    // TEMP (visible ATAG): what the CORE check reads (per boot).
    cpu.trap_pc_mem(0xC000_C870, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                let w0 = mem.read_u32(0xC000_0100).unwrap_or(0xDEAD);
                let w1 = mem.read_u32(0xC000_0104).unwrap_or(0xDEAD);
                eprintln!(
                    "ATAGRD va0={w0:#x} va1={w1:#x} r0={:#x}",
                    regs[0]
                );
            }
        }
    });
    // TEMP (suspect restore): the ldm at 0xC00219E8 restores the
    // next task's context (r4-r11,sp,pc from [r2+28...]).
    // If all zeros, switch_to picked up a ghost task.
    // TEMP (next frame): dumps the stack BELOW the restored sp
    // (where pt_regs/childregs would live if the task were real). Zeros =
    // ghost task (switch to something never set up); valid
    // content = legitimate fresh task and the bug is further ahead (path B).
    // TEMP (final jump): what does the movs pc,lr at 0xC0021A7C consume?
    cpu.trap_pc_mem(0xC002_1A7C, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("FINAL f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xC002_1A54, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("TOUSER f={} sp={:#x} r1flags={:#x}", unsafe { FATIA_ATUAL }, regs[13], regs[1]);
            }
        }
    });
    cpu.trap_pc_mem(0xC002_1A64, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("RESTORE f={} sp={:#x}", unsafe { FATIA_ATUAL }, regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xC002_1A30, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("WORK f={} r1={:#x}", unsafe { FATIA_ATUAL }, regs[1]);
            }
        }
    });
    cpu.trap_pc_mem(0xC002_1A84, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                let pc = mem.read_u32(regs[13].wrapping_add(0x3C)).unwrap_or(0xDEAD);
                let psr = mem.read_u32(regs[13].wrapping_add(0x40)).unwrap_or(0xDEAD);
                let fnv = mem.read_u32(regs[13].wrapping_add(8)).unwrap_or(0xDEAD);
                eprintln!("POSTTAIL f={} sp={:#x} [sp+3c]={pc:#x} [sp+40]={psr:#x} [sp+8]={fnv:#x}", unsafe { FATIA_ATUAL }, regs[13]);
            }
        }
    });
    // TEMP (JUMPBACK origin): what is 0xC003DC80?
    cpu.trap_pc_mem(0xC003_DC80, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 1 {
                N += 1;
                let mut c = vec![0u8; 64];
                let ok = mem.read(0xC003_DC40, 64).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("JBSRC ok={ok} code={c:02x?} lr={:#x} sp={:#x}", regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xC002_23EC, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                eprintln!("HELPER r0={:#x} r1={:#x} r2={:#x} r3={:#x}", regs[0], regs[1], regs[2], regs[3]);
            }
        }
    });
    cpu.trap_pc_mem(0xC000_887C, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                eprintln!("KINIT r0={:#x} r1={:#x} sp={:#x}", regs[0], regs[1], regs[13]);
            }
        }
    });
    // TEMP (idle?): schedule() entry — who schedules what, and the
    // timer state (0xC02A43EC gate + GPT MATCH/COUNT/ENABLE).
    // Stall tail (100th+ switch, f≈91300): dump 48 words at sp —
    // the outgoing task's park chain (unwind offline via kallsyms).
    // Cap 400 + 8 dumps (the stall leaves no switches after #107).
    cpu.trap_pc_mem(0xC021_2A08, move |mem, regs| {
        static mut N: u32 = 0;
        static mut ND: u32 = 0;
        static mut ND2: u32 = 0;
        unsafe {
            if N < 400 {
                N += 1;
                let n = N;
                let ti = regs[13] & !0x1FFF;
                let flags = mem.read_u32(ti).unwrap_or(0xDEAD);
                let gate = mem.read_u32(0xC02A_43EC).unwrap_or(0xDEAD);
                let m = mem.read_u32(0xE000_1000).unwrap_or(0xDEAD);
                let c = mem.read_u32(0xE000_1004).unwrap_or(0xDEAD);
                let e = mem.read_u32(0xE000_1008).unwrap_or(0xDEAD);
                eprintln!("SCHED#{n} f={} ti={ti:#x} flags={flags:#x} gate={gate:#x} MATCH={m:#x} COUNT={c:#x} EN={e:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[14]);
                if n >= 100 && ND < 8 {
                    ND += 1;
                    let mut st = [0u32; 48];
                    for (i, s) in st.iter_mut().enumerate() {
                        *s = mem.read_u32(regs[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                    }
                    eprintln!("SCHSTK#{n} f={} sp={:#x} stk={st:#x?}", unsafe { FATIA_ATUAL }, regs[13]);
                }
                // Late-era stacks (the 57s wall parks init once at
                // f≈103k and never switches again — early dumps miss
                // it). Fresh counter, gate f>=400000. NOTE: only fires
                // on actual switches; the parked init never re-enters
                // schedule, so the frozen-stack dump below carries it.
                if unsafe { FATIA_ATUAL } >= 400000 && ND2 < 8 {
                    ND2 += 1;
                    let mut st = [0u32; 48];
                    for (i, s) in st.iter_mut().enumerate() {
                        *s = mem.read_u32(regs[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                    }
                    eprintln!("SCHSTK-LATE#{n} f={} sp={:#x} stk={st:#x?}", unsafe { FATIA_ATUAL }, regs[13]);
                }
            }
        }
    });
    // TEMP (hot fn 0xC0180604): args + caller.
    cpu.trap_pc_mem(0xC018_0604, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 3 {
                N += 1;
                let n = N;
                eprintln!("HOT#{n} f={} r0={:#x} r1={:#x} r2={:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[14], regs[13]);
            }
        }
    });
    // Cap 12: the loop has multiple calls (r6 can vary per bank).
    cpu.trap_pc_mem(0xC002_D690, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 12 {
                N += 1;
                let n = N;
                let v6 = mem.read_u32(regs[6]).unwrap_or(0xDEAD);
                let mut c = vec![0u8; 64];
                let ok = mem.read(0xC002_D690, 64).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("E10FAIL#{n} f={} r6={:#x} [r6]={v6:#x} r4={:#x} r5={:#x} sp={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[6], regs[4], regs[5], regs[13], regs[14]);
            }
        }
    });
    // Delay skip (WIDE): 0xC01006F4 and `__const_udelay` (scales by
    // lpj + pure countdown). The calibration (0xC001C170..0xC001C2EC)
    // measures for real; TODO the rest is dumb waiting — and the stubs
    // answer instantly, so skipping is coherent. It used to be
    // gated only for proc_comm; widened because driver init has
    // hundreds of ms of udelay/mdelay (thousands of slices per ms).
    cpu.trap_pc_mem(0xC010_06F4, move |_mem, regs| {
        let lr = regs[14];
        if !(0xC001_C170..0xC001_C2EC).contains(&lr) {
            regs[15] = lr;
        }
    });
    // (The proc_comm-gated twin that used to sit here was redundant:
    // proc_comm's udelay callers are outside the calibrate range, so
    // the wide rule already skips them. Deleted: a second hook on
    // the same address would evict this one (replace semantics).)
    cpu.trap_pc_mem(0xC000_E860, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                let mut c = vec![0u8; 64];
                let ok = mem.read(0xC000_E860, 64).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("EFAIL f={} r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} sp={:#x} lr={:#x} ok={ok} code={c:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[13], regs[14]);
            }
        }
    });
    // creation; the switch consumes when the frame's fn slot is zeroed.
    // Late-window view (f >= 80000, cap 16): the 1.48s stall hangs
    // in kthread_create — which fn never starts?
    cpu.trap_pc_mem(0xC002_2614, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            // FIFO embedded in the counter: only logs (order is
            // kernel_init, kthreadd, ...; the switch uses the counter).
            if unsafe { FATIA_ATUAL } >= 80000 && N < 24 {
                N += 1;
                eprintln!("KTHREAD f={} fn={:#x} arg={:#x} flags={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2]);
            }
        }
    });
    cpu.trap_pc_mem(0xC002_19E8, move |mem, regs| {
        static mut N: u32 = 0;
        static mut PLANTA_N: u32 = 0;
        unsafe {
            // FIX fork frame (fork_ids.md d.1): copy_thread's childregs
            // memcpy never landed; plant the kernel-thread regs so
            // ret_from_fork -> helper -> kernel_init runs for real.
            // sp_novo is read from [r4+32] (cpu_context.sp).
            let mut wb = [0u8; 4];
            let sp_novo = mem
                .read(regs[4].wrapping_add(32), 4)
                .map(|s| {
                    wb.copy_from_slice(s);
                    u32::from_le_bytes(wb)
                })
                .unwrap_or(0xDEAD);
            // Generic per thread: only fills zeroed slots. fn by
            // creation order (1st=kernel_init, 2nd=kthreadd).
            let fn_slot = mem.read_u32(sp_novo.wrapping_add(8)).unwrap_or(0xDEAD);
            let pcreal = mem.read_u32(sp_novo.wrapping_add(0x38)).unwrap_or(0xDEAD);
            if pcreal == 0 {
                PLANTA_N += 1;
                let pn = PLANTA_N;
                let f = if pn == 1 { 0xC000_887Cu32 } else { 0xC005_BCB8u32 };
                if fn_slot == 0 {
                    let _ = mem.write_u32(sp_novo.wrapping_add(8), f); // ARM_r2 = fn
                }
                let _ = mem.write_u32(sp_novo.wrapping_add(12), 0xC004_9CA8); // ARM_r3 = do_exit
                let _ = mem.write_u32(sp_novo.wrapping_add(0x34), sp_novo.wrapping_add(0x3C)); // ARM_sp
                let _ = mem.write_u32(sp_novo.wrapping_add(0x38), 0xC002_23EC); // S_PC real
                let _ = mem.write_u32(sp_novo.wrapping_add(0x3C), 0xC002_23EC); // (transiente)
                let _ = mem.write_u32(sp_novo.wrapping_add(0x40), 0x0000_0013); // CPSR = SVC
                if N < 6 {
                    eprintln!("FORKFIX#{pn} planted sp_novo={sp_novo:#x} fn={f:#x} (slot was {fn_slot:#x})");
                }
            }
            if N < 3 {
                N += 1;
                let mut st = vec![0u8; 128];
                let ok = mem.read(sp_novo.wrapping_sub(128), 128).map(|s| st.copy_from_slice(s)).is_ok();
                eprintln!("CTXSTK f={} r4={:#x} sp_novo={sp_novo:#x} ok={ok} stk={st:02x?}", unsafe { FATIA_ATUAL }, regs[4]);
            }
        }
    });
    // TEMP (completion waiter/waker 0xC021335C/0xC0040228): the 1.48s
    // stall parks init in kthread_create->wait_for_completion. Log
    // every waiter (completion addr + task) and every waker
    // (completion addr). A waiter with no matching waker = the hang.
    // Cap 300 each, gate f >= 80000 (boot noise before). PLUS: the
    // msm_dmov_exec_cmd waiter (lr 0xC002B570) is completed
    // immediately (done=1) — the ADM datamover is unmodeled and
    // would never signal it (init parks here after mddi). Scoped to
    // that single call site; all other completions behave normally.
    // Revisit with a real ADM model.
    cpu.trap_pc_mem(0xC021_335C, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 80000 && N < 300 {
                N += 1;
                let n = N;
                let ti = regs[13] & !0x1FFF;
                let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                eprintln!("WAIT#{n} f={} compl={:#x} task={:#x} ti={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], task, ti, regs[14]);
                if regs[14] == 0xC002_B570 {
                    let _ = mem.write_u32(regs[0], 1);
                    eprintln!("WAIT-DMOV-COMPLETE#{n} f={}", unsafe { FATIA_ATUAL });
                }
            }
        }
    });
    cpu.trap_pc_mem(0xC004_0228, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 80000 && N < 300 {
                N += 1;
                let n = N;
                eprintln!("DONE#{n} f={} compl={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[14]);
            }
        }
    });
    // TEMP (console driver call 0xC0046A14): release_console_sem
    // calls the drivers via BL at 0xC0046C84. Dump the message text
    // (r0=start, r1=end indices into __log_buf at 0xC02C9000) to see
    // whether late output is new boot text or a repeating storm.
    // Cap 12, gate f >= 80000.
    cpu.trap_pc_mem(0xC004_6A14, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 80000 && N < 12 {
                N += 1;
                let n = N;
                let ini = regs[0] as usize;
                let fim = regs[1] as usize;
                let nbytes = fim.saturating_sub(ini).min(256);
                // LOG_BUF_MASK is 0x1FFFF (128 KB ring).
                let base = 0xC02C_9000u32.wrapping_add((ini & 0x1_FFFF) as u32);
                let s = match mem.read(base, nbytes as u32) {
                    Ok(b) => String::from_utf8_lossy(b).into_owned(),
                    Err(_) => "<unmapped>".to_string(),
                };
                eprintln!("CONDRV#{n} f={} [{ini:#x}..{fim:#x}] msg={s:?}", unsafe { FATIA_ATUAL });
            }
        }
    });
    cpu.trap_pc_mem(0xC021_2D98, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 1 {
                N += 1;
                let mut c = vec![0u8; 64];
                let lok = regs[14]
                    .checked_sub(64)
                    .and_then(|a| mem.read(a, 64).map(|s| c.copy_from_slice(s)).ok())
                    .is_some();
                let mut st = vec![0u8; 64];
                let sp = regs[13];
                let oks = mem.read(sp, 64).map(|s| st.copy_from_slice(s)).is_ok();
                eprintln!(
                    "CALLER lr={:#x} r0={:#x} r1={:#x} r2={:#x} r3={:#x} sp={sp:#x} lok={lok} code={c:02x?}",
                    regs[14], regs[0], regs[1], regs[2], regs[3]
                );
                eprintln!("CALLERSTK oks={oks} stack={st:02x?}");
            }
        }
    });
    // TEMP (B body): live bytes around the restored pc
    // 0xC0021A80 (96B from -32). One shot.
    cpu.trap_pc_mem(0xC002_1A80, move |mem, _regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 1 {
                N += 1;
                let mut c = vec![0u8; 96];
                if mem.read(0xC002_1A60, 96).map(|s| c.copy_from_slice(s)).is_ok() {
                    eprintln!("BBODY bytes={c:02x?}");
                }
            }
        }
    });
    cpu.trap_pc_mem(0xC002_19D0, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 3 {
                N += 1;
                let mut st = vec![0u8; 48];
                let sp = regs[13];
                let oks = mem.read(sp, 48).map(|s| st.copy_from_slice(s)).is_ok();
                eprintln!(
                    "CTXIN r0={:#x} r1={:#x} r2={:#x} r3={:#x} lr={:#x} sp={sp:#x} oks={oks} stack={st:02x?}",
                    regs[0], regs[1], regs[2], regs[3], regs[14]
                );
            }
        }
    });
    // TEMP (F caller): bytes around 0xC0212D9C, from where
    // the bl to 0xC00219D0 with r2=0xC601E000 leaves. One shot.
    cpu.trap_pc_mem(0xC021_2D9C, move |mem, _regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 1 {
                N += 1;
                let mut c = vec![0u8; 96];
                if mem.read(0xC021_2D60, 96).map(|s| c.copy_from_slice(s)).is_ok() {
                    eprintln!("CALLER bytes={c:02x?}");
                }
            }
        }
    });
    cpu.trap_pc_mem(0xC006_0C80, move |mem, _regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 1 {
                N += 1;
                let mut c = vec![0u8; 64];
                if mem.read(0xC006_0C74, 64).map(|s| c.copy_from_slice(s)).is_ok() {
                    eprintln!("JMPIN bytes={c:02x?}");
                }
            }
        }
    });
    // TEMP (A return): the ldmibeq at 0xC00405FC — condition (r3),
    // loaded pc ([sp+12]) and sp, per pass. The fatal pass is the
    // last one before JUMPBACK.
    cpu.trap_pc_mem(0xC004_05FC, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 8 {
                let n = N;
                N += 1;
                let dst = mem.read_u32(regs[13].wrapping_add(12)).unwrap_or(0xDEAD);
                eprintln!(
                    "ARET{n} f={} r3={:#x} sp={:#x} [sp+12]={dst:#x} lr={:#x}",
                    unsafe { FATIA_ATUAL },
                    regs[3],
                    regs[13],
                    regs[14]
                );
            }
        }
    });
    cpu.trap_pc_mem(0xC010_1A80, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                let mut c = vec![0u8; 64];
                let lok = regs[14]
                    .checked_sub(64)
                    .and_then(|a| mem.read(a, 64).map(|s| c.copy_from_slice(s)).ok())
                    .is_some();
                eprintln!(
                    "WMEMSET lr={:#x} r0={:#x} r1={:#x} r2={:#x} lok={lok} code={c:02x?}",
                    regs[14], regs[0], regs[1], regs[2]
                );
                // ti->task + comm: which thread zeroes its own ATAGs?
                let ti = (regs[13] & !8191) & !63;
                let mut task = vec![0u8; 4];
                let _ = mem.read(ti, 4).map(|s| task.copy_from_slice(s));
                let tp = u32::from_le_bytes([task[0], task[1], task[2], task[3]]);
                let mut nm = vec![0u8; 16];
                let mut achou = String::new();
                let mut off = 0u32;
                while off < 0x400 {
                    if mem.read(tp.wrapping_add(off), 16).map(|s| nm.copy_from_slice(s)).is_ok()
                        && nm.iter().all(|&b| b == 0 || (32..127).contains(&b))
                        && nm[0] != 0
                    {
                        achou = format!("[{off:#x}] {:?}", String::from_utf8_lossy(&nm));
                        break;
                    }
                    off += 16;
                }
                eprintln!("WMEMTASK ti={ti:#x} task={tp:#x} comm={achou}");
            }
        }
    });
    cpu.trap_pc_mem(0xC005_BF90, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if regs[0] == 0xC000_0100 && N < 2 {
                N += 1;
                let mut c = vec![0u8; 64];
                let lok = regs[14]
                    .checked_sub(64)
                    .and_then(|a| mem.read(a, 64).map(|s| c.copy_from_slice(s)).ok())
                    .is_some();
                eprintln!(
                    "WILH lr={:#x} r0={:#x} lok={lok} code={c:02x?}",
                    regs[14], regs[0]
                );
            }
        }
    });
    // TEMP (A's ti): thread_info that A reads ([ti], [ti+#12]).
    // If zeroed, the branch to B is taken because of stub/zeropage.
    cpu.trap_pc_mem(0xC004_05D0, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                let ti = regs[13] & !8191 & !63;
                let mut t = vec![0u8; 32];
                let okt = mem.read(ti, 32).map(|s| t.copy_from_slice(s)).is_ok();
                eprintln!("ATI sp={:#x} ti={ti:#x} okt={okt} ti32={t:02x?}", regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xC001_202C, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 16 {
                let n = N;
                N += 1;
                let nx = mem.read_u32(regs[1]).unwrap_or(0xDEAD);
                eprintln!("WALK{n} f={} r1={:#x} [r1]={nx:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[1], regs[14]);
            }
        }
    });
    // TEMP (vectors): which vector does the IRQ use — 0x18 or 0xFFFF0018?
    // Cap 3 each + 32B of the stub (ldr pc,[pc,#..] reveals the handler).
    cpu.trap_pc_mem(0x0000_0018, move |mem, _regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 3 {
                N += 1;
                let mut c = vec![0u8; 32];
                let ok = mem.read(0x18, 32).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("VECLO ok={ok} stub={c:02x?}");
            }
        }
    });
    cpu.trap_pc_mem(0xFFFF_0018, move |mem, _regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 3 {
                N += 1;
                let n = N;
                let mut c = vec![0u8; 32];
                let ok = mem.read(0xFFFF_0018, 32).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("VECHI#{n} ok={ok} stub={c:02x?}");
            }
        }
    });
    // TEMP (vector code): what is at 0xFFFF0200 — real dispatch
    // or zeros (guest did not copy)?
    cpu.trap_pc_mem(0xFFFF_0200, move |mem, _regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                let n = N;
                let mut c = vec![0u8; 64];
                let ok = mem.read(0xFFFF_0200, 64).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("VEC2#{n} ok={ok} code={c:02x?}");
            }
        }
    });
    cpu.trap_pc_mem(0xC002_AAD0, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 3 {
                N += 1;
                let n = N;
                eprintln!("TICKH#{n} f={} r0={:#x} r1={:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14], regs[13]);
            }
        }
    });
    // TEMP (vector index): lr (=SPSR&15, guest mode) + target.
    // Decides between SVC(3)->0xC00215E0, USR(0), SYS(15)->???.
    // Gated to the preempt-BUG window (f >= 84000): are there any
    // vector entries at all near the fault, or is the dispatch
    // path entered without one?
    // TEMP (vector entry stack 0xFFFF0018 = IRQ vector): dump 8 words
    // of the IRQ stack on vector entry (pc+lr chain shows what was
    // interrupted vs what jumped here). A real delivery interrupts
    // live code; a spurious in-guest jump shows a foreign context.
    // (Was on 0x1C = FIQ vector: never fired. Fixed 2026-10-23.)
    // Gated to the fault window (f >= 84000, cap 20): an ungated
    // cap would be consumed by boot vectors.
    cpu.trap_pc_mem(0xFFFF_0018, move |mem, regs| {
        static mut NV: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 84000 && NV < 20 {
                NV += 1;
                let n = NV;
                let mut st = [0u32; 8];
                for (i, s) in st.iter_mut().enumerate() {
                    *s = mem.read_u32(regs[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                }
                eprintln!("VECSTK#{n} f={} sp={:#x} stk={st:#x?}", unsafe { FATIA_ATUAL }, regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xFFFF_0224, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 84000 && N < 20 {
                N += 1;
                let n = N;
                let idx = regs[14] & 15;
                let alvo = mem.read_u32(0xFFFF_022Cu32.wrapping_add(idx * 4)).unwrap_or(0xDEAD);
                eprintln!("VIDX#{n} f={} idx={idx} lr={:#x} alvo={alvo:#x}", unsafe { FATIA_ATUAL }, regs[14]);
            }
        }
    });
    // r5 (VIC base) is valid? Cap 8 + 96B, gated to the fault window.
    cpu.trap_pc_mem(0xC002_15E0, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 84000 && N < 20 {
                N += 1;
                let n = N;
                let mut c = vec![0u8; 96];
                let ok = mem.read(0xC002_15E0, 96).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("DISP#{n} f={} r5={:#x} sp={:#x} lr={:#x} ok={ok} code={c:02x?}", unsafe { FATIA_ATUAL }, regs[5], regs[13], regs[14]);
            }
        }
    });
    // TEMP (initcalls t59-t62): trout_backlight, mmc-dbg, acoustic,
    // smd. If they fire in order, boot walks initcalls (slow but
    // alive); if never, stuck earlier (idx-20 subtree). Shared cap
    // 4 (one static for all four sites — prints once each).
    for (va, nm) in [
        (0xC000_EE64u32, "backlight"),
        (0xC000_EFF0u32, "mmcdbg"),
        (0xC000_F248u32, "acoustic"),
        (0xC000_F284u32, "smd"),
    ] {
        cpu.trap_pc_mem(va, move |_mem, _regs| {
            static mut N: u32 = 0;
            unsafe {
                if N < 4 {
                    N += 1;
                    eprintln!("INITCALL f={} {}", unsafe { FATIA_ATUAL }, nm);
                }
            }
        });
    }
    // TEMP (alarm path 0xC002ACD8/0xC002ABAC): does reactivate_alarm
    // still run post-wall, and does it reach set_next_event? MATCH
    // is frozen while the idle loop spins — if the alarm never
    // fires, nobody reprograms. Cap 10 each, gate f >= 100000.
    cpu.trap_pc_mem(0xC002_ACD8, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 100000 && N < 10 {
                N += 1;
                let n = N;
                eprintln!("REACT#{n} f={} lr={:#x}", unsafe { FATIA_ATUAL }, regs[14]);
            }
        }
    });
    cpu.trap_pc_mem(0xC002_ABAC, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 100000 && N < 10 {
                N += 1;
                let n = N;
                let tc = mem.read_u32(0xE000_1004).unwrap_or(0xDEAD);
                eprintln!("SETNX2#{n} f={} r0={:#x} r1={:#x} COUNT={tc:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14]);
            }
        }
    });
    // TEMP (set_next_event args 0xC002AC08): all tick-path MATCH
    // writes funnel here (shared by tick and alarm paths). Log delta arg + caller
    // to see who programs stale/zero-lead values (the wall: MATCH
    // stuck <= COUNT, level never drops, edge never fires while
    // unmasked checks see fresh MATCH). Re-gated f >= 100000, cap 20
    // (the wall era — earlier cap died in the transition).
    cpu.trap_pc_mem(0xC002_AC08, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 100000 && N < 20 {
                N += 1;
                let n = N;
                let tc = mem.read_u32(0xE000_1004).unwrap_or(0xDEAD);
                let tm = mem.read_u32(0xE000_1000).unwrap_or(0xDEAD);
                eprintln!("SETNX#{n} f={} r0={:#x} r1={:#x} COUNT={tc:#x} MATCH={tm:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14]);
            }
        }
    });
    // TEMP (spam skip 0xC0047610): the 1.65s wall is a printk-fueled
    // deadlock — every idle entry prints "timer late" + "no smem
    // clock" (masked console flush with fbcon render costs more
    // than the entry period, so the ISR starves, the wheel freezes,
    // deadlines stay stale, every entry stays late). Skip exactly
    // these two formats (regs[15]=lr returns immediately): "late"
    // self-retires once deadlines heal; "smem" stays until the
    // modem SMEM is modeled. Logs the first 5 skips. All other
    // printks run normally.
    cpu.trap_pc_mem(0xC004_7610, move |mem, regs| {
        static mut NSK: u32 = 0;
        unsafe {
            if let Ok(fmt) = mem.read(regs[0], 80) {
                let s = String::from_utf8_lossy(fmt);
                if s.contains("timer late") || s.contains("no smem clock") {
                    if NSK < 5 {
                        NSK += 1;
                        let n = NSK;
                        eprintln!("SKIPMSG#{n} f={} fmt={:?}", unsafe { FATIA_ATUAL }, &s[..s.len().min(60)]);
                    }
                    regs[15] = regs[14];
                    regs[0] = 0;
                }
            }
        }
    });
    // TEMP (enter_idle check 0xC002B28C): msm_timer_enter_idle
    // returns immediately unless [0xC02C1C38] == [0xC02A43C0].
    // If mismatched forever, it never reprograms MATCH (frozen
    // since ~91k) — log both sides + COUNT. Cap 5.
    cpu.trap_pc_mem(0xC002_B28C, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 5 {
                N += 1;
                let n = N;
                let r4 = regs[4];
                let dev0 = mem.read_u32(0xC02A_43C0).unwrap_or(0xDEAD);
                let tc = mem.read_u32(0xE000_1004).unwrap_or(0xDEAD);
                eprintln!("EIDLE#{n} f={} r4={:#x} [dev]={dev0:#x} eq={} COUNT={tc:#x}", unsafe { FATIA_ATUAL }, regs[4], r4 == dev0);
            }
        }
    });
    // TEMP (nohz entry 0xC0065628): tick_nohz_stop_idle — who calls,
    // how often past the wall. If entered but never returned (no
    // exit log), the guest sleeps tickless with no wakeup. Cap 20,
    // gate f >= 90000.
    cpu.trap_pc_mem(0xC006_5628, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 90000 && N < 20 {
                N += 1;
                let n = N;
                eprintln!("NOHZ#{n} f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    // TEMP (wait_for_common entry 0xC0213114): the 57s wall is init
    // in wait_for_common (lr schedule_timeout+0x98, timeout 0x64)
    // inside synaptics_ts_probe — a completion that never signals
    // AND whose timer never fires. Log completion addr (r0),
    // timeout (r1), caller (lr), task. Finite timeouts only (the
    // MAX ones are kthread noise). PLUS: complete the synaptics
    // wait (compl 0xC6017B84, on init's stack) host-side (done=1)
    // on entry — the awaited event (ATTN IRQ / i2c xfer done) has
    // no emulated source; the probe then proceeds to read device
    // state (graceful -ENODEV or a dead input device both unblock
    // boot). Scoped to the exact address; the WFC log names any
    // future mover. Revisit with real i2c/GPIO IRQ modeling.
    cpu.trap_pc_mem(0xC021_3114, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            // Finite timeouts only: the MAX (infinite) ones are
            // kthread_create noise (already understood) that exhausts
            // the cap before the synaptics wait (timeout 0x64).
            // Cap 300 (the probe re-waits in a loop — 10 dies early).
            if unsafe { FATIA_ATUAL } >= 90000 && regs[1] != 0x7FFF_FFFF && N < 300 {
                N += 1;
                let n = N;
                let ti = regs[13] & !0x1FFF;
                let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                eprintln!("WFC#{n} f={} compl={:#x} timeout={:#x} task={:#x} ti={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], task, ti, regs[14]);
            }
            if regs[0] == 0xC601_7B84 {
                let _ = mem.write_u32(regs[0], 1);
                static mut NWC: u32 = 0;
                if NWC < 3 {
                    NWC += 1;
                    eprintln!("WFC-COMPLETE f={} (synaptics wait)", unsafe { FATIA_ATUAL });
                }
            }
            // The probe steps through per-stage on-stack completions
            // (0xC6017B84 looped, then 0xC6017C74 parked) — same
            // unmodeled event (ATTN IRQ / i2c done) each time. Complete
            // ANY finite wait from the init thread (task 0xC6013C00,
            // stable across runs; the WFC log names movers), log each
            // new address. Kthread infinite waits untouched.
            if regs[1] != 0x7FFF_FFFF {
                let ti2 = regs[13] & !0x1FFF;
                let task2 = mem.read_u32(ti2.wrapping_add(12)).unwrap_or(0xDEAD);
                if task2 == 0xC601_3C00 {
                    let _ = mem.write_u32(regs[0], 1);
                    static mut NWD: u32 = 0;
                    static mut ULTIMO_WFC: u32 = 0;
                    unsafe {
                        if regs[0] != ULTIMO_WFC && NWD < 10 {
                            NWD += 1;
                            ULTIMO_WFC = regs[0];
                            eprintln!("WFC-COMPLETE-INIT f={} compl={:#x} (init finite wait)", unsafe { FATIA_ATUAL }, regs[0]);
                        }
                    }
                }
            }
        }
    });
    // TEMP (PTE mirror via update_mmu_cache 0xC0027228): the guest
    // installs user PTEs through fixmap kmap_atomic slots, invisible
    // to the lowmem alias the PT walk reads — the walk keeps missing
    // and the abort loops. update_mmu_cache(vma, addr, pte) runs on
    // every install with the exact values (proven live: it fired in
    // the abort handler's file-fault path): mirror the PTE into the
    // lowmem-alias copy of the L2 table so the walk (and the fault
    // retry) sees it. TTBR comes from the fault-arm cache (updated
    // on every user walk-miss); a task mismatch means an
    // interleaved switch — skip rather than mirror into the wrong
    // table. Uncapped writes (every install matters), log cap 12.
    // Permanent until GuestMemory grows alias coherence.
    cpu.trap_pc_mem(0xC002_7228, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let va = regs[1];
            let pte = regs[2];
            let ti = regs[13] & !0x1FFF;
            let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
            if task != TTBR_TASK || TTBR_CACHE == 0 {
                return;
            }
            // L1 walk through the lowmem alias (tables built via VA
            // writes; PA bank stale). Map + seed alias pages on demand
            // with GuestMemory's inherent API (the trap gets mem, not
            // cpu — no CpuBackend trait methods here).
            let le32 = |m: &GuestMemory, a: u32| -> Option<u32> {
                m.read(a, 4)
                    .ok()
                    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            };
            let l1pa = (TTBR_CACHE & 0xFFFF_C000).wrapping_add((va >> 20) << 2);
            let l1av = l1pa.wrapping_add(0xB000_0000);
            let l1e = match le32(mem, l1av) {
                Some(e) => e,
                None => {
                    let b0 = l1av & !0xFFF;
                    if mem.map_zeroed("usuario_ptw", b0, 0x1000).is_err() {
                        return;
                    }
                    if let Ok(src) = mem.read(l1pa & !0xFFF, 0x1000) {
                        let buf = src.to_vec();
                        let _ = mem.write(b0, &buf);
                    }
                    match le32(mem, l1av) {
                        Some(e) => e,
                        None => return,
                    }
                }
            };
            if l1e & 3 != 0b01 {
                return;
            }
            let l2pa = (l1e & 0xFFFF_FC00).wrapping_add(((va >> 12) & 0xFF) << 2);
            if !(0x1000_0000..0x2000_0000).contains(&l2pa) {
                return;
            }
            let ava = l2pa.wrapping_add(0xB000_0000);
            let mut ok = mem.write_u32(ava, pte).is_ok();
            if !ok {
                let b0 = ava & !0xFFF;
                if mem.map_zeroed("usuario_ptw", b0, 0x1000).is_ok() {
                    if let Ok(src) = mem.read(l2pa & !0xFFF, 0x1000) {
                        let buf = src.to_vec();
                        let _ = mem.write(b0, &buf);
                    }
                    ok = mem.write_u32(ava, pte).is_ok();
                }
            }
            if unsafe { N < 12 } {
                unsafe {
                    N += 1;
                }
                eprintln!("PTEMIRR f={} va={va:#x} pte={pte:#x} ok={ok}", unsafe { FATIA_ATUAL });
            }
        }
    });
    // TEMP (abort vector entries): confirm the guest abort handlers
    // execute after entra_aborto (vs pc getting clobbered between
    // delivery and the next run). Data (0xFFFF0010) and prefetch
    // (0xFFFF000C) vectors get separate one-shot logs — the
    // prefetch path was never verified.
    cpu.trap_pc_mem(0xFFFF_0010, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("ABORT-VEC f={} lr={:#x}", unsafe { FATIA_ATUAL }, regs[14]);
            }
        }
    });
    cpu.trap_pc_mem(0xFFFF_000C, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("PABORT-VEC f={} lr={:#x}", unsafe { FATIA_ATUAL }, regs[14]);
            }
        }
    });
    // TEMP (do_DataAbort entry 0xC00211F4): log what the guest's
    // abort handler receives (r0=addr, r1=fsr) — distinguishes "no
    // VMA / bad area" (handler bails before installing) from a
    // broken entry path. Cap 6, no gate (aborts are rare).
    cpu.trap_pc_mem(0xC002_11F4, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 6 {
                N += 1;
                let n = N;
                let ti = regs[13] & !0x1FFF;
                let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                eprintln!("DABT#{n} f={} addr={:#x} fsr={:#x} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], task, regs[14]);
            }
        }
    });
    // TEMP (fatal-signal watch: force_sigsegv/do_exit/panic): the
    // stack fault's handler runs update_mmu_cache never, but the
    // signal machinery (get_signal_to_deliver/do_signal/ret_to_user)
    // dominates the halt trace. Log which fatal path fires (signr,
    // task) — SIGSEGV-to-init should panic; a silent return means
    // the signal was discarded/handled. One-shot each (cap 2).
    for (va, nm) in [
        (0xC005_38E4u32, "SIGSEGV"),
        (0xC004_9CA8u32, "DOEXIT"),
        (0xC004_64D8u32, "PANIC"),
    ] {
        cpu.trap_pc_mem(va, move |mem, regs| {
            static mut N: u32 = 0;
            unsafe {
                if N < 6 {
                    N += 1;
                    let n = N;
                    let ti = regs[13] & !0x1FFF;
                    let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                    eprintln!("FATAL#{n} {nm} f={} sig={:#x} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], task, regs[14]);
                }
            }
        });
    }
    // TEMP (signal-send watch 0xC0026AB8/0xC0052610): __do_user_fault
    // (addr+fsr+sig+code) and force_sig_info (signr) — the stack
    // fault's handler installs nothing, yet no SIGSEGV/exit/panic
    // fires; do_signal runs and returns via no_work_pending. Name
    // the exact signal event (or its absence). Cap 4 each.
    cpu.trap_pc_mem(0xC002_6AB8, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("USRFLT f={} addr={:#x} fsr={:#x} sig={} code={} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[3], mem.read_u32((regs[13] & !0x1FFF).wrapping_add(12)).unwrap_or(0xDEAD), regs[14]);
            }
        }
    });
    cpu.trap_pc_mem(0xC005_2610, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                eprintln!("SENDSIG f={} sig={} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[1], mem.read_u32((regs[13] & !0x1FFF).wrapping_add(12)).unwrap_or(0xDEAD), regs[14]);
            }
        }
    });
    // TEMP (VMA decision watch: do_bad_area/find_extend_vma/
    // expand_stack): the stack fault's handler sends SIGSEGV without
    // installing — name the VMA decision (no growdown neighbor vs
    // expansion refused). Cap 4 each.
    for (va, nm) in [
        (0xC002_6DC8u32, "BADAREA"),
        (0xC008_564Cu32, "FINDEXT"),
        (0xC008_5598u32, "EXPAND"),
    ] {
        cpu.trap_pc_mem(va, move |mem, regs| {
            static mut N: u32 = 0;
            unsafe {
                if N < 4 {
                    N += 1;
                    let n = N;
                    eprintln!("VMA#{n} {nm} f={} addr={:#x} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], mem.read_u32((regs[13] & !0x1FFF).wrapping_add(12)).unwrap_or(0xDEAD), regs[14]);
                }
            }
        });
    }
    // TEMP (handle_mm_fault entry 0xC0083060): if it fires for the
    // stack fault, a VMA covers the address (proceeding to map);
    // if it never fires, find_vma found nothing (gap). vma=r1,
    // addr=r2. Cap 40 (text faults each trigger it once).
    cpu.trap_pc_mem(0xC008_3060, move |mem, regs| {
        static mut N: u32 = 0;
        // TEMP (vma layout probe): dump the first 24 words of up
        // to 8 DISTINCT user VMAs (keyed by vma addr) with a sample
        // fault addr each. Comparing file-backed (text 0x8000,
        // mmap 0x400xxxxx) vs anonymous (stack 0xBECxxxxx, brk)
        // reveals which word is vm_file (NULL for anonymous) —
        // needed for anonymous-zero seeding (fixmap-invisible
        // kmap_atomic zeroing leaves stale lowmem content that
        // poisons .bss/stack, e.g. 0x201A8=0xFF0A0000). Remove
        // after the offset is named.
        static mut ND: u32 = 0;
        static mut VISTOS: [u32; 8] = [0; 8];
        unsafe {
            if N < 40 {
                N += 1;
                let n = N;
                eprintln!("HMMF#{n} f={} vma={:#x} addr={:#x} task={:#x}", unsafe { FATIA_ATUAL }, regs[1], regs[2], mem.read_u32((regs[13] & !0x1FFF).wrapping_add(12)).unwrap_or(0xDEAD));
            }
            let vma = regs[1];
            let addr = regs[2];
            // Dedup by hand (no .contains: borrowing a static mut
            // trips static_mut_refs; indexed Copy reads/writes are
            // fine, same as TTBR_CACHE elsewhere).
            let mut seen = false;
            let mut k = 0;
            while k < 8 {
                if VISTOS[k] == vma {
                    seen = true;
                    break;
                }
                k += 1;
            }
            if addr < 0xC000_0000 && ND < 8 && !seen {
                VISTOS[ND as usize] = vma;
                ND += 1;
                let mut vw = [0u32; 24];
                for (i, s) in vw.iter_mut().enumerate() {
                    *s = mem.read_u32(vma.wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                }
                eprintln!("VMADUMP f={} addr={:#x} vma={:#x} words={vw:#x?}", unsafe { FATIA_ATUAL }, addr, vma);
            }
        }
    });
    // TEMP (find_vma entry 0xC0084F4C): log mm+addr lookups. The
    // stack/text faults SIGSEGV without any FINDEXT/EXPAND/HMMF
    // firing — if find_vma never runs for them, the path skips
    // VMA lookup entirely (mmap_sem contention? wrong mm?).
    // Cap 8.
    cpu.trap_pc_mem(0xC008_4F4C, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 8 {
                N += 1;
                let n = N;
                let ti = regs[13] & !0x1FFF;
                eprintln!("FINDVMA#{n} f={} mm={:#x} addr={:#x} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD), regs[14]);
            }
        }
    });
    // TEMP (GOT value at init+0x1A838 `bx ip`): log ip (=ip after
    // `ldr ip, [pc]` of the GOT slot at 0x1A83C). The file holds
    // 0x00015119 there; zeros mean the data page was mirrored from
    // stale/empty content (or never correctly installed).
    // Cap 3.
    cpu.trap_pc_mem(0x0001_A838, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 3 {
                N += 1;
                eprintln!("GOTVAL f={} ip={:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[12], regs[14], regs[13]);
            }
        }
    });
    // TEMP (assert entry 0x126C4): init dies via abort()
    // (sigaction/getpid/kill-SIGABRT/exit-127 chain at 0x12722+)
    // with lr=0x1275B. 0x126C4 looks like __assert2 (formats then
    // aborts inline). Log r0-r3 + lr and try the C strings they
    // point to (file/expr/message name the failed assertion).
    // One-shot +1 spare. Remove once named.
    cpu.trap_pc_mem(0x0001_26C4, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                let mut ss = String::new();
                for (i, r) in [regs[0], regs[1], regs[2], regs[3]].iter().enumerate() {
                    let v = *r;
                    let s = if (0x1000..0xC000_0000).contains(&v) {
                        match mem.read(v, 48) {
                            Ok(b) => {
                                let z = b.iter().position(|&x| x == 0).unwrap_or(b.len());
                                format!("{:?}", String::from_utf8_lossy(&b[..z]))
                            }
                            Err(_) => String::from("<unmapped>"),
                        }
                    } else {
                        format!("{v:#x}")
                    };
                    ss.push_str(&format!(" r{i}={s}"));
                }
                eprintln!("ASSERT f={} lr={:#x} sp={:#x}{ss}", unsafe { FATIA_ATUAL }, regs[14], regs[13], ss = ss);
            }
        }
    });
    // Stack-guard note (init 0xA5E4, was 0xA6F4): the canary
    // check aborted boot until the Thumb-push rollback fix; it
    // passes genuinely now ([r0]==[r7]==guard, sp stable —
    // proven live linux356). Trap removed with the fix.
    // TEMP (flush runaway 0xC0046C50): release_console_sem's inner
    // scan increments r5 per byte looking for '\n'; the r5==r7
    // termination check sits outside the inner loop. If r5 runs past
    // r7 (no newline in range, corrupt indices), the scan never
    // reaches the drivers or the check — masked spin forever. Log
    // the first 5 runaways (r5, r7). Never firing kills this theory.
    // TEMP (USB flush complete 0xC0154E14): flush_endpoint_hw
    // initiates by writing mask to [QH+0x1B4], then polls for the
    // controller to clear ([r2+0x1B4] & r4, then +0x1B8) with
    // udelay(10M) between — a ~35M-instruction busy wait per
    // iteration that nothing clears (no USB engine modeled; QH
    // lives in vmalloc RAM, reads 0xFFFFFFFF forever). Lively
    // deadlock: ticks preempt the spin, so the system looks alive
    // (sched/wait progress) while init's workqueue flush never
    // drains. Host-side completion: write 0 to both status words
    // on every hit (uncapped — the loop must terminate the same
    // iteration), log first 3. Revisit with a real USB model.
    cpu.trap_pc_mem(0xC015_4E14, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let r5 = regs[5];
            let r2 = mem.read_u32(r5.wrapping_add(12)).unwrap_or(0xDEAD);
            let va = r2.wrapping_add(0x1B4);
            if N < 3 {
                N += 1;
                let n = N;
                let val = mem.read_u32(va).unwrap_or(0xDEAD);
                eprintln!("FLUSH#{n} f={} r5={r5:#x} r2={r2:#x} addr={va:#x} val={val:#x} (completing)", unsafe { FATIA_ATUAL });
            }
            let _ = mem.write_u32(va, 0);
            let _ = mem.write_u32(va.wrapping_add(4), 0);
        }
    });
    cpu.trap_pc_mem(0xC004_6C50, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if regs[5] > regs[7] && N < 5 {
                N += 1;
                let n = N;
                eprintln!("RUNAWAY#{n} f={} r5={:#x} r7={:#x}", unsafe { FATIA_ATUAL }, regs[5], regs[7]);
            }
        }
    });
    // TEMP (idle lateness 0xC002B2A4): msm_timer_enter_idle computes
    // r5 = wakeup - now and prints "late" when behind. Sample the
    // read result (r0 = msm_read_timer_count) + wakeup slot
    // ([[r4+0xC8]]) to see which side is frozen. Cap 12, gate
    // f >= 80000 (idle starts late-boot).
    cpu.trap_pc_mem(0xC002_B2A4, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if unsafe { FATIA_ATUAL } >= 80000 && N < 12 {
                N += 1;
                let n = N;
                let r4 = regs[4];
                let slot = mem.read_u32(r4.wrapping_add(0xC8)).unwrap_or(0xDEAD);
                let wake = mem.read_u32(slot).unwrap_or(0xDEAD);
                eprintln!("LATE#{n} f={} now={:#x} slot={slot:#x} wake={wake:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
    });
    // genl_init and friends? klog stops after neigh_init returns
    // (0xC0018FE4) with genl_init (0xC0019348) never logging.
    // Entry-fire (cap 2 each) separates "never called" (parked in
    // the initcall loop/schedule) from "entered and hung".
    for (va, nm) in [
        (0xC001_9348u32, "genl"),
        (0xC001_B120u32, "sysfs_ipv4"),
        (0xC001_BBD4u32, "bt"),
        (0xC001_C138u32, "sysctl"),
    ] {
        cpu.trap_pc_mem(va, move |_mem, _regs| {
            static mut N: u32 = 0;
            unsafe {
                if N < 2 {
                    N += 1;
                    eprintln!("NINITCALL f={} {}", unsafe { FATIA_ATUAL }, nm);
                }
            }
        });
    }
    // TEMP (calibrate_delay 0xC001C170): entered? returned?
    // Never entered = stuck BEFORE it (between console and calibrate).
    // Entered but never returns = measurement loop stuck.
    cpu.trap_pc_mem(0xC001_C170, move |_mem, regs| {
        static mut NCAL: u32 = 0;
        unsafe {
            NCAL += 1;
            let n = NCAL;
            if n <= 3 {
                eprintln!("CALIB#{n} f={} sp={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[13], regs[14]);
            }
        }
    });
    cpu.trap_pc_mem(0xC001_C2EC, move |_mem, _regs| {
        static mut NCALR: u32 = 0;
        unsafe {
            NCALR += 1;
            let n = NCALR;
            if n <= 3 {
                eprintln!("CALRET#{n} f={}", unsafe { FATIA_ATUAL });
            }
        }
    });
    // No low cap: prints every 2000 entries (volume) + whenever
    // count > 0x1000 (suspect). r8=[r0+48] is the loop bound.
    // TEMP (idle?): did cpu_idle run? Counter + lr. If the runqueue
    // stays empty forever (nothing runnable = init stuck), this
    // fires nonstop; if it never fires, something runs (slow).
    cpu.trap_pc_mem(0xC002_29F0, move |_mem, regs| {
        static mut NIDL: u32 = 0;
        unsafe {
            NIDL += 1;
            let n = NIDL;
            if n <= 3 || n % 20000 == 0 {
                eprintln!("IDLE#{n} f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    // TEMP (schedule_timeout entry 0xC02133D0): timeout value + who.
    // r0 = timeout (0x7FFFFFFF = infinite). Revived 2026-10-24: the
    // 57s wall parks init once in schedule_timeout (SCHED#173,
    // f≈103k, never returns) inside synaptics_ts_probe — the old
    // cap (12) died in the 1.48s era. Cap 300 + late stack dumps
    // (fresh counter) to name the exact wait.
    cpu.trap_pc_mem(0xC021_33D0, move |mem, regs| {
        static mut NSTO: u32 = 0;
        static mut NSTK: u32 = 0;
        unsafe {
            // Skip the early init/kthreadd handshake churn (f<80000).
            if FATIA_ATUAL >= 80000 && NSTO < 300 {
                NSTO += 1;
                let n = NSTO;
                let ti = regs[13] & !0x1FFF;
                let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                eprintln!("STIME#{n} f={} timeout={:#x} ti={ti:#x} task={task:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[14], regs[13]);
                // Late era: dump the waiter's stack so the return
                // chain above schedule_timeout names the exact wait.
                if unsafe { FATIA_ATUAL } >= 100000 && NSTK < 8 {
                    NSTK += 1;
                    let mut buf = vec![0u8; 192];
                    if mem.read(regs[13], 192).map(|s| buf.copy_from_slice(s)).is_ok() {
                        let words: Vec<String> = buf.chunks(4).map(|w| format!("{:02x?}", w)).collect();
                        eprintln!("SSTK-LATE f={} sp={:#x} {}", unsafe { FATIA_ATUAL }, regs[13], words.join(" "));
                    }
                }
            }
        }
    });
    // TEMP (run_posix entry CPSR 0xC005DF60): r3 holds the mrs
    // CPSR snapshot (I-bit at entry). #1 tick passes the BUG_ON,
    // #2 trips it — same code, so entry CPSR must differ. lr names
    // the scheduler_tick path. Cap 4.
    cpu.trap_pc_mem(0xC005_DF60, move |_mem, regs| {
        static mut NRP: u32 = 0;
        unsafe {
            if NRP < 4 {
                NRP += 1;
                let n = NRP;
                eprintln!("RPX#{n} f={} cpsr={:#x} I={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[3], (regs[3] >> 7) & 1, regs[14], regs[13]);
            }
        }
    });
    // TEMP (IRQ event entry 0xC006ED74): who calls handle_IRQ_event
    // (r0 = irq, lr = caller). Single VIDX but double ACT means the
    // second entry bypasses vector delivery — lr names the path
    // (handle_level_irq+0xA8 vs __do_IRQ vs other). Cap 4.
    cpu.trap_pc_mem(0xC006_ED74, move |mem, regs| {
        static mut NE: u32 = 0;
        unsafe {
            if NE < 4 {
                NE += 1;
                let n = NE;
                let st = mem.read_u32(regs[1].wrapping_add(4)).unwrap_or(0xDEAD);
                eprintln!("HIE#{n} f={} irq={:#x} desc={:#x} status={st:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14]);
            }
        }
    });
    // TEMP (edge entry 0xC0070810): who calls handle_edge_irq
    // (r0 = irq, lr = true caller). The previous trap sat on the
    // inner BL (0xC0070910), not the entry — lr only showed
    // intra-function flow. Entry lr separates dispatch
    // (asm_do_IRQ) from a vectorless resend replay. Cap 4.
    cpu.trap_pc_mem(0xC007_0810, move |_mem, regs| {
        static mut NG: u32 = 0;
        unsafe {
            if NG < 4 {
                NG += 1;
                let n = NG;
                eprintln!("EDGE#{n} f={} irq={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[14]);
            }
        }
    });
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (dispatch entry 0xC0021000): who enters asm_do_IRQ.
    // Legit vector entries arrive via the two bne sites (0xC0021640
    // SVC / 0xC0021860 USR); anything else (loop-back, direct jump)
    // shows here. Plus the top 8 stack words: identical frames
    // across both ticks would mean the same parked thread re-enters
    // the same way. Cap 4.
    cpu.trap_pc_mem(0xC002_1000, move |mem, regs| {
        static mut ND: u32 = 0;
        unsafe {
            if ND < 4 {
                ND += 1;
                let n = ND;
                let mut st = [0u32; 8];
                for (i, s) in st.iter_mut().enumerate() {
                    *s = mem.read_u32(regs[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                }
                eprintln!("DISPIRQ#{n} f={} irq={:#x} lr={:#x} sp={:#x} stk={st:#x?}", unsafe { FATIA_ATUAL }, regs[0], regs[14], regs[13]);
            }
        }
    });
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (USR dispatch entry 0xC0021800): log entries via the USR
    // stub copy (untrapped until now: VIDX/DISP watch only the SVC
    // path). If tick #2 enters here, the vector stub routes by mode
    // and the SVC-only probes were blind to it. Cap 4.
    cpu.trap_pc_mem(0xC002_1800, move |_mem, regs| {
        static mut NU: u32 = 0;
        unsafe {
            if NU < 4 {
                NU += 1;
                let n = NU;
                eprintln!("UIRQ#{n} f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (resend check 0xC006FCB0): log check_irq_resend entries
    // (r0 = desc, r1 = irq). A PENDING+enable_irq replay would call
    // desc->handle_irq in process context (I=0) with no vector,
    // no entra, no VIDX — exactly tick #2's signature. Cap 4.
    cpu.trap_pc_mem(0xC006_FCB0, move |_mem, regs| {
        static mut NR: u32 = 0;
        unsafe {
            if NR < 4 {
                NR += 1;
                let n = NR;
                eprintln!("RESEND#{n} f={} desc={:#x} irq={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14]);
            }
        }
    });
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (dispatch branches 0xC0021640/0xC0021860): log the two
    // bne sites into asm_do_IRQ (r0 = VECT number). If tick #2
    // reaches asm_do_IRQ (DISPIRQ#2 fires) without either branch
    // firing, entry is non-branching (computed jump / return
    // landing). Cap 4.
    for bne_site in [0xC002_1640u32, 0xC002_1860] {
        cpu.trap_pc_mem(bne_site, move |_mem, regs| {
            static mut NB: u32 = 0;
            unsafe {
                if NB < 4 {
                    NB += 1;
                    let n = NB;
                    eprintln!("BNE#{n} f={} site={:#x} r0={:#x}", unsafe { FATIA_ATUAL }, bne_site, regs[0]);
                }
            }
        });
    }
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (preempt BUG entry 0xC0212EF8): the sched.c:4032 BUG_ON
    // fires when (preempt_count != 0) OR (I == 0). Log CPSR snapshot
    // (r3, from the mrs) + [ti+4] preempt count (ti in r5) + caller.
    // Distinguishes an IRQs-on entry from a corrupted count. Cap 4.
    cpu.trap_pc_mem(0xC021_2EF8, move |mem, regs| {
        static mut NPB: u32 = 0;
        unsafe {
            if NPB < 4 {
                NPB += 1;
                let n = NPB;
                let ti = regs[5] & !0x1FFF;
                let pcnt = mem.read_u32(ti.wrapping_add(4)).unwrap_or(0xDEAD);
                eprintln!("PREBUG#{n} f={} cpsr={:#x} I={} preempt={:#x} ti={ti:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[3], (regs[3] >> 7) & 1, pcnt, regs[14]);
            }
        }
    });
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (preempt entry 0xC0212EEC): log CPSR snapshot (r3, just
    // mrs'd) + [ti+4] preempt count (ti in r5) + caller, on EVERY
    // preempt_schedule_irq entry. The sched.c:4032 BUG fires when
    // (count != 0) or (I == 0); this shows which one, and what the
    // healthy entries look like. Cap 8.
    cpu.trap_pc_mem(0xC021_2EEC, move |mem, regs| {
        static mut NPEE: u32 = 0;
        unsafe {
            if NPEE < 8 {
                NPEE += 1;
                let n = NPEE;
                let ti = regs[5] & !0x1FFF;
                let pcnt = mem.read_u32(ti.wrapping_add(4)).unwrap_or(0xDEAD);
                eprintln!("PREENT#{n} f={} cpsr={:#x} I={} preempt={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[3], (regs[3] >> 7) & 1, pcnt, regs[14]);
            }
        }
    });
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (svc_preempt entry 0xC002166C): who calls it (lr) + r8
    // (the teq operand: nonzero skips everything). No static BL/B
    // caller exists in the image, so the invoker arrives by
    // fall-through or computed jump — lr names it. Cap 4.
    cpu.trap_pc_mem(0xC002_166C, move |_mem, regs| {
        static mut NSV: u32 = 0;
        unsafe {
            if NSV < 4 {
                NSV += 1;
                let n = NSV;
                eprintln!("SVCPRE#{n} f={} r8={:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[8], regs[14], regs[13]);
            }
        }
    });
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    // TEMP (IRQ action walk 0xC006EDAC): log every action->handler
    // call (r4 = action, r0 = irq, r1 = dev_id). Single VIDX but
    // double TICKH means the chain runs the timer handler twice in
    // one dispatch — or two actions share the IRQ. Cap 8.
    cpu.trap_pc_mem(0xC006_EDAC, move |mem, regs| {
        static mut NA: u32 = 0;
        unsafe {
            if NA < 8 {
                NA += 1;
                let n = NA;
                let h = mem.read_u32(regs[4]).unwrap_or(0xDEAD);
                let nx = mem.read_u32(regs[4].wrapping_add(20)).unwrap_or(0xDEAD);
                eprintln!("ACT#{n} f={} irq={:#x} dev={:#x} action={:#x} handler={h:#x} next={nx:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[4]);
            }
        }
    });
    // TEMP (program_event args 0xC0064814): log entry args (r0-r3)
    // + caller + live COUNT/MATCH + fail-latch flag + jiffies.
    // Cap 6 + every 20000th: the loop runs hundreds of thousands
    // of iterations and the first calls can't show whether the
    // expiry keeps accumulating or resets. r2 trajectory + FLAG
    // decides stale-base vs racing-now.
    // EXTENDED 2026-10-24: consecutive window n<=30 — the
    // disassembly advances next by [0xC02EAA48] every retry, yet the
    // 20000th samples look frozen. Consecutive r2 decides whether
    // next churns +10M/call (now must race ahead) or sits still
    // ([AA48] zeroed/stale).
    cpu.trap_pc_mem(0xC006_4814, move |mem, regs| {
        static mut NPE: u32 = 0;
        unsafe {
            NPE += 1;
            let n = NPE;
            if n <= 30 || n % 20000 == 0 {
                let s0 = mem.read_u32(regs[13]).unwrap_or(0xDEAD);
                let s1 = mem.read_u32(regs[13].wrapping_add(4)).unwrap_or(0xDEAD);
                let tc = mem.read_u32(0xE000_1004).unwrap_or(0xDEAD);
                let tm = mem.read_u32(0xE000_1000).unwrap_or(0xDEAD);
                let fl = mem.read_u32(0xC02E_AA28).unwrap_or(0xDEAD);
                let jf = mem.read_u32(0xC02A_B638).unwrap_or(0xDEAD);
                let g0 = mem.read_u32(0xC02E_AA48).unwrap_or(0xDEAD);
                let g1 = mem.read_u32(0xC02E_AA48 + 4).unwrap_or(0xDEAD);
                eprintln!("PROGEV#{n} f={} r0={:#x} r1={:#x} r2={:#x} r3={:#x} [sp]={s0:#x}+{s1:#x} COUNT={tc:#x} MATCH={tm:#x} FLAG={fl:#x} jif={jf:#x} GLOB={g1:#x}{g0:08x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[3], regs[14]);
            }
            // Keep the clockevent device state consistent with the
            // forced success below (TICKBRK): the host plant writes
            // MATCH directly, bypassing set_next_event, so
            // dev->next_event (dev+0x40, 8 bytes — the ldrd slot the
            // tick loop re-reads every invocation) freezes in the
            // past and every deadline, incl. idle's, computes late.
            // Mirror a successful programming: next_event = passed
            // expiry (r2/r3) PLUS one tick period (0x989680) of lead.
            // The lead is load-bearing: now advances a whole jiffy
            // per processed tick (jiffy-quantized ktime, no
            // clocksource), so parity E == now never breaks without
            // it; +10M lead makes delta positive and program_event
            // succeed for real. Arithmetic mimics the guest's own
            // normalization (low < 1e9 invariant via the 2^32-1e9
            // wrap). Uncapped: runs on every call, logs stay sampled
            // above.
            {
                let dev = regs[0];
                let (mut nl, mut nh) = (regs[2].wrapping_add(0x989680), regs[3]);
                nh = nh.wrapping_add((nl < regs[2]) as u32);
                if nl >= 0x3B9A_CA00 {
                    let (w, c) = nl.overflowing_add(0xC465_3600);
                    nl = w;
                    nh = nh.wrapping_add(c as u32);
                }
                let _ = mem.write_u32(dev.wrapping_add(0x40), nl);
                let _ = mem.write_u32(dev.wrapping_add(0x44), nh);
            }
        }
    });
    // TEMP (scheduler_tick 0xC0040394): entry count + caller. If it
    // stays ~1, the first tick never returned (loop inside). If it
    // grows unbounded, lr names the caller.
    // TEMP (update_process_times 0xC0050EF0): who calls it in a loop?
    // SCHTICK shows 1.4M+ scheduler_tick via fixed lr inside
    // update_process_times; this trap's lr picks which of the 3
    // tick_* callers drives it.
    cpu.trap_pc_mem(0xC005_0EF0, move |_mem, regs| {
        static mut NUP: u32 = 0;
        unsafe {
            NUP += 1;
            let n = NUP;
            if n <= 3 || n % 20000 == 0 {
                eprintln!("UPTIME#{n} f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    // TEMP (tick re-arm 0xC0065164): force RESTORED 2026-10-24 —
    // the observe-only run proved program_event NEVER succeeds
    // alone (permanent -ETIME, frozen MATCH, dead boot: only 28
    // klog lines, guest time dragged by the watchdog to a 335s
    // posix BUG). regs[0]=0 lets the retry loop exit so ticks
    // complete and boot progresses (healthy 10ms guest-driven
    // MATCH deltas observed with it). The NESTED-delivery hazard
    // this force enables is now covered by the `pode_irq` mode gate
    // in the backend (no delivery into IRQ/FIQ/ABT/UND). Revisit
    // both once past /init.
    cpu.trap_pc_mem(0xC006_5164, move |mem, regs| {
        static mut NBR: u32 = 0;
        unsafe {
            NBR += 1;
            let n = NBR;
            if n <= 10 || n % 20000 == 0 {
                let tm = mem.read_u32(0xE000_1000).unwrap_or(0xDEAD);
                let tc = mem.read_u32(0xE000_1004).unwrap_or(0xDEAD);
                eprintln!("TICKBRK#{n} f={} was_r0={:#x} MATCH={tm:#x} COUNT={tc:#x} (forced success + mode gate)", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
        regs[0] = 0;
    });
    cpu.trap_pc_mem(0xC004_0394, move |_mem, regs| {
        static mut NST: u32 = 0;
        unsafe {
            NST += 1;
            let n = NST;
            if n <= 3 || n % 20000 == 0 {
                eprintln!("SCHTICK#{n} f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xC005_FA9C, move |_mem, regs| {
        static mut NK2: u32 = 0;
        unsafe {
            NK2 += 1;
            let n = NK2;
            if n <= 3 || n % 20000 == 0 {
                eprintln!("KTG#{n} f={} lr={:#x} sp={:#x} r0={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13], regs[0]);
            }
        }
    });
    cpu.trap_pc_mem(0xC005_FA40, move |_mem, regs| {
        static mut NK: u32 = 0;
        unsafe {
            NK += 1;
            let n = NK;
            if n <= 3 || n % 20000 == 0 {
                eprintln!("KTS#{n} f={} lr={:#x} sp={:#x} r0={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13], regs[0]);
            }
        }
    });
    // stalls INSIDE one call (seqlock?), the count stops ~1 and the
    // loop is below; if it climbs forever, lr names the loop.
    cpu.trap_pc_mem(0xC006_1E78, move |_mem, regs| {
        static mut NG: u32 = 0;
        unsafe {
            NG += 1;
            let n = NG;
            if n <= 3 || n % 20000 == 0 {
                eprintln!("GNTOD#{n} f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xC006_2624, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            N += 1;
            let n = N;
            let cnt = mem.read_u32(regs[0].wrapping_add(48)).unwrap_or(0xDEAD);
            if n <= 4 || n % 20000 == 0 || (cnt != 0xDEAD && cnt > 0x1000) {
                let nm = mem.read_u32(regs[6]).unwrap_or(0xDEAD);
                eprintln!("TABHUNT#{n} f={} r0={:#x} r1={:#x} r2={:#x} r4={:#x} r6={:#x} [r6]={nm:#x} count={cnt:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[4], regs[6], regs[14], regs[13]);
            }
        }
    });
    // Prints every 2000 (volume) + lr (caller).
    cpu.trap_pc_mem(0xC010_8074, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            N += 1;
            if N == 1 || N % 2000 == 0 {
                let n = N;
                eprintln!("VSNPRINTF n={n} f={} lr={:#x}", unsafe { FATIA_ATUAL }, regs[14]);
            }
        }
    });
    // The frame (r0=0xC8301000) has [r0+16]=return lr (pc+4 of the
    // interrupted one) and [r0+8]=SPSR (old direct, no inference).
    cpu.trap_pc_mem(0xC002_1800, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 3 {
                N += 1;
                let n = N;
                let fr = regs[0];
                let lr_sv = mem.read_u32(fr.wrapping_add(16)).unwrap_or(0xDEAD);
                let spsr_sv = mem.read_u32(fr.wrapping_add(8)).unwrap_or(0xDEAD);
                eprintln!("USRIN#{n} f={} sp={:#x} fp={:#x} lr={:#x} r0={:#x} frame_lr={lr_sv:#x} frame_spsr={spsr_sv:#x}", unsafe { FATIA_ATUAL }, regs[13], regs[11], regs[14], regs[0]);
            }
        }
    });
    cpu.trap_pc_mem(0xC00F_ECA4, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                eprintln!("CALLEE f={} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xFFFE_00E4, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                let mut c = vec![0u8; 32];
                let ok = mem.read(0xFFFE_00E4, 32).map(|s| c.copy_from_slice(s)).is_ok();
                eprintln!("CRASH f={} lr={:#x} sp={:#x} r0={:#x} r1={:#x} ok={ok} code={c:02x?}", unsafe { FATIA_ATUAL }, regs[14], regs[13], regs[0], regs[1]);
            }
        }
    });
    cpu.trap_pc_mem(0xC001_C20C, move |_mem, _regs| {
        static mut N: u32 = 0;
        unsafe {
            N += 1;
            let n = N;
            if n == 1 || n % 500000 == 0 {
                eprintln!("KEXIT n={n}");
            }
        }
    });
    cpu.trap_pc_mem(0xC001_C1F0, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            N += 1;
            let n = N;
            if n % 200000 == 1 {
                eprintln!("KLOOP#{n} r2={:#x} r1={:#x}", regs[2], regs[1]);
            }
        }
    });
    // KENTRY dumps the first bytes at 0x10008000 when the
    // jump lands (zeros = mirror failed).
    // KDC shows what is at 0x100082DC *now* (the zImage may have
    // been overwritten with the decompressed kernel). Cap 2.
    // Parked kernel (vmlinux __error): who calls and with what (cap 2).
    cpu.trap_pc_mem(0x1000_82DC, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 2 {
                N += 1;
                eprintln!("KDC lr={:#x} r0={:#x} r1={:#x}", regs[14], regs[0], regs[1]);
            }
        }
    });
    // IRQ delivery (MSM VIC at 0xE0000000). The line is a pure
    // function of guest-visible device state, so the CPU can poll it
    // between instructions; the kernel's ack (MATCH reprogram)
    // drops it inside the same slice.
    cpu.set_fonte_irq(|mem, livre| deve_entregar(mem, livre));
    // get_irqnr_and_base (entry-macro.S, both __irq_svc and __irq_usr
    // copies in this vmlinux): `ldr r0,[r5,#0xD0]; ldr r0,[r5,#0xD4];
    // cmn r0,#1` -> plant the pending IRQ number right before the D4
    // load executes. LEVEL (vic_nivel), never the latched line: the
    // latch is already consumed by the time dispatch runs, and the
    // plant would serve "no IRQ" into a live delivery (that ate every
    // TICKH before the split). 0xFFFFFFFF when idle.
    for ldr_d4 in [0xC002_1630u32, 0xC002_1850] {
        cpu.trap_pc_mem(ldr_d4, |mem, _regs| {
            let v = vic_nivel(mem).unwrap_or(u32::MAX);
            let _ = mem.write(0xE000_00D4, &v.to_le_bytes());
        });
    }
    cpu.trap_pc_mem(0x1000_8000, move |mem, regs| {
        let mut b = vec![0u8; 64];
        let ok = mem.read(0x1000_8000, 64).map(|s| b.copy_from_slice(s)).is_ok();
        eprintln!(
            "KENTRY ok={ok} r0={:#x} r1={:#x} r2={:#x} r3={:#x} bytes={b:02x?}",
            regs[0], regs[1], regs[2], regs[3]
        );
    });
    // Kernel serial out: the bytes the UART console writes to THR
    // `[base+0x0C]` (the three UARTs of the static map). Polling per
    // slice with drain (prints + zeroes): independent of the
    // `putc` address (the earlier `0xC01396E0` was list code, not
    // UART — never fired). TX-ready (`[base+8]` bit 2) is
    // planted in the block below. Accumulates into `kernel_tx`.
    let kernel_tx = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
    let kernel_txb = kernel_tx.clone();
    // (trap_pc_mem at the old address removed: wrong address.)
    // Linux-handoff snapshot: r0-r3 + ATAG head at the trampoline
    // entry (`0x88015240`, before `mov pc, r3` at `0x880152A4`).
    // Proves the machine ID (r1, expect trout 1440) and the ATAG list
    // (NONE placement decides what the kernel sees) on a live run.
    let regs_saida = std::rc::Rc::new(std::cell::Cell::new([0u32; 4]));
    let regs_saida_b = regs_saida.clone();
    let atags = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
    let atags_b = atags.clone();
    cpu.trap_pc_mem(0x8801_5240, move |mem, regs| {
        regs_saida_b.set([regs[0], regs[1], regs[2], regs[3]]);
        let mut tag = vec![0u8; 1024];
        if mem.read(0x8000_0100, 1024).map(|s| tag.copy_from_slice(s)).is_ok() {
            *atags_b.borrow_mut() = tag;
        }
        // ATAG mirror into the physical bank: SetupTAG writes the
        // list at VA `0x80000100`, but the kernel reads it through
        // the physical alias (PA `0x10000100` -> VA `0xC0000100`,
        // phys_to_virt +0xB0000000). Guest stores are not mirrored
        // (only served loads mirror), so without this the kernel
        // sees zeros: bad configuration page + default-list parse.
        // Mirror one page (the observed list is ~2.6 KiB with WIFI;
        // the walk stops at ATAG_NONE, the rest is never read;
        // `0x10001100` is far below the zImage at `0x10008000`).
        // Do NOT plant ATAG_MEM: the trout kernel deletes it
        // (`0xBD80`) once the fixup defined banks.
        {
            let mut pagina = vec![0u8; 0x1000];
            if mem.read(0x8000_0100, 0x1000).map(|s| pagina.copy_from_slice(s)).is_ok() {
                let okw = mem.write(0x1000_0100, &pagina).is_ok();
                let v0 = mem.read_u32(0x1000_0100).unwrap_or(0xDEAD);
                let v1 = mem.read_u32(0x1000_0104).unwrap_or(0xDEAD);
                eprintln!("ATAGMIRR okw={okw} pa0={v0:#x} pa1={v1:#x}");
            }
        }
        // ATAG VA re-plant (per boot): boot 1's mm init legitimately
        // reuses the ATAG page (bootmem + INIT_LIST_HEAD at
        // `0xC0000100`, caught live), so a rebooted guest would read
        // stale content from the persisting demand-mapped VA page
        // even though the PA mirror above is fresh. Re-plant the
        // just-snapshotted 1 KiB list at VA `0xC0000100` (mapping it
        // first if this boot hasn't faulted it in yet); the kernel
        // parses it before any reuse, same as on hardware.
        {
            let tag = atags_b.borrow().clone();
            if !tag.is_empty() {
                let _ = mem.map_zeroed("atags_fresco", 0xC000_0000, 0x1000);
                let _ = mem.write(0xC000_0100, &tag);
            }
        }
    // TEMP (serve check): FNV of the zImage served at 0x80008000
        // the serve (pagina0) corrupted the zImage and the
        // decompressed kernel is born broken.
        static mut NFNV: u32 = 0;
        unsafe {
            if NFNV < 1 {
                NFNV += 1;
                let mut h: u32 = 0x811C_9DC5;
                let mut ok = true;
                let mut off = 0u32;
                while off < 0x153004 {
                    let mut b = [0u8; 2048];
                    let n = 2048.min(0x153004 - off as usize);
                    if mem.read(0x8000_8000 + off, n as u32).map(|s| b[..n].copy_from_slice(s)).is_err() {
                        ok = false;
                        break;
                    }
                    for i in 0..n {
                        h = h ^ b[i] as u32;
                        h = h.wrapping_mul(0x0100_0193);
                    }
                    off += n as u32;
                }
                eprintln!("SERVFNV ok={ok} fnv={h:#x} (expected 0xa9d4b489)");
            }
        }
    });
    // TEMP (ATAG cmdline expand, one-shot at handoff 0x88015244):
    // force periodic ticks via `nohz=off highres=off` (retire the
    // host re-arm) plus `initcall_debug` (name the post-RTC hang:
    // the kernel then logs every initcall entry+return). The CMDLINE
    // tag has only 4 free bytes but the suffix needs 38. Shift the
    // tail ([0x144..NONE] inclusive) down 64 bytes, grow CMDLINE
    // 75->91 words, append. The kernel walks tags sequentially so
    // absolute offsets don't matter. Applies to VA src, PA mirror,
    // and VA kernel copy.
    cpu.trap_pc_mem(0x8801_5244, move |mem, _regs| {
        static mut NAT: u32 = 0;
        unsafe {
            if NAT < 1 {
                NAT += 1;
                let sufixo = b" nohz=off highres=off initcall_debug init=/init";
                // Locate CMDLINE tag and list end.
                let (mut coff, mut csz) = (0u32, 0u32);
                let (mut fim, mut off) = (0u32, 0u32);
                for _ in 0..32 {
                    let base = 0x8000_0100u32.wrapping_add(off);
                    let sz = mem.read_u32(base).unwrap_or(0);
                    let id = mem.read_u32(base.wrapping_add(4)).unwrap_or(0);
                    eprintln!("ATAG off={off:#x} size={sz} id={id:#x}");
                    if sz == 0 || id == 0 || off > 0x800 {
                        fim = off + 8;
                        break;
                    }
                    if id == 0x5441_0009 {
                        coff = off;
                        csz = sz;
                    }
                    off += sz * 4;
                }
                if csz == 75 {
                    // Log the ORIGINAL cmdline once (provenance: what the
                    // SPL built — root=/console=/init= live here).
                    {
                        let mut cur0 = vec![0u8; 320];
                        let _ = mem.read(0x8000_0100 + coff + 8, 320).map(|s| cur0.copy_from_slice(s));
                        eprintln!("ATAGCMD0 orig={:?}", String::from_utf8_lossy(&cur0));
                    }
                    // Read tail [coff_end .. fim), shift +32, grow tag.
                    let ini = 0x8000_0100u32.wrapping_add(coff + csz * 4);
                    let mut cauda = vec![0u8; (fim - (coff + csz * 4)) as usize];
                    let ok = mem.read(ini, cauda.len() as u32).map(|s| cauda.copy_from_slice(s)).is_ok();
                    // Current string (for the append base).
                    let cap0 = (csz as usize) * 4 - 8;
                    let mut cur = vec![0u8; cap0.min(512)];
                    let okr = mem.read(0x8000_0100 + coff + 8, cur.len() as u32).map(|s| cur.copy_from_slice(s)).is_ok();
                    let fim0 = cur.iter().position(|&c| c == 0).unwrap_or(cur.len());
                    let mut nova = cur[..fim0].to_vec();
                    nova.extend_from_slice(sufixo);
                    nova.push(0);
                    eprintln!("ATAGCMD cap0={cap0} len={fim0} ok={okr} newlen={} tailbytes={} okread={ok}", nova.len() - 1, cauda.len());
                    if ok && okr && nova.len() <= (csz as usize + 16) * 4 - 8 {
                        // Shift tail down 64 B in all three mappings,
                        // grow CMDLINE 75 -> 91 words, write new string.
                        for b in [0x8000_0100u32, 0x1000_0100, 0xC000_0100] {
                            let _ = mem.write_u32(b + coff, csz + 16);
                            let _ = mem.write(b + coff + csz * 4 + 64, &cauda);
                            let w = mem.write(b + coff + 8, &nova).is_ok();
                            eprintln!("ATAGSFT base={b:#x} w={w}");
                        }
                    }
                }
            }
        }
    });
    // NAND flash-write capture (`0x88008F80`: r0 = NAND byte addr, r1 =
    // RAM source, r2 = length). Writes through into the shared NAND
    // buffer (addr->image-offset page math, entry-8 geometry) so a
    // reboot boots flashed content; `--salvar-nand` persists it. Does
    // NOT skip the guest writer (the normal-boot MISC writethroughs
    // run fine on stubs; NBH item flashes haven't been seen yet).
    // Cap 8 on the log.
    let nand_w = nand.clone();
    let conta_w = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let conta_wb = conta_w.clone();
    cpu.trap_pc_mem(0x8800_8F80, move |mem, regs| {
        let (addr, src, len) = (regs[0], regs[1], regs[2] as usize);
        if conta_wb.get() < 8 {
            eprintln!(
                "FLASH#{n} addr={addr:#x} src={src:#x} len={len:#x}",
                n = conta_wb.get(),
            );
            conta_wb.set(conta_wb.get() + 1);
        }
        if (0x500C_0000..0x5100_0000).contains(&addr) && len > 0 && len <= 0x80000 {
            let mut img = nand_w.borrow_mut();
            let mut a = addr;
            let mut s = src;
            let mut resto = len;
            while resto > 0 {
                let bloco = 0x126 + (a - 0x500C_0000) / 0x20000;
                let base_bloco = 0x500C_0000 + (bloco - 0x126) * 0x20000;
                let pagina = ((a - base_bloco) / 2048) as usize;
                let off_pag = ((a - base_bloco) % 2048) as usize;
                let cabe = (2048 - off_pag).min(resto);
                let off = bloco as usize * 135168 + pagina * 2112 + off_pag;
                if off + cabe > img.len() {
                    break;
                }
                let dados = match mem.read(s, cabe as u32) {
                    Ok(d) => d.to_vec(),
                    Err(_) => break,
                };
                img[off..off + cabe].copy_from_slice(&dados);
                a += cabe as u32;
                s += cabe as u32;
                resto -= cabe;
            }
        }
    });
    // (O) splash→fb blit — ANSWERED: 0x80200000→0xA6C00000 x0x4B000
    // (lr=0x88027274); BLITMAP proved the source holds the asset at
    // blit time; a second loader run (src 0x50200000, AA blocks)
    // overwrites fb — patching both images yields pixel-perfect fb
    // (verified byte-identical + rendered PNG).
    // (O2)/(M)/(J)/(J2)/(J3) one-shot probes — all ANSWERED and
    // removed (trap registrations deleted with them): SPLR (loader
    // returns 1 = fail, blits anyway), MAGIC (ANDROID! match after
    // patching guest block 0x136), SPIN2 (r0=0xB2600000 display UART),
    // WAIT2/EXITA (r4=0xB2800000, caller discards return → exit-A
    // forcing is safe). The plants they motivated stay in the Budget
    // arm below.
    // (L) TX-ring channel probe — ANSWERED: r0=0x3 (channel 3, the
    // already-drained channel). Probe hook removed; the stall was the
    // UART `[+20]` completion bit, planted per slice below.
    // Phase 2 with host ring-drain (TODO item 2 in action): run bounded
    // slices; after each, the host acts as the UART consumer for channel
    // 3 — advance the read index to the write index and clear the
    // blocked/full flag (`+8`). The tap already captures every byte via
    // the PUTC trap; the drain is purely flow control so the guest never
    // spins on a full ring. Ends on the first non-Budget stop.
    let mut parada = StopReason::Budget;
    // Guest-paced timer counts (GPT +4/slice at `0xE0001004`, DGT +72
    // at `0xE0001014`, same 18.3x ratio as the 32768 Hz / 600 kHz
    // hardware): the kernel's `msm_read_timer_count` returns when two
    // consecutive reads agree but its callers need advance across
    // trips — per-slice plants give exactly that (stable within a
    // slice, advancing between). WALL-CLOCK pacing (the old
    // `epoca`-based plant) outruns the emulated guest: every fresh
    // MATCH is already in the past, so clockevents_program_event
    // returns -ETIME forever (the 1.4M-iteration catch-up), the level
    // never drops, desc IRQ_PENDING sticks, and a resend replay runs
    // the tick handler in process context (I=0) -> BUG_ON. With
    // guest pacing, MATCH = COUNT + ~327 lands ~80 slices out:
    // program_event succeeds, the level drops until COUNT catches
    // up, ticks go periodic (~85/s at 7k slices/s), RCU advances.
    static mut CONTAGEM_GPT: u32 = 0;
    static mut CONTAGEM_DGT: u32 = 0;
    // First completion of a real GPT tick (STATUS 1->0 while enabled).
    // Watchdog, NOT one-shot kill: a single MATCH reprogram (one-shot
    // arm) used to kill the fallback forever, freezing jiffies while
    // masked spins waited on time that never came (proven live:
    // 1 tick, MATCH frozen, IRQLINHA 100% MASK). The fallback returns
    // if no tick completes in the last 2000 slices; with real
    // periodic ticks (~100 slices) it never fires (no double).
    let mut ultimo_tick: Option<u32> = None;
    // Accumulated ring output (bulk path bypasses PUTC, so the tap never
    // sees it): drained bytes per slice via `anel_bytes_novos`.
    let mut saida: Vec<u8> = Vec::new();
    // Current slice number, mirrored for TEMP traps (boot-attribution).
    #[allow(non_upper_case_globals)]
    static mut FATIA_ATUAL: u32 = 0;
    // 2k-instruction slices (see the loop bound below): host drains +
    // watches every slice; short enough that a fill-then-clear of a
    // device slot across different slices is caught (a same-slice
    // fill+clear would still hide — see note below).
    let mut limpezas = 0u32;
    let mut leituras: Vec<(u32, u32, u32)> = Vec::new();
    let mut objeto_encontrado: Option<(u32, u32)> = None;
    // NAND-slot lifecycle: the producer (0x88021198) demonstrably runs
    // (its entry prints are in the tap, no 'Can't get memory' loop), so
    // its stores should fill these — yet they read 0 post-run. Track the
    // first nonzero (filler) and the first return to zero (clearer).
    let mut nand_preenchido: Option<(u32, u32)> = None;
    let mut nand_limpo: Option<(u32, u32)> = None;
    // Demand-mapped pages (see MemoryFault arm): a repeat fault inside
    // one means "needs behavior, not memory" and stops the run instead.
    let mut mapeadas: Vec<u32> = Vec::new();
    // Kernel-VA pages (0xC0000000+): uncapped — the kernel faults in
    // megabytes legitimately; repeats still stop the run.
    let mut mapeadas_kern: Vec<u32> = Vec::new();
    // User-VA pages resolved via the guest page tables (TTBR0 walk):
    // uncapped — the ELF loader maps /init's segments, stack and
    // brk page by page; repeats still stop the run.
    let mut mapeadas_usr: Vec<u32> = Vec::new();
    // User pages already handed to the guest's abort handler: a
    // same-(page, pc) fault AFTER a delivery means the guest
    // retried without a visible fix. Allow a handful per (page,
    // pc) — recurring legitimate faults (kernel uaccess fixup
    // returns -EFAULT and the caller moves on; a later retry or
    // a different copy phase refaults) must proceed; a tight
    // livelock burns the budget fast and still stops. (Page-only
    // keying stopped linux328's 0xBEC0A000 kernel-copy fault on a
    // legitimate second touch.)
    let mut abortadas: Vec<((u32, u32), u32)> = Vec::new();
    // Host frame hook watermarks: serial bytes already handed out.
    let mut tap_marca = 0usize;
    // TEMP/RX work: separate watermark for tap channel 0 (line-input
    // echoes; see the `novos` assembly below).
    let mut tap_marca_c0 = 0usize;
    let mut saida_marca = 0usize;
    // Slice count and size used to be hardcoded (200k x 2k: the
    // post-wlan phase is straight-line silent init, hundreds of
    // bl+delay steps with no prints, and each slice advances a
    // single outer delay iteration — so slice cost is almost pure
    // spin waste; 2k slices waste 25x less than 50k for the same
    // outer progress; host per-slice work is microseconds).
    for fatia in 0..max_fatias {
        unsafe { FATIA_ATUAL = fatia; }
        match cpu.run(pc, instrs_por_fatia).unwrap() {
            StopReason::Budget => {
                // Preserve Thumb across slices: run() sets T from pc
                // bit0, and Thumb pcs are even — a bare read would
                // resume ARM and mis-execute Thumb userspace.
                let thumb = cpu.estado_completo().1 & 0x20 != 0;
                pc = cpu.read_reg(crate::cpu::Reg::Pc) | if thumb { 1 } else { 0 };
                // Host drain for channel 3 (slot `0x882A94FC + 3*16`,
                // data at constant `0x882A24FC + 3*4 KiB`).
                let slot = 0x882A_952C;
                if let (Ok(leitura), Ok(escrita)) =
                    (cpu.read_u32(slot), cpu.read_u32(slot + 4))
                {
                    if escrita != leitura {
                        let mut dados = vec![0u8; 0x1000];
                        if cpu
                            .read_mem(0x882A_24FC + 3 * 0x1000, &mut dados)
                            .is_ok()
                        {
                            saida.extend_from_slice(
                                &crate::msm7201a_serial::anel_bytes_novos(
                                    leitura as usize,
                                    escrita as usize,
                                    &dados,
                                    0x1000,
                                ),
                            );
                        }
                    }
                    let _ = cpu.write_u32(slot, escrita);
                    let _ = cpu.write_u32(slot + 8, 0);
                    limpezas += 1;
                    // Dispatcher-slot watch (`0x882F1EB4`, pool
                    // `0x88008450`): the `0x88008238` virtual call faults
                    // wild because this slot is never filled on the run
                    // path. Record the first nonzero value (with the PC);
                    // the phase-2 memset only ever writes zero, so any
                    // nonzero is the real writer.
                    if objeto_encontrado.is_none() {
                        if let Ok(valor) = cpu.read_u32(0x882F_1EB4) {
                            if valor != 0 {
                                objeto_encontrado = Some((pc, valor));
                            }
                        }
                    }
                    // NAND-slot lifecycle (`0x882F4560`): the producer
                    // demonstrably runs (entry prints in tap, no malloc
                    // fail loop), so record the first nonzero (filler)
                    // and the first return to zero (clearer), with pcs.
                    if let Ok(valor) = cpu.read_u32(0x882F_4560) {
                        if valor != 0 && nand_preenchido.is_none() {
                            nand_preenchido = Some((pc, valor));
                        } else if valor == 0
                            && nand_preenchido.is_some()
                            && nand_limpo.is_none()
                        {
                            nand_limpo = Some((pc, valor));
                        }
                    }
                    // Transfer-complete flag (decoded 0x88020AD4 poll): it
                    // spins at `0x88020B18` while `[0x882A091C+32] == 0`.
                    // No DMA completion ever queues it (channels sit in
                    // state 10, consumer never runs), so the host plants
                    // "done" every slice; the run then takes the fail
                    // path (`...results indicate failed transaction`),
                    // the next frontier. Race-free: the poll reads it
                    // every pass and nothing else clears it.
                    let _ = cpu.write_u32(0x882A_091C + 32, 1);
                    // Template gate (decoded 0x88023800 kick path): the
                    // kick `str` runs only when `[entry+0x14] == 0`
                    // (`mov r4, #0` at `0x88023828`, then `ldr r3,
                    // [r5,#20]; cmp r3, r4; bne skip` at
                    // `0x8802383C-44` — the comparison is against the
                    // just-zeroed r4, NOT against ctl as first assumed;
                    // planting ctl actively wedged the gate shut).
                    // Entry = `0x882F79EC + [ctl+4]*268 + 0x3C`. Stub
                    // init leaves the entries non-zero (busy/owned), so
                    // every kick is skipped and all NAND reads fail
                    // without any DMA. Plant 0 ("free") on the live
                    // template: idempotent, kick-neutral (only the
                    // guest's own `0x88020AD4` call kicks). Guarded: a
                    // wild index writes nowhere.
                    if let Ok(indice) = cpu.read_u32(0x882A_091C + 4) {
                        if indice < 64 {
                            let entrada =
                                0x882F_79EC + indice * 268 + 0x3C;
                            let _ = cpu.write_u32(entrada + 0x14, 0);
                        }
                    }
                    // PMEM freelist refill (decoded `0x88024874` pop):
                    // the kick pops a heap descriptor via head =
                    // `[0x882B0B44]`, count = `[...+0x10]`; stub init
                    // leaves both zero, so every kick aborts before the
                    // template gate (the single observed join arrival
                    // was a lucky non-zero word at `[0x4]`). Maintain a
                    // one-node self-loop in model scratch (node.next =
                    // node, node.payload = model desc buffer) with a
                    // high count, re-armed when drained. The guest pop
                    // unlinks (new head = node.next = node: stable) and
                    // consumes count; the serve hook later fills the
                    // desc buffer's target from the NAND image.
                    if cpu.read_u32(0x882B_0B44 + 0x10).unwrap_or(0) < 100
                    {
                        let _ = cpu.write_u32(0x882B_0B44, NAND_MODELO_NO);
                        let _ = cpu
                            .write_u32(0x882B_0B44 + 0x10, 10_000);
                        let _ = cpu.write_u32(NAND_MODELO_NO, NAND_MODELO_NO);
                        let _ =
                            cpu.write_u32(NAND_MODELO_NO + 4, NAND_MODELO_DESC);
                    }
                    // Transfer result: the poll exit checks
                    // `[0x882A091C+36] & 0xC == 0` for success
                    // (`tst ...; moveq r0,#1; popeq`). Init leaves -1
                    // (all bits set); real completion would clear the
                    // busy bits, so the host plants 0 (done, no error).
                    let _ = cpu.write_u32(0x882A_091C + 36, 0);
                    // READ-ID answer: plant (EC, AA) into the heap ID
                    // buffer once its slot is allocated
                    // (`[0x882F4564]` = heap base; the probe reads
                    // maker = word&0xFF, device = word>>8&0xFF).
                    // Upper bytes 0xFF (erased): the matcher only
                    // checks the low two, and real ID bytes 3-4 are
                    // unmodeled. Per-slice (not one-shot): the slot
                    // is allocated mid-run, and a one-shot plant
                    // before that sees buf==0 and never re-fires.
                    // Race-free: the ID DMA never writes the buffer
                    // (stub kick is a no-op), so the plant persists
                    // from the first post-alloc slice and the later
                    // probe always sees it.
                    if let Ok(buf) = cpu.read_u32(0x882F_4564) {
                        if buf != 0 {
                            let _ = cpu.write_u32(buf, 0xFFFF_AAEC);
                        }
                    }
                    // Virtual-button plants (plain registers, no guest
                    // refill — per-slice is race-free here): power key
                    // (`0x88014B00` reader) and reset reason
                    // (`0x88000E10` reader, `0xAA0FC080` page pre-mapped
                    // as `perif_aa0f_stub`). No combo without power.
                    // The indexed key slots (`0x88014B28` reader) are
                    // NOT planted: no proven consumer on this path.
                    {
                        let b = *botoes.borrow();
                        let _ = cpu.write_u32(
                            0xAA00_00C0,
                            u32::from(b.power),
                        );
                        if let Some(rr) = b.reset_reason() {
                            let _ = cpu.write_u32(0xAA0F_C080, rr);
                        }
                    }
                    // HBOOT-flash plants (all TEMP until the gates are
                    // emulated; each proven live):
                    // - Device model for the NBH Model-ID gate
                    // (`0x880190E8` loop: NBH byte vs `[0x882F2A48+r4*2]`;
                    // index 0 saw NBH 'D' vs 0xAA blank fill). Stride 2
                    // = wide chars: UTF-16LE "DREA10000" (NBH's own
                    // model). A same-slice guest refill beats a per-slice
                    // plant, so the check entry is also trapped
                    // synchronously (see the `0x880190E8` hook).
                    {
                        let modelo: &[u8] = b"D\0R\0E\0A\01\0\0\00\0\
                                              \0\0\0\0\0\0\0\0\0\0\0";
                        let _ = cpu.write_mem(0x882F_2A48, modelo);
                    }
                    // - flagB `[0x882AD614]`: TRIED and reverted — forcing
                    // it takes the update-UI path at the FIRST item and
                    // returns 0x27 ("Wrong Image") with no per-item flash.
                    // Natural value stays 0; the real setter is unknown.
                    // - "need update" `[0x882AD65C] = 1` (read per item at
                    // `0x8801AB78`; 0 = skip the item). Natural is always
                    // 0 on virgin NAND (the IfNeed version compare sees
                    // no update). With it forced, the per-item RUU worker
                    // (`0x8800A094`) runs for all 7 items — but performs
                    // tag checks only, no flash writes.
                    {
                        let _ = cpu.write_u32(0x882A_D65C, 1);
                    }
// Calibrated delay elision: the `0x88004330` delay loop
                    // (`rsb`+`cmp r5,r0`+`bhi`) waits on the hardware
                    // counter `[device+20]` — SINGLE-indirect:
                    // `0x880042C0` loads r3=`[0x880042D0]`=`0x882A1278`
                    // (slot address), r2=`[r3]`=`0xB5400000` (device
                    // base), r0=`[r2+20]`=`[0xB5400020]` (live reads
                    // confirm the full chain). The stub is frozen, so the
                    // host declares the wait over: when a slice stops
                    // inside the delay loop or its reader
                    // (`0x880042C0..0x88004358`, EXCLUSIVE of the exit
                    // sequence `0x88004358-5C`), resume at the loop exit
                    // (`0x88004358`). This is "time passes instantly" —
                    // the emulator has no timer hardware model, and the
                    // wait has no guest-observable effect but delay.
                    // The exclusion is load-bearing: forcing a slice
                    // already sitting on the exit `add sp`/`pop` re-adds
                    // and re-pops the frame, returning to garbage
                    // (observed once as a wild jump into a print
                    // buffer at `0x882A2100`).
                    //
                    // Open interpretador question (evidence preserved):
                    // satisfying the counter exactly (plant
                    // `[0xB5400020] = r4+0x10000`) SHOULD exit naturally —
                    // live reads confirm r4=0, r5=0x4B00, the plant lands
                    // (post-run `[0xB5400020] == 0x10000`), the four loop
                    // code words are byte-exact, and `alu`/`condicao`
                    // review correct for rsb/cmp/bhi (cross-checked
                    // against RE-Tools' independent AddWithCarry and
                    // HI-condition, which agree) — yet the loop never
                    // exits (r4 sampled 0 across 1500 slices, return
                    // chain static). If that is ever explained/fixed,
                    // this pc plant can go and the counter plant return.
                    if (0x8800_42C0..0x8800_4358).contains(&pc) {
                        // Single force-exit per slice (NO mini-step
                        // pump): the pump's extra `run(..., 30)` steps
                        // desynced the delay frame across a wild return
                        // to `0x882A2101` (proven by removal: the jump
                        // vanished, Budget returned). One outer
                        // iteration per slice is slower (a bounded
                        // 1000-retry poll needs ~1000 slices) but cannot
                        // re-enter mid-frame.
                        cpu.write_reg(
                            crate::cpu::Reg::Pc,
                            0x8800_4358,
                        );
                        pc = 0x8800_4358;
                    }
                    // B1D0 completion bit (decoded `0x88017638` poll): it spins
                    // on `[0xB1D00018] & 0x8000` with a 1000-retry bound,
                    // and the caller (`blt 0x8801775c` at `0x88017984`)
                    // retries the whole fill+poll sequence on FAIL — a
                    // silent infinite loop on stubs (proven by identical
                    // return chains at slices 150000/199999). Same shape
                    // as the TX-complete and transfer-done plants: the
                    // host reports "device completed instantly". OR, not
                    // assign: the guest's own magic-fill never touches
                    // +0x18 (offsets 0/4/16/20/28/... only), so no bits
                    // are clobbered.
                    if let Ok(v) = cpu.read_u32(0xB1D0_0018) {
                        let _ = cpu.write_u32(0xB1D0_0018, v | 0x8000);
                    }
                    // TEMP (periodic kick, every 100 slices from f=100k):
                    // the wall is a masked idle with frozen MATCH and a
                    // consumed one-shot latch — nothing unmasks or
                    // reprograms ever again. Force the tick: if MATCH
                    // is stale (<= COUNT+100), plant COUNT+327; point
                    // dev->event_handler (dev+0x2C) at
                    // tick_handle_periodic (0xC00650DC) — the registered
                    // handler is hrtimer_interrupt (oneshot/NO_HZ),
                    // whose ISR runs but never programs anything;
                    // unmask; mark dirty so the very next loop top
                    // delivers. If the periodic path runs (do_timer,
                    // scheduler ticks, softirqs, timer wheel), the
                    // msleep waiter wakes and boot proceeds; then
                    // retire the kick (or replace with nohz=off).
                    // 2026-10-24: the UNCONDITIONAL unmask (set_cpsr
                    // clearing I at a slice boundary) violates guest
                    // irqsave critical sections: clearing I mid-section
                    // lets a tick deliver inside it, and the ISR's path
                    // eventually reaches scheduler_tick with I=0 →
                    // posix BUG_ON(!irqs_disabled()) (racy: 27s vs 54s
                    // walls). The mode gate doesn't cover this (mode
                    // is SVC in a critical section). Fix: unmask ONLY
                    // after a PROLONGED mask (30 consecutive I=1 slice
                    // boundaries ≈ 60k instructions — the parked-masked
                    // idle signature; critical sections are <100 ins
                    // and never trip it). MATCH plant + handler pin +
                    // dirty stay unconditional (a pending edge while
                    // masked is harmless — served at the guest's own
                    // unmask; the mode gate still defers delivery out
                    // of IRQ/FIQ). The prolonged counter resets on any
                    // observed unmask.
                    if fatia >= 100000 && fatia % 100 == 0 {
                        let (_, cpsr_antes, _, _) = cpu.estado_completo();
                        let modo = cpsr_antes & 0x1F;
                        // Skip everything while in IRQ/FIQ mode (ISR in
                        // flight) — nested if, NOT continue: the rest of
                        // the slice harness must still run.
                        if modo != 0x12 && modo != 0x11 {
                            let tm = cpu.read_u32(0xE000_1000).unwrap_or(0);
                            let tc = cpu.read_u32(0xE000_1004).unwrap_or(0);
                            // Plant when MATCH is stale (behind COUNT) or only
                            // just ahead: MATCH <= COUNT+100 covers both (no
                            // wrapping-subtlety: values are far from 2^32).
                            // A stale MATCH means no edge has fired for a
                            // whole tick and the latch is consumed.
                            if tm <= tc.wrapping_add(100) {
                                let _ = cpu.write_u32(0xE000_1000, tc.wrapping_add(327));
                            }
                            let _ = cpu.write_u32(0xC02A_43C0 + 0x2C, 0xC006_50DC);
                            static mut NMASK: u32 = 0;
                            unsafe {
                                if cpsr_antes & 0x80 != 0 {
                                    NMASK += 1;
                                } else {
                                    NMASK = 0;
                                }
                                // Unmask only a genuinely parked mask:
                                // the idle wall holds I=1 for 100k+
                                // slices; a critical section never
                                // survives 30 boundaries.
                                if NMASK >= 30 {
                                    cpu.set_cpsr(cpsr_antes & !0x80);
                                    NMASK = 0;
                                    static mut NKU: u32 = 0;
                                    if NKU < 5 {
                                        NKU += 1;
                                        eprintln!("KICK-UNMASK f={fatia} after prolonged mask");
                                    }
                                }
                            }
                            cpu.marca_timer_sujo();
                            static mut NKICK: u32 = 0;
                            unsafe {
                                if NKICK < 3 {
                                    NKICK += 1;
                                    eprintln!("KICK f={fatia} MATCH was {tm:#x} vs COUNT {tc:#x}, I was {}", (cpsr_antes >> 7) & 1);
                                }
                            }
                        }
                    }
                    // the post-wall loop (if any) needs fine granularity
                    // to show repetition vs linear walk. Cap 400
                    // (covers f=90k..170k).
                    if fatia >= 90000 && fatia % 200 == 0 {
                        static mut NH: u32 = 0;
                        unsafe {
                            if NH < 400 {
                                NH += 1;
                                let n = NH;
                                eprintln!("PCS#{n} f={fatia} pc={:#x}", cpu.read_reg(crate::cpu::Reg::Pc));
                            }
                        }
                    }
                    // Arm the latch audit once past the delivery wall.
                    if fatia >= 90000 {
                        unsafe {
                            AUDIT_LATCH = true;
                        }
                    }
                    // TIMERSTATE (every 20k slices): EN_SET/EN_CLEAR/
                    // STATUS/MATCH/COUNT/EN + gate + jiffies + current
                    // task — tick AND progress diagnostics.
                    if fatia % 20000 == 0 {
                        let e30 = cpu.read_u32(0xE000_0030).unwrap_or(0xDEAD);
                        let e20 = cpu.read_u32(0xE000_0020).unwrap_or(0xDEAD);
                        let e80 = cpu.read_u32(0xE000_0080).unwrap_or(0xDEAD);
                        let tm = cpu.read_u32(0xE000_1000).unwrap_or(0xDEAD);
                        let tc = cpu.read_u32(0xE000_1004).unwrap_or(0xDEAD);
                        let te = cpu.read_u32(0xE000_1008).unwrap_or(0xDEAD);
                        let dm = cpu.read_u32(0xE000_1010).unwrap_or(0xDEAD);
                        let dc = cpu.read_u32(0xE000_1014).unwrap_or(0xDEAD);
                        let tg = cpu.read_u32(0xC02A_43EC).unwrap_or(0xDEAD);
                        let jf = cpu.read_u32(0xC02A_B638).unwrap_or(0xDEAD);
                        // ti = sp & ~0x1FFF; task = [ti+12].
                        let ti = cpu.read_reg(crate::cpu::Reg::Sp) & !0x1FFF;
                        let task = cpu.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                        // CPSR snapshot: I-bit (1 = IRQs disabled at the
                        // guest) + mode. Answers whether the "returned
                        // with disabled interrupts" initcall notices come
                        // from the guest never enabling IRQs.
                        let (_, cpsr_snap, _, _) = cpu.estado_completo();
                        let ibit = (cpsr_snap >> 7) & 1;
                        let modo = cpsr_snap & 0x1F;
                        // Total deliveries so far: the per-delivery logs
                        // are gated/capped, this shows the true rate.
                        let nent = unsafe { crate::cpu::interpretador::ULTIMA_ENTREGA };
                        // Unmask/mask edges since reset (see TOTAL_DESMASCA /
                        // TOTAL_MASCARA): unmasks without deliveries =
                        // line/edge gate blocks; neither moving at all =
                        // I=1 held (or the tracking diverged).
                        let ndes = unsafe { crate::cpu::interpretador::TOTAL_DESMASCA };
                        let nmas = unsafe { crate::cpu::interpretador::TOTAL_MASCARA };
                        let nwfi: u32 = unsafe { crate::cpu::interpretador::TOTAL_WFI };
                        // Foreground pc: where the guest is parked at the
                        // slice boundary (stall diagnosis — the irq-stack
                        // ti above goes garbage in interrupt context).
                        let fpc = cpu.read_reg(crate::cpu::Reg::Pc);
                        // Live stack (8 words at sp): stuck-in-one-frame
                        // vs slow-work distinguisher. The post-91k wall
                        // shows varied fpc with zero lock/sched/timer
                        // activity — a static stack names the spin.
                        // Plus the two parked thread stacks (init 0xC6016000
                        // + kthreadd 0xC601E000, 16 words each, kernel-text
                        // only): names what the sleepers wait in.
                        let mut stk8 = [0u32; 8];
                        let spsnap = cpu.read_reg(crate::cpu::Reg::Sp);
                        for (i, s) in stk8.iter_mut().enumerate() {
                            *s = cpu.read_u32(spsnap.wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                        }
                        let mut park: [u32; 12] = [0xDEAD; 12];
                        {
                            let mut k = 0usize;
                            for base in [0xC601_6000u32, 0xC601_E000u32] {
                                // Stacks grow DOWN: low addresses hold the
                                // newest (deepest) frames first. Collect
                                // kernel-text words in address order.
                                for w in 0..2048u32 {
                                    if k >= park.len() {
                                        break;
                                    }
                                    if let Ok(v) = cpu.read_u32(base.wrapping_add(w * 4)) {
                                        if (0xC000_0000..0xD000_0000).contains(&v) && v & 3 == 0 {
                                            park[k] = v;
                                            k += 1;
                                        }
                                    }
                                }
                            }
                        }
                        eprintln!("TIMERSTATE f={fatia} ENSET30={e30:#x} ENCLR20={e20:#x} STATUS80={e80:#x} MATCH={tm:#x} COUNT={tc:#x} EN={te:#x} DMATCH={dm:#x} DCOUNT={dc:#x} gate={tg:#x} jiffies={jf:#x} task={task:#x} I={ibit} modo={modo:#x} nent={nent} ndes={ndes} nmas={nmas} nwfi={nwfi} fpc={fpc:#x} stk={stk8:#x?} park={park:#x?}");
                        // TEMP (frozen init stack, one-shot at f=400000):
                        // the 57s wall parks init once (schedule_timeout
                        // at f≈103k, never returns) — its kernel stack is
                        // frozen, so one top-512B dump names the whole
                        // wait chain (probe → wait → timeout). Init stack
                        // base 0xC6016000, grows down from +0x2000.
                        if fatia == 400000 {
                            let mut froze = [0u32; 128];
                            for (i, s) in froze.iter_mut().enumerate() {
                                *s = cpu.read_u32(0xC601_6000u32.wrapping_add(0x1E00).wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                            }
                            eprintln!("FROZEN-INIT f={fatia} top512={froze:#x?}");
                        }
                        // TEMP (desc watch): dump 8 words at 0xC02A4468
                        // (the irq_desc/action the dispatch uses) on
                        // CHANGE, cap 10. Names who sets PENDING / moves
                        // the action chain for the double-tick mystery.
                        static mut ULT_DESC: [u32; 8] = [0xDEAD; 8];
                        static mut NDESC: u32 = 0;
                        unsafe {
                            let mut cur = [0u32; 8];
                            for (i, w) in cur.iter_mut().enumerate() {
                                *w = cpu
                                    .read_u32(0xC02A_4468u32.wrapping_add((i as u32) * 4))
                                    .unwrap_or(0xDEAD_DEAD);
                            }
                            if cur != ULT_DESC && NDESC < 10 {
                                NDESC += 1;
                                ULT_DESC = cur;
                                eprintln!("DESCCHG f={fatia} [{:x?}]", cur);
                            }
                        }
                    }
                    // proc_comm ACK (decoded `0xC002D690` poll `ldr r3,[r6];
                    // cmp r3,#1`, 10M-timeout): the poll runs with r6 =
                    // 0xE0100014 AND 0xE0100000 (E10FAIL proves both, r5=1).
                    // The guest writes a command (e.g. 0x25) and the modem
                    // OVERWRITES with 1 (assign, not OR: OR preserves 0x25
                    // and the poll never exits — frozen). Host answers
                    // "immediate ACK". 0xE0001000 EXCLUDED (timer block,
                    // risk of corrupting COUNT/MATCH).
                    for a in [0xE010_0014u32, 0xE010_0000u32] {
                        if let Ok(v) = cpu.read_u32(a) {
                            if v != 1 {
                                let _ = cpu.write_u32(a, 1);
                            }
                        }
                    }
                    // UART TX-complete (the `0x880040D4`-loop's exits):
                    // after enqueueing a byte to the channel-3 ring it
                    // re-checks `[r4+#20]` (`0x8800410C`, `beq` loop
                    // while clear) — real silicon sets it when the
                    // device consumes the byte. The stub UARTs never
                    // do: the loop spins (proven twice: 45 identical
                    // ring iterations; then 341 identical loop
                    // iterations on the valid-boot path). The host
                    // already drains those bytes to the wire (`saida`),
                    // so reporting "consumed" is coherent: OR bit 0 per
                    // slice, for BOTH UART-like bases (`0xB2800000`
                    // PUTC UART and `0xB2600000` display-path UART —
                    // the stuck loop's r4 differs per path; the J2/J3
                    // probes showed B280 early, B260 later). Callers
                    // discard the return value (proven at `0x88003868`:
                    // `bl` then unconditional return-0), so forcing
                    // exit A cannot starve anyone.
                    for base in [0xB280_0014u32, 0xB260_0014u32] {
                        if let Ok(v) = cpu.read_u32(base) {
                            let _ = cpu.write_u32(base, v | 1);
                        }
                    }
                    // TEMP/RX work (see `rx_enfileira`): plant the next
                    // queued keystroke while the console UART shows no
                    // pending byte (ready bit clear, nothing in flight).
                    // Ready = `[0xB2800008]` bit 0, data = `[0xB280000C]`
                    // low byte; error bits `0x20`/`0x40` mean "discard" to
                    // `getc`, so they are cleared on the plant while the
                    // guest's other status bits are preserved.
                    if let Ok(mut estado) = RX_FILA.lock() {
                        if estado.1.is_none() {
                            if let Ok(st) = cpu.read_u32(0xB280_0008) {
                                if st & 1 == 0 {
                                    if let Some(b) = estado.0.pop_front() {
                                        estado.1 = Some(b);
                                        let _ =
                                            cpu.write_u32(0xB280_0008, (st | 1) & !0x60);
                                        if let Ok(d) = cpu.read_u32(0xB280_000C) {
                                            let _ = cpu.write_u32(
                                                0xB280_000C,
                                                (d & !0xFF) | b as u32,
                                            );
                                        }
                                        eprintln!("RXPLANT byte={b:#x}");
                                    }
                                }
                            }
                        }
                    }
                    // UART command ACK, phase 1 (decoded `0x88004180`
                    // init): it spins at `0x88004274` for `[+8]` bit 0
                    // to clear (hardware ACK; unbounded — infinite on
                    // stubs, where +8 keeps the written 0xFF). Pc-gated:
                    // only when a slice stops inside the spin. Covers
                    // BOTH UART-like bases seen so far: `0xB2800000`
                    // (the PUTC UART; SPIN probe) and `0xB2600000`
                    // (display-path UART; SPIN2 probe on the valid-boot
                    // path — the same init function programs it).
                    // Clearing `0xB2800008` is harmless to the later
                    // PUTC wait: the per-slice `[+20]=1` plant makes
                    // exit A (`0x880040DC`) fire before the +8 check.
                    // (Phase 2 — re-setting +8 for the PUTC fallthrough
                    // — is subsumed by the +20 plant above.)
                    if (0x8800_4274..0x8800_4284).contains(&pc) {
                        for base in [0xB280_0008u32, 0xB260_0008u32] {
                            if let Ok(v) = cpu.read_u32(base) {
                                let _ = cpu.write_u32(base, v & !1);
                            }
                        }
                    }
                    if leituras.len() < 8 {
                        leituras.push((
                            cpu.read_u32(slot).unwrap_or(0xDEAD_DEAD),
                            escrita,
                            cpu.read_u32(slot + 8).unwrap_or(0xDEAD_DEAD),
                        ));
                    }
                }
                pc = if cpu.em_thumb() { pc | 1 } else { pc & !1 };
                // Kernel timers + UART TX-ready, per slice:
                // - GPT COUNT (`0xE0001004`) and DGT COUNT
                // (`0xE0001014`) advance per slice (+4/+72, the nominal
                // 32768 Hz / 600 kHz ratio) — GUEST-paced, never
                // wall-clock (see CONTAGEM_GPT). `msm_read_timer_count`
                // needs consecutive reads to agree (they do within a
                // slice) and advance across trips (they do between
                // slices) to exit its stabilize + set_next_event
                // wait loops.
                // - VIC STATUS (`0xE0000080`, bank0) recomputed from
                // COUNT/MATCH/INT_EN every slice (per irqspec.md: ack
                // is purely VIC INT_CLEAR bit 7; the kernel never
                // writes TIMER_CLEAR +0xC; a guest ack + MATCH
                // reprogram clears STATUS for free). INT_EN is
                // kernel-owned: never plant it. Bit 7 set iff
                // COUNT>=MATCH & EN-bit & clockevent registered
                // ([dev+0x2C]!=0 — gates a null-handler tail-call).
                // Inert until ISR delivery lands (nothing polls
                // STATUS today).
                // - UART TX-ready: `[uart+8] |= 0x04` (bit 2) on all
                // three static-map UARTs; TX bytes are drained from
                // THR `[uart+0x0C]` below (the old `msm_putc` trap
                // address was wrong — list code, never fired).
                // - jiffies (`0xC02AB638` = `jiffies_64` low word):
                // +1/slice fallback while no tick has ever completed
                // (keeps calibrate_delay exiting); one +1 per observed
                // tick completion (STATUS 1->0 while enabled) after.
                // The fallback dies on tick COMPLETION (not first
                // pendente) so a stuck-pending STATUS can never freeze
                // jiffies without delivery.
                {
                    static mut JA_PENDENTE: bool = false;
                    // Guest-paced counts (see the CONTAGEM_GPT note at
                    // the top of the run loop): advance per slice, not
                    // per wall-clock microsecond.
                    unsafe {
                        CONTAGEM_GPT = CONTAGEM_GPT.wrapping_add(4);
                        CONTAGEM_DGT = CONTAGEM_DGT.wrapping_add(72);
                        let _ = cpu.write_u32(0xE000_1004, CONTAGEM_GPT);
                        let _ = cpu.write_u32(0xE000_1014, CONTAGEM_DGT);
                    }
                    // Raw pending, masked by the kernel-owned enable
                    // line (setup_irq(7) -> unmask -> INT_EN bit 7;
                    // never plant INT_EN here). Before the clockevent
                    // is registered (event_handler slot
                    // [dev_id+0x2C] == 0) keep STATUS clear so a stray
                    // dispatch can never tail-call a null handler.
                    let conta = cpu.read_u32(0xE000_1004).unwrap_or(0);
                    let alvo = cpu.read_u32(0xE000_1000).unwrap_or(u32::MAX);
                    let conta_d = cpu.read_u32(0xE000_1014).unwrap_or(0);
                    let alvo_d = cpu.read_u32(0xE000_1010).unwrap_or(u32::MAX);
                    let hab = cpu.read_u32(0xE000_0030).unwrap_or(0);
                    let handler_on = cpu.read_u32(0xC02A_43EC).unwrap_or(0) != 0;
                    let pendente = conta >= alvo && alvo != u32::MAX && hab & 0x80 != 0 && handler_on;
                    let pendente_dgt =
                        conta_d >= alvo_d && alvo_d != u32::MAX && hab & 0x100 != 0 && handler_on;
                    // VIC dispatch registers: __irq_svc reads
                    // VICVECTADDR (`0xE00000D0`, then `0xD4`, uses the
                    // second) and expects the pending IRQ NUMBER, or
                    // `0xFFFFFFFF` when idle (live: the zeroed stub
                    // returned 0 -> asm_do_IRQ(0) -> bad-IRQ path,
                    // exactly one VIDX/DISP then silence, TICKH never
                    // fired). `0xE0000000` (IRQSTATUS bits) is served
                    // too although this dispatch never reads it.
                    // Slice-stale is fine: pending moves slowly vs
                    // slices, and MATCH/EN writes refresh synchronously
                    // in es_mem.
                    {
                        let vic = (if pendente { 0x80 } else { 0 })
                            | (if pendente_dgt { 0x100 } else { 0 });
                        let _ = cpu.write_u32(0xE000_0000, vic);
                        let vect = if pendente {
                            7
                        } else if pendente_dgt {
                            8
                        } else {
                            0xFFFF_FFFF
                        };
                        let _ = cpu.write_u32(0xE000_00D0, vect);
                        let _ = cpu.write_u32(0xE000_00D4, vect);
                    }
                    unsafe {
                        if pendente && !JA_PENDENTE {
                            JA_PENDENTE = true;
                            eprintln!("TICK pending at slice {fatia} (setup_irq+MATCH seen)");
                        }
                    }
                    if let Ok(st) = cpu.read_u32(0xE000_0080) {
                        let antes = st & 0x180 != 0;
                        let mut depois = st & !0x180;
                        if pendente {
                            depois |= 0x80;
                        }
                        if pendente_dgt {
                            depois |= 0x100;
                        }
                        let _ = cpu.write_u32(0xE000_0080, depois);
                        // STATUS rising edge (catch-up birth): mark timer
                        // dirty so the next UNMASKED loop top rechecks
                        // (persists across masked stretches).
                        if !antes && (depois & 0x180) != 0 {
                            cpu.marca_timer_sujo();
                        }
                        // Tick completed: a STATUS bit was set and cleared
                        // itself via guest ack + MATCH reprogram while
                        // enabled. One jiffy per real tick (either timer).
                        // The real ISR (now delivered) runs do_timer,
                        // so no host jiffies bump here.
                        let comp7 = st & 0x80 != 0 && depois & 0x80 == 0 && hab & 0x80 != 0;
                        let comp8 = st & 0x100 != 0 && depois & 0x100 == 0 && hab & 0x100 != 0;
                        if comp7 || comp8 {
                            ultimo_tick = Some(fatia);
                        }
                    }
                    // Watchdog fallback: +1 per 96 slices unless a tick
                    // completed recently. 2000 instrs/slice at the
                    // 19.2 MHz ACPU is ~0.1 ms/slice, so 96 slices
                    // make one 10 ms jiffy — the same guest pace as
                    // CONTAGEM_GPT (+4/slice). A per-slice +1 runs
                    // jiffies ~100x too fast and the whole timekeeping
                    // (ktime_get, tick_next_period comparisons) rides
                    // ahead of the timer hardware; the catch-up loop
                    // then chases a delta that never goes positive
                    // (treadmill hypothesis, 2026-10-24). Keeps
                    // calibrate_delay and early jiffies waits alive,
                    // just at guest speed.
                    let sem_tick = ultimo_tick.map_or(true, |u| fatia.wrapping_sub(u) > 2000);
                    if sem_tick && fatia % 96 == 0 {
                        if let Ok(j) = cpu.read_u32(0xC02A_B638) {
                            let _ = cpu.write_u32(0xC02A_B638, j.wrapping_add(1));
                        }
                    }
                    // TEMP (who dirties 0xC0000100): watches the 2 words
                    // of CORE with slice. Boot 1 sees [2, CORE]; boot 2
                    // reads 0xC0000100 repeatedly. Logs transitions.
                    static mut VAT0: u32 = 0xDEAD_DEAD;
                    static mut VAT1: u32 = 0xDEAD_DEAD;
                    static mut NVAT: u32 = 0;
                    if let (Ok(a), Ok(b)) = (cpu.read_u32(0xC000_0100), cpu.read_u32(0xC000_0104)) {
                        unsafe {
                            if VAT0 == 0xDEAD_DEAD {
                                VAT0 = a;
                                VAT1 = b;
                            } else if (VAT0 != a || VAT1 != b) && NVAT < 8 {
                                let pa = VAT0;
                                let pb = VAT1;
                                NVAT += 1;
                                eprintln!("VATAG {pa:#x},{pb:#x}->{a:#x},{b:#x} slice={fatia} pc={:#x}",
                                    cpu.read_reg(crate::cpu::Reg::Pc));
                                VAT0 = a;
                                VAT1 = b;
                            }
                        }
                    }
                    // TEMP (stale vs fresh): transitions of [0xC02EBC44]
                    // with slice. 1x = leftover from boot 1 (reboot dirties);
                    // 2x = writer runs per boot (per-boot bug).
                    static mut VIU: u32 = 0xDEAD_DEAD;
                    static mut NVIU: u32 = 0;
                    if let Ok(v) = cpu.read_u32(0xC02E_BC44) {
                        unsafe {
                            if VIU == 0xDEAD_DEAD {
                                VIU = v;
                            } else if VIU != v && NVIU < 6 {
                                let antes = VIU;
                                NVIU += 1;
                                eprintln!("WRES{antes:#x}->{v:#x} slice={fatia}");
                                VIU = v;
                            }
                        }
                    }
                    for base in [0xE000_3000u32, 0xE000_4000, 0xE000_5000] {
                        if let Ok(v) = cpu.read_u32(base + 8) {
                            let _ = cpu.write_u32(base + 8, v | 0x04);
                        }
                        // THR drain: the console writes the byte to
                        // `[base+0x0C]`; drains into `kernel_tx` and zeroes
                        // to see the next one (cap 20000).
                        // TEMP (serial tap): real-time console text, gated
                        // to f >= 80000 (the 1.48s stall diagnosis — the
                        // post-mortem log_buf dump shows 109 bytes and
                        // can't be trusted). Cap 300 lines.
                        if let Ok(b) = cpu.read_u32(base + 12) {
                            if b != 0 && kernel_txb.borrow().len() < 20000 {
                                kernel_txb.borrow_mut().push((b & 0xFF) as u8);
                                let _ = cpu.write_u32(base + 12, 0);
                                static mut NSER: u32 = 0;
                                unsafe {
                                    if fatia >= 80000 && NSER < 300 {
                                        NSER += 1;
                                        let c = (b & 0xFF) as u8;
                                        if c == b'\n' {
                                            eprintln!("SER f={fatia} NL");
                                        } else if c.is_ascii_graphic() || c == b' ' {
                                            eprintln!("SER f={fatia} {:#x} '{}'", c, c as char);
                                        } else {
                                            eprintln!("SER f={fatia} {:#x} .", c);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // TEMP (back to SPL): compares the pc at the START of this
                // slice with the one at the end: kernel (VA 0xC../PA 0x10..) ->
                // SPL (0x88..) within the SAME slice = direct jump
                // (the 2048 tail covers the 2000 slice + the bomb).
                static mut PC_ANT: u32 = 0;
                static mut JA_VOLTOU: bool = false;
                {
                    let nucleo_ant = (0xC000_0000..0xD000_0000).contains(&unsafe { PC_ANT })
                        || (0x1000_0000..0x1400_0000).contains(&unsafe { PC_ANT });
                    // SPL = post-MMU (0x88..) OR pre-MMU (file offset:
                    // the reboot enters at 0x478 and zeroes the BSS
                    // at 0x88000818 before returning to 0x88..).
                    let spl = (0x8800_0000..0x8900_0000).contains(&pc)
                        || pc < 0x10_0000;
                    unsafe {
                        if nucleo_ant && spl && !JA_VOLTOU {
                            JA_VOLTOU = true;
                            let de = PC_ANT;
                            // A guest reboot mid-run:
                            // boot 1 dies at `movs pc,lr` with lr=0
                            // (return with no frame) and returns to the reset
                            // vector; boot 2 dies in the list walk.
                            eprintln!("JUMPBACK slice={fatia} from={de:#x} to={pc:#x}");
                        }
                        PC_ANT = pc;
                    }
                }
                // Host frame hook: new serial bytes (tap channel 3,
                // then ring-drained bulk) since last slice; the
                // frontend uploads `RAM_A6C0_BASE` from `cpu` and/or
                // prints. Returning false stops the run early (stop
                // reason then reads `Budget`).
                // TEMP/RX work: tap channel 0 also carries console output
                // — the `Cmd>` line-input echo uses `PUTC(0, c)`, whose raw
                // r0=0 the tap records as channel 0 (measured: typed `hi`
                // lands on ch0 while prompt/error stay on ch3). Without
                // this, host typing is consumed but invisible on stdout.
                let mut novos: Vec<u8> = Vec::new();
                {
                    let tap_ref = tap.borrow();
                    for canal in [3u32, 0u32] {
                        let todos = tap_ref.bytes_do_canal(canal);
                        let marca = if canal == 3 { &mut tap_marca } else { &mut tap_marca_c0 };
                        if *marca <= todos.len() {
                            novos.extend_from_slice(&todos[*marca..]);
                            *marca = todos.len();
                        }
                    }
                }
                if saida_marca <= saida.len() {
                    novos.extend_from_slice(&saida[saida_marca..]);
                    saida_marca = saida.len();
                }
                if !a_cada_fatia(fatia, pc, &mut cpu, &novos) {
                    break;
                }
            }
            outra => {
                // TEMP (kernel fault): records regs at fault. Low cap
                // (12): demand-map pages MBs and each fault generated one
                // line with regs (~1 MB per run). Faults that STOP the
                // run always log (see `parada = outra` below).
                static mut NKF: u32 = 0;
                if let StopReason::MemoryFault { addr, pc: pc_falta } = &outra {
                    // ins = the word at pc (0xDEAD when pc itself
                    // is not mapped — in that case pc is stale and the
                    // real access came from elsewhere).
                    unsafe {
                        NKF += 1;
                        // Logs the first 12; the rest only shows in the
                        // stop summary (below) if fatal.
                        if NKF <= 12 {
                            let mut ib = [0u8; 4];
                    let ins = if cpu.read_mem(pc_falta & !3, &mut ib).is_ok() {
                        u32::from_le_bytes(ib)
                    } else {
                        0xDEAD_DEAD
                    };
                    eprintln!(
                        "KFAULT addr={addr:#x} pc={pc_falta:#x} ins={ins:#x} r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x} lr={:#x}",
                        cpu.read_reg(crate::cpu::Reg::R0),
                        cpu.read_reg(crate::cpu::Reg::R1),
                        cpu.read_reg(crate::cpu::Reg::R2),
                        cpu.read_reg(crate::cpu::Reg::R3),
                        cpu.read_reg(crate::cpu::Reg::R4),
                        cpu.read_reg(crate::cpu::Reg::R5),
                        cpu.read_reg(crate::cpu::Reg::R6),
                        cpu.read_reg(crate::cpu::Reg::R7),
                        cpu.read_reg(crate::cpu::Reg::Lr),
                    );
                        }
                    }
                }
                // Demand-map on first fault per page, stop on repeats or
                // genuinely unknown areas. Classification, in order:
                // (0) the kernel's VA space: once Linux enables its page
                // tables, execution and data move to VA `0xC0000000+`.
                // The low part is the direct-mapped RAM (= PA
                // `0x10000000+`, trout PAGE_OFFSET); the high part
                // (`0xC4000000+`: 0xC440/0xC480... probe windows) is
                // ioremapped device memory with no PA alias. Our MMU
                // is a NOP, so page in the whole VA window on demand,
                // SEEDED from the physical alias where one exists
                // (the decompressed kernel, ramdisk and ATAGs already
                // live in the PA bank; ioremap probes read unmapped
                // PA and stay zeroed). Uncapped count (the kernel
                // faults in megabytes legitimately) but still stops on
                // repeat faults (needs behavior, not memory).
                // (1) section-table alias (addressable per the SPL's own
                // table) and known suspect windows (`JANELA_MMIO`) get a
                // zeroed 4K page; anything else keeps the fault as the
                // instrument. A repeat fault inside an already mapped
                // page means "needs behavior (a status bit, a read
                // value), not memory" and stops the run. Capped so a
                // wild jump can't pave the address space forever.
                match outra {
                    StopReason::MemoryFault { addr, pc: pc_falta }
                        if (0xC000_0000..0xCC00_0000).contains(&addr) =>
                    {
                        let base = addr & !0xFFF;
                        if mapeadas_kern.contains(&base) {
                            parada = outra;
                            break;
                        }
                        if cpu.map_zeroed("nucleo_virt", base, 0x1000).is_err() {
                            parada = outra;
                            break;
                        }
                        // Seed from the physical alias (va - 0xB0000000):
                        // the kernel image, ramdisk and ATAGs were
                        // served/mirrored into the PA bank pre-MMU.
                        let pa = base.wrapping_sub(0xB000_0000);
                        let mut pg = vec![0u8; 0x1000];
                        if cpu.read_mem(pa, &mut pg).is_ok() {
                            let _ = cpu.write_mem(base, &pg);
                        }
                        mapeadas_kern.push(base);
                        pc = pc_falta;
                    }
                    // TEMP (kernel fault): records who accesses where
                    // (8k Budget pass without this; remove when mapping).
                    // User VA via guest page tables (TTBR0 walk): the ELF
                    // loader maps /init's segments, stack and brk in the
                    // user pgd, which the flat MMU never consulted — every
                    // user page faulted. Resolve VA->PA, mirror the 4 KiB
                    // physical page (seeded copy; RAM is coherent), track
                    // uncapped (dozens of legit pages). SPL-alias and
                    // known windows keep their existing arm below; repeat
                    // faults and unmapped VAs still stop the run.
                    StopReason::MemoryFault { addr, pc: pc_falta }
                        if addr < 0xC000_0000
                            && traduz(addr & !0xFFF).is_none()
                            && janela_de(addr & !0xFFF).is_none() =>
                    {
                        let base = addr & !0xFFF;
                        // First user fault: the SPL low image (0x0-0x80000,
                        // read-only leftover) shadows ALL of userspace
                        // text — the guest would execute SPL bytes as
                        // /init (proven live: 0x80BC decodes as SPL).
                        // Carve it out wholesale once; the kernel runs
                        // from high mappings (vectors are high) and never
                        // needs it again. Only on walk-miss pages... no:
                        // unconditionally here, since text pages never
                        // fault (mapped+executable SPL bytes) and would
                        // otherwise run garbage forever.
                        static mut SPL_FORA: bool = false;
                        unsafe {
                            if !SPL_FORA {
                                SPL_FORA = true;
                                let _ = cpu.desmapeia_intervalo(0x0, 0x8_0000);
                                eprintln!("SPL-UNMAP f={} (low image carved for userspace)", unsafe { FATIA_ATUAL });
                            }
                        }
                        if mapeadas_usr.contains(&base) {
                            parada = outra;
                            break;
                        }
                        // TEMP (UDECIDE): user-arm MISS decisions only
                        // (HITs already log via UFAULT). Cap 200.
                        // Remove after the bec0a000 stall is named.
                        static mut NUD: u32 = 0;
                        match caminha_pt_usuario(&mut cpu, base) {
                            Some((pa, bruto, l2base)) => {
                                // Carve out stale bytes first: low user
                                // pages collide with the SPL image mapping
                                // (0x0-0x80000, read-only leftover the
                                // buddy allocator recycled). The guest
                                // installed PTEs, so the new content wins.
                                // Carve failure stops the run (unlike the
                                // content seed below, which degrades to
                                // zeros).
                                if cpu.desmapeia_intervalo(base, 0x1000).is_err() {
                                    parada = outra;
                                    break;
                                }
                                if cpu.map_zeroed("usuario_ptw", base, 0x1000).is_err() {
                                    parada = outra;
                                    break;
                                }
                                // Seed from the physical page THROUGH the
                                // lowmem alias (live contents — see
                                // le_ram_fisica; the PA bank is stale).
                                let mut pg = vec![0u8; 0x1000];
                                if le_ram_fisica(&mut cpu, pa, &mut pg) {
                                    let _ = cpu.write_mem(base, &pg);
                                }
                                mapeadas_usr.push(base);
                                static mut NUSR: u32 = 0;
                                unsafe {
                                    if NUSR < 40 {
                                        NUSR += 1;
                                        let mut hb = [0u8; 16];
                                        let head = if cpu.read_mem(base, &mut hb).is_ok() { hb.to_vec() } else { vec![] };
                                        let mut gb = [0u8; 16];
                                        let got = if cpu.read_mem(base.wrapping_add(0x830), &mut gb).is_ok() { gb.to_vec() } else { vec![] };
                                        // L2 neighborhood: real installs
                                        // show isolated valid entries;
                                        // stale tables show garbage.
                                        let mut nb = [0u8; 32];
                                        let l2va = l2base.wrapping_add(0xB000_0000).wrapping_sub(16);
                                        let nbs = if cpu.read_mem(l2va, &mut nb).is_ok() { nb.to_vec() } else { vec![] };
                                        eprintln!("UFAULT f={} va={base:#x} pa={pa:#x} raw={bruto:#x} l2t={l2base:#x} head={head:02x?} got={got:02x?} l2n={nbs:02x?}", unsafe { FATIA_ATUAL });
                                    }
                                }
                                // Preserve Thumb: run() sets T from pc bit0,
                                // and Thumb fault addresses are even — a
                                // bare pc_falta would resume ARM and
                                // mis-execute Thumb bytes as ARM (proven
                                // live: 0x15118 Thumb slid into garbage
                                // and jumped to 0x195311C with sp
                                // untouched). T bit (0x20) round-trips it.
                                let thumb = cpu.estado_completo().1 & 0x20 != 0;
                                pc = pc_falta | if thumb { 1 } else { 0 };
                            }
                            None => {
                                // TEMP (UDECIDE miss side): log the abort
                                // decision inputs — abortadas state, mode,
                                // vector shape. Cap shared 40 above.
                                unsafe {
                                    if NUD < 200 {
                                        NUD += 1;
                                        let (_, cj, _, _) = cpu.estado_completo();
                                        let vet = if cpu.le_cp15(0x80).unwrap_or(0) & (1 << 13) != 0 { 0xFFFF_0000 } else { 0x0 } | if addr == pc_falta { 0x0C } else { 0x10 };
                                        let w = cpu.read_u32(vet).unwrap_or(0xDEAD);
                                        let ja: u32 = abortadas.iter().find(|(k, _)| *k == (base, pc_falta)).map_or(0, |(_, n)| *n);
                                        eprintln!("UDECIDE f={} va={base:#x} MISS ja={ja} modo={:#x} w={w:#x}", unsafe { FATIA_ATUAL }, cj & 0x1F);
                                    }
                                }
                                // No guest mapping yet: deliver a data
                                // abort so the kernel's own fault handler
                                // installs PTEs (demand paging faults on
                                // real HW too — VMA lookup, zero/file
                                // pages, COW — all guest-side from here).
                                // Cache TTBR0 + task for the PTE-mirror
                                // trap (which only gets mem).
                                // Same (page, pc) faulting again after a
                                // delivery: allow a handful (recurring
                                // legitimate faults proceed), then stop
                                // a tight livelock. Budget 10 per key.
                                let vezes = abortadas.iter().find(|(k, _)| *k == (base, pc_falta)).map_or(0, |(_, n)| *n);
                                if vezes >= 10 {
                                    eprintln!("ABORT-LOOP f={} va={base:#x} pc={pc_falta:#x} ({vezes}x, stopping)", unsafe { FATIA_ATUAL });
                                    parada = outra;
                                    break;
                                }
                                unsafe {
                                    TTBR_CACHE = cpu.le_cp15(0x100).unwrap_or(0);
                                    let ti0 = cpu.read_reg(crate::cpu::Reg::Sp) & !0x1FFF;
                                    TTBR_TASK = cpu.read_u32(ti0.wrapping_add(12)).unwrap_or(0xDEAD);
                                }
                                // No nested aborts (single spsr_abt) and
                                // none from ABT/FIQ mode: those would
                                // corrupt state — stop loudly.
                                let (_, cpsr_hj, _, _) = cpu.estado_completo();
                                let modo_hj = cpsr_hj & 0x1F;
                                if modo_hj == 0x17 || modo_hj == 0x11 {
                                    parada = outra;
                                    break;
                                }
                                let prefetch = addr == pc_falta;
                                // Vector sanity: the kernel copies stubs
                                // to 0xFFFF0000 early; each vector is
                                // `ldr pc, [pc, #imm]` or a plain `b`
                                // to the handler. A zero/garbage vector
                                // means the abort would jump nowhere —
                                // stop with the evidence.
                                let alto = cpu.le_cp15(0x80).unwrap_or(0) & (1 << 13) != 0;
                                let vet = if alto { 0xFFFF_0000 } else { 0x0 }
                                    | if prefetch { 0x0C } else { 0x10 };
                                let w = cpu.read_u32(vet).unwrap_or(0);
                                let forma = (w & 0xFFFF_F000 == 0xE59F_F000)
                                    || (w & 0xFF00_0000 == 0xEA00_0000);
                                if !forma {
                                    eprintln!("ABORT-NOVET f={} vet={vet:#x} w={w:#x}", unsafe { FATIA_ATUAL });
                                    parada = outra;
                                    break;
                                }
                                cpu.entra_aborto(addr, 0x5, prefetch);
                                if let Some(slot) = abortadas.iter_mut().find(|(k, _)| *k == (base, pc_falta)) {
                                    slot.1 += 1;
                                } else {
                                    abortadas.push(((base, pc_falta), 1));
                                }
                                pc = cpu.read_reg(crate::cpu::Reg::Pc) & !1;
                            }
                        }
                    }
                    StopReason::MemoryFault { addr, pc: pc_falta }
                        if mapeadas.len() < 64 =>
                    {
                        let base = addr & !0xFFF;
                        let classe = if mapeadas.contains(&base) {
                            None
                        } else if traduz(base).is_some() {
                            Some("alias")
                        } else if janela_de(base).is_some() {
                            Some("suspeita")
                        } else {
                            None
                        };
                        match classe {
                            Some(_classe) => {
                                if cpu.map_zeroed("demanda", base, 0x1000).is_err() {
                                    parada = outra;
                                    break;
                                }
                                mapeadas.push(base);
                                pc = pc_falta;
                            }
                            None => {
                                parada = outra;
                                break;
                            }
                        }
                    }
                    _ => {
                        parada = outra;
                        break;
                    }
                }
            }
        }
    }
    // Halt traceback: what instruction stopped the run, decoded in
    // place, plus the full register file. Printed once per terminal
    // stop — Budget included, since stall runs end on Budget with no
    // fault and the parked pc + stack + pc history names the stall.
    match &parada {
        StopReason::MemoryFault { addr, pc } => imprime_trace(&cpu, *pc, Some(*addr)),
        StopReason::Exception { pc } => imprime_trace(&cpu, *pc, None),
        StopReason::Budget => {
            imprime_trace(&cpu, cpu.read_reg(crate::cpu::Reg::Pc), None)
        }
        StopReason::ApiCall { addr } => {
            imprime_trace(&cpu, cpu.read_reg(crate::cpu::Reg::Pc), Some(*addr))
        }
        StopReason::Returned => {
            imprime_trace(&cpu, cpu.read_reg(crate::cpu::Reg::Pc), None)
        }
    }
    // Final drain: a fault (or any non-Budget stop) lands mid-slice,
    // one instruction after a print (`bl 0x88001968` then `strh` faults
    // at `0x88017A04`) — without this, the FAIL-path bytes sit
    // undrained in the guest ring and the tap tail goes stale. Same
    // drain as the per-slice one (`slot` there is `0x882A952C`); on a
    // Budget exit the ring is already empty so this is a no-op (plus
    // harmless slot writes).
    let esgota = 0x882A_952Cu32;
    if let (Ok(leitura), Ok(escrita)) =
        (cpu.read_u32(esgota), cpu.read_u32(esgota + 4))
    {
        if escrita != leitura {
            let mut dados = vec![0u8; 0x1000];
            if cpu
                .read_mem(0x882A_24FC + 3 * 0x1000, &mut dados)
                .is_ok()
            {
                saida.extend_from_slice(
                    &crate::msm7201a_serial::anel_bytes_novos(
                        leitura as usize,
                        escrita as usize,
                        &dados,
                        0x1000,
                    ),
                );
            }
        }
        let _ = cpu.write_u32(esgota, escrita);
        let _ = cpu.write_u32(esgota + 8, 0);
    }
    let texto = String::from_utf8_lossy(&saida).into_owned();
    let linhas: Vec<(u32, Vec<u8>)> = tap.borrow_mut().linhas();
    let parcial: Vec<(u32, Vec<u8>)> = (0..8)
        .map(|c| (c, tap.borrow().bytes_do_canal(c).to_vec()))
        .filter(|(_, b)| !b.is_empty())
        .collect();
    // Device slots the `0x88021198` init should have filled; all-zero
    // means it never ran (or was skipped) on this path.
    // `0x882F1EB4` (pool `0x88008450`): object slot for the `0x88008238`
    // virtual-call dispatcher (`ldr pc, [r3, #20]`); followed one level
    // to the wild method pointer itself.
    let slots: Vec<(u32, u32)> = [
        0x882F_79E4,
        0x882F_4558,
        0x882F_4574,
        0x882F_4578,
        0x882F_4560,
        0x882F_4588,
        0x882F_79E0,
        0x882F_457C,
        0x882A_9584,
        0x882A_0001,
        0x882A_1CD0,
        0x882A_0000,
        0x882F_79EC,
        0x882F_79F8,
        0x882A_24FC,
        0x882A_952C,
        0x882A_9530,
        0x882A_9534,
        0x882A_9538,
        0x882F_1EB4,
        0x8800_8450,
        0x8806_F6F8,
        0x8806_F6FC,
        0x8801_FCF4,
        0x882A_1278,
        0xB540_0000,
        0xB540_0020,
        0x8800_42D0,
    ]
    .iter()
    .map(|a| (*a, cpu.read_u32(*a).unwrap_or(0xDEAD_DEAD)))
    .collect();
    let objeto = cpu.read_u32(0x882F_1EB4).unwrap_or(0);
    let metodo = if objeto != 0 {
        cpu.read_u32(objeto.wrapping_add(20)).unwrap_or(0xDEAD_DEAD)
    } else {
        0xDEAD_DEAD
    };
    // TEMP (kernel log_buf, v3): printk writes to the buffer even without
    // console. v2 read 16 KB at 0xC02C9000 and went blind past index
    // 0x3FFF — but LOG_BUF_MASK is 0x1FFFF (128 KB ring, proven by
    // the CONDRV text tap). Read the whole ring so wrapped/new
    // content shows up.
    let mut kernel_log: Vec<u8> = Vec::new();
    {
        let mut buf = vec![0u8; 0x2_0000];
        let mut ok_total = 0;
        for (i, pg) in buf.chunks_mut(0x1000).enumerate() {
            let va = 0xC02C_9000u32.wrapping_add((i as u32) * 0x1000);
            if cpu.read_mem(va, pg).is_ok() {
                ok_total += 1;
            }
        }
        if ok_total > 0 {
            let txt = String::from_utf8_lossy(&buf);
            // Each message starts at <N>[  t]. Splits there, cleans,
            // sorts by timestamp, keeps the last 60.
            let mut msgs: Vec<(f64, String)> = Vec::new();
            let b = txt.as_bytes();
            let mut cortes = vec![0usize];
            let mut i = 0;
            while i + 3 < b.len() {
                if b[i] == b'<'
                    && b[i + 1].is_ascii_digit()
                    && b[i + 2] == b'>'
                    && b[i + 3] == b'['
                {
                    cortes.push(i);
                    i += 4;
                } else {
                    i += 1;
                }
            }
            cortes.push(b.len());
            for w in cortes.windows(2) {
                let seg = &txt[w[0]..w[1]];
                let limpa: String = seg
                    .split('\0')
                    .next()
                    .unwrap_or("")
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '\t')
                    .take(240)
                    .collect();
                // Extracts [  ss.mmmmmm].
                let ts = limpa.find('[').and_then(|a| {
                    limpa[a..].find(']').map(|z| limpa[a + 1..a + z].trim().parse::<f64>().unwrap_or(-1.0))
                }).unwrap_or(-1.0);
                if !limpa.is_empty() {
                    msgs.push((ts, limpa));
                }
            }
            msgs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
            // Dedupes keeping order, prints the last 60.
            let mut vistas = std::collections::HashSet::new();
            let mut finais: Vec<&String> = Vec::new();
            for (_, m) in msgs.iter() {
                if vistas.insert(m.clone()) {
                    finais.push(m);
                }
            }
            let corte = finais.len().saturating_sub(60);
            for m in &finais[corte..] {
                kernel_log.extend_from_slice(m.as_bytes());
                kernel_log.push(b'\n');
            }
        }
    }
    // Tail of the executed path: the FULL 2048-entry ring (no cap) so a
    // clearer running shortly before the fault is visible, not just the
    // final branch sequence.
    let hist = cpu.historico();
    let caminho: Vec<String> = hist
        .iter()
        .map(|pc| format!("{pc:#010x}"))
        .collect();
    // Ring content peek: head of channel 3's 4 KiB at the constant data
    // area `0x882A24FC + 3*0x1000`.
    let mut cabeca = vec![0u8; 256];
    let _ = cpu.read_mem(0x882A_24FC + 3 * 0x1000, &mut cabeca);
    VivoFim {
        parada: format!("{parada:?}"),
        linhas,
        parcial,
        slots,
        caminho,
        cabeca,
        texto,
        limpezas,
        leituras,
        objeto,
        metodo,
        achados: (objeto_encontrado, nand_preenchido, nand_limpo, mapeadas),
        regs_saida: regs_saida.get(),
        atags: atags.borrow().clone(),
        kernel_tx: kernel_tx.borrow().clone(),
        kernel_log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sonda_traduz_janela_1f000() {
        // The 0x1FCE0 user fault must reach the PT-walk arm: no SPL
        // alias, no suspect window.
        assert_eq!(traduz(0x1F000), None);
        assert!(janela_de(0x1F000).is_none());
    }

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

    #[test]
    fn trace_imprime_sem_panico() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, Reg};
        let mut cpu = Interpretador::new().unwrap();
        cpu.map_zeroed("code", 0x1000, 0x1000).unwrap();
        // add r0, r0, #0x1 ; str r1, [r2] ; b .-8 (loop).
        cpu.write_mem(0x1000, &0xE280_0001u32.to_le_bytes()).unwrap();
        cpu.write_mem(0x1004, &0xE582_1000u32.to_le_bytes()).unwrap();
        cpu.write_mem(0x1008, &0xEAFF_FFFEu32.to_le_bytes()).unwrap();
        cpu.write_reg(Reg::Pc, 0x1004);
        cpu.write_reg(Reg::R2, 0x2000);
        // Must not panic; output eyeballed with --nocapture. The 0x2000
        // store target is unmapped on purpose (fault addr demo).
        imprime_trace(&cpu, 0x1004, Some(0x2000));
    }

    /// Live-run frontier: reset vector through the reset function.
    ///
    /// The `PUTC_ADDR` trap is plumbed from the first live run even though
    /// the reset path prints nothing yet: a callback here means the wiring
    /// regressed. The run must stop at the cold/warm probe read
    /// (`[0x418] == 0x01f6a2a8`, bit `0x200`): CP15 MCR/MRC is accepted under
    /// the flat-memory hypothesis, and the probe window is deliberately
    /// unmapped, so its fault names the next peripheral to model. `0x74`
    /// loads the probe pointer from `[0x418]`; `0x78` dereferences it.
    /// Each backend/CP15/MMIO step moves this frontier forward one fault.
    #[test]
    fn spl_vivo_para_na_sonda_reset() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mem = monta_mapa_inicial(&spl).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        let chamadas = std::rc::Rc::new(std::cell::RefCell::new(0u32));
        let conta = chamadas.clone();
        cpu.trap_pc(PUTC_ADDR, move |_, _| *conta.borrow_mut() += 1);
        let parada = cpu.run(0, 1000).unwrap();
        assert_eq!(
            parada,
            StopReason::MemoryFault {
                addr: SONDA_RESET,
                pc: 0x78
            }
        );
        assert_eq!(*chamadas.borrow(), 0, "reset path prints nothing");
    }


    /// Live-run frontier on Dynarmic: reset vector until the first CP15 op.
    ///
    /// The JIT backend has no CP15/MMU support yet (see `arm_coproc` in the
    /// interpretador, which accepts MCR/MRC under the flat-memory
    /// hypothesis), so the live run must stop at the first coprocessor
    /// access (`MRC p15,0,r0,c1,c0,1` at `0x4c`). This pins the gap between
    /// the backends: same map, same trap plumbing, earlier wall. The trap
    /// itself wires up fine (no callbacks would fire: the reset path is
    /// silent) — *if* execution ever got past the CP15 wall. It does not:
    /// the guest MRC aborts the host process instead of faulting.
    ///
    /// Vendored `dynarmic` 0.1.3 hits `assertion failed: false` /
    /// `Should raise coproc exception here` and dies with SIGABRT instead of
    /// routing the fault to the `raised_exception` callback — same class of
    /// defect as the ignored LDREX/`global_monitor` test in `dynarmic.rs`,
    /// and likewise fixable only inside the dependency (implement the coproc
    /// hook or downgrade the assert to a proper exception). Until then this
    /// test stays ignored; running it with `-- --ignored` kills the runner,
    /// by design of the defect, not of the test.
    #[cfg(not(any(target_arch = "wasm32", target_os = "ios")))]
    #[ignore = "SPL MRC aborts vendored dynarmic 0.1.3 (SIGABRT); see comment"]
    #[test]
    fn spl_vivo_dynarmic_para_no_cp15() {
        use crate::cpu::dynarmic::DynarmicCpu;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mem = monta_mapa_inicial(&spl).unwrap();
        let mut cpu = DynarmicCpu::new().unwrap();
        cpu.reset(&mem).unwrap();
        let chamadas = std::rc::Rc::new(std::cell::RefCell::new(0u32));
        let conta = chamadas.clone();
        cpu.trap_pc(PUTC_ADDR, move |_, _| *conta.borrow_mut() += 1);
        let parada = cpu.run(0, 1000).unwrap();
        assert_eq!(parada, StopReason::Exception { pc: 0x4c });
        assert_eq!(*chamadas.borrow(), 0, "reset path prints nothing");
    }

    /// Pinned frontier: ready-check on a widely-referenced device base.
    ///
    /// Path: post-BSS init calls `bl 0x88028E3C` from `0x88000F34`
    /// (lr `0x88000F38` at the fault). `0x88028E3C` loads `r2 = 0xAA0FC000`
    /// from its pool and falls into `0x88028E40`, which faults at
    /// `ldr r3, [r2, #0x44]` (`0x88028E48`). `0xAA0FC000` is a pool constant
    /// referenced SPL-wide (20+ sites), but matches no `MAPA_SECOES` entry
    /// as VA or PA: either the section-table decode missed entries (sparse
    /// L1+L2 hypothesis) or later init maps it. The faulting function tests
    /// `[r2+0x44] & 1` and skips its write block when clear, so a zeroed
    /// stub takes the skip branch. Peripheral identity still UNKNOWN.
    #[test]
    fn spl_vivo_para_no_mmio_aa0fc044() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, Reg, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mut mem = monta_mapa_inicial(&spl).unwrap();
        mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
        mem.map_zeroed("perif_b540_stub", 0xB540_0000, 0x1000).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        let chamadas = std::rc::Rc::new(std::cell::RefCell::new(0u32));
        let conta = chamadas.clone();
        cpu.trap_pc(PUTC_ADDR, move |_, _| *conta.borrow_mut() += 1);
        let parada = cpu.run(0, 20_000_000).unwrap();
        assert_eq!(
            parada,
            StopReason::MemoryFault {
                addr: 0xAA0F_C044,
                pc: 0x8802_8E48
            }
        );
        assert_eq!(cpu.read_reg(Reg::R2), 0xAA0F_C000);
        assert_eq!(cpu.read_reg(Reg::Lr), 0x8800_0F38);
    }

    /// Pinned frontier: dispatcher handler on an identity-mapped peripheral.
    ///
    /// `0x8802761C` is a 12-entry dispatcher (`cmp r0, #12`, jump table at
    /// `0x88027634`; entries 8-9 return immediately). Entry 0 (taken here)
    /// lands at `0x88027708`, which loads `r2 = [0x88027D48] = 0xA8081000`
    /// and faults at `ldrb r4, [r2, #77]` (`0x88027714`): a byte-wise 32-bit
    /// RMW (`mvn r1`, `and`, `strb`) over `[base+0x4C..0x4F]`.
    /// `0xA8081000` lies inside phys `0xA8000000-0xA80FFFFF`, which the
    /// section table maps only at VA `0x90D00000`: the driver uses the
    /// physical address post-MMU, so either the table decode is incomplete
    /// (sparse L1+L2 hypothesis) or peripherals are reachable both ways.
    /// Real identity UNKNOWN; a RAM-like stub answers "what comes after?".
    #[test]
    fn spl_vivo_para_no_mmio_a808104d() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mut mem = monta_mapa_inicial(&spl).unwrap();
        mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
        mem.map_zeroed("perif_b540_stub", 0xB540_0000, 0x1000).unwrap();
        mem.map_zeroed("perif_aa0f_stub", 0xAA0F_C000, 0x1000).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        let chamadas = std::rc::Rc::new(std::cell::RefCell::new(0u32));
        let conta = chamadas.clone();
        cpu.trap_pc(PUTC_ADDR, move |_, _| *conta.borrow_mut() += 1);
        let parada = cpu.run(0, 20_000_000).unwrap();
        assert_eq!(
            parada,
            StopReason::MemoryFault {
                addr: 0xA808_104D,
                pc: 0x8802_7714
            }
        );
    }

    /// Pinned frontier: entry-0 handler stores through a slot-loaded base.
    ///
    /// After the byte RMW at `[0xA8081000+0x4C..0x4F]`, the handler loads
    /// `r1 = [0x88027D4C] = 0x882A0DDC` (another RAM slot, same pattern as
    /// `0x882A1278`), `r4 = [slot] = 0xBD000000` (stored by earlier init),
    /// and faults at `strh r3, [r4, #10]` (`0x880277A0`). Neither the slot
    /// nor the base matches decoded tables: peripheral identity UNKNOWN.
    #[test]
    fn spl_vivo_para_no_mmio_bd00000a() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mut mem = monta_mapa_inicial(&spl).unwrap();
        mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
        mem.map_zeroed("perif_b540_stub", 0xB540_0000, 0x1000).unwrap();
        mem.map_zeroed("perif_aa0f_stub", 0xAA0F_C000, 0x1000).unwrap();
        mem.map_zeroed("perif_a808_stub", 0xA808_1000, 0x1000).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        let chamadas = std::rc::Rc::new(std::cell::RefCell::new(0u32));
        let conta = chamadas.clone();
        cpu.trap_pc(PUTC_ADDR, move |_, _| *conta.borrow_mut() += 1);
        let parada = cpu.run(0, 20_000_000).unwrap();
        assert_eq!(
            parada,
            StopReason::MemoryFault {
                addr: 0xBD00_000A,
                pc: 0x8802_77A0
            }
        );
    }

    /// Pinned frontier: first log call touches NAND status.
    ///
    /// `0x88022B84` loads `r0 = [0x88022BC8]` (format string) and
    /// `0x88022B88` faults at `ldr r2, [r1]` with `r1 = [r6+#88] =
    /// 0xB2A00C10`: the log argument is a NAND-controller register in the
    /// `0xB2Axxxxx` range (same driver family as `BLOCO_B23`). The very next
    /// instruction is `bl PRINT_FORMAT` (`0x88022B8C`): serial output is one
    /// stub away. Fault page is `0xB2A00C00` (`+0xC10` exceeds a 4K page at
    /// the range base).
    #[test]
    fn spl_vivo_para_no_nand_b2a00c10() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mut mem = monta_mapa_inicial(&spl).unwrap();
        mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
        mem.map_zeroed("perif_b540_stub", 0xB540_0000, 0x1000).unwrap();
        mem.map_zeroed("perif_aa0f_stub", 0xAA0F_C000, 0x1000).unwrap();
        mem.map_zeroed("perif_a808_stub", 0xA808_1000, 0x1000).unwrap();
        mem.map_zeroed("perif_bd00_stub", 0xBD00_0000, 0x1000).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        let chamadas = std::rc::Rc::new(std::cell::RefCell::new(0u32));
        let conta = chamadas.clone();
        cpu.trap_pc(PUTC_ADDR, move |_, _| *conta.borrow_mut() += 1);
        let parada = cpu.run(0, 20_000_000).unwrap();
        assert_eq!(
            parada,
            StopReason::MemoryFault {
                addr: 0xB2A0_0C10,
                pc: 0x8802_2B88
            }
        );
    }

    /// Pinned frontier: first SPL byte reaches the host.
    ///
    /// Forced emit path B (`[0x882A1CD0] = 2` plant) routes prints through
    /// channel 3; the UART TX-ready stub bit lets `CH_PUTC` proceed to the
    /// ring-full gate (`0x88003D50` returns slot `+8`). The first `PUTC`
    /// call carries `b'+'` (start of the `+dmov…` family) on channel 3, then
    /// the run spins in the `D4..F8` poll because ring `+8` is stuck at 1
    /// (full on an empty ring: no consumer has ever drained it). Unsticking
    /// that is the host ring-drain work (TODO item 2), not another stub.
    #[test]
    fn spl_vivo_primeiro_byte_na_serial() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, Reg, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR_POS_MMU;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mut mem = monta_mapa_inicial(&spl).unwrap();
        mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
        mem.map_zeroed("perif_b540_stub", 0xB540_0000, 0x1000).unwrap();
        mem.map_zeroed("perif_aa0f_stub", 0xAA0F_C000, 0x1000).unwrap();
        mem.map_zeroed("perif_a808_stub", 0xA808_1000, 0x1000).unwrap();
        mem.map_zeroed("perif_bd00_stub", 0xBD00_0000, 0x1000).unwrap();
        mem.map_zeroed("perif_b2a0_stub", 0xB2A0_0C00, 0x1000).unwrap();
        mem.map_zeroed("perif_b280_stub", 0xB280_0000, 0x1000).unwrap();
        mem.write(0xB280_0008, &1u32.to_le_bytes()).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_u32(0xAA0F_C044, 1).unwrap();
        let mut pc = 0u32;
        for _ in 0..20 {
            match cpu.run(pc, 100_000).unwrap() {
                StopReason::Budget => {
                    pc = cpu.read_reg(Reg::Pc);
                    if pc >= 0x8800_0828 {
                        break;
                    }
                }
                outra => panic!("fase 1 parou cedo: {outra:?}"),
            }
        }
        cpu.write_u32(0x882F_79F8, 1).unwrap();
        cpu.write_u32(0x882A_1CD0, 2).unwrap();
        let tap = std::rc::Rc::new(std::cell::RefCell::new(
            crate::msm7201a_serial::SerialTap::new(),
        ));
        let grava = tap.clone();
        cpu.trap_pc(PUTC_ADDR_POS_MMU, move |canal, byte| {
            grava.borrow_mut().byte(canal, byte)
        });
        let parada = cpu.run(pc, 20_000_000).unwrap();
        assert_eq!(parada, StopReason::Budget);
        assert_eq!(tap.borrow().bytes_do_canal(3), b"+");
        let pc_fim = cpu.read_reg(Reg::Pc);
        assert!(
            (0x8800_3D50..=0x8800_3D6C).contains(&pc_fim)
                || (0x8800_40D4..=0x8800_40F8).contains(&pc_fim),
            "fora do poll do anel: {pc_fim:#010x}"
        );
    }




    /// Discovery (not pinned): same run with the NAND page stubbed, tap live.
    ///
    /// The tuple assert prints both the stop reason and any tapped lines on
    /// any deviation, so a single failure shows the next fault AND the first
    /// serial output (if the run gets that far).
    #[test]
    fn spl_vivo_descobre_apos_b2a00c10() {
        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let nand = std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/spl/nand.img"),
        )
        .unwrap_or_default();
        let fim = executa_spl_vivo(&spl, &nand, 200_000, 2_000, |_, _, _, _| true);
        assert_eq!(
            fim,
            VivoFim {
                parada: String::from("Budget"),
                linhas: Vec::new(),
                parcial: Vec::new(),
                slots: Vec::new(),
                caminho: Vec::new(),
                cabeca: Vec::new(),
                texto: String::new(),
                limpezas: 0,
                leituras: Vec::new(),
                objeto: 0,
                metodo: 0xDEAD_DEAD,
                achados: (None, None, None, Vec::new()),
                regs_saida: [0; 4],
                atags: Vec::new(),
                kernel_tx: Vec::new(),
                kernel_log: Vec::new(),
            }
        );
    }


    /// Pinned frontier: first device register access.
    ///
    /// Cold stub in place, BSS cleared (`0x882A1CCC-0x882FB0E8`), stack at
    /// `0x8809FFFC`, init reaches `0x880042D4`: `r2 = [0x88004320]` points at
    /// RAM slot `0x882A1278`, `r1 = [slot] = 0xB5400000` (stored by earlier
    /// init: the slot sits below the BSS range, so it survived the zero loop;
    /// our RAM starts zeroed, so this value was deliberately stored, not
    /// garbage), then `ldr r3, [r1, #260]` faults. The RMW that follows
    /// (`orr #6` at `+0x104`, `bic/orr` at `+0x100`) reads like a clock-enable,
    /// but `0xB5400000` matches no `MAPA_SECOES` entry and no literal in the
    /// inherited docs: peripheral identity is UNKNOWN. Next step is a RAM-like
    /// stub window answering "what comes after?" (same class of hypothesis as
    /// the cold stub), not a hardware model.
    #[test]
    fn spl_vivo_para_no_mmio_b5400104() {
        use crate::cpu::interpretador::Interpretador;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mut mem = monta_mapa_inicial(&spl).unwrap();
        mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        let chamadas = std::rc::Rc::new(std::cell::RefCell::new(0u32));
        let conta = chamadas.clone();
        cpu.trap_pc(PUTC_ADDR, move |_, _| *conta.borrow_mut() += 1);
        // 5M covers the ~390k-instruction BSS zero loop at `0x88000818` and
        // the init that follows; the optimized test profile runs this in ~1s.
        let parada = cpu.run(0, 5_000_000).unwrap();
        assert_eq!(
            parada,
            StopReason::MemoryFault {
                addr: 0xB540_0104,
                pc: 0x8800_42E0
            }
        );
    }
}
