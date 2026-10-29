//! Initial MSM7201A map for the Dream fork.
//!
//! Dreamyemu emulates the Zeebo via BREW HLE: the game never touches silicon. The
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
#[cfg(any(test, target_arch = "wasm32", target_os = "ios", feature = "interpretador"))]
use crate::cpu::CpuBackend;

/// Current slice number, mirrored for TEMP traps (see also
/// `SNAPSHOT_SAVE_FATIA`). Module level so the CPU backend can
/// stamp it (watchpoints). Remove with CRASHOBJ.
#[allow(non_upper_case_globals)]
pub(crate) static mut FATIA_ATUAL: u32 = 0;

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
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
fn le_ram_fisica(
    cpu: &mut crate::cpu::dual::DualBackend,
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
    let mut via_mapa = -1i32;
    let mut via_semente = -1i32;
    if cpu.map_zeroed("usuario_ptw", base, 0x1000).is_ok() {
        via_mapa = 1;
        let mut pg = vec![0u8; 0x1000];
        if cpu.read_mem(pa, &mut pg).is_ok() {
            via_semente = 1;
            let _ = cpu.write_mem(base, &pg);
        } else {
            via_semente = 0;
        }
    } else {
        via_mapa = 0;
    }
    let fim = cpu.read_mem(va, buf).is_ok();
    // TEMP (resume-divergence hunt): name the failing step when the
    // alias serve bails (resume logs fonte=zeros where direct logs
    // alias). Cap 8, narrow window. Remove with CRASHOBJ.
    static mut NLR: u32 = 0;
    unsafe {
        if NLR < 8 && (0xC500_0000..0xC600_0000).contains(&va) {
            NLR += 1;
            eprintln!("LRRAM#{} va={va:#x} pa={pa:#x} mapa={via_mapa} semente={via_semente} fim={fim}", unsafe { NLR });
        }
    }
    fim
}

/// Read a page-TABLE word through the lowmem alias WITHOUT mapping
/// or seeding: table pages the guest built via fixmap are invisible
/// here, and seeding from the stale PA bank manufactures phantom
/// PTEs (proven live: phantom text/data mappings). Unmapped alias =
/// miss (the abort path installs the real entry, the mirror trap
/// copies it, the retry then hits). Only RAM PAs are readable.
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
fn le_ram_tabela(
    cpu: &mut crate::cpu::dual::DualBackend,
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
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
fn caminha_pt_usuario(
    cpu: &mut crate::cpu::dual::DualBackend,
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

/// TEMP (file-backed serve): resolve (guest path, file offset) for a
/// user fault via task->mm->VMA->file->dentry. mm comes from the
/// caller (serve arm knows TTBR); mm_struct from the seeded map.
/// Returns None for anonymous pages or any unresolvable step
/// (caller falls back to alias/zeros).
///
/// Offsets fit live on this kernel (2.6.27 MSM): task->mm +0x1B0
/// (triple-hit VMA coverage incl. fault page, libdvm text, stack),
/// mm->mmap +0, vma{mm+0, start+4, end+8, next+12, ops+64,
/// pgoff+68, file+72} (vm_mm back-pointer verified), file:
/// dentry=file+12, dentry{parent+0x14, name=+0x20 -> c-string}.
/// Fecha o ciclo com o YAFFS (le() valida o conteúdo).
/// Remove with CRASHOBJ.
fn caminho_arquivo_para_falta(
    cpu: &mut crate::cpu::dual::DualBackend,
    mapa: &std::collections::HashMap<u32, u32>,
    va: u32,
) -> Option<(String, u32, u32)> {
    fn le32(cpu: &mut crate::cpu::dual::DualBackend, a: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        cpu.read_mem(a, &mut b).ok()?;
        Some(u32::from_le_bytes(b))
    }
    let mm = cpu.mm_atual();
    let &m = mapa.get(&mm)?;
    // Closure check: M+0 -> VMA whose vm_mm points back at M.
    let v0 = le32(cpu, m)?;
    if !(0xC600_0000..0xC700_0000).contains(&v0) {
        return None;
    }
    if le32(cpu, v0)? != m {
        return None;
    }
    // Walk the VMA list for the fault page.
    let mut vma = v0;
    let mut depth = 0u32;
    let (ini, pgoff, arq, flags) = loop {
        if !(0xC600_0000..0xC700_0000).contains(&vma) || depth > 200 {
            return None;
        }
        depth += 1;
        let mut vb = [0u8; 80];
        cpu.read_mem(vma, &mut vb).ok()?;
        let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
        let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
        if ini <= va && va < fim {
            let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
            let pgoff = u32::from_le_bytes([vb[68], vb[69], vb[70], vb[71]]);
            let arq = u32::from_le_bytes([vb[72], vb[73], vb[74], vb[75]]);
            break (ini, pgoff, arq, fl);
        }
        vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
    };
    if arq == 0 || !(0xC600_0000..0xC700_0000).contains(&arq) {
        return None;
    }
    // dentry + parent chain (names only; mount crossing ignored —
    // the YAFFS lookup suffix-matches).
    let mut dent = le32(cpu, arq.wrapping_add(12))?;
    let mut partes: Vec<String> = Vec::new();
    let mut guard = 0u32;
    loop {
        if !(0xC000_0000..0xD000_0000).contains(&dent) || guard >= 16 {
            return None;
        }
        guard += 1;
        let nome_p = le32(cpu, dent.wrapping_add(0x20))?;
        let mut nb = [0u8; 128];
        cpu.read_mem(nome_p, &mut nb).ok()?;
        let z = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
        if z == 0 || z >= 128 {
            return None;
        }
        let nome = String::from_utf8_lossy(&nb[..z]).into_owned();
        if z > 127 || !nome.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return None;
        }
        partes.push(nome);
        let pai = le32(cpu, dent.wrapping_add(0x14))?;
        if pai == dent {
            break;
        }
        dent = pai;
    }
    if partes.is_empty() {
        return None;
    }
    partes.reverse();
    let caminho = String::from("/") + &partes.join("/");
    let desloc = pgoff.wrapping_mul(4096).wrapping_add(va.wrapping_sub(ini));
    Some((caminho, desloc, flags))
}

/// TEMP (anon-vs-file gate): fresh anon heap must seed zeros, not
/// stale alias bytes (proven: brk/mmap anon page 0xa0000 seeded
/// alias garbage incl. 0xADA15FFF -> heap object -> wild libsgl
/// head 0xac1333d8 -> SIGSEGV). File text keeps alias (page-cache
/// ground truth, proven by URES heads). Returns Some(true)=anon
/// (VMA found, no file), Some(false)=file-backed, None=unknown
/// (no mm/VMA — keep today's alias behavior so early text before
/// MMSEED2 still works). Remove with CRASHOBJ.
fn vma_e_anonima(
    cpu: &mut crate::cpu::dual::DualBackend,
    mapa: &std::collections::HashMap<u32, u32>,
    va: u32,
) -> Option<bool> {
    fn le32(cpu: &mut crate::cpu::dual::DualBackend, a: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        cpu.read_mem(a, &mut b).ok()?;
        Some(u32::from_le_bytes(b))
    }
    let mm = cpu.mm_atual();
    let &m = mapa.get(&mm)?;
    let v0 = le32(cpu, m)?;
    if !(0xC600_0000..0xC700_0000).contains(&v0) {
        return None;
    }
    if le32(cpu, v0)? != m {
        return None;
    }
    let mut vma = v0;
    let mut depth = 0u32;
    while (0xC600_0000..0xC700_0000).contains(&vma) && depth <= 200 {
        depth += 1;
        let mut vb = [0u8; 80];
        cpu.read_mem(vma, &mut vb).ok()?;
        let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
        let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
        if ini <= va && va < fim {
            let arq = u32::from_le_bytes([vb[72], vb[73], vb[74], vb[75]]);
            if arq == 0 {
                return Some(true);
            }
            if (0xC600_0000..0xC700_0000).contains(&arq) {
                return Some(false);
            }
            return None;
        }
        vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
    }
    None
}

/// Whether the VMA covering `va` is writable (VM_WRITE).
/// Same walk as `vma_e_anonima` (vm_flags at +20, VM_WRITE = 0x2).
/// None = unreadable/unknown (caller keeps today's behavior).
fn vma_e_gravavel(
    cpu: &mut crate::cpu::dual::DualBackend,
    mapa: &std::collections::HashMap<u32, u32>,
    va: u32,
) -> Option<bool> {
    fn le32(cpu: &mut crate::cpu::dual::DualBackend, a: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        cpu.read_mem(a, &mut b).ok()?;
        Some(u32::from_le_bytes(b))
    }
    let mm = cpu.mm_atual();
    let &m = mapa.get(&mm)?;
    let v0 = le32(cpu, m)?;
    if !(0xC600_0000..0xC700_0000).contains(&v0) {
        return None;
    }
    if le32(cpu, v0)? != m {
        return None;
    }
    let mut vma = v0;
    let mut depth = 0u32;
    while (0xC600_0000..0xC700_0000).contains(&vma) && depth <= 200 {
        depth += 1;
        let mut vb = [0u8; 80];
        cpu.read_mem(vma, &mut vb).ok()?;
        let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
        let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
        if ini <= va && va < fim {
            let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
            return Some(fl & 0x2 != 0);
        }
        vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
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
    // TEMP (webcore-vs-display): disp_aa00 0xAA000000 REMOVED — SPL-era
    // display-register hypothesis shadows Linux userspace file mappings
    // that reuse the same VA (webcore text at 0xaa008000 served zeros
    // via demanda, no file branch -> wild link_map shift -> linker
    // SIGSEGV; VMA [0xaa000000,0xaa2d5000) file-backed wins). Linux
    // display runs via kernel ioremap + /dev/graphics/fb0 (file-backed
    // /dev, not this window), so dropping the window only loses SPL
    // bootloader display tracing (long done). If a genuine 0xAA00xxxx
    // device fault appears, DEMCLASSE-style logging will name it.
    // Remove with CRASHOBJ (replace with VMA-class tracking).
    // JanelaMmio {
    //     nome: "disp_aa00",
    //     base: 0xAA00_0000,
    // },
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
/// Only compiled where the dual backend exists (see [`crate::cpu::dual`]):
/// the live run dispatches through `DualBackend`, which stays on the
/// interpretador until the harness has seen userspace (see
/// [`crate::cpu::dual::DualBackend::permite_jit`]).
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
    /// Kernel printk buffer: full `printk` history for the run,
    /// stitched host-side from per-slice ring drains (chronological,
    /// repeats kept). Falls back to the end-of-run ring snapshot
    /// (last 60, for short or pre-kernel runs).
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
/// ([`executa_spl_vivo_com_botoes`]) is `dual`-gated.
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

/// Linux framebuffer mapping for the host presenter: `(mm, va0)` of the
/// 75-page userspace burst the FBMAP hunt names (320x480 RGB565,
/// single-buffered first window). `(0, 0)` until the hunt fires; the
/// presenter shows the SPL splash (`RAM_A6C0_BASE`) until then.
/// Same-thread share (the harness and the SDL frame loop run on the
/// UI thread), mirroring the file's other host-visible statics.
#[allow(non_upper_case_globals)]
pub static mut FB_LINUX_MAPA: (u32, u32) = (0, 0);

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

/// Drain new Android logcat entries from the three kernel logger ring
/// buffers (main/events/radio) into host-side lines. The logger driver
/// keeps static buffers (`_buf_log_{main,events,radio}`) with static
/// descriptors at 0xC02B9DE0/34/88 (+0 = buffer VA, +0x50 = size);
/// the write offset lives at one of +0x40/+0x48/+0x4C (layout varies
/// slightly by version — calibrated at runtime as the word that
/// advances while staying < size). Entries are `struct logger_entry`
/// (16 B header: len/pid/tid/sec/nsec) + `prio tag\0 msg\0`. Returns
/// formatted `LOGCAT {log} {P}/{tag}: {msg}` lines (P = VDIWEF).
/// Frontends call this per slice; idle slices cost a few reads.
/// Cap 30000 lines total (then only errors/fatals — the dalvik
/// preload is extremely chatty).
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
pub fn colhe_logcat(cpu: &mut crate::cpu::dual::DualBackend) -> Vec<String> {
    const LOGS: [(&str, u32, u32); 3] = [
        ("main", 0xC02B_9DE0, 65536),
        ("events", 0xC02B_9E34, 262144),
        ("radio", 0xC02B_9E88, 65536),
    ];
    const OFFS: [u32; 4] = [0x3C, 0x40, 0x48, 0x4C];
    static mut ULTIMO: [u32; 3] = [0, 0, 0];
    static mut QUAL: [usize; 3] = [0, 0, 0];
    static mut TOTAL: u32 = 0;
    static mut AVISADO: bool = false;
    static mut DIAGNOSTICADO: bool = false;
    static mut DIAG2: [bool; 3] = [false; 3];
    let mut fora = Vec::new();
    // One-shot layout diagnostic: fires on the first call where at
    // least one log's size reads back correctly (logger_init done),
    // showing buffer readability + the w_off candidates. Remove
    // once the offsets are confirmed live.
    unsafe {
        if !DIAGNOSTICADO {
            let mut pronto = false;
            for (_, base, tam_esperado) in LOGS.iter() {
                let mut b = [0u8; 4];
                if cpu.read_mem(base + 0x50, &mut b).is_ok()
                    && u32::from_le_bytes(b) == *tam_esperado
                {
                    pronto = true;
                }
            }
            if pronto {
                DIAGNOSTICADO = true;
            for (nome, base, tam_esperado) in LOGS.iter() {
                let le32 = |va: u32| {
                    let mut b = [0u8; 4];
                    cpu.read_mem(va, &mut b)
                        .map(|_| u32::from_le_bytes(b))
                        .unwrap_or(0xDEAD_DEAD)
                };
                let buf = le32(*base);
                let tam = le32(base + 0x50);
                let c: [u32; 5] = [le32(base + 0x3C), le32(base + 0x40), le32(base + 0x44), le32(base + 0x48), le32(base + 0x4C)];
                let mut hb = [0xEEu8; 16];
                let lok = cpu.read_mem(buf, &mut hb).is_ok();
                eprintln!("LOGDIAG {nome} buf={buf:#x} tam={tam:#x} (esp {tam_esperado:#x}) c3c={:#x} c40={:#x} c44={:#x} c48={:#x} c4c={:#x} read_ok={lok} head16={hb:02x?}", c[0], c[1], c[2], c[3], c[4]);
                }
            }
        }
    }
    for (li, (nome, base, tam_esperado)) in LOGS.iter().enumerate() {
        let le32 = |va: u32| {
            let mut b = [0u8; 4];
            cpu.read_mem(va, &mut b)
                .map(|_| u32::from_le_bytes(b))
                .unwrap_or(0xDEAD_DEAD)
        };
        let buf = le32(*base);
        let tam = le32(base + 0x50);
        // One-shot activity diagnostic: first call where any candidate
        // word is nonzero shows which offset moves (= w_off).
        unsafe {
            if !DIAG2[li] && tam == *tam_esperado {
                let c0 = le32(base + 0x3C);
                let c1 = le32(base + 0x40);
                let c2 = le32(base + 0x48);
                let c3 = le32(base + 0x4C);
                if c0 != 0 || c1 != 0 || c2 != 0 || c3 != 0 {
                    DIAG2[li] = true;
                    let mut hb = [0xEEu8; 16];
                    let lok = cpu.read_mem(buf, &mut hb).is_ok();
                    eprintln!("LOGDIAG2 {nome} c3c={c0:#x} c40={c1:#x} c48={c2:#x} c4c={c3:#x} head16={hb:02x?} ok={lok}");
                }
            }
        }
        if tam != *tam_esperado || buf < 0xC000_0000 {
            continue;
        }
        let cand: [u32; 4] = [le32(base + OFFS[0]), le32(base + OFFS[1]), le32(base + OFFS[2]), le32(base + OFFS[3])];
        let w = unsafe { ULTIMO[li] };
        // Adopt the write offset among the four probed words.
        // Only candidates that CHANGED since the last slice are
        // eligible: static fields (size, constants) never move and
        // must not be adopted. The old first-differing pick grabbed
        // a static word and re-emitted nearly the whole ring every
        // slice (the 21k debuggerd banners and 9.3M AKMD duplicates);
        // forward-only from a changed word can never go backward.
        // QUAL persists the pick across slices (tie-break).
        static mut ANTERIOR: [[u32; 4]; 3] = [[0, 0, 0, 0]; 3];
        let ant = unsafe { ANTERIOR[li] };
        let mut melhor: Option<(u64, usize)> = None;
        let prev = unsafe { QUAL[li] };
        for (k, v) in cand.iter().enumerate() {
            if *v >= tam || *v == w || *v == ant[k] {
                continue;
            }
            let fw = v.wrapping_sub(w) % tam;
            if fw == 0 {
                continue;
            }
            // Tie-break toward the previous pick (stable w_off).
            let chave = ((fw as u64) << 1) | (if k == prev { 0 } else { 1 });
            if melhor.map_or(true, |(m, _)| chave < m) {
                melhor = Some((chave, k));
            }
        }
        let q = match melhor {
            Some((_, k)) => k,
            None => {
                unsafe {
                    ANTERIOR[li] = cand;
                }
                continue;
            }
        };
        unsafe {
            QUAL[li] = q;
            ANTERIOR[li] = cand;
        }
        let novo = cand[q];
        if novo == w || novo >= tam {
            continue;
        }
        // Parse [w, novo) with wraparound; each entry is a 20 B
        // struct logger_entry header + len payload bytes.
        let mut saidas = 0;
        let mut off = w;
        while off != novo && saidas < 200 {
            let mut hb = [0u8; 20];
            let p0 = off;
            let mut resto = 20u32;
            let mut ok = true;
            let mut ho = 0usize;
            while resto > 0 {
                let chunk = resto.min(tam - (off % tam));
                let mut tmp = vec![0u8; chunk as usize];
                if cpu.read_mem(buf.wrapping_add(off % tam), &mut tmp).is_err() {
                    ok = false;
                    break;
                }
                hb[ho..ho + tmp.len()].copy_from_slice(&tmp);
                ho += tmp.len();
                resto -= tmp.len() as u32;
                off = (off + tmp.len() as u32) % tam;
            }
            if !ok {
                break;
            }
            let len = u16::from_le_bytes([hb[0], hb[1]]) as u32;
            if len > 4096 || len < 1 {
                break;
            }
            // struct logger_entry is 20 B (len + pad + pid + tid +
            // sec + nsec): w_off advanced by exactly 20+len on the
            // first live entries (0x3c = 20+40).
            let total = 20 + len;
            // Payload (prio + tag\0 + msg\0), may wrap.
            let mut pay = vec![0u8; len as usize];
            let mut po = 0u32;
            let mut okp = true;
            let mut src = (p0 + 20) % tam;
            while po < len {
                let chunk = (len - po).min(tam - src);
                let mut tmp = vec![0u8; chunk as usize];
                if cpu.read_mem(buf.wrapping_add(src), &mut tmp).is_err() {
                    okp = false;
                    break;
                }
                pay[po as usize..po as usize + tmp.len()].copy_from_slice(&tmp);
                po += tmp.len() as u32;
                src = (src + tmp.len() as u32) % tam;
            }
            if !okp {
                break;
            }
            let prio = match pay[0] {
                2 => 'V',
                3 => 'D',
                4 => 'I',
                5 => 'W',
                6 => 'E',
                7 => 'F',
                _ => '?',
            };
            let tag_end = pay.iter().position(|&b| b == 0).unwrap_or(pay.len()).max(1);
            let tag = String::from_utf8_lossy(&pay[1..tag_end.min(pay.len())]);
            let msg_start = tag_end.min(pay.len());
            // Skip the tag's NUL when present.
            let msg_start = if msg_start < pay.len() && pay[msg_start] == 0 {
                msg_start + 1
            } else {
                msg_start
            };
            let msg_end = pay[msg_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|z| msg_start + z)
                .unwrap_or(pay.len());
            let msg = String::from_utf8_lossy(&pay[msg_start..msg_end]);
            let total_linhas = unsafe {
                TOTAL += 1;
                TOTAL
            };
            if total_linhas < 30000 || prio == 'E' || prio == 'F' {
                fora.push(format!("LOGCAT {nome} {prio}/{tag}: {msg}"));
            } else if !unsafe { AVISADO } {
                unsafe {
                    AVISADO = true;
                }
                fora.push(String::from(
                    "LOGCAT: 30000-line cap hit, errors/fatals only from here",
                ));
            }
            saidas += 1;
            // Advance past this entry.
            off = (p0 + total) % tam;
        }
        unsafe {
            ULTIMO[li] = novo;
        }
    }
    fora
}

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
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
fn imprime_trace(
    cpu: &crate::cpu::dual::DualBackend,
    pc_falta: u32,
    addr_falta: Option<u32>,
    motivo: &str,
) {
    use crate::cpu::desarma::desarma;
    use crate::cpu::CpuBackend;
    if let Some(a) = addr_falta {
        eprintln!("TRACE stop [{motivo}] pc={pc_falta:#x} addr={a:#x}");
    } else {
        eprintln!("TRACE stop [{motivo}] pc={pc_falta:#x}");
    }
    // Disassembly window: 8 instructions back, the faulting one marked,
    // 8 forward. Unmapped words print as .word via desarma's fallback
    // only when readable; unreadable slots are marked. Raw word
    // included: the window decodes ARM only, and a Thumb-mode fault
    // would otherwise be unreadable (the bytes are the evidence).
    let mut alvo = pc_falta.wrapping_sub(32);
    for _ in 0..17 {
        let mut w = [0u8; 4];
        let linha = if cpu.read_mem(alvo, &mut w).is_ok() {
            let ins = u32::from_le_bytes(w);
            let seta = if alvo == pc_falta { "=>" } else { "  " };
            format!("{seta} {alvo:#010x} [{ins:#010x}] {}", desarma(alvo, ins))
        } else {
            format!("   {alvo:#010x} [<unmapped>]")
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
    // Process attribution: which address space faulted, which task the
    // kernel thinks is running (thread_info.task at sp&~0x1FFF + 12 —
    // only meaningful with a kernel stack; user-mode faults print
    // the user sp instead since thread_info isn't mapped there),
    // and TTBR0. Names which init/service died without guessing
    // task_struct field offsets.
    {
        let mm = cpu.mm_atual();
        let ger = cpu.geracao();
        let ttbr = cpu.le_cp15(0x100).unwrap_or(0xDEAD);
        if cpsr & 0x1F == 0x10 {
            eprintln!("TRACE mm={mm:#x} geracao={ger} ttbr0={ttbr:#x} (usr sp={:#x})", r[13]);
        } else {
            let ti = r[13] & !0x1FFF;
            let task = cpu.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
            eprintln!("TRACE mm={mm:#x} geracao={ger} ttbr0={ttbr:#x} task={task:#x} (ti={ti:#x})");
        }
    }
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
/// Only compiled where the dual backend exists (see
/// [`crate::cpu::dual`]).
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
pub fn executa_spl_vivo<F>(
    spl: &[u8],
    nand_img: &[u8],
    max_fatias: u32,
    instrs_por_fatia: u64,
    a_cada_fatia: F,
) -> VivoFim
where
    F: FnMut(u32, u32, &mut crate::cpu::dual::DualBackend, &[u8]) -> bool,
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
/// TEMP (snapshots): save trigger — when `fatia` reaches this, the
/// main loop photographs the world and exits. `u32::MAX` = off.
/// Set by the frontend (`--snapshot-save`); path via
/// `SNAPSHOT_SAVE_PATH`. Load path via `SNAPSHOT_LOAD_PATH`
/// (checked once at startup). Remove with CRASHOBJ if snapshots
/// don't pay off.
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
pub static mut SNAPSHOT_SAVE_FATIA: u32 = u32::MAX;
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
pub static SNAPSHOT_SAVE_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
pub static SNAPSHOT_LOAD_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
// TEMP (snapshots): override da vigia pós-carga
// (`--snapshot-vigia ADDR[,LEN]`). Remove with CRASHOBJ.
pub static SNAPSHOT_VIGIA: std::sync::OnceLock<String> = std::sync::OnceLock::new();
// TEMP (snapshots): one-shot/edge behavior flags hoisted to module
// level so the Foto can carry them across a resume. `SPL_FORA`
// (low-image carve) re-firing on resume destroys live low mappings
// and the run stops on the repeat fault (proven: SPL-UNMAP at
// f=375278 on every resume). `ULTIMA/ULTIMO_ALVO` edge-detect IRQ
// delivery; `PLANTA_N` picks fork fn by creation order. All three
// diverge a resume when reset. Remove with CRASHOBJ.
pub static mut SNAP_SPL_FORA: bool = false;
pub static mut SNAP_ULTIMA: Option<u32> = None;
pub static mut SNAP_ULTIMO_ALVO: u32 = 0;
pub static mut SNAP_PLANTA_N: u32 = 0;
/// The MISC plant is applied synchronously in a `memcmp` (`0x88015B80`)
/// trap, not per slice: the guest refills the MISC fields from NAND
/// mid-slice and a per-slice plant always loses that race (proven by the
/// retired `MISCCMP` witness: it saw `0xAA` refill bytes, never the
/// plant). The trap fires before the compare executes, so overwriting
/// the field buffer there wins deterministically. Power and
/// reset-reason are plain registers (no guest refill), planted per
/// slice in the Budget arm.
#[cfg(all(
    not(any(target_arch = "wasm32", target_os = "ios")),
    any(test, feature = "interpretador")
))]
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
    F: FnMut(u32, u32, &mut crate::cpu::dual::DualBackend, &[u8]) -> bool,
{
use crate::cpu::dual::DualBackend;
use crate::cpu::{CpuBackend, StopReason};
use crate::msm7201a_serial::PUTC_ADDR_POS_MMU;

/// Lowest pending, enabled VIC IRQ number (LEVEL, no latch), or
/// `None`. GPT tick (IRQ 7): COUNT >= MATCH, enabled (ENSET bit 7,
/// the kernel-owned word at +0x30), unprogrammed MATCH
/// (`0xFFFFFFFF`) excluded, and the clockevent handler registered
/// (`[0xC02A43EC] != 0`, avoids a null tail-call before setup).
/// DGT (IRQ 8): same shape at +0x10/ENSET bit 8.
/// MDDI host (IRQ 16): command outstanding (CMD doorbell written,
/// INT not yet acked — edge tracked by the MDDIWR watch) and the
/// VIC line enabled (ENSET bit 16). Lets the real IRQ handler run,
/// set its shadow, and complete the mddi_wait_interrupt waiters.
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
    if unsafe { crate::cpu::interpretador::MDDI_IRQ_PENDENTE }
        && en & 0x1_0000 != 0
    {
        return Some(16);
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
    // (ULTIMA/ULTIMO_ALVO hoisted to SNAP_*: the Foto carries the IRQ
    // edge state, else a resume re-delivers a stale edge.)
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
        let res = match (nivel, unsafe { SNAP_ULTIMA }) {
            (Some(n), u) if u != Some(n) || alvo_atual != unsafe { SNAP_ULTIMO_ALVO } => {
                unsafe { SNAP_ULTIMA = Some(n) };
                // MATCH one-shot advances ONLY on delivering
                // evaluations (livre): a masked observation must
                // never consume the edge.
                if livre {
                    unsafe { SNAP_ULTIMO_ALVO = alvo_atual };
                }
                true
            }
            (None, _) => {
                unsafe { SNAP_ULTIMA = None };
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
            let (u_copia, alv_copia) = unsafe { (SNAP_ULTIMA, SNAP_ULTIMO_ALVO) };
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
    // CAPPED at 0xB000: the MDDI host (display) registers live at
    // 0xE000B000 with their own pre-filled page (see mddi_host).
    mem.map_zeroed("uart_nucleo_stub", 0xE000_0000, 0xB000).unwrap();
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
    // MDDI host (display) registers (`0xE000B000`, PMDH, irq 16):
    // the driver fails init with "unsupported version 0x0" on a
    // zeroed page (version halfword at +0x8C must read > 31 —
    // `ldrh`+`cmp #31`+`bls fail` at vmlinux 0xD540) and times out
    // 8x polling INT (+0x18) / STAT (+0x28). Pre-fill the minimum
    // passing state (version 0x20, INT/STAT all-ones so the first
    // poll sees the interrupt) instead of zeros; the guest's own
    // reset writes land in the same page. Goal: mddi_init passes
    // so msm_fb registers fb0 for SurfaceFlinger. Remove/replace
    // with a real MDDI model once the framebuffer is up.
    {
        let mut pg = vec![0u8; 0x1000];
        pg[0x18..0x1C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        pg[0x28..0x2C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        pg[0x8C..0x8E].copy_from_slice(&0x0020u16.to_le_bytes());
        mem.map("mddi_host", 0xE000_B000, pg, true).unwrap();
    }
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
    let mut cpu = DualBackend::new().unwrap();
    cpu.reset(&mem).unwrap();
    // TEMP (mark-bit provenance): the crash walk selects slot 23
    // because the mark bitmap word is 0x100 (only bit 23). Watch the
    // word (0x41EA6000, first word of the mark bitmap) for the SET —
    // the setter PC names who visits the bins slot as an object.
    // (Replaces the 0x400090B8 slot watch: validated — 16 writes,
    // deterministic, last at ins 668M.) Cap 30. Remove with CRASHOBJ.
    cpu.arma_vigia(Some((0x41EA_6000, 4)));
    // TEMP (snapshots): on the load path the whole world comes from
    // the file — phase-1 guest execution and every plant below would
    // clobber it, so they are skipped; trap arming (after them) runs
    // in both paths (closures can't serialize). Remove with CRASHOBJ
    // if snapshots don't pay off.
    let modo_carga = SNAPSHOT_LOAD_PATH.get().is_some();
    if !modo_carga {
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
    } // fim do setup só-boot (pulso na carga de snapshot)
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
    // TEMP (file-backed serve): mm -> mm_struct, seeded at USRFLT
    // (kernel context: task via sp-trick + TTBR) with VMA-closure
    // verification; read by the fault-serve arm to resolve backing
    // files. Persisted in the snapshot (v3). Remove with CRASHOBJ.
    let mm_para_mm: std::rc::Rc<
        std::cell::RefCell<std::collections::HashMap<u32, u32>>,
    > = std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::new()));
    // TEMP (file-backed serve): lazy YAFFS index over the NAND image
    // (rebuilt on first file-serve; the image itself is snapshotted
    // so the index stays valid across resume). Remove with CRASHOBJ.
    let indice_yaffs: std::rc::Rc<
        std::cell::RefCell<Option<crate::msm7201a_yaffs::IndiceYaffs>>,
    > = std::rc::Rc::new(std::cell::RefCell::new(None));
    let estado_b = estado.clone();
    // Full kernel log: every printk call appends its formatted text
    // here via the trap below (complete + ordered — no ring to wrap,
    // no snapshot window). Continuations (no trailing newline) wait
    // in klog_pend until the line completes. Cap 16MB with a
    // one-shot marker (printk storms must not OOM the host).
    let klog_full = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
    let klog_fullb = klog_full.clone();
    let klog_pend = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
    let klog_pendb = klog_pend.clone();
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
        // (PLANTA_N hoisted to SNAP_PLANTA_N: the Foto carries the
        // fork count, else a resume plants kernel_init over a later
        // thread. Remove with CRASHOBJ.)
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
                SNAP_PLANTA_N += 1;
                let pn = SNAP_PLANTA_N;
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
    let mm_para_mm_semente2 = mm_para_mm.clone();
    cpu.trap_pc_mem(0xC002_7228, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let va = regs[1];
            let pte = regs[2];
            let ti = regs[13] & !0x1FFF;
            let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
            // TEMP (file-backed serve): seed mm -> mm_struct on every
            // PTE install (fault context: task valid, TTBR current).
            // Closure-verified (M+0 -> VMA whose vm_mm points back);
            // uncapped recording, log cap 8. The USRFLT site only
            // sees fatal faults (too late); this site sees every
            // mapping as the kernel installs it. Remove with CRASHOBJ.
            {
                let mm = mem.mm_atual();
                if mm_para_mm_semente2.borrow().get(&mm).is_none()
                    && (0xC600_0000..0xC700_0000).contains(&task)
                {
                    if let Ok(m) = mem.read_u32(task.wrapping_add(0x1B0)) {
                        let mut ok = false;
                        if (0xC600_0000..0xC700_0000).contains(&m) {
                            if let Ok(v) = mem.read_u32(m) {
                                if (0xC600_0000..0xC700_0000).contains(&v) {
                                    ok = mem.read_u32(v).unwrap_or(0) == m;
                                }
                            }
                        }
                        if ok {
                            mm_para_mm_semente2.borrow_mut().insert(mm, m);
                            static mut NS2: u32 = 0;
                            if NS2 < 8 {
                                NS2 += 1;
                                eprintln!("MMSEED2 f={} mm={mm:#x} task={task:#x} mmstruct={m:#x}", unsafe { FATIA_ATUAL });
                            }
                        }
                    }
                }
            }
            // TEMP (mirror gate fix): the TTBR_TASK/TTBR_CACHE pair
            // is captured from user sp at abort injection (fault
            // context is user mode), so the task check below almost
            // never matches and the mirror silently does nothing —
            // leaving the lowmem alias (which caminha_pt_usuario
            // reads) stale after kernel PTE updates and serving
            // wrong/pa-empty pages. Verify task->mm (+0x1B0,
            // closure-checked) against the current mm instead, and
            // use the current mm for the L1 base. Log old-vs-new
            // gate decisions (cap 8). Remove with CRASHOBJ.
            let mm = mem.mm_atual();
            let mut m_verif = 0u32;
            if let Some(&m) = mm_para_mm_semente2.borrow().get(&mm) {
                m_verif = m;
            } else if (0xC600_0000..0xC700_0000).contains(&task) {
                if let Ok(m) = mem.read_u32(task.wrapping_add(0x1B0)) {
                    if (0xC600_0000..0xC700_0000).contains(&m) {
                        if let Ok(v) = mem.read_u32(m) {
                            if (0xC600_0000..0xC700_0000).contains(&v)
                                && mem.read_u32(v).unwrap_or(0) == m
                            {
                                m_verif = m;
                            }
                        }
                    }
                }
            }
            static mut NGD: u32 = 0;
            unsafe {
                if NGD < 8 {
                    NGD += 1;
                    let n = NGD;
                    let old = (task == TTBR_TASK) && TTBR_CACHE != 0;
                    eprintln!("MIRGATE#{n} task={task:#x} mm={mm:#x} mtask={m_verif:#x} oldgate={old}");
                }
            }
            if m_verif == 0 {
                return;
            }
            // TEMP (PTE-install audit): log installs for the
            // mark-stack page to separate kernel-driven PTE changes
            // from serve-side artifacts. Uncapped (narrow filter),
            // remove with CRASHOBJ.
            if va >= 0x41030000 && va < 0x41036000 {
                eprintln!("PTEINST f={} va={va:#x} pte={pte:#x} task={task:#x}", unsafe { FATIA_ATUAL });
            }
            // (Old TTBR_TASK gate removed: it compared against a
            // user-sp-derived value and blocked the mirror almost
            // always. task->mm closure above is the validity check.)
            // L1 walk through the lowmem alias (tables built via VA
            // writes; PA bank stale). Map + seed alias pages on demand
            // with GuestMemory's inherent API (the trap gets mem, not
            // cpu — no CpuBackend trait methods here).
            let le32 = |m: &GuestMemory, a: u32| -> Option<u32> {
                m.read(a, 4)
                    .ok()
                    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            };
            let l1pa = (mm & 0xFFFF_C000).wrapping_add((va >> 20) << 2);
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
            if N < 40 {
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
                if N < 40 {
                    N += 1;
                    let n = N;
                    let ti = regs[13] & !0x1FFF;
                    let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                    eprintln!("FATAL#{n} {nm} f={} sig={:#x} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], task, regs[14]);
                }
                // TEMP (death-anchored epochs): record the dying mm
                // (do_exit entry still runs as the task). Feeds the
                // MCR hook's recycle bump. Remove with CRASHOBJ.
                if nm == "DOEXIT" {
                    mem.registra_mm_morto(mem.mm_atual());
                }
            }
        });
    }
    // TEMP (heap-corruption catch v3): janela estreita (583000+,
    // ~415 insns pos-schedule ate a morte) + caps 60: MALLOC
    // (r0=size, r14=quem chama) + CHK2/7f0 (r2/r3/r4 = chunk)
    // + F36. CHK1/7da provado inocente (fail-filtered, silent).
    // Remove with CRASHOBJ.
    for (va, nm, modo) in [
        (0xAFE0_A750u32, "MALLOC", 0u32),
        (0xAFE0_A7DAu32, "CHK1", 1u32),
        (0xAFE0_A7F0u32, "CHK2", 2u32),
        (0xAFE0_EF36u32, "F36", 3u32),
    ] {
        cpu.trap_pc_mem(va, move |mem, regs| {
            static mut N: u32 = 0;
            unsafe {
                if N >= 60 {
                    return;
                }
                if mem.mm_atual() != 0x1623_8000 {
                    return;
                }
                if modo == 1 && regs[0] == regs[3] {
                    return;
                }
                let f = FATIA_ATUAL;
                // MALLOC/CHK2 passam toda hora: janela anti-ruido.
                // CHK1 (filtrado por falha) e F36 (raro) sem janela.
                if (modo == 0 || modo == 2) && !(583_000..583_100).contains(&f) {
                    return;
                }
                N += 1;
                let n = N;
                let mut c2 = [0u8; 32];
                let mut c3 = [0u8; 32];
                let ok2 = mem.read(regs[2], 32).map(|s| c2.copy_from_slice(s)).is_ok();
                let ok3 = mem.read(regs[3], 32).map(|s| c3.copy_from_slice(s)).is_ok();
                eprintln!("{nm}#{n} f={f} r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x} r14={:#x} sp={:#x} ok={ok2}/{ok3} c2={c2:02x?} c3={c3:02x?}", regs[0], regs[1], regs[2], regs[3], regs[4], regs[14], regs[13]);
            }
        });
    }
    // TEMP (linker entry stack): o linker pos-exec morre em NULL
    // (str [r7], r7=NULL+0xa0). Dumpar sp/argc/argv/envp/auxv na
    // entrada (0xB0000100, ARM) diz se OUR exec-setup entrega
    // auxv quebrado. Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xB000_0100, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                let n = N;
                let f = FATIA_ATUAL;
                let mut sw = [0u32; 16];
                for (i, s) in sw.iter_mut().enumerate() {
                    *s = mem.read_u32(regs[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEADDEAD);
                }
                eprintln!("LDENTRY#{n} f={f} sp={:#x} mm={:#x} stk={sw:#08x?}", regs[13], mem.mm_atual());
            }
        }
    });
    // TEMP (pending bits): de onde vem o SEGV sem falta (forca
    // em task+36 no get_signal_to_deliver (0xC004A354: ldr r6,
    // [r4,#36])) — loga task + pending + signo. Diz se e stale.
    // Cap 10. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xC004_A354, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 10 {
                N += 1;
                let n = N;
                let t = regs[4];
                let p36 = mem.read_u32(t.wrapping_add(36)).unwrap_or(0xDEADDEAD);
                let f = FATIA_ATUAL;
                eprintln!("PEND#{n} f={f} task={t:#x} p36={p36:#x}");
            }
        }
    });
    // (addr+fsr+sig+code) and force_sig_info (signr) — the stack
    // fault's handler installs nothing, yet no SIGSEGV/exit/panic
    // fires; do_signal runs and returns via no_work_pending. Name
    // the exact signal event (or its absence). Cap 4 each.
    // TEMP (file-backed serve): seed mm -> mm_struct here (kernel
    // context: task via sp-trick + current TTBR), closure-verified
    // (M+0 -> VMA whose vm_mm points back). Uncapped recording;
    // the log line below stays capped. Remove with CRASHOBJ.
    let mm_para_mm_semente = mm_para_mm.clone();
    cpu.trap_pc_mem(0xC002_6AB8, move |mem, regs| {
        static mut N: u32 = 0;
        {
            let mm = mem.mm_atual();
            if mm_para_mm_semente.borrow().get(&mm).is_none() {
                let task =
                    mem.read_u32((regs[13] & !0x1FFF).wrapping_add(12)).unwrap_or(0);
                let mut okm = 0u32;
                if (0xC600_0000..0xC700_0000).contains(&task) {
                    if let Ok(m) = mem.read_u32(task.wrapping_add(0x1B0)) {
                        if (0xC600_0000..0xC700_0000).contains(&m) {
                            if let Ok(v) = mem.read_u32(m) {
                                if (0xC600_0000..0xC700_0000).contains(&v) {
                                    if mem.read_u32(v).unwrap_or(0) == m {
                                        okm = m;
                                    }
                                }
                            }
                        }
                    }
                }
                if okm != 0 {
                    mm_para_mm_semente.borrow_mut().insert(mm, okm);
                    static mut NS: u32 = 0;
                    unsafe {
                        if NS < 8 {
                            NS += 1;
                            eprintln!("MMSEED f={} mm={mm:#x} task={task:#x} mmstruct={okm:#x}", unsafe { FATIA_ATUAL });
                        }
                    }
                }
            }
        }
        unsafe {
            if N < 4 {
                N += 1;
                // Identify the crashing process: scan the task struct
                // for a comm[] name (zygote vs mediaserver decides
                // whether this wall blocks boot or just audio).
                let task = mem.read_u32((regs[13] & !0x1FFF).wrapping_add(12)).unwrap_or(0xDEAD);
                let mut tb = [0u8; 1024];
                let tok = mem.read(task, 1024).map(|s| tb.copy_from_slice(s)).is_ok();
                eprintln!("USRFLT f={} addr={:#x} fsr={:#x} sig={} code={} task={:#x} lr={:#x} tok={tok} taskdump={tb:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[3], task, regs[14]);
            }
        }
    });
    cpu.trap_pc_mem(0xC005_2610, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            // Cap 100 (era 4): restart mata 4+ com SIGKILL antes do
            // SEGV do filho (585443) — com 4 o envio some. CORRECAO:
            // signr e r0 (force_sig_info(sig,info,task)); r1 e o
            // info-ptr (lixo). Remove with CRASHOBJ.
            if N < 100 {
                N += 1;
                eprintln!("SENDSIG f={} sig={} task={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], mem.read_u32((regs[13] & !0x1FFF).wrapping_add(12)).unwrap_or(0xDEAD), regs[14]);
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
    // Full-klog tap: every guest printk call (0xC0047610) is
    // formatted host-side and appended, so the run keeps the
    // COMPLETE console history in order — no ring to wrap, no
    // 60-line snapshot window. Uncapped in count (each printk =
    // one trap, cheap next to the instruction budget); the 16MB
    // accumulator cap guards printk storms.
    cpu.trap_pc_mem(0xC004_7610, move |mem, regs| {
        // TEMP (printk convention probe): the yaffs dev/name line
        // formats as garbage (dev huge, name <unmapped>) while the
        // old guest-formatted snapshot shows sane values — the
        // r1/r2/r3-then-[sp] mapping (prox starting at 3, skipping
        // regs) is suspect. Dump raw regs+stack for that format,
        // cap 2. Remove once the convention is settled.
        unsafe {
            static mut NPK: u32 = 0;
            if NPK < 2 {
                if let Ok(fb) = mem.read(regs[0], 80) {
                    let s = String::from_utf8_lossy(fb);
                    if s.contains("yaffs: dev is") {
                        NPK += 1;
                        let n = NPK;
                        let s0 = mem.read_u32(regs[13]).unwrap_or(0xDEAD);
                        let s1 = mem.read_u32(regs[13].wrapping_add(4)).unwrap_or(0xDEAD);
                        let s2 = mem.read_u32(regs[13].wrapping_add(8)).unwrap_or(0xDEAD);
                        eprintln!("PRINTKRAW#{n} f={} fmt={:?} r1={:#x} r2={:#x} r3={:#x} [sp]={s0:#x}+{s1:#x}+{s2:#x}", unsafe { FATIA_ATUAL }, &s[..s.find('\n').unwrap_or(s.len()).min(60)], regs[1], regs[2], regs[3]);
                    }
                }
            }
        }
        let Some(texto) = formata_printk(mem, regs[0], regs[1], regs[2], regs[3], regs[13]) else {
            return;
        };
        let mut pend = klog_pendb.borrow_mut();
        let mut log = klog_fullb.borrow_mut();
        if log.len() >= 16 * 1024 * 1024 {
            static mut AVISADO: bool = false;
            unsafe {
                if !AVISADO {
                    AVISADO = true;
                    eprintln!("KLOGFULL: printk capture hit 16MB, stopping");
                }
            }
            return;
        }
        pend.push_str(&texto);
        // Flush complete lines; hold the tail (continuation).
        let mut ini = 0;
        while let Some(rel) = pend[ini..].find('\n') {
            let fim = ini + rel + 1;
            log.extend_from_slice(pend[ini..fim].as_bytes());
            ini = fim;
        }
        if ini > 0 {
            pend.drain(..ini);
        }
    });
    // TEMP (NAND scan observe + ID wedge): msm_nand_scan
    // geometry path. T1 entry (0xC0153CA0): mtd + chip + the 4
    // ID bytes the driver actually sees ([chip+28],[chip+32])
    // — zeros mean the stub bus served nothing. WEDGE
    // (0xC0153CC0, after the ID helper): plant Samsung K9K2G08
    // bytes (EC AA 00 15) into [chip+28] so the geometry decode
    // programs real values (2K page/128K block/64 spare); the
    // controller itself is still stubbed, same class as the
    // faked DMA completions. T2b (0xC0153D5C): force r7 (device
    // id) to 0xAAEC so the 256MB size match hits (real READ-ID
    // would return it; the stub DMA leaves garbage 0xEEEEEEEE).
    // T3 moved to scan EXIT (0xC0153EBC): final mtd fields
    // (size/erasesize/writesize/oobsize/oobavail at
    // +8/+12/+16/+20/+24) + CFG shadow words + return value.
    // T4 read_oob entry (0xC0153F34): mtd, from (r1/r2), ops +
    // first 32 B; cap 200 so the mount scan's per-mtd min/max
    // `from` reconstructs partition ranges. Remove once the
    // read serve is built.
    cpu.trap_pc_mem(0xC015_3CA0, move |mem, regs| {
        static mut N1: u32 = 0;
        unsafe {
            if N1 < 4 {
                N1 += 1;
                let n = N1;
                let mtd = regs[0];
                let chip = mem.read_u32(mtd.wrapping_add(0xA8)).unwrap_or(0xDEAD);
                let id0 = mem.read_u32(chip.wrapping_add(28)).unwrap_or(0xDEAD);
                let id1 = mem.read_u32(chip.wrapping_add(32)).unwrap_or(0xDEAD);
                eprintln!("NANDSCAN#{n} f={} mtd={mtd:#x} chip={chip:#x} id0={id0:#x} id1={id1:#x}", unsafe { FATIA_ATUAL });
            }
        }
    });
    cpu.trap_pc_mem(0xC015_3CC0, move |mem, regs| {
        static mut NW: u32 = 0;
        unsafe {
            // WEDGE (uncapped, idempotent): plant K9K2G08 ID bytes
            // so the decode + size match see real silicon. chip is
            // callee-saved r6 here (set at scan entry, helper
            // preserves it). EC AA = Samsung maker+device (matches
            // the 0xAAEC whitelist entry = SPL entry-8 chip);
            // 00 15 = extended-ID filler for the geometry shifts.
            let chip = regs[6];
            let _ = mem.write(chip.wrapping_add(28), &[0xEC, 0xAA, 0x00, 0x15]);
            if NW < 4 {
                NW += 1;
                let n = NW;
                eprintln!("NANDWEDGE#{n} f={} chip={chip:#x} idret={:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
    });
    cpu.trap_pc_mem(0xC015_3D5C, move |_mem, regs| {
        // WEDGE: force the device id to the Samsung match so
        // mtd->size = 256MB is stored (0xC0153E04 path). Fires
        // right after `mov r7,r0` would have run — overwrite r7.
        regs[7] = 0xAAEC;
    });
    cpu.trap_pc_mem(0xC015_3EBC, move |mem, regs| {
        static mut N3: u32 = 0;
        unsafe {
            if N3 < 4 {
                N3 += 1;
                let n = N3;
                let mtd = regs[5];
                let mut f = [0u32; 5];
                for (i, s) in f.iter_mut().enumerate() {
                    *s = mem.read_u32(mtd.wrapping_add(8 + (i as u32) * 4)).unwrap_or(0xDEAD);
                }
                let cfg0 = mem.read_u32(0xC02B_80EC).unwrap_or(0xDEAD);
                let cfg1 = mem.read_u32(0xC02B_80ECu32.wrapping_add(0x104)).unwrap_or(0xDEAD);
                eprintln!("NANDGEO#{n} f={} ret={:#x} mtd={mtd:#x} fields={f:#x?} cfg={cfg0:#x}/{cfg1:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
    });
    // TEMP (NAND read serve): serve msm_nand_read_oob from the
    // host NAND image and forge a success return, bypassing the
    // stub controller + DMOV wait + ECC entirely (same wedge
    // class as the faked DMA completions). Observed protocol:
    // r2 = absolute chip byte offset (page stepping 0x20000 =
    // per-eraseblock scan), ops = [sp] with mtd_oob_ops layout
    // (mode@0, len@4, retlen@8, ooblen@12, oobretlen@16,
    // ooboffs@20, datbuf@24, oobbuf@28 — datbuf NULL on the
    // yaffs tag scans, oobbuf set). Entry-8 geometry: data byte
    // (from+off) lives at image page*2112+(off&0x7FF); spare
    // byte i of the chunk at file page*2112+2048+ooboffs+i.
    // Forged return: sp = saved ip ([sp+120]), pc = lr, r0 = 0.
    let nand_rd = nand.clone();
    cpu.trap_pc_mem(0xC015_3F34, move |mem, regs| {
        static mut N4: u32 = 0;
        static mut LAST: u32 = 0xFFFF_FFFF;
        static mut NP: u32 = 0;
        unsafe {
            let from = regs[2];
            let last = LAST;
            LAST = from;
            // Rewind bigger than a block = new scan (partition
            // start or rescan). Small backward steps are yaffs
            // checkpoint reads (page-stepped); logging those burns
            // the cap instantly (seen live at 0x6C1D000+).
            if from + 0x10000 < last {
                if NP < 10 {
                    NP += 1;
                    let n = NP;
                    eprintln!("NANDPART#{n} f={} start={from:#x}", unsafe { FATIA_ATUAL });
                }
            }
            // NULL/unmapped ops guard: some callers may pass no ops
            // (or a stale pointer); running the driver on that
            // NULL-derefs inside read_oob and the nested abort
            // cascade kills init's reader. Fail closed with -EINVAL
            // and a forged return instead. Cap 5.
            let ops_probe = mem.read_u32(regs[13]).unwrap_or(0);
            if ops_probe == 0 || mem.read_u32(ops_probe).is_err() {
                static mut NN: u32 = 0;
                unsafe {
                    if NN < 5 {
                        NN += 1;
                        let n = NN;
                        eprintln!("NANDNULL#{n} f={} ops={ops_probe:#x}", unsafe { FATIA_ATUAL });
                    }
                }
                regs[0] = 0xFFFF_FFEA; // -EINVAL
                regs[15] = regs[14];
                return;
            }
            // Detail only for SYSTEM-partition reads
            // (0x2E40000..0x7200000): the execve path's file reads
            // (header, phdrs, interp) are the evidence. Datapath
            // scans would exhaust any cap instantly, hence the
            // range gate (drop the f>=549000 gate: exec reads may
            // precede the execve return by thousands of slices).
            // NOTE: 7 hex digits — 0x2E40_0000 (8 digits) can never
            // match on a 256MB chip and silenced this trap once.
            // Re-add the f>=500000 gate too: the mount scan
            // (f≈182k) and GC churn would otherwise burn the
            // cap long before the exec window (execve fails at
            // f≈551k; its reads land just before).
            // Linker/sh first pages bypass the cap (uncapped): the
            // -1 verdict hinges on whether the interpreter *header*
            // was ever read — the cap must not be allowed to hide it.
            if from == 0x3E96800 || from == 0x3EC5000 {
                static mut NH: u32 = 0;
                unsafe {
                    NH += 1;
                    let n = NH;
                    eprintln!("NANDHDR#{n} f={} from={from:#x}", unsafe { FATIA_ATUAL });
                }
            }
            if unsafe { FATIA_ATUAL } >= 500_000 && from >= 0x2E40000 && from < 0x7200000 && N4 < 200 {
                N4 += 1;
                let n = N4;
                let ops0 = mem.read_u32(regs[13]).unwrap_or(0xDEAD);
                let mut ow = [0u32; 8];
                for (i, s) in ow.iter_mut().enumerate() {
                    *s = mem.read_u32(ops0.wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                }
                eprintln!("NANDRD#{n} f={} from={from:#x} ops={ops0:#x} ow={ow:x?}", unsafe { FATIA_ATUAL });
            }
            // TEMP (exec-binary identification): the NANDRD detail cap
            // saturates on datapath scans, hiding which binaries the
            // exec path actually pulls. First-chunk (ELF header) reads
            // name every binary: chunk index lives in the spare area
            // the same way the offline reader decodes it (obj@+4,
            // chunk@+8 of the 2112 B page). Uncapped by N4 (own cap
            // 40), gated to the SYSTEM partition + exec window.
            // Remove once the always-failing -1 services are named.
            if unsafe { FATIA_ATUAL } >= 500_000 && from >= 0x2E40000 && from < 0x7200000 {
                static mut NH2: u32 = 0;
                unsafe {
                    if NH2 < 80 {
                        let pagina = (from >> 11) as usize;
                        if let Some(b) = pagina.checked_mul(2112) {
                            let img2 = nand_rd.borrow();
                            if b + 2064 <= img2.len()
                                && u32::from_le_bytes([img2[b + 2056], img2[b + 2057], img2[b + 2058], img2[b + 2059]]) == 1
                            {
                                NH2 += 1;
                                let n = NH2;
                                let obj = u32::from_le_bytes([img2[b + 2052], img2[b + 2053], img2[b + 2054], img2[b + 2055]]);
                                eprintln!("NANDHDR2#{n} f={} from={from:#x} obj={obj}", unsafe { FATIA_ATUAL });
                            }
                        }
                    }
                }
            }
            let ops = mem.read_u32(regs[13]).unwrap_or(0);
            if ops == 0 {
                return;
            }
            let ow = |i: u32| mem.read_u32(ops.wrapping_add(i * 4)).unwrap_or(0);
            let len = ow(1);
            let ooblen = ow(3);
            let ooboffs = ow(5);
            let datbuf = ow(6);
            let oobbuf = ow(7);
            let img = nand_rd.borrow();
            // Data (full-page content reads; tag scans pass NULL).
            if datbuf != 0 && len != 0 && len <= 0x10000 {
                // Fault-in for kernel-lowmem datbufs (page cache):
                // the guest never touches these VAs before the DMA
                // we bypass, so no region exists and the write below
                // fails silently -> short read served as success ->
                // garbage ELF header -> load_elf_interp ~0UL -> -1
                // (proven live: 0xc102xxxx writes all fail while
                // 0xc000xxxx succeed). traduz() covers the SPL
                // windows plus a linear-map arm for kernel lowmem
                // below; zero-fill matches fresh page-cache semantics (the
                // serve overwrites the asked range right after).
                // Per-page: a multi-page len can straddle.
                {
                    let fim = datbuf.wrapping_add(len);
                    let mut base = datbuf & !0xFFF;
                    loop {
                        if mem.read(base, 1).is_err() {
                            // traduz() covers only the SPL 0x8/0x9
                            // windows, NOT kernel lowmem — second arm
                            // maps the linear direct map (PAGE_OFFSET
                            // 0xC0000000 over PHYS 0x10000000:
                            // PA=VA-0xB0000000; all failing VAs land
                            // in RAM under it). RAM-only: mapping a
                            // device VA as RAM would shadow the model.
                            let pa = traduz(base).or_else(|| {
                                (0xC000_0000..0xD000_0000)
                                    .contains(&base)
                                    .then(|| base.wrapping_sub(0xB000_0000))
                            });
                            match pa {
                                Some(pa) if (0x1000_0000..0x2000_0000).contains(&pa) => {
                                    let _ = mem.map_zeroed("nand_demanda", base, 0x1000);
                                }
                                _ => break,
                            }
                        }
                        if base.wrapping_add(0x1000) >= fim || base.wrapping_add(0x1000) < base {
                            break;
                        }
                        base = base.wrapping_add(0x1000);
                    }
                }
                let mut resto = len;
                let mut pos = 0u32;
                while resto > 0 {
                    let chip = from.wrapping_add(pos);
                    let pagina = (chip >> 11) as usize;
                    let dentro = (chip & 0x7FF) as usize;
                    let base = pagina.checked_mul(2112).and_then(|b| b.checked_add(dentro));
                    let cabe = core::cmp::min(resto as usize, 2048 - dentro);
                    match base {
                        Some(b) if b + cabe <= img.len() => {
                            if mem.write(datbuf.wrapping_add(pos), &img[b..b + cabe]).is_err() {
                                // TEMP (exec-window short-read check):
                                // a failed datbuf write below silently
                                // leaves stale bytes and the kernel
                                // sees a garbage ELF header (-> ~0UL
                                // -> -1). Log the faulting window.
                                static mut NWF: u32 = 0;
                                if unsafe { NWF } < 10 {
                                    unsafe { NWF += 1; }
                                    let n = unsafe { NWF };
                                    let dp = datbuf.wrapping_add(pos);
                                    eprintln!("NANDWRFAIL#{n} f={} from={from:#x} datbuf={dp:#x} pos={pos:#x} cabe={cabe:#x}", unsafe { FATIA_ATUAL });
                                }
                                break;
                            }
                        }
                        _ => break,
                    }
                    resto -= cabe as u32;
                    pos += cabe as u32;
                }
                let _ = mem.write(ops.wrapping_add(8), &(pos.to_le_bytes()));
            }
            // Spare (yaffs tags live here; single-chunk reads).
            if oobbuf != 0 && ooblen != 0 && ooboffs <= 64 && ooblen <= 64 - ooboffs {
                let pagina = (from >> 11) as usize;
                let base = pagina * 2112 + 2048 + ooboffs as usize;
                if base + ooblen as usize <= img.len() {
                    let _ = mem.write(oobbuf, &img[base..base + ooblen as usize]);
                    let _ = mem.write(ops.wrapping_add(16), &ooblen.to_le_bytes());
                }
            }
            // Forge success: the trap fires BEFORE the prologue,
            // so the pushed frame does not exist yet and sp is
            // already the caller's correct sp — do NOT touch it.
            // pc = lr, r0 = 0.
            regs[0] = 0;
            regs[15] = regs[14];
        }
    });
    // TEMP (NAND erase/write serve): yaffs needs real erases
    // (it garbage-collects the 0xAA-filled image: "chunk was not
    // erased" then the stub-DMOV error cascade ends in the
    // posix-timers BUG + NULL-deref oops). ERASE (0xC015484C,
    // frame push12+sub28): fill the host image block range with
    // 0xFF (data+spares, entry-8: file block = 135168 B) and
    // forge success (sp=[sp+64], pc=lr, r0=0). WRITE
    // (0xC0152F68, frame push12+sub92, same ops convention as
    // read_oob): copy datbuf/oobbuf into the image, set retlens,
    // forge success (sp=[sp+128]) — but ONLY when the ops
    // decode is sane (datbuf set, len<=64K); otherwise pass
    // through to the stubs and log (cap 12). Remove with the
    // read serve once mounts are clean.
    let nand_ew = nand.clone();
    cpu.trap_pc_mem(0xC015_484C, move |mem, regs| {
        static mut NE: u32 = 0;
        unsafe {
            let instr = regs[1];
            let addr = mem.read_u32(instr.wrapping_add(4)).unwrap_or(0xDEAD);
            let len = mem.read_u32(instr.wrapping_add(8)).unwrap_or(0xDEAD);
            if NE < 12 {
                NE += 1;
                let n = NE;
                eprintln!("NANDERASE#{n} f={} addr={addr:#x} len={len:#x}", unsafe { FATIA_ATUAL });
            }
            // Serve block-aligned erases; anything else passes to
            // the stubs (logged above). Frame: push12 (ip saved at
            // S_old-16) + sub sp,#28 → S=S_old-76, so saved sp is
            // at [S+60].
            if addr != 0xDEAD && len != 0 && addr & 0x1FFFF == 0 && len & 0x1FFFF == 0 {
                let mut img = nand_ew.borrow_mut();
                let b0 = (addr >> 17) as usize;
                let nb = (len >> 17) as usize;
                if (b0 + nb).checked_mul(135168).map_or(false, |e| e <= img.len()) {
                    for b in b0..b0 + nb {
                        let o = b * 135168;
                        img[o..o + 135168].fill(0xFF);
                    }
                    // Forge: same no-sp-touch rule (trap runs before
                    // the prologue; sp is already correct).
                    regs[0] = 0;
                    regs[15] = regs[14];
                }
            }
        }
    });
    let nand_wr = nand.clone();
    cpu.trap_pc_mem(0xC015_2F68, move |mem, regs| {
        static mut NW2: u32 = 0;
        unsafe {
            let ops = mem.read_u32(regs[13]).unwrap_or(0);
            let ow = |i: u32| mem.read_u32(ops.wrapping_add(i * 4)).unwrap_or(0);
            let to = regs[2];
            let len = ow(1);
            let ooblen = ow(3);
            let ooboffs = ow(5);
            let datbuf = ow(6);
            let oobbuf = ow(7);
            // Sanity gate: forge only a clean single-chunk-style
            // write (datbuf present, bounded lens); else the stubs
            // run and the case gets logged.
            let sane = ops != 0 && datbuf != 0 && len != 0 && len <= 0x10000
                && ooboffs <= 64 && ooblen <= 64 - ooboffs;
            if NW2 < 12 {
                NW2 += 1;
                let n = NW2;
                eprintln!("NANDWR#{n} f={} to={to:#x} len={len:#x} datbuf={datbuf:#x} ooblen={ooblen:#x} oobbuf={oobbuf:#x} sane={sane}", unsafe { FATIA_ATUAL });
            }
            if sane {
                // Data: guest bytes first (ends the mem borrow),
                // then into the image.
                let mut resto = len;
                let mut pos = 0u32;
                while resto > 0 {
                    let chip = to.wrapping_add(pos);
                    let pagina = (chip >> 11) as usize;
                    let dentro = (chip & 0x7FF) as usize;
                    let cabe = core::cmp::min(resto as usize, 2048 - dentro);
                    let base = match pagina.checked_mul(2112).and_then(|b| b.checked_add(dentro)) {
                        Some(b) => b,
                        None => break,
                    };
                    let src = match mem.read(datbuf.wrapping_add(pos), cabe as u32) {
                        Ok(s) => s.to_vec(),
                        Err(_) => break,
                    };
                    {
                        let mut img = nand_wr.borrow_mut();
                        if base + cabe > img.len() {
                            break;
                        }
                        img[base..base + cabe].copy_from_slice(&src);
                    }
                    resto -= cabe as u32;
                    pos += cabe as u32;
                }
                let _ = mem.write(ops.wrapping_add(8), &pos.to_le_bytes());
                if oobbuf != 0 && ooblen != 0 {
                    let pagina = (to >> 11) as usize;
                    let base = pagina * 2112 + 2048 + ooboffs as usize;
                    if let Ok(ob) = mem.read(oobbuf, ooblen) {
                        let mut img4 = nand_wr.borrow_mut();
                        if base + ooblen as usize <= img4.len() {
                            img4[base..base + ooblen as usize].copy_from_slice(&ob);
                        }
                    }
                }
                let _ = mem.write(ops.wrapping_add(8), &pos.to_le_bytes());
                let _ = mem.write(ops.wrapping_add(16), &ooblen.to_le_bytes());
                // Frame: push12 (ip saved at S_old-16) + sub sp,#92
                // → S=S_old-140, so saved sp is at [S+124].
                regs[0] = 0;
                regs[15] = regs[14];
            }
        }
    });
    // TEMP (fb base hunt): the console is being drawn somewhere (the
    // 0xC0111Dxx font-blit loop parks 60k+ slices), but no fb0 line
    // and no FBMAP burst names the buffer. Two one-shot watches:
    // (1) msmfb_probe stores the fbram alloc result at [r7,#180]
    // (0xC011B710, file 0x113710) — r0 there is the fb base as the
    // kernel sees it; (2) the 8-word memmove loop top (0xC0111DE8,
    // file 0x111DE8 — the scroll workhorse) — ip/lr are the live
    // src/dst ends, r1 the 32B-block count. dst_start = lr+32-r1*32
    // should sit in (1)+0x4B000. Remove once the presenter tracks
    // the fb itself.
    cpu.trap_pc_mem(0xC011_B710, move |_mem, regs| {
        static mut NFB: u32 = 0;
        unsafe {
            if NFB < 2 {
                NFB += 1;
                let n = NFB;
                eprintln!("FBBASE#{n} f={} base={:#x} struct={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[7]);
            }
        }
    });
    cpu.trap_pc_mem(0xC011_1DE8, move |_mem, regs| {
        static mut NFD: u32 = 0;
        unsafe {
            if NFD < 3 {
                NFD += 1;
                let n = NFD;
                eprintln!("FBDEST#{n} f={} src_end={:#x} dst_end={:#x} blocks={:#x}", unsafe { FATIA_ATUAL }, regs[8], regs[14], regs[1]);
            }
        }
    });
    // TEMP (execve-return trap): the service children fork+execve
    // then _exit(127) with zero .so/linker opens. Catch the execve
    // RETURN at the wrapper caller (Thumb lr 0x96E7 → trap 0x96E6):
    // fires IFF execve failed in-kernel; r0 = -errno names it
    // (ENOENT = file invisible despite plant → mount/lookup;
    // ENOEXEC/EACCES = header/perm/load). If it NEVER fires,
    // execve succeeded and the 127 is userspace (linker/sh).
    // Cap 10. Remove once the 127 is named.
    // TEMP (raw execve errno): 0xBE50 is init's own execve stub
    // (mov r7,#11; svc #0 at 0xBE58); the trap at 0x96E6 only sees
    // libc/inits normalized -1. Trapping the pop right after the
    // svc sees the RAW kernel return (0 or -errno) with argv still
    // in r1/r2 for offline pairing with EXITCAL. Cap 24. Remove
    // once the -1 services' errnos are named.
    // TEMP (MDDI caps forge at the flag check 0xC0015654): the
    // toshiba client can only be discovered via reverse packets the
    // dead link never delivers, so "no client found" kills fb0. The
    // caps wait polls dev+4 bit1; forge it plus the parsed fields
    // (client ID 0xD263 from the "mddi_c_d263_0000" device-name
    // literal, version 0) and redirect to the success path 0xD6A8
    // (letting its own re-checks run on the forged state). The real
    // toshiba probe + msm_fb then run unmodified. Cap the log at 5
    // (the check retries); the forge itself is idempotent.
    // Remove if the link is ever emulated for real.
    cpu.trap_pc_mem(0xC001_5654, move |mem, regs| {
        static mut NCF: u32 = 0;
        unsafe {
            if NCF < 5 {
                NCF += 1;
                let n = NCF;
                eprintln!("CAPSFORGE#{n} f={} dev={:#x}", unsafe { FATIA_ATUAL }, regs[5]);
            }
        }
        let dev = regs[5];
        if let Ok(s) = mem.read(dev.wrapping_add(4), 2) {
            let v = u16::from_le_bytes([s[0], s[1]]) | 2;
            let _ = mem.write(dev.wrapping_add(4), &v.to_le_bytes());
        }
        let _ = mem.write(dev.wrapping_add(136), &0xD263u16.to_le_bytes());
        let _ = mem.write(dev.wrapping_add(138), &0x0000u16.to_le_bytes());
        // The publish path prints [dev+376] as the client ID (set
        // from r6, which lands 0 without a real caps round-trip);
        // forge the toshiba ID here too so the core publishes
        // mddi_c_d263_* and the toshiba driver binds.
        // Panel geometry: msmfb_probe prints "[+136] x [+138]" as
        // the panel size ("installing %d x %d"); the G1 Toshiba
        // panel is 320x480. (The client ID for binding travels
        // separately; these two halfwords are the display dims.)
        let _ = mem.write(dev.wrapping_add(136), &320u16.to_le_bytes());
        let _ = mem.write(dev.wrapping_add(138), &480u16.to_le_bytes());
        let _ = mem.write(dev.wrapping_add(376), &0xD263u16.to_le_bytes());
        let _ = mem.write(dev.wrapping_add(378), &0x0000u16.to_le_bytes());
        regs[15] = 0xC001_56A8;
    });
    cpu.trap_pc_mem(0x0000_BE5C, move |_mem, regs| {
        static mut NR: u32 = 0;
        unsafe {
            if NR < 24 {
                NR += 1;
                let n = NR;
                eprintln!("RAWRET#{n} f={} r0={:#x} r1={:#x} r2={:#x}", unsafe { FATIA_ATUAL }, regs[0] as i32, regs[1], regs[2]);
            }
        }
    });
    cpu.trap_pc_mem(0x0000_96E6, move |mem, regs| {
        static mut NX: u32 = 0;
        unsafe {
            if NX < 24 {
                NX += 1;
                let n = NX;
                let ti = regs[13] & !0x1FFF;
                let task = mem.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                // Filename via chunked read (a single 64 B read fails
                // at region edges and misreports valid paths as
                // <unmapped>; the chunked formata_printk path proved
                // this matters).
                let mut nm = Vec::new();
                let mut ok = false;
                let mut off = 0u32;
                while nm.len() < 64 {
                    match mem.read(regs[1].wrapping_add(off), 16) {
                        Ok(s) => {
                            if let Some(z) = s.iter().position(|&b| b == 0) {
                                nm.extend_from_slice(&s[..z]);
                                ok = true;
                                break;
                            }
                            nm.extend_from_slice(s);
                            off += 16;
                        }
                        Err(_) => break,
                    }
                }
                let path = if !ok && nm.is_empty() {
                    String::from("<unmapped>")
                } else {
                    String::from_utf8_lossy(&nm).into_owned()
                };
                eprintln!("EXECRET#{n} f={} r0={:#x} r7={:#x} r1={:#x} r2={:#x} lr={:#x} task={task:#x} path={path:?}", unsafe { FATIA_ATUAL }, regs[0], regs[7], regs[1], regs[2], regs[14]);
            }
        }
    });
    // TEMP (0xAFFE zeroing hunt): the fault context's 0xAFFE is
    // 0x0000 (NOP) while the file has 0x4B0A (`ldr r3,[pc,#40]`) —
    // with correct bytes the live r3=0x13E3B is arithmetically
    // impossible (0xB008+0x14484+0x6F4 = 0x1FB80), so a guest store
    // zeroed init's text between the early (correct, f~179k) and
    // fault (f~554k) contexts. Seed paths are whole-page (a stale
    // seed could not zero one halfword of an otherwise intact
    // page), and nobody writes the PA bank — leaving a wild guest
    // store (user text maps writable; hardware would SEGV where
    // we absorb). Bracket WHEN with one shot per window (cheap:
    // a single halfword read), keep the fault-window full dump.
    // Cap 5. Remove once the storer is named.
    cpu.trap_pc_mem(0x0000_B008, move |mem, regs| {
        static mut N8: u32 = 0;
        unsafe {
            let f = unsafe { FATIA_ATUAL };
            // Window shots (N8 0..3): just the 0xAFFE halfword.
            if N8 < 4
                && ((f >= 200_000 && N8 == 0)
                    || (f >= 300_000 && N8 == 1)
                    || (f >= 400_000 && N8 == 2)
                    || (f >= 500_000 && N8 == 3))
            {
                N8 += 1;
                let n = N8;
                let h = mem
                    .read(0xAFFE, 2)
                    .map(|s| u16::from_le_bytes([s[0], s[1]]))
                    .unwrap_or(0xDEAD);
                eprintln!("AFFEWIN#{n} f={f} [0xAFFE]={h:#x}");
            }
            if N8 < 5 && f >= 540_000 {
                N8 = 5;
                let r3 = regs[3];
                let w = mem.read_u32(0xB028).unwrap_or(0xDEAD);
                let w2 = mem.read_u32(0xB02C).unwrap_or(0xDEAD);
                let w3 = mem.read_u32(r3).unwrap_or(0xDEAD);
                let h = mem.read_u32(0x1FB80).unwrap_or(0xDEAD);
                // Full 0xA000 page head (first 0x400 B) plus tail:
                // identifies wholesale-stale content (SPL? zeros?
                // another file?) vs a single wild halfword store.
                // Two reads: the dump must not cross the region
                // boundary mid-way (single reads fail on straddle
                // even with both pages mapped). Full reg file this
                // time (r4 was missing and could be the store base).
                let mut pg = vec![0u8; 0x1000];
                let ok = mem.read(0xA000, 0x1000).map(|s| pg.copy_from_slice(s)).is_ok();
                let mut hh: u64 = 0xcbf29ce484222325;
                for b in &pg {
                    hh ^= *b as u64;
                    hh = hh.wrapping_mul(0x100000001b3);
                }
                eprintln!("INITPROBE f={f} r0={:#x} r1={:#x} r2={:#x} r3={r3:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x} [0xB028]={w:#x} [0xB02C]={w2:#x} [r3]={w3:#x} [0x1FB80]={h:#x} pg_ok={ok} pg_hash={hh:#x} pg_head={:02x?} pg_tail={:02x?}", regs[0], regs[1], regs[2], regs[4], regs[5], regs[6], regs[7], &pg[..0x200], &pg[0xE00..0x1000]);
                // Emulate the replaced `ldr r0,[r3,#0]`.
                if let Ok(s) = mem.read(r3, 4) {
                    regs[0] = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
                }
            }
        }
    });
    // (FAULT8A retired: 0x8AA8 turned out to be a valid Thumb push
    // (0xB570) in installd/init text, not a wild jump into data —
    // the 405 halt was a stack-page seeding failure fixed by
    // pa-gated sibling copies (406 reaches Budget). The trap's
    // skip-the-instruction semantics would now corrupt a valid
    // stack frame, so it is removed rather than kept.)
    // TEMP (padzero caller hunt): the 0xA1FC memset comes from one
    // of three `bl 0xC00CA54C` sites (load_elf_binary main, its
    // interp path, load_elf_interp). Log site + r0 (the elf_bss
    // candidate) + r1, then TRAMPOLINE into the real call.
    // Cap 6 total across the three site traps. Remove once named.
    for (va, tag) in [(0xC00C_A90Cu32, "PA"), (0xC00C_B3F8u32, "PB"), (0xC00C_B6F4u32, "PC")] {
        cpu.trap_pc_mem(va, move |mem, regs| {
            static mut NQ: u32 = 0;
            unsafe {
                // One static shared by the three site traps: cap 6
                // total (each site fires rarely; site identity is
                // in the log line).
                if NQ < 6 {
                    NQ += 1;
                    let n = NQ;
                    // Which site fired is known by which trap (see
                    // tag in the static below — NQ is per-closure).
                    let r0 = regs[0];
                    let r1 = regs[1];
                    eprintln!("PADZERO#{n} f={} site={:#x} r0={r0:#x} r1={r1:#x}", unsafe { FATIA_ATUAL }, va);
                    let _ = mem;
                    // Trampoline: perform the replaced `bl` (log-only
                    // traps must not skip calls — skipping the legit
                    // init-BSS padzero once diverged the whole run
                    // onto a dirty-BSS fault).
                    regs[14] = regs[15].wrapping_add(4);
                    regs[15] = 0xC00C_A54C;
                }
            }
        });
        let _ = tag;
    }
    // TEMP (MTD slave survey): part_read_oob entry gives the
    // partition slave mtd; dump layout words + name to recover
    // the trout partition table (sizes/offsets) exactly — the
    // 0x2E40000/0xB540000/0x71C0000 scan starts need attribution
    // before planting the NBH system image. Dedup by slave ptr
    // (6 partitions), cap 6. Remove once planted+verified.
    cpu.trap_pc_mem(0xC014_FA34, move |mem, regs| {
        static mut NSV: u32 = 0;
        static mut VISTOS: [u32; 6] = [0; 6];
        unsafe {
            let slave = regs[0];
            let mut seen = false;
            let mut k = 0;
            while k < 6 {
                if VISTOS[k] == slave {
                    seen = true;
                    break;
                }
                k += 1;
            }
            if !seen && NSV < 6 {
                VISTOS[NSV as usize] = slave;
                NSV += 1;
                let n = NSV;
                let mut w = [0u32; 14];
                for (i, s) in w.iter_mut().enumerate() {
                    *s = mem.read_u32(slave.wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                }
                // Field map (from master GEO + slave pairs): +0x00
                // type, +0x04 flags, +0x08 size, +0x0C erasesize,
                // +0x10 writesize, +0x14 oobsize, +0x18 oobavail,
                // +0x1C name*, +0x20 part index, +0x24 master*,
                // +0x28/+0x2C offset (u64?). Name via +0x1C.
                let nm = w[7];
                let ns = mem.read(nm, 16).map(|s| s.to_vec()).unwrap_or_default();
                eprintln!("MTDSLAVE#{n} f={} slave={slave:#x} w={w:#x?} nameptr={nm:#x} name={ns:02x?}", unsafe { FATIA_ATUAL });
            }
        }
    });
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
    // the same way. Cap 30, IRQ7 EXCLUDED (the tick would eat any
    // cap instantly; MDDI IRQ16 and DGT IRQ8 are the signal here).
    cpu.trap_pc_mem(0xC002_1000, move |mem, regs| {
        static mut ND: u32 = 0;
        unsafe {
            if ND < 30 && regs[0] != 7 {
                ND += 1;
                let n = ND;
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
    // (klog_full/klog_pend live near the top, with the other shared
    // trap state — the printk trap below needs them in scope.)
    // (trap_pc_mem at the old address removed: wrong address.)
    // Linux-handoff snapshot: r0-r3 + ATAG head at the trampoline
    // entry (`0x88015240`, before `mov pc, r3` at `0x880152A4`).
    // Proves the machine ID (r1, expect trout 1440) and the ATAG list
    // (NONE placement decides what the kernel sees) on a live run.
    let regs_saida = std::rc::Rc::new(std::cell::Cell::new([0u32; 4]));
    let regs_saida_b = regs_saida.clone();
    let atags = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
    let atags_b = atags.clone();
    // TEMP (zygote libsgl NULL+4): the preloader crashes in libsgl
    // at 0xAC042E88 (`str r6, [r2, #4]` with r2 = 0) right after a
    // size-0x14 malloc at 0xAC042E54. Log ONLY the bad executions
    // (malloc returning NULL, or the fault site reached with a NULL
    // base) — the site also runs fine most of the time, which would
    // burn any unconditional cap. Cap 8 each; remove once the NULL
    // source is named (failed brk/mmap serve vs guest logic).
    cpu.trap_pc_mem(0xAC04_2E58, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if regs[0] == 0 && N < 8 {
                N += 1;
                let n = N;
                eprintln!("SGLMALLOC#{n} f={} r0=NULL lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xAC04_2E88, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            // TEMP (libsgl NULL+4 workaround probe): log every arrival
            // in the crash window (r0=node, r4=slot idx, r2=base,
            // r6=value, r7=key, old word at [r2+4]) and SKIP the store
            // when r2==0 (advance PC past the str). The miss path
            // (search exhausted, r0=0) reaches the use-site with no
            // NULL guard and SIGSEGVs; hardware never faults here so
            // the state already diverged upstream. Skip keeps zygote
            // alive to reveal the next divergence. Cap 40; remove
            // with the other SGL traps.
            if FATIA_ATUAL < 300000 {
                return;
            }
            if N < 40 {
                N += 1;
                let n = N;
                if regs[2] == 0 {
                    eprintln!("SGLSKIP#{n} f={} r0={:#x} r4={:#x} r6={:#x} r7={:#x} (store skipped)", unsafe { FATIA_ATUAL }, regs[0], regs[4], regs[6], regs[7]);
                    regs[15] = regs[15].wrapping_add(4);
                } else {
                    let mut ow = [0u8; 4];
                    let ook = mem.read(regs[2].wrapping_add(4), 4).map(|s| ow.copy_from_slice(s)).is_ok();
                    eprintln!("SGLUSE#{n} f={} r0={:#x} r4={:#x} r2={:#x} r6={:#x} r7={:#x} old_ok={ook} old={ow:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[4], regs[2], regs[6], regs[7]);
                }
                return;
            }
            if regs[2] == 0 {
                regs[15] = regs[15].wrapping_add(4);
            }
        }
    });
    // TEMP (linker open-result watch): the linker's open stub is
    // ARM at 0xB000A510 (`push; mov r7,#5; svc; pop` — extracted
    // from /system/bin/linker in the NAND image, base 0xB0000000).
    // Entry (0xB000A510) stashes the path pointer; exit
    // (0xB000A51C, pop — r0 already holds the kernel's return)
    // logs failures (r0 negative, with errno) and every libOmxCore
    // open with its fd/errno. Names the "Cannot find library"
    // culprit with its errno instead of guessing from the
    // OPEN-entry trace. Cap 16; remove with the other TEMP traps.
    let open_ptr = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let open_want = std::rc::Rc::new(std::cell::Cell::new(false));
    let open_ptr2 = open_ptr.clone();
    let open_want2 = open_want.clone();
    // TEMP (linker teardown watch): every lib unmap comes from
    // 0xB0000F20 (unmap si->base, return 0). It is tail-called (b,
    // not bl), so lr is stale (entry's 0x1005) — read the true
    // caller chain from the stack instead ([sp..sp+40] holds the
    // caller's saved regs incl. its return address). Log si,
    // si->base (names the lib), si->size, sp + 10 stack words.
    // PLUS the mapped PHDR table ([si+0x80], [si+0x84] entries):
    // 0xB24 walks the MAPPED phdrs (not the read buffer) hunting
    // PT_DYNAMIC, and bails -1 when it finds none. The read buffer
    // was byte-correct (LOADs match) but the mapped pages come from
    // the demand/alias serve path — a stale mapped phdr table here
    // is the prime suspect for the silent -1. Cap 128 B (4 entries).
    // Slice-gated to the two load rounds. Cap 16. Remove with OPENRET.
    cpu.trap_pc_mem(0xB000_0F20, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if N < 16 && (284_000..420_000).contains(&f) {
                N += 1;
                let n = N;
                let si = regs[0];
                let base = mem.read_u32(si.wrapping_add(0x8C)).unwrap_or(0xDEAD);
                let size = mem.read_u32(si.wrapping_add(0x90)).unwrap_or(0xDEAD);
                let mut st = [0u8; 40];
                let sok = mem.read(regs[13], 40).map(|s| st.copy_from_slice(s)).is_ok();
                let phdr = mem.read_u32(si.wrapping_add(0x80)).unwrap_or(0);
                let phnum = mem.read_u32(si.wrapping_add(0x84)).unwrap_or(0);
                let mut ph = [0u8; 128];
                let phok = if (0x1000..0xC000_0000).contains(&phdr) && (1..=8).contains(&phnum) {
                    mem.read(phdr, phnum * 32).map(|s| ph[..s.len()].copy_from_slice(s)).is_ok()
                } else {
                    false
                };
                // Forced mapped-header dump (first 64 B at base):
                // omx's phdr/phnum read base/0, which voided the
                // gated dump above. This shows whether the mapped
                // ELF header itself is zeros (demand-serve bug) or
                // correct (si-setup bug elsewhere).
                let mut hd = [0u8; 64];
                let hdok = if (0x1000..0xC000_0000).contains(&base) {
                    mem.read(base, 64).map(|s| hd.copy_from_slice(s)).is_ok()
                } else {
                    false
                };
                // DYNAMIC-segment dump (first 64 B at si+0x94 when it
                // looks like an address): the link step beyond the
                // phdr walk reads DYNAMIC/REL tables from the mapped
                // RW pages. Top/pvplayer/pvcommon have correct
                // headers yet still fail — a zeroed DYNAMIC page
                // (same serve-bug class as omx's header) would
                // explain a silent bail with no new error.
                let dynset = mem.read_u32(si.wrapping_add(0x94)).unwrap_or(0);
                let mut dy = [0u8; 64];
                let dyok = if (0x1000..0xC000_0000).contains(&dynset) {
                    mem.read(dynset, 64).map(|s| dy.copy_from_slice(s)).is_ok()
                } else {
                    false
                };
                eprintln!("TEARDOWN#{n} f={f} si={si:#x} base={base:#x} size={size:#x} sp={:#x} sok={sok} stack={st:02x?} phdr={phdr:#x} phnum={phnum} phok={phok} phdrs={ph:02x?} hdok={hdok} hdr={hd:02x?} dyok={dyok} dyn={dy:02x?}", regs[13]);
            }
        }
    });
    // TEMP (linker fail-site watch, round 2): 0xB24 bails -1 via
    // 0xD76 from three sites: 0xBC2 (duplicate PT_DYNAMIC), 0xBE6
    // (no DYNAMIC found), 0xC50 (unhandled segment kind). Trap the
    // shared epilogue 0xD76 itself (single trap, no loop) plus one
    // branch site unconditionally: if 0xD76 fires, the -1 path is
    // real; r5 is the si at the branch. Cap 8. Remove with OPENRET.
    cpu.trap_pc_mem(0xB000_0D76, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if N < 8 && (284_000..420_000).contains(&f) {
                N += 1;
                let n = N;
                let si = regs[5];
                let base = mem.read_u32(si.wrapping_add(0x8C)).unwrap_or(0xDEAD);
                // Distinguish the three -1 sites without trusting
                // branch traps: BC2 needs si+0x94 already set (dup
                // DYNAMIC), BE6 needs it still -1 (none found); also
                // dump phdr/phnum/flags to see what the walk saw.
                let phdr = mem.read_u32(si.wrapping_add(0x80)).unwrap_or(0xDEAD);
                let phnum = mem.read_u32(si.wrapping_add(0x84)).unwrap_or(0xDEAD);
                let dynset = mem.read_u32(si.wrapping_add(0x94)).unwrap_or(0xDEAD);
                let flags = mem.read_u32(si.wrapping_add(0xA4)).unwrap_or(0xDEAD);
                eprintln!("FAIL76#{n} f={f} si={si:#x} base={base:#x} phdr={phdr:#x} phnum={phnum} dynset={dynset:#x} flags={flags:#x}");
            }
        }
    });
    // TEMP (omx mapping census): trap the linker's memset entry
    // (0xB0001A40, ARM) and dump every region overlapping omx's
    // first page with owner-mm and generation. Settles whether the
    // faulting write hits a stale-generation/execve-orphaned region
    // (invisible but blocking) vs no region at all. Cap 4.
    // Remove once the tail fault is understood.
    cpu.trap_pc_mem(0xB000_1A40, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                let n = N;
                let mm = mem.mm_atual();
                let ger = mem.geracao();
                let mut s = std::string::String::new();
                for r in mem.regions().iter() {
                    let fim = r.base.wrapping_add(r.bytes.len() as u32);
                    if r.base < 0x8000_4000 && fim > 0x8000_0000 {
                        use std::fmt::Write as _;
                        let _ = write!(s, "[{:#x}+{:#x} {} mm={:?} gen={}] ", r.base, r.bytes.len(), r.name, r.dono_mm, r.geracao);
                    }
                }
                eprintln!("OMXCENSUS#{n} f={} mm={mm:#x} ger={ger:#x} r0={:#x} r1={:#x} r2={:#x} regions: {s}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2]);
            }
        }
    });
    // TEMP (zygote wild-pointer crash, object ID): the fault is
    // `ldr r2,[r7,#0x94]` with r7=0x2e0065 (garbage, likely string
    // bytes misread as a pointer — a type confusion). Trap the
    // function entry (0xAD0156CC) in the crash window and dump the
    // entry object: valid struct vs string data vs zeros names the
    // corruption (stale page vs wrong pointer). Cap 8.
    // Remove once the bad pointer's source is named.
    cpu.trap_pc_mem(0xAD01_56CC, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if N < 8 && (384_000..386_500).contains(&f) {
                N += 1;
                let n = N;
                let obj = regs[7];
                let mut hb = [0u8; 64];
                let ok = mem.read(obj, 64).map(|s| hb.copy_from_slice(s)).is_ok();
                let mut hb2 = [0u8; 16];
                let ok2 = mem.read(obj.wrapping_add(0x48), 16).map(|s| hb2.copy_from_slice(s)).is_ok();
                // Neighbor code dump (call sites): the stack holds
                // 0xAD015FB4/0xAD015FE4 returns in this same module.
                // Dump that window to disassemble the callers offline.
                let mut nb = [0u8; 96];
                let nok = mem.read(0xAD01_5F80, 96).map(|s| nb.copy_from_slice(s)).is_ok();
                eprintln!("CRASHOBJ#{n} f={f} obj={obj:#x} ok={ok} head={hb:02x?} ok2={ok2} slot48={hb2:02x?} nok={nok} near={nb:02x?}");
                // Full object page dump (4 KiB at the page base) to
                // reconstruct heap layout: chunk headers, adjacent
                // objects/strings. Names what obj is (and what wrote
                // the string that collides with +0x48). Cap 2.
                {
                    let base = obj & !0xFFF;
                    let mut pg = vec![0u8; 0x1000];
                    let ok = mem.read(base, 0x1000).map(|s| pg.copy_from_slice(s)).is_ok();
                    eprintln!("CRASHPAGE#{n} f={f} base={base:#x} ok={ok} page={pg:02x?}");
                    // Self-consistency: re-read obj+64 through a FRESH
                    // small read and compare with both dumps. If the
                    // small read matches CRASHOBJ but not CRASHPAGE
                    // (same trap, same memory), region_for is
                    // length-dependent — file as a memory-model bug.
                    let mut chk = [0u8; 64];
                    let cok = mem.read(obj, 64).map(|s| chk.copy_from_slice(s)).is_ok();
                    let mut match_small = true;
                    let mut match_page = true;
                    let off = (obj & 0xFFF) as usize;
                    for i in 0..64 {
                        if hb[i] != chk[i] {
                            match_small = false;
                        }
                        if pg[off + i] != chk[i] {
                            match_page = false;
                        }
                    }
                    eprintln!("CRASHCHK#{n} f={f} cok={cok} match_small={match_small} match_page={match_page} off={off:#x}");
                }
                // Deep stack (256B) to find the real return address:
                // lr is stale (tail-call in), but the caller's
                // saved regs/return must be on the stack.
                {
                    let mut sc = [0u8; 256];
                    let sok = mem.read(regs[13], 256).map(|s| sc.copy_from_slice(s)).is_ok();
                    eprintln!("CRASHSTK#{n} f={f} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?}", regs[14], regs[13]);
                }
                // Region owning the object: file-backed (which file?)
                // vs anonymous vs stale. Decides serve-bug vs logic.
                {
                    use std::fmt::Write as _;
                    let mut s = std::string::String::new();
                    for r in mem.regions().iter() {
                        let fim = r.base.wrapping_add(r.bytes.len() as u32);
                        if r.base <= obj && obj < fim {
                            let _ = write!(s, "[{:#x}+{:#x} {} wr={} mm={:?} gen={}] ", r.base, r.bytes.len(), r.name, r.writable, r.dono_mm, r.geracao);
                        }
                    }
                    if !s.is_empty() {
                        eprintln!("CRASHREG#{n} f={f} obj={obj:#x} {s}curmm={:#x}", mem.mm_atual());
                    }
                    // Dump EVERY region intersecting a wide window around
                    // the object: overlapping same-VA fragments would
                    // explain CRASHOBJ vs CRASHPAGE disagreeing in one
                    // atomic handler (different lens hitting different
                    // fragments). Cap output at 16 entries.
                    {
                        use std::fmt::Write as _;
                        let mut s2 = std::string::String::new();
                        let mut cnt = 0;
                        for r in mem.regions().iter() {
                            let fim = r.base.wrapping_add(r.bytes.len() as u32);
                            if r.base < 0x4003_8000 && fim > 0x4003_0000 && cnt < 16 {
                                cnt += 1;
                                let _ = write!(s2, "[{:#x}+{:#x} {} wr={} mm={:?} gen={}] ", r.base, r.bytes.len(), r.name, r.writable, r.dono_mm, r.geracao);
                            }
                        }
                        eprintln!("CRASHREG2#{n} f={f} {s2}curmm={:#x}", mem.mm_atual());
                    }
                }
            }
        }
    });
    // TEMP (GC mark entry args): 0xAD015518 is the enclosing static
    // (dvmHeapBeginMarkStep region). Log r0/sb, r1/sl and *r0 to see
    // what object seeds the 0x156CC walk whose +0x48 is string bytes.
    // Same crash window, cap 8. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_5518, move |mem, regs| {
        static mut M: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if M < 8 && (384_000..386_500).contains(&f) {
                M += 1;
                let n = M;
                let a0 = regs[0];
                let a1 = regs[1];
                let star0 = mem.read_u32(a0).unwrap_or(0xDEAD);
                let mut hb = [0u8; 64];
                let ok = mem.read(a0, 64).map(|s| hb.copy_from_slice(s)).is_ok();
                let mut s = std::string::String::new();
                for r in mem.regions().iter() {
                    let fim = r.base.wrapping_add(r.bytes.len() as u32);
                    if r.base <= a0 && a0 < fim {
                        use std::fmt::Write as _;
                        let _ = write!(s, "[{:#x}+{:#x} {}] ", r.base, r.bytes.len(), r.name);
                    }
                }
                let mut sc = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| sc.copy_from_slice(s)).is_ok();
                eprintln!("MARKARGS#{n} f={f} r0={a0:#x} r1={a1:#x} star0={star0:#x} ok={ok} head={hb:02x?} {s}lr={:#x} sp={:#x} sok={sok} stack={sc:02x?}", regs[14], regs[13]);
            }
        }
    });
    // TEMP (GC array-loop entry): 0xAD015FB4 iterates (r0=count,
    // r1=array, r2=?, r3=table) calling 0x15518 per element. Log args
    // + first 2 elements to tell overrun (count > array) from bad
    // element (array really holds the string-headed pointer).
    // Same window, cap 8. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_5FB4, move |mem, regs| {
        static mut K: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if K < 8 && (384_000..386_500).contains(&f) {
                K += 1;
                let n = K;
                let c = regs[0];
                let arr = regs[1];
                let e0 = mem.read_u32(arr).unwrap_or(0xDEAD);
                let e1 = mem.read_u32(arr.wrapping_add(4)).unwrap_or(0xDEAD);
                // Full array dump (count words) to tell single-bad
                // element from systematic corruption. Cap count at
                // 160 to bound output.
                let cnt = (c as usize).min(160);
                let mut ab = vec![0u8; cnt * 4];
                let aok = mem.read(arr, (cnt * 4) as u32).map(|s| ab.copy_from_slice(s)).is_ok();
                // Heads of first two elements: tells whether e0 is an
                // outlier (bad object) while e1 looks like a valid
                // markable object. 32 B each to bound output.
                let mut h0 = [0u8; 32];
                let ok0 = mem.read(e0, 32).map(|s| h0.copy_from_slice(s)).is_ok();
                let mut h1 = [0u8; 32];
                let ok1 = mem.read(e1, 32).map(|s| h1.copy_from_slice(s)).is_ok();
                // Owning page of e0 (4 KiB): chunk headers + neighbors
                // tell whether e0 is an object header (corrupt clazz)
                // or mid-table data (caller passed interior pointer).
                let base0 = e0 & !0xFFF;
                let mut pg0 = vec![0u8; 0x1000];
                let okp = mem.read(base0, 0x1000).map(|s| pg0.copy_from_slice(s)).is_ok();
                eprintln!("MARKLOOP#{n} f={f} count={c:#x} arr={arr:#x} r2={:#x} r3={:#x} e0={e0:#x} e1={e1:#x} lr={:#x} aok={aok} arrd={ab:02x?} ok0={ok0} h0={h0:02x?} ok1={ok1} h1={h1:02x?} okp={okp} page0={pg0:02x?}", regs[2], regs[3], regs[14]);
            }
        }
    });
    // TEMP (GC builder log capture): 0xAD01397C is `bl log_print`
    // inside the array-builder (0x1390C). Log tag/fmt strings to name
    // the builder (verify vs mark vs scan). Same window, cap 4.
    // Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_397C, move |mem, regs| {
        static mut W: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if W < 4 && (384_000..386_500).contains(&f) {
                W += 1;
                let n = W;
                let mut tb = [0u8; 40];
                let tok = mem.read(regs[1], 40).map(|s| tb.copy_from_slice(s)).is_ok();
                let mut fb = [0u8; 80];
                let fok = mem.read(regs[2], 80).map(|s| fb.copy_from_slice(s)).is_ok();
                let tz = tb.iter().position(|&b| b == 0).unwrap_or(tb.len());
                let fz = fb.iter().position(|&b| b == 0).unwrap_or(fb.len());
                eprintln!("BUILDLOG#{n} f={f} tok={tok} tag={:?} fok={fok} fmt={:?}", String::from_utf8_lossy(&tb[..tz]), String::from_utf8_lossy(&fb[..fz]));
            }
        }
    });
    // (BUILDARR trap removed: builder runs outside the crash
    // window and never fired. Keep BUILDLOG for the write-watch pass.)
    // TEMP (who frees in the string's page): libcutils mspace_free
    // (0xAFB05FE0, Thumb entry; mspace in r0, chunk in r1) filtered
    // to page 0x40037000. The exact-address watch stayed silent
    // through the crash, so look for NEIGHBOUR frees: a coalescing
    // free links the live string chunk into a bin without ever
    // freeing it directly. A free adjacent to 0x40037E20 just before
    // WATCH#16 = coalescing confirmed (with lr naming who freed the
    // neighbour). Cap 20. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAFB0_5FE0, move |mem, regs| {
        static mut NF: u32 = 0;
        unsafe {
            if NF < 80 && (regs[1] & !0xFFF) == 0x4003_7000 {
                NF += 1;
                let n = NF;
                let mut sc = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| sc.copy_from_slice(s)).is_ok();
                eprintln!("FREEPG#{n} f={} msp={:#x} chunk={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14], regs[13]);
            }
        }
    });
    // TEMP (plant context): 0xAFB06614 links r4 into a bin list
    // (`str r4,[r2,#8]; str r4,[r1,#0xc]` …). Gate on the exact
    // plant value to catch the string-linking instance with full
    // register context: r6 = mspace-ish struct ([r6+0x14] fed r4),
    // r2/r1 = insertion neighbours, lr = malloc-vs-free caller.
    // Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAFB0_6614, move |mem, regs| {
        static mut NP: u32 = 0;
        unsafe {
            if NP < 4 && regs[4] == 0x4003_7E20 {
                NP += 1;
                let n = NP;
                let mut sc = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| sc.copy_from_slice(s)).is_ok();
                let r6b = mem.read_u32(regs[6].wrapping_add(0x14)).unwrap_or(0xDEAD);
                eprintln!("PLANTA#{n} f={} r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r6_14={r6b:#x} r7={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[14], regs[13]);
            }
        }
    });
    // TEMP (GC phase entry): 0xAD01390C drives the fill+mark loop
    // (no static callers — dispatched via callback). Log r0/r1
    // (heap/bitmap args) + lr (dispatcher = which GC phase) + stack
    // to name the operation scanning the wrong region. Window-gated
    // to the bulk-free neighborhood. Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_390C, move |mem, regs| {
        static mut NG: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if NG < 4 && (337_000..340_000).contains(&f) {
                NG += 1;
                let n = NG;
                let mut sc = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| sc.copy_from_slice(s)).is_ok();
                // Table struct content (r0 stable at 0x40009238): names
                // the heap/table being walked (bounds + bitmap slots).
                let mut tb = [0u8; 128];
                let tok = mem.read(regs[0], 128).map(|s| tb.copy_from_slice(s)).is_ok();
                eprintln!("GCPHASE#{n} f={f} r0={:#x} r1={:#x} r2={:#x} r3={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?} tok={tok} table={tb:02x?}", regs[0], regs[1], regs[2], regs[3], regs[14], regs[13]);
            }
        }
    });
    // TEMP (bulk-free dispatcher): 0xAD048EA8 loops freeing
    // consecutive mspace chunks (the 38-hit FREEPG run incl. the
    // crash string) via blx free. No static callers (callback
    // dispatch) — log r0 + lr + stack to name the operation that
    // tears down live class data at f≈338849. Window-gated to the
    // bulk-free neighborhood. Cap 8. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD04_8EA8, move |mem, regs| {
        static mut NB: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if NB < 8 && (337_000..340_000).contains(&f) {
                NB += 1;
                let n = NB;
                let mut sc = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| sc.copy_from_slice(s)).is_ok();
                eprintln!("BULKFREE#{n} f={f} r0={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?}", regs[0], regs[14], regs[13]);
            }
        }
    });
    // TEMP (writer code ID): dump 96 B at the loop-store PC
    // (0xAFB0634C x13) to match against host libs (module ID +
    // serve check). The 0x6614 plant is now covered by PLANTA#
    // with full regs — this stays for the loop store only.
    // Cap 1. Remove with CRASHOBJ.
    for va in [0xAFB0_634Cu32] {
        cpu.trap_pc_mem(va, move |mem, _regs| {
            static mut NW: u32 = 0;
            unsafe {
                if NW < 2 {
                    NW += 1;
                    let n = NW;
                    let mut cb = [0u8; 96];
                    let ok = mem.read(va, 96).map(|s| cb.copy_from_slice(s)).is_ok();
                    eprintln!("WRITER#{n} va={va:#x} ok={ok} code={cb:02x?}");
                }
            }
        });
    }
    // TEMP (bin-select inputs): 0xAD013B10 computes the selected
    // slot (sb=r5+lr base, bitmap in r1) just before the mark loop.
    // Log base/bitmap/array to tell bad-input (sb or bitmap already
    // selects the string slot) from bad-compute (emulator mis-exec).
    // Same window, cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_3B10, move |mem, regs| {
        static mut V: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if V < 4 && (384_000..386_500).contains(&f) {
                V += 1;
                let n = V;
                let sb = regs[5].wrapping_add(regs[14]);
                eprintln!("BINSEL#{n} f={f} sb={sb:#x} r5={:#x} lr={:#x} r1={:#x} r0={:#x}", regs[5], regs[14], regs[1], regs[0]);
            }
        }
    });
    // TEMP (bitmap address): 0xAD013A38 sits right after the direct
    // bitmap load (`ldr r1,[r6],#4`) in the fill outer loop. Gate on
    // the crashing chunk's exact word (r1==0x100) in the crash-walk
    // window: logs the word + bitmap cursor (r6, already post-inc —
    // base is r6-4) to name WHICH bitmap selects the bins slot
    // (mark bitmap with a stale bit? live map covering control?).
    // Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_3A38, move |mem, regs| {
        static mut NY: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if NY < 4 && (384_150..384_260).contains(&f) && regs[1] == 0x100 {
                NY += 1;
                let n = NY;
                eprintln!("BITMAP#{n} f={f} word={:#x} cursor={:#x}", regs[1], regs[6]);
            }
        }
    });
    // (XORBIT trap removed: the XOR-compare loop is a different path —
    // the crash walk's bitmap word comes from the direct load above,
    // proven by BINSEL firing while XORBIT stayed silent.)
    // TEMP (stale-root hunt): at the crash-walk entry, scan EVERY
    // mapped region for words equal to the bin slot (0x400090B8) or
    // the string (0x40037E20). Names heap referrers; an empty result
    // means the reference lives only in roots/stack (conservative
    // scan of dispatcher working state). Cap 1 (slow: full-map
    // scan). Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_56CC, move |mem, regs| {
        static mut NH: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if NH < 1 && (384_000..386_500).contains(&f) {
                NH += 1;
                let mut hits = std::string::String::new();
                let mut n = 0u32;
                for r in mem.regions().iter() {
                    if r.bytes.len() < 4 || r.bytes.len() > 64 * 1024 * 1024 {
                        continue;
                    }
                    let mut off = 0usize;
                    while off + 4 <= r.bytes.len() {
                        let v = u32::from_le_bytes([r.bytes[off], r.bytes[off+1], r.bytes[off+2], r.bytes[off+3]]);
                        if v == 0x4000_90B8 || v == 0x4003_7E20 {
                            use std::fmt::Write as _;
                            let _ = write!(hits, "[{}+{:#x}={:#x}] ", r.name, r.base, r.base.wrapping_add(off as u32));
                            n += 1;
                            if n >= 24 {
                                break;
                            }
                        }
                        off += 4;
                    }
                    if n >= 24 {
                        break;
                    }
                }
                eprintln!("REFHUNT#{n} f={f} obj={:#x} {hits}", regs[7]);
            }
        }
    });
    // TEMP (XML asset caller): libandroid_runtime+0x34D18 calls
    // ResXMLTree::setTo and feeds it the NULL blob. Trap its entry,
    // dump pointer args as C strings to name the asset path.
    // Cap 8 (few inits per boot). Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD33_4D18, move |mem, regs| {
        static mut NA: u32 = 0;
        unsafe {
            if NA < 8 {
                NA += 1;
                let n = NA;
                let mut ss = [std::string::String::new(), std::string::String::new(), std::string::String::new(), std::string::String::new()];
                for (k, r) in [regs[0], regs[1], regs[2], regs[3]].iter().enumerate() {
                    let mut b = [0u8; 64];
                    if mem.read(*r, 64).map(|s| b.copy_from_slice(s)).is_ok() {
                        let z = b.iter().position(|&x| x == 0).unwrap_or(64);
                        ss[k] = String::from_utf8_lossy(&b[..z]).into_owned();
                    }
                }
                eprintln!("ASSET#{n} f={} r0={:#x} r1={:#x} r2={:#x} r3={:#x} lr={:#x} s0={:?} s1={:?} s2={:?} s3={:?}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[3], regs[14], ss[0], ss[1], ss[2], ss[3]);
            }
        }
    });
    // TEMP (NULL source): the virtual call at libandroid_runtime+0x34DCC
    // returns the NULL data handed to setTo. Trap it, dump the
    // object (r0), vtable slot and result to name the source.
    // Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD33_4DCC, move |mem, regs| {
        static mut NV: u32 = 0;
        unsafe {
            if NV < 4 {
                NV += 1;
                let n = NV;
                let mut ob = [0u8; 128];
                let ook = mem.read(regs[0], 128).map(|s| ob.copy_from_slice(s)).is_ok();
                let mut sc = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| sc.copy_from_slice(s)).is_ok();
                eprintln!("NULLSRC#{n} f={} r0={:#x} r1={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?} ook={ook} obj={ob:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14], regs[13]);
            }
        }
    });
    // TEMP (inflate-buffer malloc): the 0x5FC8 NULL may come from
    // a failed malloc (output buffer) rather than inflate itself —
    // the mspace arena in this heap already showed live-chunk-in-bin
    // corruption. mspace_malloc entry is 0xAFB074E4 (Thumb, size in
    // r0). Broad filter (any malloc >= 4KB in the 100-slice window
    // before the crash) with entry/exit pairing to capture results:
    // a NULL result on a Zip-code lr = malloc-fail proven. Cap 30
    // entries, returns self-disarm. Remove with CRASHOBJ.
    // Shared pending-malloc slot (entry arms, exit pairs): sizes
    // this narrow don't nest, so a single slot is exact.
    let pend_tam = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let pend_lr = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let pend_armado = std::rc::Rc::new(std::cell::Cell::new(false));
    let pend_tam2 = pend_tam.clone();
    let pend_lr2 = pend_lr.clone();
    let pend_armado2 = pend_armado.clone();
    cpu.trap_pc_mem(0xAFB0_74E4, move |_mem, regs| {
        static mut NM: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if NM < 30 && (395_700..395_800).contains(&f) && regs[1] >= 0x1000 {
                NM += 1;
                let n = NM;
                pend_tam.set(regs[1]);
                pend_lr.set(regs[14]);
                pend_armado.set(true);
                eprintln!("MALLOCBIG#{n} f={f} msp={:#x} size={:#x} lr={:#x}", regs[0], regs[1], regs[14]);
            }
        }
    });
    // TEMP (malloc-result pairing): mspace_malloc's single exit
    // (0xAFB076CC `pop {r4-r7,pc}`, r0 = result). Pairs with the
    // most recent MALLOCBIG entry: NULL result here = the inflate
    // buffer never existed. Self-limiting (only fires when armed).
    // Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAFB0_76CC, move |_mem, regs| {
        unsafe {
            if pend_armado2.get() {
                pend_armado2.set(false);
                eprintln!("MALLOCRES f={} size={:#x} lr={:#x} result={:#x}", unsafe { FATIA_ATUAL }, pend_tam2.get(), pend_lr2.get(), regs[0]);
            }
        }
    });
    // TEMP (bionic-malloc pair): operator new (`_Znwj`, proven in the
    // caller) routes to bionic malloc, NOT mspace_malloc — the
    // broadened MALLOCBIG watches the wrong allocator for the
    // inflate buffer. bionic malloc entry 0xAFE0A750 (Thumb, size in
    // r0), single exit 0xAFE0A9B6 (`pop {r4-r7,pc}`). Same
    // window/size gate + pairing. A NULL result on a libutils lr =
    // buffer-malloc failed. Remove with CRASHOBJ.
    let btam = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let blr = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let barm = std::rc::Rc::new(std::cell::Cell::new(false));
    let btam2 = btam.clone();
    let blr2 = blr.clone();
    let barm2 = barm.clone();
    cpu.trap_pc_mem(0xAFE0_A750, move |_mem, regs| {
        static mut NB: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if NB < 30 && (395_700..395_800).contains(&f) && regs[0] >= 0x1000 {
                NB += 1;
                let n = NB;
                btam.set(regs[0]);
                blr.set(regs[14]);
                barm.set(true);
                eprintln!("MALLOCB#{n} f={f} size={:#x} lr={:#x}", regs[0], regs[14]);
            }
        }
    });
    cpu.trap_pc_mem(0xAFE0_A9B6, move |_mem, regs| {
        unsafe {
            if barm2.get() {
                barm2.set(false);
                eprintln!("MALLOCR f={} size={:#x} lr={:#x} result={:#x}", unsafe { FATIA_ATUAL }, btam2.get(), blr2.get(), regs[0]);
            }
        }
    });
    // TEMP (teardown sequence): the 0x5FC8 buffer at 0xa03c8 is
    // malloc'd OK (MALLOCR) yet getData() returns NULL, and setTo's
    // own malloc reuses the same address — so the buffer is FREED
    // between inflate and setTo. Trap bionic free (0xAFE09DA8,
    // Thumb, chunk in r0) gated on the buffer AND on the Asset
    // object (0x8c3c0): the order names the premature teardown
    // (buffer-vs-owner freed first, with lr naming the freer).
    // Addresses are deterministic from snap330 (TEMP). Cap 4 each.
    // Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAFE0_9DA8, move |mem, regs| {
        static mut NF: u32 = 0;
        unsafe {
            if NF < 8 && (regs[0] == 0xA03C8 || regs[0] == 0x8C3C0) {
                NF += 1;
                let n = NF;
                let mut sc = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| sc.copy_from_slice(s)).is_ok();
                eprintln!("TEARDOWN#{n} f={} chunk={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[14], regs[13]);
            }
        }
    });
    // TEMP (mystery-caller ID): MALLOCB#1's lr=0xafd0196d sits in an
    // unidentified mapping. Trap the malloc call site (bl at
    // 0xafd01968, r0=size) and dump code around lr for offline
    // file matching (proven trick for libandroid_runtime). Gate on
    // the asset size to isolate this call. Cap 2. Remove with
    // CRASHOBJ.
    cpu.trap_pc_mem(0xAFD0_1968, move |mem, regs| {
        static mut NQ: u32 = 0;
        unsafe {
            if NQ < 2 && regs[0] == 0x5FC8 {
                NQ += 1;
                let n = NQ;
                let base = regs[14].wrapping_sub(65);
                let mut cb = [0u8; 128];
                let cok = mem.read(base & !1, 128).map(|s| cb.copy_from_slice(s)).is_ok();
                eprintln!("CALLER24K#{n} f={} r0={:#x} lr={:#x} cok={cok} code={cb:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[14]);
            }
        }
    });
    // TEMP (inflate-chain audit): _CompressedAsset::getBuffer news the
    // buffer, then either lseeks + calls the streaming helper
    // (0xA9D291C4: read + inflate) or a static variant. The helper
    // returns 0 on failure → delete[] → NULL → crash. Trap each
    // link with STATIC addresses (single-threaded, sequential):
    // helper entry (fd/buf/len wiring), lseek verify (r0 vs
    // expected [r4+#0xc]), read result (0xA9D2925A, r0=bytes),
    // inflate result (0xA9D2927E, r0=ret: 1=END, 0=OK, <0=error),
    // helper verify (0xA9D1C380, r0). Cap 4 each. Remove with
    // CRASHOBJ.
    cpu.trap_pc_mem(0xA9D2_91C4, move |mem, regs| {
        static mut NH: u32 = 0;
        unsafe {
            if NH < 4 {
                NH += 1;
                let n = NH;
                let mut sc = [0u8; 32];
                let sok = mem.read(regs[13], 32).map(|s| sc.copy_from_slice(s)).is_ok();
                eprintln!("INFLATE#{n} f={} fd={:#x} buf={:#x} len={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xA9D1_C370, move |_mem, regs| {
        static mut NL: u32 = 0;
        unsafe {
            if NL < 4 {
                NL += 1;
                let n = NL;
                eprintln!("SEEKCHK#{n} f={} resultado={:#x} esperado={:#x} igual={}", unsafe { FATIA_ATUAL }, regs[0], regs[3], regs[0] == regs[3]);
            }
        }
    });
    cpu.trap_pc_mem(0xA9D2_925A, move |_mem, regs| {
        static mut NR: u32 = 0;
        unsafe {
            if NR < 8 {
                NR += 1;
                let n = NR;
                eprintln!("READRES#{n} f={} bytes={:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
    });
    cpu.trap_pc_mem(0xA9D2_927E, move |_mem, regs| {
        static mut NI: u32 = 0;
        unsafe {
            if NI < 8 {
                NI += 1;
                let n = NI;
                eprintln!("INFLATERES#{n} f={} ret={:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
    });
    cpu.trap_pc_mem(0xA9D1_C380, move |_mem, regs| {
        static mut NV: u32 = 0;
        unsafe {
            if NV < 4 {
                NV += 1;
                let n = NV;
                eprintln!("HELPERCHK#{n} f={} resultado={:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
    });
    // TEMP (variant-inflate audit): the memory variant (0xA9D288CC)
    // fails (HELPERCHK=0) — trap its inflate call (0xA9D28940,
    // blx imm) dumping the z_stream (r0, 56B: next_in/src VA at
    // +0, avail_in +4, next_out/dst +12, avail_out +16) to reveal
    // the compressed source as the guest sees it, plus the return
    // (0xA9D28944: 1=END, 0=OK, <0=zlib error). A zeros/unmapped
    // src page = serve bug (check URES fonte for that VA); valid
    // zlib bytes + error = logic/CPU bug. Cap 4 each. Remove with
    // CRASHOBJ.
    cpu.trap_pc_mem(0xA9D2_8940, move |mem, regs| {
        static mut NZ: u32 = 0;
        unsafe {
            if NZ < 4 {
                NZ += 1;
                let n = NZ;
                let mut zs = [0u8; 56];
                let zok = mem.read(regs[0], 56).map(|s| zs.copy_from_slice(s)).is_ok();
                let src = u32::from_le_bytes([zs[0], zs[1], zs[2], zs[3]]);
                let cnt = u32::from_le_bytes([zs[4], zs[5], zs[6], zs[7]]) as usize;
                let mut sb = [0u8; 64];
                let sok2 = mem.read(src, 64).map(|s| sb.copy_from_slice(s)).is_ok();
                let mut sc = [0u8; 32];
                let sok = mem.read(regs[13], 32).map(|s| sc.copy_from_slice(s)).is_ok();
                eprintln!("INFLATEZ#{n} f={} strm={:#x} lr={:#x} sp={:#x} zok={zok} z={zs:02x?} sok={sok} stack={sc:02x?} src={src:#x} cnt={cnt:#x} sok2={sok2} srcbytes={sb:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xA9D2_8944, move |_mem, regs| {
        static mut NW: u32 = 0;
        unsafe {
            if NW < 4 {
                NW += 1;
                let n = NW;
                eprintln!("INFLATERET#{n} f={} ret={:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        }
    });
    // TEMP (kernel-struct probe): dump task_struct (0xc6201000,
    // stable across snap330 resumes per USRFLT), the mm candidate
    // (0xc6224000, taskdump word[1]) and thread_info (sp-aligned)
    // to resolve task->mm->VMA->file offsets OFFLINE for the
    // file-backed serve fix. Fires once at the inflate call.
    // Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xA9D2_8940, move |mem, regs| {
        static mut NK: u32 = 0;
        unsafe {
            if NK < 1 {
                NK += 1;
                let mut tb = [0u8; 2048];
                let tok = mem.read(0xC620_1000, 2048).map(|s| tb.copy_from_slice(s)).is_ok();
                let mut mb = [0u8; 256];
                let mok = mem.read(0xC622_4000, 256).map(|s| mb.copy_from_slice(s)).is_ok();
                let ti = regs[13] & !0x1FFF;
                let mut ib = [0u8; 64];
                let iok = mem.read(ti, 64).map(|s| ib.copy_from_slice(s)).is_ok();
                eprintln!("KSTRUCT f={} sp={:#x} ti={ti:#x} tok={tok} task={tb:02x?} mok={mok} mm={mb:02x?} iok={iok} tinfo={ib:02x?}", unsafe { FATIA_ATUAL }, regs[13]);
            }
        }
    });
    // TEMP (mm-candidate scan): task->mm offset unknown; try all
    // external-pointer fields in task_struct, walk each candidate's
    // VMA list (mm->mmap=+0, vma{start+4,end+8,next+12}) checking
    // coverage of the apk page (0x40000F6B). The winner names
    // task->mm AND the covering VMA (dump vm_file area for the
    // path fit). Fires once (first inflate). ~hundreds of reads,
    // cap 1. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xA9D2_8940, move |mem, regs| {
        static mut NS: u32 = 0;
        unsafe {
            if NS < 1 {
                NS += 1;
                // task->mm resolve: +0x1B0 proven (triple hit).
                let m = mem.read_u32(0xC620_1000u32.wrapping_add(0x1B0)).unwrap_or(0);
                let mut vma = mem.read_u32(m).unwrap_or(0);
                let mut depth = 0u32;
                let alvo = 0x4000_0F6Bu32;
                let mut win = [0u8; 72];
                let mut wok = false;
                let mut win_vma = 0u32;
                while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                    depth += 1;
                    let mut vb = [0u8; 72];
                    if mem.read(vma, 72).map(|s| vb.copy_from_slice(s)).is_err() {
                        break;
                    }
                    let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
                    let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
                    let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
                    // Verbose only for the interesting neighborhood
                    // (low mmap zone) + any file-backed VMA; one line
                    // each keeps the log small.
                    let f56 = u32::from_le_bytes([vb[56], vb[57], vb[58], vb[59]]);
                    let f60 = u32::from_le_bytes([vb[60], vb[61], vb[62], vb[63]]);
                    let f64 = u32::from_le_bytes([vb[64], vb[65], vb[66], vb[67]]);
                    if ini <= alvo && alvo < fim {
                        win.copy_from_slice(&vb);
                        win_vma = vma;
                        wok = true;
                    }
                    if ini <= 0x4103_2FECu32 && 0x4103_2FECu32 < fim {
                        eprintln!("VMACOV ini={ini:#x} fim={fim:#x} fl={fl:#x} w52={f56:#x} w56={f60:#x} w60={f64:#x} vma={vma:#x}");
                    }
                    vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
                }
                // TEMP (file-chain fit): follow the covering VMA's
                // vm_file (+60/+64/+68 candidates) -> f_path ->
                // dentry, dumping each level for offline offset fit.
                // The dentry whose name reads framework-res.apk
                // confirms the whole chain. Remove with CRASHOBJ.
                if wok {
                    let c72 = u32::from_le_bytes([win[68], win[69], win[70], win[71]]);
                    eprintln!("VMFILE vma_pgoff={c72:#x}");
                    // TEMP (dentry fit): struct file validated (f_op in
                    // kernel text). Dump the dentry from file+12:
                    // short names live inline (d_iname), so the bytes
                    // should literally contain framework-res.apk.
                    // Remove with CRASHOBJ.
                    let f = mem.read_u32(win_vma.wrapping_add(72)).unwrap_or(0);
                    eprintln!("VMFILE vma={win_vma:#x} file={f:#x} pgoff={:#x}", u32::from_le_bytes([win[68], win[69], win[70], win[71]]));
                    if (0xC600_0000..0xC700_0000).contains(&f) {
                        let mut fb = [0u8; 32];
                        if mem.read(f, 32).map(|s| fb.copy_from_slice(s)).is_ok() {
                            eprintln!("VMFILE fbytes={fb:02x?}");
                            let d = u32::from_le_bytes([fb[12], fb[13], fb[14], fb[15]]);
                            let mut db = [0u8; 192];
                            let dok = mem.read(d, 192).map(|s| db.copy_from_slice(s)).is_ok();
                            eprintln!("VMFILE dentry={d:#x} dok={dok} db={db:02x?}");
                        }
                    }
                }
                let _ = regs;
            }
        }
    });
    // TEMP (linker bxpl hunt): ARM syscall wrappers end `movs r0,r0;
    // bxpl lr` — a failed syscall (r0 negative, N=1) skips the return,
    // falls through in ARM state, and eventually returns to Thumb code
    // still in ARM state -> UND at 0xB0000854. Log ONLY negatives
    // (success is the common case; failures are rare). Uncapped.
    // Remove with CRASHOBJ.
    for &va in &[0xB000_14B0u32, 0xB000_1450u32, 0xB000_1490u32] {
        cpu.trap_pc_mem(va, move |_mem, regs| {
            if (regs[0] as i32) < 0 {
                eprintln!("LINKWRNEG f={} pc={va:#x} r0={:#x}", unsafe { FATIA_ATUAL }, regs[0]);
            }
        });
    }
    // TEMP (linker Thumb-state hunt): function at 0xB00007AC runs
    // Thumb (0xB0000854 = `str r7,[r6,#0x7c]`) but faults as ARM
    // UND (cpsr T=0). Log caller lr (bit0 set = Thumb BL caller,
    // clear = ARM BL caller that should have used BLX) + stack to
    // name who entered Thumb code in ARM state. Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xB000_07AC, move |mem, regs| {
        static mut NLK: u32 = 0;
        unsafe {
            if NLK < 4 {
                NLK += 1;
                let n = NLK;
                let f = FATIA_ATUAL;
                let lr = regs[14];
                let sp = regs[13];
                let mut stk = [0u8; 32];
                let sok = mem.read(sp, 32).map(|s| stk.copy_from_slice(s)).is_ok();
                eprintln!("LINKCALL#{n} f={f} lr={lr:#x} thumb_caller={} sp={sp:#x} sok={sok} stk={stk:02x?}", lr & 1 != 0);
            }
        }
    });
    // TEMP (libsgl heap-load hunt): ldr lr,[r4,#0x20] at 0xAC09E8DC
    // is the other lr source (skips smulbb on 2nd/3rd calls). Log r4,
    // loaded lr, and VMA for both to name use-after-free vs wild.
    // Same cap. Remove with CRASHOBJ.
    let mm_para_mm_ldr = mm_para_mm.clone();
    cpu.trap_pc_mem(0xAC09_E8DC, move |mem, regs| {
        static mut NLD: u32 = 0;
        unsafe {
            if NLD < 4 {
                NLD += 1;
                let n = NLD;
                let f = FATIA_ATUAL;
                let r4 = regs[4];
                let lr = mem.read_u32(r4.wrapping_add(0x20)).unwrap_or(0xDEAD);
                let mm = mem.mm_atual();
                let mut vma_lr = String::from("n/a");
                if let Some(&m) = mm_para_mm_ldr.borrow().get(&mm) {
                    let mut vma = mem.read_u32(m).unwrap_or(0);
                    let mut depth = 0u32;
                    while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                        depth += 1;
                        let mut vb = [0u8; 32];
                        if mem.read(vma, 32).map(|s| vb.copy_from_slice(s)).is_err() {
                            break;
                        }
                        let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
                        let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
                        if ini <= lr && lr < fim {
                            let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
                            vma_lr = format!("[{ini:#x},{fim:#x}) fl={fl:#x}");
                            break;
                        }
                        vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
                    }
                    if vma_lr == "n/a" {
                        vma_lr = String::from("sem-VMA");
                    }
                }
                eprintln!("SGLLDR#{n} f={f} mm={mm:#x} r0={:#x} r4={r4:#x} lr=[r4+0x20]={lr:#x} vma_lr={vma_lr}", regs[0]);
            }
        }
    });
    // TEMP (libsgl add-trace): add r8,lr,sl at 0xAC09E9A8 feeds the
    // wild mov. Log lr/sl/r8 here to see if smulbb left lr wild
    // (emulator Rd/Rn swap?) or sl wild. Same cap. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAC09_E9A8, move |_mem, regs| {
        static mut NAD: u32 = 0;
        unsafe {
            if NAD < 4 {
                NAD += 1;
                let n = NAD;
                let f = FATIA_ATUAL;
                eprintln!("SGLADD#{n} f={f} lr={:#x} sl={:#x} r8={:#x}", regs[14], regs[10], regs[8]);
            }
        }
    });
    // TEMP (libsgl mov-trace): first ins after `mov lr,r8` (0xAC09E9B0)
    // is `ldr r2,[ip]` at 0xAC09E9B4. Log lr/r8/sl here to see if
    // the wild appears immediately (smulbb path corrupt) or later.
    // Same cap. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAC09_E9B4, move |_mem, regs| {
        static mut NMV: u32 = 0;
        unsafe {
            if NMV < 4 {
                NMV += 1;
                let n = NMV;
                let f = FATIA_ATUAL;
                eprintln!("SGLMOV#{n} f={f} lr={:#x} r8={:#x} sl={:#x}", regs[14], regs[8], regs[10]);
            }
        }
    });
    // TEMP (libsgl multiply hunt): smulbb lr,r2,r3 at 0xAC09E9A0
    // computes the wild offset (lr=r8=ac1333d8). Log r2 (glyph
    // from [sb]), r3 (stride), sl (base), r8 (accumulator) to see
    // which input is wild. Same cap. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAC09_E9A0, move |mem, regs| {
        static mut NMU: u32 = 0;
        unsafe {
            if NMU < 4 {
                NMU += 1;
                let n = NMU;
                let f = FATIA_ATUAL;
                let mut mb = [0u8; 4];
                let mok = mem.read(0xAC09_E9A0, 4).map(|s| mb.copy_from_slice(s)).is_ok();
                eprintln!("SGLMUL#{n} f={f} r2={:#x} r3={:#x} sl={:#x} r8={:#x} sb={:#x} fp={:#x} r4={:#x} mok={mok} mcode={mb:02x?}", regs[2], regs[3], regs[10], regs[8], regs[9], regs[11], regs[4]);
            }
        }
    });
    // TEMP (libsgl wild-pointer hunt): tombstone pc ac09ea48
    // (libsgl.so) is `str r0,[lr,#0x20]` with lr=r8=ac1333d8,
    // fault ac1333f8=lr+0x20, guest PTE unmapped (no host URES).
    // Log regs + host readability + VMA via mm map (sp-trick
    // invalid in USR: sp is user stack) + caller stack to name
    // who passed the wild list head. Cap 4. Remove with CRASHOBJ.
    let mm_para_mm_sgl = mm_para_mm.clone();
    cpu.trap_pc_mem(0xAC09_EA48, move |mem, regs| {
        static mut NLG: u32 = 0;
        unsafe {
            if NLG < 4 {
                NLG += 1;
                let n = NLG;
                let f = FATIA_ATUAL;
                let r0 = regs[0];
                let lr = regs[14];
                let r8 = regs[8];
                let sp = regs[13];
                let r4 = regs[4];
                let r10 = regs[10];
                let r9 = regs[9];
                let r1 = regs[1];
                let r2 = regs[2];
                let r3 = regs[3];
                let mut slv = [0u8; 4];
                let slok = mem.read(r4.wrapping_add(0x20), 4).map(|s| slv.copy_from_slice(s)).is_ok();
                let mut sbv = [0u8; 16];
                let sbok = mem.read(r9, 16).map(|s| sbv.copy_from_slice(s)).is_ok();
                let mut fb = [0u8; 4];
                let fok = mem.read(lr.wrapping_add(0x20), 4).map(|s| fb.copy_from_slice(s)).is_ok();
                let mut ob = [0u8; 64];
                let ook = mem.read(lr, 64).map(|s| ob.copy_from_slice(s)).is_ok();
                let mut cb = [0u8; 16];
                let cok = mem.read(0xAC09_EA48, 16).map(|s| cb.copy_from_slice(s)).is_ok();
                // VMA coverage via mm map (sp-trick invalid in USR).
                let mm = mem.mm_atual();
                let mut vma_lr = String::from("n/a");
                let mut vma_fl = String::from("n/a");
                if let Some(&m) = mm_para_mm_sgl.borrow().get(&mm) {
                    for alvo in [lr, lr.wrapping_add(0x20)] {
                        let mut vma = mem.read_u32(m).unwrap_or(0);
                        let mut depth = 0u32;
                        let mut achou = false;
                        while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                            depth += 1;
                            let mut vb = [0u8; 32];
                            if mem.read(vma, 32).map(|s| vb.copy_from_slice(s)).is_err() {
                                break;
                            }
                            let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
                            let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
                            if ini <= alvo && alvo < fim {
                                let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
                                let s = format!("[{ini:#x},{fim:#x}) fl={fl:#x}");
                                if alvo == lr {
                                    vma_lr = s;
                                } else {
                                    vma_fl = s;
                                }
                                achou = true;
                                break;
                            }
                            vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
                        }
                        if !achou {
                            if alvo == lr {
                                vma_lr = String::from("sem-VMA");
                            } else {
                                vma_fl = String::from("sem-VMA");
                            }
                        }
                    }
                }
                // Caller stack (sp points to caller's frame; the saved
                // lr names who passed the wild head).
                let mut stk = [0u8; 64];
                let sok = mem.read(sp, 64).map(|s| stk.copy_from_slice(s)).is_ok();
                eprintln!("SGLFAULT#{n} f={f} mm={mm:#x} r0={r0:#x} r1={r1:#x} r2={r2:#x} r3={r3:#x} r4={r4:#x} r8={r8:#x} r9={r9:#x} r10={r10:#x} lr={lr:#x} sp={sp:#x} slok={slok} slval={slv:02x?} sbok={sbok} sbval={sbv:02x?} fok={fok} fb={fb:02x?} ook={ook} cok={cok} code={cb:02x?} sok={sok} stk={stk:02x?} vma_lr={vma_lr} vma_flt={vma_fl}");
            }
        }
    });
    // TEMP (mark-stack NULL hunt): dvmHeapScanMarkedObjects drains a
    // mark stack (cursor [r4+#0x88], top [r4+#0x8c]), calling the
    // marker per object. A NULL entry crashes the callee
    // (`ldr r3,[sb]` with sb=NULL). Trap the call site
    // (0xAD016050), log NULL pops with cursor/stack context +
    // nearby stack words to see if the NULL is isolated (pushed
    // null?) or the stack page is bad (zeros/stale serve).
    // Window-gated to the new crash, cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_6050, move |mem, regs| {
        static mut NQ: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if NQ < 4 && (407_000..416_000).contains(&f) && regs[0] == 0 {
                NQ += 1;
                let n = NQ;
                let mut sw = [0u8; 256];
                let sok = mem.read(regs[2].wrapping_sub(256), 256).map(|s| sw.copy_from_slice(s)).is_ok();
                eprintln!("MARKNULL#{n} f={f} obj={:#x} cursor={:#x} r4={:#x} top={:#x} sp={:#x} sok={sok} stack={sw:02x?}", regs[0], regs[2], regs[4], regs[6], regs[13]);
            }
        }
    });
    // TEMP (NULL-memcpy caller): libutils ResXMLTree::setTo gets
    // the entry args (r1=data, r2=len); the tombstone shows
    // (NULL, 0x5FC8). Gate on exactly that to name who passes a NULL
    // blob (table miss from zeroed range? app logic?). Cap 4.
    // Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xA9D2_1ED8, move |mem, regs| {
        static mut NN: u32 = 0;
        unsafe {
            if NN < 4 && regs[1] == 0 && regs[2] == 0x5FC8 {
                NN += 1;
                let n = NN;
                let mut sc = [0u8; 256];
                let sok = mem.read(regs[13], 256).map(|s| sc.copy_from_slice(s)).is_ok();
                // Code around the caller (lr-64) for offline file
                // matching: names the calling module without guessing
                // prelink bases.
                let base = regs[14].wrapping_sub(65);
                let mut cb = [0u8; 128];
                let cok = mem.read(base & !1, 128).map(|s| cb.copy_from_slice(s)).is_ok();
                let mut ob = [0u8; 128];
                let ook = mem.read(regs[0], 128).map(|s| ob.copy_from_slice(s)).is_ok();
                eprintln!("NULLBLOB#{n} f={} r0={:#x} r3={:#x} lr={:#x} sp={:#x} sok={sok} stack={sc:02x?} cok={cok} ccode={cb:02x?} ook={ook} obj={ob:02x?}", unsafe { FATIA_ATUAL }, regs[0], regs[3], regs[14], regs[13]);
            }
        }
    });
    // (CALLER return-site trap removed: the callee crashes before
    // returning, so a return trap can never fire on the crashing
    // path. Caller bytes now come from NULLBLOB's lr-relative dump.)
    // TEMP (GC mark callback identity): 0xAD013B58 does `blx sb`
    // with the table-mark loop as target for the crashing table.
    // Log sb (callback) + r0-r3 to name which mark function is chosen
    // for this table (class-mark vs string-mark). Same window, cap 8.
    // Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD01_3B58, move |mem, regs| {
        static mut Q: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if Q < 8 && (384_000..386_500).contains(&f) {
                Q += 1;
                let n = Q;
                let fp = regs[11];
                let cb = mem.read_u32(fp.wrapping_sub(0x40)).unwrap_or(0xDEAD);
                eprintln!("MARKCB#{n} f={f} sb={:#x} r0={:#x} r1={:#x} r2={:#x} r3={:#x} cbmem={cb:#x}", regs[9], regs[0], regs[1], regs[2], regs[3]);
            }
        }
    });
    // TEMP (linker mmap-return watch): the linker's mmap wrapper
    // exits at 0xB00033FA (`pop {r4,r5,pc}` — r0 already holds the
    // kernel's returned address). The reserve allocator (0xB724)
    // demands the EXACT hint address and unmaps+retries otherwise,
    // so a kernel that ignores hints fails every prelinked load.
    // Gate to the round-2 reserves (slices 334350-334600), cap 40,
    // log r0 + caller lr. Remove with OPENRET once honored-or-not
    // is decided.
    cpu.trap_pc_mem(0xB000_33FA, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if N < 40 && (334_350..334_600).contains(&f) {
                N += 1;
                let n = N;
                eprintln!("MMAPRET#{n} f={f} r0={:#x} lr={:#x}", regs[0], regs[14]);
            }
        }
    });
    // TEMP (linker read-return watch): the linker's read stub is
    // ARM at 0xB0001440 (`push; mov r7,#3; svc; pop` — same farm as
    // the open stub; callers reach it via thumb blx-imm). Entry
    // stashes fd+buf; exit (0xB000144C, pre-pop, r0 = kernel
    // return) logs fd, byte count, and the first 8 bytes actually
    // read — a short/garbage header read on the top lib's fd is the
    // prime suspect for the silent dlopen NULL (no reserve/mmap of
    // libmedia_jni ever appears after its deps map). Slice-gated to
    // the round-2 load (top open ≈ slice 334392, failure ≈ 335k,
    // tail to 336500 for the post-storm fd-0xd read).
    // Cap 200; remove with OPENRET once the stage is named.
    let read_fd = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let read_buf = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let read_fd2 = read_fd.clone();
    let read_buf2 = read_buf.clone();
    cpu.trap_pc_mem(0xB000_1440, move |_mem, regs| {
        read_fd.set(regs[0]);
        read_buf.set(regs[1]);
    });
    cpu.trap_pc_mem(0xB000_144C, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            let f = FATIA_ATUAL;
            if N < 200 && (334_300..420_000).contains(&f) {
                N += 1;
                let n = N;
                let mut hb = [0u8; 8];
                let ok = mem.read(read_buf2.get(), 8).map(|s| hb.copy_from_slice(s)).is_ok();
                eprintln!("READRET#{n} f={f} fd={:#x} r0={:#x} ok={ok} head={hb:02x?}", read_fd2.get(), regs[0]);
            }
        }
    });
    // TEMP (libmedia_jni init-ran probe): the lib loads at its
    // prelink base (0xAB300000) and its init_array[0] is a thumb
    // ctor that calls two ARM PLT entries (Mutex ctor at
    // 0xAB3024EC, __aeabi_atexit at 0xAB302714). If either fires,
    // the linker's init phase runs — and since nothing after inits
    // can fail cleanly, dlopen should then succeed. If neither
    // fires, the bail is in relocate/verify before inits. Cap 4
    // each; remove with OPENRET once the stage is named.
    for va in [0xAB30_24ECu32, 0xAB30_2714u32] {
        cpu.trap_pc_mem(va, move |_mem, regs| {
            static mut N: u32 = 0;
            unsafe {
                if N < 4 {
                    N += 1;
                    let n = N;
                    eprintln!("JNIINIT#{n} f={} pc={va:#x} r0={:#x} r1={:#x} lr={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[14]);
                }
            }
        });
    }
    cpu.trap_pc_mem(0xB000_A510, move |mem, regs| {
        open_ptr.set(regs[0]);
        let want = mem
            .read(regs[0], 32)
            .map(|s| s.windows(3).any(|w| w == b"Omx"))
            .unwrap_or(false);
        open_want.set(want);
    });
    cpu.trap_pc_mem(0xB000_A51C, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            // Log every full-path open (success or fail) in the
            // two load windows (round-1 mediaserver ≈ slice 285k,
            // round-2 zygote ≈ slice 334k): names each fd so the
            // post-storm fd-0xd read can be attributed, and shows
            // whether round 2 diverges in open behavior. Bare-name
            // probes still skip (expected ENOENT); Omx always logs.
            // Cap 80; remove with the other TEMP traps.
            let f = FATIA_ATUAL;
            let first = mem.read_u32(open_ptr2.get()).unwrap_or(0) & 0xFF;
            let full = first == b'/' as u32;
            let in_win = (284_900..285_900).contains(&f) || (334_300..420_000).contains(&f);
            if N < 80 && in_win && (full || open_want2.get()) {
                N += 1;
                let n = N;
                let fail = regs[0] >= 0xFFFF_F000;
                let mut nm = [0u8; 48];
                let ok = mem
                    .read(open_ptr2.get(), 48)
                    .map(|s| nm.copy_from_slice(s))
                    .is_ok();
                let z = nm.iter().position(|&b| b == 0).unwrap_or(nm.len());
                let path = String::from_utf8_lossy(&nm[..z]).into_owned();
                eprintln!("OPENRET#{n} f={f} r0={:#x} fail={fail} ok={ok} path={path:?} lr={:#x}", regs[0], regs[14]);
            }
            open_want2.set(false);
        }
    });
    // Which path reaches the fault: empty-list entry (0xAC042EF4,
    // r0 already NULL) or exhausted search (0xAC042E24, r0 walked
    // to NULL)? Cap 4 each.
    cpu.trap_pc_mem(0xAC04_2EF4, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                let n = N;
                eprintln!("SGLEMPTY#{n} f={} r0={:#x} r7={:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[7], regs[14], regs[13]);
            }
        }
    });
    cpu.trap_pc_mem(0xAC04_2E24, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                let n = N;
                eprintln!("SGLEXH#{n} f={} r0={:#x} r7={:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[7], regs[14], regs[13]);
            }
        }
    });
    // TEMP (zygote libsgl caller): who calls into the faulting
    // function (entry 0xAC042CB8)? Log caller + args; cap 4.
    cpu.trap_pc_mem(0xAC04_2CB8, move |_mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            if N < 4 {
                N += 1;
                let n = N;
                eprintln!("SGLCALL#{n} f={} r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[14], regs[13]);
            }
        }
    });
    // TEMP (zygote libsgl search walk): log each visited node
    // (base in r0, key at [r0+4]) so a miss can be told apart from
    // stale zeros: genuine miss shows varied keys, stale shows zeros.
    // Cap 20 lines; remove with the other SGL traps.
    cpu.trap_pc_mem(0xAC04_2DFC, move |mem, regs| {
        static mut N: u32 = 0;
        unsafe {
            // Crash window only (faults near slice 332k; earlier
            // searches are warmup and would burn the cap).
            if FATIA_ATUAL < 300000 {
                return;
            }
            if N < 60 {
                N += 1;
                let n = N;
                let a = regs[0];
                // Full slots + the compared slot (r3 = r0+r1, loaded word
                // is [r3+4]): proves whether the key is really absent vs
                // skipped by the stride.
                let mut hb = [0u8; 20];
                let ok = mem.read(a.wrapping_add(4), 20).map(|s| hb.copy_from_slice(s)).is_ok();
                let mut kv = [0u8; 4];
                let ok2 = mem.read(a.wrapping_add(regs[1]).wrapping_add(4), 4).map(|s| kv.copy_from_slice(s)).is_ok();
                eprintln!("SGLWALK#{n} f={} node={a:#x} i={:#x} ok={ok} slots={hb:02x?} compared_ok={ok2} compared={kv:02x?}", unsafe { FATIA_ATUAL }, regs[1]);
            }
        }
    });
    // TEMP (libsgl init check): did the linker's DT_INIT_ARRAY run?
    // If none of these fire before the first SGLFAULT, the table
    // was never populated because init was skipped. Cap 22.
    for (idx, va) in [0xAC02CA5Cu32, 0xAC032574u32, 0xAC03A10Cu32, 0xAC03A6F8u32, 0xAC042710u32, 0xAC043C64u32, 0xAC0451ECu32, 0xAC0462CCu32, 0xAC0489A0u32, 0xAC06A894u32, 0xAC076178u32].iter().enumerate() {
        let va = *va;
        let idx = idx;
        cpu.trap_pc_mem(va, move |_mem, regs| {
            static mut N: u32 = 0;
            unsafe {
                if N < 22 {
                    N += 1;
                    let n = N;
                    eprintln!("SGLINIT#{n} f={} idx={idx} va={va:#x} lr={:#x} sp={:#x}", unsafe { FATIA_ATUAL }, regs[14], regs[13]);
                }
            }
        });
    }
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
    // brk page by page; repeats still stop the run. Keyed by
    // (mm, exec generation, base): another mm re-faulting the same
    // VA is a legitimate first touch, and post-exec re-faults are
    // a new image — only the same (mm, gen, page) repeating means
    // the mapping did not stick.
    let mut mapeadas_usr: Vec<(u32, u32, u32)> = Vec::new();
    // User pages already handed to the guest's abort handler: a
    // same-(mm, gen, page, pc) fault AFTER a delivery means the guest
    // retried without a visible fix. Allow a handful per key —
    // recurring legitimate faults (kernel uaccess fixup returns
    // -EFAULT and the caller moves on; a later retry or a different
    // copy phase refaults) must proceed; a tight livelock burns the
    // budget fast and still stops. (Page-only keying stopped
    // linux328's 0xBEC0A000 kernel-copy fault on a legitimate second
    // touch.)
    let mut abortadas: Vec<((u32, u32, u32, u32), u32)> = Vec::new();
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
    // TEMP (snapshots): retomada a partir de arquivo. Roda DEPOIS de
    // todo o setup (traps rearmados, tap/nand criados) e ANTES do
    // laço: sobrescreve cpu, mapa, harness e NAND com a Foto. A
    // numeração de fatias continua da salva (gates de trap batem
    // igual). Remove com CRASHOBJ se os snapshots não vingarem.
    let mut fatia_ini = 0u32;
    if let Some(caminho) = SNAPSHOT_LOAD_PATH.get() {
        match crate::msm7201a_snapshot::carrega(caminho) {
            Ok(foto) => {
                eprintln!(
                    "SNAPSHOT_CARREGA {} fatia={} pc={:#x} regioes={} nand={}B",
                    caminho,
                    foto.fatia,
                    foto.pc,
                    foto.regioes.len(),
                    foto.nand.len()
                );
                pc = foto.pc;
                fatia_ini = foto.fatia;
                cpu.aplica_nucleo(&foto.nucleo);
                {
                    let mut mem = cpu.memoria_mut();
                    mem.limpa();
                    for r in &foto.regioes {
                        mem.restaura_regiao(r);
                    }
                    mem.trocar_mm(foto.mm_atual);
                    mem.fixa_gens(foto.gens.clone());
                    mem.arma_vigia(foto.vigia);
                    // TEMP (death-anchored epochs): pre-load deaths are
                    // invisible to the FATAL# trap (it only sees in-run
                    // do_exit). The parent zygote (mm 0x16238000) dies
                    // deterministically at f=583005 every boot, before
                    // any snapshot used here — pre-seed it so the
                    // recycle bump fires for init's fork child.
                    // Remove with CRASHOBJ.
                    mem.registra_mm_morto(0x1623_8000);
                }
                unsafe {
                    TTBR_CACHE = foto.ttbr_cache;
                    TTBR_TASK = foto.ttbr_task;
                    crate::cpu::interpretador::MDDI_IRQ_PENDENTE = foto.mddi_pendente;
                    AUDIT_LATCH = foto.audit_latch;
                    FB_LINUX_MAPA = foto.fb_linux_mapa;
                    SNAP_SPL_FORA = foto.spl_fora;
                    CONTAGEM_GPT = foto.contagem_gpt;
                    CONTAGEM_DGT = foto.contagem_dgt;
                    SNAP_ULTIMA = foto.ultima;
                    SNAP_ULTIMO_ALVO = foto.ultimo_alvo;
                    SNAP_PLANTA_N = foto.planta_n;
                }
                // TEMP (snapshots): override da vigia pós-carga
                // (`--snapshot-vigia ADDR [LEN]`): arma a vigia num
                // endereço novo sem precisar re-salvar — iteração
                // rápida sobre escritas. Remove com CRASHOBJ.
                if let Some(spec) = SNAPSHOT_VIGIA.get() {
                    let mut it = spec.split(',');
                    if let (Some(a), len) = (
                        it.next().and_then(|x| u32::from_str_radix(x.trim_start_matches("0x"), 16).ok()),
                        it.next().and_then(|x| x.parse::<u32>().ok()).unwrap_or(4),
                    ) {
                        cpu.arma_vigia(Some((a, len)));
                        eprintln!("SNAPSHOT_VIGIA {a:#x}+{len:#x}");
                    }
                }
                mapeadas = foto.mapeadas.clone();
                mapeadas_kern = foto.mapeadas_kern.clone();
                mapeadas_usr = foto.mapeadas_usr.clone();
                // TEMP (file-backed serve): mm -> mm_struct seeding
                // survives resume (re-seeding live needs a fresh
                // walk-miss fault, which may come too late).
                mm_para_mm.borrow_mut().clear();
                mm_para_mm
                    .borrow_mut()
                    .extend(foto.mm_para_mm.iter().copied());
                abortadas = foto.abortadas.clone();
                tap_marca = foto.tap_marca as usize;
                tap_marca_c0 = foto.tap_marca_c0 as usize;
                saida_marca = foto.saida_marca as usize;
                tap.borrow_mut().aplica_canais(foto.tap_canais.clone());
                {
                    let mut img = nand.borrow_mut();
                    if img.len() != foto.nand.len() {
                        panic!(
                            "snapshot NAND com {} bytes, imagem atual com {}",
                            foto.nand.len(),
                            img.len()
                        );
                    }
                    img.copy_from_slice(&foto.nand);
                }
            }
            Err(e) => panic!("carregar snapshot {caminho}: {e}"),
        }
    }
    for fatia in fatia_ini..max_fatias {
        unsafe { FATIA_ATUAL = fatia; }
        // TEMP (snapshots): fotografa o mundo no topo da fatia-alvo
        // e sai (a retomada continua daqui). Remove com CRASHOBJ se
        // os snapshots não vingarem.
        if fatia == unsafe { SNAPSHOT_SAVE_FATIA } {
            let caminho = SNAPSHOT_SAVE_PATH
                .get()
                .cloned()
                .unwrap_or_else(|| "/tmp/opencode/snap.bin".to_string());
            let mut regs_foto = {
                let mem = cpu.memoria();
                mem.foto_regioes()
            };
            // TEMP (snapshot poison purge): drop all-zero file-backed user
            // pages that are read-only OR executable — they can only be
            // unseeded serves (zeros from empty/stale alias, never
            // re-faulted after silent VMA reuse). Resume re-serves them
            // via the file branch with NAND bytes. Executable covers
            // text undergoing relocation (writable for fixups, e.g.
            // webcore 0xaa008000 fl=0x8100077): pristine zeros must be
            // file bytes, not alias; guest relocations redo after
            // re-serve (relocations run on every load). Pure writable
            // data keeps zeros (guest memset must survive). Anonymous
            // pages stay untouched. Remove with CRASHOBJ.
            {
                let mapa = mm_para_mm.borrow();
                let mut npurga = 0u32;
                regs_foto.retain(|r| {
                    let mm = match r.dono_mm {
                        Some(m) => m,
                        None => return true,
                    };
                    if !r.dados.iter().all(|&b| b == 0) {
                        return true;
                    }
                    match caminho_arquivo_para_falta(&mut cpu, &mapa, r.base) {
                        Some((caminho, _, fl)) if fl & 0x2 == 0 || fl & 0x4 != 0 => {
                            npurga += 1;
                            static mut NPV: u32 = 0;
                            unsafe {
                                if NPV < 20 {
                                    NPV += 1;
                                    eprintln!("VAPURGE va={:#x} {caminho:?}", r.base);
                                }
                            }
                            false
                        }
                        _ => true,
                    }
                });
                if npurga > 0 {
                    eprintln!(
                        "VAPURGED f={} paginas={npurga}",
                        unsafe { FATIA_ATUAL }
                    );
                }
            }
            let foto = crate::msm7201a_snapshot::Foto {
                fatia,
                pc,
                nucleo: cpu.foto_nucleo(),
                mm_atual: cpu.mm_atual(),
                gens: cpu.memoria().foto_gens(),
                vigia: cpu.memoria().vigia,
                regioes: regs_foto,
                ttbr_cache: unsafe { TTBR_CACHE },
                ttbr_task: unsafe { TTBR_TASK },
                mddi_pendente: unsafe {
                    crate::cpu::interpretador::MDDI_IRQ_PENDENTE
                },
                audit_latch: unsafe { AUDIT_LATCH },
                fb_linux_mapa: unsafe { FB_LINUX_MAPA },
                mapeadas: mapeadas.clone(),
                mapeadas_kern: mapeadas_kern.clone(),
                mapeadas_usr: mapeadas_usr.clone(),
                mm_para_mm: mm_para_mm.borrow().iter().map(|(&a, &b)| (a, b)).collect(),
                abortadas: abortadas.clone(),
                tap_marca: tap_marca as u64,
                tap_marca_c0: tap_marca_c0 as u64,
                saida_marca: saida_marca as u64,
                tap_canais: tap.borrow().foto_canais(),
                nand: nand.borrow().clone(),
                spl_fora: unsafe { SNAP_SPL_FORA },
                contagem_gpt: unsafe { CONTAGEM_GPT },
                contagem_dgt: unsafe { CONTAGEM_DGT },
                ultima: unsafe { SNAP_ULTIMA },
                ultimo_alvo: unsafe { SNAP_ULTIMO_ALVO },
                planta_n: unsafe { SNAP_PLANTA_N },
            };
            match crate::msm7201a_snapshot::salva(&caminho, &foto) {
                Ok(()) => eprintln!("SNAPSHOT_SALVO {caminho} fatia={fatia}"),
                Err(e) => eprintln!("SNAPSHOT_FALHA {caminho}: {e}"),
            }
            break;
        }
        // TEMP (slice-cost hunt): the user-phase pace collapsed to
        // ~180 slices/s (~5ms host per slice vs ~300us on the old
        // tree). Split blame run-vs-host per slow slice; cap 20.
        // Remove once the cost is named.
        let t_fora = std::time::Instant::now();
        let saida_fatia = cpu.run(pc, instrs_por_fatia).unwrap();
        let t_run = t_fora.elapsed();
        // TEMP (custo por braço): separa o tempo de host do braço
        // Budget (devolve) e do braço de falta (demanda/aborto).
        // Remove com a caçada.
        let mut foi_orcamento = false;
        match saida_fatia {
            StopReason::Budget => {
                foi_orcamento = true;
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
                                // SUSPENDED 2026-10-24 (linux376): the
                                // posix-timers BUG at 18.2s fires in a
                                // nested tick with I=0 — prime suspect
                                // is THIS unmask landing mid-tick-chain
                                // at a slice boundary (NMASK tripped by
                                // NAND-window masking; NKU cap hides
                                // later firings). Ticks are already
                                // forced periodic (ATAG nohz=off +
                                // MATCH plant + handler pin); test
                                // whether the unmask is vestigial.
                                if false && NMASK >= 30 {
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
                            && (traduz(addr & !0xFFF).is_none()
                                // The SPL section-table alias for VA
                                // 0x80000000 x64 went stale at the kernel
                                // handoff (proven: a user mapping there
                                // reads zeros via the alias while the
                                // guest tables map file content — the
                                // linker tore down libOmxCore for it).
                                // In user mode the guest tables are
                                // authoritative, so route those faults
                                // through the PTWALK serve below. Kernel
                                // mode keeps the old path (SPL boot
                                // needs the alias).
                                || (cpu.em_usuario()
                                    && (0x8000_0000..0x8400_0000)
                                        .contains(&(addr & !0xFFF))))
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
                        // (Flag hoisted to SNAP_SPL_FORA: the Foto
                        // carries it, else a resume re-carves live low
                        // mappings and stops on the repeat fault.)
                        unsafe {
                            if !SNAP_SPL_FORA {
                                SNAP_SPL_FORA = true;
                                let _ = cpu.desmapeia_intervalo(0x0, 0x8_0000);
                                eprintln!("SPL-UNMAP f={} (low image carved for userspace)", unsafe { FATIA_ATUAL });
                            }
                        }
                        if mapeadas_usr.contains(&(cpu.mm_atual(), cpu.geracao(), base)) {
                            // TEMP (repeat-guard forensics): log the
                            // live-region state that decides
                            // drop-induced re-serve vs genuine repeat.
                            // Remove with CRASHOBJ.
                            static mut NGR: u32 = 0;
                            unsafe {
                                if NGR < 12 {
                                    NGR += 1;
                                    eprintln!("GUARD f={} mm={:#x} ger={} base={base:#x} tem_regiao={}", unsafe { FATIA_ATUAL }, cpu.mm_atual(), cpu.geracao(), cpu.tem_mapeada(cpu.mm_atual(), cpu.geracao(), base));
                                }
                            }
                            // TEMP (drop-aware repeat guard): a VMA
                            // invalidation drop (munmap/MAP_FIXED)
                            // legitimately re-faults a served page —
                            // with no live region the fault is fresh,
                            // not a repeat. Only a fault on a LIVE
                            // region that still fails stops the run.
                            // Remove with CRASHOBJ.
                            if cpu.tem_mapeada(cpu.mm_atual(), cpu.geracao(), base) {
                                eprintln!("GUARD-STOP f={} mm={:#x} ger={} base={base:#x} (regiao viva, repeat real)", unsafe { FATIA_ATUAL }, cpu.mm_atual(), cpu.geracao());
                                eprintln!("GUARD-STOP outra={outra:?}");
                                parada = outra;
                                break;
                            }
                            mapeadas_usr.retain(|k| {
                                *k != (cpu.mm_atual(), cpu.geracao(), base)
                            });
                        }
                        // TEMP (UDECIDE): user-arm MISS decisions only
                        // (HITs already log via UFAULT). Cap 200.
                        // Remove after the bec0a000 stall is named.
                        static mut NUD: u32 = 0;
                        match caminha_pt_usuario(&mut cpu, base) {
                            Some((pa, bruto, l2base)) => {
                                let mm = cpu.mm_atual();
                                let ger = cpu.geracao();
                                // Adopt: own region already mirrors this
                                // exact physical page (argv still live
                                // across the execve bump, COW-shared page
                                // untouched)? Keep the bytes, just refresh
                                // the generation — no carve, no re-seed.
                                let adotado = match cpu.regiao_propria(base) {
                                    Some((Some(pa_semente), _)) if pa_semente == pa => {
                                        cpu.adotar_geracao(base);
                                        true
                                    }
                                    _ => false,
                                };
                                let mut fonte = "adotado";
                                if !adotado {
                                    // Preserve live overlapping bytes first
                                    // (mid-page sobra pattern): a munmap
                                    // with exact byte length (e.g. font
                                    // FileMap teardown 0x41009000+0x29fec
                                    // = 0x41032fec) leaves a tail sobra
                                    // [0x41032fec,0x41033000) holding live
                                    // guest writes (proven: mark-stack push
                                    // 0x4008b110 wiped by full-page re-serve
                                    // -> NULL pop -> zygote SIGSEGV). Snapshot
                                    // readable 4B words before carve (same
                                    // pattern as SLACKFILL but word-granular:
                                    // 64B chunks straddle mid-page sobra
                                    // starts and miss them), overlay after
                                    // seeding so live bytes survive.
                                    let mut preservado: Vec<(u32, [u8; 4])> = Vec::new();
                                    {
                                        let mut offp = 0u32;
                                        while offp < 0x1000 {
                                            let mut hb = [0u8; 4];
                                            if cpu.read_mem(base.wrapping_add(offp), &mut hb).is_ok() {
                                                preservado.push((offp, hb));
                                            }
                                            offp += 4;
                                        }
                                    }
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
                                    // User-owned (per-mm): same VA in another
                                    // address space gets its own region
                                    // instead of aliasing this mapping.
                                    if cpu.map_usuario_zeroed("usuario_ptw", base, 0x1000).is_err() {
                                        parada = outra;
                                        break;
                                    }
                                    // Seed: a sibling mirroring the SAME physical
                                    // page first (fork-COW content the pa bank
                                    // never held; same pa = same bytes by
                                    // construction), then the lowmem alias
                                    // (page-cache ground truth for file text),
                                    // else zeros (fresh anon). The sibling
                                    // MUST be pa-gated: all ET_EXEC binaries
                                    // share 0x8000, and an ungated copy once
                                    // planted installd's text in a foreign
                                    // address space (proven by URES heads).
                                    // Anon gate: fresh anon heap (brk/mmap)
                                    // must NOT seed alias (stale PA bank
                                    // garbage -> heap pointers like 0xADA15FFF
                                    // -> wild libsgl head). File/unknown keep
                                    // alias (early text before MMSEED2).
                                    let anon_opt = vma_e_anonima(&mut cpu, &mm_para_mm.borrow(), base);
                                    let anon = anon_opt == Some(true);
                                    // TEMP (anon-gate audit): log the heap
                                    // pages' VMA verdicts (the 0x388f3071
                                    // wild word was alias-seeded at f=295251
                                    // into 0x41a2e000; need to know what the
                                    // walk says TODAY for these VAs).
                                    // Cap 4, filtered VAs. Remove with CRASHOBJ.
                                    if base == 0x41a2e000 || base == 0x410a4000 || base == 0x4104a000 || base == 0x1f000 || base == 0x8000 || base == 0x41aa8000 || base == 0x41aa7000 {
                                        static mut NAG: u32 = 0;
                                        unsafe {
                                            if NAG < 8 {
                                                NAG += 1;
                                                let f = FATIA_ATUAL;
                                                let caminho = caminho_arquivo_para_falta(
                                                    &mut cpu,
                                                    &mm_para_mm.borrow(),
                                                    base,
                                                );
                                                let grav = vma_e_gravavel(&mut cpu, &mm_para_mm.borrow(), base);
                                                // Read the file bytes too: is
                                                // the resident word file truth
                                                // (guest must relocate) or
                                                // stale alias (our bug)?
                                                let mut fbytes = String::from("n/a");
                                                if let Some((ref cam, desloc, _)) = caminho {
                                                    let mut idxg = indice_yaffs.borrow_mut();
                                                    if idxg.is_none() {
                                                        *idxg = Some(
                                                            crate::msm7201a_yaffs::IndiceYaffs::constroi(
                                                                &nand.borrow(),
                                                            ),
                                                        );
                                                    }
                                                    let mut pgf = vec![0u8; 0x1000];
                                                    if idxg.as_ref().unwrap().le(
                                                        &nand.borrow(),
                                                        cam,
                                                        desloc,
                                                        &mut pgf,
                                                    ) {
                                                        fbytes = format!("{:02x?}", &pgf[0xaf0..0xb00]);
                                                    } else {
                                                        fbytes = String::from("le=false");
                                                    }
                                                }
                                                eprintln!("ANONGATE f={f} mm={:#x} va={base:#x} vma={anon_opt:?} gravavel={grav:?} caminho={caminho:?} file={fbytes}", cpu.mm_atual());
                                            }
                                        }
                                    }
                                    let mut pg = vec![0u8; 0x1000];
                                    let mut ok = false;
                                    // TEMP (GOT-clobber hunt): dump regions
                                    // at serve time to name the irmao miss
                                    // (zygote's region exists with same pa
                                    // at NULL40 but fonte still vmafile).
                                    // Remove with CRASHOBJ.
                                    if base == 0xad07e000 {
                                        eprintln!("GOTSERVE f={} mm={:#x} pa={pa:#x} regs={}", unsafe { FATIA_ATUAL }, cpu.mm_atual(), cpu.debug_regioes(base));
                                    }
                                    if let Some(buf) = cpu.irmao_mesma_va(base, pa) {
                                        pg.copy_from_slice(&buf);
                                        ok = true;
                                        fonte = "irmao_pa";
                                    } else if !anon
                                        && !(0x41E6_6000..0x41EE_6000).contains(&base)
                                        && std::env::var("DREMSNAP_SEM_GATE_ZEROS").is_err()
                                        && le_ram_fisica(&mut cpu, pa, &mut pg)
                                    {
                                        // (PROVEN live 0x41EA6000: its first
                                        // touch seeded stale pa bytes
                                        // [00,01,00,00,...] = bit 23 set,
                                        // and the GC mark walk selected a
                                        // bins link as an object -> zygote
                                        // SIGSEGV. Anonymous bitmap memory
                                        // must demand-zero like the kernel
                                        // does; the alias seed only holds
                                        // for file text. TEMP dial: if the
                                        // crash moves past preload, replace
                                        // with tracked VMA classes.)
                                        ok = true;
                                        fonte = "alias";
                                    } else {
                                        fonte = "zeros";
                                    }
                                    // TEMP (file-backed serve): VMA says
                                    // file but the alias seed came up
                                    // empty/zeros (page cache never
                                    // populated — our swallowed faults
                                    // bypass the kernel's own fill).
                                    // Resolve the path via
                                    // task->mm->VMA->file->dentry and
                                    // serve NAND bytes. Nonzero alias
                                    // keeps today's behavior (text
                                    // segments provably work through
                                    // it). Remove with CRASHOBJ.
                                    // File branch: VMA says file but alias came up
                                    // empty/zeros (page cache never populated —
                                    // our swallowed faults bypass the kernel's
                                    // own fill), OR alias came up stale non-zero
                                    // shadowing the file (proven: webcore text
                                    // page 0xaa008000 served stale alias with
                                    // zeros at 0x85c0 ["chbk_fail" in file] ->
                                    // wild link_map shift -> linker SIGSEGV).
                                    // Ground rule (kernel semantics): a
                                    // READ-ONLY file page is immutable — the
                                    // file always wins (text, rodata, odex;
                                    // the linker never relocates RO). A
                                    // WRITABLE file page may hold guest
                                    // relocations: live sibling bytes win,
                                    // the file is the fresh-page fallback,
                                    // and guest writes (preserved) overlay
                                    // afterwards. Proven both ways: webcore
                                    // text needs file-over-alias; GOT[prctl]
                                    // 0xad07ee88 needs live-relocated over
                                    // pristine file (0x11008 -> PLT jumps to
                                    // heap trash, NULL+64 at 0x11020).
                                    // Remove with CRASHOBJ.
                                    let eh_file = vma_e_anonima(&mut cpu, &mm_para_mm.borrow(), base) == Some(false);
                                    let gravavel = vma_e_gravavel(&mut cpu, &mm_para_mm.borrow(), base);
                                    // RO file: force the file (ground truth;
                                    // sibling/alias can only be stale here).
                                    // RW file: sibling wins when hit (same-pa
                                    // live copy, e.g. relocated GOT); the
                                    // file stays the fallback via !ok /
                                    // all-zeros. Unknown flags: force the
                                    // file (today's behavior).
                                    let forca_arquivo = eh_file && gravavel != Some(true);
                                    // Enter the file branch whenever the seed
                                    // isn't a trusted live sibling: file is
                                    // ground truth for unmapped/unrelocated
                                    // pages, and ashmem-like (le=false) pages
                                    // need zeros instead of stale alias.
                                    if !ok || pg.iter().all(|&b| b == 0) || forca_arquivo || (eh_file && fonte == "alias") {
                                        let eh_webcore = (0xaa000000..0xaa330000).contains(&base);
                                        if let Some((caminho, desloc, _)) =
                                            caminho_arquivo_para_falta(
                                                &mut cpu,
                                                &mm_para_mm.borrow(),
                                                base,
                                            )
                                        {
                                            let mut idxg = indice_yaffs.borrow_mut();
                                            if idxg.is_none() {
                                                *idxg = Some(
                                                    crate::msm7201a_yaffs::IndiceYaffs::constroi(
                                                        &nand.borrow(),
                                                    ),
                                                );
                                                eprintln!("YAFFSIDX f={} arquivos={}", unsafe { FATIA_ATUAL }, idxg.as_ref().unwrap().arquivos());
                                            }
                                            let mut pgf = vec![0u8; 0x1000];
                                            if idxg.as_ref().unwrap().le(
                                                &nand.borrow(),
                                                &caminho,
                                                desloc,
                                                &mut pgf,
                                            ) {
                                                pg.copy_from_slice(&pgf);
                                                ok = true;
                                                fonte = "vmafile";
                                                static mut NVF: u32 = 0;
                                                unsafe {
                                                    if NVF < 100 {
                                                        NVF += 1;
                                                        eprintln!("VMAFILE f={} va={base:#x} {caminho:?}+{desloc:#x}", unsafe { FATIA_ATUAL });
                                                    }
                                                }
                                            } else {
                                                // Not host-backed (ashmem,
                                                // anon inode, missing file):
                                                // the kernel zero-fills such
                                                // pages, so zeros beat stale
                                                // alias — but never clobber a
                                                // trusted live sibling.
                                                if eh_file && fonte == "alias" {
                                                    pg.fill(0);
                                                    fonte = "zeros";
                                                }
                                                if eh_webcore {
                                                    eprintln!("WEBCOREFAIL f={} va={base:#x} caminho={caminho:?} desloc={desloc:#x} le=false", unsafe { FATIA_ATUAL });
                                                }
                                            }
                                        } else if eh_webcore {
                                            eprintln!("WEBCOREFAIL f={} va={base:#x} caminho=None", unsafe { FATIA_ATUAL });
                                        }
                                    }
                                    if ok {
                                        // Overlay preserved live words (see
                                        // above): a guest-written non-zero word
                                        // beats alias/sibling/zero seeds (fresh
                                        // anon page wiping a mid-page sobra
                                        // tail, or stale alias over live heap).
                                        // Proven live twice: mark-stack push
                                        // 0x4008b110 (NULL pop -> zygote SIGSEGV
                                        // without it) and heap tails. The
                                        // system_server NULL+64 persists with
                                        // AND without this overlay, so it is
                                        // NOT the cause there — keep enabled.
                                        // Skip only for a read-only file page
                                        // served from the file: its text is
                                        // never guest-written, so preserved
                                        // words can only be stale (proven:
                                        // webcore 0xaa008000). Writable file
                                        // pages keep the overlay (linker
                                        // relocations win over pristine).
                                        let eh_arquivo_ro = fonte == "vmafile" && gravavel != Some(true);
                                        if !eh_arquivo_ro {
                                            for (offp, hb) in preservado.iter() {
                                                let o = *offp as usize;
                                                let velho = u32::from_le_bytes(*hb);
                                                if velho != 0 {
                                                    pg[o..o + 4].copy_from_slice(hb);
                                                }
                                            }
                                        }
                                        let _ = cpu.write_mem(base, &pg);
                                    }
                                    cpu.anotar_semente(base, pa);
                                }
                                mapeadas_usr.push((mm, ger, base));
                                // TEMP (framebuffer run hunt): the fb smem
                                // is 75+ CONTIGUOUS pages (320x480x2,
                                // single-buffered) faulted in one burst,
                                // with contiguous PAs (bootmem, unlike
                                // scattered page-cache text). Track
                                // per-mm (va,pa) runs here and shout when
                                // one crosses 75 pages — that (mm, base)
                                // is the mapping the host presenter must
                                // snapshot. Table of 16 mms; report each
                                // mm once. Remove once the presenter
                                // tracks the fb mmap itself.
                                static mut NFBM: u32 = 0;
                                static mut FBMAP: [(u32, u32, u32, u32, u32); 16] =
                                    [(0, 0, 0, 0, 0); 16];
                                unsafe {
                                    if unsafe { FATIA_ATUAL } >= 150_000 {
                                        let mut idx: Option<usize> = None;
                                        let mut free: Option<usize> = None;
                                        let mut i = 0;
                                        while i < 16 {
                                            let m0 = FBMAP[i].0;
                                            if m0 == 0 && free.is_none() {
                                                free = Some(i);
                                            }
                                            if m0 == mm {
                                                idx = Some(i);
                                                break;
                                            }
                                            i += 1;
                                        }
                                        if let Some(j) = idx {
                                            let (m0, va1, pa1, va0, n) = FBMAP[j];
                                            // Contiguous VA run, PA adjacent
                                            // either way: the 0x4000x linker
                                            // burst proved bootmem hands PFNs
                                            // out descending, so a real fb
                                            // mmap can descend too.
                                            let pa_adj = pa == pa1.wrapping_add(0x1000)
                                                || pa1 == pa.wrapping_add(0x1000);
                                            if base == va1.wrapping_add(0x1000) && pa_adj
                                            {
                                                FBMAP[j] = (m0, base, pa, va0, n + 1);
                                                if n + 1 == 75 && NFBM < 5 {
                                                    NFBM += 1;
                                                    eprintln!("FBMAP f={} mm={mm:#x} va0={va0:#x} vaN={base:#x} paN={pa:#x} len={} pages", unsafe { FATIA_ATUAL }, n + 1);
                                                    unsafe { FB_LINUX_MAPA = (mm, va0); }
                                                }
                                            } else {
                                                FBMAP[j] = (mm, base, pa, base, 1);
                                            }
                                        } else if let Some(j) = free {
                                            FBMAP[j] = (mm, base, pa, base, 1);
                                        }
                                    }
                                }
                                // TEMP (exec-window resolution audit): log
                                // every user page resolution path in the
                                // exec window (adopt vs sibling vs alias
                                // vs zeros), capped. This names the source
                                // of each page the exec path actually gets.
                                // Remove once execve returns are named.
                                static mut NRES: u32 = 0;
                                // TEMP (late-fault attribution): compact
                                // uncapped resolution log (mm/va/pa/adotado/
                                // fonte only — no heads) so a far-future
                                // stop (e.g. the init NULL+0x8A) can name
                                // its page's provenance. Remove with NRES.
                                unsafe {
                                    eprintln!("URES2 f={} mm={mm:#x} va={base:#x} pa={pa:#x} adotado={adotado} fonte={fonte}", unsafe { FATIA_ATUAL });
                                }
                                unsafe {
                                    if NRES < 300 && unsafe { FATIA_ATUAL } >= 150_000 {
                                        NRES += 1;
                                        let n = NRES;
                                        let mut hb = [0u8; 8];
                                        let head = if cpu.read_mem(base, &mut hb).is_ok() { hb.to_vec() } else { vec![] };
                                        eprintln!("URES#{n} f={} mm={mm:#x} va={base:#x} pa={pa:#x} adotado={adotado} fonte={fonte} head={head:02x?}", unsafe { FATIA_ATUAL });
                                    }
                                }
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
                                // TEMP (LineNum wild-read tolerance): dvmLineNumFromPC
                                // reads dexPC-as-method from a stale walker node
                                // ([r2+0x24], r2=0x388f3071 unmapped). Map zeros
                                // and retry instead of delivering SIGSEGV, so the
                                // trace completes with garbage and system_server
                                // boot can proceed past Audio init; the real Audio
                                // failure (if fatal) surfaces downstream. PC-gated
                                // to the LineNum ldr only, cap 4. Remove with
                                // CRASHOBJ (real fix: stale walker chain).
                                let mut tolerado = false;
                                if pc_falta == 0xAD05_19E4 {
                                    static mut NWT: u32 = 0;
                                    unsafe {
                                        if NWT < 4 {
                                            NWT += 1;
                                            let n = NWT;
                                            let f = FATIA_ATUAL;
                                            eprintln!("WILDTOL#{n} f={f} va={base:#x}");
                                            if cpu.map_usuario_zeroed("tolerante_silvestre", base, 0x1000).is_ok() {
                                                mapeadas_usr.push((cpu.mm_atual(), cpu.geracao(), base));
                                                pc = pc_falta;
                                                tolerado = true;
                                            }
                                        }
                                    }
                                }
                                if !tolerado {
                                // TEMP (UDECIDE miss side): log the abort
                                // decision inputs — abortadas state, mode,
                                // vector shape. Cap shared 40 above.
                                unsafe {
                                    if NUD < 200 {
                                        NUD += 1;
                                        let (_, cj, _, _) = cpu.estado_completo();
                                        let vet = if cpu.le_cp15(0x80).unwrap_or(0) & (1 << 13) != 0 { 0xFFFF_0000 } else { 0x0 } | if addr == pc_falta { 0x0C } else { 0x10 };
                                        let w = cpu.read_u32(vet).unwrap_or(0xDEAD);
                                        let ja: u32 = abortadas.iter().find(|(k, _)| *k == (cpu.mm_atual(), cpu.geracao(), base, pc_falta)).map_or(0, |(_, n)| *n);
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
                                let chave_ab = (cpu.mm_atual(), cpu.geracao(), base, pc_falta);
                                let vezes = abortadas.iter().find(|(k, _)| *k == chave_ab).map_or(0, |(_, n)| *n);
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
                                if let Some(slot) = abortadas.iter_mut().find(|(k, _)| *k == chave_ab) {
                                    slot.1 += 1;
                                } else {
                                    abortadas.push((chave_ab, 1));
                                }
                                pc = cpu.read_reg(crate::cpu::Reg::Pc) & !1;
                                }
                                }
                            }
                        }
                    StopReason::MemoryFault { addr, pc: pc_falta }
                        if cpu.em_usuario()
                            && pc_falta == 0xAD00_E3DC
                            && cpu.read_u32(pc_falta & !3).is_ok() =>
                    {
                        // TEMP (mterp wild-object tolerance): OP_IGET_OBJECT
                        // at 0xad00e3dc `ldr r3,[r0,#8]` reads a wild object
                        // out of frame locals (proven: r0=0xe4280000 from
                        // slot [r5+r1*4]=0x4104af38; the value came from an
                        // odex-data "method" 0x41aa8ba0+0x10 — stale
                        // Method*/dexPC confusion in Dalvik frames, same
                        // disease as the walker crash fixed by WALKERFIX).
                        // Zero-map the page and retry (null object flows
                        // into the guest NPE path) instead of stopping the
                        // run; a real failure surfaces downstream. USR-only,
                        // pc-gated, cap 8. Remove with CRASHOBJ (real fix:
                        // stale fp/chain at the invoke).
                        let base = addr & !0xFFF;
                        let mut tolerado = false;
                        static mut NET: u32 = 0;
                        unsafe {
                            if NET < 8 {
                                NET += 1;
                                let n = NET;
                                let f = FATIA_ATUAL;
                                eprintln!("MTERPTOL#{n} f={f} va={base:#x}");
                                if cpu.map_usuario_zeroed("tolerante_mterp", base, 0x1000).is_ok() {
                                    mapeadas_usr.push((cpu.mm_atual(), cpu.geracao(), base));
                                    pc = pc_falta;
                                    tolerado = true;
                                }
                            }
                        }
                        // TEMP (v10 viveiro): the RuntimeInit argv String[]
                        // (frame slot [0x4104af38], v10 of the 0x41aa7afa
                        // method) holds the wild 0xe4280000 from an invoke
                        // arg-push over-read (proven: MTERP slot bytes and
                        // MISSARG v10 agree; the array-length then reads 0,
                        // which EQUALS the expected count, so the guest logs
                        // "Missing classname" spuriously and aborts at
                        // 0xdeadd00d). Snapshot forensics (temp_caca_v10)
                        // found NO live String[] in either mm (child: 1
                        // bogus 1-elem; parent: 1 bogus), so the host
                        // fabricates argv in this same zero page
                        // (scratch at +0x100, past the [+8] word the
                        // in-flight retry reads as 0) and restores the
                        // slot. Later IGETs reload r0 from the slot and see
                        // the real length. POISON-GATED, NOT one-shot: a
                        // refire with a fixed slot is a silent no-op, and
                        // every fresh zygote fork reproduces the poison
                        // (same over-read) and needs its own restore.
                        // Real fix: the over-reading invoke. Remove with
                        // CRASHOBJ.
                        static mut NVIV: u32 = 0;
                        unsafe {
                            if tolerado {
                                NVIV += 1;
                                const SLOT_V10: u32 = 0x4104af38;
                                const VENENO: u32 = 0xe4280000;
                                const RASO: u32 = 0xe4280100;
                                const OBJ_STR: u32 = 0xe4280200;
                                const VETOR_CH: u32 = 0xe4280300;
                                let slot_agora = cpu.read_u32(SLOT_V10).unwrap_or(0xFFFF_FFFF);
                                // Guarda extra: so restaura se a pagina
                                // tolerada continua zerada ([+8]==0). Se o
                                // guest mapeou algo real em 0xe4280000, o
                                // slot pode ser legitimo — nao tocar.
                                let pagina_zero = cpu.read_u32(VENENO + 8).unwrap_or(0xDEAD_DEAD) == 0;
                                if slot_agora == VENENO && pagina_zero {
                                    let f = FATIA_ATUAL;
                                    // Layout String calibrado ao vivo
                                    // (temp_charvec, 3/3): {clazz+0, 1@+4,
                                    // array@+8, hash@+12, offset@+16=0,
                                    // count@+20=len}. O +16=array antigo
                                    // estava errado (offset=0 dava
                                    // "obj-ok-noarray@0x0" nos probes);
                                    // count=0 esvaziava a classname e
                                    // clazz=0 estourava ArrayStoreException
                                    // no arraycopy/aput. Clazzes reais do
                                    // snap583 (temp_caca_clazz), verificadas
                                    // ao vivo pelo descritor.
                                    let mut cab = [0u8; 24];
                                    let mut de_onde = "zeros";
                                    let verifica = |cpu: &mut crate::cpu::dual::DualBackend, cl: u32, esp: &[u8]| -> bool {
                                        let mut wb = [0u8; 4];
                                        if cpu.memoria().read(cl + 24, 4).map(|s| wb.copy_from_slice(s)).is_err() {
                                            return false;
                                        }
                                        let pd = u32::from_le_bytes(wb);
                                        let mut hb = [0u8; 8];
                                        if cpu.memoria().read(pd, 8).map(|s| hb.copy_from_slice(s)).is_err() {
                                            return false;
                                        }
                                        &hb == esp
                                    };
                                    let ok_str = verifica(&mut cpu, 0x4000d5b0, b"Ljava/la");
                                    let ok_arr = verifica(&mut cpu, 0x4107ea48, b"[Ljava/l");
                                    let clazz_str: u32 = if ok_str { 0x4000d5b0 } else { 0 };
                                    let clazz_arr: u32 = if ok_arr { 0x4107ea48 } else { 0 };
                                    de_onde = if ok_str && ok_arr { "viveiro" } else if ok_str || ok_arr { "parcial" } else { "zeros" };
                                    // Header-modelo: [clazz,1,0,0,0,0]; o
                                    // array ptr e o count vao por string.
                                    cab[0..4].copy_from_slice(&clazz_str.to_le_bytes());
                                    cab[4..8].copy_from_slice(&1u32.to_le_bytes());
                                    // argv Donut de 7 (ordem do startSystemServer):
                                    // o arraycopy (INVOKE#1, r4=0x41aa7b5e em
                                    // zygoteInit) copia 7 e estoura com len
                                    // 1 ou 2 (AIOOBE nativo, sem <init> leaf;
                                    // supers via INVOKE#2-4, fill #5, captura
                                    // com 5 pares e shutdown). len<7 da o
                                    // mesmo muro identico (196==195 ins a
                                    // ins); len 7 deve passar a copia e
                                    // chegar ao invokeStaticMain.
                                    let nomes = [
                                        "--setuid=1000",
                                        "--setgid=1000",
                                        "--setgroups=1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,3001,3002,3003",
                                        "--capabilities=34,30",
                                        "--runtime-init",
                                        "--nice-name=system_server",
                                        "com.android.server.SystemServer",
                                    ];
                                    // (dex-confirmed a classe em 0x41bc5f76.)
                                    let mut ok_w = true;
                                    {
                                        let mut mb = cpu.memoria_mut();
                                        // Array de 7 em RASO (clazz real).
                                        ok_w &= mb.write_u32(RASO, clazz_arr).is_ok();
                                        ok_w &= mb.write_u32(RASO + 4, 0).is_ok();
                                        ok_w &= mb.write_u32(RASO + 8, nomes.len() as u32).is_ok();
                                        // Sete Strings + sete vetores: par k em
                                        // +0x200+0x200k (obj) / +0x300+0x200k
                                        // (vetor); cabe no zero page (ultimo
                                        // vetor em 0xF00, setgroups ~200 B).
                                        // String: [clazz,+4=1,array@+8,
                                        // hash@+12=0,offset@+16=0,count@+20].
                                        for (k, nome) in nomes.iter().enumerate() {
                                            let obj = OBJ_STR + (k as u32) * 0x200;
                                            let vet = VETOR_CH + (k as u32) * 0x200;
                                            let utf16: Vec<u16> = nome.encode_utf16().collect();
                                            ok_w &= mb.write_u32(RASO + 12 + (k as u32) * 4, obj).is_ok();
                                            ok_w &= mb.write(obj, &cab).is_ok();
                                            ok_w &= mb.write_u32(obj + 8, vet).is_ok();
                                            ok_w &= mb.write_u32(obj + 20, utf16.len() as u32).is_ok();
                                            ok_w &= mb.write_u32(vet, 0).is_ok();
                                            ok_w &= mb.write_u32(vet + 4, 0).is_ok();
                                            ok_w &= mb.write_u32(vet + 8, utf16.len() as u32).is_ok();
                                            let mut cb = Vec::with_capacity(utf16.len() * 2);
                                            for u in &utf16 {
                                                cb.extend_from_slice(&u.to_le_bytes());
                                            }
                                            ok_w &= mb.write(vet + 12, &cb).is_ok();
                                        }
                                        // Restaura o slot v10.
                                        ok_w &= mb.write_u32(SLOT_V10, RASO).is_ok();
                                    }
                                    eprintln!("V10VIVEIRO f={f} ok={ok_w} modelo={de_onde} cls={clazz_str:#x}/{clazz_arr:#x} slot_agora={slot_agora:#x} argc=7");
                                } else {
                                    let f = FATIA_ATUAL;
                                    eprintln!("V10VIVEIRO f={f} pula slot={slot_agora:#x}");
                                }
                            }
                        }
                        if !tolerado {
                            parada = outra;
                            break;
                        }
                    }
                    StopReason::MemoryFault { addr, pc: pc_falta }
                        if mapeadas.len() < 64 =>
                    {
                        let base = addr & !0xFFF;
                        // TEMP (MMIO-vs-file): SPL-era MMIO windows (e.g.
                        // disp_aa00 0xAA000000, display registers in SPL)
                        // shadow Linux userspace file mappings that reuse
                        // the same VA (webcore text at 0xaa008000 served
                        // zeros via demanda, no file branch -> wild link).
                        // File-backed VMAs win over the MMIO hypothesis;
                        // genuine device VAs have no NAND file (caminho
                        // None or YAFFS miss) and keep today's path.
                        // Remove with CRASHOBJ.
                        let eh_arquivo_mmio = vma_e_anonima(&mut cpu, &mm_para_mm.borrow(), base) == Some(false);
                        let classe = if mapeadas.contains(&base) {
                            None
                        } else if traduz(base).is_some() {
                            Some("alias")
                        } else if janela_de(base).is_some() && !eh_arquivo_mmio {
                            Some("suspeita")
                        } else {
                            None
                        };
                        match classe {
                            Some(_classe) => {
                                if cpu.map_zeroed("demanda", base, 0x1000).is_err() {
                                    // Overlap: an exact-length region (e.g. a
                                    // file mapping sized by the loader, not
                                    // the page) already covers part of this
                                    // page — proven live: the linker's BSS
                                    // memset writes the first byte past
                                    // libOmxCore LOAD1 end (0x80003198) and
                                    // the run stops here instead of serving
                                    // the in-page slack. The guest VMA covers
                                    // the whole page, so extend coverage with
                                    // zero fill (kernel zero-page semantics),
                                    // preserving the existing bytes. Any
                                    // failure below stops the run, as before.
                                    let mut pg = vec![0u8; 0x1000];
                                    let mut tem_algo = false;
                                    let mut off = 0u32;
                                    while off < 0x1000 {
                                        let mut hb = [0u8; 64];
                                        if cpu
                                            .read_mem(base.wrapping_add(off), &mut hb)
                                            .is_ok()
                                        {
                                            pg[off as usize..off as usize + 64]
                                                .copy_from_slice(&hb);
                                            tem_algo = true;
                                        }
                                        off += 64;
                                    }
                                    if !tem_algo {
                                        parada = outra;
                                        break;
                                    }
                                    cpu.desmapeia_intervalo(base, 0x1000);
                                    if cpu.map_zeroed("demanda", base, 0x1000).is_err() {
                                        parada = outra;
                                        break;
                                    }
                                    let mut ok = true;
                                    let mut off2 = 0u32;
                                    while off2 < 0x1000 {
                                        if cpu
                                            .write_mem(
                                                base.wrapping_add(off2),
                                                &pg[off2 as usize..off2 as usize + 64],
                                            )
                                            .is_err()
                                        {
                                            ok = false;
                                            break;
                                        }
                                        off2 += 64;
                                    }
                                    if !ok {
                                        parada = outra;
                                        break;
                                    }
                                    eprintln!("SLACKFILL f={} va={base:#x}", unsafe { FATIA_ATUAL });
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
                    StopReason::MemoryFault { addr, pc: pc_falta }
                        if ({
                            let base = addr & !0xFFF;
                            let aliased = traduz(base).is_some() || janela_de(base).is_some();
                            if !aliased {
                                false
                            } else {
                                let mut tem = false;
                                let mut off = 0u32;
                                while off < 0x1000 {
                                    let mut hb = [0u8; 64];
                                    // Read-only probe; true if any chunk
                                    // of the page is already mapped.
                                    if cpu.read_mem(base.wrapping_add(off), &mut hb).is_ok() {
                                        tem = true;
                                        break;
                                    }
                                    off += 64;
                                }
                                tem
                            }
                        }) =>
                    {
                        // Overlap-tail serve when the mapeadas brake
                        // (64) already shut the main alias arm: the
                        // page is partially mapped (exact-length file
                        // region) and the fault is in-page slack the
                        // guest VMA covers. Same preserve-extend as
                        // SLACKFILL above, own cap (64) to bound blast
                        // radius; ABORT-LOOP still guards true loops.
                        static mut NSLACK2: u32 = 0;
                        unsafe {
                            if NSLACK2 >= 64 {
                                parada = outra;
                                break;
                            }
                            NSLACK2 += 1;
                        }
                        let base = addr & !0xFFF;
                        let mut pg = vec![0u8; 0x1000];
                        let mut off = 0u32;
                        while off < 0x1000 {
                            let mut hb = [0u8; 64];
                            if cpu.read_mem(base.wrapping_add(off), &mut hb).is_ok() {
                                pg[off as usize..off as usize + 64].copy_from_slice(&hb);
                            }
                            off += 64;
                        }
                        cpu.desmapeia_intervalo(base, 0x1000);
                        if cpu.map_zeroed("demanda_slack", base, 0x1000).is_err() {
                            parada = outra;
                            break;
                        }
                        let mut ok = true;
                        let mut off2 = 0u32;
                        while off2 < 0x1000 {
                            if cpu
                                .write_mem(base.wrapping_add(off2), &pg[off2 as usize..off2 as usize + 64])
                                .is_err()
                            {
                                ok = false;
                                break;
                            }
                            off2 += 64;
                        }
                        if !ok {
                            parada = outra;
                            break;
                        }
                        eprintln!("SLACKFILL2 f={} va={base:#x}", unsafe { FATIA_ATUAL });
                        pc = pc_falta;
                    }
                    _ => {
                        // TEMP (shadow-range fault attribution): log any
                        // MemoryFault in 0x80000000-0x84000000 that reaches
                        // the catch-all with the arm-3 gate inputs.
                        if let StopReason::MemoryFault { addr, pc: pc_falta } = &outra {
                            if (0x8000_0000..0x8400_0000).contains(addr) {
                                let base = addr & !0xFFF;
                                let mut tem = false;
                                let mut off = 0u32;
                                while off < 0x1000 {
                                    let mut hb = [0u8; 64];
                                    if cpu.read_mem(base.wrapping_add(off), &mut hb).is_ok() {
                                        tem = true;
                                        break;
                                    }
                                    off += 64;
                                }
                                eprintln!("SHADOWMISS f={} va={addr:#x} pc={pc_falta:#x} mapeado={tem}", unsafe { FATIA_ATUAL });
                            }
                        }
                        // User-mode undefined instruction: deliver to
                        // the guest UND vector (SIGILL kills the
                        // process, init restarts it) instead of
                        // stopping the run — a dying service past
                        // startup must not end the boot. Kernel-mode
                        // UNDs still stop (our bug or unrecoverable).
                        // TEMP (linker blx-input hunt): blx at 0xB000029C feeds the wild
    // r1 (via 0xCBAC return). Log r0/r1/r2 + [r2] to name which input
    // is wild. Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xB000_029C, move |mem, regs| {
        static mut NLB: u32 = 0;
        unsafe {
            if NLB < 4 {
                NLB += 1;
                let n = NLB;
                let f = FATIA_ATUAL;
                let r2 = regs[2];
                let mut w = [0u8; 4];
                let ok = mem.read(r2, 4).map(|s| w.copy_from_slice(s)).is_ok();
                eprintln!("LNKBLX#{n} f={f} r0={:#x} r1={:#x} r2={r2:#x} [r2]ok={ok}={w:02x?}", regs[0], regs[1]);
            }
        }
    });
    // TEMP (system_server NULL+64 hunt): pc 0x11020 faults on 0x40
    // (NULL+64) in system_server, caller libdvm ad03ba39 (same call
    // site as 0x11014 SIGILL, now advanced 12 bytes after THUMBFIX).
    // Log regs + VMA + code to name the null object. Cap 4. Remove
    // with CRASHOBJ.
    let mm_para_mm_null = mm_para_mm.clone();
    cpu.trap_pc_mem(0x0001_1020, move |mem, regs| {
        static mut NNU: u32 = 0;
        unsafe {
            if NNU < 4 {
                NNU += 1;
                let n = NNU;
                let f = FATIA_ATUAL;
                let mm = mem.mm_atual();
                let mut cb = [0u8; 16];
                let cok = mem.read(0x11020, 16).map(|s| cb.copy_from_slice(s)).is_ok();
                let mut cb2 = [0u8; 32];
                let cok2 = mem.read(0x11000u32, 32).map(|s| cb2.copy_from_slice(s)).is_ok();
                let mut stk = [0u8; 64];
                let sok = mem.read(regs[13], 64).map(|s| stk.copy_from_slice(s)).is_ok();
                let mut vma_s = String::from("n/a");
                let mut vma_r0 = String::from("n/a");
                if let Some(&m) = mm_para_mm_null.borrow().get(&mm) {
                    for (alvo, eh_r0) in [(0x11020u32, false), (regs[0], true)] {
                        let mut vma = mem.read_u32(m).unwrap_or(0);
                        let mut depth = 0u32;
                        let mut achou = false;
                        while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                            depth += 1;
                            let mut vb = [0u8; 80];
                            if mem.read(vma, 80).map(|s| vb.copy_from_slice(s)).is_err() {
                                break;
                            }
                            let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
                            let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
                            if ini <= alvo && alvo < fim {
                                let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
                                let arq = u32::from_le_bytes([vb[72], vb[73], vb[74], vb[75]]);
                                let s = format!("[{ini:#x},{fim:#x}) fl={fl:#x} arq={arq:#x}");
                                if eh_r0 {
                                    vma_r0 = s;
                                } else {
                                    vma_s = s;
                                }
                                achou = true;
                                break;
                            }
                            vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
                        }
                        if !achou {
                            if eh_r0 {
                                vma_r0 = String::from("sem-VMA");
                            } else {
                                vma_s = String::from("sem-VMA");
                            }
                        }
                    }
                }
                // TEMP (GOT-clobber hunt): GOT[prctl] 0xad07ee88 reads
                // 0x11008 (heap trash from the pristine file image);
                // the linker should have relocated it. Dump every
                // region covering the GOT page to name why
                // irmao_mesma_va missed the parent's relocated copy.
                // Remove with CRASHOBJ.
                let dbg_got = mem.debug_regioes(0xad07e000);
                eprintln!("NULL40#{n} f={f} mm={mm:#x} r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x} r5={:#x} r6={:#x} r7={:#x} lr={:#x} sp={:#x} cok={cok} code={cb:02x?} pre={cb2:02x?} sok={sok} stk={stk:02x?} vma={vma_s} vma_r0={vma_r0} gotreg={dbg_got}", regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[14], regs[13]);
            }
        }
    });
    // TEMP (prctl caller hunt): blx at 0xAD03BA34 targets PLT 0xAD00D1A8
    // (prctl). GOTPRCTL at the PLT never fired while NULL40 keeps firing
    // with lr=0xad03ba39, so either the base differs in system_server or
    // the lr is stale. Trap the caller itself: log args + GOT slot.
    // Cap 4. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAD03_BA34, move |mem, regs| {
        static mut NCB: u32 = 0;
        unsafe {
            if NCB < 4 {
                NCB += 1;
                let n = NCB;
                let f = FATIA_ATUAL;
                let mut gv = [0u8; 4];
                let gok = mem.read(0xad07ee88, 4).map(|s| gv.copy_from_slice(s)).is_ok();
                eprintln!("CALLERBLX#{n} f={f} r0={:#x} r1={:#x} r2={:#x} r3={:#x} got={:#x} gok={gok}", regs[0], regs[1], regs[2], regs[3], u32::from_le_bytes(gv));
            }
        }
    });
    // TEMP (GOT prctl hunt): subagent proved caller is zygote
    // forkAndSpecialize child path (r6=0 is fork child return, valid)
    // and the crash is a bad prctl GOT slot (0xad07ee88) jumping to
    // anon trash 0x11020 instead of libc prctl. Log GOT value + VMA
    // to decide unrelocated vs stale adopt. Cap 4. Remove with CRASHOBJ.
    let mm_para_mm_got = mm_para_mm.clone();
    cpu.trap_pc_mem(0xAD00_D1A8, move |mem, regs| {
        static mut NG: u32 = 0;
        unsafe {
            if NG < 4 {
                NG += 1;
                let n = NG;
                let f = FATIA_ATUAL;
                let mm = mem.mm_atual();
                let mut gv = [0u8; 4];
                let gok = mem.read(0xad07ee88, 4).map(|s| gv.copy_from_slice(s)).is_ok();
                let got = u32::from_le_bytes(gv);
                let mut vma_g = String::from("n/a");
                if let Some(&m) = mm_para_mm_got.borrow().get(&mm) {
                    let mut vma = mem.read_u32(m).unwrap_or(0);
                    let mut depth = 0u32;
                    while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                        depth += 1;
                        let mut vb = [0u8; 32];
                        if mem.read(vma, 32).map(|s| vb.copy_from_slice(s)).is_err() {
                            break;
                        }
                        let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
                        let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
                        if ini <= 0xad07ee88 && 0xad07ee88 < fim {
                            let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
                            vma_g = format!("[{ini:#x},{fim:#x}) fl={fl:#x}");
                            break;
                        }
                        vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
                    }
                    if vma_g == "n/a" {
                        vma_g = String::from("sem-VMA");
                    }
                }
                eprintln!("GOTPRCTL#{n} f={f} mm={mm:#x} got={got:#x} gok={gok} vma={vma_g} lr={:#x}", regs[14]);
            }
        }
    });
    // TEMP (malloc exit hunt): log all malloc NULL returns with caller
    // stack to name the failing allocation (r6=0 store needs malloc NULL?
    // Or heap corruption?). Cap 12 (NULLs should be rare). Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAFE0_A9B6, move |mem, regs| {
        static mut NMO: u32 = 0;
        unsafe {
            if NMO < 12 && regs[0] == 0 {
                NMO += 1;
                let n = NMO;
                let f = FATIA_ATUAL;
                let mut stk = [0u8; 16];
                let sok = mem.read(regs[13], 16).map(|s| stk.copy_from_slice(s)).is_ok();
                eprintln!("MALLOCNULL#{n} f={f} sp={:#x} sok={sok} stk={stk:02x?}", regs[13]);
            }
        }
    });
    // TEMP (malloc NULL hunt): system_server NULL+64 store has r4=1000
    // (size?) r6=0 (NULL dst). Log malloc(1000) callers to name who gets
    // NULL (OOM? Our host never fails mmap/brk, so guest OOM logic or
    // heap corruption). Cap 8. Remove with CRASHOBJ.
    cpu.trap_pc_mem(0xAFE0_A750, move |_mem, regs| {
        static mut NMA: u32 = 0;
        unsafe {
            if NMA < 8 && regs[0] == 0x3e8 {
                NMA += 1;
                let n = NMA;
                let f = FATIA_ATUAL;
                eprintln!("MALLOC1000#{n} f={f} lr={:#x}", regs[14]);
            }
        }
    });
    // TEMP (SIGILL 0x11014 hunt): system_server (or zygote) branches to
    // low memory 0x11014 (carved SPL area) from libdvm ad03ba36 and SIGILLs
    // (T=0, ARM decoding Thumb?). Log regs + VMA + code bytes + caller to
    // decide wild branch vs mode bug (linker pattern). Cap 4. Remove with CRASHOBJ.
    let mm_para_mm_ill = mm_para_mm.clone();
    cpu.trap_pc_mem(0x0001_1014, move |mem, regs| {
        static mut NIL: u32 = 0;
        unsafe {
            if NIL < 4 {
                NIL += 1;
                let n = NIL;
                let f = FATIA_ATUAL;
                let lr = regs[14];
                let sp = regs[13];
                let mm = mem.mm_atual();
                let mut cb = [0u8; 16];
                let cok = mem.read(0x11014, 16).map(|s| cb.copy_from_slice(s)).is_ok();
                let mut vma_s = String::from("n/a");
                if let Some(&m) = mm_para_mm_ill.borrow().get(&mm) {
                    let mut vma = mem.read_u32(m).unwrap_or(0);
                    let mut depth = 0u32;
                    while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                        depth += 1;
                        let mut vb = [0u8; 32];
                        if mem.read(vma, 32).map(|s| vb.copy_from_slice(s)).is_err() {
                            break;
                        }
                        let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
                        let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
                        if ini <= 0x11014 && 0x11014 < fim {
                            let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
                            vma_s = format!("[{ini:#x},{fim:#x}) fl={fl:#x}");
                            break;
                        }
                        vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
                    }
                    if vma_s == "n/a" {
                        vma_s = String::from("sem-VMA");
                    }
                }
                eprintln!("ILL14#{n} f={f} mm={mm:#x} lr={lr:#x} thumb_caller={} sp={sp:#x} cok={cok} code={cb:02x?} vma={vma_s}", lr & 1 != 0);
            }
        }
    });
    // TEMP (linker webcore hunt): pc 0xB00002A8 `ldr r5,[r1,r3]`
    // faults at 0xa8021440 (wild relocation address while loading
    // libwebcore). Log r1/r3 + VMA via mm map to decide wild vs
    // missing serve. Cap 4. Remove with CRASHOBJ.
    let mm_para_mm_lnk = mm_para_mm.clone();
    cpu.trap_pc_mem(0xB000_02A8, move |mem, regs| {
        static mut NLF: u32 = 0;
        unsafe {
            if NLF < 4 {
                NLF += 1;
                let n = NLF;
                let f = FATIA_ATUAL;
                let r1 = regs[1];
                let r3 = regs[3];
                let r6 = regs[6];
                let r4 = regs[4];
                let r0 = regs[0];
                let flt = r1.wrapping_add(r3);
                // link_map fields feeding r1/r3: [r6+0xb0]>>2=r1 pre-shift?
                // Actually r1 already shifted; log raw fields.
                let mut f_b0 = [0u8; 4];
                let ok_b0 = mem.read(r6.wrapping_add(0xb0), 4).map(|s| f_b0.copy_from_slice(s)).is_ok();
                let mut f_b8 = [0u8; 4];
                let ok_b8 = mem.read(r6.wrapping_add(0xb8), 4).map(|s| f_b8.copy_from_slice(s)).is_ok();
                let mm = mem.mm_atual();
                let mut vma_flt = String::from("n/a");
                let mut vma_wc = String::from("n/a");
                if let Some(&m) = mm_para_mm_lnk.borrow().get(&mm) {
                    for (alvo, eh_wc) in [(flt, false), (0xaa008000u32, true)] {
                        let mut vma = mem.read_u32(m).unwrap_or(0);
                        let mut depth = 0u32;
                        let mut achou = false;
                        while (0xC600_0000..0xC700_0000).contains(&vma) && depth < 200 {
                            depth += 1;
                            let mut vb = [0u8; 80];
                            if mem.read(vma, 80).map(|s| vb.copy_from_slice(s)).is_err() {
                                break;
                            }
                            let ini = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]);
                            let fim = u32::from_le_bytes([vb[8], vb[9], vb[10], vb[11]]);
                            if ini <= alvo && alvo < fim {
                                let fl = u32::from_le_bytes([vb[20], vb[21], vb[22], vb[23]]);
                                let arq = u32::from_le_bytes([vb[72], vb[73], vb[74], vb[75]]);
                                let s = format!("[{ini:#x},{fim:#x}) fl={fl:#x} arq={arq:#x}");
                                if eh_wc {
                                    vma_wc = s;
                                } else {
                                    vma_flt = s;
                                }
                                achou = true;
                                break;
                            }
                            vma = u32::from_le_bytes([vb[12], vb[13], vb[14], vb[15]]);
                        }
                        if !achou {
                            if eh_wc {
                                vma_wc = String::from("sem-VMA");
                            } else {
                                vma_flt = String::from("sem-VMA");
                            }
                        }
                    }
                }
                eprintln!("LNKFLT#{n} f={f} mm={mm:#x} r0={r0:#x} r4={r4:#x} r6={r6:#x} r1={r1:#x} r3={r3:#x} flt={flt:#x} [r6+0xb0]ok={ok_b0}={f_b0:02x?} [r6+0xb8]ok={ok_b8}={f_b8:02x?} vma_flt={vma_flt} vma_wc={vma_wc}");
            }
        }
    });
    // TEMP (Thumb-state): user Thumb code faults as ARM UND
                        // (T=0). Proven at linker 0xB0000854/0xAA0/0x9E1 and
                        // system_server 0x11014 (VMA exec, Thumb caller).
                        // Force Thumb and retry once per pc; retried pcs
                        // that fault again fall through to normal UND
                        // delivery. Remove once the bx/svc-return T bug is
                        // found. Remove with CRASHOBJ.
                        if let StopReason::Exception { pc: pc_falta } = &outra {
                            if cpu.em_usuario() {
                                static mut ULTIMO_THUMBFIX: u32 = 0;
                                let repetiu = unsafe { *pc_falta == ULTIMO_THUMBFIX };
                                if !repetiu {
                                    unsafe { ULTIMO_THUMBFIX = *pc_falta; }
                                    cpu.forca_thumb();
                                    // run() derives T from pc bit0.
                                    pc = *pc_falta | 1;
                                    static mut NTH: u32 = 0;
                                    unsafe {
                                        if NTH < 12 {
                                            NTH += 1;
                                            let f = FATIA_ATUAL;
                                            eprintln!("THUMBFIX f={f} pc={pc:#x}", pc = pc);
                                        }
                                    }
                                    continue;
                                }
                            }
                            if cpu.em_usuario() {
                                cpu.entra_undef();
                                pc = cpu.read_reg(crate::cpu::Reg::Pc) & !1;
                                continue;
                            }
                            let _ = pc_falta;
                        }
                        parada = outra;
                        break;
                    }
                    // TEMP (shadow-range fault attribution): log any
                    // MemoryFault in 0x80000000-0x84000000 that reaches
                    // the catch-all (i.e. was NOT served by the alias
                    // arm above) with the arm-3 gate inputs. Names
                    // whether the omx-tail stop is cap-full, probe-miss,
                    // or a third path. Uncapped (fires at most a handful
                    // of times — any hit here means a stop is imminent).
                }
            }
        }
        // TEMP (slice-cost hunt): the user-phase pace collapsed (~2
        // full slices/s). Track max/avg host time per slice, reported
        // every 5000 slices with the max slice's pc. Remove with the hunt.
        {
            static mut NSL: u32 = 0;
            static mut SUMU: u64 = 0;
            static mut SUMRUN: u64 = 0;
            static mut SUMB: u64 = 0;
            static mut SUMF: u64 = 0;
            static mut MAXU: u64 = 0;
            static mut MAXPC: u32 = 0;
            static mut MAXMM: u32 = 0;
            let t_tot = t_fora.elapsed();
            let t_run = t_run.as_micros() as u64;
            let t_tot = t_tot.as_micros() as u64;
            let t_host = t_tot.saturating_sub(t_run);
            unsafe {
                SUMU += t_tot;
                SUMRUN += t_run;
                if foi_orcamento {
                    SUMB += t_host;
                } else {
                    SUMF += t_host;
                }
                NSL += 1;
                if t_tot > MAXU {
                    MAXU = t_tot;
                    MAXPC = pc;
                    MAXMM = cpu.mm_atual();
                }
                if NSL >= 5000 {
                    let n = NSL;
                    let avg = SUMU / NSL as u64;
                    let mx = MAXU;
                    let mpc = MAXPC;
                    let mmm = MAXMM;
                    let run = SUMRUN / NSL as u64;
                    let hb = SUMB / NSL as u64;
                    let hf = SUMF / NSL as u64;
                    eprintln!(
                        "SLICESTAT f={fatia} n={n} avg={avg}us run={run}us hostB={hb}us hostF={hf}us max={mx}us maxpc={mpc:#x} maxmm={mmm:#x} traps={} regions={}",
                        cpu.num_armadilhas(),
                        cpu.num_regioes(),
                    );
                    NSL = 0;
                    SUMU = 0;
                    SUMRUN = 0;
                    SUMB = 0;
                    SUMF = 0;
                    MAXU = 0;
                }
            }
        }
    }
    // Halt traceback: what instruction stopped the run, decoded in
    // place, plus the full register file. Printed once per terminal
    // stop — Budget included, since stall runs end on Budget with no
    // fault and the parked pc + stack + pc history names the stall.
    match &parada {
        StopReason::MemoryFault { addr, pc } => imprime_trace(&cpu, *pc, Some(*addr), parada.motivo()),
        StopReason::Exception { pc } => imprime_trace(&cpu, *pc, None, parada.motivo()),
        StopReason::Budget => {
            imprime_trace(&cpu, cpu.read_reg(crate::cpu::Reg::Pc), None, parada.motivo())
        }
        StopReason::ApiCall { addr } => {
            imprime_trace(&cpu, cpu.read_reg(crate::cpu::Reg::Pc), Some(*addr), parada.motivo())
        }
        StopReason::Returned => {
            imprime_trace(&cpu, cpu.read_reg(crate::cpu::Reg::Pc), None, parada.motivo())
        }
    }
    // Final logcat drain: same mid-slice loss as the serial ring —
    // a stop lands after the last per-slice collection, leaving the
    // abort's own logger entries (stack-trace tail) unread in the
    // ring. Forward-only from ULTIMO, so re-collection is safe.
    // TEMP (bring-up forensics): fold into the per-slice path or
    // drop when stops move past zygote. Remove with CRASHOBJ.
    for linha in colhe_logcat(&mut cpu) {
        eprintln!("{linha}");
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
    //
    // Full history: the per-slice stitcher (`klog_full`, every 50
    // slices) already accumulated the whole run chronologically.
    // When present it wins outright (no sort/dedup/cut — repeats
    // are data, e.g. yaffs GC spam); the snapshot below stays as
    // the fallback for short/pre-kernel runs.
    // slices) already accumulated the whole run chronologically.
    // When present it wins outright (no sort/dedup/cut — repeats
    // are data, e.g. yaffs GC spam); the snapshot below stays as
    // the fallback for short/pre-kernel runs.
    //
    // Minimal guest-printk formatter for the full-klog tap (fires
    // on every printk call, so the log is complete and ordered —
    // no ring to wrap, no snapshot window). Handles what the
    // trout kernel emits (%s %d %i %u %x %X %o %c %p %% plus
    // l/ll/h/z length mods, width/zero-pad/left-justify, `*`
    // width). Anything else renders as `<%?>` so gaps stay
    // visible. NEVER writes to the guest (notably: no %n
    // semantics — printed literally). String args read with a
    // 512 B cap; unreadable pointers render as `<unmapped>`.
    // Returns None when the format itself is unreadable (caller
    // skips silently — a faulting guest would trip UFAULT anyway
    // through its own read).
    fn formata_printk(mem: &GuestMemory, fmt_va: u32, r1: u32, r2: u32, r3: u32, sp: u32) -> Option<String> {
        // Format string in 64 B chunks (a single 512 B read fails
        // when the string sits at a region edge).
        let mut fmtb = Vec::new();
        let mut ok = false;
        for k in 0..8u32 {
            match mem.read(fmt_va.wrapping_add(k * 64), 64) {
                Ok(s) => {
                    if let Some(z) = s.iter().position(|&b| b == 0) {
                        fmtb.extend_from_slice(&s[..z]);
                        ok = true;
                        break;
                    }
                    fmtb.extend_from_slice(s);
                }
                Err(_) => break,
            }
        }
        if !ok && fmtb.is_empty() {
            return None;
        }
        let fmt: &[u8] = &fmtb;
        // First vararg is in r1 (prox starts at 0): the tap fires
        // BEFORE the prologue on the caller's regs, so r1/r2/r3
        // still hold args 1-3 and only args 4+ live at [sp]
        // (proven live: yaffs dev/name print has r1=0x1f00003,
        // r2=name pointer; starting at 3 formatted stack garbage
        // as dev and printed <unmapped> for the name).
        let mut prox = 0u32;
        let mut arg = |mem: &GuestMemory| -> u32 {
            let v = match prox {
                0 => r1,
                1 => r2,
                2 => r3,
                n => mem.read_u32(sp.wrapping_add((n - 3) * 4)).unwrap_or(0),
            };
            prox += 1;
            v
        };
        let mut fora = String::new();
        // KERN_* prefix (`\x01` + level) renders as `<N>` like the
        // ring dump, so downstream splitting keeps working.
        let mut resto = fmt;
        if resto.len() >= 2 && resto[0] == 1 && resto[1].is_ascii_digit() {
            fora.push('<');
            fora.push(resto[1] as char);
            fora.push('>');
            resto = &resto[2..];
        }
        let mut i = 0;
        while i < resto.len() {
            let c = resto[i];
            i += 1;
            if c != b'%' {
                // Bytes verbatim (lossy); newlines structure lines.
                if c == b'\n' {
                    fora.push('\n');
                } else if c.is_ascii_graphic() || c == b' ' || c == b'\t' {
                    fora.push(c as char);
                } else {
                    fora.push('\u{FFFD}');
                }
                continue;
            }
            if i < resto.len() && resto[i] == b'%' {
                fora.push('%');
                i += 1;
                continue;
            }
            // Flags. All consumed so later args stay aligned even
            // for rare ones; only placements seen in printk matter
            // for output ('-' left, '0' zero-pad, '#' 0x/0 prefix).
            let mut canhoto = false;
            let mut zero = false;
            let mut especial = false;
            loop {
                if i >= resto.len() {
                    break;
                }
                match resto[i] {
                    b'-' => canhoto = true,
                    b'0' => zero = true,
                    b'#' => especial = true,
                    b'+' | b' ' => {}
                    _ => break,
                }
                i += 1;
            }
            // Width.
            let mut larg = 0usize;
            let mut larg_explicita = false;
            if i < resto.len() && resto[i] == b'*' {
                larg = arg(mem) as usize;
                larg_explicita = true;
                i += 1;
            } else {
                while i < resto.len() && resto[i].is_ascii_digit() {
                    larg = larg * 10 + (resto[i] - b'0') as usize;
                    larg_explicita = true;
                    i += 1;
                }
            }
            // Precision (honored for %s only).
            let mut prec: Option<usize> = None;
            if i < resto.len() && resto[i] == b'.' {
                i += 1;
                if i < resto.len() && resto[i] == b'*' {
                    let v = arg(mem) as usize;
                    prec = Some(v);
                    i += 1;
                } else {
                    let mut p = 0usize;
                    while i < resto.len() && resto[i].is_ascii_digit() {
                        p = p * 10 + (resto[i] - b'0') as usize;
                        i += 1;
                    }
                    prec = Some(p);
                }
            }
            // Length. 'L' alone counts as long long (the kernel
            // maps both 'll' and lone 'L' to qualifier 'L' =
            // va_arg(args, long long): two stack slots. Getting
            // this wrong shifts every later arg (seen live as
            // garbage values after the first %Ld).
            let mut longo = 0u8;
            while i < resto.len() && (resto[i] == b'l' || resto[i] == b'L' || resto[i] == b'h' || resto[i] == b'z' || resto[i] == b't') {
                if resto[i] == b'l' {
                    longo += 1;
                } else if resto[i] == b'L' {
                    longo = 2;
                }
                i += 1;
            }
            if i >= resto.len() {
                fora.push_str("<%?>");
                break;
            }
            let conv = resto[i] as char;
            i += 1;
            // Rendered body, padded below.
            let corpo = match conv {
                's' => {
                    let p = arg(mem);
                    if p < 4096 {
                        // Matches the kernel's "<NULL>" for low
                        // pointers (2.6.25 checks < PAGE_SIZE).
                        String::from("<NULL>")
                    } else {
                        // Chunked: a single 512 B read fails if the
                        // string straddles an unmapped region end.
                        let mut out = Vec::new();
                        let mut resto_s = 512usize;
                        let mut off = 0u32;
                        let mut ok = false;
                        while resto_s > 0 {
                            let n = resto_s.min(64);
                            match mem.read(p.wrapping_add(off), n as u32) {
                                Ok(s) => {
                                    if let Some(z) = s.iter().position(|&b| b == 0) {
                                        out.extend_from_slice(&s[..z]);
                                        ok = true;
                                        break;
                                    }
                                    out.extend_from_slice(s);
                                    off += n as u32;
                                    resto_s -= n;
                                }
                                Err(_) => break,
                            }
                        }
                        if !ok && out.is_empty() {
                            String::from("<unmapped>")
                        } else {
                            let z = out.iter().position(|&b| b == 0).unwrap_or(out.len());
                            String::from_utf8_lossy(&out[..z]).into_owned()
                        }
                    }
                }
                'd' | 'i' => {
                    if longo >= 2 {
                        let lo = arg(mem) as u64;
                        let hi = arg(mem) as u64;
                        ((hi << 32) | lo) as i64
                    } else {
                        arg(mem) as i32 as i64
                    }
                    .to_string()
                }
                'u' => {
                    if longo >= 2 {
                        let lo = arg(mem) as u64;
                        let hi = arg(mem) as u64;
                        ((hi << 32) | lo).to_string()
                    } else {
                        (arg(mem)).to_string()
                    }
                }
                'o' => {
                    let v = if longo >= 2 {
                        let lo = arg(mem) as u64;
                        let hi = arg(mem) as u64;
                        (hi << 32) | lo
                    } else {
                        arg(mem) as u64
                    };
                    // '#' forces a leading 0 even when the value
                    // already starts with one (matches number()).
                    let digitos = format!("{v:o}");
                    if especial {
                        format!("0{digitos}")
                    } else {
                        digitos
                    }
                }
                'x' | 'X' => {
                    let v = if longo >= 2 {
                        let lo = arg(mem) as u64;
                        let hi = arg(mem) as u64;
                        (hi << 32) | lo
                    } else {
                        arg(mem) as u64
                    };
                    let digitos = if conv == 'x' {
                        format!("{v:x}")
                    } else {
                        format!("{v:X}")
                    };
                    // '#' prefixes 0x/0X (kernel puts the prefix
                    // before any zero padding; with an explicit
                    // width the generic padder below may still pad
                    // in front — accepted deviation, never seen in
                    // practice).
                    if especial {
                        if conv == 'x' {
                            format!("0x{digitos}")
                        } else {
                            format!("0X{digitos}")
                        }
                    } else {
                        digitos
                    }
                }
                'c' => {
                    let v = (arg(mem) & 0xFF) as u8;
                    if v == b'\n' {
                        String::from("\n")
                    } else if v.is_ascii_graphic() || v == b' ' {
                        (v as char).to_string()
                    } else {
                        "\u{FFFD}".to_string()
                    }
                }
                'p' => {
                    let v = arg(mem);
                    // No 0x prefix and no NULL special-case in this
                    // kernel: number() always prints bare hex,
                    // zero-padded to 8 when no width was given.
                    // (Old logs show the literal "0x" from formats
                    // like "initcall 0x%p"; the 0x0x duplication was
                    // ours.)
                    let digitos = if larg_explicita {
                        format!("{v:x}")
                    } else {
                        format!("{v:08x}")
                    };
                    if especial {
                        format!("0x{digitos}")
                    } else {
                        digitos
                    }
                }
                'n' => {
                    // Consumes one pointer arg; the kernel writes the
                    // count there, which a read-only tap must NOT do.
                    // Emits nothing (matching the kernel's silence).
                    let _ = arg(mem);
                    String::new()
                }
                _ => format!("<%{conv}?>"),
            };
            // Width (left/right pad; '0' pads numbers only).
            let numerico = matches!(conv, 'd' | 'i' | 'u' | 'o' | 'x' | 'X' | 'p');
            if corpo.len() < larg {
                let ench = larg - corpo.len();
                let ch = if zero && !canhoto && numerico { '0' } else { ' ' };
                if canhoto {
                    fora.push_str(&corpo);
                    for _ in 0..ench {
                        fora.push(ch);
                    }
                } else {
                    for _ in 0..ench {
                        fora.push(ch);
                    }
                    fora.push_str(&corpo);
                }
            } else {
                fora.push_str(&corpo);
            }
        }
        Some(fora)
    }
    fn divide_limpa(txt: &str) -> Vec<(f64, String)> {
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
        msgs
    }
    let mut kernel_log: Vec<u8> = Vec::new();
    let costurado: Vec<u8> = klog_full.borrow().clone();
    if !costurado.is_empty() {
        // Stitched trap lines are already complete + ordered: split
        // on newlines only (no <N>[ split — the level prefix is
        // already inline — and no sort/dedup/cut; repeats are data).
        for seg in costurado.split(|&b| b == b'\n') {
            let limpa: String = seg
                .split(|&b| b == 0)
                .next()
                .unwrap_or_default()
                .iter()
                .take(240)
                .filter(|c| c.is_ascii_graphic() || **c == b' ' || **c == b'\t')
                .map(|&c| c as char)
                .collect();
            if limpa.is_empty() {
                continue;
            }
            kernel_log.extend_from_slice(limpa.as_bytes());
            kernel_log.push(b'\n');
        }
        // Flush a trailing partial line (printk without '\n').
        let resto: String = klog_pend.borrow().clone();
        if !resto.is_empty() {
            kernel_log.extend_from_slice(resto.as_bytes());
            kernel_log.push(b'\n');
        }
    } else {
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
            let mut msgs = divide_limpa(&txt);
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
        // same spirit as the `DREAMYEMU_ROM` scan.
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
        use crate::cpu::dual::DualBackend;
        use crate::cpu::{CpuBackend, Reg};
        let mut cpu = DualBackend::new().unwrap();
        cpu.map_zeroed("code", 0x1000, 0x1000).unwrap();
        // add r0, r0, #0x1 ; str r1, [r2] ; b .-8 (loop).
        cpu.write_mem(0x1000, &0xE280_0001u32.to_le_bytes()).unwrap();
        cpu.write_mem(0x1004, &0xE582_1000u32.to_le_bytes()).unwrap();
        cpu.write_mem(0x1008, &0xEAFF_FFFEu32.to_le_bytes()).unwrap();
        cpu.write_reg(Reg::Pc, 0x1004);
        cpu.write_reg(Reg::R2, 0x2000);
        // Must not panic; output eyeballed with --nocapture. The 0x2000
        // store target is unmapped on purpose (fault addr demo).
        imprime_trace(&cpu, 0x1004, Some(0x2000), "memory fault (unmapped access)");
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
        use crate::cpu::dual::DualBackend;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mem = monta_mapa_inicial(&spl).unwrap();
        let mut cpu = DualBackend::new().unwrap();
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
        use crate::cpu::dual::DualBackend;
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
        let mut cpu = DualBackend::new().unwrap();
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
        use crate::cpu::dual::DualBackend;
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
        let mut cpu = DualBackend::new().unwrap();
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
        use crate::cpu::dual::DualBackend;
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
        let mut cpu = DualBackend::new().unwrap();
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
        use crate::cpu::dual::DualBackend;
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
        let mut cpu = DualBackend::new().unwrap();
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
        use crate::cpu::dual::DualBackend;
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
        let mut cpu = DualBackend::new().unwrap();
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
        use crate::cpu::dual::DualBackend;
        use crate::cpu::{CpuBackend, StopReason};
        use crate::msm7201a_serial::PUTC_ADDR;

        let Some(p) = caminho_do_spl() else {
            eprintln!("no SPL under tests/spl: skipped");
            return;
        };
        let spl = std::fs::read(p).unwrap();
        let mut mem = monta_mapa_inicial(&spl).unwrap();
        mem.map_zeroed("sonda_fria", 0x01f6_a000, 0x1000).unwrap();
        let mut cpu = DualBackend::new().unwrap();
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
