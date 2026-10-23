//! SPL text output: tap points and a host-side byte sink.
//!
//! Goal: see SPL logs as early as possible. The SPL prints through a small
//! chain, confirmed by disassembly (`-b binary -m arm`, file offsets ==
//! pre-MMU physical addresses; post-MMU the same code runs at `+0x88000000`):
//!
//! ```text
//! caller -> 0x1968 (printf-like format into buffer at [0x1C38] == 0x882A20DC)
//!   -> 0x18D4 (emit dispatch on channel state A [0x882A1CD0] / B [0x882A9584])
//!     -> 0x3890 (fan-out: drops channels 0-2, 3..5 byte-wise, 6 bulk via 0x333B8)
//!       -> 0x3814 (putc: r0 = channel, r1 = byte)
//!         -> 0x40A4 (per-channel write into RAM ring buffers)
//! ```
//!
//! Provenance: ARM disassembly of the SPL blob at those file offsets. Path B
//! of the `0x18D4` dispatch (`[0x882A1CD0] == 2` -> `mov r0, #3`, direct
//! channel-3 byte output) is additionally proven live: forcing it in the
//! `spl_vivo_primeiro_byte_na_serial` frontier test delivers the first byte
//! (`b'+'`, start of the `+dmov…` family) to the `PUTC` trap on channel 3.
//!
//! Trap `PUTC_ADDR_POS_MMU` (`0x88003814`), not pre-MMU `0x3814`: the SPL
//! enables the MMU before printing anything, so all observed output happens
//! at the VA. The same frontier test pins this.
//!
//! `0x40A4` never touches MMIO itself. Per byte it polls two RAM flags on
//! the channel's device struct: `+8` TX-ready (spins at `0x880040E4` while
//! clear; the frontier stub models "always ready") and `+20`, which selects
//! the write mode — set means direct-TX (returns on TX-complete, stubbed at
//! device `+0x14`), clear means ring-enqueue (re-enqueues until the host
//! drains). Provenance: disassembly of `0x40A4` and its `0x40D4..F8` poll;
//! behavior confirmed live by the frontier stubs (`0xB2800008 = 1`,
//! `0xB2800014 = 1`, `+20 == 0`).
//!
//! Ring layout, decoded from `0x88003DD4` (evidence, not hypothesis): the
//! table at `0x882A94FC` holds 16-byte slots (`channel << 4`); data bytes
//! land at `0x882A24FC + (channel << 12) + write_idx` — the pool holds the
//! data-area base address itself (used directly, never dereferenced), so no
//! pointer plant is needed or valid there. Slot fields: `+0` read index,
//! `+4` write index (wraps at `0x1000`), `+8` full/blocked flag, `+12`
//! ready. Ring init `0x3CEC` zeroes `+0/+4/+8` and sets `+12 = 1`
//! (`0x3D28` returns `+12`, `0x3D50` returns `+8`). An earlier harness
//! revision mistook the base for an indirection and planted/stubbed around
//! it; the live run plus agent D's pool scan corrected this — see the
//! `b2a00c10` discovery test history.
//!
//! Bring-up strategy: trap `PUTC_ADDR_POS_MMU` in the CPU backend, feed
//! `(r0, r1)` into `SerialTap`, and let execution continue. No hardware
//! model needed to read the first logs. The real UART model comes later,
//! once the drain side is traced.
//!
//! Fallback with zero backend support: after each run slice, read the ring
//! table (`RING_TABLE`) and `FORMAT_BUF` straight out of guest RAM and drain
//! host-side with `anel_bytes_novos`. If the SPL spins on a full buffer
//! (`0x40A4` polls RAM flags at device `+8`/`+20`), the host must advance
//! the read index — same helper, applied as a write. This per-slice drain is
//! implemented inline in the `b2a00c10` discovery test (working) but is not
//! yet a reusable harness.
//!
//! UNKNOWN (do not harden): which channel is UART vs USB; who the drain
//! consumer is and which MMIO it writes; who fills the `0x882A1254/58/5C`
//! device structs (their init is untraced). Channel 6 routing to `0x333B8`
//! smells like USB bulk, but that is a guess from call shape, not evidence.

/// `printf`-like formatter entry. `r0` = format string (VA in `0x8806xxxx`).
pub const PRINT_FORMAT: u32 = 0x1968;
/// Emit dispatch. Reads channel state words A `[0x882A1CD0]` and B
/// `[0x882A9584]`; path B (`[A] == 2`) emits direct channel-3 bytes.
/// Provenance: disassembly of `0x18D4`; path B proven live by the
/// `spl_vivo_primeiro_byte_na_serial` frontier test.
pub const PRINT_EMIT: u32 = 0x18D4;
/// Channel fan-out write. `r0` = channel, `r1` = ptr, `r2` = len.
/// Drops channels 0-2, byte-writes 3-5 via `PUTC_ADDR`, channel 6 bulk via
/// `0x333B8`. Provenance: disassembly of `0x3890`.
pub const CH_WRITE: u32 = 0x3890;
/// Per-byte output. **`r0` = channel, `r1` = byte. Trap here.**
///
/// Pre-MMU address (file offset = physical). All observed output happens
/// post-MMU, where the same code runs at `PUTC_ADDR_POS_MMU`: trap the alias
/// the code actually executes at. The `spl_vivo_primeiro_byte_na_serial`
/// frontier test pins this (first byte `b'+'` arrives on channel 3).
pub const PUTC_ADDR: u32 = 0x3814;
/// Post-MMU virtual address of `PUTC_ADDR` (`RAM_VIRTUAL_BASE + PUTC_ADDR`).
/// The SPL enables the MMU before printing anything, so this is the address
/// a PC trap must watch.
pub const PUTC_ADDR_POS_MMU: u32 = 0x8800_3814;
/// Per-channel ring-buffer write behind `PUTC_ADDR`. Polls device `+8`
/// (TX-ready) and selects direct-TX vs ring-enqueue by device `+20`.
/// Provenance: disassembly of `0x40A4`; stub behavior confirmed live by the
/// frontier tests.
pub const CH_PUTC: u32 = 0x40A4;
/// Ring-buffer table, 16 bytes per channel (indexed `channel << 4`).
/// Decoded from `0x88003DD4`; slot fields documented on `ANEL_LEITURA`.
pub const RING_TABLE: u32 = 0x882A_94FC;
/// Base address (in RAM) of the 4 KiB-per-channel ring data region.
/// `0x3DD4` loads pools holding this address on every byte; data lands at
/// `DATA_BASE + (channel << 12) + write_idx`. It is the area itself, not an
/// indirection: nothing dereferences it to find another pointer.
pub const DATA_BASE: u32 = 0x882A_24FC;
/// `printf` scratch buffer. `0x1968` formats the line here (`[0x1C38]`), then
/// `0x18D4` emits it — reading this after a slice shows the last line even
/// with no trap and no drain.
pub const FORMAT_BUF: u32 = 0x882A_20DC;
/// Global holding the active output channel (default 0). Read on the print
/// path; dumped live in the discovery test's slot list. Distinct from the
/// emit-dispatch state words A `[0x882A1CD0]` / B `[0x882A9584]`.
pub const CANAL_ATIVO: u32 = 0x882A_0001;
/// Pointers to the channel 3/4/5 device structs (RAM, filled at init).
/// UNKNOWN: who fills them is untraced — finding their init is the way to
/// trace the hardware drain. Polled offsets: `+8` TX-ready, `+20`
/// direct-TX select / TX-complete.
pub const DISPOSITIVO_C3: u32 = 0x882A_1254;
pub const DISPOSITIVO_C4: u32 = 0x882A_1258;
pub const DISPOSITIVO_C5: u32 = 0x882A_125C;

/// Ring entry field offsets within one 16-byte `RING_TABLE` slot.
///
/// Decoded from `0x88003DD4` (evidence): `+0` read index, `+4` write index
/// (increments per byte, wraps at `0x1000`), `+8` full/blocked flag
/// (returned by `0x3D50`; the guest spins while set), `+12` ready flag
/// (returned by `0x3D28`). Ring init `0x3CEC` zeroes `+0/+4/+8` and sets
/// `+12 = 1`.
pub const ANEL_LEITURA: usize = 0;
pub const ANEL_ESCRITA: usize = 4;
pub const ANEL_TAMANHO_DADOS: usize = 0x1000;

/// Bytes added to a ring since `leitura_idx`: `dados[leitura..escrita]`,
/// wrapping at `tamanho_dados`. Pure function over a RAM snapshot — the
/// host-side drain for early testing.
pub fn anel_bytes_novos(
    leitura_idx: usize,
    escrita_idx: usize,
    dados: &[u8],
    tamanho_dados: usize,
) -> Vec<u8> {
    let le = leitura_idx % tamanho_dados;
    let es = escrita_idx % tamanho_dados;
    if es >= le {
        dados.get(le..es.min(dados.len())).unwrap_or(&[]).to_vec()
    } else {
        let mut fora = dados.get(le..).unwrap_or(&[]).to_vec();
        fora.extend_from_slice(dados.get(..es.min(dados.len())).unwrap_or(&[]));
        fora
    }
}
/// Command/status block used by the `0x2C7xx`/`0x2C8xx` driver family.
///
/// `str cmd, [0xB2300000]` / `ldrh status, [0xB2300000, #8]` polled with
/// `tst`, data at `+12`. ~40 callers in init code (`0x125E8…`), always
/// paired with `0x1968` logging and `0x4364` delays. EBI address range, so
/// this smells like NAND/flash — NOT the UART. Recorded so nobody
/// re-discovers it while hunting the serial path.
pub const BLOCO_B23: u32 = 0xB230_0000;

/// Output channel as seen in `r0` at `PUTC_ADDR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canal {
    /// Channel 0: "current channel" — resolved via `CANAL_ATIVO`.
    Padrao,
    /// Channels 3, 4, 5: byte-wise ring-buffer path via `CH_PUTC`.
    C3,
    C4,
    C5,
    /// Channel 6: bulk path via `0x333B8`. The call edge (CH_WRITE -> 0x333B8)
    /// is evidence; the USB-bulk assignment is a guess from call shape.
    Bulk6,
    /// Anything else: not observed on this path.
    Outro(u32),
}

impl Canal {
    /// Map the raw `r0` value at `PUTC_ADDR`.
    pub fn de_r0(valor: u32) -> Self {
        match valor {
            0 => Self::Padrao,
            3 => Self::C3,
            4 => Self::C4,
            5 => Self::C5,
            6 => Self::Bulk6,
            outro => Self::Outro(outro),
        }
    }
}

/// Host-side sink for tapped `(channel, byte)` pairs.
///
/// The backend traps `PUTC_ADDR_POS_MMU`, reads `r0`/`r1`, and calls `byte()`.
/// Bytes accumulate per channel; `linhas()` returns complete `\n`-terminated
/// lines (the SPL ends most messages with `\n`), leaving partial lines
/// buffered. Keeps raw bytes (the SPL is ASCII in practice; no decoding
/// guesses here).
#[derive(Debug, Default)]
pub struct SerialTap {
    por_canal: std::collections::BTreeMap<u32, Vec<u8>>,
}

impl SerialTap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one trapped byte. Only the low 8 bits of `byte` matter.
    pub fn byte(&mut self, canal: u32, byte: u32) {
        self.por_canal
            .entry(canal)
            .or_default()
            .push((byte & 0xFF) as u8);
    }

    /// Raw buffered bytes for a channel (including any partial line).
    pub fn bytes_do_canal(&self, canal: u32) -> &[u8] {
        self.por_canal.get(&canal).map_or(&[], Vec::as_slice)
    }

    /// Drain complete `\n`-terminated lines for a channel.
    ///
    /// Returns `(canal, line bytes without terminator)` in channel order.
    /// A trailing `\r` is stripped (the SPL prints `\r\n` in places).
    pub fn linhas(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut fora = Vec::new();
        for (canal, buf) in self.por_canal.iter_mut() {
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let mut linha: Vec<u8> = buf.drain(..=pos).collect();
                linha.pop(); // `\n`
                if linha.last() == Some(&b'\r') {
                    linha.pop();
                }
                fora.push((*canal, linha));
            }
        }
        fora
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canal_mapeia_r0() {
        assert_eq!(Canal::de_r0(0), Canal::Padrao);
        assert_eq!(Canal::de_r0(3), Canal::C3);
        assert_eq!(Canal::de_r0(6), Canal::Bulk6);
        assert_eq!(Canal::de_r0(9), Canal::Outro(9));
    }

    #[test]
    fn tap_junta_linhas_por_canal() {
        let mut tap = SerialTap::new();
        for b in b"Load ADDR: 0x88000800\r\n" {
            tap.byte(3, *b as u32);
        }
        for b in b"partial" {
            tap.byte(4, *b as u32);
        }
        let linhas = tap.linhas();
        assert_eq!(linhas, vec![(3, b"Load ADDR: 0x88000800".to_vec())]);
        // Partial line stays buffered.
        assert_eq!(tap.bytes_do_canal(4), b"partial");
        assert!(tap.linhas().is_empty());
    }

    #[test]
    fn tap_guarda_somente_byte_baixo() {
        let mut tap = SerialTap::new();
        tap.byte(3, 0x1_41);
        assert_eq!(tap.bytes_do_canal(3), b"A");
    }

    #[test]
    fn anel_drena_linear_e_com_volta() {
        let dados: Vec<u8> = (0..16u8).collect();
        assert_eq!(anel_bytes_novos(2, 6, &dados, 16), vec![2, 3, 4, 5]);
        assert_eq!(anel_bytes_novos(5, 5, &dados, 16), Vec::<u8>::new());
        // Wrap: reads 14..16 then 0..3.
        assert_eq!(anel_bytes_novos(14, 3, &dados, 16), vec![14, 15, 0, 1, 2]);
    }
}
