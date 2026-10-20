//! SPL text output: tap points and a host-side byte sink.
//!
//! Goal: see SPL logs as early as possible. The SPL prints through a small
//! chain, confirmed by disassembly (`-b binary -m arm`, file offsets ==
//! pre-MMU physical addresses):
//!
//! ```text
//! caller -> 0x1968 (printf-like format into buffer at [0x1C38] == 0x882A20DC)
//!   -> 0x18D4 (emit dispatch on channel state)
//!     -> 0x3890 (fan-out by channel; 3..5 byte-wise, 6 bulk via 0x333B8)
//!       -> 0x3814 (putc: r0 = channel, r1 = byte)
//!         -> 0x40A4 (per-channel write into RAM ring buffers)
//! ```
//!
//! `0x40A4` never touches MMIO itself: for channels 3..5 it enqueues into a
//! ring (table at `0x882A94FC`, 16 bytes/channel, 4 KiB data buffers) and
//! polls RAM flags. The hardware drain (UART/USB registers) is a separate,
//! not-yet-traced consumer — see UNKNOWN below.
//!
//! Bring-up strategy: trap `PUTC_ADDR` in the CPU backend, feed `(r0, r1)`
//! into `SerialTap`, and let execution continue. No hardware model needed to
//! read the first logs. The real UART model comes later, once the drain side
//! is traced.
//!
//! Fallback with zero backend support: after each run slice, read the ring
//! table (`RING_TABLE`) and `FORMAT_BUF` straight out of guest RAM and drain
//! host-side with `anel_bytes_novos`. If the SPL ever spins on a full buffer
//! (`0x40A4` polls RAM flags at device `+8`/`+20`), the host must advance the
//! read index — same helper, applied as a write.
//!
//! UNKNOWN (do not harden): which channel is UART vs USB; what the drain
//! consumer is and which MMIO it writes; meaning of the `0x882A1254/58/5C`
//! device structs. Channel 6 routing to `0x333B8` smells like USB bulk, but
//! that is a guess from call shape, not evidence.

/// `printf`-like formatter entry. `r0` = format string (VA in `0x8806xxxx`).
pub const PRINT_FORMAT: u32 = 0x1968;
/// Emit dispatch. Reads channel state, calls into `CH_WRITE` / bulk path.
pub const PRINT_EMIT: u32 = 0x18D4;
/// Channel fan-out write. `r0` = channel, `r1` = ptr, `r2` = len.
pub const CH_WRITE: u32 = 0x3890;
/// Per-byte output. **`r0` = channel, `r1` = byte. Trap here.**
pub const PUTC_ADDR: u32 = 0x3814;
/// Per-channel ring-buffer write behind `PUTC_ADDR`.
pub const CH_PUTC: u32 = 0x40A4;
/// Ring-buffer table, 16 bytes per channel (indexed `channel << 4`).
pub const RING_TABLE: u32 = 0x882A_94FC;
/// Pointer (in RAM) to the 4 KiB-per-channel data region base.
/// `0x3DD4` loads it from here on every byte: data byte lands at
/// `[DATA_BASE_PTR] + (channel << 12) + write_idx`.
pub const DATA_BASE_PTR: u32 = 0x882A_24FC;
/// `printf` scratch buffer. `0x1968` formats the line here (`[0x1C38]`), then
/// `0x18D4` emits it — reading this after a slice shows the last line even
/// with no trap and no drain.
pub const FORMAT_BUF: u32 = 0x882A_20DC;
/// Global holding the active output channel (default 0).
pub const CANAL_ATIVO: u32 = 0x882A_0001;
/// Pointers to the channel 3/4/5 device structs (RAM, filled at init).
pub const DISPOSITIVO_C3: u32 = 0x882A_1254;
pub const DISPOSITIVO_C4: u32 = 0x882A_1258;
pub const DISPOSITIVO_C5: u32 = 0x882A_125C;

/// Ring entry field offsets within one 16-byte `RING_TABLE` slot.
///
/// From `0x3CEC` (init: `+0/+4/+8 = 0`, `+12 = 1`), `0x3D28` (returns `+12`),
/// `0x3D50` (returns `+8`), `0x3DD4` (write path: `+4` increments, wraps at
/// `0x1000`; `+0` compared against it). Mapping `+0 = read index`,
/// `+4 = write index` is an inference from that comparison, not a fact.
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
    /// Channel 6: bulk path via `0x333B8`. Purpose unknown (USB guess).
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
/// The backend traps `PUTC_ADDR`, reads `r0`/`r1`, and calls `byte()`.
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
