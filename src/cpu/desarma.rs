//! Minimal ARM (A32) disassembler for halt traces.
//!
//! Covers what kernels and bootloaders actually execute around a fault:
//! branches, single and multiple transfers, data processing, multiply,
//! status access, semaphore ops and SVC. Anything else prints as
//! `.word`, which is still more useful than raw hex in a log.
//!
//! Deliberately dependency-free (capstone would add a native library,
//! which the Libretro core must not link).

const REGS: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
    "r12", "sp", "lr", "pc",
];

const CONDS: [&str; 16] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt",
    "gt", "le", "", "nv",
];

const OPS: [&str; 16] = [
    "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq",
    "cmp", "cmn", "orr", "mov", "bic", "mvn",
];

fn reg(r: u32) -> &'static str {
    REGS[(r & 15) as usize]
}

/// Shift operand text for data-processing and single-transfer offsets.
fn deslocamento(tipo: u32, qtd: u32, rm: u32, imediato: bool) -> String {
    if imediato {
        if qtd == 0 && tipo == 0 {
            String::new()
        } else {
            let nome = ["lsl", "lsr", "asr", "ror"][tipo as usize];
            format!(", {nome} #{qtd}")
        }
    } else {
        let nome = ["lsl", "lsr", "asr", "ror"][tipo as usize];
        format!(", {nome} {}", reg(rm))
    }
}

/// Disassemble one little-endian word at `addr` (used for the `pc+8`
/// of PC-relative literals and branch targets).
pub fn desarma(addr: u32, word: u32) -> String {
    let cond = CONDS[(word >> 28) as usize];
    if cond == "nv" {
        return "UNPREDICTABLE".to_string();
    }
    let cls = (word >> 25) & 7;
    // Branch / branch-with-link (bit 24 = L; BLX immediate is 0xFA).
    if cls == 0b101 && (word >> 24) != 0xFA {
        let off = sext24(word & 0x00FF_FFFF) << 2;
        let alvo = addr.wrapping_add(8).wrapping_add(off as u32);
        let nome = if word & (1 << 24) != 0 { "bl" } else { "b" };
        return format!("{nome}{cond} {alvo:#x}");
    }
    if (word >> 24) == 0xFA {
        let off = sext24(word & 0x00FF_FFFF) << 2;
        let alvo = addr.wrapping_add(8).wrapping_add(off as u32);
        // H bit (BLX halfword offset) is ignored: kernels don't use it.
        return format!("blx{cond} {alvo:#x}");
    }
    match cls {
        // Single transfer, register/extra forms and block transfer share
        // bit 27..25 == 0b000/0b100 with bit 24..20 deciding.
        _ => {}
    }
    // BLX(2)/BX, MRS/MSR, data processing with register source.
    if cls == 0b000 && (word & 0x0FF0_00F0) == 0x0120_0030 {
        let rn = (word >> 12) & 0xF;
        let rm = word & 0xF;
        let nome = if word & (1 << 22) != 0 { "msr" } else { "mrs" };
        if nome == "mrs" {
            return format!("mrs{cond} {}, CPSR", reg(rn));
        }
        let campo = (word >> 16) & 0xF;
        let alvo = if word & (1 << 22) != 0 { "SPSR" } else { "CPSR" };
        return format!("msr{cond} {alvo}_xsf /*#{campo:#x}*/, {}", reg(rm));
    }
    if cls == 0b000 && (word & 0x0FFF_0FFF) == 0x012F_FF10 {
        return format!("bx{cond} {}", reg(word & 0xF));
    }
    // MRS CPSR (0xE10F0000) and MSR immediate/register are decoded by
    // mask below together with the data-processing group.
    if (word & 0x0FFF_0FFF) == 0x010F_0000 {
        let rd = (word >> 12) & 0xF;
        return format!("mrs{cond} {}, CPSR", reg(rd));
    }
    if (word & 0x0FF0_0000) == 0x0320_0000 {
        // MSR immediate (encoding shares the data-processing space).
        let rot = ((word >> 8) & 0xF) * 2;
        let imm = (word & 0xFF).rotate_right(rot);
        let para_spsr = word & (1 << 22) != 0;
        let alvo = if para_spsr { "SPSR" } else { "CPSR" };
        let campo = (word >> 16) & 0xF;
        return format!("msr{cond} {alvo}_xsf /*#{campo:#x}*/, #{imm:#x}");
    }
    // Data processing (register/immediate) incl. MRS/MSR register forms
    // handled above, plus CLZ/Sign.
    if cls == 0b000 || cls == 0b001 {
        let opcode = (word >> 21) & 0xF;
        let s = word & (1 << 20) != 0;
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;
        // CLZ.
        if word & 0x0FFF_F0F0 == 0x016F_0F10 {
            return format!("clz{cond} {}, {}", reg(rd), reg(word & 0xF));
        }
        // MRS already handled; MSR register form.
        if (word & 0x0FBF_0FFF) == 0x0102_9000 || (word & 0x0FBF_0FFF) == 0x0122_9000 {
            let para_spsr = word & (1 << 22) != 0;
            let alvo = if para_spsr { "SPSR" } else { "CPSR" };
            let campo = (word >> 16) & 0xF;
            return format!(
                "msr{cond} {alvo}_xsf /*#{campo:#x}*/, {}",
                reg(word & 0xF)
            );
        }
        let nome = OPS[opcode as usize];
        let sufixo = if s
            && !matches!(opcode, 0b1000 | 0b1001 | 0b1010 | 0b1011)
        {
            "s"
        } else {
            ""
        };
        // MOV/MVN ignore Rn.
        let primeiro = if opcode == 0b1101 || opcode == 0b1111 {
            String::new()
        } else {
            format!("{}, ", reg(rn))
        };
        let segundo = if cls == 0b001 {
            let rot = ((word >> 8) & 0xF) * 2;
            let imm = (word & 0xFF).rotate_right(rot);
            format!("#{imm:#x}")
        } else if word & (1 << 4) == 0 {
            let tipo = (word >> 5) & 3;
            let qtd = (word >> 7) & 0x1F;
            let rm = word & 0xF;
            format!("{}{}", reg(rm), deslocamento(tipo, qtd, 0, true))
        } else {
            // Register-shifted; keep it short (rare at fault sites).
            format!("{}, ...", reg(word & 0xF))
        };
        // Test/compare have no destination.
        if matches!(opcode, 0b1000 | 0b1001 | 0b1010 | 0b1011) {
            return format!("{nome}{cond} {primeiro}{segundo}");
        }
        return format!("{nome}{sufixo}{cond} {}, {primeiro}{segundo}", reg(rd));
    }
    // Multiply.
    if cls == 0b000 && word & 0x0FC0_00F0 == 0x0000_0090 {
        let acumula = word & (1 << 21) != 0;
        let s = if word & (1 << 20) != 0 { "s" } else { "" };
        let rd = (word >> 16) & 0xF;
        let rn = (word >> 12) & 0xF;
        let rs = (word >> 8) & 0xF;
        let rm = word & 0xF;
        if acumula {
            return format!(
                "mla{s}{cond} {}, {}, {}, {}",
                reg(rd),
                reg(rm),
                reg(rs),
                reg(rn)
            );
        }
        let _ = rn;
        return format!("mul{s}{cond} {}, {}, {}", reg(rd), reg(rm), reg(rs));
    }
    // Single data transfer (word/byte, immediate/offset).
    if cls == 0b010 || cls == 0b011 {
        let p = word & (1 << 24) != 0;
        let u = word & (1 << 23) != 0;
        let b = word & (1 << 22) != 0;
        let w = word & (1 << 21) != 0;
        let l = word & (1 << 20) != 0;
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;
        let nome = if l { "ldr" } else { "str" };
        let tam = if b { "b" } else { "" };
        let sinal = if !p && w { "!" } else if p && w { "!" } else { "" };
        let desloc = if cls == 0b011 {
            // Register offset.
            let tipo = (word >> 5) & 3;
            let qtd = (word >> 7) & 0x1F;
            let rm = word & 0xF;
            let sinal2 = if u { "" } else { "-" };
            format!("[{}, {sinal2}{}{}]", reg(rn), reg(rm), deslocamento(tipo, qtd, 0, true).trim_start_matches(','))
        } else {
            let off = word & 0xFFF;
            if off == 0 && p && !w {
                format!("[{}]", reg(rn))
            } else {
                let sinal2 = if u { "" } else { "-" };
                format!("[{}, #{sinal2}{off:#x}]{sinal}", reg(rn))
            }
        };
        let _ = sinal;
        return format!("{nome}{tam}{cond} {}, {desloc}", reg(rd));
    }
    // Halfword/signed/double transfers.
    if cls == 0b000 && word & 0x0E40_0090 == 0x0040_0090 {
        let p = word & (1 << 24) != 0;
        let u = word & (1 << 23) != 0;
        let w = word & (1 << 21) != 0;
        let l = word & (1 << 20) != 0;
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;
        let op = (word >> 5) & 3;
        let nome = match (l, op) {
            (false, 1) => "strh",
            (true, 1) => "ldrh",
            (true, 2) => "ldrsb",
            (true, 3) => "ldrsh",
            (false, 2) => "lrd",
            (false, 3) => "strd",
            _ => "ldm?",
        };
        let off = if word & (1 << 22) != 0 {
            ((word >> 8) & 0xF) << 4 | (word & 0xF)
        } else {
            word & 0xF
        };
        let _ = (p, u, w);
        return format!("{nome}{cond} {}, [{}, #{off:#x}]", reg(rd), reg(rn));
    }
    // Block transfer.
    if cls == 0b100 {
        let p = word & (1 << 24) != 0;
        let u = word & (1 << 23) != 0;
        let s = word & (1 << 22) != 0;
        let w = word & (1 << 21) != 0;
        let l = word & (1 << 20) != 0;
        let rn = (word >> 16) & 0xF;
        // Compact register list with ranges (r4-r11, not r4,r5,...).
        let mut regs = String::new();
        let mut r = 0u32;
        while r < 16 {
            if word & (1 << r) == 0 {
                r += 1;
                continue;
            }
            let mut fim = r;
            while fim + 1 < 16 && word & (1 << (fim + 1)) != 0 {
                fim += 1;
            }
            if !regs.is_empty() {
                regs.push(',');
            }
            if fim > r {
                regs.push_str(&format!("{}-{}", reg(r), reg(fim)));
            } else {
                regs.push_str(reg(r));
            }
            r = fim + 1;
        }
        let modo = match (p, u) {
            (false, true) => "ia",
            (true, true) => "ib",
            (false, false) => "da",
            (true, false) => "db",
        };
        let nome = if l { "ldm" } else { "stm" };
        let bang = if w { "!" } else { "" };
        let chapeu = if s { "^" } else { "" };
        return format!("{nome}{modo}{cond} {}{bang}, {{{regs}}}{chapeu}", reg(rn));
    }
    // SWP / LDREX / STREX.
    if cls == 0b000 && word & 0x0FB0_0FF0 == 0x0100_0090 {
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;
        let rm = word & 0xF;
        if word & (1 << 23) != 0 {
            return format!("swp{cond} {}, {}, [{}]", reg(rd), reg(rm), reg(rn));
        }
        let largura = if word & (1 << 22) != 0 { "h" } else { "" };
        if word & (1 << 24) != 0 {
            return format!("strex{largura}{cond} {}, {}, [{}]", reg(rd), reg(rm), reg(rn));
        }
        return format!("ldrex{largura}{cond} {}, [{}]", reg(rd), reg(rn));
    }
    // SVC.
    if (word >> 24) == 0xEF {
        return format!("svc{cond} #{:#x}", word & 0xFF_FFFF);
    }
    // CPS (interrupt masks / mode switch).
    if (word & 0x0FF1_0000) == 0xF10_0000 || (word & 0x0FF0_0000) == 0x0100_0000 {
        return format!("cps /*#{:#x}*/", word & 0x000F_FFFF);
    }
    format!(".word {word:#010x}")
}

fn sext24(v: u32) -> i32 {
    (((v & 0xFFFFFF) ^ 0x800000) as i32).wrapping_sub(0x800000)
}

#[cfg(test)]
mod tests {
    use super::desarma;

    #[test]
    fn cobre_casos_do_boot() {
        // Straight from the live runs (immediates print in hex).
        assert_eq!(desarma(0xC00219E8, 0xE894AFF0), "ldmia r4, {r4-r11,sp,pc}");
        assert_eq!(desarma(0xFFFF0204, 0xE88D4001), "stmia sp, {r0,lr}");
        assert_eq!(desarma(0xC000E860, 0xE5837000), "str r7, [r3]");
        assert_eq!(desarma(0xC0021A7C, 0xE1B0F00E), "movs pc, lr");
        assert_eq!(desarma(0xC00219D4, 0xE282401C), "add r4, r2, #0x1c");
        assert_eq!(desarma(0xFFFF0200, 0xE24EE004), "sub lr, lr, #0x4");
        assert_eq!(desarma(0xC00219E0, 0xEB00FC9D), "bl 0xc0060c5c");
        assert_eq!(desarma(0xC000E820, 0xE59F109C), "ldr r1, [pc, #0x9c]");
        assert_eq!(desarma(0xC003DC7C, 0xE0900002), "adds r0, r0, r2");
    }
}
