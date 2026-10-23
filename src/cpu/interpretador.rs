//! ARM1176 interpreter (A32 and Thumb), the WebAssembly core's engine.
//!
//! `dynarmic` and `unicorn` recompile the guest block to host native code and jump to
//! it. In a WebAssembly module that jump does not exist: the browser only runs Wasm. This
//! file reads the instruction from guest memory and executes it here, under the same
//! [`CpuBackend`] contract — stop on the vtable range, address bit 0 as Thumb mode, dirt
//! watch that ignores what the host wrote.
//!
//! Not measured against the JIT. The desktop stays on `dynarmic`; this goes into `wasm32`,
//! where the emitted block does not run, and into iOS, where the system does not let the
//! process map code.

use super::mem::GuestMemory;
use super::{API_BASE, API_SIZE, RETURN_MAGIC, apara_semihosting};
use super::{CpuBackend, CpuError, Reg, StopReason};

const N: u32 = 1 << 31;
const Z: u32 = 1 << 30;
const C: u32 = 1 << 29;
const V: u32 = 1 << 28;
const Q: u32 = 1 << 27;
const T: u32 = 1 << 5;
const MODO_USUARIO: u32 = 0x10;

/// Semihosting operations recorded by the `unicorn` hook. The `SVC` immediate does not change
/// course: any `SVC` looks at the operation in `r0`. The PopCap games initialize through here.
const SYS_WRITEC: u32 = 0x03;
const SYS_WRITE0: u32 = 0x04;
const MAX_SEMIHOSTING_STRING: u32 = 4096;

pub struct Interpretador {
    mem: GuestMemory,
    r: [u32; 16],
    cpsr: u32,
    instrucoes: u64,
    vigias: Vec<(u32, u32, u32, bool)>,
    semihosting: String,
    /// Address of the `LDREX` still without `STREX`. Any write drops it: it is the
    /// single-core exclusive monitor, which is what this process is.
    exclusivo: Option<u32>,
    /// Flat-model CP15 registers: packed `(opc1, CRn, CRm, opc2)` key to value.
    /// See `arm_coproc`.
    cp15: Vec<(u32, u32)>,
    /// Observational PC trap for Dream SPL bring-up: when the guest PC reaches
    /// `trap_addr` (e.g. `PUTC_ADDR = 0x3814`), the hook sees `(r0, r1)` and
    /// execution continues into the real code. The hook feeds a host-side
    /// `SerialTap`; the guest ring-buffer write still runs, so this never
    /// changes guest behavior. Survives `reset` on purpose: it is host
    /// instrumentation, not guest state.
    armadilha_pc: Option<u32>,
    gancho_pc: Option<Box<dyn FnMut(u32, u32)>>,
    /// Addressed memory traps (`trap_pc_mem`), possibly several at once.
    /// Separate from `armadilha_pc`: the live run arms PUTC (observe-only)
    /// and several NAND hooks at once, and the hooks have different
    /// signatures, so they coexist instead of sharing one slot. Each
    /// entry is `(addr, hook)`; firing one never disarms the others.
    /// The register file is passed mutably so a hook can skip guest code
    /// (NAND serve) as well as read it; hooks that only observe keep
    /// working unchanged.
    armadilhas_mem: Vec<(u32, Box<dyn FnMut(&mut GuestMemory, &mut [u32; 16])>)>,
    /// Ring of recently executed instruction PCs, oldest overwritten first.
    ///
    /// Test/debug aid for the Dream bring-up (same direction as the `--code`
    /// diagnostics debt): on a fault, the harness dumps the tail of the path
    /// instead of bisecting it one trap at a time. One store per instruction;
    /// negligible next to decode+execute. Cleared on `reset` (it describes a
    /// run, unlike the trap, which describes the harness).
    historico: Box<[u32; 2048]>,
    hist_pos: usize,
    hist_cheio: bool,
    /// Banked R13/R14 per mode (usr/sys, fiq, irq, svc, abt, und) and
    /// SPSR per exception mode. The live registers stay in `r`; the
    /// bank of the current mode is stale until `troca_modo` swaps.
    /// FIQ's R8-R12 are not banked (Dream kernel never enters FIQ).
    banco: [[u32; 2]; 6],
    spsr: [u32; 6],
    /// Level IRQ line, polled from host device state (the MSM VIC).
    fonte_irq: Option<Box<dyn FnMut(&GuestMemory) -> bool>>,
    /// Set by WFI (CP15 c7,c0,4): idle until the line rises.
    esperando: bool,
    sondagem_irq: u32,
}

impl Interpretador {
    pub fn new() -> Result<Self, CpuError> {
        Ok(Self {
            mem: GuestMemory::new(),
            r: [0; 16],
            cpsr: MODO_USUARIO,
            instrucoes: 0,
            vigias: Vec::new(),
            semihosting: String::new(),
            exclusivo: None,
            cp15: Vec::new(),
            armadilha_pc: None,
            gancho_pc: None,
            armadilhas_mem: Vec::new(),
            historico: Box::new([0; 2048]),
            hist_pos: 0,
            hist_cheio: false,
            banco: [[0; 2]; 6],
            spsr: [0; 6],
            fonte_irq: None,
            esperando: false,
            sondagem_irq: 0,
        })
    }

    /// Full architected state for halt traces: general registers,
    /// CPSR, per-mode SPSR and banked R13/R14. Inherent (not trait):
    /// only the interpreter backend needs it and the trait stays
    /// Dynarmic-compatible.
    pub fn estado_completo(&self) -> ([u32; 16], u32, [u32; 6], [[u32; 2]; 6]) {
        (self.r, self.cpsr, self.spsr, self.banco)
    }

    /// PCs of the last executed instructions, oldest first (up to 2048).
    pub fn historico(&self) -> Vec<u32> {
        if !self.hist_cheio {
            return self.historico[..self.hist_pos].to_vec();
        }
        let mut fora = Vec::with_capacity(2048);
        fora.extend_from_slice(&self.historico[self.hist_pos..]);
        fora.extend_from_slice(&self.historico[..self.hist_pos]);
        fora
    }

    pub fn semihosting(&self) -> String {
        self.semihosting.clone()
    }

    /// Arm a PC trap: `gancho(r0, r1)` runs each time the guest reaches `addr`,
    /// before the instruction there executes. For the SPL serial path, `addr`
    /// is `PUTC_ADDR` and the hook records into a `SerialTap`.
    pub fn trap_pc(&mut self, addr: u32, gancho: impl FnMut(u32, u32) + 'static) {
        self.armadilha_pc = Some(addr);
        self.gancho_pc = Some(Box::new(gancho));
    }

    /// Install the IRQ line source: `fonte(mem)` returns whether any
    /// enabled interrupt is pending. Polled between instructions while
    /// CPSR.I is clear (and while idling in WFI).
    pub fn set_fonte_irq(&mut self, fonte: impl FnMut(&GuestMemory) -> bool + 'static) {
        self.fonte_irq = Some(Box::new(fonte));
    }

    fn linha_irq(&mut self) -> bool {
        match self.fonte_irq.as_mut() {
            Some(f) => f(&self.mem),
            None => false,
        }
    }

    /// Switch CPSR (mode included), swapping banked R13/R14.
    fn troca_modo(&mut self, novo: u32) {
        // TEMP (mode dance): the 6 FIRST real switches (a!=b)
        // since reset, with no pc gate: shows when the CPU leaves the
        // initial mode (reset = USR!) for the first time.
        static mut NTM: u32 = 0;
        unsafe {
            if NTM < 6 {
                let a0 = idx_modo(self.cpsr);
                let b0 = idx_modo(novo);
                if a0 != b0 {
                    NTM += 1;
                    eprintln!(
                        "TROCA0 pc={:#x} {}->{} savesp={:#x} loadsp={:#x}",
                        self.r[15],
                        self.cpsr & 0x1F,
                        novo & 0x1F,
                        self.r[13],
                        self.banco[b0][0]
                    );
                }
            }
        }
        let a = idx_modo(self.cpsr);
        let b = idx_modo(novo);
        if a != b {
            self.banco[a] = [self.r[13], self.r[14]];
            [self.r[13], self.r[14]] = self.banco[b];
        }
        self.cpsr = novo;
    }

    fn spsr_atual(&self) -> Option<u32> {
        let i = idx_modo(self.cpsr);
        (i != 0).then(|| self.spsr[i])
    }

    /// Exception return: CPSR <- SPSR, then branch honoring the restored T.
    fn retorno_excecao(&mut self, alvo: u32) {
        // TEMP (I-change hunt): log exception returns that flip I.
        // RPX shows tick #1 entering run_posix with I=1 but tick #2
        // with I=0; no cps/msr enable fires between them, so the bit
        // must come back wrong through a restore. Cap 10.
        if let Some(spsr) = self.spsr_atual() {
            let antes_i = self.cpsr & 0x80;
            let depois_i = spsr & 0x80;
            if antes_i != depois_i {
                static mut NRET: u32 = 0;
                unsafe {
                    if NRET < 10 {
                        NRET += 1;
                        let n = NRET;
                        eprintln!("RETX#{n} alvo={alvo:#x} mode={mode:#x} I:{a}->{b}", mode = self.cpsr & 0x1F, a = antes_i != 0, b = depois_i != 0);
                    }
                }
            }
            self.troca_modo(spsr);
        }
        self.r[15] = if self.thumb() { alvo & !1 } else { alvo & !3 };
    }

    /// Take an IRQ before the instruction at `r[15]` executes.
    fn entra_irq(&mut self) {
        let velho = self.cpsr;
        // TEMP (entry audit): log pre/post CPSR + faulting pc for the
        // first deliveries. RPX shows tick #2 entering run_posix with
        // I=0 while #1 shows I=1, with no clearer in between — audit
        // whether entry itself ever fails to set I. Cap 6.
        static mut NENT: u32 = 0;
        unsafe {
            if NENT < 6 {
                NENT += 1;
                let n = NENT;
                eprintln!("ENTRA#{n} velho={velho:#x} pc={pc:#x}", pc = self.r[15]);
            }
        }
        let retorno = self.r[15].wrapping_add(4);
        // ARMv6 IRQ entry: mode IRQ, ARM state, I and A masked.
        self.troca_modo((velho & !(0x1F | T)) | 0x12 | 0x80 | 0x100);
        // IRQ-bank SP fallback: hardware reset leaves it undefined and the
        // kernel programs it in cpu_init — but the first tick can arrive
        // with it still zero (live-proven: vector prologue `stm sp,{r0,lr}`
        // faults addr=0 pc=0xFFFF0204). Park it on a private page instead
        // of faulting; the kernel's own setup overwrites this later.
        if self.r[13] == 0 {
            const PILHA_IRQ: u32 = 0xC830_0000;
            const TAM_PILHA_IRQ: usize = 0x1000;
            if self.mem.read_u32(PILHA_IRQ).is_err() {
                let _ = self.mem.map_zeroed("pilha_irq", PILHA_IRQ, TAM_PILHA_IRQ);
            }
            self.r[13] = PILHA_IRQ.wrapping_add(TAM_PILHA_IRQ as u32);
        }
        // FIQ-bank SP fallback (same root cause, proven live): a USR-mode
        // IRQ dispatches (via the 0xFFFF0200 eor-#1 trick) into FIQ mode
        // (0x10^1=0x11), and the FIQ bank is also zero at reset. Park the
        // lower half of the same page (IRQ uses the top).
        if self.banco[1][0] == 0 {
            self.banco[1][0] = 0xC830_0000u32.wrapping_add(0x800);
        }
        self.spsr[2] = velho;
        self.r[14] = retorno;
        // CP15 c1 (key 0x80) bit 13: high vectors.
        let sctlr = self.cp15.iter().find(|(k, _)| *k == 0x80).map_or(0, |(_, v)| *v);
        self.r[15] = if sctlr & (1 << 13) != 0 { 0xFFFF_0018 } else { 0x18 };
    }

    /// Remove the PC trap, if any.
    pub fn untrap_pc(&mut self) {
        self.armadilha_pc = None;
        self.gancho_pc = None;
    }

    /// Arm a memory-serving PC trap: `gancho(mem, regs)` runs each time the
    /// guest reaches `addr`, before the instruction there executes. Unlike
    /// `trap_pc` (observe `(r0, r1)` only), the hook sees the full register
    /// file and can read and write guest memory synchronously — the NAND
    /// model uses it to serve transfers inline, which a slice-boundary
    /// plant can never win (the guest consumes the buffer in the same
    /// slice). Several addresses may be armed at once (NAND model arms
    /// method-entry, memcpy and validate-return together); firing one
    /// never disarms the others. Additive on purpose: `CpuBackend` and
    /// Dynarmic are untouched, and the `(r0, r1)` trap keeps working
    /// beside it.
    ///
    /// Same address twice REPLACES the hook (no stacking): two callers
    /// arming one address silently lose the first. The live run hit this
    /// once (a length probe evicted the serve-state hook and killed all
    /// NAND serving) — merge same-address prints into one hook instead.
    pub fn trap_pc_mem(
        &mut self,
        addr: u32,
        gancho: impl FnMut(&mut GuestMemory, &mut [u32; 16]) + 'static,
    ) {
        if let Some(slot) = self.armadilhas_mem.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = Box::new(gancho);
        } else {
            // Sorted insertion (firing uses binary search).
            let pos = self.armadilhas_mem.partition_point(|(a, _)| *a < addr);
            self.armadilhas_mem.insert(pos, (addr, Box::new(gancho)));
        }
    }

    /// Remove the memory-serving PC trap at `addr`, if any. Other armed
    /// addresses keep working.
    pub fn untrap_pc_mem(&mut self, addr: u32) {
        self.armadilhas_mem.retain(|(a, _)| *a != addr);
    }

    fn thumb(&self) -> bool {
        self.cpsr & T != 0
    }

    fn flag_c(&self) -> bool {
        self.cpsr & C != 0
    }

    /// The value an instruction reads when it asks for the `PC`.
    ///
    /// On ARM the pipeline delivers the instruction address plus 8; on Thumb, plus 4. `extra`
    /// covers the shifted-by-register-amount case, where ARM delivers plus 12 — the
    /// instruction takes one extra cycle and the visible `PC` moves along.
    fn le_pc(&self, pc: u32, extra: u32) -> u32 {
        let base = if self.thumb() { 4 } else { 8 };
        pc.wrapping_add(base + extra)
    }

    fn le_reg(&self, n: u32, pc: u32, extra: u32) -> u32 {
        if n == 15 {
            self.le_pc(pc, extra)
        } else {
            self.r[n as usize]
        }
    }

    fn poe_nz(&mut self, valor: u32) {
        self.cpsr = (self.cpsr & !(N | Z))
            | if valor & 0x8000_0000 != 0 { N } else { 0 }
            | if valor == 0 { Z } else { 0 };
    }

    fn poe_c(&mut self, carry: bool) {
        if carry {
            self.cpsr |= C;
        } else {
            self.cpsr &= !C;
        }
    }

    fn poe_v(&mut self, overflow: bool) {
        if overflow {
            self.cpsr |= V;
        } else {
            self.cpsr &= !V;
        }
    }

    fn poe_q(&mut self) {
        self.cpsr |= Q;
    }

    /// Branch that does **not** switch instruction sets. `MOV PC` and `B` stay in the mode
    /// they were in; `BX` is what switches.
    fn desvia_sem_troca(&mut self, alvo: u32) {
        self.r[15] = if self.thumb() { alvo & !1 } else { alvo & !3 };
    }

    fn bx(&mut self, alvo: u32) {
        if alvo & 1 != 0 {
            self.cpsr |= T;
            self.r[15] = alvo & !1;
        } else {
            self.cpsr &= !T;
            self.r[15] = alvo & !3;
        }
    }

    fn busca(&self, addr: u32, len: u32) -> Result<u32, StopReason> {
        if addr == RETURN_MAGIC {
            return Err(StopReason::Returned);
        }
        if (API_BASE..API_BASE.saturating_add(API_SIZE)).contains(&addr) {
            return Err(StopReason::ApiCall { addr });
        }
        let bytes = self
            .mem
            .read(addr, len)
            .map_err(|_| StopReason::MemoryFault { addr, pc: addr })?;
        // `GuestMemory::executavel` requires four bytes. A Thumb at the end of the region fits in
        // two and would be refused; the right question is whether the region the read found allows
        // execution (via `busca_permitida`: binary + MRU, no scan).
        if !self.mem.busca_permitida(addr, len) {
            return Err(StopReason::MemoryFault { addr, pc: addr });
        }
        Ok(match len {
            2 => u32::from(u16::from_le_bytes([bytes[0], bytes[1]])),
            _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    fn le_mem(&self, addr: u32, len: u32, pc: u32) -> Result<u32, StopReason> {
        let bytes = self
            .mem
            .read(addr, len)
            .map_err(|_| StopReason::MemoryFault { addr, pc })?;
        Ok(match len {
            1 => u32::from(bytes[0]),
            2 => u32::from(u16::from_le_bytes([bytes[0], bytes[1]])),
            _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    fn es_mem(&mut self, addr: u32, dados: &[u8], pc: u32) -> Result<(), StopReason> {
        // VIC EN_SET/EN_CLEAR semantics (exact, per-write): gpio/vic
        // setup writes single enable bits within one slice; plain-store
        // keeps only the last (proven live: 0x982 -> 0x102, IRQ7 lost,
        // no tick, freeze). SET = OR; CLEAR applies AND-NOT to the SET
        // counterpart (and keeps its own plain store, write-only).
        if dados.len() == 4 {
            let v = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
            let alvo: Option<(u32, bool)> = match addr {
                0xE000_0030 => Some((0xE000_0030, true)),
                0xE000_0034 => Some((0xE000_0034, true)),
                0xE000_0020 => Some((0xE000_0030, false)),
                0xE000_0024 => Some((0xE000_0034, false)),
                _ => None,
            };
            if let Some((reg_set, e_set)) = alvo {
                if let Ok(atual) = self.mem.read_u32(reg_set) {
                    let novo = if e_set { atual | v } else { atual & !v };
                    let _ = self.mem.write_u32(reg_set, novo);
                }
                if e_set {
                    self.exclusivo = None;
                    self.suja(addr, 4);
                    return Ok(());
                }
            }
        }
        // Synchronous VIC refresh on timer/EN writes: the per-slice
        // plant recomputes VIC registers AFTER each run, so a MATCH
        // programmed already-in-the-past (wall-clock COUNT outruns
        // the guest) fires its one rising edge while VECTADDR still
        // holds the previous slice's 0xFFFFFFFF -> the delivery is
        // skipped as no-IRQ (live: exactly one VIDX/DISP, TICKH
        // never fired). Recomputing here, synchronously with the
        // write, makes the vector fresh at dispatch. The dispatch
        // (__irq_svc) reads VICVECTADDR (`0xE00000D0`, then `0xD4`,
        // uses the second) expecting the pending IRQ NUMBER or
        // `0xFFFFFFFF` when idle. Same formula as the plant.
        if dados.len() == 4
            && (addr == 0xE000_0030
                || addr == 0xE000_0034
                || addr == 0xE000_0020
                || addr == 0xE000_0024
                || (0xE000_1000..0xE000_1018).contains(&addr))
        {
            let v = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
            // Shadow EN (0x30/0x34 bank) with THIS write applied.
            let r = |m: &GuestMemory, a: u32| m.read_u32(a).unwrap_or(0);
            let mut en = r(&self.mem, 0xE000_0030);
            match addr {
                0xE000_0030 => en |= v,
                0xE000_0020 => en &= !v,
                _ => {}
            }
            let conta = if addr == 0xE000_1004 { v } else { r(&self.mem, 0xE000_1004) };
            let alvo = if addr == 0xE000_1000 { v } else { r(&self.mem, 0xE000_1000) };
            let conta_d = if addr == 0xE000_1014 { v } else { r(&self.mem, 0xE000_1014) };
            let alvo_d = if addr == 0xE000_1010 { v } else { r(&self.mem, 0xE000_1010) };
            let gate = r(&self.mem, 0xC02A_43EC) != 0;
            let st = r(&self.mem, 0xE000_0080);
            // Unprogrammed MATCH reads all-ones: never pending.
            let p7 = conta >= alvo && alvo != u32::MAX && en & 0x80 != 0 && gate;
            let p8 = conta_d >= alvo_d && alvo_d != u32::MAX && en & 0x100 != 0 && gate;
            let vic = (if p7 { 0x80 } else { 0 }) | (if p8 { 0x100 } else { 0 });
            let _ = self.mem.write_u32(0xE000_0000, vic);
            let vect = if p7 {
                7
            } else if p8 {
                8
            } else {
                0xFFFF_FFFF
            };
            let _ = self.mem.write_u32(0xE000_00D0, vect);
            let _ = self.mem.write_u32(0xE000_00D4, vect);
            let _ = self.mem.write_u32(0xE000_0080, st & !0x180 | vic & 0x180);
        }
        if addr == 0xE000_0030
            || addr == 0xE000_0034
            || addr == 0xE000_0020
            || addr == 0xE000_0024
            || (0xE000_1000..0xE000_1010).contains(&addr)
        {
            static mut N: u32 = 0;
            unsafe {
                if N < 30 {
                    N += 1;
                    let mut v = [0u8; 4];
                    v.copy_from_slice(&dados[..dados.len().min(4)]);
                    eprintln!("VICST pc={pc:#x} addr={addr:#x} val={:#x}", u32::from_le_bytes(v));
                }
            }
        }
        // TEMP (desc writes 0xC02A4400..0xC02A44C0): logs every store
        // into the irq_desc/action the dispatch uses, with pc. The
        // double-tick mystery needs the PENDING setter: who writes
        // desc status around f=79025/79234. Cap 30.
        if (0xC02A_4400..0xC02A_44C0).contains(&addr) {
            static mut N: u32 = 0;
            unsafe {
                if N < 30 {
                    N += 1;
                    let n = N;
                    let mut v = [0u8; 4];
                    v.copy_from_slice(&dados[..dados.len().min(4)]);
                    eprintln!("DESCWR#{n} pc={pc:#x} addr={addr:#x} val={:#x}", u32::from_le_bytes(v));
                }
            }
        }
        // TEMP (who writes B's stack): logs every store to
        // 0xC481B000 (cap 30). Silence until B = no frame was
        // pushed (the exception never happened).
        if (0xC481_0000..0xC481_2000).contains(&addr) {
            static mut N: u32 = 0;
            unsafe {
                if N < 30 {
                    N += 1;
                    let mut v = [0u8; 4];
                    v.copy_from_slice(&dados[..dados.len().min(4)]);
                    eprintln!("WSTK pc={pc:#x} addr={addr:#x} val={:#x}", u32::from_le_bytes(v));
                }
            }
        }
        // TEMP (who dirties 0xC0000100): the ATAG CORE becomes a self-pointer
        // in slice ~88271 (boot 1), and boot 2 inherits the warning. Cap 6.
        // Now with value + lr + caller-function bytes.
        if addr == 0xC000_0100 || addr == 0xC000_0104 {
            static mut N: u32 = 0;
            unsafe {
                if N < 6 {
                    N += 1;
                    let mut v = [0u8; 4];
                    v.copy_from_slice(&dados[..dados.len().min(4)]);
                    let mut f = vec![0u8; 48];
                    let base = pc.wrapping_sub(32) & !3;
                    let okf = self
                        .mem
                        .read(base, 48)
                        .map(|s| f.copy_from_slice(s))
                        .is_ok();
                    eprintln!(
                        "WATAG pc={pc:#x} addr={addr:#x} val={:#x} lr={:#x} r0={:#x} okf={okf} fn={f:02x?}",
                        u32::from_le_bytes(v),
                        self.r[14],
                        self.r[0],
                    );
                }
            }
        }
        self.mem
            .write(addr, dados)
            .map_err(|_| StopReason::MemoryFault { addr, pc })?;
        self.exclusivo = None;
        self.suja(addr, dados.len() as u32);
        Ok(())
    }

    fn suja(&mut self, addr: u32, len: u32) {
        let fim = addr.saturating_add(len);
        for vigia in &mut self.vigias {
            if addr < vigia.2 && fim > vigia.1 {
                vigia.3 = true;
            }
        }
    }

    /// `true` once the instruction has written the `PC`.
    fn passo(&mut self) -> Result<bool, StopReason> {
        let pc = self.r[15];
        if self.thumb() {
            if pc & 1 != 0 {
                return Err(StopReason::Exception { pc });
            }
            let op = self.busca(pc, 2)?;
            self.thumb_exec(op as u16, pc)
        } else {
            if pc & 3 != 0 {
                return Err(StopReason::Exception { pc });
            }
            let op = self.busca(pc, 4)?;
            self.arm_exec(op, pc)
        }
    }

    fn arm_exec(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let cond = instr >> 28;
        if cond == 0xF {
            return self.arm_incondicional(instr, pc);
        }
        if !condicao(self.cpsr, cond) {
            return Ok(false);
        }
        match (instr >> 25) & 7 {
            0b000 => self.arm_000(instr, pc),
            0b001 => self.arm_dados(instr, pc, true),
            0b010 | 0b011 => self.arm_ls(instr, pc),
            0b100 => self.arm_bloco(instr, pc),
            0b101 => self.arm_b(instr, pc),
            0b111 if instr & (1 << 24) != 0 => self.svc(pc),
            0b110 | 0b111 => self.arm_coproc(instr, pc),
            _ => Err(StopReason::Exception { pc }),
        }
    }

    /// Immediate `BLX` and the hints (`PLD`, `SETEND`). The rest of this space is not a user
    /// instruction on the ARM1176 that we execute.
    fn arm_incondicional(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        if (instr >> 25) & 7 == 0b101 {
            let h = (instr >> 24) & 1;
            let imm = sext(instr & 0x00FF_FFFF, 24) << 2;
            let alvo = pc.wrapping_add(8).wrapping_add(imm).wrapping_add(h * 2);
            self.r[14] = pc.wrapping_add(4);
            self.cpsr |= T;
            self.r[15] = alvo & !1;
            return Ok(true);
        }
        // PLD and the other preloads are hints. SETEND to big-endian is not: memory here is
        // little-endian, and executing the instruction "right" without switching the order would be
        // a lie.
        if instr & 0x0FF0_0FF0 == 0x0100_0100 && instr & (1 << 9) != 0 {
            return Err(StopReason::Exception { pc });
        }
        // CPS (change processor state): top byte 0x10 (AL forms land
        // here; conditional forms go through arm_misc, same helper).
        // Low 20 bits never equal SETEND's 0x10000/0x10200 (CPS has
        // zeros at [17:9] and imod at [19:18]; SETEND has bit 16 set).
        if instr & 0x0FF0_0000 == 0x0100_0000
            && instr & 0x000F_FFFF != 0x0001_0000
            && instr & 0x000F_FFFF != 0x0001_0200
        {
            return self.cps(instr, pc);
        }
        if (instr >> 25) & 7 == 0b010
            || (instr >> 25) & 7 == 0b011
            || instr & 0x0FFF_0FFF == 0x0100_0000
        {
            return Ok(false);
        }
        Err(StopReason::Exception { pc })
    }

    /// CPS helper shared by the unconditional decoder and `arm_misc`
    /// (conditional forms): imod 2/3 set/clear the A/I/F bits named in
    /// the instruction; imod 0 switches mode (the only form the kernel
    /// uses for that; the flat register file makes banked modes moot,
    /// and no guest exception ever needs them). No privilege check —
    /// flat model, everything runs effectively privileged (same as
    /// `msr`).
    fn cps(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let imod = (instr >> 18) & 3;
        if imod & 2 != 0 {
            let mascara = ((instr >> 8) & 1) << 8
                | ((instr >> 7) & 1) << 7
                | ((instr >> 6) & 1) << 6;
            // imod bit 0 selects: 1 = enable (CLEAR the mask bits),
            // 0 = disable (SET them). cpsid i is imod=2, cpsie i is
            // imod=3 — verified against the encodings (0xF1080080 /
            // 0xF10C0080), not just the manual's table. (This was
            // inverted for the whole bring-up: enables disabled and
            // vice versa, freezing the kernel masked after tick #1.)
            if imod & 1 != 0 {
                // TEMP (I-clear hunt): log every cps that clears I
                // (guest enable). Cap 8. The RPX probe shows tick #1
                // enters run_posix with I=1 but tick #2 with I=0 —
                // same path, so something enables mid-handler.
                if mascara & 0x80 != 0 && self.cpsr & 0x80 != 0 {
                    static mut NCPSE: u32 = 0;
                    unsafe {
                        // Gate to just before the first tick (f≈78984, i.e.
                        // ~157.97M instructions; SPL alone burns ~156M).
                        // The setup_irq triplets would otherwise eat the
                        // cap before the window opens.
                        if self.instrucoes > 157_500_000 && NCPSE < 200 {
                            NCPSE += 1;
                            let n = NCPSE;
                            eprintln!("CPSIE#{n} pc={pc:#x} mode={mode:#x}", pc = pc, mode = self.cpsr & 0x1F);
                        }
                    }
                }
                self.cpsr &= !mascara;
            } else {
                self.cpsr |= mascara;
            }
        }
        if imod == 0 {
            match instr & 0x1F {
                0x10 | 0x11 | 0x12 | 0x13 | 0x17 | 0x1B | 0x1F => {
                    self.troca_modo((self.cpsr & !0x1F) | (instr & 0x1F))
                }
                _ => return Err(StopReason::Exception { pc }),
            }
        }
        Ok(false)
    }

    fn arm_000(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let bit4 = instr & (1 << 4) != 0;
        let bit7 = instr & (1 << 7) != 0;
        if bit4 && bit7 && (instr >> 5) & 3 != 0 {
            return self.arm_extra(instr, pc);
        }
        if bit4 && bit7 {
            return self.arm_mul(instr, pc);
        }
        // TST/TEQ/CMP/CMN with S=0 are not ALU: this is the BX, CLZ, MSR, QADD space.
        if (instr >> 23) & 0x1F == 0b00010 && instr & (1 << 20) == 0 {
            return self.arm_misc(instr, pc);
        }
        self.arm_dados(instr, pc, false)
    }

    fn arm_b(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let imm = sext(instr & 0x00FF_FFFF, 24) << 2;
        let alvo = pc.wrapping_add(8).wrapping_add(imm);
        if instr & (1 << 24) != 0 {
            self.r[14] = pc.wrapping_add(4);
        }
        self.desvia_sem_troca(alvo);
        Ok(true)
    }

    fn svc(&mut self, pc: u32) -> Result<bool, StopReason> {
        let op = self.r[0];
        let arg = self.r[1];
        match op {
            SYS_WRITEC => {
                if let Ok(b) = self.le_mem(arg, 1, pc) {
                    self.semihosting.push(b as u8 as char);
                }
            }
            SYS_WRITE0 => {
                for offset in 0..MAX_SEMIHOSTING_STRING {
                    let Ok(b) = self.le_mem(arg.wrapping_add(offset), 1, pc) else {
                        break;
                    };
                    if b == 0 {
                        break;
                    }
                    self.semihosting.push(b as u8 as char);
                }
            }
            _ => {}
        }
        apara_semihosting(&mut self.semihosting);
        self.r[0] = 0;
        Ok(false)
    }

    fn arm_misc(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        if instr & 0x0FFF_FFF0 == 0x012F_FF10 {
            self.bx(self.le_reg(instr & 0xF, pc, 0));
            return Ok(true);
        }
        if instr & 0x0FFF_FFF0 == 0x012F_FF30 {
            self.r[14] = pc.wrapping_add(4);
            self.bx(self.le_reg(instr & 0xF, pc, 0));
            return Ok(true);
        }
        if instr & 0x0FFF_0FF0 == 0x016F_0F10 {
            let rm = self.le_reg(instr & 0xF, pc, 0);
            let rd = (instr >> 12) & 0xF;
            return self.poe_rd(rd, rm.leading_zeros(), pc);
        }
        if instr & 0x0FFF_0FFF == 0x010F_0000 {
            let rd = (instr >> 12) & 0xF;
            return self.poe_rd(rd, self.cpsr, pc);
        }
        if instr & 0x0FFF_0FFF == 0x014F_0000 {
            let rd = (instr >> 12) & 0xF;
            let v = self.spsr_atual().unwrap_or(self.cpsr);
            return self.poe_rd(rd, v, pc);
        }
        if instr & 0x0FB0_FFF0 == 0x0120_F000 {
            let valor = self.le_reg(instr & 0xF, pc, 0);
            self.msr((instr >> 16) & 0xF, valor, instr & (1 << 22) != 0, pc);
            return Ok(false);
        }
        if instr & 0x0FF0_00F0 == 0x0120_0070 {
            return Err(StopReason::Exception { pc });
        }
        // QADD / QSUB / QDADD / QDSUB: bits 7–4 = 0101.
        if instr & 0x0F90_00F0 == 0x0100_0050 {
            return self.arm_qadd(instr, pc);
        }
        // SMULxy / SMLAxy / SMULWy / SMLAWy: bit 7 set and bit 4 clear.
        if instr & 0x0F00_0090 == 0x0100_0080 {
            return self.arm_dsp_mul(instr, pc);
        }
        // CPS (conditional forms; AL forms go through
        // `arm_incondicional`). Placed last: tighter masks win first.
        if instr & 0x0FF0_0000 == 0x0100_0000
            && instr & 0x000F_FFFF != 0x0001_0000
            && instr & 0x000F_FFFF != 0x0001_0200
        {
            return self.cps(instr, pc);
        }
        Err(StopReason::Exception { pc })
    }

    fn arm_qadd(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let rn = self.le_reg((instr >> 16) & 0xF, pc, 0) as i32 as i64;
        let rm = self.le_reg(instr & 0xF, pc, 0) as i32 as i64;
        let op = (instr >> 21) & 3;
        let (dobro, sat1) = if op & 2 != 0 {
            sat_i32(rm.saturating_mul(2))
        } else {
            (rm, false)
        };
        // The saturated double already sets Q, even when the following add fits.
        if sat1 {
            self.poe_q();
        }
        let soma = match op {
            0 | 2 => rn + dobro,
            _ => rn - dobro,
        };
        let (valor, sat2) = sat_i32(soma);
        if sat2 {
            self.poe_q();
        }
        self.poe_rd((instr >> 12) & 0xF, valor as u32, pc)
    }

    fn arm_dsp_mul(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let rd = (instr >> 12) & 0xF;
        let rn = self.le_reg((instr >> 16) & 0xF, pc, 0);
        let rs = self.le_reg((instr >> 8) & 0xF, pc, 0);
        let rm = self.le_reg(instr & 0xF, pc, 0);
        let x = (instr >> 5) & 1 != 0;
        let y = (instr >> 6) & 1 != 0;
        // Bits 22–21 separate the forms; bit 5 (x) separates SMULW from SMLAW within the same.
        let produto: i64 = match (instr >> 21) & 3 {
            // SMLAxy: accumulates the product of the halves into Rn.
            0 => {
                let (soma, sat) =
                    sat_i32(meia(rm, x) as i64 * meia(rs, y) as i64 + rn as i32 as i64);
                if sat {
                    self.poe_q();
                }
                soma
            }
            // SMLAWy (x = 0) accumulates; SMULWy (x = 1) does not. The SMULW Rn field is zero in
            // the encoding, but that names r0 — it must not enter the sum.
            1 => {
                let p = ((rm as i32 as i64) * meia(rs, y) as i64) >> 16;
                if x {
                    p
                } else {
                    let (soma, sat) = sat_i32(p + rn as i32 as i64);
                    if sat {
                        self.poe_q();
                    }
                    soma
                }
            }
            // SMULxy: just the product, no accumulator and no flag.
            3 => meia(rm, x) as i64 * meia(rs, y) as i64,
            _ => return Err(StopReason::Exception { pc }),
        };
        self.poe_rd(rd, produto as u32, pc)
    }

    fn msr(&mut self, campo: u32, valor: u32, para_spsr: bool, pc: u32) {
        // User mode may only write the flags; privileged modes also the
        // control byte (mode, I, F). T is never written by MSR CPSR.
        let privilegiado = self.cpsr & 0x1F != MODO_USUARIO;
        let mut mascara = 0;
        if campo & 0x8 != 0 {
            mascara |= 0xFF00_0000;
        }
        if para_spsr {
            if campo & 0x4 != 0 { mascara |= 0x00FF_0000; }
            if campo & 0x2 != 0 { mascara |= 0x0000_FF00; }
            if campo & 0x1 != 0 { mascara |= 0x0000_00FF; }
            let i = idx_modo(self.cpsr);
            if i != 0 {
                self.spsr[i] = (self.spsr[i] & !mascara) | (valor & mascara);
            }
            return;
        }
        // FLAT MODEL (2026-10-22, live-proven): the kernel believes it is
        // in SVC since head.S (`msr cpsr_c, #SVC`), but reset leaves USR
        // and the privilege gate silently dropped the switch — everything
        // ran USR (SVC/FIQ banks zeroed, USR-mode IRQ going to __irq_usr
        // with no stack). Flat model = everything effectively privileged
        // (as `cps` already did): always honor the control byte. Logs
        // when honoring from USR.
        let era_usr = self.cpsr & 0x1F == MODO_USUARIO;
        if !privilegiado {
            static mut NMSR: u32 = 0;
            unsafe {
                if NMSR < 6 && campo & 0x1 != 0 && (valor & 0x1F) != (self.cpsr & 0x1F) {
                    NMSR += 1;
                    eprintln!("MSRHONR pc={:#x} {:#x}->{:#x}", pc, self.cpsr & 0x1F, valor & 0x1F);
                }
            }
            mascara |= 0xDF;
        } else if campo & 0x1 != 0 {
            mascara |= 0xDF;
        }
        let novo = (self.cpsr & !mascara) | (valor & mascara);
        // TEMP (I-clear hunt): log every msr-to-CPSR that clears I.
        // Cap 8. Companion to the cps() probe above.
        if !para_spsr && self.cpsr & 0x80 != 0 && novo & 0x80 == 0 {
            static mut NMSRE: u32 = 0;
            unsafe {
                if NMSRE < 200 {
                    NMSRE += 1;
                    let n = NMSRE;
                    eprintln!("MSRIE#{n} pc={pc:#x} mode={mode:#x}", pc = pc, mode = self.cpsr & 0x1F);
                }
            }
        }
        self.troca_modo(novo);
    }

    fn arm_dados(&mut self, instr: u32, pc: u32, imediato: bool) -> Result<bool, StopReason> {
        let opcode = (instr >> 21) & 0xF;
        let s = instr & (1 << 20) != 0;
        let rn_i = (instr >> 16) & 0xF;
        let rd = (instr >> 12) & 0xF;
        if (8..12).contains(&opcode) && !s {
            if imediato && (opcode == 0b1001 || opcode == 0b1011) && rd == 0xF {
                // Immediate MSR: the encoding splits the immediate with the data-processing shifter.
                let imm = instr & 0xFF;
                let rot = ((instr >> 8) & 0xF) * 2;
                self.msr((instr >> 16) & 0xF, imm.rotate_right(rot), opcode == 0b1011, pc);
                return Ok(false);
            }
            return Err(StopReason::Exception { pc });
        }
        let extra = u32::from(!imediato && instr & (1 << 4) != 0) * 4;
        let (operando, carry_sh) = if imediato {
            let imm = instr & 0xFF;
            let rot = ((instr >> 8) & 0xF) * 2;
            let valor = imm.rotate_right(rot);
            let carry = if rot == 0 {
                self.flag_c()
            } else {
                valor & 0x8000_0000 != 0
            };
            (valor, carry)
        } else {
            self.operando_reg(instr, pc)?
        };
        let a = self.le_reg(rn_i, pc, extra);
        let c_in = self.flag_c();
        let (valor, escreve, logico, c, v) = alu(opcode, a, operando, c_in);
        if s && rd == 15 {
            // Data processing with S=1 to the PC (e.g. `MOVS pc, lr`,
            // `SUBS pc, lr, #4`): exception return, CPSR <- SPSR. In
            // usr/sys (no SPSR) it stays a plain branch.
            self.retorno_excecao(valor);
            return Ok(true);
        }
        if s {
            self.poe_nz(valor);
            if logico {
                self.poe_c(carry_sh);
            } else {
                self.poe_c(c);
                self.poe_v(v);
            }
        }
        if escreve {
            self.poe_rd(rd, valor, pc)
        } else {
            Ok(false)
        }
    }

    fn operando_reg(&mut self, instr: u32, pc: u32) -> Result<(u32, bool), StopReason> {
        let rm = self.le_reg(instr & 0xF, pc, u32::from(instr & (1 << 4) != 0) * 4);
        let tipo = (instr >> 5) & 3;
        let (quant, imediato) = if instr & (1 << 4) != 0 {
            let rs = self.le_reg((instr >> 8) & 0xF, pc, 4);
            (rs & 0xFF, false)
        } else {
            ((instr >> 7) & 0x1F, true)
        };
        Ok(desloca(rm, tipo, quant, self.flag_c(), imediato))
    }

    fn poe_rd(&mut self, rd: u32, valor: u32, _pc: u32) -> Result<bool, StopReason> {
        if rd == 15 {
            self.desvia_sem_troca(valor);
            Ok(true)
        } else {
            self.r[rd as usize] = valor;
            Ok(false)
        }
    }

    fn poe_carga_pc(&mut self, rd: u32, valor: u32) -> bool {
        if rd == 15 {
            // LDR/LDM to the PC switch mode on bit 0. Data processing does not switch.
            self.bx(valor);
            true
        } else {
            self.r[rd as usize] = valor;
            false
        }
    }

    fn arm_ls(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let forma_reg = (instr >> 25) & 1 == 1;
        if forma_reg && instr & (1 << 4) != 0 {
            return self.arm_media(instr, pc);
        }
        let p = instr & (1 << 24) != 0;
        let u = instr & (1 << 23) != 0;
        let b = instr & (1 << 22) != 0;
        let w = instr & (1 << 21) != 0;
        let l = instr & (1 << 20) != 0;
        let rn = (instr >> 16) & 0xF;
        let rd = (instr >> 12) & 0xF;
        let offset = if forma_reg {
            let (valor, _) = self.operando_reg(instr, pc)?;
            valor
        } else {
            instr & 0xFFF
        };
        let base = self.le_reg(rn, pc, 0);
        let modificado = if u {
            base.wrapping_add(offset)
        } else {
            base.wrapping_sub(offset)
        };
        let endereco = if p { modificado } else { base };
        let saltou = if l {
            let valor = if b {
                self.le_mem(endereco, 1, pc)?
            } else {
                self.le_mem(endereco, 4, pc)?
            };
            self.poe_carga_pc(rd, valor)
        } else {
            let valor = self.le_reg(rd, pc, 0);
            if b {
                self.es_mem(endereco, &[valor as u8], pc)?;
            } else {
                self.es_mem(endereco, &valor.to_le_bytes(), pc)?;
            }
            false
        };
        if (w || !p) && rn != 15 {
            self.r[rn as usize] = modificado;
        }
        Ok(saltou)
    }

    fn arm_extra(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let p = instr & (1 << 24) != 0;
        let u = instr & (1 << 23) != 0;
        let i = instr & (1 << 22) != 0;
        let w = instr & (1 << 21) != 0;
        let l = instr & (1 << 20) != 0;
        let rn = (instr >> 16) & 0xF;
        let rd = (instr >> 12) & 0xF;
        let sh = (instr >> 5) & 3;
        let offset = if i {
            ((instr >> 4) & 0xF0) | (instr & 0xF)
        } else {
            self.le_reg(instr & 0xF, pc, 0)
        };
        let base = self.le_reg(rn, pc, 0);
        let modificado = if u {
            base.wrapping_add(offset)
        } else {
            base.wrapping_sub(offset)
        };
        let endereco = if p { modificado } else { base };
        // sh: 1 unsigned half, 2 signed byte (or double, when storing), 3 signed half.
        let saltou = match (l, sh) {
            (false, 1) => {
                let valor = self.le_reg(rd, pc, 0);
                self.es_mem(endereco, &(valor as u16).to_le_bytes(), pc)?;
                false
            }
            (true, 1) => {
                let valor = self.le_mem(endereco, 2, pc)?;
                self.poe_carga_pc(rd, valor)
            }
            (true, 2) => {
                let valor = self.le_mem(endereco, 1, pc)? as i8 as i32 as u32;
                self.poe_carga_pc(rd, valor)
            }
            (true, 3) => {
                let valor = self.le_mem(endereco, 2, pc)? as i16 as i32 as u32;
                self.poe_carga_pc(rd, valor)
            }
            (false, 2) => {
                // LDRD encoded with L=0 and S=1 H=0 is STRD? No: L=0 S=1 H=0 is LDRD.
                // The table: L=0 S=1 H=0 loads the pair. Who stores the pair is L=0 S=1 H=1.
                let lo = self.le_mem(endereco, 4, pc)?;
                let hi = self.le_mem(endereco.wrapping_add(4), 4, pc)?;
                let s1 = self.poe_carga_pc(rd, lo);
                let s2 = self.poe_carga_pc(rd.wrapping_add(1) & 0xF, hi);
                s1 || s2
            }
            (false, 3) => {
                let lo = self.le_reg(rd, pc, 0);
                let hi = self.le_reg(rd.wrapping_add(1) & 0xF, pc, 0);
                self.es_mem(endereco, &lo.to_le_bytes(), pc)?;
                self.es_mem(endereco.wrapping_add(4), &hi.to_le_bytes(), pc)?;
                false
            }
            _ => return Err(StopReason::Exception { pc }),
        };
        if (w || !p) && rn != 15 {
            self.r[rn as usize] = modificado;
        }
        Ok(saltou)
    }

    fn arm_bloco(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let p = instr & (1 << 24) != 0;
        let u = instr & (1 << 23) != 0;
        let s = instr & (1 << 22) != 0;
        let w = instr & (1 << 21) != 0;
        let l = instr & (1 << 20) != 0;
        let rn = (instr >> 16) & 0xF;
        let lista = instr & 0xFFFF;
        let n = lista.count_ones();
        if n == 0 {
            return Err(StopReason::Exception { pc });
        }
        // S bit: with PC in an LDM list it is an exception return;
        // otherwise the transfer uses the user-mode bank (R13/R14).
        let retorno = s && l && lista & (1 << 15) != 0;
        let banco_usr = s && !retorno && idx_modo(self.cpsr) != 0;
        let bytes = n * 4;
        let base = self.le_reg(rn, pc, 0);
        let (mut endereco, novo) = match (u, p) {
            (true, false) => (base, base.wrapping_add(bytes)),
            (true, true) => (base.wrapping_add(4), base.wrapping_add(bytes)),
            (false, false) => (
                base.wrapping_sub(bytes).wrapping_add(4),
                base.wrapping_sub(bytes),
            ),
            (false, true) => (base.wrapping_sub(bytes), base.wrapping_sub(bytes)),
        };
        let mut saltou = false;
        let mut pc_retorno = None;
        if l {
            let mut valores = Vec::with_capacity(n as usize);
            let mut cursor = endereco;
            for _ in 0..n {
                valores.push(self.le_mem(cursor, 4, pc)?);
                cursor = cursor.wrapping_add(4);
            }
            let mut i = 0;
            for reg in 0..16 {
                if lista & (1 << reg) != 0 {
                    if banco_usr && (reg == 13 || reg == 14) {
                        self.banco[0][reg as usize - 13] = valores[i];
                    } else if retorno && reg == 15 {
                        // Applied after writeback (old mode's Rn).
                        pc_retorno = Some(valores[i]);
                        saltou = true;
                    } else if self.poe_carga_pc(reg, valores[i]) {
                        saltou = true;
                    }
                    i += 1;
                }
            }
        } else {
            for reg in 0..16 {
                if lista & (1 << reg) != 0 {
                    let valor = if banco_usr && (reg == 13 || reg == 14) {
                        self.banco[0][reg as usize - 13]
                    } else {
                        self.le_reg(reg, pc, 0)
                    };
                    self.es_mem(endereco, &valor.to_le_bytes(), pc)?;
                    endereco = endereco.wrapping_add(4);
                }
            }
        }
        if w && rn != 15 && (l && lista & (1 << rn) == 0 || !l) {
            self.r[rn as usize] = novo;
        }
        if let Some(alvo) = pc_retorno {
            self.retorno_excecao(alvo);
        }
        Ok(saltou)
    }

    fn arm_mul(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        // SWP and LDREX/STREX share bit 23 with the multiply family, but the rest of the
        // mask does not: handling both before `op` keeps a SWP from being read as UMULL.
        if instr & 0x0FB0_0FF0 == 0x0100_0090 {
            return self.arm_swp(instr, pc);
        }
        if instr & 0x0FF0_0FFF == 0x0190_0F9F || instr & 0x0FF0_0FF0 == 0x0180_0F90 {
            return self.arm_exclusivo(instr, pc);
        }
        let s = instr & (1 << 20) != 0;
        let rd = (instr >> 16) & 0xF;
        let rn = (instr >> 12) & 0xF;
        let rs = self.le_reg((instr >> 8) & 0xF, pc, 0);
        let rm = self.le_reg(instr & 0xF, pc, 0);
        let op = (instr >> 21) & 0xF;
        let saltou = match op {
            0b0000 => {
                // MUL Rd, Rm, Rs. The Rn field must be zero; otherwise it is still MUL on v4.
                let valor = rm.wrapping_mul(rs);
                if s {
                    self.poe_nz(valor);
                }
                self.poe_rd(rd, valor, pc)?
            }
            0b0001 => {
                let acc = self.le_reg(rn, pc, 0);
                let valor = rm.wrapping_mul(rs).wrapping_add(acc);
                if s {
                    self.poe_nz(valor);
                }
                self.poe_rd(rd, valor, pc)?
            }
            0b0100 | 0b0101 | 0b0110 | 0b0111 => {
                let com_sinal = op & 0b0010 != 0;
                let acumula = op & 1 != 0;
                let produto = if com_sinal {
                    (rm as i32 as i64).wrapping_mul(rs as i32 as i64) as u64
                } else {
                    u64::from(rm).wrapping_mul(u64::from(rs))
                };
                let produto = if acumula {
                    let lo = self.le_reg(rn, pc, 0);
                    let hi = self.le_reg(rd, pc, 0);
                    produto.wrapping_add(u64::from(lo) | (u64::from(hi) << 32))
                } else {
                    produto
                };
                let lo = produto as u32;
                let hi = (produto >> 32) as u32;
                if s {
                    let flags = if hi & 0x8000_0000 != 0 { N } else { 0 }
                        | if produto == 0 { Z } else { 0 };
                    self.cpsr = (self.cpsr & !(N | Z)) | flags;
                }
                let s1 = self.poe_rd(rn, lo, pc)?;
                let s2 = self.poe_rd(rd, hi, pc)?;
                s1 || s2
            }
            _ => return Err(StopReason::Exception { pc }),
        };
        Ok(saltou)
    }

    fn arm_swp(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        if instr & 0x0FB0_0FF0 != 0x0100_0090 {
            return Err(StopReason::Exception { pc });
        }
        let rn = (instr >> 16) & 0xF;
        let rd = (instr >> 12) & 0xF;
        let rm = self.le_reg(instr & 0xF, pc, 0);
        let addr = self.le_reg(rn, pc, 0);
        let byte = instr & (1 << 22) != 0;
        if byte {
            let velho = self.le_mem(addr, 1, pc)?;
            self.es_mem(addr, &[rm as u8], pc)?;
            self.poe_rd(rd, velho, pc)
        } else {
            let velho = self.le_mem(addr, 4, pc)?;
            self.es_mem(addr, &rm.to_le_bytes(), pc)?;
            self.poe_rd(rd, velho, pc)
        }
    }

    fn arm_exclusivo(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let rn = (instr >> 16) & 0xF;
        let rd = (instr >> 12) & 0xF;
        let addr = self.le_reg(rn, pc, 0);
        // LDREX: bits 27–20 = 0001 1001. STREX: 0001 1000.
        if instr & 0x0FF0_0FFF == 0x0190_0F9F {
            let valor = self.le_mem(addr, 4, pc)?;
            self.exclusivo = Some(addr);
            return self.poe_rd(rd, valor, pc);
        }
        if instr & 0x0FF0_0FF0 == 0x0180_0F90 {
            let rm = self.le_reg(instr & 0xF, pc, 0);
            let ok = self.exclusivo == Some(addr);
            self.exclusivo = None;
            if ok {
                self.es_mem(addr, &rm.to_le_bytes(), pc)?;
            }
            return self.poe_rd(rd, u32::from(!ok), pc);
        }
        Err(StopReason::Exception { pc })
    }

    /// MCR/MRC to p15 under a flat-memory hypothesis.
    ///
    /// The Dream SPL enables the MMU early, but the initial map already covers
    /// both sides of every alias it uses (pre-MMU code at `0x0`, post-MMU entry
    /// at `0x88000800`), so translation, cache and barrier ops are accepted
    /// without changing the mapping: MCR stores the value under its packed
    /// `(opc1, CRn, CRm, opc2)` key, MRC returns the stored value (0 when the
    /// key was never written — unmodeled ID/feature registers read as 0,
    /// except Main ID, seeded at reset with the ARM1136EJ-S ID).
    /// Anything that is not an MCR/MRC to p15 (CDP, LDC/STC, other
    /// coprocessors, MRC with Rd == 15 setting the flags) faults: accepting
    /// those silently would hide real behavior.
    fn arm_coproc(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        if (instr >> 24) & 0xF != 0xE || instr & (1 << 4) == 0 {
            // TEMP (kernel CP15): which instruction fails.
            eprintln!("COPROC unk {instr:#x} @{pc:#x}");
            return Err(StopReason::Exception { pc });
        }
        if (instr >> 8) & 0xF != 0xF {
            eprintln!("COPROC n-p15 {instr:#x} @{pc:#x}");
            return Err(StopReason::Exception { pc });
        }
        let chave = ((instr >> 21) & 7) << 11 | ((instr >> 16) & 0xF) << 7 | (instr & 0xF) << 3 | (instr >> 5) & 7;
        let rd = (instr >> 12) & 0xF;
        if instr & (1 << 20) == 0 {
            // MCR p15, 0, Rd, c7, c0, 4: wait for interrupt.
            if chave == (7 << 7) | 4 {
                self.esperando = true;
                return Ok(false);
            }
            let valor = self.le_reg(rd, pc, 0);
            match self.cp15.iter_mut().find(|(k, _)| *k == chave) {
                Some(slot) => slot.1 = valor,
                None => self.cp15.push((chave, valor)),
            }
            Ok(false)
        } else {
            if rd == 15 {
                // TEMP (kernel CP15): MRC with Rd==15 (flags) — the kernel
                // uses it for cache test-and-clean.
                eprintln!("COPROC rd15 {instr:#x} @{pc:#x}");
                return Err(StopReason::Exception { pc });
            }
            let valor = self.cp15.iter().find(|(k, _)| *k == chave).map_or(0, |(_, v)| *v);
            self.r[rd as usize] = valor;
            Ok(false)
        }
    }

    fn arm_media(&mut self, instr: u32, pc: u32) -> Result<bool, StopReason> {
        let rd = (instr >> 12) & 0xF;
        let rn = (instr >> 16) & 0xF;
        let rm = self.le_reg(instr & 0xF, pc, 0);
        let cabeca = (instr >> 20) & 0xFF;
        // REV / REV16 / REVSH sit in the middle of the extension space, with Rn = 15 and their own
        // opcode in bits 11–4.
        if instr & 0x0FFF_0FF0 == 0x06BF_0F30 {
            return self.poe_rd(rd, rm.swap_bytes(), pc);
        }
        if instr & 0x0FFF_0FF0 == 0x06BF_0FB0 {
            let valor = ((rm & 0x00FF_00FF) << 8) | ((rm & 0xFF00_FF00) >> 8);
            return self.poe_rd(rd, valor, pc);
        }
        if instr & 0x0FFF_0FF0 == 0x06FF_0FB0 {
            let valor = (rm as u16).swap_bytes() as i16 as i32 as u32;
            return self.poe_rd(rd, valor, pc);
        }
        if matches!(cabeca, 0x6A | 0x6B | 0x6E | 0x6F) && instr & 0x70 == 0x70 {
            let rot = ((instr >> 10) & 3) * 8;
            let girado = rm.rotate_right(rot);
            let meia = cabeca & 1 == 1;
            let sinal = cabeca & 4 == 0;
            let estendido = if meia {
                if sinal {
                    girado as u16 as i16 as i32 as u32
                } else {
                    u32::from(girado as u16)
                }
            } else if sinal {
                girado as u8 as i8 as i32 as u32
            } else {
                u32::from(girado as u8)
            };
            let valor = if rn == 15 {
                estendido
            } else {
                self.le_reg(rn, pc, 0).wrapping_add(estendido)
            };
            return self.poe_rd(rd, valor, pc);
        }
        // SSAT is 0110101x, USAT is 0110111x. The remaining bit is the saturation immediate, and
        // bits 5–4 = 01 separate this from the extension, which already returned above.
        if matches!(cabeca & 0xFE, 0x6A | 0x6E) && instr & 0x30 == 0x10 {
            return self.arm_sat(instr, pc, cabeca & 0xFE == 0x6A);
        }
        Err(StopReason::Exception { pc })
    }

    fn arm_sat(&mut self, instr: u32, pc: u32, com_sinal: bool) -> Result<bool, StopReason> {
        let rd = (instr >> 12) & 0xF;
        let rn = self.le_reg(instr & 0xF, pc, 0);
        let sat_imm = (instr >> 16) & 0x1F;
        let sh = (instr >> 6) & 1;
        let imm5 = (instr >> 7) & 0x1F;
        let mut valor = rn as i32 as i64;
        if sh == 0 {
            valor <<= imm5;
        } else {
            let q = if imm5 == 0 { 32 } else { imm5 };
            valor >>= q;
        }
        let (saida, sat) = if com_sinal {
            let bits = sat_imm + 1;
            let max = (1i64 << (bits - 1)) - 1;
            let min = -(1i64 << (bits - 1));
            if valor > max {
                (max as u32, true)
            } else if valor < min {
                (min as u32, true)
            } else {
                (valor as u32, false)
            }
        } else {
            let max = if sat_imm == 31 {
                u32::MAX as i64
            } else {
                (1i64 << sat_imm) - 1
            };
            if valor < 0 {
                (0, true)
            } else if valor > max {
                (max as u32, true)
            } else {
                (valor as u32, false)
            }
        };
        if sat {
            self.poe_q();
        }
        self.poe_rd(rd, saida, pc)
    }

    fn thumb_exec(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let op = instr >> 11;
        match op {
            0b00000 | 0b00001 | 0b00010 => self.thumb_desloca_imm(instr, pc),
            0b00011 => self.thumb_add_sub(instr, pc),
            0b00100 | 0b00101 | 0b00110 | 0b00111 => self.thumb_imm(instr, pc),
            0b01000 => {
                if instr & (1 << 10) == 0 {
                    self.thumb_alu(instr, pc)
                } else {
                    self.thumb_alta(instr, pc)
                }
            }
            0b01001 => self.thumb_ldr_pc(instr, pc),
            0b01010 | 0b01011 => self.thumb_ls_reg(instr, pc),
            0b01100 | 0b01101 | 0b01110 | 0b01111 => self.thumb_ls_imm(instr, pc, false),
            0b10000 | 0b10001 => self.thumb_ls_imm(instr, pc, true),
            0b10010 | 0b10011 => self.thumb_ls_sp(instr, pc),
            0b10100 | 0b10101 => self.thumb_adr(instr, pc),
            0b10110 | 0b10111 => self.thumb_misc(instr, pc),
            0b11000 | 0b11001 => self.thumb_bloco(instr, pc),
            0b11010 | 0b11011 => self.thumb_bcond(instr, pc),
            0b11100 => {
                let imm = sext(u32::from(instr & 0x7FF), 11) << 1;
                self.desvia_sem_troca(pc.wrapping_add(4).wrapping_add(imm));
                Ok(true)
            }
            0b11101 | 0b11110 | 0b11111 => self.thumb_bl(instr, pc),
            _ => Err(StopReason::Exception { pc }),
        }
    }

    fn thumb_desloca_imm(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let tipo = u32::from((instr >> 11) & 3);
        let quant = u32::from((instr >> 6) & 0x1F);
        let rm = self.le_reg(u32::from((instr >> 3) & 7), pc, 0);
        let rd = u32::from(instr & 7);
        let (valor, carry) = desloca(rm, tipo, quant, self.flag_c(), true);
        self.poe_nz(valor);
        self.poe_c(carry);
        self.r[rd as usize] = valor;
        Ok(false)
    }

    fn thumb_add_sub(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rd = u32::from(instr & 7);
        let rn = self.le_reg(u32::from((instr >> 3) & 7), pc, 0);
        let imediato = instr & (1 << 10) != 0;
        let sub = instr & (1 << 9) != 0;
        let op = if imediato {
            u32::from((instr >> 6) & 7)
        } else {
            self.le_reg(u32::from((instr >> 6) & 7), pc, 0)
        };
        let (valor, c, v) = if sub {
            subtracao(rn, op, 0)
        } else {
            adicao(rn, op, 0)
        };
        self.poe_nz(valor);
        self.poe_c(c);
        self.poe_v(v);
        self.r[rd as usize] = valor;
        Ok(false)
    }

    fn thumb_imm(&mut self, instr: u16, _pc: u32) -> Result<bool, StopReason> {
        let kind = (instr >> 11) & 3;
        let rd = u32::from((instr >> 8) & 7);
        let imm = u32::from(instr & 0xFF);
        let atual = self.r[rd as usize];
        match kind {
            0 => {
                self.r[rd as usize] = imm;
                self.poe_nz(imm);
            }
            1 => {
                let (valor, c, v) = subtracao(atual, imm, 0);
                self.poe_nz(valor);
                self.poe_c(c);
                self.poe_v(v);
            }
            2 => {
                let (valor, c, v) = adicao(atual, imm, 0);
                self.r[rd as usize] = valor;
                self.poe_nz(valor);
                self.poe_c(c);
                self.poe_v(v);
            }
            _ => {
                let (valor, c, v) = subtracao(atual, imm, 0);
                self.r[rd as usize] = valor;
                self.poe_nz(valor);
                self.poe_c(c);
                self.poe_v(v);
            }
        }
        Ok(false)
    }

    fn thumb_alu(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let op = (instr >> 6) & 0xF;
        let rm = self.le_reg(u32::from((instr >> 3) & 7), pc, 0);
        let rd_i = u32::from(instr & 7);
        let rd = self.r[rd_i as usize];
        let c_in = self.flag_c();
        let (valor, logico, c, v, escreve) = match op {
            0x0 => (rd & rm, true, c_in, false, true),
            0x1 => (rd ^ rm, true, c_in, false, true),
            0x2 => {
                let (v, c) = desloca(rd, 0, rm & 0xFF, c_in, false);
                (v, true, c, false, true)
            }
            0x3 => {
                let (v, c) = desloca(rd, 1, rm & 0xFF, c_in, false);
                (v, true, c, false, true)
            }
            0x4 => {
                let (v, c) = desloca(rd, 2, rm & 0xFF, c_in, false);
                (v, true, c, false, true)
            }
            0x5 => {
                let (v, c, ov) = adicao(rd, rm, u32::from(c_in));
                (v, false, c, ov, true)
            }
            0x6 => {
                let (v, c, ov) = subtracao(rd, rm, u32::from(!c_in));
                (v, false, c, ov, true)
            }
            0x7 => {
                let (v, c) = desloca(rd, 3, rm & 0xFF, c_in, false);
                (v, true, c, false, true)
            }
            0x8 => (rd & rm, true, c_in, false, false),
            0x9 => {
                let (v, c, ov) = subtracao(0, rm, 0);
                (v, false, c, ov, true)
            }
            0xA => {
                let (v, c, ov) = subtracao(rd, rm, 0);
                (v, false, c, ov, false)
            }
            0xB => {
                let (v, c, ov) = adicao(rd, rm, 0);
                (v, false, c, ov, false)
            }
            0xC => (rd | rm, true, c_in, false, true),
            0xD => (rd.wrapping_mul(rm), true, c_in, false, true),
            0xE => (rd & !rm, true, c_in, false, true),
            _ => (!rm, true, c_in, false, true),
        };
        self.poe_nz(valor);
        if logico {
            // Thumb MUL on ARMv6 does not touch C. Shifts do.
            if matches!(op, 0x2 | 0x3 | 0x4 | 0x7) {
                self.poe_c(c);
            }
        } else {
            self.poe_c(c);
            self.poe_v(v);
        }
        if escreve {
            self.r[rd_i as usize] = valor;
        }
        Ok(false)
    }

    fn thumb_alta(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let op = (instr >> 8) & 3;
        let h1 = u32::from((instr >> 7) & 1);
        let h2 = u32::from((instr >> 6) & 1);
        let rm = (u32::from((instr >> 3) & 7)) | (h2 << 3);
        let rd = (u32::from(instr & 7)) | (h1 << 3);
        let a = self.le_reg(rd, pc, 0);
        let b = self.le_reg(rm, pc, 0);
        match op {
            0 => {
                let valor = a.wrapping_add(b);
                if rd == 15 {
                    self.desvia_sem_troca(valor);
                    Ok(true)
                } else {
                    self.r[rd as usize] = valor;
                    Ok(false)
                }
            }
            1 => {
                let (valor, c, v) = subtracao(a, b, 0);
                self.poe_nz(valor);
                self.poe_c(c);
                self.poe_v(v);
                Ok(false)
            }
            2 => {
                if rd == 15 {
                    self.desvia_sem_troca(b);
                    Ok(true)
                } else {
                    self.r[rd as usize] = b;
                    Ok(false)
                }
            }
            _ => {
                if h1 != 0 {
                    self.r[14] = pc.wrapping_add(2) | 1;
                }
                self.bx(b);
                Ok(true)
            }
        }
    }

    fn thumb_ldr_pc(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rd = u32::from((instr >> 8) & 7);
        let imm = u32::from(instr & 0xFF) << 2;
        // Bit 1 of the PC is forced to zero: the word is aligned, even with the instruction at
        // an odd halfword address.
        let addr = (pc.wrapping_add(4) & !3).wrapping_add(imm);
        let valor = self.le_mem(addr, 4, pc)?;
        self.r[rd as usize] = valor;
        Ok(false)
    }

    fn thumb_ls_reg(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rd = u32::from(instr & 7);
        let rn = self.le_reg(u32::from((instr >> 3) & 7), pc, 0);
        let rm = self.le_reg(u32::from((instr >> 6) & 7), pc, 0);
        let addr = rn.wrapping_add(rm);
        let op = (instr >> 9) & 7;
        match op {
            0 => self
                .es_mem(addr, &self.r[rd as usize].to_le_bytes(), pc)
                .map(|()| false),
            1 => self
                .es_mem(addr, &(self.r[rd as usize] as u16).to_le_bytes(), pc)
                .map(|()| false),
            2 => self
                .es_mem(addr, &[self.r[rd as usize] as u8], pc)
                .map(|()| false),
            3 => {
                let v = self.le_mem(addr, 1, pc)? as i8 as i32 as u32;
                self.r[rd as usize] = v;
                Ok(false)
            }
            4 => {
                let v = self.le_mem(addr, 4, pc)?;
                self.r[rd as usize] = v;
                Ok(false)
            }
            5 => {
                let v = self.le_mem(addr, 2, pc)?;
                self.r[rd as usize] = v;
                Ok(false)
            }
            6 => {
                let v = self.le_mem(addr, 1, pc)?;
                self.r[rd as usize] = v;
                Ok(false)
            }
            _ => {
                let v = self.le_mem(addr, 2, pc)? as i16 as i32 as u32;
                self.r[rd as usize] = v;
                Ok(false)
            }
        }
    }

    fn thumb_ls_imm(&mut self, instr: u16, pc: u32, meia: bool) -> Result<bool, StopReason> {
        let rd = u32::from(instr & 7);
        let rn = self.le_reg(u32::from((instr >> 3) & 7), pc, 0);
        let imm5 = u32::from((instr >> 6) & 0x1F);
        let l = instr & (1 << 11) != 0;
        let (addr, len, byte) = if meia {
            (rn.wrapping_add(imm5 << 1), 2, false)
        } else if (instr >> 12) & 1 == 0 {
            (rn.wrapping_add(imm5 << 2), 4, false)
        } else {
            (rn.wrapping_add(imm5), 1, true)
        };
        if l {
            let valor = self.le_mem(addr, len, pc)?;
            self.r[rd as usize] = valor;
            Ok(false)
        } else {
            let valor = self.r[rd as usize];
            if byte {
                self.es_mem(addr, &[valor as u8], pc)?;
            } else if len == 2 {
                self.es_mem(addr, &(valor as u16).to_le_bytes(), pc)?;
            } else {
                self.es_mem(addr, &valor.to_le_bytes(), pc)?;
            }
            Ok(false)
        }
    }

    fn thumb_ls_sp(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rd = u32::from((instr >> 8) & 7);
        let imm = u32::from(instr & 0xFF) << 2;
        let addr = self.r[13].wrapping_add(imm);
        if instr & (1 << 11) != 0 {
            self.r[rd as usize] = self.le_mem(addr, 4, pc)?;
        } else {
            self.es_mem(addr, &self.r[rd as usize].to_le_bytes(), pc)?;
        }
        Ok(false)
    }

    fn thumb_adr(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rd = u32::from((instr >> 8) & 7);
        let imm = u32::from(instr & 0xFF) << 2;
        let base = if instr & (1 << 11) == 0 {
            pc.wrapping_add(4) & !3
        } else {
            self.r[13]
        };
        self.r[rd as usize] = base.wrapping_add(imm);
        Ok(false)
    }

    fn thumb_misc(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let grupo = (instr >> 8) & 0xF;
        match grupo {
            0b0000 => {
                let imm = u32::from(instr & 0x7F) << 2;
                if instr & (1 << 7) != 0 {
                    self.r[13] = self.r[13].wrapping_sub(imm);
                } else {
                    self.r[13] = self.r[13].wrapping_add(imm);
                }
                Ok(false)
            }
            0b0010 => self.thumb_estende(instr, pc),
            0b0100 | 0b0101 => self.thumb_push(instr, pc, false),
            0b1010 => self.thumb_rev(instr, pc),
            0b1100 | 0b1101 => self.thumb_push(instr, pc, true),
            0b1110 => Err(StopReason::Exception { pc }),
            _ => Err(StopReason::Exception { pc }),
        }
    }

    fn thumb_estende(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rm = self.le_reg(u32::from((instr >> 3) & 7), pc, 0);
        let rd = u32::from(instr & 7);
        let valor = match (instr >> 6) & 3 {
            0 => rm as u16 as i16 as i32 as u32,
            1 => rm as u8 as i8 as i32 as u32,
            2 => u32::from(rm as u16),
            _ => u32::from(rm as u8),
        };
        self.r[rd as usize] = valor;
        Ok(false)
    }

    fn thumb_rev(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rm = self.le_reg(u32::from((instr >> 3) & 7), pc, 0);
        let rd = u32::from(instr & 7);
        let valor = match (instr >> 6) & 3 {
            0 => rm.swap_bytes(),
            1 => ((rm & 0x00FF_00FF) << 8) | ((rm & 0xFF00_FF00) >> 8),
            3 => (rm as u16).swap_bytes() as i16 as i32 as u32,
            _ => return Err(StopReason::Exception { pc }),
        };
        self.r[rd as usize] = valor;
        Ok(false)
    }

    fn thumb_push(&mut self, instr: u16, pc: u32, pop: bool) -> Result<bool, StopReason> {
        let mut lista = u32::from(instr & 0xFF);
        let extra = instr & (1 << 8) != 0;
        if extra {
            lista |= if pop { 1 << 15 } else { 1 << 14 };
        }
        let n = lista.count_ones();
        if n == 0 {
            return Err(StopReason::Exception { pc });
        }
        if pop {
            let mut addr = self.r[13];
            let mut saltou = false;
            for reg in 0..16 {
                if lista & (1 << reg) != 0 {
                    let valor = self.le_mem(addr, 4, pc)?;
                    if reg == 15 {
                        self.bx(valor);
                        saltou = true;
                    } else {
                        self.r[reg] = valor;
                    }
                    addr = addr.wrapping_add(4);
                }
            }
            self.r[13] = self.r[13].wrapping_add(n * 4);
            Ok(saltou)
        } else {
            let mut addr = self.r[13].wrapping_sub(n * 4);
            self.r[13] = addr;
            for reg in 0..16 {
                if lista & (1 << reg) != 0 {
                    let valor = self.le_reg(reg, pc, 0);
                    self.es_mem(addr, &valor.to_le_bytes(), pc)?;
                    addr = addr.wrapping_add(4);
                }
            }
            Ok(false)
        }
    }

    fn thumb_bloco(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let rn = u32::from((instr >> 8) & 7);
        let lista = u32::from(instr & 0xFF);
        let l = instr & (1 << 11) != 0;
        let n = lista.count_ones();
        if n == 0 {
            return Err(StopReason::Exception { pc });
        }
        let mut addr = self.r[rn as usize];
        if l {
            for reg in 0..8 {
                if lista & (1 << reg) != 0 {
                    self.r[reg] = self.le_mem(addr, 4, pc)?;
                    addr = addr.wrapping_add(4);
                }
            }
        } else {
            for reg in 0..8 {
                if lista & (1 << reg) != 0 {
                    self.es_mem(addr, &self.r[reg].to_le_bytes(), pc)?;
                    addr = addr.wrapping_add(4);
                }
            }
        }
        if !l || lista & (1 << rn) == 0 {
            self.r[rn as usize] = self.r[rn as usize].wrapping_add(n * 4);
        }
        Ok(false)
    }

    fn thumb_bcond(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let cond = u32::from((instr >> 8) & 0xF);
        if cond == 0xF {
            return self.svc(pc);
        }
        if cond == 0xE {
            return Err(StopReason::Exception { pc });
        }
        if condicao(self.cpsr, cond) {
            let imm = sext(u32::from(instr & 0xFF), 8) << 1;
            self.desvia_sem_troca(pc.wrapping_add(4).wrapping_add(imm));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn thumb_bl(&mut self, instr: u16, pc: u32) -> Result<bool, StopReason> {
        let prefixo = (instr >> 11) & 0x1F;
        let imm = u32::from(instr & 0x7FF);
        match prefixo {
            0b11110 => {
                // Bit 1 goes out: the pair spans two halfwords and the offset is a word offset.
                let base = pc.wrapping_add(4) & !2;
                self.r[14] = base.wrapping_add(sext(imm, 11) << 12);
                Ok(false)
            }
            0b11111 => {
                let proxima = pc.wrapping_add(2);
                self.r[15] = self.r[14].wrapping_add(imm << 1);
                self.r[14] = proxima | 1;
                self.cpsr |= T;
                Ok(true)
            }
            0b11101 => {
                let proxima = pc.wrapping_add(2);
                let alvo = self.r[14].wrapping_add(imm << 1) & !3;
                self.r[14] = proxima | 1;
                self.cpsr &= !T;
                self.r[15] = alvo;
                Ok(true)
            }
            _ => Err(StopReason::Exception { pc }),
        }
    }
}

fn meia(valor: u32, alta: bool) -> i32 {
    let h = if alta { valor >> 16 } else { valor & 0xFFFF };
    h as u16 as i16 as i32
}

fn sat_i32(v: i64) -> (i64, bool) {
    if v > i64::from(i32::MAX) {
        (i64::from(i32::MAX), true)
    } else if v < i64::from(i32::MIN) {
        (i64::from(i32::MIN), true)
    } else {
        (v, false)
    }
}

fn sext(valor: u32, bits: u32) -> u32 {
    let shift = 32 - bits;
    (((valor << shift) as i32) >> shift) as u32
}

fn condicao(cpsr: u32, cond: u32) -> bool {
    let n = cpsr & N != 0;
    let z = cpsr & Z != 0;
    let c = cpsr & C != 0;
    let v = cpsr & V != 0;
    match cond {
        0x0 => z,
        0x1 => !z,
        0x2 => c,
        0x3 => !c,
        0x4 => n,
        0x5 => !n,
        0x6 => v,
        0x7 => !v,
        0x8 => c && !z,
        0x9 => !c || z,
        0xA => n == v,
        0xB => n != v,
        0xC => !z && n == v,
        0xD => z || n != v,
        0xE => true,
        _ => false,
    }
}

fn adicao(a: u32, b: u32, carry: u32) -> (u32, bool, bool) {
    let (s1, c1) = a.overflowing_add(b);
    let (s2, c2) = s1.overflowing_add(carry);
    let c = c1 || c2;
    let v = (a ^ s2) & (b ^ s2) & 0x8000_0000 != 0;
    (s2, c, v)
}

/// Carry in the ARM sense: `true` means there was **no** borrow.
fn subtracao(a: u32, b: u32, borrow: u32) -> (u32, bool, bool) {
    let (s1, b1) = a.overflowing_sub(b);
    let (s2, b2) = s1.overflowing_sub(borrow);
    let c = !(b1 || b2);
    let v = (a ^ b) & (a ^ s2) & 0x8000_0000 != 0;
    (s2, c, v)
}

/// `(result, output carry)`.
///
/// A zero immediate amount is not "no shift" for LSR, ASR and ROR: the encoding stores the
/// 32 in that zero, and ROR zero is RRX. An amount from a register has no such shortcut —
/// a true zero does not shift.
fn desloca(valor: u32, tipo: u32, quant: u32, carry: bool, imediato: bool) -> (u32, bool) {
    if !imediato && quant == 0 {
        return (valor, carry);
    }
    match tipo {
        0 => {
            if quant == 0 {
                (valor, carry)
            } else if quant < 32 {
                (valor << quant, valor & (1 << (32 - quant)) != 0)
            } else if quant == 32 {
                (0, valor & 1 != 0)
            } else {
                (0, false)
            }
        }
        1 => {
            let q = if imediato && quant == 0 { 32 } else { quant };
            if q < 32 {
                (valor >> q, valor & (1 << (q - 1)) != 0)
            } else if q == 32 {
                (0, valor & 0x8000_0000 != 0)
            } else {
                (0, false)
            }
        }
        2 => {
            let q = if imediato && quant == 0 { 32 } else { quant };
            if q < 32 {
                let saida = ((valor as i32) >> q) as u32;
                (saida, valor & (1 << (q - 1)) != 0)
            } else {
                let sinal = valor & 0x8000_0000 != 0;
                (if sinal { 0xFFFF_FFFF } else { 0 }, sinal)
            }
        }
        _ => {
            if imediato && quant == 0 {
                let bit = u32::from(carry);
                ((valor >> 1) | (bit << 31), valor & 1 != 0)
            } else if quant == 0 {
                (valor, carry)
            } else {
                let q = quant & 31;
                if q == 0 {
                    (valor, valor & 0x8000_0000 != 0)
                } else {
                    let saida = valor.rotate_right(q);
                    (saida, saida & 0x8000_0000 != 0)
                }
            }
        }
    }
}

/// `(value, writes to Rd, C comes from the shifter, arithmetic carry, overflow)`.
fn alu(opcode: u32, a: u32, b: u32, carry: bool) -> (u32, bool, bool, bool, bool) {
    let cin = u32::from(carry);
    match opcode {
        0x0 => (a & b, true, true, false, false),
        0x1 => (a ^ b, true, true, false, false),
        0x2 => {
            let (v, c, ov) = subtracao(a, b, 0);
            (v, true, false, c, ov)
        }
        0x3 => {
            let (v, c, ov) = subtracao(b, a, 0);
            (v, true, false, c, ov)
        }
        0x4 => {
            let (v, c, ov) = adicao(a, b, 0);
            (v, true, false, c, ov)
        }
        0x5 => {
            let (v, c, ov) = adicao(a, b, cin);
            (v, true, false, c, ov)
        }
        0x6 => {
            let (v, c, ov) = subtracao(a, b, u32::from(!carry));
            (v, true, false, c, ov)
        }
        0x7 => {
            let (v, c, ov) = subtracao(b, a, u32::from(!carry));
            (v, true, false, c, ov)
        }
        0x8 => (a & b, false, true, false, false),
        0x9 => (a ^ b, false, true, false, false),
        0xA => {
            let (v, c, ov) = subtracao(a, b, 0);
            (v, false, false, c, ov)
        }
        0xB => {
            let (v, c, ov) = adicao(a, b, 0);
            (v, false, false, c, ov)
        }
        0xC => (a | b, true, true, false, false),
        0xD => (b, true, true, false, false),
        0xE => (a & !b, true, true, false, false),
        _ => (!b, true, true, false, false),
    }
}

impl CpuBackend for Interpretador {
    fn reset(&mut self, mem: &GuestMemory) -> Result<(), CpuError> {
        let mut copia = GuestMemory::new();
        for regiao in mem.regions() {
            copia
                .map_com_execucao(
                    regiao.name,
                    regiao.base,
                    regiao.bytes.clone(),
                    regiao.writable,
                    regiao.executavel,
                )
                .map_err(|e| CpuError(e.to_string()))?;
        }
        self.mem = copia;
        self.r = [0; 16];
        self.cpsr = MODO_USUARIO;
        self.instrucoes = 0;
        self.vigias.clear();
        self.semihosting.clear();
        self.exclusivo = None;
        self.cp15.clear();
        // Main ID (MRC p15,0,Rd,c0,c0,0, key 0): ARM1136EJ-S r0p0. The
        // Dream's MSM7201A app core is an ARM1136; Linux __lookup_processor_type
        // matches (id & 0x7F000) == 0x7B000 and parks at __error when the
        // MRC reads 0 (proven live: r9=0 -> beq park). Other CP15 keys
        // still read 0 until the guest writes them.
        self.cp15.push((0, 0x4117_B360));
        self.hist_pos = 0;
        self.hist_cheio = false;
        self.banco = [[0; 2]; 6];
        self.spsr = [0; 6];
        self.esperando = false;
        Ok(())
    }

    fn read_reg(&self, reg: Reg) -> u32 {
        self.r[indice(reg)]
    }

    fn write_reg(&mut self, reg: Reg, value: u32) {
        self.r[indice(reg)] = value;
    }

    fn run(&mut self, pc: u32, max_instructions: u64) -> Result<StopReason, CpuError> {
        if pc & 1 == 1 {
            self.cpsr |= T;
        } else {
            self.cpsr &= !T;
        }
        self.r[15] = pc & !1;
        let limite = self.instrucoes.saturating_add(max_instructions);
        loop {
            if self.instrucoes >= limite {
                return Ok(StopReason::Budget);
            }
            // IRQ delivery. The line is polled every 64 instructions
            // (device state only changes at slice boundaries or through
            // guest writes, so this bounds latency, not correctness).
            if self.esperando {
                if self.linha_irq() {
                    self.esperando = false;
                } else {
                    // Idle: burn the rest of the slice; host time moves on.
                    self.instrucoes = limite;
                    return Ok(StopReason::Budget);
                }
            }
            // TEMP (tick timeline): logs masked<->free transitions
            // + heartbeat every 50000 samples. No low total cap: the
            // masked post-tick spin must show until the end of the run.
            // Samples the I-bit directly (NOT linha_irq: the delivery
            // gate consumes its edge, and a logging poll must never
            // steal a delivery).
            if self.instrucoes & 1023 == 0 {
                static mut NLIN: u32 = 0;
                static mut ULTLIN: u32 = 2;
                unsafe {
                    let estado = if self.cpsr & 0x80 != 0 { 0 } else { 1 };
                    NLIN += 1;
                    if estado != ULTLIN || NLIN % 500000 == 0 {
                        ULTLIN = estado;
                        let n = NLIN;
                            // Current stack (8 words): saved lrs
                            // reveal the spin's call chain.
                            let mut st = [0u32; 8];
                            for (i, s) in st.iter_mut().enumerate() {
                                *s = self.mem.read_u32(self.r[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                            }
                            eprintln!(
                                "IRQLINHA n={n} pc={:#x} sp={:#x} {} stk={:#x?}",
                                self.r[15],
                                self.r[13],
                                if estado == 0 { "MASK" } else { "FREE" },
                                st
                            );
                        }
                    }
                }
            if self.cpsr & 0x80 == 0 {
                self.sondagem_irq = self.sondagem_irq.wrapping_add(1);
                if self.sondagem_irq & 63 == 0 && self.linha_irq() {
                    self.entra_irq();
                }
            }
            // Observational trap: report (r0, r1) at the trapped PC, then run
            // the real instruction. Guest state is untouched.
            if self.armadilha_pc == Some(self.r[15]) {
                if let Some(gancho) = self.gancho_pc.as_mut() {
                    gancho(self.r[0], self.r[1]);
                }
            }
            // Memory-serving traps: binary search by pc (arming keeps
            // the vec sorted; addresses are unique — replace semantics).
            // Take-call-restore per hook (the hooks live in self): take
            // the entry out, call it, put it back — so a hook may
            // arm/disarm others without aliasing the vec. Reinsertion
            // is sorted; removals only take effect next arrival.
            let n = self
                .armadilhas_mem
                .partition_point(|(a, _)| *a <= self.r[15]);
            if let Some((alvo, _)) = self.armadilhas_mem.get(n.wrapping_sub(1)) {
                if *alvo == self.r[15] {
                    let (alvo, mut gancho) = self.armadilhas_mem.remove(n - 1);
                    gancho(&mut self.mem, &mut self.r);
                    let pos = self.armadilhas_mem.partition_point(|(a, _)| *a < alvo);
                    self.armadilhas_mem.insert(pos, (alvo, gancho));
                }
            }
            self.historico[self.hist_pos] = self.r[15];
            self.hist_pos += 1;
            if self.hist_pos >= self.historico.len() {
                self.hist_pos = 0;
                self.hist_cheio = true;
            }
            match self.passo() {
                Ok(saltou) => {
                    if !saltou {
                        let passo = if self.thumb() { 2 } else { 4 };
                        self.r[15] = self.r[15].wrapping_add(passo);
                    }
                    self.instrucoes += 1;
                }
                Err(motivo) => {
                    // TEMP (kernel bring-up): failing instruction.
                    if matches!(motivo, StopReason::Exception { .. }) {
                        let w = self
                            .mem
                            .read(self.r[15], 4)
                            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
                            .unwrap_or(0xDEAD);
                        eprintln!("FAILINS pc={:#x} ins={:#x}", self.r[15], w);
                    }
                    return Ok(motivo);
                }
            }
        }
    }

    fn instructions(&self) -> u64 {
        self.instrucoes
    }

    fn set_instructions(&mut self, valor: u64) {
        self.instrucoes = valor;
    }

    fn cpsr(&self) -> u32 {
        self.cpsr
    }

    fn set_cpsr(&mut self, valor: u32) {
        self.cpsr = valor;
    }

    fn em_thumb(&self) -> bool {
        self.thumb()
    }

    fn watch_dirty(&mut self, id: u32, base: u32, len: u32) -> Result<(), CpuError> {
        self.unwatch_dirty(id);
        self.vigias.push((id, base, base.saturating_add(len), true));
        Ok(())
    }

    fn unwatch_dirty(&mut self, id: u32) {
        self.vigias.retain(|vigia| vigia.0 != id);
    }

    fn take_dirty(&mut self, id: u32) -> bool {
        match self.vigias.iter_mut().find(|vigia| vigia.0 == id) {
            Some(vigia) => std::mem::replace(&mut vigia.3, false),
            None => true,
        }
    }

    fn marca_sujo(&mut self, addr: u32, len: u32) {
        self.suja(addr, len);
    }

    fn read_mem(&self, addr: u32, buf: &mut [u8]) -> Result<(), CpuError> {
        self.mem
            .read(addr, buf.len() as u32)
            .map(|bytes| buf.copy_from_slice(bytes))
            .map_err(|e| CpuError(e.to_string()))
    }

    fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<(), CpuError> {
        self.mem
            .write(addr, data)
            .map_err(|e| CpuError(e.to_string()))
    }

    fn map_zeroed(&mut self, name: &'static str, base: u32, len: usize) -> Result<(), CpuError> {
        self.mem
            .map_zeroed(name, base, len)
            .map_err(|e| CpuError(e.to_string()))
    }
}

/// Bank index for a mode: usr/sys 0, fiq 1, irq 2, svc 3, abt 4, und 5.
fn idx_modo(cpsr: u32) -> usize {
    match cpsr & 0x1F {
        0x11 => 1,
        0x12 => 2,
        0x13 => 3,
        0x17 => 4,
        0x1B => 5,
        _ => 0,
    }
}

fn indice(reg: Reg) -> usize {
    match reg {
        Reg::R0 => 0,
        Reg::R1 => 1,
        Reg::R2 => 2,
        Reg::R3 => 3,
        Reg::R4 => 4,
        Reg::R5 => 5,
        Reg::R6 => 6,
        Reg::R7 => 7,
        Reg::R8 => 8,
        Reg::R9 => 9,
        Reg::R10 => 10,
        Reg::R11 => 11,
        Reg::R12 => 12,
        Reg::Sp => 13,
        Reg::Lr => 14,
        Reg::Pc => 15,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu_with(code: &[u8]) -> Interpretador {
        let mut mem = GuestMemory::new();
        let mut bytes = code.to_vec();
        bytes.resize(0x1000, 0);
        mem.map("code", 0, bytes, true).unwrap();
        mem.map_zeroed("data", 0x1000, 0x1000).unwrap();
        mem.map_zeroed("stack", 0x2000_0000, 0x1000).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        cpu
    }

    fn arm(palavras: &[u32]) -> Vec<u8> {
        palavras.iter().flat_map(|p| p.to_le_bytes()).collect()
    }

    #[test]
    fn movs_para_pc_desvia_sem_spsr() {
        // `MOVS pc, lr` (0xE1B0F00E) is the kernel's exception return;
        // the flat model has no SPSR, so it is a plain branch.
        let mut cpu = cpu_with(&arm(&[0xe1b0_f00e]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
    }

    #[test]
    fn irq_entra_e_volta_com_cpsr_restaurado() {
        // IRQ delivery + exception return through the handler. The
        // fonte is always pending; the handler runs and the CPSR
        // (USR, I clear) comes back intact.
        // 0x00: mov r0, #0; 0x04: b . ; 0x18: mov r0, #7; movs pc, lr.
        let mut cpu = cpu_with(&arm(&[
            0xe3a0_0000,
            0xeaff_fffe,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0xe3a0_0007,
            0xe1b0_f00e,
        ]));
        cpu.set_fonte_irq(|_| true);
        assert_eq!(cpu.run(0, 200).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 7);
        assert_eq!(cpu.cpsr(), 0x10);
    }

    #[test]
    fn cpsid_sets_cpsie_clears_i_bit() {
        // cpsid i (0xF1080080, imod=2) SETS I; cpsie i (0xF10C0080,
        // imod=3) CLEARS it. This was inverted for the whole bring-up
        // (enables masked, disables unmasked), freezing the kernel
        // with I=1 after the first tick. Regression guard.
        let mut cpu = cpu_with(&arm(&[0xf108_0080, 0xf10c_0080]));
        cpu.write_reg(Reg::Pc, 0);
        assert_eq!(cpu.cpsr() & 0x80, 0);
        cpu.run(0, 1).unwrap();
        assert_ne!(cpu.cpsr() & 0x80, 0, "cpsid i must SET I");
        cpu.run(4, 1).unwrap();
        assert_eq!(cpu.cpsr() & 0x80, 0, "cpsie i must CLEAR I");
    }

    #[test]
    fn troca_de_modo_preserva_sp_bancado() {
        // SVC and USR/SYS have separate banks (SYS shares USR's).
        // Without bx lr at the end: lr went to the bank on the first switch;
        // ends in Budget and checks the registers.
        let mut cpu = cpu_with(&arm(&[
            0xf100_0013, // cps #svc
            0xe1a0_200d, // mov r2, sp (bank novo, zero)
            0xe3a0_d055, // mov sp, #0x55
            0xe3a0_101f, // mov r1, #0x1f
            0xe121_f001, // msr CPSR_c, r1 (->SYS, same bank as USR)
            0xe1a0_300d, // mov r3, sp (sp do USR, preservado)
            0xe3a0_1013, // mov r1, #0x13
            0xe121_f001, // msr CPSR_c, r1 (->SVC back)
            0xe1a0_400d, // mov r4, sp (0x55 back)
        ]));
        cpu.write_reg(Reg::Sp, 0xAAAA);
        assert_eq!(cpu.run(0, 20).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R2), 0);
        assert_eq!(cpu.read_reg(Reg::R3), 0xAAAA);
        assert_eq!(cpu.read_reg(Reg::R4), 0x55);
    }

    #[test]
    fn wfi_queima_orcamento_sem_travar() {
        // mcr p15,0,r0,c7,c0,4 = 0xEE070F90. Without fonte: burns the
        // slice and returns Budget (never hangs the run).
        let mut cpu = cpu_with(&arm(&[0xee07_0f90, 0xe12f_ff1e]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 100000).unwrap(), StopReason::Budget);
    }

    #[test]
    fn wfi_acordado_por_irq_nao_entra_com_i_mascarado() {
        // cpsid i = 0xF10C0080. With I masked the line stays high
        // but no IRQ is taken: exits via Budget, no handler.
        let mut cpu = cpu_with(&arm(&[
            0xf10c_0080, // cpsid i
            0xee07_0f90, // wfi
            0xeaff_fffe, // b . (nunca sai daqui sem IRQ)
        ]));
        cpu.set_fonte_irq(|_| true);
        assert_eq!(cpu.run(0, 200).unwrap(), StopReason::Budget);
        assert_ne!(cpu.cpsr() & (1 << 7), 0);
    }

    #[test]
    fn msr_spsr_ignorado_em_modo_usuario() {
        // msr SPSR_fsxc, r0 = 0xE16FF000; mrs r1, SPSR = 0xE14F1000.
        // In USR the write is ignored; in IRQ the bank is zeroed.
        // Without bx lr at the end (lr went to the bank on the switch);
        // ends in Budget.
        let mut cpu = cpu_with(&arm(&[
            0xe3a0_00ff, // mov r0, #0xFF
            0xe16f_f000, // msr SPSR_fsxc, r0 (ignorado em USR)
            0xf100_0012, // cps #0x12 (->IRQ)
            0xe14f_1000, // mrs r1, SPSR (= 0)
        ]));
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R1), 0);
    }

    #[test]
    fn ldm_pc_s_restaura_modo_e_volta() {
        // ldmia sp, {r0, pc}^ = 0xE8FD8001: restores CPSR from SPSR
        // and branches. sp is loaded AFTER cps (the bank switch
        // zeroes sp): ldr sp, [pc, #8] = 0xE59FD008, pool at +0x1C.
        // Builds the frame by hand (r0=0xBE, pc=RETURN).
        let mut cpu = cpu_with(&arm(&[
            0xf100_0013, // cps #0x13 (->SVC, privilegiado)
            0xe3a0_0010, // mov r0, #0x10 (modo USR)
            0xe16f_f000, // msr SPSR_fsxc, r0
            0xe59f_d004, // ldr sp, [pc, #4] (sp = 0x1000)
            0xe8fd_8001, // ldmia sp, {r0, pc}^
            0xe12f_ff1e, // (nunca chega aqui)
            0x0000_1000, // pool: sp
        ]));
        cpu.write_mem(0x1000, &[0xBE, 0, 0, 0]).unwrap();
        cpu.write_mem(0x1004, &RETURN_MAGIC.to_le_bytes()).unwrap();
        assert_eq!(cpu.run(0, 20).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 0xBE);
        assert_eq!(cpu.cpsr() & 0x1F, 0x10);
    }

    #[test]
    fn executa_instrucao_e_le_registrador() {
        let mut cpu = cpu_with(&arm(&[0xe3a0_0037, 0xeaff_fffe]));
        assert_eq!(cpu.run(0, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x37);
    }

    #[test]
    fn salto_para_a_faixa_de_api_vira_chamada() {
        let mut cpu = cpu_with(&arm(&[0xe3a0_020f, 0xe12f_ff10]));
        assert_eq!(
            cpu.run(0, 10).unwrap(),
            StopReason::ApiCall { addr: API_BASE }
        );
    }

    #[test]
    fn endereco_com_bit_zero_entra_em_thumb() {
        let mut code = vec![0u8; 0x100];
        code.extend_from_slice(&[0x37, 0x20, 0xfe, 0xe7]);
        let mut cpu = cpu_with(&code);
        assert_eq!(cpu.run(0x101, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x37);
    }

    #[test]
    fn endereco_par_volta_para_arm_depois_de_thumb() {
        let mut code = arm(&[0xe3a0_0037, 0xeaff_fffe]);
        code.resize(0x100, 0);
        code.extend_from_slice(&[0x00, 0x20, 0xfe, 0xe7]);
        let mut cpu = cpu_with(&code);
        cpu.run(0x101, 1).unwrap();
        assert_eq!(cpu.run(0, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x37);
    }

    #[test]
    fn a_vigia_liga_com_escrita_do_guest_e_nao_com_a_do_host() {
        let mut cpu = cpu_with(&arm(&[0xe3a0_1a01, 0xe581_0000, 0xeaff_fffe]));
        cpu.watch_dirty(7, 0x1000, 4).unwrap();
        assert!(cpu.take_dirty(7));
        assert!(!cpu.take_dirty(7));
        cpu.write_mem(0x1000, &[1, 2, 3, 4]).unwrap();
        assert!(!cpu.take_dirty(7));
        cpu.run(0, 2).unwrap();
        assert!(cpu.take_dirty(7));
        cpu.unwatch_dirty(7);
        assert!(cpu.take_dirty(7));
    }

    #[test]
    fn retorno_para_o_sentinela_e_reconhecido() {
        let mut cpu = cpu_with(&arm(&[0xe12f_ff1e]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
    }

    #[test]
    fn semihosting_escreve_sem_interromper_o_guest() {
        let mut cpu = cpu_with(&arm(&[0xe3a0_0003, 0xe3a0_1a01, 0xef00_00ab, 0xe12f_ff1e]));
        cpu.write_mem(0x1000, b"Z").unwrap();
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.semihosting(), "Z");
        assert_eq!(cpu.read_reg(Reg::R0), 0);
    }

    #[test]
    fn codigo_alterado_pelo_host_e_executado() {
        let mut cpu = cpu_with(&arm(&[0xe3a0_0001, 0xe12f_ff1e]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 1);
        cpu.write_mem(0, &0xe3a0_0002u32.to_le_bytes()).unwrap();
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 2);
    }

    #[test]
    fn adds_atualiza_flags_e_o_deslocamento_de_32_poe_o_carry() {
        // adds r0, r1, #1 with r1 = 0xFFFFFFFF → 0, C and Z
        let mut cpu = cpu_with(&arm(&[0xe291_0001, 0xe1b0_1020, 0xe12f_ff1e]));
        cpu.write_reg(Reg::R1, 0xFFFF_FFFF);
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0);
        assert_ne!(cpu.cpsr() & Z, 0);
        assert_ne!(cpu.cpsr() & C, 0);
        // movs r1, r0, lsr #32 — r0 is still 0 here; re-run from the second instruction
        // with r0 = 0x80000000.
        cpu.write_reg(Reg::R0, 0x8000_0000);
        cpu.run(4, 1).unwrap();
        assert_eq!(cpu.read_reg(Reg::R1), 0);
        assert_ne!(cpu.cpsr() & C, 0);
        assert_ne!(cpu.cpsr() & Z, 0);
    }

    #[test]
    fn ldr_str_e_ldm_voltam_os_bytes() {
        // mov r0, #0x11; mov r1, #0x1000; str r0, [r1]; ldr r2, [r1]; bx lr
        let mut cpu = cpu_with(&arm(&[
            0xe3a0_0011,
            0xe3a0_1a01,
            0xe581_0000,
            0xe591_2000,
            0xe12f_ff1e,
        ]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R2), 0x11);
    }

    #[test]
    fn clz_rev_e_sxtb() {
        let mut cpu = cpu_with(&arm(&[0xe16f_0f11, 0xe6bf_0f32, 0xe6af_1071, 0xe12f_ff1e]));
        cpu.write_reg(Reg::R1, 0x0001_0000);
        cpu.write_reg(Reg::R2, 0x1234_5678);
        cpu.write_reg(Reg::R1, 0x0001_0000);
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        // The third instruction reads r1 again, so SXTB sees the original value only if we
        // have not overwritten r1. CLZ writes r0. REV writes r0 from r2. SXTB reads r1.
        cpu.write_reg(Reg::R1, 0x80);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 0x7856_3412);
        assert_eq!(cpu.read_reg(Reg::R1), 0xFFFF_FF80);
    }

    #[test]
    fn clz_de_zero_e_trinta_e_dois() {
        let mut cpu = cpu_with(&arm(&[0xe16f_0f11, 0xe12f_ff1e]));
        cpu.write_reg(Reg::R1, 0);
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 32);
    }

    #[test]
    fn bl_thumb_grava_o_retorno_com_bit_de_thumb() {
        // BL to 8, then the caller's `movs r0, #1` and `bx lr` do not: the target does `movs r1, #7`.
        // at 0: f000 f801  (BL, imm hi 0, imm lo 1 → PC = 4 + 2 = 6? )
        // Recomputed in the test itself: the target is 8.
        // first: LR = (0+4) + 0 = 4
        // second at 2: PC = 4 + (imm<<1). To land on 8, imm = 2. 11111 00000000010 = 0xF802
        let mut code = vec![0x00, 0xF0, 0x02, 0xF8];
        code.resize(8, 0);
        code.extend_from_slice(&[0x07, 0x21]); // movs r1, #7
        code.extend_from_slice(&[0x70, 0x47]); // bx lr — returns to the address right after the pair
        let mut cpu = cpu_with(&code);
        // Four instructions: the two BL halves, the movs and the bx. Next would be the zero
        // word left at address 4, and the budget runs out before it.
        assert_eq!(cpu.run(1, 4).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R1), 7);
        assert_eq!(cpu.read_reg(Reg::Lr) & 1, 1);
        assert_eq!(cpu.read_reg(Reg::Pc), 4);
    }

    #[test]
    fn ssat_corta_e_liga_q() {
        // `SSAT r0, #8, r1`. Bit 4 must be set: without it the word falls into
        // load/store space and the test ends up measuring another instruction.
        let mut cpu = cpu_with(&arm(&[0xe6a7_0011, 0xe12f_ff1e]));
        cpu.write_reg(Reg::R1, 200);
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 127);
        assert_ne!(cpu.cpsr() & Q, 0);
    }

    #[test]
    fn historico_grava_ultimos_pcs_na_ordem() {
        // mov r0, #1; mov r1, #2; b . (at 8)
        let mut cpu = cpu_with(&arm(&[0xe3a0_0001, 0xe3a0_1002, 0xeaff_fffe]));
        assert_eq!(cpu.run(0, 5).unwrap(), StopReason::Budget);
        // 2 from the preamble + 3 spins on the `b .` at 8.
        assert_eq!(cpu.historico(), vec![0, 4, 8, 8, 8]);
        let mut mem = GuestMemory::new();
        mem.map("code", 0, vec![0; 0x1000], true).unwrap();
        cpu.reset(&mem).unwrap();
        assert!(cpu.historico().is_empty());
    }

    #[test]
    fn condicional_falha_nao_escreve() {
        // cmp r0, #1; moveq r1, #2; bx lr
        let mut cpu = cpu_with(&arm(&[0xe350_0001, 0x03a0_1002, 0xe12f_ff1e]));
        cpu.write_reg(Reg::R0, 0);
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R1), 0);
    }

    #[test]
    fn coproc_p15_guarda_e_devolve() {
        // mcr p15,0,r1,c1,c0,0 (0xEE011F10); mrc p15,0,r0,c1,c0,0 (0xEE110F10); bx lr
        let mut cpu = cpu_with(&arm(&[0xee01_1f10, 0xee11_0f10, 0xe12f_ff1e]));
        cpu.write_reg(Reg::R1, 0x1005);
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 0x1005);
    }

    #[test]
    fn coproc_chave_nunca_escrita_le_zero() {
        // mrc p15,0,r0,c2,c0,0 (TTBR, 0xEE120F10); bx lr
        let mut cpu = cpu_with(&arm(&[0xee12_0f10, 0xe12f_ff1e]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 0);
    }

    #[test]
    fn coproc_fora_do_p15_falha() {
        // mrc p14,0,r0,c1,c0,0 has the same format with another coprocessor.
        let mut cpu = cpu_with(&arm(&[0xee11_0f10 & !0x0000_0f00 | 0x0000_0e00]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Exception { pc: 0 });
    }

    #[test]
    fn armadilha_mem_escreve_na_memoria_e_ve_registradores() {
        use std::cell::RefCell;
        use std::rc::Rc;
        // mov r0, #7; mov r1, #8; b 0x100; (at 0x100:) b .
        // (Rd sits at bits 15-12: 0xe3a0_1008, not 0xe3a0_0008.)
        let mut code = arm(&[0xe3a0_0007, 0xe3a0_1008, 0xea00_003c]);
        code.resize(0x100, 0);
        code.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        let mut cpu = cpu_with(&code);
        let vistos = Rc::new(RefCell::new(Vec::new()));
        let copia = vistos.clone();
        // Synchronous serve: write r0+r1 to the data page, record r6.
        cpu.write_reg(Reg::R6, 0x1234);
        cpu.trap_pc_mem(0x100, move |mem, regs| {
            let soma = regs[0].wrapping_add(regs[1]);
            mem.write(0x1000, &soma.to_le_bytes()).unwrap();
            copia.borrow_mut().push((regs[0], regs[1], regs[6]));
        });
        // Coexists with the observe-only trap at another address.
        let obs = Rc::new(RefCell::new(0u32));
        let conta = obs.clone();
        cpu.trap_pc(0x8, move |_, _| *conta.borrow_mut() += 1);
        // 3 of preamble + 2 spins: the mem hook fires on the 2 spins.
        assert_eq!(cpu.run(0, 5).unwrap(), StopReason::Budget);
        assert_eq!(*vistos.borrow(), vec![(7, 8, 0x1234), (7, 8, 0x1234)]);
        assert_eq!(cpu.read_u32(0x1000).unwrap(), 15);
        assert_eq!(*obs.borrow(), 1, "trap_pc segue armado junto");
        assert_eq!(cpu.read_reg(Reg::Pc), 0x100);
        cpu.untrap_pc_mem(0x100);
        cpu.run(0x100, 1).unwrap();
        assert_eq!(vistos.borrow().len(), 2, "sem armadilha, sem escrita");
    }

    #[test]
    fn armadilha_pc_observa_r0_r1_e_nao_muda_o_guest() {
        use std::cell::RefCell;
        use std::rc::Rc;
        // mov r0, #3; mov r1, #0x41; b 0x100; (at 0x100:) b .
        let mut code = arm(&[0xe3a0_0003, 0xe3a0_1041, 0xea00_003c]);
        code.resize(0x100, 0);
        code.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        let mut cpu = cpu_with(&code);
        let vistos = Rc::new(RefCell::new(Vec::new()));
        let copia = vistos.clone();
        cpu.trap_pc(0x100, move |r0, r1| copia.borrow_mut().push((r0, r1)));
        // 3 of preamble + 2 spins on the `b .`: the trap fires on the 2 spins.
        assert_eq!(cpu.run(0, 5).unwrap(), StopReason::Budget);
        assert_eq!(*vistos.borrow(), vec![(3, 0x41), (3, 0x41)]);
        // The guest walked the same way: PC stays in the loop.
        assert_eq!(cpu.read_reg(Reg::Pc), 0x100);
        cpu.untrap_pc();
        cpu.run(0x100, 2).unwrap();
        assert_eq!(vistos.borrow().len(), 2, "sem armadilha, sem registro");
    }
}
