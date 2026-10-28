//! Hybrid backend for the Dream bring-up: Dynarmic runs user-mode slices
//! at JIT speed; the interpretador keeps privileged code with full
//! banking/SPSR fidelity, and delivers every exception. The wrapper picks
//! per `run` call by CPSR mode and syncs architected state on switch.
//! Both backends share one [`GuestMemory`], so demand-paged and
//! trap-served bytes are identical whichever backend runs.
//!
//! Dynarmic emulates user mode only (no privilege levels, per its own
//! README): entering privileged code under it would silently misbehave,
//! so the wrapper never lets that happen — any non-USR mode, plus one
//! slice in N for tick delivery (the JIT never takes interrupts on its
//! own), runs on the interpretador.

use std::cell::RefCell;
use std::rc::Rc;

use super::dynarmic::DynarmicCpu;
use super::interpretador::Interpretador;
use super::mem::GuestMemory;
use super::{CpuBackend, CpuError, Reg, StopReason};

/// Backend that ran last (and whose register file is current).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lado {
    Interp,
    Dyna,
}

/// Forced interpreter slice every N runs: IRQs only deliver there.
/// Bounds tick latency while keeping the JIT fast path dominant.
const FATIAS_INTERP_A_CADA: u32 = 16;

/// ARM CPSR mode field mask and the user-mode value.
const MODO_MASCARA: u32 = 0x1F;
const MODO_USUARIO: u32 = 0x10;

/// Shared serving-trap hook: one registration fans out to whichever
/// backend is armed (the interpretador always; Dynarmic once the JIT is
/// allowed — see `DualBackend::permite_jit`).
type GanchoMem = Rc<RefCell<Box<dyn FnMut(&mut GuestMemory, &mut [u32; 16])>>>;

pub struct DualBackend {
    interp: Interpretador,
    dyna: DynarmicCpu,
    mem: Rc<RefCell<GuestMemory>>,
    ativo: Lado,
    desde_interp: u32,
    /// JIT eligibility, harness-controlled (default off). The guest's
    /// privilege model is the interpretador's flat fiction (reset leaves
    /// USR and USR control-field writes take effect, so SPL and early
    /// kernel run USR-valued while logically privileged). Dynarmic
    /// implements real USR semantics (those writes are dropped), so it
    /// may only run genuine userspace — which does no control-field
    /// MSR, takes no exceptions in-JIT (SVC exits via the handoff in
    /// `run`), and needs no banking. Until the harness has seen
    /// userspace (first exec), everything stays on the interpretador
    /// and behavior is bit-identical to the interp-only bring-up.
    jit: bool,
    /// Serving traps armed on the interpretador immediately; on Dynarmic
    /// only once the JIT is allowed (arming patches guest memory, which
    /// the interpretador would then execute as code).
    pendentes: Vec<(u32, bool, GanchoMem)>,
}

impl DualBackend {
    pub fn new() -> Result<Self, CpuError> {
        let mem = Rc::new(RefCell::new(GuestMemory::new()));
        Ok(Self {
            interp: Interpretador::with_shared_mem(mem.clone())?,
            dyna: DynarmicCpu::with_shared_mem(mem.clone())?,
            mem,
            ativo: Lado::Interp,
            desde_interp: 0,
            jit: false,
            pendentes: Vec::new(),
        })
    }

    /// Allow (or forbid) user-mode slices on the JIT. The harness sets
    /// this once genuine userspace exists; until then `run` never leaves
    /// the interpretador. Enabling arms every pending serving trap on
    /// Dynarmic (arming patches guest memory, so it must wait for this);
    /// disabling disarms them again (original bytes restored).
    pub fn permite_jit(&mut self, v: bool) {
        if v == self.jit {
            return;
        }
        self.jit = v;
        // Clone the list: arming borrows `self.dyna` mutably.
        let lista = self.pendentes.clone();
        if v {
            // Fresh fast table: maps/unmaps while the JIT was off
            // skipped maintenance (see map_zeroed), so rebuild once
            // here instead of per carve.
            self.dyna.reconstroi_tabela();
            for (addr, thumb, g) in &lista {
                if *thumb {
                    let g2 = g.clone();
                    self.dyna
                        .trap_pc_mem_thumb(*addr, move |m, r| g2.borrow_mut()(m, r));
                } else {
                    let g2 = g.clone();
                    self.dyna
                        .trap_pc_mem(*addr, move |m, r| g2.borrow_mut()(m, r));
                }
            }
        } else {
            for (addr, _, _) in &lista {
                self.dyna.untrap_pc_mem(*addr);
            }
        }
    }

    /// CPSR mode of the backend that ran last.
    fn modo(&self) -> u32 {
        match self.ativo {
            Lado::Interp => self.interp.cpsr() & MODO_MASCARA,
            Lado::Dyna => self.dyna.cpsr() & MODO_MASCARA,
        }
    }

    /// Copy registers, CPSR and the CP15 store from the active backend to
    /// `alvo`, and clear both exclusive monitors (a reservation never
    /// survives a switch: the STREX would otherwise succeed against the
    /// wrong monitor — the guest retries, which is the architecturally
    /// correct outcome).
    fn sincroniza(&mut self, alvo: Lado) {
        if alvo == self.ativo {
            return;
        }
        let mut regs = [0u32; 16];
        let cpsr;
        let cp15;
        match self.ativo {
            Lado::Interp => {
                for (i, r) in regs.iter_mut().enumerate() {
                    *r = self.interp.read_reg(Self::indice(i));
                }
                cpsr = self.interp.cpsr();
                cp15 = self.interp.cp15_vec();
            }
            Lado::Dyna => {
                for (i, r) in regs.iter_mut().enumerate() {
                    *r = self.dyna.read_reg(Self::indice(i));
                }
                cpsr = self.dyna.cpsr();
                cp15 = self.dyna.cp15_vec();
            }
        }
        match alvo {
            Lado::Interp => {
                for (i, v) in regs.iter().enumerate() {
                    self.interp.write_reg(Self::indice(i), *v);
                }
                self.interp.set_cpsr(cpsr);
                self.interp.carrega_cp15(cp15);
            }
            Lado::Dyna => {
                for (i, v) in regs.iter().enumerate() {
                    self.dyna.write_reg(Self::indice(i), *v);
                }
                self.dyna.set_cpsr(cpsr);
                self.dyna.carrega_cp15(cp15);
            }
        }
        self.interp.limpa_exclusivo();
        self.dyna.limpa_exclusivo();
        self.ativo = alvo;
    }

    fn indice(i: usize) -> Reg {
        match i {
            0 => Reg::R0,
            1 => Reg::R1,
            2 => Reg::R2,
            3 => Reg::R3,
            4 => Reg::R4,
            5 => Reg::R5,
            6 => Reg::R6,
            7 => Reg::R7,
            8 => Reg::R8,
            9 => Reg::R9,
            10 => Reg::R10,
            11 => Reg::R11,
            12 => Reg::R12,
            13 => Reg::Sp,
            14 => Reg::Lr,
            _ => Reg::Pc,
        }
    }

    /// Shared map for callers that address memory directly instead of
    /// through a backend (diagnostics, tests).
    pub fn memoria(&self) -> std::cell::Ref<GuestMemory> {
        self.mem.borrow()
    }

    /// TEMP (snapshots): acesso mutável ao mapa compartilhado para
    /// restauração de `Foto`. Remove com o CRASHOBJ se os snapshots
    /// não vingarem.
    pub(crate) fn memoria_mut(&mut self) -> std::cell::RefMut<'_, GuestMemory> {
        self.mem.borrow_mut()
    }

    /// TEMP (write watchpoint): arm/clear the `GuestMemory::vigia`
    /// range checked in `interpretador::es_mem`. Remove with CRASHOBJ.
    pub fn arma_vigia(&mut self, alvo: Option<(u32, u32)>) {
        self.mem.borrow_mut().arma_vigia(alvo);
    }

    /// TEMP (snapshots): núcleo via interpretador + contador de
    /// revezamento (o JIT fica desligado; a tabela rápida do Dynarmic
    /// é irrelevante e os traps são rearmados pelo setup). Remove com
    /// o CRASHOBJ se os snapshots não vingarem.
    pub(crate) fn foto_nucleo(&self) -> crate::msm7201a_snapshot::NucleoFoto {
        let mut n = self.interp.foto_nucleo();
        n.desde_interp = self.desde_interp;
        n
    }

    /// TEMP (snapshots): restaura o núcleo (par de `foto_nucleo`).
    pub(crate) fn aplica_nucleo(&mut self, n: &crate::msm7201a_snapshot::NucleoFoto) {
        self.interp.aplica_nucleo(n);
        self.desde_interp = n.desde_interp;
    }

    /// Which backend the next `run` would pick (mode rule + periodic
    /// interp slice). Test hook for the switch policy; the real
    /// decision lives in `run`.
    #[cfg(test)]
    pub fn proximo(&self) -> &'static str {
        let modo = self.modo();
        let mut alvo = if self.jit && modo == MODO_USUARIO {
            Lado::Dyna
        } else {
            Lado::Interp
        };
        if alvo == Lado::Dyna && self.desde_interp + 1 >= FATIAS_INTERP_A_CADA {
            alvo = Lado::Interp;
        }
        match alvo {
            Lado::Interp => "interp",
            Lado::Dyna => "dyna",
        }
    }

    /// ARM PC trap (observational): reports `(r0, r1)` on arrival, then
    /// runs the real instruction. Armed on both backends.
    pub fn trap_pc(&mut self, addr: u32, gancho: impl FnMut(u32, u32) + 'static) {
        let g = std::rc::Rc::new(std::cell::RefCell::new(
            Box::new(gancho) as Box<dyn FnMut(u32, u32)>,
        ));
        let g2 = g.clone();
        self.interp.trap_pc(addr, move |a, b| g.borrow_mut()(a, b));
        self.dyna.trap_pc(addr, move |a, b| g2.borrow_mut()(a, b));
    }

    /// Remove the PC trap, if any, on both backends.
    pub fn untrap_pc(&mut self) {
        self.interp.untrap_pc();
        self.dyna.untrap_pc();
    }

    /// Serving trap (ARM): on arrival the hook runs with guest memory
    /// and registers, then the real instruction steps. Armed on the
    /// interpretador immediately; on Dynarmic only once the JIT is
    /// allowed (arming patches guest memory with an SVC, which the
    /// interpretador would otherwise fetch and execute as code).
    pub fn trap_pc_mem(
        &mut self,
        addr: u32,
        gancho: impl FnMut(&mut GuestMemory, &mut [u32; 16]) + 'static,
    ) {
        let g: GanchoMem = Rc::new(RefCell::new(Box::new(gancho)));
        if let Some(slot) = self.pendentes.iter_mut().find(|(a, _, _)| *a == addr) {
            slot.1 = false;
            slot.2 = g.clone();
        } else {
            self.pendentes.push((addr, false, g.clone()));
        }
        let g2 = g.clone();
        self.interp
            .trap_pc_mem(addr, move |m, r| g.borrow_mut()(m, r));
        if self.jit {
            self.dyna
                .trap_pc_mem(addr, move |m, r| g2.borrow_mut()(m, r));
        }
    }

    /// Serving trap (16-bit Thumb): same contract as `trap_pc_mem`.
    pub fn trap_pc_mem_thumb(
        &mut self,
        addr: u32,
        gancho: impl FnMut(&mut GuestMemory, &mut [u32; 16]) + 'static,
    ) {
        let g: GanchoMem = Rc::new(RefCell::new(Box::new(gancho)));
        if let Some(slot) = self.pendentes.iter_mut().find(|(a, _, _)| *a == addr) {
            slot.1 = true;
            slot.2 = g.clone();
        } else {
            self.pendentes.push((addr, true, g.clone()));
        }
        // The interpretador's traps are mode-agnostic; one registration
        // covers both spellings.
        let g2 = g.clone();
        self.interp
            .trap_pc_mem(addr, move |m, r| g.borrow_mut()(m, r));
        if self.jit {
            self.dyna
                .trap_pc_mem_thumb(addr, move |m, r| g2.borrow_mut()(m, r));
        }
    }

    /// Remove the serving trap, if any, on both backends.
    pub fn untrap_pc_mem(&mut self, addr: u32) {
        self.pendentes.retain(|(a, _, _)| *a != addr);
        self.interp.untrap_pc_mem(addr);
        self.dyna.untrap_pc_mem(addr);
    }

    /// Serving-trap count on the interpretador (perf audit).
    pub fn num_armadilhas(&self) -> usize {
        self.interp.num_armadilhas()
    }

    /// Guest-map region count (perf audit).
    pub fn num_regioes(&self) -> usize {
        self.mem.borrow().num_regioes()
    }

    /// CP15 read (flat model, both backends): the active backend's copy
    /// is current, and switches sync both ways.
    pub fn le_cp15(&self, chave: u32) -> Option<u32> {
        match self.ativo {
            Lado::Interp => self.interp.le_cp15(chave),
            Lado::Dyna => self.dyna.le_cp15(chave),
        }
    }

    /// Whether the current mode is USR (the only mode Dynarmic runs).
    pub fn em_usuario(&self) -> bool {
        match self.ativo {
            Lado::Interp => self.interp.em_usuario(),
            // Invariant: Dynarmic only ever executes user-mode code
            // (the run loop switches away on any privileged mode).
            Lado::Dyna => true,
        }
    }

    /// Current address space key (masked TTBR0). Shared map: either
    /// backend's view is identical.
    pub fn mm_atual(&self) -> u32 {
        self.mem.borrow().mm_atual()
    }

    /// Current execve generation (shared map — see `mm_atual`).
    pub fn geracao(&self) -> u32 {
        self.mem.borrow().geracao()
    }

    /// Whether a live user region exists for (mm, gen, base) — see
    /// `GuestMemory::tem_mapeada`.
    pub fn tem_mapeada(&self, mm: u32, ger: u32, base: u32) -> bool {
        self.mem.borrow().tem_mapeada(mm, ger, base)
    }

    /// Records which physical page a user region was mirrored from.
    pub fn anotar_semente(&mut self, base: u32, pa: u32) {
        self.mem.borrow_mut().anotar_semente(base, pa);
    }

    /// Sibling mapping of the same VA mirroring the same physical page.
    pub fn irmao_mesma_va(&self, base: u32, pa: u32) -> Option<Vec<u8>> {
        self.mem.borrow().irmao_mesma_va(base, pa)
    }

    // TEMP (GOT-clobber hunt): region dump for the serve-miss
    // forensics. Remove with CRASHOBJ.
    pub fn debug_regioes(&self, base: u32) -> String {
        self.mem.borrow().debug_regioes(base)
    }

    /// Current mm's own region at `base`, if any.
    pub fn regiao_propria(&self, base: u32) -> Option<(Option<u32>, u32)> {
        self.mem.borrow().regiao_propria(base)
    }

    /// Refreshes a same-pa region's generation in place (adopt).
    pub fn adotar_geracao(&mut self, base: u32) {
        self.mem.borrow_mut().adotar_geracao(base);
    }

    /// TEMP (linker Thumb-state): force Thumb mode (see
    /// `Interpretador::forca_thumb`). Forwards to the active backend
    /// (bring-up runs interpretador-only; JIT off). Remove with CRASHOBJ.
    pub fn forca_thumb(&mut self) {
        self.interp.forca_thumb();
    }

    /// User mapping (text, stack, heap): one mapping in the shared map,
    /// then publish the pages to the JIT's fast table (only while the
    /// JIT may run — see `map_zeroed`).
    pub fn map_usuario_zeroed(
        &mut self,
        name: &'static str,
        base: u32,
        len: usize,
    ) -> Result<(), CpuError> {
        self.mem
            .borrow_mut()
            .map_usuario_zeroed(name, base, len)
            .map_err(|e| CpuError(e.to_string()))?;
        if self.jit {
            self.dyna.atualiza_tabela(base, len as u32);
        }
        Ok(())
    }

    /// Full architected state for halt traces. On Dynarmic the banked
    /// registers and SPSR read as zero (user mode has no banking and no
    /// SPSR); the general registers and CPSR are live. Diagnostics only:
    /// nothing branches on the banked half.
    pub fn estado_completo(&self) -> ([u32; 16], u32, [u32; 6], [[u32; 2]; 6]) {
        match self.ativo {
            Lado::Interp => self.interp.estado_completo(),
            Lado::Dyna => {
                let mut r = [0u32; 16];
                for (i, v) in r.iter_mut().enumerate() {
                    *v = self.dyna.read_reg(Self::indice(i));
                }
                (r, self.dyna.cpsr(), [0; 6], [[0; 2]; 6])
            }
        }
    }

    /// PCs of recently executed instructions, oldest first. On Dynarmic
    /// this is sparse (run entries and trap arrivals, not every
    /// instruction): enough to name a stall, not to replay one.
    pub fn historico(&self) -> Vec<u32> {
        match self.ativo {
            Lado::Interp => self.interp.historico(),
            Lado::Dyna => self.dyna.historico(),
        }
    }

    /// Semihosting output, both backends concatenated (each run appends
    /// to its own; the Dream guest barely uses it).
    pub fn semihosting(&self) -> String {
        format!("{}{}", self.interp.semihosting(), self.dyna.semihosting())
    }

    /// Delivery-side timer flag lives on the interpretador (the JIT never
    /// takes interrupts, so it has nothing to recheck).
    pub fn marca_timer_sujo(&mut self) {
        self.interp.marca_timer_sujo();
    }

    /// IRQ line source, armed on both backends (delivery itself always
    /// runs on the interpretador — see `run`).
    pub fn set_fonte_irq(
        &mut self,
        fonte: impl FnMut(&GuestMemory, bool) -> bool + 'static,
    ) {
        let g = std::rc::Rc::new(std::cell::RefCell::new(
            Box::new(fonte) as Box<dyn FnMut(&GuestMemory, bool) -> bool>,
        ));
        let g2 = g.clone();
        self.interp.set_fonte_irq(move |m, l| g.borrow_mut()(m, l));
        self.dyna.set_fonte_irq(move |m, l| g2.borrow_mut()(m, l));
    }

    /// Deliver a data/prefetch abort: always on the interpretador (full
    /// banking/SPSR model), syncing first when Dynarmic ran last.
    pub fn entra_aborto(&mut self, addr_falta: u32, fsr: u32, prefetch: bool) {
        self.sincroniza(Lado::Interp);
        self.ativo = Lado::Interp;
        self.interp.entra_aborto(addr_falta, fsr, prefetch);
    }

    /// Deliver an undefined-instruction fault: always on the
    /// interpretador, syncing first when Dynarmic ran last.
    pub fn entra_undef(&mut self) {
        self.sincroniza(Lado::Interp);
        self.ativo = Lado::Interp;
        self.interp.entra_undef();
    }
}

impl CpuBackend for DualBackend {
    fn reset(&mut self, mem: &GuestMemory) -> Result<(), CpuError> {
        // One shared map: the interpretador copies the harness map in,
        // then Dynarmic rebuilds its page table over the same bytes.
        // The `jit` flag survives: the harness sets it once when
        // userspace exists, and a map reload must not disarm it.
        self.interp.reset(mem)?;
        self.dyna.reset(mem)?;
        self.ativo = Lado::Interp;
        self.desde_interp = 0;
        Ok(())
    }

    fn run(&mut self, pc: u32, max_instructions: u64) -> Result<StopReason, CpuError> {
        // Dynarmic emulates genuine user mode only: privileged code must
        // run on the interpretador (full banking/SPSR model), and so must
        // USR-valued-but-logically-privileged code (the flat model honors
        // USR control-field writes; Dynarmic drops them). USR slices go to
        // the JIT only once the harness has seen userspace (`permite_jit`),
        // except one slice in N for tick delivery (the JIT never takes
        // interrupts on its own).
        let modo = self.modo();
        let mut alvo = if self.jit && modo == MODO_USUARIO {
            Lado::Dyna
        } else {
            Lado::Interp
        };
        if alvo == Lado::Dyna {
            self.desde_interp += 1;
            if self.desde_interp >= FATIAS_INTERP_A_CADA {
                alvo = Lado::Interp;
            }
        }
        if alvo == Lado::Interp {
            self.desde_interp = 0;
        }
        if alvo != self.ativo {
            self.sincroniza(alvo);
        }
        self.ativo = alvo;
        match alvo {
            Lado::Interp => self.interp.run(pc, max_instructions),
            Lado::Dyna => {
                let antes = self.dyna.instructions();
                let saida = self.dyna.run(pc, max_instructions)?;
                match saida {
                    StopReason::Budget => Ok(saida),
                    StopReason::MemoryFault { addr, pc: pc_falta } => {
                        // Harness maps/pages on faults: sync the faulting
                        // state to the interpretador first, so every
                        // handler read (regs, CPSR, TTBR0, history) sees
                        // the fault site, not the last interp slice.
                        self.sincroniza(Lado::Interp);
                        self.ativo = Lado::Interp;
                        Ok(StopReason::MemoryFault { addr, pc: pc_falta })
                    }
                    StopReason::Exception { pc: pc_falta } => {
                        // SVC/undefined inside a JIT slice: the JIT cannot
                        // enter privileged code itself, so hand the faulting
                        // instruction to the interpretador, which delivers
                        // the exception (SVC entry, undef) and continues
                        // for the rest of the budget. The faulting pc is
                        // re-executed there by design — that IS delivery.
                        // (Completed pre-fault instructions are not
                        // re-run: only the remainder is granted.)
                        self.sincroniza(Lado::Interp);
                        self.ativo = Lado::Interp;
                        let feito = self.dyna.instructions().saturating_sub(antes);
                        let resto = max_instructions.saturating_sub(feito);
                        self.interp.run(pc_falta, resto)
                    }
                    // API/return need no delivery: sync and pass through.
                    outra => {
                        self.sincroniza(Lado::Interp);
                        self.ativo = Lado::Interp;
                        Ok(outra)
                    }
                }
            }
        }
    }

    fn read_reg(&self, reg: Reg) -> u32 {
        match self.ativo {
            Lado::Interp => self.interp.read_reg(reg),
            Lado::Dyna => self.dyna.read_reg(reg),
        }
    }

    fn write_reg(&mut self, reg: Reg, value: u32) {
        match self.ativo {
            Lado::Interp => self.interp.write_reg(reg, value),
            Lado::Dyna => self.dyna.write_reg(reg, value),
        }
    }

    fn instructions(&self) -> u64 {
        self.interp
            .instructions()
            .saturating_add(self.dyna.instructions())
    }

    fn relato_do_jit(&self) -> Option<(u64, u64, u64)> {
        self.dyna.relato_do_jit()
    }

    fn cpsr(&self) -> u32 {
        match self.ativo {
            Lado::Interp => self.interp.cpsr(),
            Lado::Dyna => self.dyna.cpsr(),
        }
    }

    fn set_cpsr(&mut self, valor: u32) {
        match self.ativo {
            Lado::Interp => self.interp.set_cpsr(valor),
            Lado::Dyna => self.dyna.set_cpsr(valor),
        }
    }

    fn set_instructions(&mut self, valor: u64) {
        // Pins the active backend's clock (the only writer on the Dream
        // path is a harness stopwatch, which never runs here).
        match self.ativo {
            Lado::Interp => self.interp.set_instructions(valor),
            Lado::Dyna => self.dyna.set_instructions(valor),
        }
    }

    fn em_thumb(&self) -> bool {
        match self.ativo {
            Lado::Interp => self.interp.em_thumb(),
            Lado::Dyna => self.dyna.em_thumb(),
        }
    }

    fn read_mem(&self, addr: u32, buf: &mut [u8]) -> Result<(), CpuError> {
        match self.ativo {
            Lado::Interp => self.interp.read_mem(addr, buf),
            Lado::Dyna => self.dyna.read_mem(addr, buf),
        }
    }

    fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<(), CpuError> {
        // Same bytes either way (shared map); invalidate the JIT window
        // so a patched code page re-translates instead of running stale.
        self.interp.write_mem(addr, data)?;
        self.dyna.invalida(addr, data.len() as u32);
        Ok(())
    }

    fn read_u32(&self, addr: u32) -> Result<u32, CpuError> {
        match self.ativo {
            Lado::Interp => self.interp.read_u32(addr),
            Lado::Dyna => self.dyna.read_u32(addr),
        }
    }

    fn write_u32(&mut self, addr: u32, value: u32) -> Result<(), CpuError> {
        self.write_mem(addr, &value.to_le_bytes())
    }

    fn read_cbytes(&self, addr: u32, max_len: usize) -> Vec<u8> {
        match self.ativo {
            Lado::Interp => self.interp.read_cbytes(addr, max_len),
            Lado::Dyna => self.dyna.read_cbytes(addr, max_len),
        }
    }

    fn read_cstring(&self, addr: u32, max_len: usize) -> String {
        match self.ativo {
            Lado::Interp => self.interp.read_cstring(addr, max_len),
            Lado::Dyna => self.dyna.read_cstring(addr, max_len),
        }
    }

    fn map_zeroed(&mut self, name: &'static str, base: u32, len: usize) -> Result<(), CpuError> {
        // One mapping in the shared map; the JIT fast table only
        // matters while the JIT may run (rebuilding it is a full
        // page walk — see permite_jit, which rebuilds once on
        // enabling instead of per map).
        self.interp.map_zeroed(name, base, len)?;
        if self.jit {
            self.dyna.atualiza_tabela(base, len as u32);
        }
        Ok(())
    }

    fn desmapeia_intervalo(&mut self, base: u32, len: usize) -> Result<(), CpuError> {
        // Carving reallocates survivor buffers, so no stale fast-table
        // entry may survive — but only while the JIT may run (same
        // rebuild-on-enable deal as map_zeroed).
        self.interp.desmapeia_intervalo(base, len)?;
        if self.jit {
            self.dyna.reconstroi_tabela();
        }
        Ok(())
    }

    fn fill_mem(&mut self, addr: u32, valor: u8, len: u32) -> Result<(), CpuError> {
        self.interp.fill_mem(addr, valor, len)?;
        self.dyna.invalida(addr, len);
        Ok(())
    }

    fn suja_pilha(&mut self, addr: u32, len: u32) -> Result<(), CpuError> {
        // Stack dirt only matters to the JIT's invalidation tracking.
        self.dyna.suja_pilha(addr, len)
    }

    fn watch_dirty(&mut self, id: u32, base: u32, len: u32) -> Result<(), CpuError> {
        self.dyna.watch_dirty(id, base, len)
    }

    fn unwatch_dirty(&mut self, id: u32) {
        self.dyna.unwatch_dirty(id)
    }

    fn take_dirty(&mut self, id: u32) -> bool {
        self.dyna.take_dirty(id)
    }

    fn marca_sujo(&mut self, addr: u32, len: u32) {
        self.dyna.marca_sujo(addr, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::mem::GuestMemory;

    fn cpu_com(code: &[u8]) -> DualBackend {
        let mut mem = GuestMemory::new();
        let mut bytes = code.to_vec();
        bytes.resize(0x1000, 0);
        mem.map("codigo", 0, bytes, true).unwrap();
        mem.map_zeroed("pilha", 0x2000_0000, 0x1000).unwrap();
        let mut cpu = DualBackend::new().unwrap();
        cpu.reset(&mem).unwrap();
        // Unit code is genuine userspace (no control-field MSR, no
        // exceptions): enable the JIT path under test.
        cpu.permite_jit(true);
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        cpu
    }

    #[test]
    fn inicia_no_interpretador_e_passa_para_o_jit_em_usuario() {
        // mov r0, #0x37 ; b . — reset leaves CPSR in USR, so the first
        // slice already runs on Dynarmic; r0 proves the JIT executed it.
        let code = [0xe3a0_0037u32.to_le_bytes(), 0xeaff_fffeu32.to_le_bytes()].concat();
        let mut cpu = cpu_com(&code);
        assert_eq!(cpu.proximo(), "dyna");
        assert_eq!(cpu.run(0, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x37);
    }

    #[test]
    fn estado_sobrevive_a_troca_de_ida_e_volta() {
        // r1 survives interp -> dyna -> interp: the sync copies the file.
        let code = [0xe3a0_002au32.to_le_bytes(), 0xeaff_fffeu32.to_le_bytes()].concat();
        let mut cpu = cpu_com(&code);
        assert_eq!(cpu.run(0, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x2a);
        cpu.write_reg(Reg::R1, 0x1234);
        // Force an interp slice, then back: registers must round-trip.
        cpu.desde_interp = super::FATIAS_INTERP_A_CADA - 1;
        assert_eq!(cpu.run(0x8, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R1), 0x1234);
        assert_eq!(cpu.read_reg(Reg::R0), 0x2a);
    }

    #[test]
    fn armadilha_dispara_nos_dois_lados() {
        // Trap on the second instruction: it must fire whether the slice
        // runs on the JIT or the interpretador.
        let code = [
            0xe3a0_0001u32.to_le_bytes(),
            0xe3a0_0002u32.to_le_bytes(),
            0xeaff_fffeu32.to_le_bytes(),
        ]
        .concat();
        let mut cpu = cpu_com(&code);
        let visto = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let copia = visto.clone();
        cpu.trap_pc_mem(0x4, move |_mem, regs| {
            copia.set(regs[0]);
        });
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Budget);
        assert_eq!(visto.get(), 1);
        assert_eq!(cpu.read_reg(Reg::R0), 2);
    }

    #[test]
    fn armadilha_nao_remenda_sem_jit() {
        // With the JIT off (bring-up: SPL/kernel), arming a serving trap
        // must not patch guest memory — the interpretador would fetch
        // the SVC patch as a real instruction and die (seen live:
        // `svc #0xD00000` executed at the SPL print routine, vectors
        // garbage, run over at slice 0). Enabling later arms Dynarmic.
        let code = [
            0xe3a0_0001u32.to_le_bytes(),
            0xe3a0_0002u32.to_le_bytes(),
            0xeaff_fffeu32.to_le_bytes(),
        ]
        .concat();
        let mut mem = GuestMemory::new();
        let mut bytes = code.to_vec();
        bytes.resize(0x1000, 0);
        mem.map("codigo", 0, bytes, true).unwrap();
        mem.map_zeroed("pilha", 0x2000_0000, 0x1000).unwrap();
        let mut cpu = DualBackend::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        let visto = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let copia = visto.clone();
        cpu.trap_pc_mem(0x4, move |_mem, regs| {
            copia.set(regs[0]);
        });
        // Bytes intact, hook fires on the interpretador, real code runs.
        assert_eq!(cpu.read_u32(0x4).unwrap(), 0xe3a0_0002);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Budget);
        assert_eq!(visto.get(), 1);
        assert_eq!(cpu.read_reg(Reg::R0), 2);
        // Enabling the JIT arms Dynarmic over the same shared hook.
        cpu.permite_jit(true);
        let visto2 = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let copia2 = visto2.clone();
        cpu.trap_pc_mem(0x0, move |_mem, regs| {
            copia2.set(regs[0]);
        });
        assert_eq!(cpu.run(0x0, 10).unwrap(), StopReason::Budget);
        assert_eq!(visto2.get(), 2);
    }
}
