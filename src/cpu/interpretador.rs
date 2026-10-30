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

use std::cell::RefCell;
use std::rc::Rc;

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

/// Total IRQ deliveries taken since reset. The per-delivery ENTRA log
/// is gated and capped; TIMERSTATE samples this counter to show the
/// true tick rate (monotonic — read-only for the harness).
pub static mut ULTIMA_ENTREGA: u32 = 0;
/// Total data/prefetch aborts delivered to the guest since reset
/// (see entra_aborto): user page faults handled by the kernel's
/// own do_page_fault instead of stopping the run.
pub static mut TOTAL_ABORTOS: u32 = 0;
/// MDDI host IRQ16 edge (see the MDDIWR watch in es_mem and
/// vic_nivel): true while a command is outstanding (CMD doorbell
/// written, INT not yet acked). Lets the VIC raise line 16 so the
/// real MDDI IRQ handler runs and completes the waiters.
pub static mut MDDI_IRQ_PENDENTE: bool = false;
/// Total SVC (syscall) exceptions delivered to the guest kernel
/// since reset (see entra_svc): Linux userspace syscalls (set_tls
/// first — it writes the TLS value to 0xFFFF0FF0, without which
/// init segfaults on a null+8 store) run through the guest's own
/// vector_swi instead of the semihosting stub.
pub static mut TOTAL_SVC: u32 = 0;
/// Total unmask edges (cpsie/exception-return/msr clearing I) since
/// reset. TIMERSTATE samples it alongside deliveries: unmasks without
/// deliveries = the line/edge gate is the blocker; no unmasks at all =
/// something holds I=1 (mask-holder hunt).
pub static mut TOTAL_DESMASCA: u32 = 0;
/// Total maskings (cpsid/msr setting I/exception entry saving I=0? no:
/// only explicit sets) since reset. Rate per slice shows whether the
/// guest still toggles IRQs (alive) or is stuck masked (wall).
pub static mut TOTAL_MASCARA: u32 = 0;
/// WFI executions since reset (see TIMERSTATE): distinguishes a
/// sleeping idle loop (WFI burns whole slices) from a busy spin
/// (no WFI, full slices executed).
pub static mut TOTAL_WFI: u32 = 0;

/// Semihosting operations recorded by the `unicorn` hook. The `SVC` immediate does not change
/// course: any `SVC` looks at the operation in `r0`. The PopCap games initialize through here.
const SYS_WRITEC: u32 = 0x03;
const SYS_WRITE0: u32 = 0x04;
const MAX_SEMIHOSTING_STRING: u32 = 4096;

pub struct Interpretador {
    /// Guest memory, shared with a sibling backend when the Dream harness
    /// runs hybrid (see `DualBackend`): both backends read and write the
    /// same map, so demand-paged content and trap-served bytes survive a
    /// backend switch. Borrowed per access; never held across a hook call
    /// (hooks receive `&mut` directly instead of re-borrowing).
    mem: Rc<RefCell<GuestMemory>>,
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
    fonte_irq: Option<Box<dyn FnMut(&GuestMemory, bool) -> bool>>,
    /// Set by WFI (CP15 c7,c0,4): idle until the line rises.
    esperando: bool,
    sondagem_irq: u32,
    /// An unmask happened (cpsie / exception return / msr clearing
    /// I): recheck the line at the next loop top. The 64-instruction
    /// poll counter provably strides over brief unmasked windows
    /// (live: idle unmasks every iteration, zero deliveries for
    /// 200k slices) — this edge makes delivery unmissable.
    irq_pendente: bool,
    /// Timer/IRQ state changed (MMIO write or per-slice COUNT
    /// catch-up flipped STATUS 0->1): recheck the line at the next
    /// UNMASKED loop top. Unlike irq_pendente (consumed by the first
    /// check), this persists across masked stretches, so an edge born
    /// while masked is served at the next unmask instead of being
    /// sampled away. Set in es_mem (timer/EN writes) and by the
    /// harness per-slice plant (STATUS rising edge).
    timer_sujo: bool,
}

impl Interpretador {
    pub fn new() -> Result<Self, CpuError> {
        Self::with_shared_mem(Rc::new(RefCell::new(GuestMemory::new())))
    }

    /// Same as `new`, but the guest map is shared with a sibling backend
    /// (see `DualBackend`): both backends read and write the same bytes,
    /// so demand-paged and trap-served content survives a backend switch.
    /// `reset` replaces the map *contents* without swapping the `Rc`,
    /// keeping every clone valid.
    pub fn with_shared_mem(mem: Rc<RefCell<GuestMemory>>) -> Result<Self, CpuError> {
        Ok(Self {
            mem,
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
            irq_pendente: false,
            timer_sujo: false,
        })
    }

    /// Full architected state for halt traces: general registers,
    /// CPSR, per-mode SPSR and banked R13/R14. Inherent (not trait):
    /// only the interpreter backend needs it and the trait stays
    /// Dynarmic-compatible.
    pub fn estado_completo(&self) -> ([u32; 16], u32, [u32; 6], [[u32; 2]; 6]) {
        (self.r, self.cpsr, self.spsr, self.banco)
    }

    /// User-owned zeroed region for the current mm (demand-paged user
    /// page: text, stack, heap). Inherent (not trait): only the
    /// interpreter backend needs it and the trait stays
    /// Dynarmic-compatible.
    pub fn map_usuario_zeroed(&mut self, name: &'static str, base: u32, len: usize) -> Result<(), CpuError> {
        self.mem.borrow_mut()
            .map_usuario_zeroed(name, base, len)
            .map_err(|e| CpuError(e.to_string()))
    }

    /// TEMP (snapshots): fotografa o núcleo arquitetural (o guest vê
    /// isto; traps, vigias canário, histórico e `fonte_irq` são da
    /// harness e remontados pelo setup). Remove com o CRASHOBJ se os
    /// snapshots não vingarem.
    pub(crate) fn foto_nucleo(&self) -> crate::msm7201a_snapshot::NucleoFoto {
        crate::msm7201a_snapshot::NucleoFoto {
            r: self.r,
            cpsr: self.cpsr,
            spsr: self.spsr,
            banco: self.banco,
            exclusivo: self.exclusivo,
            instrucoes: self.instrucoes,
            cp15: self.cp15.clone(),
            esperando: self.esperando,
            irq_pendente: self.irq_pendente,
            timer_sujo: self.timer_sujo,
            sondagem_irq: self.sondagem_irq,
            desde_interp: 0,
        }
    }

    /// TEMP (snapshots): restaura o núcleo (par de `foto_nucleo`).
    pub(crate) fn aplica_nucleo(&mut self, n: &crate::msm7201a_snapshot::NucleoFoto) {
        self.r = n.r;
        self.cpsr = n.cpsr;
        self.spsr = n.spsr;
        self.banco = n.banco;
        self.exclusivo = n.exclusivo;
        self.instrucoes = n.instrucoes;
        self.cp15 = n.cp15.clone();
        self.esperando = n.esperando;
        self.irq_pendente = n.irq_pendente;
        self.timer_sujo = n.timer_sujo;
        self.sondagem_irq = n.sondagem_irq;
    }

    /// Current address space key (masked TTBR0, tracked on MCR).
    pub fn mm_atual(&self) -> u32 {
        self.mem.borrow().mm_atual()
    }

    /// Current execve generation (bumped whenever exec replaces the
    /// image, so per-(mm, base) trackers tell a post-exec re-fault
    /// from a tight abort loop).
    pub fn geracao(&self) -> u32 {
        self.mem.borrow().geracao()
    }

    /// Records which physical page a user region was mirrored from
    /// (for the adopt check on post-exec re-faults).
    pub fn anotar_semente(&mut self, base: u32, pa: u32) {
        self.mem.borrow_mut().anotar_semente(base, pa);
    }

    /// Sibling mapping of the same VA in another current-generation
    /// mm mirroring the same physical page, if any (fork-COW content
    /// to copy instead of seeding zeros from a pa bank that never
    /// held user bytes). The pa gate keeps different binaries sharing
    /// the 0x8000 load address from swapping text.
    pub fn irmao_mesma_va(&self, base: u32, pa: u32) -> Option<Vec<u8>> {
        self.mem.borrow().irmao_mesma_va(base, pa)
    }

    /// Current mm's own region at `base`, if any (seed pa + generation,
    /// regardless of whether the generation is still current).
    pub fn regiao_propria(&self, base: u32) -> Option<(Option<u32>, u32)> {
        self.mem.borrow().regiao_propria(base)
    }

    /// Refreshes a same-pa region's generation in place (adopt).
    pub fn adotar_geracao(&mut self, base: u32) {
        self.mem.borrow_mut().adotar_geracao(base);
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

    /// Install the IRQ line source: `fonte(mem, livre)` returns
    /// whether any enabled interrupt is pending. `livre` is true only
    /// when the caller will actually deliver (I==0): the harness
    /// latch advances its MATCH one-shot only on delivering
    /// evaluations, so a masked observation must never consume the
    /// edge. Polled between instructions while CPSR.I is clear (and
    /// while idling in WFI).
    pub fn set_fonte_irq(&mut self, fonte: impl FnMut(&GuestMemory, bool) -> bool + 'static) {
        self.fonte_irq = Some(Box::new(fonte));
    }

    fn linha_irq(&mut self, livre: bool) -> bool {
        match self.fonte_irq.as_mut() {
            Some(f) => f(&self.mem.borrow(), livre),
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
        // TEMP (I-change hunt): log exception returns that flip I,
        // gated to the preempt-BUG window (ins >= 166M, cap 200).
        // An early uncapped run died at boot (cap 10 consumed by
        // SPL/kernel transitions) and went blind before the fault.
        if let Some(spsr) = self.spsr_atual() {
            let antes_i = self.cpsr & 0x80;
            let depois_i = spsr & 0x80;
            if antes_i != depois_i {
                static mut NRET: u32 = 0;
                unsafe {
                    if self.instrucoes >= 245_000_000 && NRET < 200 {
                        NRET += 1;
                        let n = NRET;
                        eprintln!("RETX#{n} ins={} alvo={alvo:#x} mode={mode:#x} I:{a}->{b}", self.instrucoes, mode = self.cpsr & 0x1F, a = antes_i != 0, b = depois_i != 0);
                    }
                }
            }
            self.troca_modo(spsr);
            // Unmask edge: genuine 1->0 only.
            if antes_i != 0 && depois_i == 0 {
                self.irq_pendente = true;
                unsafe { TOTAL_DESMASCA = TOTAL_DESMASCA.wrapping_add(1); }
            }
        }
        self.r[15] = if self.thumb() { alvo & !1 } else { alvo & !3 };
    }

    /// Write a cached CP15 register (same key layout as the read
    /// path). The harness uses it for FAR/DFSR on abort entry.
    pub fn escreve_cp15(&mut self, chave: u32, valor: u32) {
        match self.cp15.iter_mut().find(|(k, _)| *k == chave) {
            Some(slot) => slot.1 = valor,
            None => self.cp15.push((chave, valor)),
        }
    }

    /// Take a data/prefetch abort for the fault at `r[15]` (which
    /// sits AT the faulting pc for fault traps). lr = fault+8 for
    /// data aborts, fault+4 for prefetch aborts (matching the
    /// guest's `subs pc, lr, #8` / `#4` retry convention); r15 =
    /// vector, mode ABT with I and A masked, FAR/FSR recorded. Delivers guest
    /// page faults (do_page_fault) to the kernel instead of stopping
    /// the run — mandatory for userspace: ELF demand-paging faults
    /// on real hardware too. `fsr` is the fault status (0x5 section /
    /// 0x7 page translation fault); `prefetch` selects the IFSR key
    /// (0x281) and vector 0x0C, else DFSR (0x280) and 0x10.
    /// Counts in TOTAL_ABORTOS. NOT re-entrant: the harness must
    /// not call this while already in ABT mode (single spsr_abt).
    pub fn entra_aborto(&mut self, addr_falta: u32, fsr: u32, prefetch: bool) {
        let velho = self.cpsr;
        unsafe {
            TOTAL_ABORTOS = TOTAL_ABORTOS.wrapping_add(1);
        }
        static mut NABT: u32 = 0;
        unsafe {
            if NABT < 400 {
                NABT += 1;
                let n = NABT;
                eprintln!("ABORT#{n} ins={} velho={velho:#x} pc={:#x} far={addr_falta:#x} fsr={fsr:#x} pre={prefetch} mm={:#x}", self.instrucoes, self.r[15], self.mem.borrow().mm_atual());
                // TEMP (child-fault path): historico no abort com
                // mm do pai/filho (0x16238000) — de onde veio o pc
                // selvagem (fork-return? ramo filho do init? salto
                // louco?). Cap 4. Remove with CRASHOBJ.
                if self.mem.borrow().mm_atual() == 0x1623_8000 {
                    static mut NHF: u32 = 0;
                    unsafe {
                        if NHF < 4 {
                            NHF += 1;
                            let h = self.historico();
                            let ini = h.len().saturating_sub(120);
                            eprintln!("ABHIST f={} pcs={:08x?}", unsafe { crate::msm7201a::FATIA_ATUAL }, &h[ini..]);
                        }
                    }
                }
            }
        }
        // ABT-bank SP fallback (same root cause as IRQ: reset leaves
        // it undefined; the kernel programs it in cpu_init). Private
        // page — IRQ uses 0xC8300000, FIQ its lower half.
        if self.r[13] == 0 {
            const PILHA_ABT: u32 = 0xC831_0000;
            const TAM_PILHA_ABT: usize = 0x1000;
            if self.mem.borrow().read_u32(PILHA_ABT).is_err() {
                let _ = self.mem.borrow_mut().map_zeroed("pilha_abt", PILHA_ABT, TAM_PILHA_ABT);
            }
            self.r[13] = PILHA_ABT.wrapping_add(TAM_PILHA_ABT as u32);
        }
        // FAR (c6,c0,0 → 0x300), DFSR (c5,c0,0 → 0x280) / IFSR
        // (c5,c0,1 → 0x281). Domain 0: translation faults only (the
        // flat model has no permissions to violate).
        self.escreve_cp15(0x300, addr_falta);
        self.escreve_cp15(if prefetch { 0x281 } else { 0x280 }, fsr);
        self.spsr[4] = velho;
        // ARMv6 abort entry: mode ABT, ARM state, I and A masked.
        // Switch banks FIRST (like entra_irq): writing r14 before
        // the swap would be clobbered by the bank load.
        self.troca_modo((velho & !(0x1F | T)) | 0x17 | 0x80 | 0x100);
        // lr = fault+8 for data aborts (the guest's `subs pc, lr, #8`
        // re-executes the faulting instruction), fault+4 for prefetch
        // aborts (guest resumes with `subs pc, lr, #4`). r15 sits AT
        // the fault for fault traps (unlike IRQ delivery, where it
        // has advanced past — proven live: ABORT-VEC lr was fault+4
        // with an r15+4 formula, and the prefetch path then skipped
        // its faulting ldr and branched on stale ip=0, jumping to 0).
        self.r[14] = self.r[15].wrapping_add(if prefetch { 4 } else { 8 });
        // CP15 c1 (key 0x80) bit 13: high vectors.
        let sctlr = self.cp15.iter().find(|(k, _)| *k == 0x80).map_or(0, |(_, v)| *v);
        let vet = if sctlr & (1 << 13) != 0 { 0xFFFF_0000 } else { 0x0 };
        self.r[15] = vet | if prefetch { 0x0C } else { 0x10 };
    }

    /// Take an undefined-instruction exception for the faulting `r[15]`
    /// (which sits AT the faulting instruction): delivers user-mode
    /// garbage execution to the guest's own UND handler instead of
    /// stopping the run — mandatory past service startup, where any
    /// dying service (missing hardware, bad pointer) would otherwise
    /// end the whole boot. The kernel's __und_usr sends SIGILL and
    /// init restarts the service; the run continues. spsr_und (idx 5),
    /// lr = fault+4 ARM / fault+2 Thumb (pipeline-correct; the guest
    /// never resumes from it anyway), vector 0x04 (SCTLR.V aware).
    /// I masked, A untouched (spec), ARM state. Counts in TOTAL_ABORTOS
    /// (shares the abort budget: same delivery family). NOT re-entrant
    /// (single spsr_und): the harness routes only USR-mode UNDs here.
    pub fn entra_undef(&mut self) {
        let velho = self.cpsr;
        unsafe {
            TOTAL_ABORTOS = TOTAL_ABORTOS.wrapping_add(1);
        }
        static mut NUND: u32 = 0;
        unsafe {
            if NUND < 80 {
                NUND += 1;
                let n = NUND;
                let ins = if let Ok(s) = self.mem.borrow().read(self.r[15] & !3, 4) {
                    u32::from_le_bytes([s[0], s[1], s[2], s[3]])
                } else {
                    0xDEAD_DEAD
                };
                // Top of user stack: return addresses name the
                // crashing function/binary offline (pc alone is
                // often a wild jump into data).
                let mut st = [0u32; 8];
                for (i, s) in st.iter_mut().enumerate() {
                    *s = self.mem.borrow().read_u32(self.r[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEAD);
                }
                eprintln!("UND#{n} ins={} velho={velho:#x} pc={:#x} mm={:#x} insn={ins:#x} sp={:#x} lr={:#x} stk={st:#x?}", self.instrucoes, self.r[15], self.mem.borrow().mm_atual(), self.r[13], self.r[14]);
            }
        }
        // UND-bank SP fallback (same root cause as IRQ/ABT/SVC:
        // reset leaves it undefined; the kernel never programs it
        // on a healthy boot because no UND ever fires). Private
        // page (ABT 0xC8310000, SVC 0xC8320000).
        if self.r[13] == 0 {
            const PILHA_UND: u32 = 0xC833_0000;
            const TAM_PILHA_UND: usize = 0x1000;
            if self.mem.borrow().read_u32(PILHA_UND).is_err() {
                let _ = self.mem.borrow_mut().map_zeroed("pilha_und", PILHA_UND, TAM_PILHA_UND);
            }
            self.r[13] = PILHA_UND.wrapping_add(TAM_PILHA_UND as u32);
        }
        self.spsr[5] = velho;
        // Thumb-ness BEFORE the switch below clears T (lr formula
        // depends on the faulting state, not the handler state).
        let era_thumb = self.thumb();
        // ARMv6 UND entry: mode UND, ARM state, I masked (A per spec
        // untouched — our async aborts don't exist, and the guest
        // UND path never observes it). Switch banks FIRST (like
        // entra_aborto/entra_irq): writing r14 before the swap would
        // be clobbered by the bank load.
        self.troca_modo((velho & !(0x1F | T)) | 0x1B | 0x80);
        // lr = fault+4 ARM / fault+2 Thumb (r15 sits AT the faulting
        // instruction, unlike IRQ delivery where it has advanced).
        self.r[14] = self.r[15].wrapping_add(if era_thumb { 2 } else { 4 });
        // CP15 c1 (key 0x80) bit 13: high vectors.
        let sctlr = self.cp15.iter().find(|(k, _)| *k == 0x80).map_or(0, |(_, v)| *v);
        self.r[15] = (if sctlr & (1 << 13) != 0 { 0xFFFF_0000 } else { 0x0 }) | 0x04;
    }

    /// Whether the CPU is currently in USR mode (for the harness:
    /// only user-mode faults are deliverable to the guest; kernel
    /// faults always stop the run).
    pub fn em_usuario(&self) -> bool {
        self.cpsr & 0x1F == MODO_USUARIO
    }

    /// Take a Linux syscall (SVC) exception for the `svc` at `r[15]`
    /// (which sits AT the faulting instruction): lr = next
    /// instruction (fault+4 ARM, fault+2 Thumb — the guest resumes
    /// with plain `movs pc, lr`), r15 = SWI vector 0x08, mode SVC
    /// with I masked (A per spec untouched — our async aborts don't
    /// exist, and the guest never observes it), T forced ARM.
    /// Delivers userspace syscalls (set_tls first: it writes the
    /// TLS value to 0xFFFF0FF0, without which init segfaults) to
    /// the guest's own vector_swi instead of the semihosting stub.
    /// Counts in TOTAL_SVC. NOT re-entrant (single spsr_svc): the
    /// caller routes only USR-mode SVCs here; the harness must not
    /// call this from SVC/ABT/FIQ.
    pub fn entra_svc(&mut self) {
        let velho = self.cpsr;
        unsafe {
            TOTAL_SVC = TOTAL_SVC.wrapping_add(1);
        }
        static mut NSVC: u32 = 0;
        unsafe {
            if NSVC < 300 {
                NSVC += 1;
                let n = NSVC;
                eprintln!("SVC#{n} ins={} velho={velho:#x} pc={:#x} r7={:#x} r0={:#x}", self.instrucoes, self.r[15], self.r[7], self.r[0]);
            }
            // TEMP (Audio-init syscall watch): log every SVC in the
            // system_server init window (cap 400) to find the
            // setCapabilities/capset failure. Remove with CRASHOBJ.
            static mut NSVCA: u32 = 0;
            let f = crate::msm7201a::FATIA_ATUAL;
            if (579_000..586_500).contains(&f) && NSVCA < 2000 {
                NSVCA += 1;
                let n = NSVCA;
                eprintln!("SVCA#{n} f={f} pc={:#x} r7={:#x} r0={:#x} r1={:#x} r2={:#x}", self.r[15], self.r[7], self.r[0], self.r[1], self.r[2]);
                // TEMP (capset forensics): dump pointed-to structs for the
                // identity/capability calls (the setCapabilities EPERM
                // source): capset header/data, prctl args are values.
                // Remove with CRASHOBJ.
                if matches!(self.r[7], 0xb9 | 0xb8 | 0xac | 0xd5 | 0xd6 | 0xce) {
                    let mb = self.mem.borrow();
                    let mut h0 = [0u8; 16];
                    let ok0 = mb.read(self.r[0], 16).map(|s| h0.copy_from_slice(s)).is_ok();
                    let mut h1 = [0u8; 16];
                    let ok1 = mb.read(self.r[1], 16).map(|s| h1.copy_from_slice(s)).is_ok();
                    eprintln!("SVCARG#{n} r7={:#x} [r0]ok={ok0}={h0:02x?} [r1]ok={ok1}={h1:02x?}", self.r[7]);
                }
            }
            // TEMP (failure attribution): snapshot regs when the guest
            // writes a key failure line (EPERM / Missing classname /
            // preload failure) so the caller is named, not just the
            // message. Matches write()/writev() buffers; cap 8.
            // Remove with CRASHOBJ.
            if self.r[7] == 4 || self.r[7] == 146 {
                static mut NLG: u32 = 0;
                unsafe {
                    if NLG < 8 {
                        let mut achou = false;
                        if self.r[7] == 4 {
                            if let Ok(s) = self.mem.borrow().read(self.r[1], 96) {
                                // contains(), not windows(N): needles have
                                // mixed lengths (a 17-window can never match
                                // a 16-byte needle — which is why the
                                // "Shutting down VM" hunt stayed silent).
                                let t = String::from_utf8_lossy(s);
                                achou = t.contains("Missing classname")
                                    || t.contains("Error setting cap")
                                    || t.contains("Failure preloadin")
                                    || t.contains("Shutting down VM")
                                    || t.contains("Zygote died with")
                                    || t.contains("FATAL EXCEPTION:");
                            }
                        } else {
                            // writev(fd, iov, iovcnt): scan first 4 chunks.
                            for k in 0..4u32 {
                                let mut iv = [0u8; 8];
                                if self.mem.borrow().read(self.r[1].wrapping_add(k * 8), 8).map(|s| iv.copy_from_slice(s)).is_err() {
                                    break;
                                }
                                let ptr = u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]);
                                let len = u32::from_le_bytes([iv[4], iv[5], iv[6], iv[7]]);
                                if len == 0 || len > 512 {
                                    continue;
                                }
                                if let Ok(s) = self.mem.borrow().read(ptr, len.min(96)) {
                                    let t = String::from_utf8_lossy(s);
                                    if t.contains("Missing classname")
                                        || t.contains("Error setting cap")
                                        || t.contains("Failure preloadin")
                                        || t.contains("Shutting down VM")
                                        || t.contains("Zygote died with")
                                        || t.contains("FATAL EXCEPTION:")
                                    {
                                        achou = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if achou {
                            NLG += 1;
                            // Which message: re-read first chunk text for the tag.
                            let mut tag = String::from("?");
                            if let Ok(s2) = self.mem.borrow().read(self.r[1], 16) {
                                if s2.windows(9).any(|w| w == b"Missing c") {
                                    tag = String::from("missing-direct");
                                }
                            }
                            if tag == "?" {
                                // writev: dump chunk0 text (usually prio/tag).
                                let mut iv0 = [0u8; 8];
                                if self.mem.borrow().read(self.r[1], 8).map(|x| iv0.copy_from_slice(x)).is_ok() {
                                    let p0 = u32::from_le_bytes([iv0[0], iv0[1], iv0[2], iv0[3]]);
                                    let l0 = u32::from_le_bytes([iv0[4], iv0[5], iv0[6], iv0[7]]);
                                    if l0 != 0 && l0 < 256 {
                                        if let Ok(c0) = self.mem.borrow().read(p0, l0.min(64)) {
                                            tag = format!("iov0={:02x?}", &c0[..]);
                                        }
                                    }
                                }
                            }
                                                    // Native stack to name the caller chain
                        // (liblog <- Log JNI <- dalvik bridge?). 512 B: the
                        // start()-tail shutdown runs ~6+ frames above the
                        // writev and 128 B never reaches it. Remove with
                        // CRASHOBJ.
                        let mut nstk = [0u8; 512];
                        let okn = self.mem.borrow().read(self.r[13], 512).map(|s| nstk.copy_from_slice(s)).is_ok();
                        eprintln!("LOGWR#{} {} f={} pc={:#x} lr={:#x} r7={:#x} r0={:#x} r1={:#x} r2={:#x} sp={:#x} mm={:#x} nok={okn} nstk={nstk:02x?}", unsafe { NLG }, tag, unsafe { crate::msm7201a::FATIA_ATUAL }, self.r[15], self.r[14], self.r[7], self.r[0], self.r[1], self.r[2], self.r[13], self.mem.borrow().mm_atual());
                        }
                    }
                }
            }
        }
        // TEMP (exit-class watch): init dies via do_exit (no
        // segfault) — catch exit/exit_group (r7=1/248), execve
        // (r7=11), fork/clone (r7=2/120), kill/tkill/tgkill
        // (r7=37/238/241, r0=pid/tid, r1=sig — names the SIGKILL
        // sender behind the 584233+ mass deaths) with args + task +
        // lr + execve path. A service child failing execve (empty
        // /system!) exits 127 normally; init itself exiting is the
        // panic. Clone/fork presence separates the two stories.
        // Cap 40 (was 10): service execves/exits happen late
        // (f≈1.1B) and need headroom past early init.
        if self.r[7] == 1 || self.r[7] == 248 || self.r[7] == 11 || self.r[7] == 2 || self.r[7] == 120 || self.r[7] == 37 || self.r[7] == 238 || self.r[7] == 241 {
            static mut NEX: u32 = 0;
            unsafe {
                if NEX < 40 {
                    NEX += 1;
                    let ti = self.r[13] & !0x1FFF;
                    let task = self.mem.borrow().read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                    let mut extra = String::new();
                    if self.r[7] == 11 {
                        // Chunked read: a single 64 B read fails at
                        // region edges and misreports valid paths as
                        // <unmapped> (same lesson as formata_printk).
                        let mut nm = Vec::new();
                        let mut off = 0u32;
                        loop {
                            match self.mem.borrow().read(self.r[0].wrapping_add(off), 16) {
                                Ok(s) => {
                                    if let Some(z) = s.iter().position(|&b| b == 0) {
                                        nm.extend_from_slice(&s[..z]);
                                        break;
                                    }
                                    nm.extend_from_slice(s);
                                    off += 16;
                                    if nm.len() >= 64 {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        if nm.is_empty() {
                            extra = String::from(" path=<unmapped>");
                        } else {
                            extra = format!(" path={:?}", String::from_utf8_lossy(&nm));
                        }
                    }
                    // TEMP (exec-stack audit): the post-exec linker dies
                    // on NULL+0xa0 (str to [r7], r7 derived from a NULL
                    // solist) — dump the execve-time user stack
                    // (argc/argv/envp words) to see if OUR exec setup
                    // (or its serve) hands NULL. Cap 10. Remove with CRASHOBJ.
                    if self.r[7] == 11 {
                        static mut NXSTACK: u32 = 0;
                        unsafe {
                            if NXSTACK < 10 {
                                NXSTACK += 1;
                                let mut sw = [0u32; 12];
                                for (i, s) in sw.iter_mut().enumerate() {
                                    *s = self.mem.borrow().read_u32(self.r[13].wrapping_add((i as u32) * 4)).unwrap_or(0xDEADDEAD);
                                }
                                eprintln!("EXECSTK f={} sp={:#x} mm={:#x} stk={sw:#x?}", unsafe { crate::msm7201a::FATIA_ATUAL }, self.r[13], self.mem.borrow().mm_atual());
                            }
                        }
                    }
                    // Stack do chamador (quem chamou exit/abort/kill — o lr sozinho
        // nao basta: o abort() da libc esconde o chamador real).
        // 512 B como no LOGWR. Remove with CRASHOBJ.
        let mut nstk = [0u8; 512];
        let okn = self.mem.borrow().read(self.r[13], 512).map(|s| nstk.copy_from_slice(s)).is_ok();
        eprintln!("EXITCAL f={} r7={:#x} r0={:#x} r1={:#x} task={task:#x} lr={:#x} pc={:#x} mode={:#x} mm={:#x} nok={okn} nstk={nstk:02x?}{extra}", self.instrucoes, self.r[7], self.r[0], self.r[1], self.r[14], self.r[15], self.cpsr & 0x1F, self.mem.borrow().mm_atual());
                }
            }
        }
        // TEMP (binder snoop): the kernel HAS drivers/android/binder.c
        // (125 strings in vmlinux; open+mmap observed live), so the
        // work is observe-first, not implement-first. Log ioctl(54)
        // BINDER_WRITE_READ traffic read-only: BC_* out (target
        // handle, code, sizes, interface token) + BR_* in (replies
        // from the previous call, still in the buffer). Names who
        // talks to whom (servicemanager? system_server?) and where
        // it stalls. Cap 60. Remove with CRASHOBJ (or keep as the
        // binder bring-up tap).
        if self.r[7] == 54 {
            static mut NBI: u32 = 0;
            unsafe {
                if NBI < 60 {
                    NBI += 1;
                    let n = NBI;
                    let mb = self.mem.borrow();
                    let r = self.r;
                    let f = crate::msm7201a::FATIA_ATUAL;
                    let mm = mb.mm_atual();
                    let ti = r[13] & !0x1FFF;
                    let task = mb.read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                    let fd = r[0];
                    let cmd = r[1];
                    let arg = r[2];
                    // Decodifica WRITE_READ (0xC0186201) com parcimonia;
                    // outros cmds so o numero.
                    let mut det = String::new();
                    if cmd == 0xC0186201 {
                        let mut bw = [0u8; 24];
                        if mb.read(arg, 24).map(|s| bw.copy_from_slice(s)).is_ok() {
                            let wsz = u32::from_le_bytes([bw[0], bw[1], bw[2], bw[3]]) as usize;
                            let wbuf = u32::from_le_bytes([bw[8], bw[9], bw[10], bw[11]]);
                            let rsz = u32::from_le_bytes([bw[12], bw[13], bw[14], bw[15]]) as usize;
                            let rbuf = u32::from_le_bytes([bw[20], bw[21], bw[22], bw[23]]);
                            // Lado escrita: comandos BC_*.
                            let mut wb = vec![0u8; wsz.min(512)];
                            if !wb.is_empty() {
                                if mb.read(wbuf, wb.len() as u32).map(|s| wb.copy_from_slice(s)).is_ok() {
                                    let mut o = 0usize;
                                    let mut nb = 0;
                                    while o + 4 <= wb.len() && nb < 4 {
                                        let c = u32::from_le_bytes([wb[o], wb[o+1], wb[o+2], wb[o+3]]);
                                        o += 4;
                                        let cn = match c {
                                            0 => "TRANSACTION", 1 => "REPLY", 2 => "ACQUIRE_RESULT",
                                            3 => "FREE_BUFFER", 4 => "INCREFS", 5 => "ACQUIRE",
                                            6 => "RELEASE", 7 => "DECREFS", 8 => "INCREFS_DONE",
                                            9 => "ACQUIRE_DONE", 10 => "ATTEMPT_ACQUIRE",
                                            11 => "REGISTER_LOOPER", 12 => "ENTER_LOOPER",
                                            13 => "EXIT_LOOPER", 14 => "REQUEST_DEATH",
                                            15 => "CLEAR_DEATH", 16 => "DEAD_DONE",
                                            _ => "?",
                                        };
                                        if c <= 1 && o + 44 <= wb.len() {
                                            let tgt = u32::from_le_bytes([wb[o], wb[o+1], wb[o+2], wb[o+3]]);
                                            let code = u32::from_le_bytes([wb[o+8], wb[o+9], wb[o+10], wb[o+11]]);
                                            let ds = u32::from_le_bytes([wb[o+24], wb[o+25], wb[o+26], wb[o+27]]);
                                            let os = u32::from_le_bytes([wb[o+28], wb[o+29], wb[o+30], wb[o+31]]);
                                            let pb = u32::from_le_bytes([wb[o+32], wb[o+33], wb[o+34], wb[o+35]]);
                                            // InterfaceToken: primeira string UTF-16 do payload.
                                            let mut itf = String::new();
                                            let mut tb = [0u8; 64];
                                            if mb.read(pb, 64).map(|s| tb.copy_from_slice(s)).is_ok() {
                                                let nch = u32::from_le_bytes([tb[0], tb[1], tb[2], tb[3]]) as usize;
                                                if nch > 0 && nch < 16 {
                                                    for k in 0..nch {
                                                        let ch = u16::from_le_bytes([tb[4+k*2], tb[5+k*2]]);
                                                        if ch == 0 || ch > 0x7e {
                                                            break;
                                                        }
                                                        itf.push(ch as u8 as char);
                                                    }
                                                }
                                            }
                                            det.push_str(&format!(" BC{c}={cn}->h{tgt:#x} code{code} ds{ds} os{os} [{itf}];"));
                                            o += 44 + ds as usize + os as usize;
                                        } else {
                                            det.push_str(&format!(" BC{c}={cn};"));
                                            // Payloads pequenos: pula com conservadorismo
                                            // (FREE_BUFFER=ptr, ref ops=handle+...).
                                            if c == 3 {
                                                o += 4;
                                            } else if (4..=7).contains(&c) || c == 14 || c == 15 {
                                                o += 8;
                                            }
                                        }
                                        nb += 1;
                                    }
                                }
                            }
                            // Lado leitura: respostas BR_* da chamada anterior.
                            let mut rb = vec![0u8; rsz.min(256)];
                            if !rb.is_empty() {
                                if mb.read(rbuf, rb.len() as u32).map(|s| rb.copy_from_slice(s)).is_ok() {
                                    let mut o = 0usize;
                                    let mut nb = 0;
                                    while o + 4 <= rb.len() && nb < 4 {
                                        let c = u32::from_le_bytes([rb[o], rb[o+1], rb[o+2], rb[o+3]]);
                                        o += 4;
                                        let cn = match c {
                                            0 => "ERROR", 1 => "OK", 2 => "TRANSACTION", 3 => "REPLY",
                                            4 => "ACQUIRE_RESULT", 5 => "DEAD_REPLY", 6 => "TRAN_COMPLETE",
                                            7 => "INCREFS", 8 => "ACQUIRE", 9 => "RELEASE",
                                            10 => "DECREFS", 11 => "ATTEMPT_ACQUIRE", 12 => "NOOP",
                                            13 => "SPAWN_LOOPER", 14 => "FINISHED", 15 => "DEAD_BINDER",
                                            16 => "CLEAR_DEATH_DONE", 17 => "FAILED_REPLY",
                                            _ => "?",
                                        };
                                        if c == 2 || c == 3 {
                                            if o + 44 <= rb.len() {
                                                let tgt = u32::from_le_bytes([rb[o], rb[o+1], rb[o+2], rb[o+3]]);
                                                let code = u32::from_le_bytes([rb[o+8], rb[o+9], rb[o+10], rb[o+11]]);
                                                let ds = u32::from_le_bytes([rb[o+24], rb[o+25], rb[o+26], rb[o+27]]);
                                                let os = u32::from_le_bytes([rb[o+28], rb[o+29], rb[o+30], rb[o+31]]);
                                                det.push_str(&format!(" BR{c}={cn} h{tgt:#x} code{code} ds{ds} os{os};"));
                                                o += 44 + ds as usize + os as usize;
                                            } else {
                                                det.push_str(&format!(" BR{c}={cn}(trunc);"));
                                                break;
                                            }
                                        } else {
                                            det.push_str(&format!(" BR{c}={cn};"));
                                            if c == 0 || c == 4 {
                                                o += 4;
                                            }
                                        }
                                        nb += 1;
                                    }
                                }
                            }
                            det = format!(" WR wsz{wsz} rsz{rsz}{det}");
                        }
                    }
                    eprintln!("BINDER#{n} f={f} mm={mm:#x} task={task:#x} fd={fd} cmd={cmd:#x}{det}");
                }
            }
        }
        // TEMP (block watch): where userspace parks when the boot
        // goes quiet — futex (240), nanosleep (162), poll (168),
        // select (142), epoll_wait (287), wait4 (114). Gated to
        // late boot (the stuck state forms past ~1.5B instrs; early
        // boot would burn any cap on linker futexes). Cap 30/type.
        // Remove once the zygote stall is named.
        // goes quiet — futex (240), nanosleep (162), poll (168),
        // select (142), epoll_wait (287), wait4 (114). Gated to
        // late boot (the stuck state forms past ~1.5B instrs; early
        // boot would burn any cap on linker futexes). Cap 30/type.
        // Remove once the zygote stall is named.
        // TEMP (stderr watch): captura escritas no fd 2 (stderr) na
        // janela do abort (583005) — a mensagem do assert/LOG_FATAL
        // morre no stub e o abort() fica mudo. r7==4 (write) com
        // r0==2, despeja 128 B; cap 10, janela 582900-583100.
        // Remove with CRASHOBJ.
        if self.r[7] == 4 && self.r[0] == 2 {
            static mut NER: u32 = 0;
            unsafe {
                let f = crate::msm7201a::FATIA_ATUAL;
                if (582_900..583_100).contains(&f) && NER < 10 {
                    NER += 1;
                    let n = NER;
                    let mut eb = [0u8; 128];
                    let oke = self.mem.borrow().read(self.r[1], 128).map(|s| eb.copy_from_slice(s)).is_ok();
                    let txt = String::from_utf8_lossy(&eb);
                    eprintln!("STDERR#{n} f={f} pc={:#x} lr={:#x} mm={:#x} ok={oke} msg={txt:?}", self.r[15], self.r[14], self.mem.borrow().mm_atual());
                }
            }
        }
        // goes quiet — futex (240), nanosleep (162), poll (168),
        // select (142), epoll_wait (287), wait4 (114). Gated to
        // late boot (the stuck state forms past ~1.5B instrs; early
        // boot would burn any cap on linker futexes). Cap 30/type.
        // Remove once the zygote stall is named.
        {
            let r7 = self.r[7];
            let qual = match r7 {
                240 | 162 | 168 | 142 | 287 | 114 => Some(r7),
                _ => None,
            };
            if let Some(q) = qual {
                if self.instrucoes > 1_500_000_000 {
                    static mut NBL: [u32; 6] = [0; 6];
                    let slot = match q {
                        240 => 0,
                        162 => 1,
                        168 => 2,
                        142 => 3,
                        287 => 4,
                        _ => 5,
                    };
                    unsafe {
                        if NBL[slot] < 30 {
                            NBL[slot] += 1;
                            let mm = self.mem.borrow().mm_atual();
                            // nanosleep req / futex timeout hint.
                            let mut xtra = String::new();
                            if q == 162 {
                                if let Ok(s) = self.mem.borrow().read(self.r[0], 8) {
                                    let sec = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
                                    let ns = u32::from_le_bytes([s[4], s[5], s[6], s[7]]);
                                    xtra = format!(" {sec}.{ns:09}");
                                }
                            }
                            eprintln!("BLOQUEIO f={} r7={q:#x} r0={:#x} r1={:#x} r2={:#x} mm={mm:#x}{xtra}", self.instrucoes, self.r[0], self.r[1], self.r[2]);
                        }
                    }
                }
            }
        }
        // TEMP (mmap watch, r7=192/mmap2): log addr/len/prot/flags/
        // fd/offset to find the fb0 mapping (init mmaps the smem
        // after opening /dev/graphics/fb0; the mapping's (mm, va,
        // len) is what the host presenter snapshots). Cap 100.
        // Remove once the presenter tracks the mapping itself.
        if self.r[7] == 192 {
            static mut NMM: u32 = 0;
            unsafe {
                if NMM < 100 {
                    NMM += 1;
                    let n = NMM;
                    eprintln!("MMAP#{n} f={} mm={:#x} addr={:#x} len={:#x} prot={:#x} flags={:#x} fd={:#x} off={:#x}", self.instrucoes, self.mem.borrow().mm_atual(), self.r[0], self.r[1], self.r[2], self.r[3], self.r[4], self.r[5]);
                }
            }
            // TEMP (stale-alias carve): the SPL section-table alias
            // VA 0x80000000 x64 (`ram_banco1` in the harness) is a
            // flat-model static region that outlives the handoff it
            // exists for. It shadows every later guest user mapping
            // in that bank with stale zeros (proven: libOmxCore's
            // load at 0x80000000 reads zeros, si setup parses
            // e_phoff=0/e_phnum=0, link_image finds no DYNAMIC and
            // tears the load down). Carve the requested overlap out
            // of the shadow so the guest's own mapping wins and
            // later faults serve file content (same precedent as
            // `desmapeia_intervalo`'s doc comment). Runs at most
            // once per overlapping mmap; the kernel never maps here
            // itself (user range), so only genuine user mappings
            // trigger it. Canonical defs live in msm7201a.rs.
            const SOMBRA_BASE: u32 = 0x8000_0000;
            const SOMBRA_FIM: u32 = 0x8400_0000;
            {
                let base = self.r[0];
                let fim = base.saturating_add(self.r[1]);
                if base < SOMBRA_FIM && fim > SOMBRA_BASE && fim > base {
                    let ini = base.max(SOMBRA_BASE);
                    let mut mem = self.mem.borrow_mut();
                    mem.desmapeia_intervalo(ini, (fim.min(SOMBRA_FIM) - ini) as usize);
                }
            }
            // TEMP (linker load-stage watch): round-1 (mediaserver,
            // ~562M insns) loads libOmxCore fine, round-2 (zygote
            // preload, ~656M) fails after a successful open — with
            // mapping activity but a stale "Cannot find library".
            // Log every mmap in both windows to compare the segment
            // maps (fd 3 vs fd 14 stand out). Open-ended on the
            // right: the libmedia_jni self-map lands past 658M.
            // Cap 250. Remove with OPENRET once the stage is named.
            static mut NMM2: u32 = 0;
            unsafe {
                let f = self.instrucoes;
                if NMM2 < 250 && ((562_000_000..563_500_000).contains(&f) || f >= 656_300_000) {
                    NMM2 += 1;
                    let n = NMM2;
                    eprintln!("MMAP2#{n} f={f} mm={:#x} addr={:#x} len={:#x} prot={:#x} flags={:#x} fd={:#x} off={:#x}", self.mem.borrow().mm_atual(), self.r[0], self.r[1], self.r[2], self.r[3], self.r[4], self.r[5]);
                }
            }
        }
        // TEMP (linker load-stage watch): same windows, log read()
        // args (fd/count) — a missing header read on fd 14 vs fd 3
        // separates fail-before-read from fail-after-read. Open
        // right end like MMAP2. Cap 400. Remove with MMAP2/OPENRET.
        if self.r[7] == 3 {
            static mut NRD2: u32 = 0;
            unsafe {
                let f = self.instrucoes;
                if NRD2 < 400 && ((562_000_000..563_500_000).contains(&f) || f >= 656_300_000) {
                    NRD2 += 1;
                    let n = NRD2;
                    eprintln!("READ2#{n} f={f} fd={:#x} len={:#x}", self.r[0], self.r[2]);
                }
            }
        }
        // TEMP (guest VMA invalidation): our host regions shadow
        // guest remaps — a munmap/MAP_FIXED/mremap that frees VA
        // must drop our pages there, else the next touch reads
        // stale bytes with no fault (proven live: apk FileMap over
        // a zero-filled 0x40000000). munmap + MAP_FIXED drop
        // eagerly (address known at entry); addr=0 mmaps resolve
        // at return (fresh VA, no stale to drop — the fault path
        // serves them). brk deliberately excluded (heap reuse must
        // keep content). Log cap 40. Remove with CRASHOBJ.
        if self.r[7] == 91 {
            let (base, len) = (self.r[0], self.r[1]);
            if len != 0 && base.checked_add(len).is_some_and(|e| e > base) {
                self.mem.borrow_mut().desmapeia_intervalo(base, len as usize);
                static mut NVI: u32 = 0;
                unsafe {
                    if NVI < 40 {
                        NVI += 1;
                        let n = NVI;
                        eprintln!("VMAINV#{n} f={} mm={:#x} op=munmap base={base:#x} len={len:#x}", self.instrucoes, self.mem.borrow().mm_atual());
                    }
                }
            }
        }
        if self.r[7] == 192 && self.r[0] != 0 && (self.r[3] & 0x10) != 0 {
            let (base, len) = (self.r[0], self.r[1]);
            if len != 0 && base.checked_add(len).is_some_and(|e| e > base) {
                self.mem.borrow_mut().desmapeia_intervalo(base, len as usize);
                static mut NVF: u32 = 0;
                unsafe {
                    if NVF < 40 {
                        NVF += 1;
                        let n = NVF;
                        eprintln!("VMAINV#{n} f={} mm={:#x} op=mapfixed base={base:#x} len={len:#x}", self.instrucoes, self.mem.borrow().mm_atual());
                    }
                }
            }
        }
        if self.r[7] == 163 {
            let (base, len) = (self.r[0], self.r[1]);
            if len != 0 && base.checked_add(len).is_some_and(|e| e > base) {
                self.mem.borrow_mut().desmapeia_intervalo(base, len as usize);
                static mut NVR: u32 = 0;
                unsafe {
                    if NVR < 40 {
                        NVR += 1;
                        let n = NVR;
                        eprintln!("VMAINV#{n} f={} mm={:#x} op=mremap base={base:#x} len={len:#x}", self.instrucoes, self.mem.borrow().mm_atual());
                    }
                }
            }
        }
        // TEMP (madvise DONTNEED invalidation): dlmalloc returns freed
        // spans via madvise(MADV_DONTNEED) — the kernel discards the
        // pages (fresh zeros on next touch). Our host regions would
        // otherwise keep serving the stale pre-discard bytes.
        // Drop like munmap. r7=0xDC=220 ARM EABI (verified against
        // bionic's own wrapper; the earlier r7==219 guess was wrong
        // and silently matched nothing). r0=addr, r1=len, r2=advice
        // (4 = DONTNEED). Other advices only log. Cap 40.
        // Remove with CRASHOBJ.
        if self.r[7] == 0xDC {
            let (base, len, adv) = (self.r[0], self.r[1], self.r[2]);
            if adv == 4 && len != 0 && base.checked_add(len).is_some_and(|e| e > base) {
                self.mem.borrow_mut().desmapeia_intervalo(base, len as usize);
            }
            static mut NVM: u32 = 0;
            unsafe {
                if NVM < 40 {
                    NVM += 1;
                    let n = NVM;
                    eprintln!("VMAINV#{n} f={} mm={:#x} op=madvise adv={adv} base={base:#x} len={len:#x}", self.instrucoes, self.mem.borrow().mm_atual());
                }
            }
        }
        // TEMP (SVC census): log r7 numbers in/near the unmapped
        // range to name unhandled syscalls if madvise never fires
        // above (a wrong number leaves discards invisible and stale
        // pages get re-served as zeros). Cap 60. Remove with
        // CRASHOBJ.
        if (200..260).contains(&self.r[7]) && self.r[7] != 219 {
            static mut NSC: u32 = 0;
            unsafe {
                if NSC < 60 {
                    NSC += 1;
                    let n = NSC;
                    eprintln!("SVCC#{n} f={} r7={:#x} r0={:#x} r1={:#x} r2={:#x} r3={:#x}", self.instrucoes, self.r[7], self.r[0], self.r[1], self.r[2], self.r[3]);
                }
            }
        }
        // TEMP (brk lifecycle watch + shrink invalidation): brk
        // shrink+regrow without a drop resurrects freed heap bytes
        // via the preservation overlay (stale pointers -> wild
        // libsgl head). Drop [new,old) on shrink (new!=0, new<old);
        // grow needs no drop. Cap 40. Remove with CRASHOBJ.
        if self.r[7] == 45 {
            static mut NBK: u32 = 0;
            static mut OLD_BRK: u32 = 0;
            unsafe {
                let novo = self.r[0];
                if OLD_BRK != 0 && novo != 0 && novo < OLD_BRK {
                    let velho = OLD_BRK;
                    self.mem.borrow_mut().desmapeia_intervalo(novo, (velho - novo) as usize);
                    if NBK < 40 {
                        NBK += 1;
                        eprintln!("BRKSHRINK ins={} [{:#x},{:#x})", self.instrucoes, novo, velho);
                    }
                } else if NBK < 20 {
                    NBK += 1;
                    let n = NBK;
                    eprintln!("BRK#{n} ins={} addr={:#x}", self.instrucoes, novo);
                }
                if novo != 0 {
                    OLD_BRK = novo;
                }
            }
        }
        // TEMP (linker failure-cleanup watch): if link_image fails
        // after mapping, old bionic munmaps the reserve and closes
        // the fd. A munmap of the top reserve (0xab300000/0x7000)
        // is the smoking gun for link-vs-init failure and pins the
        // failure instant. Same windows as MMAP2. Caps 40/80.
        // Remove with MMAP2/OPENRET.
        if self.r[7] == 91 {
            static mut NMU2: u32 = 0;
            unsafe {
                let f = self.instrucoes;
                if NMU2 < 40 && ((562_000_000..563_500_000).contains(&f) || f >= 656_300_000) {
                    NMU2 += 1;
                    let n = NMU2;
                    eprintln!("MUNMAP2#{n} f={f} mm={:#x} addr={:#x} len={:#x} lr={:#x}", self.mem.borrow().mm_atual(), self.r[0], self.r[1], self.r[14]);
                }
            }
        }
        if self.r[7] == 6 {
            static mut NCL2: u32 = 0;
            unsafe {
                let f = self.instrucoes;
                if NCL2 < 80 && ((562_000_000..563_500_000).contains(&f) || f >= 656_300_000) {
                    NCL2 += 1;
                    let n = NCL2;
                    let ti = self.r[13] & !0x1FFF;
                    let task = self.mem.borrow().read_u32(ti.wrapping_add(12)).unwrap_or(0xDEAD);
                    eprintln!("CLOSE2#{n} f={f} fd={:#x} mm={:#x} task={task:#x} lr={:#x} pc={:#x}", self.r[0], self.mem.borrow().mm_atual(), self.r[14], self.r[15]);
                }
            }
        }
        // TEMP (open-path watch): log path args for open/creat/
        // mknod/mkdir (r7=5/8/14/39) to see exactly which files
        // init/services touch (linker .so opens, /dev nodes).
        // Cap 1500 (was 200): service startup runs past 1B insns.
        // Remove with EXITCAL once the killer is named.
        if matches!(self.r[7], 5 | 8 | 14 | 39) {
            static mut NOP: u32 = 0;
            unsafe {
                if NOP < 1500 {
                    NOP += 1;
                    let p = self.r[0];
                    let nm = if (0x1000..0xC000_0000).contains(&p) {
                        match self.mem.borrow().read(p, 64) {
                            Ok(s) => {
                                let z = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                                format!("{:?}", String::from_utf8_lossy(&s[..z]))
                            }
                            Err(_) => String::from("<unmapped>"),
                        }
                    } else {
                        format!("{p:#x}")
                    };
                    eprintln!("OPEN f={} r7={:#x} path={nm} flags={:#x}", self.instrucoes, self.r[7], self.r[1]);
                }
            }
        }
        // Execve entry (r7==11): bump the exec generation so
        // post-exec user touches re-resolve from the new page tables
        // instead of reusing stale regions. (Does NOT carve: the new
        // image's argv/envp still live in the old user pages until
        // the loader replaces them — carving here once starved an
        // execve of its own arguments.) Runs before the guest handler.
        if self.r[7] == 11 {
            self.mem.borrow_mut().bump_geracao();
        }
        // SVC-bank SP fallback (same root cause as IRQ/ABT: reset
        // leaves it undefined; the kernel programs it in cpu_init).
        // Private page; the kernel's own setup overwrites this later.
        if self.r[13] == 0 {            const PILHA_SVC: u32 = 0xC832_0000;
            const TAM_PILHA_SVC: usize = 0x1000;
            if self.mem.borrow().read_u32(PILHA_SVC).is_err() {
                let _ = self.mem.borrow_mut().map_zeroed("pilha_svc", PILHA_SVC, TAM_PILHA_SVC);
            }
            self.r[13] = PILHA_SVC.wrapping_add(TAM_PILHA_SVC as u32);
        }
        self.spsr[3] = velho;
        // ARMv6 SVC entry: mode SVC, ARM state, I masked. Switch
        // banks FIRST (like entra_irq/entra_aborto): writing r14
        // before the swap would be clobbered by the bank load.
        // Thumb state read BEFORE the switch (troca_modo clears T).
        let thumb = velho & T != 0;
        self.troca_modo((velho & !(0x1F | T)) | 0x13 | 0x80);
        // lr = next instruction (r15 sat AT the svc): the guest's
        // `movs pc, lr` resumes after it.
        self.r[14] = self.r[15].wrapping_add(if thumb { 2 } else { 4 });
        // CP15 c1 (key 0x80) bit 13: high vectors.
        let sctlr = self.cp15.iter().find(|(k, _)| *k == 0x80).map_or(0, |(_, v)| *v);
        let vet = if sctlr & (1 << 13) != 0 { 0xFFFF_0000 } else { 0x0 };
        self.r[15] = vet | 0x08;
    }

    /// Take an IRQ before the instruction at `r[15]` executes.
    /// Counts every delivery in ULTIMA_ENTREGA (read by TIMERSTATE's
    /// per-slice log): the per-delivery ENTRA log is gated and capped,
    /// but the counter shows the true tick rate through the fault.
    fn entra_irq(&mut self) {        let velho = self.cpsr;
        unsafe {
            ULTIMA_ENTREGA = ULTIMA_ENTREGA.wrapping_add(1);
        }
        // TEMP (entry audit): log pre-entry CPSR + faulting pc,
        // gated to the preempt-BUG window (ins >= 167M, fault at
        // ~168.5M). Are there any backend deliveries at all near
        // the fault, or is the dispatch path entered without one?
        static mut NENT: u32 = 0;
        unsafe {
            if self.instrucoes >= 167_000_000 && NENT < 20 {
                NENT += 1;
                let n = NENT;
                eprintln!("ENTRA#{n} ins={} velho={velho:#x} pc={pc:#x}", self.instrucoes, pc = self.r[15]);
            }
        }
        let retorno = self.r[15].wrapping_add(4);
        // ARMv6 IRQ entry: mode IRQ, ARM state, I and A masked.
        self.troca_modo((velho & !(0x1F | T)) | 0x12 | 0x80 | 0x100);
        // TEMP: verify the entry mask actually lands. The preempt BUG
        // sees I=0 with no clearer in between — confirm entra_irq
        // itself still sets I=1 on every delivery.
        unsafe {
            static mut NENT2: u32 = 0;
            if NENT2 < 20 && (self.cpsr & 0x80) == 0 {
                NENT2 += 1;
                let n = NENT2;
                eprintln!("ENTRA-NOI#{n} ins={} cpsr={:#x}", self.instrucoes, self.cpsr);
            }
        }
        // IRQ-bank SP fallback: hardware reset leaves it undefined and the
        // kernel programs it in cpu_init — but the first tick can arrive
        // with it still zero (live-proven: vector prologue `stm sp,{r0,lr}`
        // faults addr=0 pc=0xFFFF0204). Park it on a private page instead
        // of faulting; the kernel's own setup overwrites this later.
        if self.r[13] == 0 {
            const PILHA_IRQ: u32 = 0xC830_0000;
            const TAM_PILHA_IRQ: usize = 0x1000;
            if self.mem.borrow().read_u32(PILHA_IRQ).is_err() {
                let _ = self.mem.borrow_mut().map_zeroed("pilha_irq", PILHA_IRQ, TAM_PILHA_IRQ);
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
        // TEMP (trap audit): libdvm-address traps never fire while
        // 0x11020 traps do — verify arming actually lands. Remove
        // with CRASHOBJ.
        eprintln!("ARMA trap={addr:#x}");
        if let Some(slot) = self.armadilhas_mem.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = Box::new(gancho);
        } else {
            // Sorted insertion (firing uses binary search).
            let pos = self.armadilhas_mem.partition_point(|(a, _)| *a < addr);
            self.armadilhas_mem.insert(pos, (addr, Box::new(gancho)));
        }
    }

    /// Serving-trap count (perf audit: the run loop binary-searches
    /// this table on every instruction).
    pub fn num_armadilhas(&self) -> usize {
        self.armadilhas_mem.len()
    }

    /// Mark timer/IRQ state dirty: recheck the line at the next
    /// UNMASKED loop top. Called by the harness per-slice plant when
    /// COUNT catches up (STATUS 0->1); es_mem sets the flag directly
    /// for MMIO writes.
    pub fn marca_timer_sujo(&mut self) {
        self.timer_sujo = true;
    }

    /// CP15 store as a whole (dual-backend sync: the wrapper copies the
    /// active backend's table to the idle one on every switch).
    pub fn cp15_vec(&self) -> Vec<(u32, u32)> {
        self.cp15.clone()
    }

    /// Replace the CP15 store wholesale (dual-backend sync counterpart).
    pub fn carrega_cp15(&mut self, v: Vec<(u32, u32)>) {
        self.cp15 = v;
    }

    /// Clear a stale LDREX reservation (dual-backend switch: a reservation
    /// never survives a backend change — the STREX retry path handles it).
    pub fn limpa_exclusivo(&mut self) {
        self.exclusivo = None;
    }

    /// Read a cached CP15 register by key (same key layout as the
    /// MCR/MRC path: op1/CRn/CRm/op2). The harness uses it to read
    /// TTBR0 (key 0x100: c2,c0,0) for the guest page-table walk on
    /// user faults. None = the guest never wrote it.
    pub fn le_cp15(&self, chave: u32) -> Option<u32> {
        self.cp15.iter().find(|(k, _)| *k == chave).map(|(_, v)| *v)
    }

    /// Remove the memory-serving PC trap at `addr`, if any. Other armed
    /// addresses keep working.
    pub fn untrap_pc_mem(&mut self, addr: u32) {
        self.armadilhas_mem.retain(|(a, _)| *a != addr);
    }

    fn thumb(&self) -> bool {
        self.cpsr & T != 0
    }

    /// TEMP (linker Thumb-state): force Thumb mode to retry a pc that
    /// is proven Thumb code but faulted as ARM UND (0xB0000854 =
    /// `str r7,[r6,#0x7c]`, caller Thumb via BL). The mode flip is
    /// lost on some ARM->Thumb return path; re-executing in Thumb
    /// unblocks boot. Narrow to the proven pc; remove once the
    /// underlying bx/svc-return bug is found. Remove with CRASHOBJ.
    pub fn forca_thumb(&mut self) {
        self.cpsr |= T;
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
        let mem = self.mem.borrow();
        let bytes = mem
                        .read(addr, len)
            .map_err(|_| StopReason::MemoryFault { addr, pc: addr })?;
        // `GuestMemory::executavel` requires four bytes. A Thumb at the end of the region fits in
        // two and would be refused; the right question is whether the region the read found allows
        // execution (via `busca_permitida`: binary + MRU, no scan).
        if !self.mem.borrow().busca_permitida(addr, len) {
            return Err(StopReason::MemoryFault { addr, pc: addr });
        }
        Ok(match len {
            2 => u32::from(u16::from_le_bytes([bytes[0], bytes[1]])),
            _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    fn le_mem(&self, addr: u32, len: u32, pc: u32) -> Result<u32, StopReason> {
        let mem = self.mem.borrow();
        let bytes = mem
                        .read(addr, len)
            .map_err(|_| StopReason::MemoryFault { addr, pc })?;
        Ok(match len {
            1 => u32::from(bytes[0]),
            2 => u32::from(u16::from_le_bytes([bytes[0], bytes[1]])),
            _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    fn es_mem(&mut self, addr: u32, dados: &[u8], pc: u32) -> Result<(), StopReason> {
        // Canary watches (BSSWR/BSSRD/STKWR/VALWR) retired with the
        // Thumb-push rollback fix: the guard lifecycle is named
        // (seeder 0x1277C, copy 0xA5FA, check 0xA6F4) and the check
        // passes genuinely. This hot path stays clean.
        // TEMP (write watchpoint, harness-armed): log every store
        // overlapping `vigia` with PC + first 4 bytes. Names the
        // writer of the string-headed slot (zygote crash). Cap 2000
        // (raised for the Dalvik-stack poison hunt; normally 30).
        // Remove with CRASHOBJ.
        if let Some((base, len)) = self.mem.borrow().vigia {
            let fim_w = base.wrapping_add(len);
            let fim_s = addr.wrapping_add(dados.len() as u32);
            if (addr as u64) < fim_w as u64 && (base as u64) < fim_s as u64 {
                static mut NW: u32 = 0;
                unsafe {
                    // TEMP (poison-origin hunt): when ANY watched write
                    // carries 0xe4280000 (the mterp IGET wild object),
                    // dump mterp regs + fp words. Own cap (outside the
                    // WATCH# budget, which exhausts on whole-page
                    // watches). Remove with CRASHOBJ.
                    static mut NPW: u32 = 0;
                    if dados.len() == 4
                        && (dados == [0x00, 0x00, 0x28, 0xe4]
                            || dados == [0xa0, 0x8b, 0xaa, 0x41])
                        && NPW < 20 {
                        NPW += 1;
                        let mb = self.mem.borrow();
                        let mut wfp = [0u8; 32];
                        let okfp = mb.read(self.r[5], 32).map(|s| wfp.copy_from_slice(s)).is_ok();
                        let mut wobj = [0u8; 32];
                        let oko = mb.read(self.r[3], 32).map(|s| wobj.copy_from_slice(s)).is_ok();
                        // Dex bytecode around rPC (r4 points past the
                        // current 2-unit insn: the IGET should be at
                        // r4-4). If it doesn't decode as the expected
                        // IGET (vA=dest idx, offset=r1), rPC is stale.
                        let mut wdex = [0u8; 16];
                        let okd = mb.read(self.r[4].wrapping_sub(8), 16).map(|s| wdex.copy_from_slice(s)).is_ok();
                        eprintln!("POISONWR#{} ins={} f={} pc={pc:#x} addr={addr:#x} r0={:08x} r1={:08x} r2={:08x} r3={:08x} r4={:08x} r5={:08x} r6={:08x} r8={:08x} lr={:08x} fpok={okfp} fpw={wfp:02x?} objok={oko} obj={wobj:02x?} dexok={okd} dex={wdex:02x?}", unsafe { NPW }, self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, self.r[0], self.r[1], self.r[2], self.r[3], self.r[4], self.r[5], self.r[6], self.r[8], self.r[14]);
                    }
                    if NW < 2000 {
                        NW += 1;
                        let n = NW;
                        let mut hb = [0u8; 4];
                        let m = dados.len().min(4);
                        hb[..m].copy_from_slice(&dados[..m]);
                        eprintln!("WATCH#{n} ins={} f={} pc={pc:#x} addr={addr:#x} len={:#x} data={hb:02x?}", self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, dados.len());
                    }
                }
            }
        }
        // TEMP (VIC write watch [0xE0000000,0xE0000040)): the VIC
        // enable/clear registers live here; log addr + value to
        // learn which word gates IRQ16 (mddi) — vic_nivel currently
        // reads +0x30, which may be the wrong word for line 16.
        // Cap 30. Remove once IRQ16 delivers.
        if dados.len() == 4 && (0xE000_0000..0xE000_0040).contains(&addr) {
            static mut NVC: u32 = 0;
            unsafe {
                if NVC < 30 {
                    NVC += 1;
                    let n = NVC;
                    let val = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
                    eprintln!("VICWR#{n} ins={} pc={pc:#x} addr={addr:#x} val={val:#x}", self.instrucoes);
                }
            }
        }
        // host reset writes ~15 control regs then polls INT/STAT;
        // log addr + value to confirm the VA and the offsets the
        // driver actually uses (vmlinux says CMD+0, INT+0x18,
        // STAT+0x28, VERSION+0x8C). Doubles as the IRQ16 edge:
        // CMD writes raise the pending flag (doorbell rung), INT
        // writes (+0x18, the handler's ack) lower it — vic_nivel
        // raises line 16 while outstanding so the real IRQ handler
        // runs and completes the waiters. Cap 30. Remove once the
        // client handshake is emulated for real.
        if dados.len() == 4 && (0xE000_B000..0xE000_C000).contains(&addr) {
            static mut NMD: u32 = 0;
            unsafe {
                if addr == 0xE000_B000 {
                    MDDI_IRQ_PENDENTE = true;
                } else if addr == 0xE000_B018 {
                    MDDI_IRQ_PENDENTE = false;
                }
                if NMD < 30 {
                    NMD += 1;
                    let n = NMD;
                    let val = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
                    eprintln!("MDDIWR#{n} ins={} pc={pc:#x} addr={addr:#x} val={val:#x}", self.instrucoes);
                }
            }
        }
        // holds file bytes to 0xA1FC then zeros (file has code to
        // 0xB000), NOP-sledding the fault pass into 0xB008 with a
        // garbage r3. A guest store zeroed it (user text maps
        // writable; hardware would SEGV where we absorb) — any
        // 4-byte store in range logs pc + addr + value. Cap 20.
        // Zero hits + still-zeroed page = host-side writer instead
        // (seed/serve/fault-in/mirror), different hunt. Remove once
        // the storer is named.
        if dados.len() == 4 && (0xA000..0xB000).contains(&addr) {
            static mut NTW: u32 = 0;
            unsafe {
                if NTW < 20 {
                    NTW += 1;
                    let n = NTW;
                    let val = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
                    eprintln!("TEXTWR#{n} ins={} mm={:#x} pc={pc:#x} addr={addr:#x} val={val:#x} r0={:#x} r1={:#x} lr={:#x}", self.instrucoes, self.mem.borrow().mm_atual(), self.r[0], self.r[1], self.r[14]);
                }
            }
        }
        // TEMP (kuser fill watch [0xFFFF0F00,0xFFFF1000)): init reads
        // [0xFFFF0FF0] (pool 0xFFFF0FF0 in the 0x1259c getter) and gets
        // 0, so *ptr=0 and r0=8 faults. The kernel should have copied
        // helpers to 0xFFFF0F00+. Any 4-byte store in range logs
        // pc + value — if silent, the copy never happens through our
        // map (alias/stale-PA variant of the page-table issue). Cap 16.
        if dados.len() == 4 && (0xFFFF_0F00..0xFFFF_1000).contains(&addr) {
            static mut NKW: u32 = 0;
            unsafe {
                if NKW < 16 {
                    NKW += 1;
                    let n = NKW;
                    let val = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
                    eprintln!("KUSERW#{n} ins={} pc={pc:#x} addr={addr:#x} val={val:#x}", self.instrucoes);
                }
            }
        }
        // TEMP (GOT-slot watch 0x1A83C): who zeroes the GOT entry the
        // 0x1A834 ldr reads (file has 0x15119, guest reads 0)? Any
        // 4-byte store to [0x1A838..0x1A844) logs pc + value. Cap 8.
        // Remove once the zeroing writer is named.
        if dados.len() == 4 && (0x1A838..0x1A844).contains(&addr) {
            static mut NGW: u32 = 0;
            unsafe {
                if NGW < 8 {
                    NGW += 1;
                    let n = NGW;
                    let val = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
                    eprintln!("GOTWR#{n} ins={} pc={pc:#x} addr={addr:#x} val={val:#x}", self.instrucoes);
                }
            }
        }
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
                // Read first, guard dropped at statement end: the body
                // below takes `borrow_mut`, which would panic against a
                // guard held open by an `if let` scrutinee.
                let atual = self.mem.borrow().read_u32(reg_set);
                if let Ok(atual) = atual {
                    let novo = if e_set { atual | v } else { atual & !v };
                    let _ = self.mem.borrow_mut().write_u32(reg_set, novo);
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
            // Any timer/EN write may birth an edge: mark dirty so the
            // next UNMASKED loop top rechecks (persists across masked
            // stretches, unlike the one-shot unmask flag).
            self.timer_sujo = true;
            let v = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
            // Shadow EN (0x30/0x34 bank) with THIS write applied.
            let r = |m: &GuestMemory, a: u32| m.read_u32(a).unwrap_or(0);
            let mut en = r(&*self.mem.borrow(), 0xE000_0030);
            match addr {
                0xE000_0030 => en |= v,
                0xE000_0020 => en &= !v,
                _ => {}
            }
            let conta = if addr == 0xE000_1004 { v } else { r(&*self.mem.borrow(), 0xE000_1004) };
            let alvo = if addr == 0xE000_1000 { v } else { r(&*self.mem.borrow(), 0xE000_1000) };
            let conta_d = if addr == 0xE000_1014 { v } else { r(&*self.mem.borrow(), 0xE000_1014) };
            let alvo_d = if addr == 0xE000_1010 { v } else { r(&*self.mem.borrow(), 0xE000_1010) };
            let gate = r(&*self.mem.borrow(), 0xC02A_43EC) != 0;
            let st = r(&*self.mem.borrow(), 0xE000_0080);
            // Unprogrammed MATCH reads all-ones: never pending.
            let p7 = conta >= alvo && alvo != u32::MAX && en & 0x80 != 0 && gate;
            let p8 = conta_d >= alvo_d && alvo_d != u32::MAX && en & 0x100 != 0 && gate;
            let vic = (if p7 { 0x80 } else { 0 }) | (if p8 { 0x100 } else { 0 });
            let _ = self.mem.borrow_mut().write_u32(0xE000_0000, vic);
            let vect = if p7 {
                7
            } else if p8 {
                8
            } else {
                0xFFFF_FFFF
            };
            let _ = self.mem.borrow_mut().write_u32(0xE000_00D0, vect);
            let _ = self.mem.borrow_mut().write_u32(0xE000_00D4, vect);
            let _ = self.mem.borrow_mut().write_u32(0xE000_0080, st & !0x180 | vic & 0x180);
        }
        // TEMP (MATCH writers, gated ins > 166M ≈ f 83k, cap 30):
        // the 1.65s wall has STATUS stuck while wake advances —
        // is the GPT MATCH fought over by the tick (10ms) and the
        // idle alarm (~88 ticks)? Logs every writer pc + value.
        if dados.len() == 4 && addr == 0xE000_1000 {
            static mut NMW: u32 = 0;
            unsafe {
                if self.instrucoes > 166_000_000 && NMW < 30 {
                    NMW += 1;
                    let n = NMW;
                    let v = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
                    eprintln!("MATCHW#{n} ins={} pc={pc:#x} val={v:#x}", self.instrucoes);
                }
            }
        }
        // TEMP (direct MATCH writes, ins > 180M ≈ f 90k, cap 20):
        // MATCH advances in lockstep with COUNT but neither
        // set_next_event wrapper fires — someone writes 0xE0001000
        // directly. Name the pc + value.
        if dados.len() == 4 && addr == 0xE000_1000 {
            static mut NMW2: u32 = 0;
            unsafe {
                if self.instrucoes > 180_000_000 && NMW2 < 20 {
                    NMW2 += 1;
                    let n = NMW2;
                    let v = u32::from_le_bytes([dados[0], dados[1], dados[2], dados[3]]);
                    eprintln!("MATCHW2#{n} ins={} pc={pc:#x} val={v:#x}", self.instrucoes);
                }
            }
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
                    let okf = self.mem.borrow()
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
        self.mem.borrow_mut()
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
            0b111 if instr & (1 << 24) != 0 => self.svc(instr, pc, false),
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
            // imod bit 0 selects: 0 = enable (CLEAR the mask bits),
            // 1 = disable (SET them). cpsie i is 0xF1080080 (imod=2),
            // cpsid i is 0xF10C0080 (imod=3) — verified by assembling
            // both mnemonics with arm-none-eabi-as (the toolchain that
            // built this kernel), not by reading the manual's table.
            // (An earlier \"fix\" had this backwards, matching a swapped
            // objdump print table; it made every guest disable enable
            // and vice versa, which is exactly what tripped the
            // sched.c:4032 BUG_ON: __do_softirq's post-loop cpsid
            // left I clear instead of set.)
            if imod & 1 != 0 {
                // TEMP (I-set hunt): log every cps that SETS I (guest
                // disable). Completes the I-bit timeline: with both
                // directions logged, any drift to I=0 must come from
                // an unlogged path (there is none left).
                if mascara & 0x80 != 0 && self.cpsr & 0x80 == 0 {
                    static mut NCPSD: u32 = 0;
                    unsafe {
                        if self.instrucoes >= 245_000_000 && NCPSD < 100 {
                            NCPSD += 1;
                            let n = NCPSD;
                            eprintln!("CPSID#{n} ins={} pc={pc:#x} mode={mode:#x}", self.instrucoes, pc = pc, mode = self.cpsr & 0x1F);
                        }
                    }
                    unsafe { TOTAL_MASCARA = TOTAL_MASCARA.wrapping_add(1); }
                }
                self.cpsr |= mascara;
            } else {
                // Genuine I 1->0 only (FIQ-only cps must not count).
                let limpava = mascara & 0x80 != 0 && self.cpsr & 0x80 != 0;
                // TEMP (I-clear hunt): log every cps that clears I
                // (guest enable). Cap 100, gated past the wall.
                if limpava {
                    static mut NCPSE: u32 = 0;
                    unsafe {
                        if self.instrucoes >= 245_000_000 && NCPSE < 100 {
                            NCPSE += 1;
                            let n = NCPSE;
                            eprintln!("CPSIE#{n} ins={} pc={pc:#x} mode={mode:#x}", self.instrucoes, pc = pc, mode = self.cpsr & 0x1F);
                        }
                    }
                }
                self.cpsr &= !mascara;
                // Unmask edge: recheck the line at the next loop top
                // (unmissable delivery; the 64-poll strides over brief
                // idle unmasks).
                if limpava {
                    self.irq_pendente = true;
                    unsafe { TOTAL_DESMASCA = TOTAL_DESMASCA.wrapping_add(1); }
                }
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

    fn svc(&mut self, instr: u32, pc: u32, thumb: bool) -> Result<bool, StopReason> {
        // Routing by SVC immediate. Semihosting numbers (SPL + unit
        // test + standard): ARM #0x123456, #0xAB (also used by the
        // test as an ARM imm), SPL's observed #0xCDAB89, Thumb #0xAB.
        // Anything else from USR mode is a Linux syscall (EABI svc #0,
        // OABI swi #0x90xxxx) → deliver to the guest kernel's
        // vector_swi (entra_svc). The old path silently returned 0,
        // which dropped set_tls (TLS value never reached 0xFFFF0FF0,
        // so init's first TLS access read 0 and segfaulted on a
        // null+8 store). Privileged modes keep the legacy
        // semihosting stub below (SPL boot, kernel — neither issues
        // Linux syscalls).
        let imm = if thumb { instr & 0xFF } else { instr & 0xFF_FFFF };
        let semihosting = matches!(imm, 0x123456 | 0xAB | 0xCDAB89);
        if !semihosting && self.cpsr & 0x1F == MODO_USUARIO {
            // USR entry never clobbers spsr[3] (SVC bank), so a
            // single-level delivery is safe. (Nested SVC from SVC
            // mode can't happen here — this arm only fires in USR.)
            let alto = self.cp15.iter().find(|(k, _)| *k == 0x80).map_or(0, |(_, v)| *v) & (1 << 13) != 0;
            let vet = if alto { 0xFFFF_0008 } else { 0x08 };
            let w = self.mem.borrow().read_u32(vet).unwrap_or(0);
            let forma = (w & 0xFFFF_F000 == 0xE59F_F000)
                || (w & 0xFF00_0000 == 0xEA00_0000);
            if !forma {
                eprintln!("SVC-NOVET pc={pc:#x} vet={vet:#x} w={w:#x}");
                return Err(StopReason::Exception { pc });
            }
            self.entra_svc();
            return Ok(true);
        }
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
        // Rd = bits[19:16], Rn (accumulator) = bits[15:12] — same
        // layout as arm_mul (MUL Rd,Rm,Rs). PROVEN live: smulbb
        // lr,r2,r3 = 0xE16E0382 has Rd=0xE in bits[19:16]; the old
        // code read Rd from bits[15:12] (=0x0) and wrote r0 instead
        // of lr, leaving a stale bl return in lr -> wild libsgl head.
        let rd = (instr >> 16) & 0xF;
        let rn = self.le_reg((instr >> 12) & 0xF, pc, 0);
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
                if self.instrucoes >= 245_000_000 && NMSRE < 200 {
                    NMSRE += 1;
                    let n = NMSRE;
                    eprintln!("MSRIE#{n} ins={} pc={pc:#x} mode={mode:#x}", self.instrucoes, pc = pc, mode = self.cpsr & 0x1F);
                }
            }
        }
        let era_mascarado = !para_spsr && self.cpsr & 0x80 != 0;
        self.troca_modo(novo);
        // Unmask edge: genuine 1->0 on CPSR writes only.
        if era_mascarado && self.cpsr & 0x80 == 0 {
            self.irq_pendente = true;
            unsafe { TOTAL_DESMASCA = TOTAL_DESMASCA.wrapping_add(1); }
        }
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
        // LDC/STC to p15 (cache preload / maintenance hints — the
        // `pld`-class ops in flush_pfn_alias, hit on the /init exec
        // path via flush_dcache_page). The flat model has no caches:
        // GuestMemory is directly coherent, so these are
        // architecturally NOPs. Transfers for any other coprocessor
        // (e.g. VFP data via p10/p11) still fault — silently
        // accepting those would corrupt real state.
        if (instr >> 25) & 7 == 0b110 && (instr >> 8) & 0xF == 0xF {
            return Ok(false);
        }
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
                unsafe { TOTAL_WFI = TOTAL_WFI.wrapping_add(1); }
                return Ok(false);
            }
            let valor = self.le_reg(rd, pc, 0);
            match self.cp15.iter_mut().find(|(k, _)| *k == chave) {
                Some(slot) => slot.1 = valor,
                None => self.cp15.push((chave, valor)),
            }
            // TTBR0 (key 0x100: c2,c0,0) switches the address space:
            // track it so user lookups only see shared regions plus
            // the current mm's own (fork/exec children stop aliasing
            // the parent's pages).
            if chave == 0x100 {
                // TEMP (mm audit): confirm TTBR writes actually flow
                // and see the pgd values (cap 400 — switches continue
                // late (init restarts, zygote forks); cap 8 blinded
                // the 584233+ deaths.
                static mut NM: u32 = 0;
                unsafe {
                    if NM < 400 {
                        NM += 1;
                        let n = NM;
                        eprintln!("MM#{n} ins={} ttbr={valor:#x}", self.instrucoes);
                    }
                }
                // TEMP (ttbr-verify): cross-check the written TTBR
                // against task->mm->pgd (guest truth: task+0x1B0=mm,
                // mm+0x24=pgd kva, TTBR=pgd-0xB0000000). A mismatch
                // names WHO lies (guest wrote stale vs OUR hook
                // misread) — the fork child (MM#17=16238000) is the
                // suspect. Cap 40, user TTBRs only. Remove with CRASHOBJ.
                unsafe {
                    static mut NTV: u32 = 0;
                    if NTV < 40 {
                        let ti = self.r[13] & !0x1FFF;
                        if let Ok(task) = self.mem.borrow().read_u32(ti.wrapping_add(12)) {
                            if (0xC600_0000..0xC700_0000).contains(&task) {
                                if let Ok(mm) = self.mem.borrow().read_u32(task.wrapping_add(0x1B0)) {
                                    if (0xC600_0000..0xD000_0000).contains(&mm) {
                                        if let Ok(pgd) = self.mem.borrow().read_u32(mm.wrapping_add(0x24)) {
                                            let espera = pgd.wrapping_sub(0xB000_0000);
                                            let tem = valor & 0xFFFF_C000;
                                            if espera != tem && (0x1600_0000..0x1700_0000).contains(&espera) && (0x1600_0000..0x1700_0000).contains(&tem) {
                                                NTV += 1;
                                                let n = NTV;
                                                eprintln!("TTBRVRF#{n} ins={} tem={tem:#x} espera={espera:#x} task={task:#x} mm={mm:#x} pgd={pgd:#x} pc={:#x} r0={:#x} r1={:#x} r2={:#x} r3={:#x} r4={:#x}", self.instrucoes, self.r[15], self.r[0], self.r[1], self.r[2], self.r[3], self.r[4]);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                self.mem.borrow_mut().trocar_mm(valor & 0xFFFF_C000);
                // TEMP (death-anchored epochs): a TTBR write to a
                // recorded-dead value means buddy-recycle (fresh page
                // tables under a stale TTBR value → stale regions
                // fetchable with no fault). Consume one record with a
                // text-epoch bump (text re-serves correctly; heap/data
                // stay). Cap logs 20. Remove with CRASHOBJ.
                unsafe {
                    static mut NEP: u32 = 0;
                    let vv = valor & 0xFFFF_C000;
                    if self.mem.borrow_mut().consome_mm_morto(vv) {
                        let cort = self.mem.borrow_mut().nova_epoca_mm(vv);
                        if NEP < 20 {
                            NEP += 1;
                            let n = NEP;
                            eprintln!("EPOCH#{n} ins={} mm={vv:#x} cortadas={cort} pc={:#x}", self.instrucoes, self.r[15]);
                        }
                    }
                }
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
            // Rollback on fault: sp is committed BEFORE the stores,
            // so a mid-push fault (demand-paged stack growth) must
            // restore it — otherwise the resume re-executes the push
            // and decrements twice (proven live: init's canary slot
            // drifted -24 = one 6-reg push double-applied, so the
            // epilogue compared the wrong slot and popped the guard
            // value into pc). Loads (pop/ldm) already commit last.
            let anterior = self.r[13];
            let mut addr = anterior.wrapping_sub(n * 4);
            self.r[13] = addr;
            for reg in 0..16 {
                if lista & (1 << reg) != 0 {
                    let valor = self.le_reg(reg, pc, 0);
                    if let Err(falha) = self.es_mem(addr, &valor.to_le_bytes(), pc) {
                        self.r[13] = anterior;
                        return Err(falha);
                    }
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
            return self.svc(u32::from(instr), pc, true);
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
                // Old-Thumb BL first half: LR = (fault pc + 4) +
                // (sign-extended imm10 << 12), NO alignment masking —
                // the fault pc+4 may have bit 1 set (e.g. pair at
                // 0x8ECE: base 0x8ED2, not 0x8ED0). The old `& !2`
                // sent such calls 2 bytes early, into padding that
                // decoded as a BL second half with a stale odd LR
                // (proven live: 0x8ED3+0xFFE=0x9ED1 odd-pc fault).
                let base = pc.wrapping_add(4);
                self.r[14] = base.wrapping_add(sext(imm, 11) << 12);
                Ok(false)
            }
            0b11111 => {
                let proxima = pc.wrapping_add(2);
                // Unmasked (like the first half): a stale-LR pairing
                // yields an odd target, which the fetch guard
                // (pc & 1) rejects loudly as an Exception.
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
        *self.mem.borrow_mut() = copia;
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
        self.irq_pendente = false;
        self.timer_sujo = false;
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
            // Delivery gate: unmasked AND in a deliverable mode
            // (USR/SVC/SYS). Delivering into IRQ/FIQ/ABT/UND nests
            // entra_irq and clobbers the single spsr_irq — the
            // posix-cpu-timers BUG_ON(!irqs_disabled()) wall. Computed
            // once per loop top; every path below takes it.
            let modo = self.cpsr & 0x1F;
            let pode_irq = self.cpsr & 0x80 == 0
                && (modo == 0x10 || modo == 0x13 || modo == 0x1F);
            // IRQ delivery. The line is polled every 64 instructions
            // (device state only changes at slice boundaries or through
            // guest writes, so this bounds latency, not correctness).
            if self.esperando {
                if self.linha_irq(pode_irq) {
                    self.esperando = false;
                    // Wake on a pending edge: deliver NOW if unmasked,
                    // before the guest reprograms MATCH and hides it
                    // (the 1.65s wall: every unmask-check sees a fresh
                    // future MATCH, so the edge never survives to a
                    // check). r15 already advanced past WFI: back up
                    // 4 so lr resumes after WFI, not 8 past it.
                    // TEMP (wake audit): log pc+I at every wake (cap
                    // 10) — masked wakes explain the frozen nent.
                    static mut NWAKE: u32 = 0;
                    unsafe {
                        if NWAKE < 10 {
                            NWAKE += 1;
                            let n = NWAKE;
                            eprintln!("WAKE#{n} ins={} pc={:#x} I={} mode={:#x}", self.instrucoes, self.r[15], (self.cpsr >> 7) & 1, self.cpsr & 0x1F);
                        }
                    }
                    if pode_irq {
                        self.r[15] = self.r[15].wrapping_sub(4);
                        self.entra_irq();
                    }
                } else {
                    // Idle: burn the rest of the slice; host time moves on.
                    self.instrucoes = limite;
                    return Ok(StopReason::Budget);
                }
            }
            // Unmask edge: an unmask happened since the last check
            // (cpsie / exception return / msr clearing I). Serve a
            // pending line NOW, unmissable — the 64-poll below strides
            // over the idle loop's brief unmasked windows forever.
            // (Backstop poll stays.) Deferred while !pode_irq (see gate
            // above); the flag is NOT consumed so nothing is lost.
            if self.irq_pendente {
                if pode_irq {
                    self.irq_pendente = false;
                    // TEMP (check audit, f >= 100000, cap 10): log I-bit +
                    // gate verdict at every unmask-check. Distinguishes
                    // latch-shut (I=0, false) from re-masked-before-check
                    // (I=1, which should be impossible).
                    static mut NCHK: u32 = 0;
                    unsafe {
                        if self.instrucoes > 200_000_000 && NCHK < 10 {
                            NCHK += 1;
                            let n = NCHK;
                            let res = self.linha_irq(true);
                            eprintln!("CHK#{n} ins={} I={} res={res}", self.instrucoes, (self.cpsr >> 7) & 1);
                            if res && self.cpsr & 0x80 == 0 {
                                self.entra_irq();
                            }
                        } else if self.cpsr & 0x80 == 0 && self.linha_irq(true) {
                            self.entra_irq();
                        }
                    }
                } else {
                    // Deferred (masked or IRQ/FIQ/ABT/UND mode): poll
                    // without consuming so level tracking stays fresh.
                    let _ = self.linha_irq(false);
                }
            }
            // Dirty timer state: a birth (MMIO write or per-slice
            // catch-up) happened since the last deliverable check.
            // Persists across masked stretches (unlike the flag above,
            // which the first low check consumes), so an edge born
            // while masked is served at the next unmask instead of
            // being sampled away. Consumed only by a deliverable check.
            if self.timer_sujo {
                if pode_irq {
                    self.timer_sujo = false;
                    if self.linha_irq(true) {
                        self.entra_irq();
                    }
                } else {
                    let _ = self.linha_irq(false);
                }
            }
            // TEMP (tick timeline): logs masked<->free transitions
            // + heartbeat every 50000 samples. No low total cap: the
            // masked post-tick spin must show until the end of the run.
            // Samples the I-bit directly (NOT linha_irq: the delivery
            // gate consumes its edge, and a logging poll must never
            // steal a delivery).
            // Log shape is one line per transition (no stack dump):
            // the 8-word dump used to be 90% of every logfile.
            if self.instrucoes & 1023 == 0 {
                static mut NLIN: u32 = 0;
                static mut ULTLIN: u32 = 2;
                unsafe {
                    let estado = if self.cpsr & 0x80 != 0 { 0 } else { 1 };
                    NLIN += 1;
                    if estado != ULTLIN || NLIN % 500000 == 0 {
                        ULTLIN = estado;
                        let n = NLIN;
                        eprintln!(
                            "IRQLINHA n={n} pc={:#x} sp={:#x} {}",
                            self.r[15],
                            self.r[13],
                            if estado == 0 { "MASK" } else { "FREE" },
                        );
                    }
                    }
                }
            if self.cpsr & 0x80 == 0 {
                self.sondagem_irq = self.sondagem_irq.wrapping_add(1);
                if self.sondagem_irq & 63 == 0 {
                    if pode_irq {
                        if self.linha_irq(true) {
                            self.entra_irq();
                        }
                    } else {
                        // Deferred (IRQ/FIQ/ABT/UND mode): poll without
                        // consuming so level tracking stays fresh.
                        let _ = self.linha_irq(false);
                    }
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
                    gancho(&mut *self.mem.borrow_mut(), &mut self.r);
                    let pos = self.armadilhas_mem.partition_point(|(a, _)| *a < alvo);
                    self.armadilhas_mem.insert(pos, (alvo, gancho));
                }
            }
            self.historico[self.hist_pos] = self.r[15];
            // TEMP (F36 arrival edge): the parent reaches abort-tail
            // F36 with no body passage and no SVC — dump regs + last
            // 65 pcs (oldest first) to name the edge: kernel resume?
            // fallthrough? wild branch? Cap 2. Remove with CRASHOBJ.
            if self.r[15] == 0xAFE0_EF36 {
                static mut NH36: u32 = 0;
                unsafe {
                    if NH36 < 2 {
                        NH36 += 1;
                        let h = self.historico();
                        let ini = h.len().saturating_sub(500);
                        eprintln!("EDGE36 f={} ins={} n={} r0={:#x} r1={:#x} r4={:#x} r7={:#x} r14={:#x} sp={:#x} mm={:#x} hist={:08x?}", unsafe { crate::msm7201a::FATIA_ATUAL }, self.instrucoes, h.len(), self.r[0], self.r[1], self.r[4], self.r[7], self.r[14], self.r[13], self.mem.borrow().mm_atual(), &h[ini..]);
                    }
                }
            }
            // TEMP (system_server crash forensics): pc 0x11020 was heap
            // trash via a bad prctl GOT (fixed); pc 0xad0519e4 faults
            // on 0x388f3095 during Audio init; pc 0xad038700/0xad038796
            // walker entry/loop; pc 0xad0126d4 mterp invoke store;
            // pc 0xad03add8 dvmThrowException, 0xad03adb9 WithClassMessage, 0xad02ab6c mterp throw
            // dvmThreadSelf return. trap_pc_mem never fires for
            // libdvm addresses, so dump here instead. TRIMMED for
            // host speed (no historico; short line for the hot
            // invoke pc). Remove with CRASHOBJ.
            // TEMP (missing-classname forensics III): chase EVERY heap
            // pointer in the frame as a potential String (obj+16 =
            // array ptr, array+12 = UTF-16 chars). Whichever spells
            // the message names the true msg register (exposes any
            // fp/v-reg shift). Cap 2. Remove with CRASHOBJ.
            // TEMP (missing-classname resolve hunt): catch the genuine
            // const-string resolve for idx 0x3456 (slow path at
            // 0xad00e3dc? no: 0xad00e210, proven by KFAULT: r1=idx,
            // r2=table, r4=dex pc 0x41aa7afa, r5=frame). Dump v-regs
            // (v1 expected, v6 tag, v10 array), chase v6/v10 Strings
            // and the array length. Cap 2. Remove with CRASHOBJ.
            if self.r[15] == 0xad00e210 && self.r[1] == 0x3456 {
                static mut NR: u32 = 0;
                unsafe {
                    if NR < 2 {
                        NR += 1;
                        let mb = self.mem.borrow();
                        let r = self.r;
                        let mut wfr = [0u8; 128];
                        let okf = mb.read(r[5], 128).map(|s| wfr.copy_from_slice(s)).is_ok();
                        let v1 = u32::from_le_bytes([wfr[4], wfr[5], wfr[6], wfr[7]]);
                        let v6 = u32::from_le_bytes([wfr[0x18], wfr[0x19], wfr[0x1a], wfr[0x1b]]);
                        let v10 = u32::from_le_bytes([wfr[0x28], wfr[0x29], wfr[0x2a], wfr[0x2b]]);
                        let mut chase = |o: u32| -> String {
                            let mut wo = [0u8; 20];
                            if mb.read(o, 20).map(|s| wo.copy_from_slice(s)).is_err() {
                                return String::from("unread-obj");
                            }
                            let ap = u32::from_le_bytes([wo[16], wo[17], wo[18], wo[19]]);
                            let mut wc = [0u8; 64];
                            if mb.read(ap.wrapping_add(12), 64).map(|s| wc.copy_from_slice(s)).is_err() {
                                return format!("obj-ok-noarray@{ap:#x}");
                            }
                            let mut nm = String::new();
                            for k in (0..64).step_by(2) {
                                let ch = u16::from_le_bytes([wc[k], wc[k + 1]]);
                                if ch == 0 || ch > 0x7e {
                                    break;
                                }
                                nm.push(ch as u8 as char);
                            }
                            if nm.is_empty() {
                                return String::from("array-noascii");
                            }
                            nm
                        };
                        let s6 = chase(v6);
                        let s10 = chase(v10);
                        let mut wl = [0u8; 4];
                        let okl = mb.read(v10.wrapping_add(8), 4).map(|s| wl.copy_from_slice(s)).is_ok();
                        eprintln!("RESOLV#{} ins={} f={} r4={:08x} r5={:08x} v1={v1:#x} v6={v6:#x} v10={v10:#x} s6=\"{s6}\" s10=\"{s10}\" lenok={okl} len={:02x?} frame={:02x?}", unsafe { NR }, self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, r[4], r[5], wl, wfr);
                    }
                }
            }
            if self.r[15] != 0xad0126d4
                && self.r[4] == 0x41aa7afe
                && (0x4100_0000..0x4200_0000).contains(&self.r[5])
                && (0xAD00_0000..0xAD08_0000).contains(&self.r[15])
            {
                static mut NQ: u32 = 0;
                unsafe {
                    if NQ < 2 {
                        NQ += 1;
                        let mb = self.mem.borrow();
                        let r = self.r;
                        let mut wfr = [0u8; 128];
                        let okf = mb.read(r[5], 128).map(|s| wfr.copy_from_slice(s)).is_ok();
                        let mut ach = String::new();
                        let mut i = 0u32;
                        while i < 32 {
                            let cand = u32::from_le_bytes([wfr[i as usize], wfr[i as usize + 1], wfr[i as usize + 2], wfr[i as usize + 3]]);
                            if (0x4000_0000..0x4200_0000).contains(&cand) {
                                let mut wo = [0u8; 20];
                                if mb.read(cand, 20).map(|s| wo.copy_from_slice(s)).is_ok() {
                                    let ap = u32::from_le_bytes([wo[16], wo[17], wo[18], wo[19]]);
                                    let mut wc = [0u8; 64];
                                    if mb.read(ap.wrapping_add(12), 64).map(|s| wc.copy_from_slice(s)).is_ok() {
                                        // UTF-16LE decode first 32 chars.
                                        let mut nm = String::new();
                                        for k in (0..64).step_by(2) {
                                            let ch = u16::from_le_bytes([wc[k], wc[k + 1]]);
                                            if ch == 0 || ch > 0x7e {
                                                break;
                                            }
                                            nm.push(ch as u8 as char);
                                        }
                                        if !nm.is_empty() {
                                            ach.push_str(&format!(" [+{i:#x}]={cand:#x} \"{nm}\";"));
                                        }
                                    }
                                }
                            }
                            i += 4;
                        }
                        eprintln!("MSGSCAN#{} ins={} f={} r4={:08x} r5={:08x} fpok={okf}{ach}", unsafe { NQ }, self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, r[4], r[5]);
                    }
                }
            }
            if self.r[15] != 0xad0126d4
                && self.r[4] == 0x41aa7afe
                && (0x4100_0000..0x4200_0000).contains(&self.r[5])
                && (0xAD00_0000..0xAD08_0000).contains(&self.r[15])
            {
                static mut NL: u32 = 0;
                unsafe {
                    if NL < 2 {
                        NL += 1;
                        let mb = self.mem.borrow();
                        let r = self.r;
                        let mut wfr = [0u8; 128];
                        let okf = mb.read(r[5], 128).map(|s| wfr.copy_from_slice(s)).is_ok();
                        let v1 = u32::from_le_bytes([wfr[4], wfr[5], wfr[6], wfr[7]]);
                        let v6 = u32::from_le_bytes([wfr[0x18], wfr[0x19], wfr[0x1a], wfr[0x1b]]);
                        let v7 = u32::from_le_bytes([wfr[0x1c], wfr[0x1d], wfr[0x1e], wfr[0x1f]]);
                        let v10 = u32::from_le_bytes([wfr[0x28], wfr[0x29], wfr[0x2a], wfr[0x2b]]);
                        // v7 String object head + its char array.
                        let mut wso = [0u8; 32];
                        let oks = mb.read(v7, 32).map(|s| wso.copy_from_slice(s)).is_ok();
                        let arrp = u32::from_le_bytes([wso[16], wso[17], wso[18], wso[19]]);
                        let mut wch = [0u8; 64];
                        let okc = mb.read(arrp.wrapping_add(12), 64).map(|s| wch.copy_from_slice(s)).is_ok();
                        // v10 array object: length at +8, first elements.
                        let mut war = [0u8; 40];
                        let oka = mb.read(v10.wrapping_sub(0), 40).map(|s| war.copy_from_slice(s)).is_ok();
                        // Live dex bytes around rPC (validates the
                        // file decode: const-string target reg + invoke).
                        let mut wdx = [0u8; 24];
                        let okx = mb.read(r[4].wrapping_sub(10), 24).map(|s| wdx.copy_from_slice(s)).is_ok();
                        eprintln!("MISSARG#{} ins={} f={} r4={:08x} r5={:08x} v1={:#x} v6={:#x} v7={:#x} v10={:#x} sok={oks} sobj={wso:02x?} cok={okc} chars={wch:02x?} aok={oka} arrobj={war:02x?} dexok={okx} dex={wdx:02x?} frame={wfr:02x?}", unsafe { NL }, self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, r[4], r[5], v1, v6, v7, v10);
                    }
                }
            }
            if self.r[15] != 0xad0126d4
                && self.r[4] == 0x41aa7afa
                && (0x4100_0000..0x4200_0000).contains(&self.r[5])
                && (0xAD00_0000..0xAD08_0000).contains(&self.r[15])
            {
                static mut NM: u32 = 0;
                unsafe {
                    if NM < 4 {
                        NM += 1;
                        let mb = self.mem.borrow();
                        let r = self.r;
                        let mut wfr = [0u8; 128];
                        let okf = mb.read(r[5], 128).map(|s| wfr.copy_from_slice(s)).is_ok();
                        let va10 = u32::from_le_bytes([wfr[0x28], wfr[0x29], wfr[0x2a], wfr[0x2b]]);
                        let mut warr = [0u8; 40];
                        let oka = mb.read(va10.wrapping_sub(8), 40).map(|s| warr.copy_from_slice(s)).is_ok();
                        eprintln!("MISSCLASS#{} ins={} f={} r4={:08x} r5={:08x} lr={:08x} sp={:08x} fpok={okf} frame={wfr:02x?} arr={va10:#x} arok={oka} arrobj={warr:02x?}", unsafe { NM }, self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, r[4], r[5], r[14], r[13]);
                    }
                }
            }
            if self.r[15] == 0x11020
                || self.r[15] == 0xad0519e4
                || self.r[15] == 0xad038796
                || self.r[15] == 0xad0126d4
                || self.r[15] == 0xad038700
                || self.r[15] == 0xad03add8
                || self.r[15] == 0xad03adb9
                || self.r[15] == 0xad0388d5
                || self.r[15] == 0xad02ab6c
                || self.r[15] == 0xad00e3dc
                || self.r[15] == 0xafe0b4c8
                || self.r[15] == 0xad349854
            {
                static mut JH: u32 = 0;
                static mut JI: u32 = 0;
                unsafe {
                    // TEMP (stale walker link): the walker reads dexPC
                    // as method from a stale node ([0x4104af6c]). Zero it
                    // at walker entry so the node is skipped (null check)
                    // instead of crashing LineNumFromPC. One-shot. Remove
                    // with CRASHOBJ (real fix: stale fp/chain).
                    if self.r[15] == 0xad038700 {
                        static mut NZ: u32 = 0;
                        unsafe {
                            if NZ < 1 {
                                NZ += 1;
                                let mut mbw = self.mem.borrow_mut();
                                // TEMP (WALKERFIX friendly-fire audit): log
                                // the OLD value before zeroing. The zero was
                                // proven for the Audio-era stale node, but
                                // [0x4104af6c] now sits at fp+8 of the LIVE
                                // zygoteInit frame 0x4104af64 (visited 50
                                // ins later with a zeroed +8 and no
                                // FRAMEMETH#5 hit) — a mid-stack word is
                                // live by construction. If the old value is
                                // live, the zero derails the run into the
                                // silent shutdown and must be gated off.
                                // Remove with CRASHOBJ.
                                let mut vb = [0u8; 4];
                                let old = mbw.read(0x4104af6c, 4).map(|s| {
                                    vb.copy_from_slice(s);
                                    u32::from_le_bytes(vb)
                                }).unwrap_or(0xDEAD_DEAD);
                                // Idempotente: so zera se sujo (cada fork
                                // novo pode trazer o no podre de volta).
                                if old != 0 {
                                    let _ = mbw.write_u32(0x4104af6c, 0);
                                }
                                eprintln!("WALKERFIX ins={} zerado [0x4104af6c] era={old:#x}", self.instrucoes);
                            }
                        }
                    }
                    if self.r[15] == 0xad0126d4 {
                        // Hot path: one short line per invoke (cap 2000 for
                        // fp/curFrame correlation). Chase r0 as Method*
                        // ([r0+16] = name ptr) to name the invoked Java
                        // method — the shutdown-wall needs to know whether
                        // SystemServer.main was ever entered. Best-effort
                        // (unreadable -> "?"); layout proven by the MTERP
                        // name chase. Remove with CRASHOBJ.
                        if JI < 2000 {
                            JI += 1;
                            let ji = unsafe { JI };
                            let mb = self.mem.borrow();
                            // Calibre (temp_metodo_classe, snap583): Method
                            // {clazz@+0, name@+16, insns@+32}, Class
                            // {descriptor@+24}. Nomeia CLASSE.metodo.
                            let mut mnome = String::from("?");
                            let mut cla = String::from("?");
                            let mut wmet = [0u8; 36];
                            if mb.read(self.r[0], 36).map(|s| wmet.copy_from_slice(s)).is_ok() {
                                let pa_nome = u32::from_le_bytes([wmet[16], wmet[17], wmet[18], wmet[19]]);
                                let cl = u32::from_le_bytes([wmet[0], wmet[1], wmet[2], wmet[3]]);
                                let mut mnb = [0u8; 64];
                                if mb.read(pa_nome, 64).map(|s| mnb.copy_from_slice(s)).is_ok() {
                                    let fim = mnb.iter().position(|&b| b == 0).unwrap_or(64);
                                    let t = String::from_utf8_lossy(&mnb[..fim]);
                                    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                                        mnome = t.into_owned();
                                    } else {
                                        mnome = format!("noname@{pa_nome:#x}");
                                    }
                                }
                                let mut wcl = [0u8; 32];
                                if mb.read(cl, 32).map(|s| wcl.copy_from_slice(s)).is_ok() {
                                    let pa_d = u32::from_le_bytes([wcl[24], wcl[25], wcl[26], wcl[27]]);
                                    let mut dnb = [0u8; 72];
                                    if mb.read(pa_d, 72).map(|s| dnb.copy_from_slice(s)).is_ok() {
                                        let fim = dnb.iter().position(|&b| b == 0).unwrap_or(72);
                                        let t = String::from_utf8_lossy(&dnb[..fim]);
                                        if !t.is_empty() && t.len() < 70 && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                                            cla = t.into_owned();
                                        }
                                    }
                                }
                            }
                            eprintln!(
                                "INVOKE#{} ins={} r0={:#x} r1={:#x} r2={:#x} r4={:#x} r5={:#x} met={} cla={} mm={:#x}",
                                ji,
                                self.instrucoes,
                                self.r[0],
                                self.r[1],
                                self.r[2],
                                self.r[4],
                                self.r[5],
                                mnome,
                                cla,
                                mb.mm_atual(),
                            );
                            // TEMP (this-hunt): despeja o frame do chamador
                            // para achar `this` (o mesmo objeto em #2/#3/#4
                            // = a excecao; sua clazz nomeia a subclasse
                            // leaf). Remove with CRASHOBJ.
                            {
                                let mut wloc = [0u8; 64];
                                if mb.read(self.r[5], 64).map(|s| wloc.copy_from_slice(s)).is_ok() {
                                    eprintln!("INVKFR#{} r5={:#x} mm={:#x} loc={:02x?}", ji, self.r[5], mb.mm_atual(), wloc);
                                }
                            }
                        }
                    } else if self.r[15] == 0xad00e3dc {
                        // mterp OP_IGET wild r0 (new wall past Audio):
                        // r0=[r5+r1*4] locals slot holds a wild object
                        // pointer; dump the slot computation + locals
                        // + region of r0. Own budget (fires constantly).
                        // Remove with CRASHOBJ.
                        static mut JE: u32 = 0;
                        unsafe {
                            if JE < 200 {
                                JE += 1;
                                let n = JE;
                                let mb = self.mem.borrow();
                                let r = self.r;
                                let slot = r[5].wrapping_add(r[1].wrapping_mul(4));
                                let mut wslot = [0u8; 4];
                                let oks = mb.read(slot, 4).map(|s| wslot.copy_from_slice(s)).is_ok();
                                let mut wloc = [0u8; 64];
                                let okl = mb.read(r[5], 64).map(|s| wloc.copy_from_slice(s)).is_ok();
                                let greg0 = mb.debug_regioes(r[0] & !0xFFF);
                                let greg5 = mb.debug_regioes(r[5] & !0xFFF);
                                // Method name for the IGET site: r4 was already
                                // post-incremented by `ldrh r8,[r4,#2]!`,
                                // so the Method* is r4-2; name at +16.
                                let mut mn = [0u8; 4];
                                let mut mnome_s = String::from("n/a");
                                let met = r[4].wrapping_sub(2);
                                let mut wmet = [0u8; 32];
                                let okm = mb.read(met, 32).map(|s| wmet.copy_from_slice(s)).is_ok();
                                if okm {
                                    let pa_nome = u32::from_le_bytes([wmet[16], wmet[17], wmet[18], wmet[19]]);
                                    let mut mnb = [0u8; 48];
                                    let oknm = mb.read(pa_nome, 48).map(|s| mnb.copy_from_slice(s)).is_ok();
                                    if oknm {
                                        let fim = mnb.iter().position(|&b| b == 0).unwrap_or(48);
                                        mnome_s = String::from_utf8_lossy(&mnb[..fim]).into_owned();
                                    } else {
                                        mnome_s = format!("noname@{pa_nome:#x}");
                                    }
                                } else {
                                    mnome_s = format!("nomet@{met:#x}");
                                }
                                eprintln!("MTERP#{n} ins={} f={} r0={:08x} r1={:08x} r2={:08x} r4={:08x} r5={:08x} r6={:08x} r8={:08x} lr={:08x} sp={:08x} slot={:08x} [slot]ok={oks}={wslot:02x?} locok={okl} loc={wloc:02x?} reg0={greg0} reg5={greg5} metodo={mnome_s}", self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, r[0], r[1], r[2], r[4], r[5], r[6], r[8], r[14], r[13], slot);
                            }
                        }
                    } else if self.r[15] == 0xafe0b4c8 {
                        // TEMP (capset caller hunt): bionic capset entry.
                        // Dump JNI caller (lr), header/data structs and
                        // native stack to name the setCapabilities path
                        // and its EPERM inputs. Cap 8. Remove with CRASHOBJ.
                        static mut NC: u32 = 0;
                        unsafe {
                            if NC < 8 {
                                NC += 1;
                                let n = NC;
                                let mb = self.mem.borrow();
                                let r = self.r;
                                let mut hh = [0u8; 8];
                                let okh = mb.read(r[0], 8).map(|s| hh.copy_from_slice(s)).is_ok();
                                let mut dd = [0u8; 12];
                                let okd = mb.read(r[1], 12).map(|s| dd.copy_from_slice(s)).is_ok();
                                let mut sk = [0u8; 64];
                                let oks = mb.read(r[13], 64).map(|s| sk.copy_from_slice(s)).is_ok();
                                // JNI caller code around lr (Thumb): dump
                                // 64B back + 32 forward to disassemble the
                                // setCapabilities JNI path offline.
                                let mut cj = [0u8; 96];
                                let okj = mb.read(r[14].wrapping_sub(65).wrapping_sub(64), 96).map(|s| cj.copy_from_slice(s)).is_ok();
                                eprintln!("CAPSET#{} ins={} f={} lr={:08x} r0={:08x} r1={:08x} sp={:08x} spok={} stk={:02x?} hok={} hdr={:02x?} dok={} dat={:02x?} jok={} jcode={:02x?}", unsafe { NC }, self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, r[14], r[0], r[1], r[13], oks, sk, okh, hh, okd, dd, okj, cj);
                            }
                        }
                    } else if self.r[15] == 0xad349854 {
                        // TEMP (setCapabilities JNI entry): the (JJ)V args
                        // (r2/r3 = arg0 lo/hi, stack = arg1 lo/hi) are the
                        // Java-passed capability masks. Dump them to tell
                        // poisoned-Java from corrupted-native. Cap 4.
                        // Remove with CRASHOBJ.
                        static mut NJ: u32 = 0;
                        unsafe {
                            if NJ < 4 {
                                NJ += 1;
                                let mb = self.mem.borrow();
                                let r = self.r;
                                let mut sa = [0u8; 16];
                                let oks = mb.read(r[13], 16).map(|s| sa.copy_from_slice(s)).is_ok();
                                eprintln!("JNISET#{} ins={} f={} r0={:08x} r1={:08x} r2={:08x} r3={:08x} sok={} stk={:02x?}", unsafe { NJ }, self.instrucoes, unsafe { crate::msm7201a::FATIA_ATUAL }, r[0], r[1], r[2], r[3], oks, sa);
                            }
                        }
                    } else if JH < 40 && self.r[15] != 0xad038700 {
                        JH += 1;
                        let n = unsafe { JH };
                        let mb = self.mem.borrow();
                        let r = self.r;
                        let mut wnd = [0u8; 80];
                        let okn = mb.read(0x4104af40, 80).map(|s| wnd.copy_from_slice(s)).is_ok();
                        let mut w4 = [0u8; 16];
                        let ok4 = mb.read(r[4], 16).map(|s| w4.copy_from_slice(s)).is_ok();
                        eprintln!("CRASHDUMP#{n} ins={} pc={:08x} r0={:08x} r1={:08x} r2={:08x} r3={:08x} r4={:08x} r5={:08x} r6={:08x} r7={:08x} r8={:08x} r9={:08x} lr={:08x} sp={:08x} [r4]ok={ok4}={w4:02x?} nodeaf40ok={okn}={wnd:02x?}", self.instrucoes, r[15], r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[14], r[13]);
                        // TEMP (walker-frame naming): at the 0xad038796
                        // stack-walk step, chase every heap word in the
                        // visited frame as a Method* ([cand+16] = name).
                        // The guest renderer prints only 1 of ~9 frames
                        // (stale-method resolution); the host chase names
                        // the other 8 without odex parsing. Same cap as
                        // CRASHDUMP (fires together). Remove with CRASHOBJ.
                        if r[15] == 0xad038796 {
                            let mut wfr = [0u8; 64];
                            if mb.read(r[4], 64).map(|s| wfr.copy_from_slice(s)).is_ok() {
                                let mut ach = String::new();
                                let mut i = 0usize;
                                while i + 4 <= 64 {
                                    let cand = u32::from_le_bytes([wfr[i], wfr[i+1], wfr[i+2], wfr[i+3]]);
                                    if (0x4000_0000..0x4200_0000).contains(&cand) && cand != r[4] {
                                        let mut wm = [0u8; 32];
                                        if mb.read(cand, 32).map(|s| wm.copy_from_slice(s)).is_ok() {
                                            let pa = u32::from_le_bytes([wm[16], wm[17], wm[18], wm[19]]);
                                            let cl = u32::from_le_bytes([wm[0], wm[1], wm[2], wm[3]]);
                                            let mut mnb = [0u8; 48];
                                            if mb.read(pa, 48).map(|s| mnb.copy_from_slice(s)).is_ok() {
                                                let fim = mnb.iter().position(|&b| b == 0).unwrap_or(48);
                                                let t = String::from_utf8_lossy(&mnb[..fim]);
                                                if !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                                                    // Classe via Method.clazz@+0,
                                                    // Class.descriptor@+24.
                                                    let mut cs = String::new();
                                                    let mut wcl = [0u8; 32];
                                                    if mb.read(cl, 32).map(|s| wcl.copy_from_slice(s)).is_ok() {
                                                        let pa_d = u32::from_le_bytes([wcl[24], wcl[25], wcl[26], wcl[27]]);
                                                        let mut dnb = [0u8; 72];
                                                        if mb.read(pa_d, 72).map(|s| dnb.copy_from_slice(s)).is_ok() {
                                                            let f2 = dnb.iter().position(|&b| b == 0).unwrap_or(72);
                                                            let u = String::from_utf8_lossy(&dnb[..f2]);
                                                            if !u.is_empty() && u.len() < 70 && u.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                                                                cs = format!("{u}.");
                                                            }
                                                        }
                                                    }
                                                    ach.push_str(&format!(" [+{i:#x}]={cand:#x} \"{cs}{t}\";"));
                                                }
                                            }
                                        }
                                    }
                                    i += 4;
                                }
                                if !ach.is_empty() {
                                    eprintln!("FRAMEMETH#{n} r4={:08x}{ach}", r[4]);
                                }
                            }
                        }
                    }
                }
            }
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
                        let w = self.mem.borrow()
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
        self.mem.borrow()
            .read(addr, buf.len() as u32)
            .map(|bytes| buf.copy_from_slice(bytes))
            .map_err(|e| CpuError(e.to_string()))
    }

    fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<(), CpuError> {
        self.mem.borrow_mut()
            .write(addr, data)
            .map_err(|e| CpuError(e.to_string()))
    }

    fn map_zeroed(&mut self, name: &'static str, base: u32, len: usize) -> Result<(), CpuError> {
        self.mem.borrow_mut()
            .map_zeroed(name, base, len)
            .map_err(|e| CpuError(e.to_string()))
    }

    fn desmapeia_intervalo(&mut self, base: u32, len: usize) -> Result<(), CpuError> {
        self.mem.borrow_mut().desmapeia_intervalo(base, len);
        Ok(())
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
    fn undef_entrega_ao_vetor_em_modo_usuario() {
        // UND delivery: from USR (Thumb, pc AT the faulting insn),
        // entra_undef parks spsr_und, switches to UND/ARM/I-masked,
        // sets lr = fault+2 and vectors to 0x04 (low vectors: the
        // test SCTLR has no V bit). The guest handler runs instead
        // of the run stopping.
        let mut cpu = cpu_with(&arm(&[0xe1a0_0000]));
        cpu.write_reg(Reg::Pc, 0x1000);
        // Force Thumb USR: T set, mode USR (cpu_with leaves ARM).
        cpu.cpsr |= 1 << 5;
        assert!(cpu.em_usuario());
        cpu.entra_undef();
        assert_eq!(cpu.cpsr & 0x1F, 0x1B);
        assert_eq!(cpu.cpsr & (1 << 5), 0);
        assert_eq!(cpu.read_reg(Reg::Pc), 0x04);
        assert_eq!(cpu.read_reg(Reg::Lr), 0x1002);
        assert!(!cpu.em_usuario());
    }

    #[test]
    fn irq_entra_e_volta_com_cpsr_restaurado() {
        // IRQ delivery + exception return through the handler. The
        // fonte is always pending; the handler runs and the CPSR
        // (USR, I clear) comes back intact.
        // Delivery is edge-driven on unmask: with the line stuck
        // high and I=0, the return redelivers IMMEDIATELY (same as
        // hardware — no 64-instruction poll gap), so the run ends
        // mid-handler, not in the USR spin. Assert delivery happened
        // (r0==7); the final mode is where Budget lands.
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
        cpu.set_fonte_irq(|_, _| true);
        assert_eq!(cpu.run(0, 200).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 7);
    }

    #[test]
    fn cpsid_sets_cpsie_clears_i_bit() {
        // cpsie i is 0xF1080080 (imod=2, CLEARS I); cpsid i is
        // 0xF10C0080 (imod=3, SETS it) — mapping verified by assembling
        // both mnemonics with arm-none-eabi-as. An earlier version of
        // this test had them backwards (matching a swapped objdump
        // print table), which masked a backend inversion that tripped
        // the sched.c:4032 BUG_ON. Regression guard.
        let mut cpu = cpu_with(&arm(&[0xf108_0080, 0xf10c_0080]));
        cpu.write_reg(Reg::Pc, 0);
        assert_eq!(cpu.cpsr() & 0x80, 0);
        cpu.run(0, 1).unwrap();
        assert_eq!(cpu.cpsr() & 0x80, 0, "cpsie i must CLEAR I");
        cpu.run(4, 1).unwrap();
        assert_ne!(cpu.cpsr() & 0x80, 0, "cpsid i must SET I");
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
    fn desmascarar_entrega_irq_pendente_sem_poll() {
        // Unmask edge: cpsie with the line already high must deliver
        // on the very next loop top, not up to 63 instructions later.
        // (The 64-poll counter strides over default_idle's brief
        // unmasked windows forever — live: zero deliveries for 200k
        // slices.) Budget 6 proves immediacy: without the edge the
        // poll would need ~64 unmasked instructions first (r0==0).
        // 0x00: cpsid i; 0x04: cpsie i; 0x08: b .;
        // 0x18: mov r0, #7; movs pc, lr.
        let mut cpu = cpu_with(&arm(&[
            0xf10c_0080, // cpsid i (masked start)
            0xf108_0080, // cpsie i (unmask edge)
            0xeaff_fffe, // b . (never runs: delivery preempts it)
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0xe3a0_0007, // handler: mov r0, #7
            0xe1b0_f00e, // movs pc, lr
        ]));
        cpu.set_fonte_irq(|_, _| true);
        assert_eq!(cpu.run(0, 6).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 7);
    }

    #[test]
    fn wfi_acorda_e_entrega_irq_desmascarado() {
        // WFI wake with I=0 delivers on the spot (before the guest
        // can reprogram MATCH and hide the edge — the 1.65s wall).
        // Masked WFI still just wakes (see wfi_acordado...).
        // 0x00: wfi; 0x04: b . (never runs: delivery preempts it);
        // 0x18: mov r0, #7; movs pc, lr.
        let mut cpu = cpu_with(&arm(&[
            0xee07_0f90, // wfi
            0xeaff_fffe, // b .
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0xe3a0_0007, // handler: mov r0, #7
            0xe1b0_f00e, // movs pc, lr
        ]));
        cpu.set_fonte_irq(|_, _| true);
        assert_eq!(cpu.run(0, 6).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 7);
    }

    #[test]
    fn aborto_dado_grava_far_e_vai_ao_vetor() {
        // entra_aborto(0x1FCE0, 0x5, false) with r15 AT the fault
        // (faulting accesses don't advance it, unlike IRQ delivery):
        // mode ABT, I+A masked, FAR/DFSR recorded, lr=fault+8,
        // pc=0x10 (low vectors: SCTLR bit13 clear on reset).
        let mut cpu = cpu_with(&arm(&[0xeaff_fffe]));
        cpu.write_reg(Reg::Pc, 0x1000);
        cpu.entra_aborto(0x1fce0, 0x5, false);
        assert_eq!(cpu.cpsr() & 0x1F, 0x17);
        assert_ne!(cpu.cpsr() & 0x80, 0);
        assert_ne!(cpu.cpsr() & 0x100, 0);
        assert_eq!(cpu.read_reg(Reg::Pc), 0x10);
        assert_eq!(cpu.read_reg(Reg::Lr), 0x1008);
        assert_eq!(cpu.le_cp15(0x300), Some(0x1fce0));
        assert_eq!(cpu.le_cp15(0x280), Some(0x5));
        // Prefetch variant: lr = fault+4, IFSR key, 0x0C vector.
        let mut cpu = cpu_with(&arm(&[0xeaff_fffe]));
        cpu.write_reg(Reg::Pc, 0x80bc);
        cpu.entra_aborto(0x80bc, 0x5, true);
        assert_eq!(cpu.cpsr() & 0x1F, 0x17);
        assert_eq!(cpu.read_reg(Reg::Pc), 0x0C);
        assert_eq!(cpu.read_reg(Reg::Lr), 0x80c0);
        assert_eq!(cpu.le_cp15(0x281), Some(0x5));
    }

    #[test]
    fn bl_reverso_longo_desvia() {
        // init's 0xAFFC list walk starts with a backward `bl 0xABD4`
        // (first half 0xF7FF at 0xB002, S=1 negative offset); the
        // live 0xB012 fault analysis hinged on whether this bl is
        // taken (its fallthrough would silently skip the callee).
        // Exact init bytes: the bl must leave to 0xABD4 (fetch
        // fault there), with lr set to the 0xB006 return (bit0 set)
        // and r3/r2 holding just the literal loads.
        let mut mem = GuestMemory::new();
        let code: Vec<u8> = vec![
            0x0A, 0x4B, // 0xAFFE: ldr r3, [pc, #40]
            0x0A, 0x4A, // 0xB000: ldr r2, [pc, #40]
            0xFF, 0xF7, 0xE7, 0xFD, // 0xB002: bl 0xABD4 (backward)
            0x7B, 0x44, // 0xB004: add r3, pc (never runs: bl left)
        ];
        // One region [0xA000,0xB200): sequence tail at 0xAFFE,
        // literal pool at 0xB028/0xB02C, and a marker at the bl
        // target 0xABD4 (`movs r0,#0x42; b .`). Taken bl ⟺ r0==0x42
        // (fallthrough instead reaches the 0xB004 adds and faults on
        // the unmapped literal base). Zeros elsewhere NOP-sled, so
        // Budget is the only other outcome.
        let mut pag = vec![0u8; 0xFFE];
        pag.extend_from_slice(&code);
        pag.resize(0x1200, 0);
        pag[0xBD4] = 0x42;
        pag[0xBD4 + 1] = 0x20;
        pag[0xBD4 + 2] = 0xFE;
        pag[0xBD4 + 3] = 0xE7;
        mem.map("code", 0xA000, pag, true).unwrap();
        mem.write(0xB028, &0x14484u32.to_le_bytes()).unwrap();
        mem.write(0xB02C, &0x6F4u32.to_le_bytes()).unwrap();
        let mut cpu = Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        let parada = cpu.run(0xAFFF, 20).unwrap();
        // The backward bl must reach the 0xABD4 marker (r0==0x42);
        // the adds must not have run (r3 still the literal).
        assert_eq!(cpu.read_reg(Reg::R0), 0x42, "bl did not branch? {parada:?}");
        assert_eq!(cpu.read_reg(Reg::Lr), 0xB007);
        assert_eq!(cpu.read_reg(Reg::R3), 0x14484);
        assert_eq!(cpu.read_reg(Reg::R2), 0x6F4);
    }

    #[test]
    fn ldc_p15_e_nop_outro_coprocessador_falha() {
        // STC p15 (0xEC442F0E, the preload op in flush_pfn_alias on
        // the /init exec path): accepted as NOP in the cacheless
        // flat model. Same encoding to p10 must still fault (real
        // VFP state would corrupt).
        // 0x00: stc p15, cr2, [r4]; 0x04: b . (never runs: Budget).
        let mut cpu = cpu_with(&arm(&[0xec44_2f0e, 0xeaff_fffe]));
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 6).unwrap(), StopReason::Budget);
        // 0x00: stc p10, cr2, [r4] (CP#=0xA): Exception.
        let mut cpu = cpu_with(&arm(&[0xec44_2a0e]));
        assert!(matches!(cpu.run(0, 6).unwrap(), StopReason::Exception { .. }));
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
        cpu.set_fonte_irq(|_, _| true);
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
    fn push_thumb_falhado_restaura_sp() {
        // Thumb push commits sp BEFORE storing: a fault on the 3rd
        // word (stack growth into unmapped) must roll sp back, or
        // the resume re-executes and double-decrements (live: -24
        // drift broke init's canary check and popped the guard
        // into pc). 12-byte stack window, sp 4 above it, 3-reg push
        // (12 B): first two stores land, third faults.
        let mut bytes = vec![0u8; 0x1000];
        // 0x00: push {r0-r2} (0xB407); 0x02: b . (0xE7FE).
        bytes[0x00..0x02].copy_from_slice(&0xB407u16.to_le_bytes());
        bytes[0x02..0x04].copy_from_slice(&0xE7FEu16.to_le_bytes());
        let mut mem = crate::cpu::mem::GuestMemory::new();
        mem.map("code", 0, bytes, true).unwrap();
        mem.map_zeroed("stack", 0x2000_0000, 8).unwrap();
        let mut cpu = crate::cpu::interpretador::Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0008);
        let parada = cpu.run(1, 10).unwrap();
        assert!(matches!(parada, StopReason::MemoryFault { .. }), "{parada:?}");
        assert_eq!(cpu.read_reg(Reg::Sp), 0x2000_0008);
    }

    #[test]
    fn thumb_bl_par_nao_alinhado_acerta_alvo() {
        // Old-Thumb BL with the pair at pc≡2 (mod 4): base is the
        // unmasked pc+4. Pair at 0x02: first 0xF000 (imm10=0 → LR=6),
        // second 0xF87D (imm11=0x7D → target 6+0xFA=0x100). The old
        // `& !2` gave base 4, target 0xFE (proven live: init's bl at
        // 0x8ECE landed 2 early on padding and faulted odd-pc).
        let mut bytes = vec![0u8; 0x1000];
        bytes[0x02..0x04].copy_from_slice(&0xF000u16.to_le_bytes());
        bytes[0x04..0x06].copy_from_slice(&0xF87Du16.to_le_bytes());
        let mut mem = crate::cpu::mem::GuestMemory::new();
        mem.map("code", 0, bytes, true).unwrap();
        mem.map_zeroed("data", 0x1000, 0x1000).unwrap();
        mem.map_zeroed("stack", 0x2000_0000, 0x1000).unwrap();
        let mut cpu = crate::cpu::interpretador::Interpretador::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        let _ = cpu.run(3, 2);
        assert_eq!(cpu.read_reg(Reg::Pc) & !1, 0x100);
        assert!(cpu.read_reg(Reg::Pc) & 1 == 0);
        assert_eq!(cpu.read_reg(Reg::Lr), 0x07);
    }

    #[test]
    fn svc_usuario_vai_ao_vetor_convidado() {
        // svc #0 (EABI syscall) in USR mode → entra_svc: mode SVC,
        // I masked, lr=fault+4, pc=0x08 (low vectors: SCTLR bit13
        // clear on reset), semihosting untouched.
        let mut cpu = cpu_with(&arm(&[0xef00_0000, 0xeaff_fffe]));
        // 0x08 lies inside cpu_with's zero-padded code region:
        // plant a branch-shaped vector there (no extra mapping).
        cpu.write_mem(0x08, &0xEA00_0000u32.to_le_bytes()).unwrap();
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.cpsr() & 0x1F, 0x10);
        let _ = cpu.run(0, 1);
        assert_eq!(cpu.cpsr() & 0x1F, 0x13);
        assert_ne!(cpu.cpsr() & 0x80, 0);
        assert_eq!(cpu.read_reg(Reg::Pc), 0x08);
        assert_eq!(cpu.read_reg(Reg::Lr), 0x04);
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
