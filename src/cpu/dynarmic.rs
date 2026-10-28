//! ARM backend over Dynarmic.
//!
//! Dynarmic recompiles A32 blocks to host native code. This file keeps the same
//! [`CpuBackend`] boundary: the unmapped BREW vtable addresses remain the
//! stop that returns control to the Rust dispatcher.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::ffi::c_void;
use std::mem::size_of;
use std::rc::Rc;

use dynarmic::a32::{ArchVersion, Callbacks, Coprocessor, Dynarmic as Jit, VAddr};
use dynarmic::cxx::CxxSharedPtr;
use dynarmic::{CallbackImpl, ExclusiveMonitor, GuestInt, HaltReason};

use super::mem::GuestMemory;
use super::{API_BASE, API_SIZE, RETURN_MAGIC};
use super::{CpuBackend, CpuError, Reg, StopReason};

/// ARM user-mode `CPSR`. The Superscape extension checks this field before touching
/// the MMU tables; the BREW applet is never privileged code.
const MODO_USUARIO: u32 = 0x10;

/// The `T` bit of `CPSR`: when set, the core fetches Thumb instructions.
const CPSR_THUMB: u32 = 1 << 5;

/// Defensive limit for the string received via `SYS_WRITE0`: an unterminated string must not
/// trap the host in an endless read.
const MAX_SEMIHOSTING_STRING: u32 = 4096;

/// Granularity Dynarmic uses to index recompiled code.
const PAGE: u32 = 4096;

/// How many 4 KB pages fit in the guest's 32 bits: the page table size.
const PAGINAS: usize = 1 << 20;

/// Bytes reserved past the end of each writable region. A four-byte read in the last
/// bytes of a page ending the region would cross the boundary in host memory; with the slack, it
/// reads allocated memory instead of running off the vector.
const FOLGA_DA_REGIAO: usize = 16;

/// What a callback asked `run` to return. Dynarmic receives memory accesses inside
/// the recompiled block; storing the reason here preserves the distinction between API, return and fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parada {
    Nenhuma,
    Fetch(u32),
    Memoria(u32),
    Excecao(u32),
    /// The guest reached the address armed by [`DynarmicCpu::trap_pc`]. Unlike
    /// `Fetch`, this is not a fault: the host reports `(r0, r1)` and resumes
    /// into the real bytes.
    Armadilha(u32),
    /// The guest reached an address armed by [`DynarmicCpu::trap_pc_mem`].
    /// Unlike `Fetch`, this is not a fault: the host runs the armed hook
    /// with guest memory and registers, then resumes into the real bytes.
    ArmadilhaMem(u32),
}

/// Guest pages already fetched as code, one bit per page.
///
/// Every guest write asks here, and the Kingdom Hearts ARM renderer writes
/// millions of pixels per frame. With a `BTreeSet` behind a `RefCell`, each pixel paid a
/// borrow and a tree lookup — and that is what made the 3D, already accelerated by the JIT, lose
/// frames again. One bit per page, in `Cell`, answers with a shift and a mask: that is
/// 2^20 4 KB pages, 16,384 words, 131 KB.
struct PaginasExecutadas {
    bits: Box<[Cell<u64>]>,
}

impl PaginasExecutadas {
    fn new() -> Self {
        Self {
            bits: (0..(1usize << 20).div_ceil(64)).map(|_| Cell::new(0)).collect(),
        }
    }

    fn marca(&self, pagina: u32) {
        let (palavra, bit) = ((pagina / 64) as usize, pagina % 64);
        if let Some(celula) = self.bits.get(palavra) {
            celula.set(celula.get() | (1 << bit));
        }
    }

    fn contem(&self, pagina: u32) -> bool {
        let (palavra, bit) = ((pagina / 64) as usize, pagina % 64);
        self.bits
            .get(palavra)
            .is_some_and(|celula| celula.get() & (1 << bit) != 0)
    }
}

/// State shared between the C++ callbacks and the Rust wrapper.
///
/// The JIT is kept in a `Box` in the backend, so its address does not change when the `DynarmicCpu`
/// moves. That lets the callback stop execution the moment the PC enters a
/// BREW vtable, instead of executing a fake instruction at that address.
struct Estado {
    memoria: Rc<RefCell<GuestMemory>>,
    semihosting: Rc<RefCell<String>>,
    /// Only a write to memory already fetched as code can invalidate a JIT block.
    /// That excludes the millions of writes to the RGB565 buffers.
    paginas_executadas: PaginasExecutadas,
    /// Invalidations requested by ARM during the executing block; applied after `run`.
    codigo_sujo: RefCell<BTreeSet<u32>>,
    /// The [`CpuBackend::watch_dirty`] ranges: `(id, start, end, dirty)`.
    vigias: RefCell<Vec<(u32, u32, u32, bool)>>,
    /// The smallest interval containing all watches. Almost every guest write falls outside it,
    /// and then it costs two comparisons instead of a trip through the list.
    envoltorio: Cell<(u32, u32)>,
    /// A range already dirty. Writes inside it need nothing more.
    ///
    /// That is the case almost always: an ARM renderer writes millions of pixels in a row into the same
    /// buffer, and after the first they all land in a range already marked. Without the shortcut,
    /// each of them would borrow the list and walk it to mark what was already
    /// marked. Cleared whenever some range may have become clean again.
    atalho: Cell<(u32, u32)>,
    instrucoes: Cell<u64>,
    limite: Cell<u64>,
    parada: Cell<Parada>,
    /// How many times the host entered the JIT, and how long it stayed inside.
    ///
    /// **It is the number that separates guest from dispatch.** Each API call is an exit and a
    /// reentry, so what is left of the clock after subtracting the time spent inside
    /// `jit.run` is, almost all of it, trampoline plus method body. Without this accounting the per-
    /// API-call cost is unknown — and it was by treating a Unicorn-era number as current that
    /// the external review went wrong. See [`CpuBackend::relato_do_jit`].
    ///
    /// They live here, not in `DynarmicCpu`, because the `Jit` borrow is alive for the whole
    /// `run`: a `Cell` in the state crosses the immutable borrow without fighting it.
    ///
    /// **Counting is free; timing is not.** Measured: one `Instant::now()` pair per entry
    /// cost **40% of the clock** on this machine (`Instant::now` here is a system call, not
    /// the fast vDSO path), and there are 1.3 million entries in a fifteen-second Quake. So
    /// the count is always on — a sum in a `Cell` — and the clock is **sampled**, and only
    /// when someone asks for the cost profile. See [`liga_medicao_do_jit`].
    entradas_no_jit: Cell<u64>,
    nanos_no_jit: Cell<u64>,
    amostras_no_jit: Cell<u64>,
    /// Address armed by `trap_pc`, if any. Compared against every code fetch
    /// while set: one `u32` compare per fetched instruction, no extra loan.
    armadilha: Cell<Option<u32>>,
    /// One-shot pass over the trap: the resume step sets it so the next fetch
    /// of the trapped address returns the real bytes instead of faulting.
    /// Consumed by that fetch. Without it the step would fault again and the
    /// outer loop would never make progress past the trapped instruction.
    passagem: Cell<bool>,
    /// Multi-PC traps: address, Thumb patch, original word, hook. Shared
    /// with the backend (like `memoria`): arming survives `reset`. Same
    /// hook shape as the interpretador, so harness code ports unchanged.
    armadilhas_mem:
        Rc<RefCell<Vec<(u32, bool, u32, Box<dyn FnMut(&mut GuestMemory, &mut [u32; 16])>)>>>,
    jit: Cell<*mut Jit<Estado>>,
    /// Dynarmic's page table: `PAGINAS` pointers, the start of each page on the host, or
    /// null for pages that must go through the callbacks. See [`DynarmicCpu::tabela`].
    tabela: *mut *mut u8,
}

impl Estado {
    /// Removes the page from the table: from then on reads and writes to it go through the callbacks.
    fn anula_pagina(&self, pagina: u32) {
        if (pagina as usize) < PAGINAS {
            unsafe { *self.tabela.add(pagina as usize) = std::ptr::null_mut() };
        }
    }

    fn para(cb: &CallbackImpl<Self>, parada: Parada) {
        cb.parada.set(parada);
        let jit = cb.jit.get();
        if !jit.is_null() {
            // `HaltExecution` is Dynarmic's documented way for a callback to return
            // control to the host. The concrete reason is kept in `parada`, since the public enum only
            // offers the generic user bits.
            unsafe { (*jit).halt(HaltReason::UserDefined1) };
        }
    }

    fn le(&self, addr: u32, out: &mut [u8]) -> bool {
        self.memoria
            .borrow()
            .read(addr, out.len() as u32)
            .map_or_else(
                |_| false,
                |bytes| {
                    out.copy_from_slice(bytes);
                    true
                },
            )
    }

    fn escreve(&self, addr: u32, bytes: &[u8]) -> bool {
        if self.memoria.borrow_mut().write(addr, bytes).is_err() {
            return false;
        }
        self.marca_codigo_sujo(addr, bytes.len() as u32);
        self.marca_vigias(addr, addr.saturating_add(bytes.len() as u32));
        true
    }

    fn marca_vigias(&self, inicio: u32, fim: u32) {
        let (menor, maior) = self.envoltorio.get();
        if fim <= menor || inicio >= maior {
            return;
        }
        let (a, b) = self.atalho.get();
        if inicio >= a && fim <= b {
            return;
        }
        let mut vigias = self.vigias.borrow_mut();
        let mut tocadas = 0;
        let mut faixa = (0, 0);
        for vigia in vigias.iter_mut() {
            if inicio < vigia.2 && fim > vigia.1 {
                vigia.3 = true;
                tocadas += 1;
                faixa = (vigia.1, vigia.2);
            }
        }
        // The shortcut only holds for a range containing the whole write that is the only one touched:
        // with two overlapping, skipping the second would fail to mark it.
        if tocadas == 1 && inicio >= faixa.0 && fim <= faixa.1 {
            self.atalho.set(faixa);
        }
    }

    fn recalcula_envoltorio(&self) {
        self.atalho.set((0, 0));
        let vigias = self.vigias.borrow();
        let menor = vigias.iter().map(|v| v.1).min().unwrap_or(0);
        let maior = vigias.iter().map(|v| v.2).max().unwrap_or(0);
        self.envoltorio.set((menor, maior));
    }

    fn marca_codigo_sujo(&self, addr: u32, len: u32) {
        let fim = addr.saturating_add(len.saturating_sub(1));
        for pagina in (addr / PAGE)..=(fim / PAGE) {
            // The one-bit test comes before any borrow: almost every write lands on a
            // data page, and only one landing on code pays for the dirty list.
            if self.paginas_executadas.contem(pagina) {
                self.codigo_sujo.borrow_mut().insert(pagina);
            }
        }
    }
}

impl Callbacks for Estado {
    fn memory_read_code(cb: &CallbackImpl<Self>, addr: VAddr) -> Option<u32> {
        // Observational PC trap (Dream SPL serial bring-up: `PUTC_ADDR_POS_MMU`
        // in `msm7201a_serial`). Faulting here instead of reporting inline is
        // what makes the trap per-execution rather than per-translation: the
        // translated block is discarded, so the next arrival re-fetches and
        // faults again. A fetch hook without the fault would fire once, when
        // the block is first compiled, and stay silent on every hot revisit.
        if cb.armadilha.get() == Some(addr) {
            if cb.passagem.get() {
                cb.passagem.set(false);
            } else {
                // Fault only when translation starts at the trap. While a
                // block is being translated the JIT PC still holds the block
                // entry (measured: entry == fetch address on branch arrival),
                // so a mismatch means a fall-through fetch in the middle of
                // a block. Faulting there would discard the whole block and
                // skip its prefix on resume, corrupting the guest — the
                // observational trap must never change guest behavior. Those
                // arrivals fall through with real bytes and are missed until
                // the block is retranslated; see `trap_pc`.
                let inicio = unsafe { (*cb.jit.get()).get_pc() } & !1;
                if inicio == addr {
                    Self::para(cb, Parada::Armadilha(addr));
                    return None;
                }
            }
        }
        let mut bytes = [0; 4];
        if cb.memoria.borrow().executavel(addr) && cb.le(addr, &mut bytes) {
            // A page turning into code leaves the table, so every write to it reaches the callback
            // that invalidates the recompiled block.
            let pagina = addr / PAGE;
            if !cb.paginas_executadas.contem(pagina) {
                cb.paginas_executadas.marca(pagina);
                cb.anula_pagina(pagina);
            }
            Some(u32::from_le_bytes(bytes))
        } else {
            // A trap fault above already armed `parada`: keep it, so the
            // wrapper reports the trap instead of a memory fault for the
            // trapped address. Same guard shape as `raised_exception` below.
            if cb.parada.get() == Parada::Nenhuma {
                Self::para(cb, Parada::Fetch(addr));
            }
            None
        }
    }

    extern "C" fn memory_read<T: GuestInt>(cb: &CallbackImpl<Self>, addr: VAddr) -> T {
        let mut bytes = [0u8; 8];
        let len = size_of::<T>();
        if !cb.le(addr, &mut bytes[..len]) {
            Self::para(cb, Parada::Memoria(addr));
        }
        // The hosts Dynarmic accepts are x86-64 and AArch64, both little-endian. `T` is only
        // instantiated by the JIT for u8/u16/u32/u64.
        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
    }

    extern "C" fn memory_write<T: GuestInt>(cb: &mut CallbackImpl<Self>, addr: VAddr, value: T) {
        let len = size_of::<T>();
        let bytes = unsafe { std::slice::from_raw_parts((&value as *const T).cast::<u8>(), len) };
        if !cb.escreve(addr, bytes) {
            Self::para(cb, Parada::Memoria(addr));
        }
    }

    extern "C" fn call_svc(cb: &mut CallbackImpl<Self>, swi: u32) {
        // `SVC #0xAB` is the ARM semihosting Peggle and Zuma use for logging. It is not a
        // BREW interrupt: after serving it execution continues at the next instruction.
        // We recognize the two output operations the observed games use and return zero
        // for the rest, as the ARM monitor does for most harmless queries.
        //
        // **The number changes with the core state**: `0xAB` is Thumb's, and `0x123456` is ARM's.
        // Ultimate Chess 3D writes its log in ARM, and with only `0xAB` recognized the
        // first `SYS_WRITEC` — when capturing an opponent piece — stopped the game with an "ARM
        // core exception". The interpreter already served both: it only looks at `r0`.
        if SEMIHOSTING.contains(&swi) {
            let jit = unsafe { &mut *cb.jit.get() };
            let op = jit.get_reg(0);
            let arg = jit.get_reg(1);
            let mut saida = cb.semihosting.borrow_mut();
            match op {
                0x03 => {
                    let mut byte = [0u8; 1];
                    if cb.le(arg, &mut byte) {
                        saida.push(byte[0] as char);
                    }
                }
                0x04 => {
                    for offset in 0..MAX_SEMIHOSTING_STRING {
                        let mut byte = [0u8; 1];
                        if !cb.le(arg.saturating_add(offset), &mut byte) || byte[0] == 0 {
                            break;
                        }
                        saida.push(byte[0] as char);
                    }
                }
                _ => {}
            }
            super::apara_semihosting(&mut saida);
            jit.set_reg(0, 0);
        } else if swi == SVC_ARMADILHA || swi == SVC_ARMADILHA_THUMB {
            // Serving trap (patched in by `trap_pc_mem`): halt for the run
            // loop, which looks the hook up by PC. The JIT reports the
            // instruction AFTER the SVC (measured: svc at 0x4 reports
            // pc=0x8), so step back over it; the T bit selects the width.
            let jit = unsafe { &*cb.jit.get() };
            let pc = jit.get_pc();
            let t = jit.get_cpsr() & 0x20 != 0;
            Self::para(cb, Parada::ArmadilhaMem(pc.wrapping_sub(if t { 2 } else { 4 })));
        } else if cb.parada.get() == Parada::Nenhuma {
            let pc = unsafe { (*cb.jit.get()).get_pc() };
            Self::para(cb, Parada::Excecao(pc));
        }
    }

    extern "C" fn add_ticks(cb: &mut CallbackImpl<Self>, ticks: u64) {
        cb.instrucoes.set(cb.instrucoes.get().saturating_add(ticks));
    }

    extern "C" fn get_ticks_remaining(cb: &CallbackImpl<Self>) -> u64 {
        cb.limite.get().saturating_sub(cb.instrucoes.get())
    }

    extern "C" fn raised_exception(
        cb: &mut CallbackImpl<Self>,
        pc: VAddr,
        _exception: ::dynarmic::a32::Exception,
    ) {
        // `MemoryReadCode(None)` ends up as `NoExecuteFault`, arriving here after the
        // callback already recorded the fetch. Not overwriting it is what keeps the
        // BREW vtable boundary distinguishable from a truly invalid instruction.
        if cb.parada.get() == Parada::Nenhuma {
            // The current binding turns the fetch's `optional<u32>::none()` into
            // `NoExecuteFault` before returning control. The API range and the sentinel
            // never contain code by definition, so they can still be classified here without
            // ambiguity.
            if pc == RETURN_MAGIC || (API_BASE..API_BASE.saturating_add(API_SIZE)).contains(&pc) {
                Self::para(cb, Parada::Fetch(pc));
            } else {
                Self::para(cb, Parada::Excecao(pc));
            }
        }
    }
}

/// The ARM semihosting `SVC` numbers: Thumb's and ARM's.
const SEMIHOSTING: [u32; 2] = [0xab, 0x12_3456];

/// SVC numbers reserved for serving traps (see [`DynarmicCpu::trap_pc_mem`]).
/// The guest uses `svc #0` (syscalls), `0xAB`/`0x123456` (semihosting) and
/// `0xCDAB89` (SPL semihosting); these two never appear on the wire.
const SVC_ARMADILHA: u32 = 0xD0_0000;
const SVC_ARMADILHA_THUMB: u32 = 0xD0;

/// ARM `svc #SVC_ARMADILHA` encoding (patched over trapped ARM code).
const SVC_ARMADILHA_INSTR: u32 = 0xEF00_0000 | SVC_ARMADILHA;
/// Thumb `svc #SVC_ARMADILHA_THUMB` encoding (patched over trapped Thumb code).
const SVC_ARMADILHA_THUMB_INSTR: u32 = 0xDF00 | SVC_ARMADILHA_THUMB;

/// Every how many JIT entries the clock is read, when measurement is on.
const AMOSTRA_DO_JIT: u64 = 64;

/// A32 recompiler. Stays separate from the default backend until equivalence is established game
/// by game; creating the CPU does not allocate the JIT, because the guest map only exists in `reset`.
/// CP15 state for the Dream bring-up: the flat model, mirroring the
/// interpretador's `arm_coproc` (accept-and-store, mapping unchanged).
/// Lives in a `Box` so the C++ coprocessor shim keeps a stable pointer;
/// replaced on every `reset`, after the old JIT (its only user) is gone.
struct P15Ctx {
    cp15: Vec<(u32, u32)>,
    /// MCR p15 c7,c0,4 seen (guest asked to sleep until interrupt).
    /// Recorded only for now: IRQ delivery under Dynarmic is open.
    wfi: bool,
    /// Last TTBR0 value (key `0x100`), tracked like the interpretador.
    ttbr: u32,
    mem: Rc<RefCell<GuestMemory>>,
    /// Set after `init`, so the unhandled-encoding path can stop the run
    /// cleanly instead of aborting the process.
    jit: *mut Jit<Estado>,
    /// Set by the unhandled path; the `run` loop maps it to
    /// `StopReason::Exception` at the halting PC.
    fault: bool,
}

/// MCR p15 c7,c0,4 (wait-for-interrupt) key.
const P15_WFI: u32 = (7 << 7) | 4;
/// TTBR0 (MCR/MRC p15,0,Rt,c2,c0,0) key.
const P15_TTBR0: u32 = 2 << 7;
/// Main ID (MRC p15,0,Rd,c0,c0,0) key and the ARM1136EJ-S value the
/// Dream's MSM7201A reports (the kernel parks if this reads 0).
const P15_MIDR: u32 = 0;
const MIDR_ARM1136: u32 = 0x4117_B360;

extern "C" fn p15_access(ctx: *mut c_void, key: u32, is_write: u32, value: u32) -> u32 {
    let st = unsafe { &mut *(ctx as *mut P15Ctx) };
    if is_write != 0 {
        if key == P15_WFI {
            st.wfi = true;
            return 0;
        }
        match st.cp15.iter_mut().find(|(k, _)| *k as u32 == key) {
            Some(slot) => slot.1 = value,
            None => st.cp15.push((key, value)),
        }
        if key == P15_TTBR0 {
            st.ttbr = value & 0xFFFF_C000;
            let _ = st.mem.borrow_mut().trocar_mm(st.ttbr);
        }
        0
    } else {
        st.cp15.iter().find(|(k, _)| *k as u32 == key).map_or(0, |(_, v)| *v)
    }
}

extern "C" fn p15_unhandled(ctx: *mut c_void, kind: u32, _d0: u32, _d1: u32) {
    let st = unsafe { &mut *(ctx as *mut P15Ctx) };
    eprintln!("dynarmic-p15: unhandled coprocessor encoding kind={kind}");
    st.fault = true;
    if !st.jit.is_null() {
        unsafe { (*st.jit).halt(HaltReason::UserDefined1) };
    }
}

pub struct DynarmicCpu {
    memoria: Rc<RefCell<GuestMemory>>,
    semihosting: Rc<RefCell<String>>,
    jit: Option<Box<Jit<Estado>>>,
    /// Flat CP15 model for the Dream bring-up (see `P15Ctx`).
    p15: Option<Box<P15Ctx>>,
    /// Exclusive-access monitor for LDREX/STREX (the Dream kernel uses
    /// them for every spinlock; without it translation aborts).
    /// Boxed: the JIT keeps a raw pointer to it, so the struct must not
    /// move after `reset` hands it over.
    monitor_exclusivo: Box<ExclusiveMonitor>,
    /// Multi-PC trap table, shared with the JIT state (like `memoria`):
    /// arming survives `reset`. Entry: address, Thumb patch, original
    /// word, hook.
    armadilhas_mem: Rc<
        RefCell<Vec<(u32, bool, u32, Box<dyn FnMut(&mut GuestMemory, &mut [u32; 16])>)>>,
    >,
    /// IRQ line source, parked: the JIT never takes interrupts on its own,
    /// so delivery always happens on the interpretador side. Stored for a
    /// future delivery path; set alongside the interpretador's hook.
    fonte_irq: Option<Box<dyn FnMut(&GuestMemory, bool) -> bool>>,
    /// Sparse pc history for halt traces (run entries + trap arrivals).
    /// The interpretador logs every instruction; here that would cost the
    /// JIT advantage, so this names stalls instead of replaying them.
    historico: Vec<u32>,
    /// **The page table: memory access without a callback.** Without it, every read and write
    /// from recompiled code would leave the JIT for a Rust callback, take the map via `RefCell` and
    /// look up the region. In Need for Speed, while racing, that left the emulator at 176 million
    /// instructions per second — 69% of console speed.
    ///
    /// Each entry points to the start of the page in the writable regions' memory, which does not
    /// move after `reset`. Null pages stay on the callbacks: the read-only regions, pages already
    /// executed (writing them invalidates code), pages with a write watch (surfaces and buffers
    /// the emulator needs to see dirty) and the last page of a region that does not fill it.
    tabela: Box<[*mut u8]>,
    /// Host-side PC trap mirroring `Interpretador::armadilha_pc`: the guest PC
    /// that reports `(r0, r1)` to `gancho_pc` on every arrival, then runs the
    /// real instruction. Kept on the backend (not in `Estado`) so `reset`,
    /// which rebuilds the JIT and its state, can reinstall it: the trap is
    /// host instrumentation, not guest state.
    armadilha_pc: Option<u32>,
    gancho_pc: Option<Box<dyn FnMut(u32, u32)>>,
}

impl DynarmicCpu {
    pub fn new() -> Result<Self, CpuError> {
        Self::with_shared_mem(Rc::new(RefCell::new(GuestMemory::new())))
    }

    /// Same as `new`, but the guest map is shared with a sibling backend
    /// (see `DualBackend`): both backends read and write the same bytes.
    /// `reset` replaces the map *contents* without swapping the `Rc`,
    /// keeping every clone (including the C++ trap table's view) valid.
    pub fn with_shared_mem(memoria: Rc<RefCell<GuestMemory>>) -> Result<Self, CpuError> {
        Ok(Self {
            memoria,
            semihosting: Default::default(),
            jit: None,
            p15: None,
            monitor_exclusivo: Box::new(ExclusiveMonitor::new(1)),
            armadilhas_mem: Default::default(),
            fonte_irq: None,
            historico: Vec::new(),
            tabela: vec![std::ptr::null_mut(); PAGINAS].into_boxed_slice(),
            armadilha_pc: None,
            gancho_pc: None,
        })
    }

    /// Whether the current mode is USR (the only mode this backend runs).
    pub fn em_usuario(&self) -> bool {
        self.cpsr() & 0x1F == MODO_USUARIO
    }

    /// CP15 read (flat model, mirrors the interpretador's `le_cp15`).
    pub fn le_cp15(&self, chave: u32) -> Option<u32> {
        self.p15.as_ref().and_then(|p| {
            p.cp15
                .iter()
                .find(|(k, _)| *k == chave)
                .map(|(_, v)| *v)
        })
    }

    /// Whole CP15 store (dual-backend sync).
    pub fn cp15_vec(&self) -> Vec<(u32, u32)> {
        self.p15
            .as_ref()
            .map(|p| p.cp15.clone())
            .unwrap_or_default()
    }

    /// Replace the CP15 store wholesale (dual-backend sync counterpart).
    pub fn carrega_cp15(&mut self, v: Vec<(u32, u32)>) {
        if let Some(p) = self.p15.as_mut() {
            p.cp15 = v;
        }
    }

    /// Clear a stale LDREX reservation (dual-backend switch).
    pub fn limpa_exclusivo(&mut self) {
        self.monitor_exclusivo.clear();
    }

    /// Install the IRQ line source (parked: delivery always runs on the
    /// interpretador side; stored here for a future delivery path).
    pub fn set_fonte_irq(&mut self, fonte: impl FnMut(&GuestMemory, bool) -> bool + 'static) {
        self.fonte_irq = Some(Box::new(fonte));
    }

    /// PCs of recently executed code, oldest first (sparse: run entries
    /// and trap arrivals — see the `historico` field).
    pub fn historico(&self) -> Vec<u32> {
        self.historico.clone()
    }

    fn anota_pc(&mut self, pc: u32) {
        self.historico.push(pc);
        if self.historico.len() > 2048 {
            self.historico.remove(0);
        }
    }

    /// Publish `[base, base+len)` to the fast table and drop translated
    /// blocks covering it. Call after mapping new pages into shared
    /// memory outside `reset`/`map_zeroed`.
    pub fn atualiza_tabela(&mut self, base: u32, len: u32) {
        if len == 0 {
            return;
        }
        let fim = base.saturating_add(len as u32);
        {
            let memoria = self.memoria.borrow();
            for pagina in (base / PAGE)..=(fim.saturating_sub(1) / PAGE) {
                self.tabela[pagina as usize] = ponteiro_da_pagina(&memoria, pagina);
            }
        }
        self.invalida(base, len);
    }

    /// Rebuild the whole fast table and drop all translated blocks.
    /// Needed after carving (survivor buffers move, invalidating every
    /// stale host pointer), so it must not be skipped.
    pub fn reconstroi_tabela(&mut self) {
        {
            let memoria = self.memoria.borrow();
            for pagina in 0..PAGINAS as u32 {
                self.tabela[pagina as usize] = ponteiro_da_pagina(&memoria, pagina);
            }
        }
        self.invalida(0, 0xFFFF_FFFF);
    }

    /// Drop translated blocks covering `[addr, addr+len)`.
    pub fn invalida(&mut self, addr: u32, len: u32) {
        if let Ok(jit) = self.jit_mut() {
            let inicio = addr & !(PAGE - 1);
            let fim = addr.saturating_add(len);
            jit.invalidate_cache_range(inicio, fim.saturating_sub(inicio) as usize);
        }
    }

    /// Puts back into the table the pages in `[inicio, fim)` nothing else needs to intercept.
    fn restaura_paginas(&mut self, inicio: u32, fim: u32) {
        let Some(jit) = self.jit.as_deref() else {
            return;
        };
        let vigias = jit.vigias.borrow();
        let memoria = self.memoria.borrow();
        for pagina in (inicio / PAGE)..=(fim.saturating_sub(1) / PAGE) {
            let (de, ate) = (pagina * PAGE, (pagina * PAGE).saturating_add(PAGE));
            let vigiada = vigias.iter().any(|v| de < v.2 && ate > v.1);
            if vigiada || jit.paginas_executadas.contem(pagina) {
                continue;
            }
            self.tabela[pagina as usize] = ponteiro_da_pagina(&memoria, pagina);
        }
    }

    fn jit(&self) -> Result<&Jit<Estado>, CpuError> {
        self.jit
            .as_deref()
            .ok_or_else(|| CpuError("Dynarmic não recebeu mapa de memória".into()))
    }

    fn jit_mut(&mut self) -> Result<&mut Jit<Estado>, CpuError> {
        self.jit
            .as_deref_mut()
            .ok_or_else(|| CpuError("Dynarmic não recebeu mapa de memória".into()))
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

    /// The diagnostics interface calls this method on both cores.
    pub fn semihosting(&self) -> String {
        self.semihosting.borrow().clone()
    }

    /// The host API also writes guest memory, always between two JIT entries. If it
    /// changes a page already executed, the next block must be recompiled.
    fn invalida_codigo_escrito(&mut self, addr: u32, len: u32) {
        let Ok(jit) = self.jit_mut() else {
            return;
        };
        jit.marca_codigo_sujo(addr, len);
        let paginas = std::mem::take(&mut *jit.codigo_sujo.borrow_mut());
        // **How many code pages fell to host writes.** It is the number answering whether
        // read/write on an already-executed page is a rare event (nothing to do) or a hot path
        // (candidate for direct read with a write trap). Without it, the SMC cost is
        // invisible in the profile: it shows up diluted in dispatch, as "some API call".
        if !paginas.is_empty() {
            crate::registro!(
                crate::registro::Nivel::Depuracao,
                "cpu",
                "write to {addr:#010x}+{len} invalidated {} code page(s)",
                paginas.len()
            );
        }
        for pagina in paginas {
            jit.invalidate_cache_range(pagina * PAGE, PAGE as usize);
        }
    }

    /// Close the sampled JIT-time measurement opened in `run`. One call per
    /// `run`, however many inner slices a trap needed: the sample still
    /// covers only time inside `jit.run`, never the hook or the dispatcher.
    fn finaliza_medicao(&mut self, cronometrar: bool, comeco: Option<std::time::Instant>) {
        if !cronometrar {
            return;
        }
        if let (Some(comeco), Ok(jit)) = (comeco, self.jit_mut()) {
            jit.nanos_no_jit.set(
                jit.nanos_no_jit
                    .get()
                    .saturating_add(comeco.elapsed().as_nanos() as u64),
            );
            jit.amostras_no_jit
                .set(jit.amostras_no_jit.get().saturating_add(1));
        }
    }

    /// Arm a PC trap: `gancho(r0, r1)` runs on every guest arrival at `addr`,
    /// before the instruction there executes, and execution then continues
    /// into the real code. For the SPL serial path `addr` is
    /// `PUTC_ADDR_POS_MMU` (`msm7201a_serial`) and the hook feeds a
    /// `SerialTap`; the guest ring-buffer write still runs, so guest behavior
    /// never changes. Survives `reset`: the address and hook stay on the
    /// backend while only the JIT state is rebuilt.
    ///
    /// Firing semantics (chosen mechanism: fault-and-resume, because
    /// `memory_read_code` fires per translation, not per execution — a pure
    /// fetch hook would go silent once the block is cached):
    ///
    /// * One report per arrival. The trapped fetch faults (`NoExecuteFault`),
    ///   the hook runs, a one-instruction pass executes the real bytes, and
    ///   the trap page is invalidated so the next arrival re-fetches and
    ///   faults again. A `b .` spin loop reports once per lap, like the
    ///   interpretador backend.
    /// * `(r0, r1)` are sampled with nothing of the arrival executed yet.
    ///   Exact when arrival is via branch — a fresh block starts at the trap,
    ///   which is the SPL `BL putc` case. A fall-through arrival lands
    ///   mid-block: faulting there would discard the whole block and skip
    ///   its prefix on resume, so the fetch is served with real bytes and
    ///   the arrival is missed instead (guest integrity wins over reporting;
    ///   the block stays cached, so later fall-through arrivals miss too
    ///   until something else invalidates the page). `putc` is a call
    ///   target, so the approximate case does not occur there.
    /// * Cost per arrival is one halt round-trip plus retranslation of the
    ///   trapped page. Negligible for serial output; do not trap a hot loop
    ///   in a benchmark.
    ///
    /// Bit 0 is an ARM/Thumb mode flag, not part of the address, and is
    /// masked off so a caller passing a Thumb-style `lr` value still traps.
    pub fn trap_pc(&mut self, addr: u32, gancho: impl FnMut(u32, u32) + 'static) {
        let addr = addr & !1;
        self.armadilha_pc = Some(addr);
        self.gancho_pc = Some(Box::new(gancho));
        if let Ok(jit) = self.jit_mut() {
            jit.armadilha.set(Some(addr));
            jit.passagem.set(false);
        }
    }

    /// Remove the PC trap, if any.
    pub fn untrap_pc(&mut self) {
        self.armadilha_pc = None;
        self.gancho_pc = None;
        if let Ok(jit) = self.jit_mut() {
            jit.armadilha.set(None);
            jit.passagem.set(false);
        }
    }

    /// Arms a serving hook at `addr`: on arrival the hook runs with guest
    /// memory and registers, then the real instruction steps. Same contract
    /// as the interpretador's, so harness code ports unchanged — including
    /// replace semantics (re-arming swaps the hook) and Thumb transparency
    /// (nothing executes in place; see `trap_pc_mem_thumb` for 16-bit sites).
    /// Implemented as a debugger-style SVC patch, so only the trapped
    /// instruction faults: the rest of the page keeps full JIT speed.
    pub fn trap_pc_mem(
        &mut self,
        addr: u32,
        gancho: impl FnMut(&mut GuestMemory, &mut [u32; 16]) + 'static,
    ) {
        self.arma(addr, false, Box::new(gancho));
    }

    /// Same as [`DynarmicCpu::trap_pc_mem`] for 16-bit Thumb code (the
    /// patch is one halfword; the run-loop path is shared). The harness
    /// picks per site — it disassembled the target and knows the mode.
    pub fn trap_pc_mem_thumb(
        &mut self,
        addr: u32,
        gancho: impl FnMut(&mut GuestMemory, &mut [u32; 16]) + 'static,
    ) {
        self.arma(addr, true, Box::new(gancho));
    }

    fn arma(
        &mut self,
        addr: u32,
        thumb: bool,
        gancho: Box<dyn FnMut(&mut GuestMemory, &mut [u32; 16])>,
    ) {
        let (svc, larg) = if thumb {
            (SVC_ARMADILHA_THUMB_INSTR, 2)
        } else {
            (SVC_ARMADILHA_INSTR, 4)
        };
        // Read the original word first: patching an unmapped address
        // would fault it in as real code, and a trap that can never fire
        // is a silent harness bug — log loudly instead of recording it.
        // On replace, keep the stored original: the bytes in memory are
        // already the patch, and re-reading them would make the restore
        // write the trap back over the real instruction.
        let mut original = [0u8; 4];
        let legivel = self
            .memoria
            .borrow()
            .read(addr, larg)
            .map(|b| original[..larg as usize].copy_from_slice(b))
            .is_ok();
        {
            let mut tab = self.armadilhas_mem.borrow_mut();
            if let Some(slot) = tab.iter_mut().find(|(a, _, _, _)| *a == addr) {
                slot.1 = thumb;
                slot.3 = gancho;
            } else {
                let pos = tab.partition_point(|(a, _, _, _)| *a < addr);
                tab.insert(pos, (addr, thumb, u32::from_le_bytes(original), gancho));
            }
        }
        if !legivel {
            eprintln!("dynarmic: trap armado em endereço ilegível {addr:#x}");
            return;
        }
        if self
            .memoria
            .borrow_mut()
            .write(addr, &svc.to_le_bytes()[..larg as usize])
            .is_err()
        {
            eprintln!("dynarmic: trap não gravou em {addr:#x}");
            return;
        }
        if let Ok(jit) = self.jit_mut() {
            jit.invalidate_cache_range(addr & !(PAGE - 1), PAGE as usize);
        }
    }

    /// Removes the hook at `addr`, if any, restoring the original bytes.
    pub fn untrap_pc_mem(&mut self, addr: u32) {
        let alvo: u32 = addr;
        let achado = {
            let mut tab = self.armadilhas_mem.borrow_mut();
            tab.iter()
                .position(|(a, _, _, _)| *a == alvo)
                .map(|i| tab.remove(i))
        };
        if let Some((_, thumb, original, _)) = achado {
            let larg = if thumb { 2 } else { 4 };
            let _ = self.memoria.borrow_mut().write(
                alvo,
                &original.to_le_bytes()[..larg as usize],
            );
            if let Ok(jit) = self.jit_mut() {
                jit.invalidate_cache_range(alvo & !(PAGE - 1), PAGE as usize);
            }
        }
    }

    /// Run the trapped instruction for real after the hook has fired.
    ///
    /// Grants one fetch of the trapped address (`passagem`), executes it via
    /// the single-step entry, then drops the translated blocks for the trap
    /// page: the next arrival re-fetches and faults again, which is what
    /// keeps the trap per-execution instead of per-translation.
    /// Returns the stop the step ended in, if it was not a plain step.
    fn passo_sobre_armadilha(
        &mut self,
        armadilha: u32,
        compensar_falha: bool,
    ) -> Result<Option<StopReason>, CpuError> {
        {
            let jit = self.jit_mut()?;
            // Restart at the trap: a fetch fault leaves the resume PC past
            // the fault (measured: without this the step translated from
            // trap+4), while nothing of the faulted block executed — so this
            // neither repeats nor skips guest code.
            jit.set_pc(armadilha);
            jit.passagem.set(true);
            // Drop the fault's raise-block first. A failed fetch still
            // compiles — a block that writes fault+4 to the PC and raises —
            // and re-running against that cached block would re-raise without
            // fetching, skipping the real instruction. Applied when `step`
            // enters; only `UserDefined1` is cleared here, never the
            // `CacheInvalidation` bit that carries the range.
            jit.invalidate_cache_range(armadilha & !(PAGE - 1), PAGE as usize);
            jit.clear_halt(HaltReason::UserDefined1);
            jit.parada.set(Parada::Nenhuma);
            // Single step, not a tick-budgeted `run`: the step compiles the
            // one instruction unlinked and always returns to the dispatcher,
            // so even a self-loop trap target stops after one lap. The
            // return path still reports the tick via `add_ticks`, keeping the
            // outer budget exact.
            let _ = jit.step();
            jit.clear_halt(HaltReason::Step);
            // Take back the fault's tick, but only when the raise-block ran.
            // Whether it ran is told by `compensar_falha`, read from the PC
            // the outer run left behind: a fault translated at `Run` entry
            // trips the halt pre-check, so the fresh block is skipped and the
            // PC stays on the trap; a fault translated mid-run through the
            // dispatcher slow path executes the one-fetch raise-block
            // (`CycleCount == 1`), advancing the PC past the trap and
            // reporting one tick via `add_ticks` — but no guest instruction
            // ran there. Without this, each executed fault would cost two
            // ticks (one phantom, one for the step) instead of one, and the
            // budget math would drift from the interpretador's
            // per-instruction count.
            if compensar_falha {
                jit.instrucoes.set(jit.instrucoes.get().saturating_sub(1));
            }
            let paginas = std::mem::take(&mut *jit.codigo_sujo.borrow_mut());
            for pagina in paginas {
                jit.invalidate_cache_range(pagina * PAGE, PAGE as usize);
            }
        }
        let jit = self.jit_mut()?;
        // Drop the step's single-step block too: the next arrival must
        // translate (and fault) fresh, never reuse a cached pass-through.
        jit.invalidate_cache_range(armadilha & !(PAGE - 1), PAGE as usize);
        match jit.parada.get() {
            // A second `Armadilha` here would mean the pass was consumed
            // without the trapped instruction executing, but re-translation
            // is deterministic: the same fetch consumes the pass again on the
            // same bytes. Unreachable in practice; continuing lets the outer
            // loop re-report rather than lose the arrival. Same for a second
            // `ArmadilhaMem` (a hook stepping into another trapped fetch).
            Parada::Nenhuma | Parada::Armadilha(_) | Parada::ArmadilhaMem(_) => Ok(None),
            Parada::Fetch(destino) if destino == RETURN_MAGIC => Ok(Some(StopReason::Returned)),
            Parada::Fetch(destino)
                if (API_BASE..API_BASE.saturating_add(API_SIZE)).contains(&destino) =>
            {
                Ok(Some(StopReason::ApiCall { addr: destino }))
            }
            Parada::Fetch(destino) => Ok(Some(StopReason::MemoryFault {
                addr: destino,
                pc: destino,
            })),
            Parada::Memoria(destino) => Ok(Some(StopReason::MemoryFault {
                addr: destino,
                pc: jit.get_pc(),
            })),
            Parada::Excecao(pc) => Ok(Some(StopReason::Exception { pc })),
        }
    }
}

impl CpuBackend for DynarmicCpu {
    fn reset(&mut self, mem: &GuestMemory) -> Result<(), CpuError> {
        // Drop the old JIT first: it owns the C++ coprocessor object,
        // which is the only user of the old p15 context pointer.
        // Then the context itself, before a fresh one is made below.
        self.jit = None;
        self.p15 = None;
        // `GuestMemory` is deliberately built once before execution. Copying the map
        // into the memory the callbacks own keeps the backend contract: the Rust API and
        // ARM see the same bytes from here on.
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
        for regiao in copia.regions_mut() {
            regiao.bytes.reserve_exact(FOLGA_DA_REGIAO);
        }
        self.tabela.fill(std::ptr::null_mut());
        for pagina in 0..PAGINAS as u32 {
            self.tabela[pagina as usize] = ponteiro_da_pagina(&copia, pagina);
        }
        // How many of the guest's 32-bit pages have direct access and how many stayed on callbacks.
        // It is the first number to look at when discussing JIT memory cost: the difference
        // between the two columns is what goes through Rust on every read and write.
        let diretas = self
            .tabela
            .iter()
            .filter(|ponteiro| !ponteiro.is_null())
            .count();
        crate::registro!(
            crate::registro::Nivel::Depuracao,
            "cpu",
            "page table: {diretas} of {} with direct access ({} region(s))",
            PAGINAS,
            copia.regions().len()
        );
        *self.memoria.borrow_mut() = copia;
        self.semihosting.borrow_mut().clear();
        // Flat CP15 model for the Dream bring-up (mirrors the
        // interpretador's `arm_coproc` accept-and-store; the Main ID the
        // kernel's procinfo lookup needs is seeded here, as there).
        // Boxed for a stable address: the C++ shim calls back into it.
        let mut p15 = Box::new(P15Ctx {
            cp15: vec![(P15_MIDR, MIDR_ARM1136)],
            wfi: false,
            ttbr: 0,
            mem: self.memoria.clone(),
            jit: std::ptr::null_mut(),
            fault: false,
        });
        let p15_ptr = (&mut *p15) as *mut P15Ctx as *mut c_void;
        let estado = Estado {
            memoria: self.memoria.clone(),
            semihosting: self.semihosting.clone(),
            paginas_executadas: PaginasExecutadas::new(),
            codigo_sujo: Default::default(),
            vigias: Default::default(),
            envoltorio: Cell::new((0, 0)),
            atalho: Cell::new((0, 0)),
            instrucoes: Cell::new(0),
            limite: Cell::new(0),
            parada: Cell::new(Parada::Nenhuma),
            entradas_no_jit: Cell::new(0),
            nanos_no_jit: Cell::new(0),
            amostras_no_jit: Cell::new(0),
            // The trap is host instrumentation: a fresh JIT keeps watching the
            // same address with the backend's hook. Guest registers and memory
            // start over; the harness tap does not.
            armadilha: Cell::new(self.armadilha_pc),
            passagem: Cell::new(false),
            armadilhas_mem: self.armadilhas_mem.clone(),
            jit: Cell::new(std::ptr::null_mut()),
            tabela: self.tabela.as_mut_ptr(),
        };
        let mut config = Jit::<Estado>::new_config();
        config.arch_ver(ArchVersion::V6K);
        // 64 MiB fits on desktop. On Switch this block competes for heap with the game
        // and Mesa; 32 MiB still covers Double Dragon's translated code
        // when the title is opened holding R.
        config.code_cache_size(if cfg!(dreamyemu_switch) {
            32 * 1024 * 1024
        } else {
            64 * 1024 * 1024
        });
        // Entry = start of the page on the host, no absolute offset or attribute bits.
        config.page_table_mask(0);
        unsafe { config.page_table(self.tabela.as_mut_ptr().cast()) };
        config.global_monitor(&mut self.monitor_exclusivo);
        // Dream p15 coprocessor (vendored patch): without it any MCR/MRC
        // aborts the process inside the JIT. MCR/MRC route to `p15_access`
        // above; LDC/STC are silent NOPs; anything else halts cleanly.
        config.coprocessor(15, CxxSharedPtr::<Coprocessor>::p15(p15_ptr, p15_access, p15_unhandled));
        let mut jit = Box::new(config.init(estado));
        // Balance our handle: the JIT holds its own copy now.
        config.release_coprocessor(15);
        let ptr = &mut *jit as *mut Jit<Estado>;
        jit.jit.set(ptr);
        // The unhandled-coproc path halts through here.
        p15.jit = ptr;
        self.p15 = Some(p15);
        jit.set_cpsr(MODO_USUARIO);
        self.jit = Some(jit);
        Ok(())
    }

    fn read_reg(&self, reg: Reg) -> u32 {
        self.jit().map_or(0, |jit| jit.get_reg(Self::indice(reg)))
    }

    fn write_reg(&mut self, reg: Reg, value: u32) {
        if let Ok(jit) = self.jit_mut() {
            jit.set_reg(Self::indice(reg), value);
        }
    }

    fn instructions(&self) -> u64 {
        self.jit().map_or(0, |jit| jit.instrucoes.get())
    }

    fn relato_do_jit(&self) -> Option<(u64, u64, u64)> {
        self.jit().ok().map(|jit| {
            let entradas = jit.entradas_no_jit.get();
            let amostras = jit.amostras_no_jit.get();
            // The sampled average holds for all entries: none of them is special.
            let nanos = match amostras {
                0 => 0,
                n => jit.nanos_no_jit.get() / n * entradas,
            };
            (entradas, nanos, amostras)
        })
    }

    fn set_instructions(&mut self, valor: u64) {
        if let Ok(jit) = self.jit_mut() {
            jit.instrucoes.set(valor);
        }
    }

    fn cpsr(&self) -> u32 {
        self.jit().map_or(0, |jit| jit.get_cpsr())
    }

    fn set_cpsr(&mut self, valor: u32) {
        if let Ok(jit) = self.jit_mut() {
            jit.set_cpsr(valor);
        }
    }

    fn em_thumb(&self) -> bool {
        self.jit().is_ok_and(|jit| jit.get_cpsr() & CPSR_THUMB != 0)
    }

    /// The write watch: only **guest** writes trip the flag.
    ///
    /// Without it the default contract answers "always dirty", and every drawing call imported
    /// all whole surfaces. In Pac-Mania, 100 thousand `IIMAGE_Draw` added up to 22 seconds
    /// just reading buffers the game had never touched.
    fn watch_dirty(&mut self, id: u32, base: u32, len: u32) -> Result<(), CpuError> {
        self.unwatch_dirty(id);
        let jit = self.jit_mut()?;
        // Starts dirty: we have seen nothing of this range yet.
        jit.vigias
            .borrow_mut()
            .push((id, base, base.saturating_add(len), true));
        jit.recalcula_envoltorio();
        // Writes to a watched range must go through the callback that marks it dirty.
        let fim = base.saturating_add(len);
        for pagina in (base / PAGE)..=(fim.saturating_sub(1) / PAGE) {
            jit.anula_pagina(pagina);
        }
        Ok(())
    }

    fn unwatch_dirty(&mut self, id: u32) {
        let Ok(jit) = self.jit_mut() else {
            return;
        };
        let faixa = jit
            .vigias
            .borrow()
            .iter()
            .find(|vigia| vigia.0 == id)
            .map(|vigia| (vigia.1, vigia.2));
        jit.vigias.borrow_mut().retain(|vigia| vigia.0 != id);
        jit.recalcula_envoltorio();
        if let Some((inicio, fim)) = faixa {
            self.restaura_paginas(inicio, fim);
        }
    }

    fn take_dirty(&mut self, id: u32) -> bool {
        let Ok(jit) = self.jit_mut() else {
            return true;
        };
        // A range may become clean again here, so the shortcut stops holding.
        jit.atalho.set((0, 0));
        let mut vigias = jit.vigias.borrow_mut();
        match vigias.iter_mut().find(|vigia| vigia.0 == id) {
            Some(vigia) => std::mem::replace(&mut vigia.3, false),
            None => true,
        }
    }

    fn marca_sujo(&mut self, addr: u32, len: u32) {
        let Ok(jit) = self.jit_mut() else {
            return;
        };
        let fim = addr.saturating_add(len);
        for vigia in jit.vigias.borrow_mut().iter_mut() {
            if addr < vigia.2 && fim > vigia.1 {
                vigia.3 = true;
            }
        }
    }

    fn read_mem(&self, addr: u32, buf: &mut [u8]) -> Result<(), CpuError> {
        self.memoria
            .borrow()
            .read(addr, buf.len() as u32)
            .map(|bytes| buf.copy_from_slice(bytes))
            .map_err(|e| CpuError(e.to_string()))
    }

    fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<(), CpuError> {
        self.memoria
            .borrow_mut()
            .write(addr, data)
            .map_err(|e| CpuError(e.to_string()))?;
        self.invalida_codigo_escrito(addr, data.len() as u32);
        Ok(())
    }

    /// Demand-map zeroed RAM (the harness's fault arm), then publish it.
    /// Two things must happen together, or the guest refaults forever:
    /// the fast page table learns the new pages AND any translation
    /// cached from when the fetch failed is dropped — a stale
    /// no-execute verdict must not survive the mapping it faulted on.
    fn map_zeroed(&mut self, name: &'static str, base: u32, len: usize) -> Result<(), CpuError> {
        self.memoria
            .borrow_mut()
            .map_zeroed(name, base, len)
            .map_err(|e| CpuError(e.to_string()))?;
        if len == 0 {
            return Ok(());
        }
        let fim = base.saturating_add(len as u32);
        {
            let memoria = self.memoria.borrow();
            for pagina in (base / PAGE)..=(fim.saturating_sub(1) / PAGE) {
                self.tabela[pagina as usize] = ponteiro_da_pagina(&memoria, pagina);
            }
        }
        if let Ok(jit) = self.jit_mut() {
            let inicio = base & !(PAGE - 1);
            jit.invalidate_cache_range(inicio, (fim.saturating_sub(inicio)) as usize);
        }
        Ok(())
    }

    /// Carve [base, base+len) out of the map (bring-up use: a live mapping
    /// replacing stale bytes). Unpublish the pages so later accesses fault
    /// instead of reading shadows, and drop translations of the old bytes.
    fn desmapeia_intervalo(&mut self, base: u32, len: usize) -> Result<(), CpuError> {
        if len == 0 {
            return Ok(());
        }
        let fim = base.saturating_add(len as u32);
        self.memoria.borrow_mut().desmapeia_intervalo(base, len);
        for pagina in (base / PAGE)..=(fim.saturating_sub(1) / PAGE) {
            self.tabela[pagina as usize] = std::ptr::null_mut();
        }
        if let Ok(jit) = self.jit_mut() {
            let inicio = base & !(PAGE - 1);
            jit.invalidate_cache_range(inicio, (fim.saturating_sub(inicio)) as usize);
        }
        Ok(())
    }

    fn fill_mem(&mut self, addr: u32, valor: u8, len: u32) -> Result<(), CpuError> {
        self.memoria
            .borrow_mut()
            .fill(addr, valor, len)
            .map_err(|e| CpuError(e.to_string()))?;
        self.invalida_codigo_escrito(addr, len);
        Ok(())
    }

    fn suja_pilha(&mut self, addr: u32, len: u32) -> Result<(), CpuError> {
        // No invalidation on purpose: stack never became code (see the trace). Marking
        // pays `jit_mut` and two borrows per API call only to always come out empty, and that
        // was what cost the 30% — measured in the Crash Nitro Kart `bench`, which goes from 296%
        // back to 368% without it alone.
        debug_assert!(
            self.jit_mut().is_ok_and(|jit| {
                let fim = addr.saturating_add(len.saturating_sub(1));
                ((addr / PAGE)..=(fim / PAGE)).all(|p| !jit.paginas_executadas.contem(p))
            }),
            "stack dirt at {addr:#010x}+{len} hit an executed page"
        );
        self.memoria
            .borrow_mut()
            .fill(addr, 0, len)
            .map_err(|e| CpuError(e.to_string()))
    }

    fn run(&mut self, pc: u32, max_instructions: u64) -> Result<StopReason, CpuError> {
        // Zero budget runs nothing, not even the trap check — same order as
        // the interpretador, which tests its limit before sampling the PC.
        if max_instructions == 0 {
            return Ok(StopReason::Budget);
        }
        self.anota_pc(pc & !1);
        // Setup reads and writes the JIT, but the trap hook below needs
        // `&mut self` too, so every JIT borrow stays short-lived: setup here,
        // one slice per loop turn, timing at the end.
        let (limite_externo, cronometrar, comeco) = {
            let jit = self.jit_mut()?;
            // **Bit 0 of the address is the mode, not part of the address.** The dispatcher resumes at the `lr`
            // as it came, and the `lr` of a call made from Thumb code carries bit 0
            // set — that is ARM's interworking convention. Here it must be explicit:
            // writing the raw address, Zenonia, which is all Thumb, came back from each API one byte
            // ahead and the core stopped on an "instruction" built from halves of two.
            let cpsr = jit.get_cpsr();
            match pc & 1 {
                1 => jit.set_cpsr(cpsr | CPSR_THUMB),
                _ => jit.set_cpsr(cpsr & !CPSR_THUMB),
            }
            jit.set_pc(pc & !1);
            // `HaltExecution` leaves the reason armed for the return that just exited. The next
            // stretch starts after the BREW dispatcher wrote r0/pc, so it must clear
            // the generic bit before entering the JIT again.
            jit.clear_halt(HaltReason::UserDefined1);
            jit.parada.set(Parada::Nenhuma);
            let limite = jit.instrucoes.get().saturating_add(max_instructions);
            jit.limite.set(limite);
            // The clock around `jit.run`, and only it: everything happening in here is guest
            // execution (plus the memory callbacks, which the JIT itself calls). What stays out is
            // dispatch — and that is where the trampoline lives.
            //
            // **Sampled on purpose, and always on.** This machine's `Instant::now` is a system
            // call, and one pair per entry cost 40% of the clock. One entry in every `AMOSTRA` measures
            // the same for 1/64 of the price — about 0.6% of the clock, measured — and so the share
            // goes out in every report instead of depending on someone remembering to turn it on. The
            // sampled average is multiplied by the counter afterwards.
            //
            // With a trap, one `run` call enters the JIT several times
            // (fault, resume step, continuation); the clock covers all of them,
            // and the entry counts once, as before.
            let entrada = jit.entradas_no_jit.get();
            let cronometrar = entrada % AMOSTRA_DO_JIT == 0;
            let comeco = cronometrar.then(std::time::Instant::now);
            jit.entradas_no_jit.set(entrada.saturating_add(1));
            (limite, cronometrar, comeco)
        };
        loop {
            {
                let jit = self.jit_mut()?;
                jit.clear_halt(HaltReason::UserDefined1);
                jit.parada.set(Parada::Nenhuma);
                let _ = unsafe { jit.run() };
                // No invalidation for data pages: only previously executed code gets here.
                // It is safe to touch the cache after the JIT returns control, never from the callback.
                let paginas = std::mem::take(&mut *jit.codigo_sujo.borrow_mut());
                for pagina in paginas {
                    jit.invalidate_cache_range(pagina * PAGE, PAGE as usize);
                }
            }
            // Unhandled CP15 encoding: the callback already halted the JIT.
            // Report it as an exception at the halting PC, like any other
            // core fault (the interpretador faults these encodings too).
            if self.p15.as_mut().is_some_and(|p| std::mem::replace(&mut p.fault, false)) {
                let pc = self.jit()?.get_pc();
                self.finaliza_medicao(cronometrar, comeco);
                return Ok(StopReason::Exception { pc });
            }
            match self.jit()?.parada.get() {
                Parada::Nenhuma => {
                    self.finaliza_medicao(cronometrar, comeco);
                    return Ok(StopReason::Budget);
                }
                Parada::ArmadilhaMem(destino) => {
                    self.anota_pc(destino);
                    // Serving trap: take the hook out (it may arm/disarm
                    // others), run it with guest memory and registers,
                    // restore the real bytes, step over them, then re-patch.
                    // The step runs the restored instruction via the normal
                    // resume path; re-patching plus invalidation makes the
                    // next arrival fault again.
                    let executou_falha = self.jit()?.get_pc() != destino;
                    let gancho = {
                        let mut tab = self.armadilhas_mem.borrow_mut();
                        tab.iter()
                            .position(|(a, _, _, _)| *a == destino)
                            .map(|i| tab.remove(i))
                    };
                    if let Some((_, thumb, original, mut gancho)) = gancho {
                        let mut regs = *self.jit()?.get_regs();
                        {
                            let mut mem = self.memoria.borrow_mut();
                            gancho(&mut *mem, &mut regs);
                        }
                        self.jit_mut()?.set_regs(regs);
                        let larg = if thumb { 2 } else { 4 };
                        let _ = self.memoria.borrow_mut().write(
                            destino,
                            &original.to_le_bytes()[..larg as usize],
                        );
                        let mut tab = self.armadilhas_mem.borrow_mut();
                        let pos = tab.partition_point(|(a, _, _, _)| *a < destino);
                        tab.insert(pos, (destino, thumb, original, gancho));
                    }
                    if let Some(parada) = self.passo_sobre_armadilha(destino, executou_falha)? {
                        self.finaliza_medicao(cronometrar, comeco);
                        return Ok(parada);
                    }
                    // Re-patch so the next arrival faults again (the step's
                    // resume path invalidated the restored block already).
                    let repoe = {
                        let tab = self.armadilhas_mem.borrow();
                        tab.iter().find(|(a, _, _, _)| *a == destino).map(
                            |(a, thumb, _, _)| {
                                (
                                    *a,
                                    if *thumb {
                                        SVC_ARMADILHA_THUMB_INSTR
                                    } else {
                                        SVC_ARMADILHA_INSTR
                                    },
                                    if *thumb { 2 } else { 4 },
                                )
                            },
                        )
                    };
                    if let Some((alvo, svc, larg)) = repoe {
                        let _ = self.memoria.borrow_mut().write(
                            alvo,
                            &svc.to_le_bytes()[..larg as usize],
                        );
                        if let Ok(jit) = self.jit_mut() {
                            jit.invalidate_cache_range(alvo & !(PAGE - 1), PAGE as usize);
                        }
                    }
                    // Same budget enforcement as the single-trap arm above.
                    if self.jit()?.instrucoes.get() >= limite_externo {
                        self.finaliza_medicao(cronometrar, comeco);
                        return Ok(StopReason::Budget);
                    }
                }
                Parada::Armadilha(destino) => {
                    // Observational trap: sample (r0, r1) with nothing
                    // executed since arrival, report, then run the real
                    // instruction. The guest never sees the fault. Whether
                    // the fault's raise-block executed is told by the PC it
                    // left behind: past the trap means one phantom tick to
                    // take back in the resume step.
                    let (r0, r1, executou_falha) = {
                        let jit = self.jit()?;
                        (jit.get_reg(0), jit.get_reg(1), jit.get_pc() != destino)
                    };
                    if let Some(gancho) = self.gancho_pc.as_mut() {
                        gancho(r0, r1);
                    }
                    if let Some(parada) = self.passo_sobre_armadilha(destino, executou_falha)? {
                        self.finaliza_medicao(cronometrar, comeco);
                        return Ok(parada);
                    }
                    // The fault preempts the tick check: every slice ends
                    // here while arrivals continue, so the budget never trips
                    // on its own. Enforce it in the loop, like the
                    // interpretador checks its limit before each instruction.
                    if self.jit()?.instrucoes.get() >= limite_externo {
                        self.finaliza_medicao(cronometrar, comeco);
                        return Ok(StopReason::Budget);
                    }
                }
                Parada::Fetch(addr) if addr == RETURN_MAGIC => {
                    self.finaliza_medicao(cronometrar, comeco);
                    return Ok(StopReason::Returned);
                }
                Parada::Fetch(addr)
                    if (API_BASE..API_BASE.saturating_add(API_SIZE)).contains(&addr) =>
                {
                    self.finaliza_medicao(cronometrar, comeco);
                    return Ok(StopReason::ApiCall { addr });
                }
                Parada::Fetch(addr) => {
                    self.finaliza_medicao(cronometrar, comeco);
                    return Ok(StopReason::MemoryFault { addr, pc: addr });
                }
                Parada::Memoria(addr) => {
                    let pc = self.jit()?.get_pc();
                    self.finaliza_medicao(cronometrar, comeco);
                    return Ok(StopReason::MemoryFault { addr, pc });
                }
                Parada::Excecao(pc) => {
                    self.finaliza_medicao(cronometrar, comeco);
                    return Ok(StopReason::Exception { pc });
                }
            }
        }
    }
}

/// The start of `pagina` in host memory, when it is writable and fits wholly inside one region.
fn ponteiro_da_pagina(memoria: &GuestMemory, pagina: u32) -> *mut u8 {
    let inicio = u64::from(pagina) * u64::from(PAGE);
    let fim = inicio + u64::from(PAGE);
    memoria
        .regions()
        .iter()
        .find(|r| {
            r.writable
                && inicio >= u64::from(r.base)
                && fim <= u64::from(r.base) + r.bytes.len() as u64
        })
        .map_or(std::ptr::null_mut(), |r| {
            // The region is not reallocated after `reset`: the vector is only written to, never grown.
            unsafe { r.bytes.as_ptr().add((inicio - u64::from(r.base)) as usize) as *mut u8 }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu_with(code: &[u8]) -> DynarmicCpu {
        let mut mem = GuestMemory::new();
        let mut bytes = code.to_vec();
        bytes.resize(0x1000, 0);
        // The Zeebo module image is writable: extensions may assemble small routines or
        // tables in RAM. Leaving the test code writable allows checking JIT invalidation.
        mem.map("code", 0, bytes, true).unwrap();
        mem.map_zeroed("data", 0x1000, 0x1000).unwrap();
        mem.map_zeroed("stack", 0x2000_0000, 0x1000).unwrap();
        let mut cpu = DynarmicCpu::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        cpu
    }

    #[test]
    fn executa_instrucao_e_le_registrador() {
        let code = [0xe3a0_0037u32.to_le_bytes(), 0xeaff_fffeu32.to_le_bytes()].concat();
        let mut cpu = cpu_with(&code); // mov r0, #0x37 ; b .
        assert_eq!(cpu.run(0, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x37);
    }

    #[test]
    fn armadilha_mem_dispara_e_continua() {
        // mov r0, #1 @0 ; mov r0, #2 @4 ; b . @8, trap at 0x4.
        let code = [
            0xe3a0_0001u32.to_le_bytes(),
            0xe3a0_0002u32.to_le_bytes(),
            0xeaff_fffeu32.to_le_bytes(),
        ]
        .concat();
        let mut cpu = cpu_with(&code);
        let visto = std::rc::Rc::new(std::cell::Cell::new(0xFFFF_FFFFu32));
        let copia = visto.clone();
        cpu.trap_pc_mem(0x4, move |_mem, regs| {
            copia.set(regs[0]);
        });
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Budget);
        // The hook saw r0 before the trapped instruction ran...
        assert_eq!(visto.get(), 1);
        // ...and the real instruction ran after it.
        assert_eq!(cpu.read_reg(Reg::R0), 2);
    }

    #[test]
    fn armadilha_mem_rearma_troca_o_gancho() {
        let code = [
            0xe3a0_0001u32.to_le_bytes(),
            0xe3a0_0002u32.to_le_bytes(),
            0xeaff_fffeu32.to_le_bytes(),
        ]
        .concat();
        let mut cpu = cpu_with(&code);
        let visto = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let copia = visto.clone();
        cpu.trap_pc_mem(0x4, move |_mem, _regs| {
            copia.set(1);
        });
        let copia = visto.clone();
        cpu.trap_pc_mem(0x4, move |_mem, _regs| {
            copia.set(2);
        });
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Budget);
        assert_eq!(visto.get(), 2);
        assert_eq!(cpu.read_reg(Reg::R0), 2);
    }

    #[test]
    fn desarma_mem_para_de_disparar() {
        let code = [
            0xe3a0_0001u32.to_le_bytes(),
            0xe3a0_0002u32.to_le_bytes(),
            0xeaff_fffeu32.to_le_bytes(),
        ]
        .concat();
        let mut cpu = cpu_with(&code);
        let visto = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let copia = visto.clone();
        cpu.trap_pc_mem(0x4, move |_mem, _regs| {
            copia.set(copia.get() + 1);
        });
        assert_eq!(cpu.run(0, 2).unwrap(), StopReason::Budget);
        assert_eq!(visto.get(), 1);
        cpu.untrap_pc_mem(0x4);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Budget);
        // Ran again without firing (the counter only moved once).
        assert_eq!(visto.get(), 1);
        assert_eq!(cpu.read_reg(Reg::R0), 2);
    }

    #[test]
    fn armadilha_thumb_dispara_e_continua() {
        // Thumb: `movs r0, #1 ; movs r0, #2 ; b .` at 0x100,
        // trap on the second instruction.
        let mut code = vec![0u8; 0x100];
        code.extend_from_slice(&[0x01, 0x20, 0x02, 0x20, 0xfe, 0xe7]);
        let mut cpu = cpu_with(&code);
        let visto = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let copia = visto.clone();
        cpu.trap_pc_mem_thumb(0x102, move |_mem, regs| {
            copia.set(regs[0]);
        });
        assert_eq!(cpu.run(0x101, 10).unwrap(), StopReason::Budget);
        // The hook saw r0 before the trapped instruction ran...
        assert_eq!(visto.get(), 1);
        // ...and the real instruction ran after it.
        assert_eq!(cpu.read_reg(Reg::R0), 2);
    }

    #[test]
    fn falta_demanda_executa_bytes_novos() {
        // Fetch from unmapped code faults; mapping it afterwards must run
        // the fresh bytes, not a stale no-execute verdict from the fault.
        let mut mem = GuestMemory::new();
        mem.map_zeroed("pilha", 0x2000_0000, 0x1000).unwrap();
        let mut cpu = DynarmicCpu::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        assert_eq!(
            cpu.run(0x10000, 10).unwrap(),
            StopReason::MemoryFault {
                addr: 0x10000,
                pc: 0x10000
            }
        );
        // Thumb `movs r0, #42 ; b .`
        cpu.map_zeroed("codigo", 0x10000, 0x1000).unwrap();
        cpu.write_mem(0x10000, &[0x2a, 0x20, 0xfe, 0xe7]).unwrap();
        assert_eq!(cpu.run(0x10001, 100).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 42);
    }

    /// **One exclusive instruction must not take down the process.**
    ///
    /// Dynarmic's x64 emitter requires a `global_monitor` at translation time
    /// for LDREX/STREX; the wrapper left it null and the process aborted.
    /// The backend now installs one at `reset`, and this test guards it:
    /// `ldrex r0, [r1]` followed by `b .`, with r1 on mapped data.
    #[test]
    fn a_instrucao_exclusiva_nao_derruba_o_processo() {
        // `ldrex r0, [r1]` (0xE1910F9F) e `b .` (0xEAFFFFFE).
        let code = [0xe191_0f9fu32.to_le_bytes(), 0xeaff_fffeu32.to_le_bytes()].concat();
        let mut cpu = cpu_with(&code);
        // r1 points at data memory, so the read has a mapped address.
        cpu.write_reg(Reg::R1, 0x1000);
        assert_eq!(cpu.run(0, 2).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0, "a memória começa zerada");
    }

    #[test]
    fn salto_para_a_faixa_de_api_vira_chamada() {
        let code = [0xe3a0_020fu32.to_le_bytes(), 0xe12f_ff10u32.to_le_bytes()].concat();
        let mut cpu = cpu_with(&code);
        assert_eq!(
            cpu.run(0, 10).unwrap(),
            StopReason::ApiCall { addr: API_BASE }
        );
    }

    #[test]
    fn endereco_com_bit_zero_entra_em_thumb() {
        // In Thumb, `movs r0, #0x37` then `b .` — aligned at 0x100. Called with 0x101,
        // which is how the dispatcher resumes a Thumb caller.
        let mut code = vec![0u8; 0x100];
        code.extend_from_slice(&[0x37, 0x20, 0xfe, 0xe7]);
        let mut cpu = cpu_with(&code);
        assert_eq!(cpu.run(0x101, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x37);
    }

    #[test]
    fn endereco_par_volta_para_arm_depois_de_thumb() {
        // `mov r0, #0x37` in ARM at zero; at 0x100, any Thumb code.
        let mut code = [0xe3a0_0037u32.to_le_bytes(), 0xeaff_fffeu32.to_le_bytes()].concat();
        code.resize(0x100, 0);
        code.extend_from_slice(&[0x00, 0x20, 0xfe, 0xe7]);
        let mut cpu = cpu_with(&code);
        cpu.run(0x101, 1).unwrap();
        assert_eq!(cpu.run(0, 1).unwrap(), StopReason::Budget);
        assert_eq!(cpu.read_reg(Reg::R0), 0x37);
    }

    #[test]
    fn a_vigia_liga_com_escrita_do_guest_e_nao_com_a_do_host() {
        // `mov r1, #0x1000 ; str r0, [r1] ; b .`
        let code = [
            0xe3a0_1a01u32.to_le_bytes(),
            0xe581_0000u32.to_le_bytes(),
            0xeaff_fffeu32.to_le_bytes(),
        ]
        .concat();
        let mut cpu = cpu_with(&code);
        cpu.watch_dirty(7, 0x1000, 4).unwrap();
        assert!(cpu.take_dirty(7), "nasce sujo");
        assert!(!cpu.take_dirty(7), "e ler limpa");
        cpu.write_mem(0x1000, &[1, 2, 3, 4]).unwrap();
        assert!(!cpu.take_dirty(7), "escrita do host não conta");
        cpu.run(0, 2).unwrap();
        assert!(cpu.take_dirty(7), "escrita do guest conta");
        // A disarmed range returns to the default contract: when in doubt, dirty.
        cpu.unwatch_dirty(7);
        assert!(cpu.take_dirty(7));
    }

    #[test]
    fn retorno_para_o_sentinela_e_reconhecido() {
        let mut cpu = cpu_with(&0xe12f_ff1eu32.to_le_bytes()); // bx lr
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
    }

    #[test]
    fn semihosting_escreve_sem_interromper_o_guest() {
        // mov r0,#SYS_WRITEC ; mov r1,#0x1000 ; svc #0xab ; bx lr
        let code = [0xe3a0_0003u32, 0xe3a0_1a01, 0xef00_00ab, 0xe12f_ff1e]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut cpu = cpu_with(&code);
        cpu.write_mem(0x1000, b"Z").unwrap();
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.semihosting(), "Z");
        assert_eq!(cpu.read_reg(Reg::R0), 0);
    }

    /// Semihosting in ARM state uses `SVC #0x123456`, and must not stop the game.
    #[test]
    fn semihosting_do_estado_arm_tambem_escreve() {
        // mov r0,#SYS_WRITEC ; mov r1,#0x1000 ; svc #0x123456 ; bx lr
        let code = [0xe3a0_0003u32, 0xe3a0_1a01, 0xef12_3456, 0xe12f_ff1e]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut cpu = cpu_with(&code);
        cpu.write_mem(0x1000, b"C").unwrap();
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.semihosting(), "C");
    }

    #[test]
    fn codigo_alterado_pelo_host_e_recompilado() {
        let mut cpu = cpu_with(
            &[0xe3a0_0001u32.to_le_bytes(), 0xe12f_ff1eu32.to_le_bytes()].concat(),
        );
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 1);

        // It is the equivalent of a BREW API updating a module table/routine between two
        // calls. Without `invalidate_cache_range`, Dynarmic would reuse the `mov r0,#1`.
        cpu.write_mem(0, &0xe3a0_0002u32.to_le_bytes()).unwrap();
        cpu.write_reg(Reg::Lr, RETURN_MAGIC);
        assert_eq!(cpu.run(0, 10).unwrap(), StopReason::Returned);
        assert_eq!(cpu.read_reg(Reg::R0), 2);
    }

    #[test]
    fn armadilha_pc_observa_r0_r1_e_nao_muda_o_guest() {
        use std::cell::RefCell;
        use std::rc::Rc;
        // mov r0, #3; mov r1, #0x41; b 0x100; (at 0x100:) b .
        let mut code = [0xe3a0_0003u32, 0xe3a0_1041, 0xea00_003c]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        code.resize(0x100, 0);
        code.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        // `reset` rebuilds the JIT but keeps host instrumentation, so the map
        // is built here instead of reusing `cpu_with`: the trap is armed once
        // and must survive the `reset` below without re-arming.
        let mut mem = GuestMemory::new();
        let mut imagem = code.clone();
        imagem.resize(0x1000, 0);
        mem.map("code", 0, imagem, true).unwrap();
        mem.map_zeroed("data", 0x1000, 0x1000).unwrap();
        mem.map_zeroed("stack", 0x2000_0000, 0x1000).unwrap();
        let mut cpu = DynarmicCpu::new().unwrap();
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        let vistos = Rc::new(RefCell::new(Vec::new()));
        let copia = vistos.clone();
        cpu.trap_pc(0x100, move |r0, r1| copia.borrow_mut().push((r0, r1)));
        // 3 of preamble + 2 spins on the `b .`: the trap fires on the 2 spins.
        assert_eq!(cpu.run(0, 5).unwrap(), StopReason::Budget);
        assert_eq!(*vistos.borrow(), vec![(3, 0x41), (3, 0x41)]);
        // The guest walked the same way: registers intact, PC stays in the loop.
        assert_eq!(cpu.read_reg(Reg::R0), 3);
        assert_eq!(cpu.read_reg(Reg::R1), 0x41);
        assert_eq!(cpu.read_reg(Reg::Pc), 0x100);
        cpu.untrap_pc();
        cpu.run(0x100, 2).unwrap();
        assert_eq!(vistos.borrow().len(), 2, "sem armadilha, sem registro");
        // The trap survives `reset`: without re-arming, the same spin records.
        cpu.trap_pc(0x100, {
            let copia = vistos.clone();
            move |r0, r1| copia.borrow_mut().push((r0, r1))
        });
        cpu.reset(&mem).unwrap();
        cpu.write_reg(Reg::Sp, 0x2000_0f00);
        assert_eq!(cpu.run(0, 5).unwrap(), StopReason::Budget);
        assert_eq!(
            *vistos.borrow(),
            vec![(3, 0x41), (3, 0x41), (3, 0x41), (3, 0x41)]
        );
    }
}
