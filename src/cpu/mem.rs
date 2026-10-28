//! Guest memory.
//!
//! The map is built from named regions instead of a flat 4 GiB block: that way an access
//! outside the map becomes an identifiable error (and that is exactly what the vtable
//! trampoline will use to detect calls to BREW APIs).

// Removed once the core is wired into the main loop.
#![allow(dead_code)]

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;

/// One contiguous range of guest memory.
#[derive(Debug)]
pub struct Region {
    /// Name used in logs and error messages.
    pub name: &'static str,
    /// Start address in guest address space.
    pub base: u32,
    pub bytes: Vec<u8>,
    pub writable: bool,
    /// Whether the processor may fetch instructions here. Only the null page may not: reading
    /// from it is what the console tolerates, jumping to it is an error we want to see.
    pub executavel: bool,
    /// Owning address space (`None` = shared: kernel, devices, page
    /// cache, SPL image). User pages are per-mm: a fork/exec child
    /// that maps the same VA gets its own region instead of aliasing
    /// the parent's (proven live: servicemanager's BSS padzero at
    /// 0xA1FC zeroed init's shared text page and the fault surfaced
    /// 300k slices later as an impossible r3).
    pub dono_mm: Option<u32>,
    /// Physical page this region was mirrored from (guest PTE walk
    /// result at map time). A post-exec re-fault that walks to the
    /// SAME pa can adopt the bytes in place (argv still live there);
    /// a different pa means the mapping changed and the page is
    /// re-seeded from the new source instead.
    pub semente_pa: Option<u32>,
    /// Exec generation at map time. A user region is only visible
    /// while this matches the current generation: execve bumps it,
    /// turning stale same-VA hits into faults that re-resolve from
    /// the new page tables (shared regions ignore it).
    pub geracao: u32,
}

impl Region {
    fn contains(&self, addr: u32, len: u32) -> bool {
        let end = match self.base.checked_add(self.bytes.len() as u32) {
            Some(end) => end,
            None => return false,
        };
        addr >= self.base && addr.checked_add(len).is_some_and(|a| a <= end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemError {
    /// No region covers the requested address.
    Unmapped { addr: u32, len: u32 },
    /// The region exists but is read-only.
    ReadOnly { addr: u32, region: &'static str },
    /// Two regions overlap — a map setup error, not a guest error.
    Overlap { name: &'static str, base: u32 },
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmapped { addr, len } => {
                write!(f, "acesso a {addr:#010x} (+{len}) fora do mapa de memória")
            }
            Self::ReadOnly { addr, region } => {
                write!(
                    f,
                    "escrita em {addr:#010x}, região '{region}' é somente leitura"
                )
            }
            Self::Overlap { name, base } => {
                write!(
                    f,
                    "região '{name}' em {base:#010x} sobrepõe outra já mapeada"
                )
            }
        }
    }
}

impl std::error::Error for MemError {}

#[derive(Debug, Default)]
pub struct GuestMemory {
    /// Insertion order (public contract: `regions()[0]` is the module,
    /// saves serialize in this order, tests document it). Do NOT reorder.
    regions: Vec<Region>,
    /// Index into `regions`, sorted by `base`: the binary search uses
    /// this vector instead of scanning `regions`. Maintained in `map`
    /// (sorted insertion); indices into `regions` are stable
    /// (push only, never remove/reorder).
    ordem: Vec<usize>,
    /// MRU of the last hit (mm, base, end, index into `regions`):
    /// sequential fetch and stack hit the same region every time;
    /// O(1) in the common case. Stable index (see above); checking
    /// base AND mm guards against any inconsistency.
    ultimo: Cell<Option<(u32, u32, u32, u32, usize)>>,
    /// Current address space (masked TTBR0, set by the MCR hook):
    /// user lookups only see shared regions plus this mm's own.
    mm_atual: u32,
    /// Execve generation PER mm: bumped when a task starts exec, so
    /// per-(mm, base) livelock trackers can tell a post-exec
    /// re-fault (legitimate new image) from a tight abort loop.
    /// Per-mm (not global): a global bump orphaned every address
    /// space at once, so a fork child's copy_from_user re-fault
    /// found its parent's (stale-gen) regions invisible, seeded
    /// zeros from the bank, and execve failed ENOENT on a valid
    /// path (proven live: filename pages resolving alias=zeros).
    /// Only the exec'ing mm goes stale; the parent's pages stay
    /// resolvable as same-pa siblings.
    gen_por_mm: HashMap<u32, u32>,
    /// TEMP (write watchpoint for the zygote wild-pointer crash):
    /// when set, `interpretador::es_mem` logs every overlapping
    /// store with PC (cap 30). Armed by the harness on the
    /// string-headed slot; remove with CRASHOBJ.
    pub vigia: Option<(u32, u32)>,
}

impl GuestMemory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps a new region. Fails if it collides with an existing one.
    pub fn map(
        &mut self,
        name: &'static str,
        base: u32,
        bytes: Vec<u8>,
        writable: bool,
    ) -> Result<(), MemError> {
        self.map_com_execucao(name, base, bytes, writable, true)
    }

    /// Like [`GuestMemory::map`], also stating whether the region may be executed.
    pub fn map_com_execucao(
        &mut self,
        name: &'static str,
        base: u32,
        bytes: Vec<u8>,
        writable: bool,
        executavel: bool,
    ) -> Result<(), MemError> {
        self.mapeia(name, base, bytes, writable, executavel, None)
    }

    /// Maps a user region owned by the current mm: same VA in another
    /// address space gets its own region instead of aliasing this one.
    /// Overlap with a shared region or the same mm still fails; overlap
    /// with a *different* mm's region is the isolated case and is fine.
    pub fn map_usuario(
        &mut self,
        name: &'static str,
        base: u32,
        bytes: Vec<u8>,
        writable: bool,
    ) -> Result<(), MemError> {
        self.mapeia(name, base, bytes, writable, true, Some(self.mm_atual))
    }

    /// Zeroed user region owned by the current mm (demand-paged user
    /// page: text, stack, heap, linker mappings).
    pub fn map_usuario_zeroed(
        &mut self,
        name: &'static str,
        base: u32,
        len: usize,
    ) -> Result<(), MemError> {
        self.map_usuario(name, base, vec![0; len], true)
    }

    /// Records which physical page a user region was mirrored from
    /// (the guest PTE walk result). A post-exec re-fault that walks
    /// to the SAME pa adopts the bytes in place (argv still live);
    /// a different pa means the mapping changed and the page is
    /// re-seeded instead.
    pub fn anotar_semente(&mut self, base: u32, pa: u32) {
        let mm = self.mm_atual;
        if let Some(r) = self
            .regions
            .iter_mut()
            .find(|r| r.base == base && r.dono_mm == Some(mm))
        {
            r.semente_pa = Some(pa);
            self.ultimo.set(None);
        }
    }

    /// Finds a sibling mapping of the same VA in another mm that is
    /// current in ITS OWN mm and mirrors the same physical page
    /// (same underlying page = same content by construction:
    /// fork-COW shares, argv/filename pages surviving exec). The pa
    /// gate is load-bearing: different ET_EXEC binaries all load at
    /// 0x8000, so an ungated same-VA copy once planted installd's
    /// text in a foreign address space. The per-mm-current gate
    /// (instead of a global generation match) is what lets a fork
    /// child resolve parent pages across its own exec bump — the
    /// bump stales only the exec'ing mm, never the parent's.
    /// Returns owned bytes (the caller maps its own region after).
    pub fn irmao_mesma_va(&self, base: u32, pa: u32) -> Option<Vec<u8>> {
        let mm = self.mm_atual;
        self.regions.iter().find_map(|r| {
            if r.base == base
                && r.dono_mm.is_some_and(|d| d != mm)
                && r.semente_pa == Some(pa)
                && r.dono_mm.is_some_and(|d| r.geracao == self.gen_de(d))
            {
                Some(r.bytes.clone())
            } else {
                None
            }
        })
    }

    /// The current user region (if any) covering `base`, regardless
    /// of generation (for the adopt check: same pa means the bytes
    /// are still the mapping's contents).
    pub fn regiao_propria(&self, base: u32) -> Option<(Option<u32>, u32)> {
        let mm = self.mm_atual;
        self.regions.iter().find_map(|r| {
            if r.base == base && r.dono_mm == Some(mm) {
                Some((r.semente_pa, r.geracao))
            } else {
                None
            }
        })
    }

    /// Refreshes a same-pa region's generation in place (adopt: the
    /// bytes are already the mapping's contents, no carve or copy).
    pub fn adotar_geracao(&mut self, base: u32) {
        let mm = self.mm_atual;
        let ger = self.gen_de(mm);
        if let Some(r) = self
            .regions
            .iter_mut()
            .find(|r| r.base == base && r.dono_mm == Some(mm))
        {
            r.geracao = ger;
        }
        self.ultimo.set(None);
    }

    /// Whether a live user region exists for (mm, gen, base). The
    /// repeat-fault guard (`mapeadas_usr`) stops the run when the
    /// same page faults twice — but a VMA invalidation drop
    /// (munmap/MAP_FIXED) legitimately re-faults: with no live
    /// region the fault is fresh, not a repeat. TEMP with the
    /// invalidation hooks. Remove with CRASHOBJ.
    pub fn tem_mapeada(&self, mm: u32, ger: u32, base: u32) -> bool {
        self.regions
            .iter()
            .any(|r| r.base == base && r.dono_mm == Some(mm) && r.geracao == ger)
    }

    /// Switches the current address space (masked TTBR0 value, from the
    /// MCR hook). Lookups from now on see shared regions plus this mm's
    /// own user regions.
    pub fn trocar_mm(&mut self, mm: u32) {
        self.mm_atual = mm;
    }

    /// TEMP (snapshots): pares (mm, geração) para a `Foto`.
    /// Remove com o CRASHOBJ se os snapshots não vingarem.
    pub(crate) fn foto_gens(&self) -> Vec<(u32, u32)> {
        self.gen_por_mm.iter().map(|(m, g)| (*m, *g)).collect()
    }

    /// TEMP (snapshots): fotografa as regiões (par da `restaura`
    /// em lote). Remove com o CRASHOBJ se os snapshots não vingarem.
    pub(crate) fn foto_regioes(&self) -> Vec<crate::msm7201a_snapshot::RegiaoFoto> {
        self.regions
            .iter()
            .map(|r| crate::msm7201a_snapshot::RegiaoFoto {
                nome: r.name.to_string(),
                base: r.base,
                dados: r.bytes.clone(),
                gravavel: r.writable,
                executavel: r.executavel,
                dono_mm: r.dono_mm,
                geracao: r.geracao,
                semente_pa: r.semente_pa,
            })
            .collect()
    }

    /// TEMP (snapshots): restaura o mapa de gerações por mm (par da
    /// serialização em `msm7201a_snapshot`). Remove com o CRASHOBJ se
    /// os snapshots não vingarem.
    pub(crate) fn fixa_gens(&mut self, gens: Vec<(u32, u32)>) {
        self.gen_por_mm.clear();
        self.gen_por_mm.extend(gens);
        self.ultimo.set(None);
    }

    /// Current address space key (for per-(mm, base) livelock tracking
    /// in the harness: a re-fault under another mm is a legitimate
    /// first touch, not a stuck abort loop).
    pub fn mm_atual(&self) -> u32 {
        self.mm_atual
    }

    /// Current execve generation OF THIS mm (bumped at execve entry,
    /// so per-(mm, base) trackers tell a post-exec re-fault from a
    /// tight abort loop). Mms start at 0 on first switch.
    pub fn geracao(&self) -> u32 {
        self.gen_de(self.mm_atual)
    }

    // TEMP (GOT-clobber hunt): list every region covering `base`
    // (owner mm, seed pa, generation vs that mm's current) to name
    // why irmao_mesma_va missed. Remove with CRASHOBJ.
    pub fn debug_regioes(&self, base: u32) -> String {
        let mut s = String::new();
        for r in &self.regions {
            if base >= r.base && base < r.base.wrapping_add(r.bytes.len() as u32) {
                let gd = r.dono_mm.map(|d| self.gen_de(d));
                s.push_str(&format!(
                    "[mm={:?} pa={:?} ger={} genatual={:?} len={:#x}]",
                    r.dono_mm,
                    r.semente_pa,
                    r.geracao,
                    gd,
                    r.bytes.len()
                ));
            }
        }
        if s.is_empty() {
            s.push_str("(nenhuma)");
        }
        s.push_str(&format!(
            " mm_atual={:#x} ger_atual={}",
            self.mm_atual,
            self.geracao()
        ));
        s
    }

    /// Arm (or clear with `None`) the write watchpoint (see `vigia`).
    pub fn arma_vigia(&mut self, alvo: Option<(u32, u32)>) {
        self.vigia = alvo;
    }

    /// TEMP (snapshots): esvazia o mapa para reconstrução a partir
    /// de uma `Foto` (a ordem é refeita a cada região; o MRU cai por
    /// ser só desempenho). Remove com o CRASHOBJ se os snapshots
    /// não vingarem.
    pub(crate) fn limpa(&mut self) {        self.regions.clear();
        self.ordem.clear();
        self.ultimo.set(None);
        self.mm_atual = 0;
        self.gen_por_mm.clear();
        self.vigia = None;
    }

    /// TEMP (snapshots): reinsere uma região com todos os campos
    /// (`mapeia` não expõe geração/semente; nomes viram `'static`
    /// via vazamento único — ferramenta de depuração, não caminho
    /// quente). Remove com o CRASHOBJ se os snapshots não vingarem.
    pub(crate) fn restaura_regiao(&mut self, r: &crate::msm7201a_snapshot::RegiaoFoto) {
        let nome: &'static str = Box::leak(r.nome.clone().into_boxed_str());
        let idx = self.regions.len();
        let pos = self
            .ordem
            .partition_point(|&i| (self.regions[i].base as u64) < r.base as u64);
        self.ordem.insert(pos, idx);
        self.regions.push(Region {
            name: nome,
            base: r.base,
            bytes: r.dados.clone(),
            writable: r.gravavel,
            executavel: r.executavel,
            dono_mm: r.dono_mm,
            geracao: r.geracao,
            semente_pa: r.semente_pa,
        });
        self.ultimo.set(None);
    }

    fn gen_de(&self, mm: u32) -> u32 {
        self.gen_por_mm.get(&mm).copied().unwrap_or(0)
    }

    /// Bumps only the current mm's generation (call at execve entry,
    /// before the guest handler runs). ONLY the exec'ing address
    /// space goes stale: post-exec touches re-resolve from the new
    /// page tables, while the parent's (COW-shared argv/filename)
    /// pages stay resolvable as same-pa siblings. (Does NOT carve:
    /// the new image's argv/envp still live in the old user pages
    /// until the loader replaces them — carving here once starved
    /// an execve of its own arguments.)
    pub fn bump_geracao(&mut self) {
        let mm = self.mm_atual;
        let g = self.gen_de(mm).wrapping_add(1);
        self.gen_por_mm.insert(mm, g);
        // New mm generation: the MRU may point at a now-stale
        // region of this mm (region_for re-checks visibility, so
        // this is belt-and-braces, not load-bearing).
        self.ultimo.set(None);
    }

    fn mapeia(
        &mut self,
        name: &'static str,
        base: u32,
        bytes: Vec<u8>,
        writable: bool,
        executavel: bool,
        dono_mm: Option<u32>,
    ) -> Result<(), MemError> {
        let end = base as u64 + bytes.len() as u64;
        let bate = |r: &Region| {
            let r_end = r.base as u64 + r.bytes.len() as u64;
            (base as u64) < r_end && (r.base as u64) < end
        };
        // Same VA in another mm is isolation, not collision (each
        // address space gets its own region). Anything else that
        // overlaps is a genuine setup error, as before.
        let collides = self.regions.iter().any(|r| {
            bate(r)
                && match (r.dono_mm, dono_mm) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                }
        });
        if collides {
            return Err(MemError::Overlap { name, base });
        }
        // Push preserves insertion order (contract); the base-sorted
        // index goes into `ordem`. MRU invalidated for safety
        // (indices stay valid, but it is cheap).
        // TEMP (lifecycle audit): log region creation (cap 2000;
        // filter post-hoc). Remove with CRASHOBJ.
        {
            static mut NCR: u32 = 0;
            unsafe {
                if NCR < 2000 {
                    NCR += 1;
                    eprintln!("CRIAVA base={base:#x} len={} mm={:#x} geracao={} nome={name}", bytes.len(), self.mm_atual, self.gen_de(self.mm_atual));
                }
            }
        }
        // TEMP (mid-page region hunt): log any mapping whose base
        // or length isn't page-aligned — normal code maps whole
        // pages; a mid-page region shadows the binary search's
        // same-base runs. Uncapped (should be vanishingly rare).
        // Remove with CRASHOBJ.
        if (base & 0xFFF) != 0 || (bytes.len() & 0xFFF) != 0 {
            eprintln!("MIDPAGE f={} base={base:#x} len={:#x} mm={:#x} geracao={}", unsafe { crate::msm7201a::FATIA_ATUAL }, bytes.len(), self.mm_atual, self.gen_de(self.mm_atual));
        }
        let idx = self.regions.len();
        let pos = self
            .ordem
            .partition_point(|&i| (self.regions[i].base as u64) < base as u64);
        self.ordem.insert(pos, idx);
        let ger = self.gen_de(self.mm_atual);
        self.regions.push(Region {
            name,
            base,
            bytes,
            writable,
            executavel,
            dono_mm,
            geracao: ger,
            semente_pa: None,
        });
        self.ultimo.set(None);
        Ok(())
    }

    /// Maps a zeroed writable region — stack, heap, framebuffer.
    pub fn map_zeroed(
        &mut self,
        name: &'static str,
        base: u32,
        len: usize,
    ) -> Result<(), MemError> {
        self.map(name, base, vec![0; len], true)
    }

    /// Remove [base, base+len) from the map, splitting any overlapped
    /// region and keeping the survivors (content + flags). Used when a
    /// live mapping must replace stale bytes — e.g. a user page over
    /// the SPL image the kernel's buddy allocator recycled (the guest
    /// installed PTEs, so the new content wins). No-op when nothing
    /// overlaps; never fails.
    pub fn desmapeia_intervalo(&mut self, base: u32, len: usize) {
        if len == 0 {
            return;
        }
        // TEMP (carve audit): log unmaps covering live regions
        // (cap 2000; filter post-hoc). Remove with CRASHOBJ.
        {
            static mut NCRV: u32 = 0;
            unsafe {
                if NCRV < 2000 {
                    let fim = base.saturating_add(len as u32);
                    for r in self.regions.iter() {
                        let rf = r.base.wrapping_add(r.bytes.len() as u32);
                        if r.base < fim && base < rf {
                            NCRV += 1;
                            eprintln!("CARVEDET f={} base={base:#x} len={len:#x} mm={:#x} <- regiao base={:#x} len={:#x} mm={:?} ger={}", unsafe { crate::msm7201a::FATIA_ATUAL }, self.mm_atual, r.base, r.bytes.len(), r.dono_mm, r.geracao);
                            if NCRV >= 2000 {
                                break;
                            }
                        }
                    }
                }
            }
        }
        let fim = base.saturating_add(len as u32);
        if fim <= base {
            return;
        }
        // Carve covers shared regions plus the current mm's own:
        // sibling mms' same-VA pages are theirs (valid mappings),
        // never collateral.
        let mm = self.mm_atual;
        let mut novas: Vec<Region> = Vec::new();
        for r in self.regions.drain(..) {
            let r_fim = r.base.saturating_add(r.bytes.len() as u32);
            if r_fim <= base || r.base >= fim {
                novas.push(r);
                continue;
            }
            if r.dono_mm.is_some_and(|d| d != mm) {
                novas.push(r);
                continue;
            }
            if r.base < base {
                let n = (base - r.base) as usize;
                novas.push(Region {
                    name: r.name,
                    base: r.base,
                    bytes: r.bytes[..n].to_vec(),
                    writable: r.writable,
                    executavel: r.executavel,
                    dono_mm: r.dono_mm,
                    geracao: r.geracao,
                    semente_pa: r.semente_pa,
                });
            }
            if r_fim > fim {
                let ini = (fim - r.base) as usize;
                novas.push(Region {
                    name: r.name,
                    base: fim,
                    bytes: r.bytes[ini..].to_vec(),
                    writable: r.writable,
                    executavel: r.executavel,
                    dono_mm: r.dono_mm,
                    geracao: r.geracao,
                    semente_pa: r.semente_pa,
                });
            }
        }
        self.regions = novas;
        self.ordem.clear();
        let mut idx: Vec<usize> = (0..self.regions.len()).collect();
        idx.sort_by_key(|&i| self.regions[i].base);
        self.ordem = idx;
        self.ultimo.set(None);
    }

    /// Whether code may be fetched at `addr`.
    pub fn executavel(&self, addr: u32) -> bool {
        self.region_for(addr, 4).is_some_and(|r| r.executavel)
    }

    fn region_for(&self, addr: u32, len: u32) -> Option<&Region> {
        let mm = self.mm_atual;
        let ger = self.gen_de(mm);
        // MRU of the last hit (mm, gen, base, end, index): sequential
        // fetch and stack hit the same region every time; O(1) in the
        // common case. Stable index (see above); checking mm, gen and
        // base guards against any inconsistency (notably a post-exec
        // re-resolve, which must fault, not reuse).
        if let Some((mm_hit, ger_hit, base, fim, idx)) = self.ultimo.get() {
            if mm_hit == mm
                && ger_hit == ger
                && addr >= base
                && addr.checked_add(len).is_some_and(|a| a <= fim)
            {
                if let Some(r) = self.regions.get(idx) {
                    if r.base == base && Self::visivel(r, mm, ger) {
                        return Some(r);
                    }
                }
            }
        }
        // Binary search over the base-sorted index: the candidate is the
        // last region with base <= addr. The same VA may exist in
        // several mms (per-mm user pages): scan that same-base run for
        // the entry visible to this mm (own and current, else shared)
        // that contains the range. A smaller base can still contain
        // addr through a cross-mm overlap with a different base
        // (mid-page sub-regions exist) — the linear fallback below
        // covers that shadow case.
        let n = self
            .ordem
            .partition_point(|&i| self.regions[i].base <= addr);
        if n == 0 {
            return None;
        }
        let base_limite = self.regions[self.ordem[n - 1]].base;
        let mut k = n;
        while k > 0 {
            k -= 1;
            let idx = self.ordem[k];
            let r = &self.regions[idx];
            if r.base != base_limite {
                break;
            }
            if Self::visivel(r, mm, ger) && r.contains(addr, len) {
                let fim = r.base.wrapping_add(r.bytes.len() as u32);
                self.ultimo.set(Some((mm, ger, r.base, fim, idx)));
                return Some(r);
            }
        }
        // Slow path (miss or shadow): exact linear scan, mirroring
        // `region_for_mut`. A visible region can hide behind an
        // invisible later-base overlap (proven live: a mid-page
        // 0x4010876a region in another mm shadows zygote's heap
        // page 0x40108000 and kills mspace with a repeat fault).
        let achou = self
            .regions
            .iter()
            .position(|r| r.contains(addr, len) && Self::visivel(r, mm, ger));
        if achou.is_some() {
            static mut NSOMBRAL: u32 = 0;
            unsafe {
                if NSOMBRAL < 5 {
                    NSOMBRAL += 1;
                    eprintln!("SOMBRAL addr={addr:#x} (binary miss, linear hit)");
                }
            }
        }
        achou.and_then(|i| self.regions.get(i))
    }

    /// Visibility for the current lookup: shared regions are always
    /// visible; a per-mm region only to its owner *and* only while its
    /// exec generation is current (post-exec hits must fault and
    /// re-resolve from the new image instead).
    fn visivel(r: &Region, mm: u32, ger: u32) -> bool {
        match r.dono_mm {
            None => true,
            Some(d) => d == mm && r.geracao == ger,
        }
    }

    /// For fetch (`busca`): the region covers `[addr, addr+len)` AND allows
    /// execution. Replaces the `regions().iter().any(...)` scan the
    /// interpreter used to do per instruction (same bottleneck as `region_for`).
    pub fn busca_permitida(&self, addr: u32, len: u32) -> bool {
        self.region_for(addr, len).is_some_and(|r| r.executavel)
    }

    fn region_for_mut(&mut self, addr: u32, len: u32) -> Option<&mut Region> {
        // Same search as `region_for` (binary search over the
        // base-sorted index + same-base run for cross-mm pages),
        // which replaced the linear scan here: writes are ~1/3 of
        // guest instructions and the scan scaled with the map
        // (kernel demand-mapping grows it into the thousands —
        // measured 3x slice cost from 54 to 1093 regions). On a miss,
        // fall back to the exact linear scan: a visible region can
        // hide behind an invisible later-base overlap (legal
        // cross-mm with different bases; same-mm overlaps stay
        // rejected at map time). The fallback also counts: if it
        // ever fires, the shadow case is real, not theoretical.
        // Predicates are unchanged (`contains` + `visivel`).
        let mm = self.mm_atual;
        let ger = self.gen_de(mm);
        let n = self
            .ordem
            .partition_point(|&i| self.regions[i].base <= addr);
        if n > 0 {
            let base_limite = self.regions[self.ordem[n - 1]].base;
            let mut k = n;
            while k > 0 {
                k -= 1;
                let idx = self.ordem[k];
                let r = &self.regions[idx];
                if r.base != base_limite {
                    break;
                }
                if Self::visivel(r, mm, ger) && r.contains(addr, len) {
                    return self.regions.get_mut(idx);
                }
            }
        }
        // Slow path (miss or shadow): exact linear scan.
        let achou = self
            .regions
            .iter()
            .position(|r| r.contains(addr, len) && Self::visivel(r, mm, ger));
        if achou.is_some() {
            static mut NSOMBRA: u32 = 0;
            unsafe {
                if NSOMBRA < 5 {
                    NSOMBRA += 1;
                    eprintln!("SOMBRA addr={addr:#x} (binary miss, linear hit)");
                }
            }
        }
        achou.and_then(|i| self.regions.get_mut(i))
    }

    pub fn read(&self, addr: u32, len: u32) -> Result<&[u8], MemError> {
        let region = match self.region_for(addr, len) {
            Some(r) => r,
            None => {
                // TEMP (lookup forensics): the mspace fault hits a
                // live region per tem_mapeada yet faults — log map
                // state on miss to see why (gen mismatch? absent?).
                // Cap 5. Remove with CRASHOBJ.
                static mut NRF: u32 = 0;
                unsafe {
                    if NRF < 5 && (0x4010_8000..0x4011_0000).contains(&addr) {
                        NRF += 1;
                        let n = NRF;
                        let mm = self.mm_atual;
                        let ger = self.gen_de(mm);
                        let mut cobre = 0u32;
                        let mut visivel = 0u32;
                        for r in self.regions.iter() {
                            if r.base <= addr && addr + len as u32 <= r.base.wrapping_add(r.bytes.len() as u32) {
                                cobre += 1;
                                if Self::visivel(r, mm, ger) {
                                    visivel += 1;
                                }
                            }
                        }
                        eprintln!("READMISS#{n} addr={addr:#x} len={len} mm={mm:#x} ger={ger} nreg={} cobre={cobre} visivel={visivel}", self.regions.len());
                    }
                }
                return Err(MemError::Unmapped { addr, len });
            }
        };
        let start = (addr - region.base) as usize;
        Ok(&region.bytes[start..start + len as usize])
    }

    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemError> {
        let len = data.len() as u32;
        let region = self
            .region_for_mut(addr, len)
            .ok_or(MemError::Unmapped { addr, len })?;
        if !region.writable {
            return Err(MemError::ReadOnly {
                addr,
                region: region.name,
            });
        }
        let start = (addr - region.base) as usize;
        region.bytes[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Fills the regions directly, without creating an intermediate buffer.
    ///
    /// Validates the whole range before touching any bytes. That way a failure in the second
    /// region does not leave the first one modified without the caller invalidating the
    /// corresponding JIT cache.
    pub fn fill(&mut self, addr: u32, value: u8, len: u32) -> Result<(), MemError> {
        let inicio = u64::from(addr);
        let fim = inicio + u64::from(len);
        if fim > u64::from(u32::MAX) + 1 {
            return Err(MemError::Unmapped { addr, len });
        }

        let mut cursor = inicio;
        while cursor < fim {
            let onde = cursor as u32;
            let restante = fim - cursor;
            let region = self.region_for(onde, 1).ok_or(MemError::Unmapped {
                addr: onde,
                len: restante.min(u64::from(u32::MAX)) as u32,
            })?;
            if !region.writable {
                return Err(MemError::ReadOnly {
                    addr: onde,
                    region: region.name,
                });
            }
            let fim_da_regiao = u64::from(region.base) + region.bytes.len() as u64;
            cursor = fim.min(fim_da_regiao);
        }

        cursor = inicio;
        while cursor < fim {
            let onde = cursor as u32;
            let region = self.region_for_mut(onde, 1).expect("range already validated");
            let inicio_na_regiao = (onde - region.base) as usize;
            let passo = ((fim - cursor) as usize).min(region.bytes.len() - inicio_na_regiao);
            region.bytes[inicio_na_regiao..inicio_na_regiao + passo].fill(value);
            cursor += passo as u64;
        }
        Ok(())
    }

    pub fn read_u32(&self, addr: u32) -> Result<u32, MemError> {
        let b = self.read(addr, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn write_u32(&mut self, addr: u32, value: u32) -> Result<(), MemError> {
        self.write(addr, &value.to_le_bytes())
    }

    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Region count (perf audit: binary searches scale with it).
    pub fn num_regioes(&self) -> usize {
        self.regions.len()
    }

    pub fn regions_mut(&mut self) -> &mut [Region] {
        &mut self.regions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> GuestMemory {
        let mut m = GuestMemory::new();
        m.map("rom", 0x0000_0000, vec![0xaa; 0x100], false).unwrap();
        m.map_zeroed("ram", 0x1000_0000, 0x100).unwrap();
        m
    }

    #[test]
    fn desmapeia_intervalo_recorta_e_preserva_sobras() {
        // Carve [0x40..0x80) out of [0x0..0x100]: survivors keep
        // content + flags, middle is gone, order index rebuilt.
        let mut m = GuestMemory::new();
        m.map("alvo", 0x1000, vec![0xbb; 0x100], true).unwrap();
        m.desmapeia_intervalo(0x1040, 0x40);
        assert!(m.read(0x1040, 4).is_err());
        assert_eq!(m.read(0x1000, 4).unwrap(), &[0xbb; 4]);
        assert_eq!(m.read(0x10fc, 4).unwrap(), &[0xbb; 4]);
        // Fresh map over the carved hole works (no overlap error).
        m.map_zeroed("nova", 0x1040, 0x40).unwrap();
        assert_eq!(m.read(0x1040, 4).unwrap(), &[0; 4]);
        // Full-region carve removes it entirely.
        m.desmapeia_intervalo(0x1000, 0x100);
        assert!(m.read(0x1000, 4).is_err());
    }

    #[test]
    fn le_e_escreve_dentro_das_regioes() {
        let mut m = mem();
        assert_eq!(m.read(0, 2).unwrap(), &[0xaa, 0xaa]);
        m.write_u32(0x1000_0010, 0xdead_beef).unwrap();
        assert_eq!(m.read_u32(0x1000_0010).unwrap(), 0xdead_beef);
    }

    #[test]
    fn regioes_usuario_isolam_por_mm() {
        // Same VA in two address spaces: each mm sees its own bytes;
        // writes through one never leak into the other (the
        // servicemanager-padzero class: shared text zeroed by a
        // sibling's BSS init).
        let mut m = GuestMemory::new();
        m.trocar_mm(0x1000_0000);
        m.map_usuario("dados", 0x8000, vec![0x11; 0x1000], true).unwrap();
        m.trocar_mm(0x2000_0000);
        // Other mm's region does not shadow: fresh map allowed.
        m.map_usuario("dados", 0x8000, vec![0x22; 0x1000], true).unwrap();
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x22; 4]);
        m.trocar_mm(0x1000_0000);
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x11; 4]);
        // A write lands only in the current mm's region.
        let _ = m.write(0x8000, &[0x99; 4]);
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x99, 0x99, 0x99, 0x99]);
        m.trocar_mm(0x2000_0000);
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x22; 4]);
    }

    #[test]
    fn geracao_nova_invalida_regioes_antigas() {
        // Exec bump: same-VA user regions from before the exec stop
        // matching (reads fault and re-resolve from the new image
        // instead of reusing stale bytes); shared mappings are
        // untouched, and re-mapping under the new generation works.
        let mut m = GuestMemory::new();
        m.map("nucleo", 0xC000_0000, vec![0xcc; 0x1000], true).unwrap();
        m.trocar_mm(0x1000_0000);
        m.map_usuario("dados", 0x8000, vec![0x11; 0x100], true).unwrap();
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x11; 4]);
        assert_eq!(m.geracao(), 0);
        m.bump_geracao();
        assert_eq!(m.geracao(), 1);
        // Stale user region no longer matches (would re-fault and
        // re-resolve live instead of serving pre-exec bytes)...
        assert!(m.read(0x8000, 4).is_err());
        let _ = m.write(0x8000, &[0x99; 4]);
        assert!(m.read(0x8000, 4).is_err());
        // ...while shared kernel mappings are unaffected.
        assert_eq!(m.read(0xC000_0000, 4).unwrap(), &[0xcc; 4]);
        // Re-mapping under the new generation works normally (the
        // UFAULT path always carves before mirroring, like here).
        m.desmapeia_intervalo(0x8000, 0x100);
        m.map_usuario("dados2", 0x8000, vec![0x22; 0x100], true).unwrap();
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x22; 4]);
        let _ = m.write(0x8000, &[0x77; 4]);
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x77; 4]);
    }

    #[test]
    fn irmao_mesma_va_copia_conteudo_fork() {
        // Fork: the child's first touch of a COW-shared page copies
        // the parent's bytes (the pa bank never held them) instead of
        // seeding zeros from the alias. Same pa is required: an
        // ungated same-VA copy once mixed two ET_EXEC binaries that
        // share the 0x8000 load address.
        let mut m = GuestMemory::new();
        m.trocar_mm(0x1000_0000);
        m.map_usuario("dados", 0x8000, vec![0x11; 0x100], true).unwrap();
        m.anotar_semente(0x8000, 0x1600_0000);
        m.trocar_mm(0x2000_0000);
        // No region yet: invisible.
        assert!(m.read(0x8000, 4).is_err());
        // Sibling maps the same physical page: copy its bytes.
        let buf = m.irmao_mesma_va(0x8000, 0x1600_0000).expect("irmao");
        assert_eq!(&buf[..4], &[0x11; 4]);
        // Same VA but a different physical page (another binary's
        // text at the shared load address): no copy.
        assert!(m.irmao_mesma_va(0x8000, 0x1700_0000).is_none());
        // The child's own exec bump stales only the child's mm: the
        // parent's pages stay resolvable as same-pa siblings (this
        // is what lets copy_from_user see argv/filename across the
        // bump instead of seeding zeros -> ENOENT).
        m.bump_geracao();
        let buf2 = m.irmao_mesma_va(0x8000, 0x1600_0000).expect("irmao-pos-bump");
        assert_eq!(&buf2[..4], &[0x11; 4]);
        // ...but once the PARENT remaps (different pa under the same
        // VA), the sibling no longer mirrors this page: no copy.
        m.trocar_mm(0x1000_0000);
        m.bump_geracao();
        m.trocar_mm(0x2000_0000);
        assert!(m.irmao_mesma_va(0x8000, 0x1600_0000).is_none());
    }

    #[test]
    fn adocao_preserva_bytes_mesmo_pa() {
        // Adopt: same pa as the region already holds means the bytes
        // are still the mapping's contents (argv surviving the bump).
        let mut m = GuestMemory::new();
        m.map_usuario("dados", 0x8000, vec![0x22; 0x100], true).unwrap();
        m.anotar_semente(0x8000, 0x1234_5000);
        m.bump_geracao();
        // Stale generation: invisible until adopted.
        assert!(m.read(0x8000, 4).is_err());
        // Same pa: adopt keeps bytes, refreshes generation.
        assert_eq!(m.regiao_propria(0x8000), Some((Some(0x1234_5000), 0)));
        m.adotar_geracao(0x8000);
        assert_eq!(m.read(0x8000, 4).unwrap(), &[0x22; 4]);
        // Different pa: no adopt (caller carves and re-seeds).
        m.bump_geracao();
        assert!(m.read(0x8000, 4).is_err());
    }

    #[test]
    fn acesso_fora_do_mapa_falha() {
        let m = mem();
        assert_eq!(
            m.read(0x2000_0000, 4),
            Err(MemError::Unmapped {
                addr: 0x2000_0000,
                len: 4
            })
        );
    }

    #[test]
    fn acesso_que_cruza_o_fim_da_regiao_falha() {
        let m = mem();
        assert!(m.read(0xfe, 4).is_err());
    }

    #[test]
    fn escrita_em_regiao_somente_leitura_falha() {
        let mut m = mem();
        assert_eq!(
            m.write_u32(0, 1),
            Err(MemError::ReadOnly {
                addr: 0,
                region: "rom"
            })
        );
    }

    #[test]
    fn fill_preenche_ram_sem_buffer_intermediario() {
        let mut m = mem();
        m.fill(0x1000_0010, 0x5a, 0x20).unwrap();
        assert_eq!(m.read(0x1000_0010, 0x20).unwrap(), &[0x5a; 0x20]);
    }

    #[test]
    fn fill_respeita_regiao_somente_leitura() {
        let mut m = mem();
        assert_eq!(
            m.fill(0, 0, 4),
            Err(MemError::ReadOnly {
                addr: 0,
                region: "rom"
            })
        );
    }

    #[test]
    fn fill_que_falha_na_segunda_regiao_nao_altera_a_primeira() {
        let mut m = GuestMemory::new();
        m.map("w", 0x2000, vec![0xaa; 4], true).unwrap();
        m.map("ro", 0x2004, vec![0xbb; 4], false).unwrap();
        assert_eq!(
            m.fill(0x2002, 0, 4),
            Err(MemError::ReadOnly {
                addr: 0x2004,
                region: "ro"
            })
        );
        assert_eq!(m.read(0x2000, 4).unwrap(), &[0xaa; 4]);
    }
}

#[cfg(test)]
mod snapshot_diag_tests {
    // TEMP (diagnóstico de resume): replica a servidão do braço-usuário
    // para um fault conhecido (va=0x77000, pa=0x15070000, mm=0x16238000)
    // sobre o mapa restaurado do snap330, para nomear onde diverge.
    // Pula se o snapshot não estiver presente (mesmo espírito dos
    // testes que pulam sem o SPL). Remove com o CRASHOBJ.
    #[test]
    fn serve_falha_usuario_no_mapa_restaurado() {
        let caminho = "/tmp/opencode/snap330.bin";
        let bytes = match std::fs::read(caminho) {
            Ok(b) => b,
            Err(_) => return,
        };
        // Decodifica o mínimo (regiões + mm + gens) à mão para não
        // acoplar o teste ao formato inteiro.
        let foto = crate::msm7201a_snapshot::carrega(caminho).expect("snapshot válido");
        let mut mem = super::GuestMemory::new();
        mem.limpa();
        for r in &foto.regioes {
            mem.restaura_regiao(r);
        }
        mem.trocar_mm(foto.mm_atual);
        mem.fixa_gens(foto.gens.clone());
        // 1. região da VA de usuário cobre a falta?
        let cobre_va = mem.read(0x77000, 64).is_ok();
        // 2. alias de RAM cobre a semente?
        let alias_va = 0x1507_0000u32.wrapping_add(0xB000_0000);
        let cobre_alias = mem.read(alias_va, 64).is_ok();
        // 3. PA física coberta?
        let cobre_pa = mem.read(0x1507_0000, 64).is_ok();
        // 4. remapear o alias como o fallback faz?
        let remapeia = mem.map_zeroed("usuario_ptw", alias_va & !0xFFF, 0x1000);
        eprintln!("DIAG va={cobre_va} alias={cobre_alias} pa={cobre_pa} remap={remapeia:?}");
        assert!(cobre_va == false, "VA 0x77000 não deveria estar mapeada no save");
    }
}

#[cfg(test)]
mod snap_diag_tests {
    // TEMP (repeat-guard forensics): the resume stops on
    // MemoryFault at 0x4010Cxxx with no URES/UDECIDE. Check
    // whether the snapshot carries (mm,gen,base) guard entries
    // and/or live regions for those pages.
    #[test]
    fn lista_mapeadas_e_regioes_heap() {
        let foto = match crate::msm7201a_snapshot::carrega("/tmp/opencode/snap330.bin") {
            Ok(f) => f,
            Err(_) => return,
        };
        for (mm, g, b) in foto.mapeadas_usr.iter() {
            if (0x40108000..0x40110000).contains(b) {
                eprintln!("DIAGGUARD mm={mm:#x} gen={g} base={b:#x}");
            }
        }
        for r in foto.regioes.iter() {
            if r.base >= 0x40108000 && r.base < 0x40110000 && r.dono_mm == Some(foto.mm_atual) {
                let z = r.dados.iter().all(|&x| x == 0);
                eprintln!("DIAGREG base={:#x} len={:#x} ger={} zeros={z}", r.base, r.dados.len(), r.geracao);
            }
        }
        eprintln!("DIAGFIM mm_atual={:#x}", foto.mm_atual);
        for r in foto.regioes.iter() {
            if r.dono_mm == Some(foto.mm_atual) && r.base >= 0x41030000 && r.base < 0x41036000 {
                eprintln!("DIAGREG3 base={:#x} len={:#x} ger={} zeros={}", r.base, r.dados.len(), r.geracao, r.dados.iter().all(|&x| x==0));
            }
        }
        for v in [0x40108000u32, 0x4010C8E4] {
            let base = v & !0xFFF;
            let tem = foto.regioes.iter().any(|r| {
                r.base == base && r.dono_mm == Some(foto.mm_atual)
            });
            eprintln!("DIAGPARADA va={v:#x} regiao_viva={tem}");
        }
        for r in foto.regioes.iter() {
            let fim = r.base.wrapping_add(r.dados.len() as u32);
            if r.base <= 0x41032fec && 0x41032fec < fim {
                eprintln!("DIAGCOBRE2 base={:#x} len={:#x} mm={:?} ger={} gravavel={}", r.base, r.dados.len(), r.dono_mm, r.geracao, r.gravavel);
            }
        }
        for r in foto.regioes.iter() {
            let fim = r.base.wrapping_add(r.dados.len() as u32);
            if r.base <= 0x4010876c && 0x4010876c + 4 <= fim {
                eprintln!("DIAGCOBRE base={:#x} len={:#x} mm={:?} ger={} gravavel={} ex={:?}", r.base, r.dados.len(), r.dono_mm, r.geracao, r.gravavel, &r.nome[..r.nome.len().min(16)]);
            }
        }
    }
}

#[cfg(test)]
mod guest_bytes_diag_tests {
    // TEMP (comparação de bytes servidos): extrai do snap330 os bytes
    // que o guest vê em [0x40000F6B, +4872) — a entrada comprimida
    // do autotext.xml que o inflate rejeitou (Z_DATA_ERROR) — e
    // compara com os bytes do host (/tmp/opencode/hostcomp.bin).
    // Iguais = inflate falha por lógica/CPU; diferentes/zeros =
    // servidão entregou lixo. Pula sem o snapshot. Remove com CRASHOBJ.
    #[test]
    fn compara_entrada_comprimida() {
        let foto = match crate::msm7201a_snapshot::carrega("/tmp/opencode/snap330.bin") {
            Ok(f) => f,
            Err(_) => return,
        };
        let host = match std::fs::read("/tmp/opencode/hostcomp.bin") {
            Ok(h) => h,
            Err(_) => return,
        };
        let mm = foto.mm_atual;
        eprintln!("DIAGGENS mm={mm:#x} gens={:?}", foto.gens);
        let (va, need) = (0x4000_0F6Bu32, host.len());
        let mut guest = Vec::new();
        let mut regioes: Vec<_> = foto.regioes.iter()
            .filter(|r| r.dono_mm == Some(mm))
            .filter(|r| r.base < va + need as u32 && r.base + r.dados.len() as u32 > va)
            .collect();
        regioes.sort_by_key(|r| r.base);
        for r in &regioes {
            let lo = va.max(r.base);
            let hi = (va + need as u32).min(r.base + r.dados.len() as u32);
            if hi > lo {
                guest.extend_from_slice(&r.dados[(lo - r.base) as usize..(hi - r.base) as usize]);
            }
        }
        for r in &regioes {
            if (0x3F00_0000..0x4100_0000).contains(&r.base) {
                eprintln!("DIAGMAP base={:#x} len={:#x} ger={} wr={} head={:02x?}", r.base, r.dados.len(), r.geracao, r.gravavel, &r.dados[..r.dados.len().min(16)]);
            }
        }
        for r in regioes {
            if r.base < va + need as u32 && r.base + r.dados.len() as u32 > va {
                eprintln!("DIAGREG base={:#x} len={:#x} ger={} head={:02x?}", r.base, r.dados.len(), r.geracao, &r.dados[..r.dados.len().min(16)]);
            }
        }
        eprintln!("DIAGCOMP mm={mm:#x} bytes={} head={:02x?}", guest.len(), &guest[..guest.len().min(16)]);
        std::fs::write("/tmp/opencode/guestcomp.bin", &guest).ok();
        assert_eq!(guest.len(), need, "bytes cobertos diferem do esperado");
        assert_eq!(guest, host, "bytes servidos divergem do host");
    }
}
