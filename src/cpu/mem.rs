//! Guest memory.
//!
//! The map is built from named regions instead of a flat 4 GiB block: that way an access
//! outside the map becomes an identifiable error (and that is exactly what the vtable
//! trampoline will use to detect calls to BREW APIs).

// Removed once the core is wired into the main loop.
#![allow(dead_code)]

use std::cell::Cell;
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
    /// MRU of the last hit (base, end, index into `regions`): sequential
    /// fetch and stack hit the same region every time; O(1) in the common
    /// case. Stable index (see above); checking the base guards against
    /// any inconsistency.
    ultimo: Cell<Option<(u32, u32, usize)>>,
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
        let end = base as u64 + bytes.len() as u64;
        let collides = self.regions.iter().any(|r| {
            let r_end = r.base as u64 + r.bytes.len() as u64;
            (base as u64) < r_end && (r.base as u64) < end
        });
        if collides {
            return Err(MemError::Overlap { name, base });
        }
        // Push preserves insertion order (contract); the base-sorted
        // index goes into `ordem`. MRU invalidated for safety
        // (indices stay valid, but it is cheap).
        let idx = self.regions.len();
        let pos = self
            .ordem
            .partition_point(|&i| (self.regions[i].base as u64) < base as u64);
        self.ordem.insert(pos, idx);
        self.regions.push(Region {
            name,
            base,
            bytes,
            writable,
            executavel,
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

    /// Whether code may be fetched at `addr`.
    pub fn executavel(&self, addr: u32) -> bool {
        self.region_for(addr, 4).is_some_and(|r| r.executavel)
    }

    fn region_for(&self, addr: u32, len: u32) -> Option<&Region> {
        // MRU: the common case (sequential fetch, stack) hits first try.
        if let Some((base, fim, idx)) = self.ultimo.get() {
            if addr >= base && addr.checked_add(len).is_some_and(|a| a <= fim) {
                if let Some(r) = self.regions.get(idx) {
                    if r.base == base {
                        return Some(r);
                    }
                }
            }
        }
        // Binary search over the base-sorted index: the candidate is the
        // last region with base <= addr (no overlap, at most one
        // contains addr).
        let n = self
            .ordem
            .partition_point(|&i| self.regions[i].base <= addr);
        let &idx = self.ordem.get(n.wrapping_sub(1))?;
        let r = self.regions.get(idx)?;
        if !r.contains(addr, len) {
            return None;
        }
        let fim = r.base.wrapping_add(r.bytes.len() as u32);
        self.ultimo.set(Some((r.base, fim, idx)));
        Some(r)
    }

    /// For fetch (`busca`): the region covers `[addr, addr+len)` AND allows
    /// execution. Replaces the `regions().iter().any(...)` scan the
    /// interpreter used to do per instruction (same bottleneck as `region_for`).
    pub fn busca_permitida(&self, addr: u32, len: u32) -> bool {
        self.region_for(addr, len).is_some_and(|r| r.executavel)
    }

    fn region_for_mut(&mut self, addr: u32, len: u32) -> Option<&mut Region> {
        self.regions.iter_mut().find(|r| r.contains(addr, len))
    }

    pub fn read(&self, addr: u32, len: u32) -> Result<&[u8], MemError> {
        let region = self
            .region_for(addr, len)
            .ok_or(MemError::Unmapped { addr, len })?;
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
    fn le_e_escreve_dentro_das_regioes() {
        let mut m = mem();
        assert_eq!(m.read(0, 2).unwrap(), &[0xaa, 0xaa]);
        m.write_u32(0x1000_0010, 0xdead_beef).unwrap();
        assert_eq!(m.read_u32(0x1000_0010).unwrap(), 0xdead_beef);
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
