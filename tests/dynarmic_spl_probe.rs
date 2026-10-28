//! TEMP probe: what stops Dynarmic on the Dream SPL (CP15 bring-up).
//! Delete once the JIT path runs the SPL. Run with:
//!   cargo test --release --locked -p dreamyemu --test dynarmic_spl_probe -- --nocapture

use dreamyemu::cpu::dynarmic::DynarmicCpu;
use dreamyemu::cpu::mem::GuestMemory;
use dreamyemu::cpu::{CpuBackend, Reg, StopReason};

#[test]
fn dynarmic_para_no_cp15_do_spl() {
    let spl = std::fs::read("tests/spl/G1OrigBootloader_nocheck/spl.bin")
        .expect("SPL blob (third-party, never committed)");
    let mut mem = GuestMemory::new();
    mem.map("spl", 0x0, spl.clone(), true).unwrap();
    // Post-MMU alias: the flat model ignores the MMU-enable, so the VA
    // window must alias the same bytes (the harness pre-maps both).
    mem.map("spl_va", 0x8800_0000, spl, true).unwrap();
    // Stack scratch the SPL touches early (empirically low RAM).
    mem.map_zeroed("pilha", 0x0800_0000, 0x1_0000).unwrap();
    // Cold/warm probe (see `sonda_fria` in `msm7201a.rs`): the SPL tests
    // bit `0x200` here before anything else. Zeroed, like the harness.
    mem.map_zeroed("sonda_fria", 0x01F6_A000, 0x1000).unwrap();
    let mut cpu = DynarmicCpu::new().unwrap();
    cpu.reset(&mem).unwrap();
    let mut pc = 0u32;
    let mut ultimo: (u32, ParadaKind) = (0, ParadaKind::Orcamento);
    for passo in 0..40u32 {
        let parada = cpu.run(pc, 10_000).unwrap();
        let agora = match parada {
            StopReason::Budget => cpu.read_reg(Reg::Pc),
            StopReason::MemoryFault { pc: p, .. } => p,
            StopReason::Exception { pc: p } => p,
            StopReason::ApiCall { addr } => addr,
            StopReason::Returned => {
                eprintln!("passo {passo}: returned");
                break;
            }
        };
        let ins = cpu
            .read_u32(agora)
            .map(|w| format!("{w:#010x}"))
            .unwrap_or_else(|_| "ilegivel".into());
        eprintln!("passo {passo}: parada={parada:?} em pc={agora:#x} ins={ins}");
        // Same stop twice in a row: the guest makes no progress without
        // the next stub (map it, then extend the walk).
        if (agora, parada_mirrors(&parada)) == ultimo {
            eprintln!("parado no mesmo ponto; proxima janela a mapear");
            break;
        }
        ultimo = (agora, parada_mirrors(&parada));
        pc = agora;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ParadaKind {
    Orcamento,
    Falta,
    Excecao,
    Chamada,
}

fn parada_mirrors(p: &StopReason) -> ParadaKind {
    match p {
        StopReason::Budget => ParadaKind::Orcamento,
        StopReason::MemoryFault { .. } => ParadaKind::Falta,
        StopReason::Exception { .. } => ParadaKind::Excecao,
        StopReason::ApiCall { .. } => ParadaKind::Chamada,
        StopReason::Returned => ParadaKind::Chamada,
    }
}
