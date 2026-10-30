//! The Dream's SDL window, with virtual buttons.
//!
//! Runs the SPL live bring-up (`dreamyemu::msm7201a`, the same harness as the
//! discovery test) and shows the framebuffer (`RAM_A6C0_BASE`,
//! 320x480 RGB565) in an SDL2 window, with the SPL serial on stdout. Usage:
//!
//! ```sh
//! cargo run -p dreamyemu-sdl -- [spl.bin [nand.img]] [--sair] [--botao <nome>]
//!   [--snapshot-save <fatia>] [--snapshot-arquivo <caminho>]
//!   [--snapshot-load <caminho>]
//!   [--snapshot-vigia ADDR[,LEN]]
//! ```
//!
//! Snapshots (TEMP, bring-up): `--snapshot-save 375000` fotografa o
//! mundo no topo da fatia e sai; `--snapshot-load snap.bin` retoma
//! dali. `--snapshot-vigia` arma o watchpoint pós-carga sem
//! re-salvar. Atalho para depurar a 6 min por iteração.
//!
//! Without arguments, looks for `tests/spl/G1OrigBootloader_nocheck/spl.bin` and
//! `tests/spl/nand.img` from the current directory. The SPL is a third-party
//! blob (never committed); the NAND is generated with
//! `ferramentas/cria_nand.py` + `ferramentas/nand_conteudo.py`.
//!
//! Buttons (Dream combos, all with Power held: Power+Shutter =
//! HBOOT, Power+Home = recovery, Power+Back = fastboot, Power+Trackball
//! = RADIO test). Click the bottom-bar cells or use the keyboard:
//! P = power, S = shutter, H = home, B = back, T = trackball,
//! R/Enter = reboot with the combo held, Esc/Q = quit. `--botao <nome>`
//! (`shutter|home|back|trackball`) starts with Power+key already held and
//! implies `--sair` (headless/CI smoke).

use std::io::Write;
use std::time::{Duration, Instant};

use dreamyemu::cpu::CpuBackend;
use dreamyemu::msm7201a::{
    Botoes, FB_LINUX_MAPA, RAM_A6C0_BASE, RAM_A6C0_TAMANHO, SNAPSHOT_LOAD_PATH,
    SNAPSHOT_SAVE_FATIA, SNAPSHOT_SAVE_PATH, SNAPSHOT_VIGIA, executa_spl_vivo_com_botoes,
    rx_enfileira,
};

const LARGURA: u32 = 320;
const ALTURA: u32 = 480;
const ESCALA: u32 = 2;
const BARRA: u32 = 96;

fn rgb565_para_rgb888(px: &[u8], fora: &mut [u8]) {
    debug_assert_eq!(px.len(), (LARGURA * ALTURA * 2) as usize);
    debug_assert_eq!(fora.len(), (LARGURA * ALTURA * 3) as usize);
    for (i, par) in px.chunks_exact(2).enumerate() {
        let v = u16::from_le_bytes([par[0], par[1]]);
        let r = (((v >> 11) & 0x1F) as u8) << 3 | (((v >> 11) & 0x1F) as u8) >> 2;
        let g = (((v >> 5) & 0x3F) as u8) << 2 | (((v >> 5) & 0x3F) as u8) >> 4;
        let b = ((v & 0x1F) as u8) << 3 | ((v & 0x1F) as u8) >> 2;
        fora[i * 3] = r;
        fora[i * 3 + 1] = g;
        fora[i * 3 + 2] = b;
    }
}

/// The 6 bar cells, in draw order.
const CELULAS: [&str; 6] = ["PWR", "SHUT", "HOME", "BACK", "TRCK", "RBT"];

fn legenda() -> &'static str {
    "botoes: clique ou P(power) S(shutter/HBOOT) H(home/rec) B(back/fb) T(trck/radio) R(reboot) Esc/sai"
}

fn titulo(b: &Botoes) -> String {
    let mut s = String::from("Dream SPL [");
    if b.power {
        s.push_str("PWR+");
    }
    let mut teclas = Vec::new();
    if b.shutter {
        teclas.push("SHUT");
    }
    if b.home {
        teclas.push("HOME");
    }
    if b.back {
        teclas.push("BACK");
    }
    if b.trackball {
        teclas.push("TRCK");
    }
    if teclas.is_empty() {
        s.push_str(if b.power { "PWR" } else { "sem teclas" });
    } else {
        s.push_str(&teclas.join("+"));
    }
    s.push(']');
    s
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `--sair`: quit after the run instead of keeping the window open
    // (headless/CI smoke; with a real window the default is to wait for close).
    let mut sair = args.iter().any(|a| a == "--sair");
    let mut botao_cli: Option<String> = None;
    let mut sd_cli: Option<String> = None;
    let mut salvar_nand: Option<String> = None;
    let mut fatias: u32 = 200_000;
    let mut resto: Vec<String> = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if a == "--botao" {
            botao_cli = it.next().cloned();
        } else if a == "--sd" {
            sd_cli = it.next().cloned();
        } else if a == "--salvar-nand" {
            salvar_nand = it.next().cloned();
        } else if a == "--fatias" {
            fatias = it.next().and_then(|s| s.parse().ok()).unwrap_or(fatias);
        } else if a == "--snapshot-save" {
            // TEMP (snapshots): fotografa no topo desta fatia e sai.
            if let Some(n) = it.next().and_then(|s| s.parse().ok()) {
                unsafe { SNAPSHOT_SAVE_FATIA = n };
            }
        } else if a == "--snapshot-arquivo" {
            // TEMP (snapshots): destino do save / origem do load
            // quando a flag irmã não traz caminho próprio.
            if let Some(p) = it.next() {
                let _ = SNAPSHOT_SAVE_PATH.set(p.clone());
            }
        } else if a == "--snapshot-load" {
            // TEMP (snapshots): retoma daqui em vez de bootar do zero.
            if let Some(p) = it.next() {
                let _ = SNAPSHOT_LOAD_PATH.set(p.clone());
            }
        } else if a == "--snapshot-vigia" {
            // TEMP (snapshots): `ADDR[,LEN]` arma a vigia pós-carga.
            if let Some(p) = it.next() {
                let _ = SNAPSHOT_VIGIA.set(p.clone());
            }
        } else if a != "--sair" {
            resto.push(a.clone());
        }
    }
    let caminho_spl = resto
        .first()
        .cloned()
        .unwrap_or_else(|| "tests/spl/G1OrigBootloader_nocheck/spl.bin".to_string());
    let caminho_nand = resto
        .get(1)
        .cloned()
        .unwrap_or_else(|| "tests/spl/nand.img".to_string());
    let spl = match std::fs::read(&caminho_spl) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no SPL at {caminho_spl}: {e} (third-party blob, never committed)");
            return std::process::ExitCode::from(2);
        }
    };
    let nand = match std::fs::read(&caminho_nand) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no NAND at {caminho_nand}: {e}");
            eprintln!("generate with: python3 ferramentas/cria_nand.py -o tests/spl/nand.img --fill 0xaa");
            eprintln!("and fill with: python3 ferramentas/nand_conteudo.py tests/spl/nand.img assets/Default_US.raw565");
            return std::process::ExitCode::from(2);
        }
    };
    // NAND shared across reboots: HBOOT flashing writes to it, and
    // the next reboot starts from the written contents. `--salvar-nand`
    // dumps to disk on exit (without it, flashing lives only for the session).
    let nand_rc =
        std::rc::Rc::new(std::cell::RefCell::new(nand));
    // SD card (FAT32 with DREAIMG.nbh): `--sd <img>`, or
    // tests/spl/sd.img when present
    // (generate with: python3 ferramentas/cria_sd.py -o tests/spl/sd.img).
    // Without a card, the SPL follows the `No card inserted` branch.
    let caminho_sd = sd_cli.unwrap_or_else(|| "tests/spl/sd.img".to_string());
    let sd_rc: Option<std::rc::Rc<Vec<u8>>> = match std::fs::read(&caminho_sd) {
        Ok(b) => {
            eprintln!("sd: {} ({} bytes)", caminho_sd, b.len());
            Some(std::rc::Rc::new(b))
        }
        Err(_) => {
            eprintln!("sd: no card ({caminho_sd} missing)");
            None
        }
    };

    let botoes = std::rc::Rc::new(std::cell::RefCell::new(Botoes::default()));
    if let Some(nome) = botao_cli {
        let mut b = botoes.borrow_mut();
        b.power = true;
        match nome.as_str() {
            "shutter" => b.shutter = true,
            "home" => b.home = true,
            "back" => b.back = true,
            "trackball" => b.trackball = true,
            outro => {
                eprintln!("--botao unknown: {outro} (shutter|home|back|trackball)");
                return std::process::ExitCode::from(2);
            }
        }
        sair = true;
    }
    eprintln!("{}", legenda());

    let sdl = match sdl2::init() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SDL init: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let video = match sdl.video() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SDL video: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let janela = match video
        .window(
            "Dream SPL",
            LARGURA * ESCALA,
            ALTURA * ESCALA + BARRA,
        )
        .position(100, 60)
        .build()
    {
        Ok(j) => j,
        Err(e) => {
            eprintln!("SDL window: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut tela = match janela.into_canvas().present_vsync().build() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("SDL canvas: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let criador = tela.texture_creator();
    let mut textura = match criador.create_texture_streaming(
        sdl2::pixels::PixelFormatEnum::RGB24,
        LARGURA,
        ALTURA,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("SDL texture: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut eventos = match sdl.event_pump() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SDL events: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    // TEMP/RX work: host keystrokes reach the guest `Cmd>` shell as text.
    // `TextInput` (not `KeyDown`) carries the printable characters, so the
    // P/S/H/B/T button shortcuts keep working untouched; `rx_enfileira`
    // filters to what the shell line input accepts (printable + BS + CR).
    video.text_input().start();
    let mut fb = vec![0u8; RAM_A6C0_TAMANHO];
    let mut rgb = vec![0u8; (LARGURA * ALTURA * 3) as usize];
    // TEMP (Linux fb watch): FBBASE's fbram VA, logged by the harness
    // (identical across runs: 0xC60DD520). Unmapped on our side — the
    // kernel draws through the direct map, not the ioremap window —
    // so this only names the window until FB_LINUX_MAPA fires.
    // Remove with the FBDUMP sampler below.
    const FB_LINUX_VA: u32 = 0xC60D_D520;
    let mut fb_linux = vec![0u8; RAM_A6C0_TAMANHO];
    let mut ultimo_envio = Instant::now() - Duration::from_secs(1);
    let mut mostrou = false;
    let mut mostrou_linux = false;
    let mut stdout = std::io::stdout().lock();
    // Reboot request with the current combo held (R/Enter or the RBT cell): the
    // callback returns false and the outer loop runs the SPL again, CPU
    // reset, with the keys still held (a real reboot).
    let reiniciar = std::rc::Rc::new(std::cell::Cell::new(false));
    let quer_sair = std::rc::Rc::new(std::cell::Cell::new(false));

    // Toggle one cell by index (5 = RBT = reboot, not latched).
    let alternar = |i: usize,
                    botoes: &std::rc::Rc<std::cell::RefCell<Botoes>>,
                    reiniciar: &std::rc::Rc<std::cell::Cell<bool>>,
                    tela: &mut sdl2::render::Canvas<sdl2::video::Window>| {
        let mut b = botoes.borrow_mut();
        match i {
            0 => b.power = !b.power,
            1 => b.shutter = !b.shutter,
            2 => b.home = !b.home,
            3 => b.back = !b.back,
            4 => b.trackball = !b.trackball,
            _ => reiniciar.set(true),
        }
        tela.window_mut().set_title(&titulo(&b)).unwrap_or(());
        eprintln!("botoes: {}", titulo(&b));
    };

    let trata_tecla =
        |codigo: sdl2::keyboard::Keycode,
         botoes: &std::rc::Rc<std::cell::RefCell<Botoes>>,
         reiniciar: &std::rc::Rc<std::cell::Cell<bool>>,
         quer_sair: &std::rc::Rc<std::cell::Cell<bool>>,
         tela: &mut sdl2::render::Canvas<sdl2::video::Window>| {
            use sdl2::keyboard::Keycode;
            match codigo {
                Keycode::Escape | Keycode::Q => quer_sair.set(true),
                Keycode::P => {
                    let mut b = botoes.borrow_mut();
                    b.power = !b.power;
                    tela.window_mut().set_title(&titulo(&b)).unwrap_or(());
                    eprintln!("botoes: {}", titulo(&b));
                }
                Keycode::S => {
                    let mut b = botoes.borrow_mut();
                    b.shutter = !b.shutter;
                    tela.window_mut().set_title(&titulo(&b)).unwrap_or(());
                    eprintln!("botoes: {}", titulo(&b));
                }
                Keycode::H => {
                    let mut b = botoes.borrow_mut();
                    b.home = !b.home;
                    tela.window_mut().set_title(&titulo(&b)).unwrap_or(());
                    eprintln!("botoes: {}", titulo(&b));
                }
                Keycode::B => {
                    let mut b = botoes.borrow_mut();
                    b.back = !b.back;
                    tela.window_mut().set_title(&titulo(&b)).unwrap_or(());
                    eprintln!("botoes: {}", titulo(&b));
                }
                Keycode::T => {
                    let mut b = botoes.borrow_mut();
                    b.trackball = !b.trackball;
                    tela.window_mut().set_title(&titulo(&b)).unwrap_or(());
                    eprintln!("botoes: {}", titulo(&b));
                }
                Keycode::R | Keycode::Return => reiniciar.set(true),
                _ => {}
            }
        };

    // Draw the button bar (no font: color = state; legend on
    // stdout and in the title). Latched = green, released = gray, PWR = red
    // when latched, RBT = blue.
    let desenha_barra = |tela: &mut sdl2::render::Canvas<sdl2::video::Window>,
                         b: &Botoes| {
        use sdl2::pixels::Color;
        let base_y = (ALTURA * ESCALA) as i32;
        let larg = (LARGURA * ESCALA / 6) as i32;
        let trav = [b.power, b.shutter, b.home, b.back, b.trackball, false];
        for (i, _) in CELULAS.iter().enumerate() {
            let r = sdl2::rect::Rect::new(
                i as i32 * larg + 2,
                base_y + 2,
                (larg - 4) as u32,
                BARRA - 4,
            );
            let cor = if i == 5 {
                Color::RGB(60, 90, 180)
            } else if trav[i] {
                if i == 0 {
                    Color::RGB(180, 60, 60)
                } else {
                    Color::RGB(60, 160, 80)
                }
            } else {
                Color::RGB(70, 70, 80)
            };
            tela.set_draw_color(cor);
            let _ = tela.fill_rect(r);
        }
        // "Press PWR + key" marker: light fillet under the
        // key cells while power is held.
        if b.power {
            tela.set_draw_color(Color::RGB(220, 220, 230));
            let _ = tela.fill_rect(sdl2::rect::Rect::new(
                larg + 2,
                base_y + BARRA as i32 - 8,
                (larg * 4 - 4) as u32,
                4,
            ));
        }
        let _ = tela.present();
    };

    tela.window_mut().set_title(&titulo(&botoes.borrow())).unwrap_or(());

    loop {
        reiniciar.set(false);
        quer_sair.set(false);
        let botoes_cb = botoes.clone();
        let reiniciar_cb = reiniciar.clone();
        let quer_sair_cb = quer_sair.clone();
        let fim = {
            // Counted suppression of the kernel NAND driver's status-error
            // loop ("read_page - error bad status"): it fires thousands of
            // times while probing an unimplemented controller and drowns
            // the log. First 3 lines pass through, then one notice, then
            // dropped. (The proper fix is serving READY status — pending.)
            let resto_serial = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
            let suprimidas = std::rc::Rc::new(std::cell::Cell::new((0usize, false)));
            let resto_serial_cb = resto_serial.clone();
            let suprimidas_cb = suprimidas.clone();
            let devolve = |fatia: u32,
                           _pc: u32,
                           cpu: &mut dreamyemu::cpu::dual::DualBackend,
                           serial: &[u8]|
             -> bool {
                // Android logcat: drain the kernel logger rings
                // (main/events/radio) into host stdout. This is the
                // userspace counterpart to the klog tap — init,
                // servicemanager, dalvik, debuggerd and the crashing
                // processes all speak here.
                for linha in dreamyemu::msm7201a::colhe_logcat(cpu) {
                    let _ = writeln!(stdout, "{linha}");
                }
                let _ = stdout.flush();
                if !serial.is_empty() {
                    // Bytes may split lines across slices; buffer them and
                    // emit whole lines so the filter sees complete text.
                    let mut resto = resto_serial_cb.borrow_mut();
                    resto.extend_from_slice(serial);
                    let mut ini = 0;
                    while let Some(fim) = resto[ini..]
                        .iter()
                        .position(|&x| x == b'\n')
                        .map(|p| ini + p)
                    {
                        let linha = resto[ini..=fim].to_vec();
                        ini = fim + 1;
                        let texto = String::from_utf8_lossy(&linha);
                        if texto.contains("error bad status") {
                            let (n, avisado) = suprimidas_cb.get();
                            suprimidas_cb.set((n + 1, avisado));
                            if n < 3 {
                                let _ = stdout.write_all(&linha);
                            } else if !avisado {
                                suprimidas_cb.set((n + 1, true));
                                let _ = writeln!(
                                    stdout,
                                    "[nand status-error loop: suppressing further identical lines]"
                                );
                            }
                        } else {
                            let _ = stdout.write_all(&linha);
                        }
                    }
                    resto.drain(..ini);
                    drop(resto);
                    let _ = stdout.flush();
                }
                // Headless heartbeat: slice + pc every 20k slices to
                // locate where long runs (91 MB flash) stop.
                if fatia % 20_000 == 0 {
                    eprintln!("fatia={fatia} pc={_pc:#x}");
                    // Presenter's source, first set wins: the FBMAP hunt
                    // publishes (mm, va0) when boot animation mmaps the fb.
                    let (mm_linux, va_linux) = unsafe { FB_LINUX_MAPA };
                    let va = if va_linux != 0 { va_linux } else { FB_LINUX_VA };
                    let lido = if va_linux != 0 {
                        cpu.memoria().le_no_mm(mm_linux, va, &mut fb_linux).is_ok()
                    } else {
                        cpu.read_mem(va, &mut fb_linux).is_ok()
                    };
                    if lido {
                        let mut nz = 0u32;
                        let mut h = 0xcbf29ce4u32;
                        for par in fb_linux.chunks_exact(2) {
                            let v = u16::from_le_bytes([par[0], par[1]]);
                            if v != 0 {
                                nz += 1;
                            }
                            h ^= v as u32;
                            h = h.wrapping_mul(0x01000193);
                        }
                        let qual = if va_linux != 0 { "mapa" } else { "fbram" };
                        eprintln!("FBDUMP f={fatia} {qual} va={va:#x} nonzero={nz} hash={h:#x}");
                        // Both halves of the double buffer (minui pans
                        // between them with FBIOPUT_VSCREENINFO), latest
                        // heartbeat wins: the frame on disk tracks the
                        // run even headless, where no window samples.
                        if va_linux != 0 {
                            let mut duplo = vec![0u8; RAM_A6C0_TAMANHO * 2];
                            if cpu.memoria().le_no_mm(mm_linux, va, &mut duplo).is_ok() {
                                let mut rgb2 = vec![0u8; (LARGURA * ALTURA * 3) as usize];
                                let mut ppm = format!("P6\n{LARGURA} {}\n255\n", ALTURA * 2).into_bytes();
                                for metade in duplo.chunks_exact(RAM_A6C0_TAMANHO) {
                                    rgb565_para_rgb888(metade, &mut rgb2);
                                    ppm.extend_from_slice(&rgb2);
                                }
                                let _ = std::fs::create_dir_all("/tmp/opencode");
                                let _ = std::fs::write("/tmp/opencode/fb_linux_duplo.ppm", &ppm);
                            }
                        }
                    } else {
                        eprintln!("FBDUMP f={fatia} va={va:#x} unmapped", va = va);
                    }
                    // TEMP (MDP DMA hunt): the kernel mdp driver programs
                    // the display DMA from a static 562-pair table; the
                    // source address it lands in the E00xxxxx stubs IS the
                    // scanned-out fb, whoever draws it. Dump nonzero stub
                    // words (cap 40) so the RAM-ish value stands out.
                    // Remove once the presenter tracks the MDP source.
                    if fatia >= 100_000 {
                        let mut mdp = vec![0u8; 0x1000];
                        let mut mostrados = 0;
                        for base in [0xE001_0000u32, 0xE002_0000, 0xE005_0000, 0xE006_0000] {
                            if cpu.read_mem(base, &mut mdp).is_err() {
                                continue;
                            }
                            for (i, w) in mdp.chunks_exact(4).enumerate() {
                                let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                                if v != 0 {
                                    if mostrados < 40 {
                                        eprintln!(
                                            "MDPDUMP f={fatia} {:#x}+{:#x}={:#x}",
                                            base,
                                            i * 4,
                                            v
                                        );
                                    }
                                    mostrados += 1;
                                }
                            }
                        }
                        if mostrados > 0 {
                            eprintln!("MDPDUMP f={fatia} total_nonzero={mostrados}");
                        }
                    }
                }
                let _ = fatia;
                for evento in eventos.poll_iter() {
                    use sdl2::event::Event;
                    match evento {
                        Event::Quit { .. } => return false,
                        Event::KeyDown {
                            keycode: Some(k), ..
                        } => trata_tecla(
                            k,
                            &botoes_cb,
                            &reiniciar_cb,
                            &quer_sair_cb,
                            &mut tela,
                        ),
                        // TEMP/RX work: typed text becomes guest keystrokes
                        // (see `rx_enfileira`). Host Enter arrives as LF
                        // here; the shell wants CR (`0x0A`/`0x0D` both end
                        // a line, but CR matches the hardware path).
                        Event::TextInput { text, .. } => {
                            for b in text.bytes() {
                                rx_enfileira(if b == b'\n' { b'\r' } else { b });
                            }
                        }
                        Event::MouseButtonDown { x, y, .. } => {
                            let base_y = (ALTURA * ESCALA) as i32;
                            if y >= base_y {
                                let larg = (LARGURA * ESCALA / 6) as i32;
                                let i = (x / larg).clamp(0, 5) as usize;
                                alternar(
                                    i,
                                    &botoes_cb,
                                    &reiniciar_cb,
                                    &mut tela,
                                );
                            }
                        }
                        _ => {}
                    }
                }
                if quer_sair_cb.get() || reiniciar_cb.get() {
                    return false;
                }
                if ultimo_envio.elapsed() >= Duration::from_millis(33) {
                    // Linux fb once the FBMAP hunt names it, else the SPL
                    // splash: first set wins and sticks (no switching back).
                    let (mm_linux, va_linux) = unsafe { FB_LINUX_MAPA };
                    let va = if va_linux != 0 { va_linux } else { RAM_A6C0_BASE };
                    // The fb mmap lives in the drawing task's mm, rarely
                    // the current one when this samples (see `le_no_mm`).
                    let lido = if va_linux != 0 {
                        cpu.memoria().le_no_mm(mm_linux, va, &mut fb).is_ok()
                    } else {
                        cpu.read_mem(va, &mut fb).is_ok()
                    };
                    if lido {
                        rgb565_para_rgb888(&fb, &mut rgb);
                        let _ = textura.update(None, &rgb, (LARGURA * 3) as usize);
                        let _ = tela.copy(&textura, None, None);
                        desenha_barra(&mut tela, &botoes_cb.borrow());
                        ultimo_envio = Instant::now();
                        if !mostrou {
                            mostrou = true;
                            // Show the window when the first frame arrives (the WM
                            // may have opened it minimized asking for attention).
                            tela.window_mut().raise();
                        }
                        // Proof artifact: first Linux frame to disk (PPM).
                        if va_linux != 0 && !mostrou_linux {
                            mostrou_linux = true;
                            let mut ppm = format!("P6\n{LARGURA} {ALTURA}\n255\n").into_bytes();
                            ppm.extend_from_slice(&rgb);
                            let _ = std::fs::create_dir_all("/tmp/opencode");
                            let _ = std::fs::write("/tmp/opencode/fb_linux.ppm", &ppm);
                            eprintln!("FBDUMP first linux frame -> /tmp/opencode/fb_linux.ppm");
                        }
                    }
                }
                true
            };

            executa_spl_vivo_com_botoes(
                &spl,
                nand_rc.clone(),
                sd_rc.clone(),
                fatias,
                2_000,
                botoes.clone(),
                devolve,
            )
        };
        println!("\nparada: {} botoes: {}", fim.parada, titulo(&botoes.borrow()));
        if sair {
            // Headless diagnostics: last stops (non-delay) tell where
            // each combo parks (HBOOT waits for USB/key? fastboot spins?).
            use std::collections::HashSet;
            let delay: HashSet<&str> = [
                "0x880042c0",
                "0x880042c4",
                "0x880042c8",
                "0x880042cc",
                "0x88004348",
                "0x8800434c",
                "0x88004350",
                "0x88004354",
            ]
            .into_iter()
            .collect();
            let cauda: Vec<&String> = fim
                .caminho
                .iter()
                .rev()
                .filter(|p| !delay.contains(p.as_str()))
                .take(200)
                .collect();
            println!("cauda:");
            for p in cauda.iter().rev() {
                println!("  {p}");
            }
        }
        // Handoff snapshot: machine ID + ATAGs at the trampoline.
        if fim.regs_saida != [0, 0, 0, 0] || !fim.atags.is_empty() {
            println!(
                "handoff: r0={:#x} r1={} r2={:#x} r3={:#x}",
                fim.regs_saida[0],
                fim.regs_saida[1],
                fim.regs_saida[2],
                fim.regs_saida[3]
            );
            let w: Vec<u32> = fim.atags.chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            let mut i = 0;
            while i + 1 < w.len() {
                let (sz, tag) = (w[i] as usize, w[i + 1]);
                if sz < 2 {
                    break;
                }
                println!("  atag sz={sz} tag={tag:#x}");
                if tag == 0 {
                    break;
                }
                i += sz;
                if i >= 256 {
                    break;
                }
            }
        }
        // Kernel serial: everything the UART console emitted after the handoff.
        if !fim.kernel_tx.is_empty() {
            println!("kernel: {} bytes via THR:", fim.kernel_tx.len());
            print!("{}", String::from_utf8_lossy(&fim.kernel_tx));
            println!();
        }
        // Kernel printk buffer: text found in RAM at the end of the run.
        if !fim.kernel_log.is_empty() {
            println!("klog: {} bytes from the printk buffer:", fim.kernel_log.len());
            print!("{}", String::from_utf8_lossy(&fim.kernel_log));
            println!();
        }
        if sair || quer_sair.get() || !reiniciar.get() {
            if sair || quer_sair.get() {
                if let Some(dest) = &salvar_nand {
                    match std::fs::write(dest, &*nand_rc.borrow()) {
                        Ok(()) => eprintln!("nand saved to {dest}"),
                        Err(e) => eprintln!("failed to save nand: {e}"),
                    }
                }
                return std::process::ExitCode::SUCCESS;
            }
            // Run ended on its own (e.g. jump to the kernel):
            // keep the last image until close; R/Enter reboots with the
            // current combo (back to the outer loop).
            let mut reboot_pedido = false;
            'fora: loop {
                for evento in eventos.wait_timeout_iter(100) {
                    use sdl2::event::Event;
                    match evento {
                        Event::Quit { .. } => break 'fora,
                        Event::KeyDown {
                            keycode: Some(k),
                            ..
                        } => {
                            use sdl2::keyboard::Keycode;
                            match k {
                                Keycode::Escape | Keycode::Q => break 'fora,
                                Keycode::R | Keycode::Return => {
                                    reboot_pedido = true;
                                    break 'fora;
                                }
                                _ => trata_tecla(
                                    k,
                                    &botoes,
                                    &reiniciar,
                                    &quer_sair,
                                    &mut tela,
                                ),
                            }
                        }
                        Event::MouseButtonDown { x, y, .. } => {
                            let base_y = (ALTURA * ESCALA) as i32;
                            if y >= base_y {
                                let larg = (LARGURA * ESCALA / 6) as i32;
                                let i = (x / larg).clamp(0, 5) as usize;
                                alternar(i, &botoes, &reiniciar, &mut tela);
                                if reiniciar.get() {
                                    reiniciar.set(false);
                                    reboot_pedido = true;
                                    break 'fora;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                let _ = tela.copy(&textura, None, None);
                desenha_barra(&mut tela, &botoes.borrow());
            }
            if reboot_pedido {
                eprintln!("reboot with {}", titulo(&botoes.borrow()));
                continue;
            }
            break;
        }
        eprintln!("reboot with {}", titulo(&botoes.borrow()));
    }
    if let Some(dest) = &salvar_nand {
        match std::fs::write(dest, &*nand_rc.borrow()) {
            Ok(()) => eprintln!("nand saved to {dest}"),
            Err(e) => eprintln!("failed to save nand: {e}"),
        }
    }
    std::process::ExitCode::SUCCESS
}
