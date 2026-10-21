# Guide for agents

This file is for an AI about to work in this repository. It says what you cannot
learn by reading one file at a time: where things live, what must not break, and
how this project writes.

Humans may read it too — there is nothing here that is secret from the code.

## What Dreamyemu is

A fork of Zeebx aimed at the **HTC Dream** (the 2008 T-Mobile G1), not the Zeebo.
Both machines share the **Qualcomm MSM7201A** SoC (app-side ARM1136EJ-S + modem
ARM9), but the emulation target is the opposite of Zeebx's: the Dream's SPL
(`tests/spl/.../spl.bin`, 512 KiB) is bare metal and programs real silicon, so
this fork is **low-level emulation** — SoC memory map, CP15/MMU, UART, NAND —
where Zeebx is high-level emulation of the BREW 4.0.2 conversation. What must be
faithful here is the silicon behavior the SPL touches, not an API conversation.

Inherited from Zeebx and still true: the overall layout is in
[`ARCHITECTURE.md`](ARCHITECTURE.md), and each subsystem has its own doc under
[`docs/implementacao/`](docs/implementacao/README.md) (older docs are still in
Portuguese; translate on touch, do not mass-translate). What the fork reuses is
the CPU backend (`cpu`), `GuestMemory`, and the session/harness scaffolding —
see `src/msm7201a.rs` and `src/msm7201a_serial.rs` for the Dream-specific map
and serial work. Nothing under `brew/` applies to the Dream target.

## The map

```
Cargo.toml          the `zeebx` library — the emulator core, no UI
                    (crate/package renames for the fork are still TBD)
src/                BREW (inherited, Zeebo-only), CPU, video, audio, loader, session, save state
src/msm7201a.rs     Dream SoC map: SPL layout, VA->PA section table, initial GuestMemory
src/msm7201a_serial.rs  SPL text output: putc tap points, SerialTap sink, ring drain
src/ui/             screens and state shared between frontends (see warning below)
tests/spl/          the original Dream SPL blob — UNTRACKED, third-party, never commit
frontends/
  qt-standalone/          the UI: the `zeebx-qt` binary, in Qt Quick
  cli/                    the command line: the `zeebx` binary (`run`, `sessao`, `bench`...), no Qt
  headless/               no UI, configured by `config.ini`
  libretro/               the RetroArch core
  android/                the app, without a line of Java
  ios/                    the iOS app: UIKit over a static library
ferramentas/        Python scripts: catalog, sweep, core install
docs/               documentation; `patch-notes/` holds each version's notes
assets/             icons, fonts and `lang/` — the factory languages
```

**`src/ui/` is not just UI.** `library`, `settings`, `saves`, `acervo` and `i18n`
live there but are read **by the core** — `machine`, `loader` and `session` talk
to them. Only `ui::window` (the raw `zeebx run --window`), `ui::atualizacao` and
`ui::discord` are truly desktop; the UI window lives in `frontends/qt-standalone`.

**`tests/spl/` is never committed.** It holds the copyrighted HTC bootloader blob
used as a reversing reference and bring-up target. The `msm7201a` tests skip
gracefully without it, in the same spirit as the `ZEEBX_ROM` sweep.

## The features, and why they exist

| Feature | What it brings | Who uses it |
|---|---|---|
| `desktop` | gilrs, minifb, rfd, Discord, glutin — implies `gpu`, `audio`, `soundfont` | Qt, command line, headless |
| `audio` | just `cpal`, which on Android talks to Oboe | Android, and `desktop` |
| `gl` | drawing on the GPU; **pulls in no host libraries** | core, Android, and `desktop` |
| `gpu` | creating its own context (glutin) — implies `gl` | desktop |
| `soundfont` | MIDI via sample bank (rustysynth, pure Rust) | core and desktop |

**House rule: the Libretro core links no host library.** No window, no sound card,
no gamepad. Video, audio and input come from the frontend. `libretro.yml` enforces
this with `ldd`, and a `dep:` in the wrong place breaks the core build.

Before putting a `#[cfg(feature = "desktop")]` on something, ask whether it is
**really** desktop. Three wrong gates once broke the Android build unnoticed,
because the APK is only assembled on tag.

## Building and proving

The UI is the Qt frontend (`zeebx-standalone-qt`, binary `zeebx-qt`), and it is what
ships in the installers. The command line (`zeebx-cli`, binary `zeebx`) is the
measure-and-debug bench and needs no Qt. The egui UI was removed after 0.4.2. Qt
needs **Qt 6** (6.4 or newer), found via `qmake6`, `qmake` or `QMAKE`.
`python3 ferramentas/prepara_build.py` says what is missing. The Qt UI is documented in
[`docs/implementacao/21-migracao-para-qt.md`](docs/implementacao/21-migracao-para-qt.md).

```bash
cargo build --release --locked -p zeebx-cli                 # the `zeebx` binary
cargo build --release --locked -p zeebx-standalone-qt       # the `zeebx-qt` binary
cargo test  --release --locked -p zeebx -p zeebx-cli -p zeebx-standalone-qt
timeout 60 ./target/release/zeebx controles                 # comes up for real, no screen

cargo build --release --locked -p zeebx-headless
cargo build --release --locked -p zeebx-libretro            # alone: see below
python3 ferramentas/verifica_core.py target/release/libzeebx_libretro.so
```

**The Libretro core compiles in a command of its own.** Together with another
package, Cargo merges the core features both ask for, and the core inherits the
other's `audio`: code that only compiles with sound passes the joint command and
breaks in `libretro.yml`, which compiles it alone. Already happened once with
`ui::partida`'s `set_audio`.

`verifica_core.py` opens the library the way the frontend opens it (`dlopen`) and
calls the ABI. It is not `nm` on a symbol list: it catches a missing link-time
dependency, which symbol reading does not.

**Android** needs the toolchain in `$HOME`, no sudo — the table is in
[`frontends/android/LEIAME.md`](frontends/android/LEIAME.md):

```bash
export PATH="$HOME/.cargo/bin:$HOME/Android/gradle/bin:$PATH"
export JAVA_HOME="$HOME/Android/jdk"
./frontends/android/compilar.sh --apk
```

**Switch** (the static `.a` the ROMBundler links) lives in
[`frontends/switch/compilar.sh`](frontends/switch/compilar.sh). That script's
`cfg(zeebx_switch)` is what shrinks the dynarmic code cache and grows the kept
sound count. On Mac the `rombundler-switch` Docker image brings devkitA64 and
rustc; `libretro.yml`'s `core-switch` job runs the same script with `--local`
inside the `devkitpro/devkita64` image. Release does the same and publishes
`zeebx_libretro-switch.zip`. The `.a` does not link alone: the `switch_jit_*` and
`switch_spinlock_*` the dynarmic patch calls come from ROMBundler.

**iOS** needs a Mac with Xcode and the `aarch64-apple-ios` and
`aarch64-apple-ios-sim` targets in rustup. Step by step in
[`frontends/ios/LEIAME.md`](frontends/ios/LEIAME.md):

```bash
./frontends/ios/compilar.sh --app
```

## CI

**The tag is the only automatic trigger.** `release.yml` fires on `v0.0.0` and
assembles the release as a draft. `ci.yml`, `libretro.yml`, `headless.yml`,
`android.yml`, `ios.yml` and `qt.yml` are `workflow_dispatch`: the default CI
compiles the command line — and with it the core and tests — on all six platforms
and calls `qt.yml`, which compiles the UI and assembles the installers. Release
calls the same `qt.yml`: the Qt steps live in one place. Eleven jobs per run is too
expensive to spend on every push, and the requester decides. The exception is
`discord-issues.yml`, which compiles nothing: it pings Discord when an issue opens,
closes or changes assignee.

If you touched something only one of them covers — the APK, the core on an ARM
target — tell the human that workflow is worth triggering before the tag. You
cannot trigger it.

## What must not break

- **Binary names are inherited from Zeebx for now** (`zeebx-qt`, `zeebx`). The fork
  will rename them when it has its own installers; until then scripts, CI and docs
  still type these names. When the rename happens, shortcut, `.desktop`, updater
  and docs move together, in one commit.
- **The core `.so` and `zeebx_libretro.info` travel as a pair.** An old `.info`
  next to a new core makes the RetroArch scan mark everything `??`. And the
  `.info` capability fields must match what the ABI does.
- **This code is GPL-2.0-or-later**. The default CPU backend is Dynarmic, so that
  GPLv3 frontends like Qt 6 can link the core without picking up a GPLv2-only
  dependency. Before proposing a new library, check its license and the features
  of the binary that will link it. **The binaries are already GPLv3 in practice**:
  all of them link crates that are Apache-2.0-only, which do not combine with
  GPLv2. So no GPL-2.0-only dependency goes into any binary.
- **The `CHAVE_PUBLICA` in `src/ui/atualizacao.rs` and the `ZEEBX_ATUALIZADOR_CHAVE`
  GitHub secret travel as a pair** (inherited Zeebo updater; the fork will replace
  or drop this mechanism — do not touch without a plan). The secret signs release
  packages; the embedded key is what the emulator accepts. Swapping one without the
  other gets every automatic update refused — and anyone on the old version only
  escapes by downloading by hand.
- **`THIRD-PARTY-NOTICES.txt` tracks `Cargo.lock`.** Dependency changed, run
  `python3 ferramentas/avisos_de_terceiros.py` and commit together; release checks.
- **`Cargo.lock` is versioned** and CI uses `--locked`. New workspace member goes
  in the lock, in the same commit.
- **Third-party blobs never enter git.** `tests/spl/` (Dream SPL), `roms/`,
  `vendor/` are reference material only. Derived facts (addresses, tables,
  constants) live in code with provenance notes; the bytes stay local.

## How this project writes

**Comments explain why, not what.** The code already says what it does. What gets
lost is the reason: the measurement that killed the hypothesis, the defect the line
prevents, the path that was tried and did not work. There are long comments here,
and they are long on purpose.

**Claims come with measurements.** "34x faster", "from 79% to 284%", "1214 frames per
virtual millisecond". If you did not measure, say you did not measure — do not round
to an impression.

**Commit messages are one declarative sentence in English**, saying what changed and
why. No conventional-commit prefix in recent history. The body explains the reason,
it does not repeat the diff.

**English in code and docs.** Older inherited docs under `docs/` are still in
Portuguese; translate a file when you touch it for other reasons, do not do mass
translation drives. Exception: user-facing strings that already ship translated
stay as they are.

**Evidence-backed constants say where they came from.** Blob-derived addresses and
tables (see `src/msm7201a.rs`) carry provenance and mark hypotheses as hypotheses.
A guess from call shape never poses as a measured fact.

## The README contributors list

The README's "Who makes Zeebx" table is written, not fetched: the README runs
nothing. It comes from `python3 ferramentas/contribuidores.py`, which reads the
same site API (`docs/site.js`) and rewrites the section between the
`<!-- contribuidores -->` markers. Redo it when new people join. (Fork note: the
table still describes the upstream project; the fork will replace it.)

## Release notes

Each version leaves its note in [`docs/patch-notes/`](docs/patch-notes/), written
for the emulator's users: what was fixed, in player language, not programmer
language.

## If you are not sure

This repository prefers a question over a well-written guess. If the reading does
not close — if you cannot tell whether a control sends the d-pad as a key or an
axis, for example — say which instrument would settle it instead of picking the
most likely path.
