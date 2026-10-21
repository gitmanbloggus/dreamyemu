# Architecture

How Dreamyemu is built inside. Each subsystem has its own document under
[`docs/implementacao/`](docs/implementacao/README.md) (older docs are still in
Portuguese; translate on touch); this is the overall drawing.

> Fork note: this repo started as Zeebx, a high-level emulator of the Brazilian
> TecToy Zeebo (BREW 4.0.2). This fork targets the **HTC Dream** (2008 T-Mobile
> G1) instead. Same SoC family (**Qualcomm MSM7201A**, ARM1136EJ-S app core +
> ARM9 modem), opposite emulation: the Dream's SPL is bare metal, so the goal is
> low-level SoC emulation (memory map, CP15/MMU, UART, NAND), reusing the CPU
> backend, guest memory, and session harness. The HLE BREW core described below
> is inherited and still present, but nothing under `brew/` applies to the Dream
> target — see `src/msm7201a.rs` and `src/msm7201a_serial.rs` for the Dream side.

## The starting point

Emulating Zeebo means reimplementing Qualcomm BREW 4.0.2. The game is an ARM
binary that never touches hardware: it talks to the system through function
pointer tables — `IShell`, `IDisplay`, `IFileMgr`, `IHID`, OpenGL ES. There is no
video register to write, no timer interrupt to serve, no console firmware involved
at any point.

So the (inherited) emulation is high-level. The game's ARM code runs on an
emulated core and API calls are intercepted and served on the host. What must be
faithful is the conversation, not the silicon.

## The trampoline

The vtables handed to the game point at an unmapped address range. When the game
calls a method, the core faults on instruction fetch and we read the address: it
encodes which interface and which method were requested.

```
  game (ARM)                          emulator (Rust)
      │ ldr r12, [vtable + 0x30]
      │ blx r12
      ▼
  0xf000_7038  ── unmapped ──▶  FETCH_UNMAPPED
                                         │  aee::decode → (Bitmap, slot 14)
                                         │  Machine::dispatch
                                         ▼  r0 = result, pc = lr, continue
```

There is no ARM glue code, no compiled stub, no jump table inside the guest. The
address is the call's identifier. Return works the same: `lr` gets a sentinel
address that is also unmapped, and reaching it means the module returned.

The cost of this is measured, **but the measurement is from the Unicorn era**.
The round trip through the core — leaving the JIT and re-entering — cost **1.4 µs**
per call even when the method did nothing. With Dynarmic that number **was never
redone**: today's instrument (`ZEEBX_ROM_PERFIL`) times only the method body, not
the `halt` plus re-entry, which is where the fixed cost lives. Until the
micro-benchmark exists, the per-call cost is unknown, not 1.4 µs.

What remains depends on the method, and is sometimes far more than that: in
Pac-Mania the 8 µs average per call came not from the trampoline but from two
methods doing too much work. See
[`docs/OPTIMIZING_V0.3.0.md`](docs/OPTIMIZING_V0.3.0.md).

## Layers

```
  UI (Qt)                   ─┐
  command line              ─┤
  frontends/android         ─┼─▶  Session  ─▶  Machine  ─▶  CpuBackend  ─▶  dynarmic (A32)
  frontends/libretro        ─┘                                            └─▶ interpreter (wasm32)
  frontends/headless        ─┘
                                               │
                                               ├─▶ software rasterizer (OpenGL ES 1.1)
                                               ├─▶ 2D framebuffer
                                               ├─▶ audio mixer ─▶ cpal
                                               ├─▶ VFS ─▶ module directory
                                               └─▶ heap, objects, timers
```

`CpuBackend` isolates the ARM core. Natively the implementation is **Dynarmic**
(A32, ARMv6K), on `wasm32` it is the interpreter: Dynarmic does not compile to
WebAssembly. **Unicorn was removed**; the backend swap this paragraph foresaw
happened, without touching the rest of the code — which is exactly what the trait
existed to guarantee.

`Machine` is the emulator proper: the loop, dispatch, and machine state. It does
not know a window exists.

`Session` is a running game, from file to frames. It is what the UI uses, and it
is where the speed governor and measurement live.

Frontends are packages of their own next to the core, each with its window and
event loop: [`frontends/android`](frontends/android/LEIAME.md) over
`NativeActivity`, [`frontends/ios`](frontends/ios/LEIAME.md) over UIKit, and
[`frontends/headless`](frontends/headless/LEIAME.md), with no UI at all, for
anyone who already has their own frontend and just wants emulation from a command
line with a `config.ini`. No emulation line knows which one it runs in.

> Fork note: the Dream bring-up does not go through `Machine`/`Session` yet. The
> current Dream path is `src/msm7201a.rs` (initial `GuestMemory`: SPL at `0x0`,
> page-table scratch, mirrored RAM) plus `src/msm7201a_serial.rs` (serial tap).
> A Dream machine loop and session will grow beside — not inside — the BREW
> ones.

### The modules

The tree follows the subsystems: one folder per subject, one file per piece.

Execution:

| | |
|---|---|
| `cpu/mod.rs` | The `CpuBackend` trait: registers, memory, `run` |
| `cpu/dynarmic.rs` | The Dynarmic implementation, with direct page table |
| `cpu/interpretador.rs` | The `wasm32` backend, where Dynarmic does not exist |
| `cpu/mem.rs` | The guest memory map, in named regions |
| `loader/` | Loading the `.mod` and building the environment, plus `.mif`, `.bar`, `.zip` formats |
| `machine/mod.rs` | The loop, dispatch, and machine state |
| `machine/*.rs` | One submodule per BREW interface — see [`docs/implementacao/01-arquitetura.md`](docs/implementacao/01-arquitetura.md) |
| `msm7201a.rs` | **(Dream)** SoC map: SPL layout, VA→PA section table, initial memory |
| `msm7201a_serial.rs` | **(Dream)** SPL text output: putc tap, `SerialTap`, ring drain |

BREW API (`brew/`, Zeebo-only, not the Dream path):

| | |
|---|---|
| `brew/aee.rs` | The trampoline: address ↔ (interface, slot) |
| `brew/aee_slots.rs` | Each method's name, in vtable order |
| `brew/aee_helpers.rs` | The BREW stdlib: `memcpy`, `malloc`, `sprintf` and friends |
| `brew/objects.rs`, `brew/heap.rs` | Reference-counted objects, and the guest heap |
| `brew/cformat.rs`, `brew/fmath.rs` | The guest's `printf` and floating point |
| `brew/crypto.rs` | AES and MD5, for `ICipher1` and `IHash` |
| `brew/sql.rs` | The `ISQLMgr` SQLite databases, over `rusqlite` |
| `brew/vfs.rs` | Guest paths, pinned to the module directory |

Output:

| | |
|---|---|
| `video/rasterizer.rs` | OpenGL ES 1.1 in software |
| `video/gles.rs`, `video/atc.rs`, `video/paltex.rs` | GL state and compressed textures |
| `video/display.rs` | Framebuffer and 2D ops |
| `video/font.rs` | `IDISPLAY_DrawText` text, with the font the game ships |
| `video/icon.rs`, `video/gif.rs` | Images bundled inside games |
| `audio/` | Sound mixing, and WAV, MP3, MIDI formats |
| `input/` | The Zeebo controller, host gamepads, button map |

Outside the emulator:

| | |
|---|---|
| `session.rs` | A running game |
| `ui/` | UI: screens, library, preferences, saves, translation |
| `main.rs` | Command line and UI launch |

## The loop

`Machine::advance` is one turn. It fast-forwards the clock when the game is only
waiting, fires expired timers, and delivers pending callbacks and threads.

One turn is not one frame. The game may run its whole main loop inside one
callback, and each turn returns only the instruction slice that fit; in Zeebo
Sports Peteca it is a million and a half turns for a few dozen frames. Who orders
a redraw is `eglSwapBuffers` in 3D and the real clock in 2D.

The emulator runs on the UI's own thread. Dynarmic does not cross threads — the
`Jit` is bound to the thread it was born on — and `Session::step` already yields
control every slice of real time, which is what keeps the window alive while the
game runs. A separate thread would bring synchronization with nothing in return.
Same reason the Libretro core delivers one frame per `retro_run`, and the core
registry is drained there instead of from inside the drawing.

## What the project keeps on purpose

Frames are bit-for-bit reproducible: two identical runs draw the same pixels. That
is what proved the rasterizer parallelization and per-frame dump changed nothing,
with 921,600 bytes compared and zero differences. A real GPU backend would cost
that guarantee, and it is one reason it is not at the front of the queue.

**One caveat, measured 2026-09-24: reproduction needs the same extraction cache
state.** Three runs with a warm cache give **760,815 instructions, digit for
digit**; the same ROM with a freshly extracted cache gives **760,921**, with one
extra `CreateInstance` and the heap shifted 64 bytes. The emulator is
deterministic — what changes is what the guest observes of the host, and the cause
is still open: the `.zeebx-pacote` manifest hypothesis was tested and
**rejected**. See [`docs/OPTIMIZING_V0.3.0.md`](docs/OPTIMIZING_V0.3.0.md),
sections 32 and 33. Whoever compares two runs must warm the cache first, or they
will measure this instead of what they wanted.

The clock belongs to the guest, not the host. Time the game measures comes from
executed instructions, and idle time is fast-forwarded instead of spent. Without
that, a game waiting in a loop would spend the wait for real; with it,
`--seconds=N` means the same thing on any machine.

Guesses are marked as guesses. An API served without documentation lands in the
`assumptions` set and shows up in the report. The `IHash` slot order is one
example: SDK 4.0.2 does not ship the header, so the order is a hypothesis, stated
in the code and in the program output.

## Dependencies

Image decoding, sound, rasterization, `printf`, AES, MD5 and resource inflate are
written here. Dependencies cover what is host-side or what would be reinventing
badly.

`dynarmic` is the ARM core, behind `CpuBackend`, and only exists natively: `wasm32`
uses the `cpu/interpretador.rs` interpreter. The UI is in Qt Quick, via `cxx-qt`
(`frontends/qt-standalone`), and `minifb` is the command line's `--window` window,
separate from it. `egui` stays in the core with no window: the recorded key names
in configuration and the frame painter Android and headless use. `cpal` only puts
sound on the card; decoding is ours. `gilrs` gives real gamepads on all three
systems.

`ab_glyph` rasterizes `IDISPLAY_DrawText` glyphs: writing a TrueType interpreter
would be reinventing badly. The font itself is never ours: it is the one the game
ships.

`rusqlite`, with the bundled build, serves `AEECLSID_SQLMGR`. Not convenience: the
console really used SQLite — the `tt_prefs.db` the Z-Wheel ships in the package
starts with "SQLite format 3", and the instructions the module loads as text use
`INSERT OR REPLACE`, `COLLATE NOCASE` and JOIN. Writing an engine for that would be
reinventing badly.

`flate2` inflates the BREW `IUnzipAStream`. `zip` enters for reading only and only
with `deflate`, which is what packagers use. `png`, `zune-jpeg` and `resvg` cover
the formats `.mif` files and resources bring. `rfd` is just the folder picker, via
`xdg-portal` to avoid depending on GTK on Linux. `serde` and `serde_json` hold the
configuration.

`build.rs` at the root existed for one reason only: linking the `libatomic` that
`unicorn-engine-sys` needed, and that reason **left the tree with Unicorn**. What
remains of it is the `cargo:rerun-if-changed` and the record that the `.exe` icon
is compiled by the packages producing executables: `frontends/qt-standalone` and
`frontends/cli`. What has a real-job `build.rs` today is the Libretro core, for a
different reason: the pre-2.34 glibc compatibility shim
([`frontends/libretro/src/r36s_compat.c`](frontends/libretro/src/r36s_compat.c)),
which defines `__libc_single_threaded` and the `__dso_handle`/`__cxa_finalize`
pair as weak symbols.

## Debugging tools

Almost every hard defect in this project was found by one of these, not by reading
code.

`--trace[=section]` shows every API call with arguments and return. `--watch=ADDRESS`
says who wrote and who read a field, which is how you answer "who should have filled
this in?". `--code=START:END` lists executed instructions in a range.

`--profile` shows where time goes on **both** sides: in the guest, per translation
block instead of per instruction, so as not to change what is being measured; and
on the host, the real time of each emulated API method. The second exists because
averages lie — "8 µs per API call" hid that `IIMAGE_Draw` and `IIMAGE_SetParm` alone
were 99% of Pac-Mania's dispatch. `--wall=SECONDS` interrupts on real time, even
from inside a slice, which is what makes profiling a never-ending game possible.

Outside the emulator there is `ferramentas/desmonta.py`, which disassembles a slice
of the game's module resolving literals and strings. It answers the question none
of the inside tools answer — **why** the game branched — and the difference is big:
"`0x78b70` is where the app dies" and "`0x78b70` is the error branch that only
prints the message" are indistinguishable without it.

`--sonda=0xCLSID` serves an unknown class with an observing object instead of
refusing it, and reports at the end which slots the game called, with which
arguments and text. That is how you learn what interface a class is without the
header — the console's `ISQLMgr` came out of one run, whole. The procedure is in
[docs/implementacao/13-classes-desconhecidas.md](docs/implementacao/13-classes-desconhecidas.md).

`--keys=ms:key` scripts input in virtual time, so the same sequence happens every
run. `--dump-gl=DIR` writes one `.bmp` per presented frame. `--seconds` and
`--frames` bound how much runs, in virtual time or loop turns.

The main instrument, though, is the report `run` prints at the end: where it
stopped, with registers and stack; the classes the game asked for and we lack; the
files it did not find; the APIs served by hypothesis; and the game's own log, via
`DBGPRINTF` and ARM semihosting.

> Fork note: none of the above instruments the Dream SPL yet. Dream debugging
> today is `arm-none-eabi-objdump -b binary -m arm`, the `SerialTap`/ring-drain
> in `msm7201a_serial.rs`, and fault addresses from unmapped MMIO. A Dream
> equivalent of `--trace` (trap + log at `PUTC_ADDR`) is the next instrument to
> build.

## Tests

308 test functions, all next to the code they test. Commands are in
[docs/implementacao/17-testes.md](docs/implementacao/17-testes.md).

Some verify algorithms against the spec: the RFC 1321 vectors in MD5, the
FIPS-197 ones in AES. Others verify format parsers against real files: `.mod`,
`.mif`, `.bar`.

The third group is the most useful day to day: each test carries the defect that
generated it in its comment. The `%02d` that made Resident Evil 4 look for
`3d_stg02_0.h2z` when the file is `3d_stg02_00.h2z`. The out-of-Qualcomm-range
ClassID that kept Zenonia from opening. The instruction budget that must be
checked before adding the block, not after.

Beyond that there is the compatibility sweep, which runs real ROMs and grades each
one. It lives in [`src/varredura.rs`](src/varredura.rs) and is **environment
driven**: without `ZEEBX_ROM` the tests warn and pass, because no ROM is in the
tree. With it, each game advances in virtual time and a report comes out — where
it stopped, what it cost, which API and class were missing, which file was not
found, and the registers of whatever broke.

What makes that testing instead of a report is the **baseline**: each game's
summary is compared against what was already known of it, and what changed shows
up as `+`/`-` in the failure. Performance stays out of the comparison on purpose —
one machine's numbers are not emulator behavior. The procedure is in
[docs/implementacao/11-compatibilidade.md](docs/implementacao/11-compatibilidade.md).

> Fork note: `msm7201a` tests skip gracefully without the SPL blob (kept out of
> git), mirroring the `ZEEBX_ROM` pattern. Dream sweep infrastructure does not
> exist yet.

## Known limits

**The dates below matter, and the date matters.** Everything marked *Unicorn era*
was measured before Dynarmic became the backend, and **does not describe today's
emulator**. When Unicorn left the tree nobody redid the measurements; redoing them
is item 1 of [`docs/OPTIMIZING_V0.3.0.md`](docs/OPTIMIZING_V0.3.0.md), where today's
numbers live.

### What is known today (Dynarmic)

Measured on an x86-64 bench, `--release`, profile off, 15,016 virtual ms of Quake:

| | |
|---|---|
| speed | **170%** of the console |
| core pace | **195 million** instructions per second |

Both numbers 2.3x what Unicorn delivered. **The caveat is in the document:** the
scene is not the same as the old measurement, so what compares directly is the
core pace, not the wall clock of two different scenes.

What the long run showed, with 63 ROMs and 60 virtual seconds each, **with the
profile on** — which makes the clock ~43% more expensive and is therefore for
ordering, not publishing: Action Hero 3D 91%, Quake 93%, Ultimate Chess 3D 114%,
Need for Speed Carbon 123%. Pac-Mania does not close 60 s even in 240 s of real
clock: it spends 32 million `GetClipRect` and 16 million `SetClipRect` on the
draw path, and it is the clearest optimization candidate the tree has today.

### What stayed from the Unicorn era

It is here because it is still true as a **lesson**, not as a current measurement.

**Always measure without `--profile`.** It cost 24% in the old measurement — 36 s
vs 29 s on the same work — because the block profile does one table insert per
translation block. The cost sat almost entirely in the ARM slice, so with it on,
emulation looked bigger than it is. The same care applies today, for another
reason: `ZEEBX_ROM_PERFIL` times each API method.

**Ask for the block, never the element.** Geometry was 14% of the time in one old
measurement and fell when `read_attribute` stopped asking one `read_u32` per
component: each request crossed Unicorn's FFI, which looked up the region before
copying four bytes — **57 ns**, vs **0.3 ns** when the same bytes came from a 1 KB
`read_mem`. With 6.65 million vertices in 15 seconds, that was 3.2 s of the
3.6 s draw calls cost, vs 400 ms of actual drawing. The lesson still holds for
every guest array: it underpins today's block reads.

**Per-API-call cost is unknown, not 1.4 µs.** That number measured the trip through
Unicorn's `emu_start`. Today's instrument does not measure the JIT `halt` plus
re-entry: it measures the method body. Until the micro-benchmark exists, treating
1.4 µs as fact means treating a removed backend's measurement as the current
one — and that is exactly the mistake the external review made.

**The rasterizer *is* the bottleneck on the software path.** The sentence "not a
bottleneck today" is also from the Unicorn era. With Dynarmic, the ARM slice shrank
and presentation came to dominate: in the five profiled games it was 54–85% of API
method time, and `eglSwapBuffers` carries rasterization, RGB565 conversion and
copy, because that is where the triangle queue becomes pixels (`frame_rgb565`
calls `flush`). On the card path a different cost set rules — and portable
telemetry still has to show it.

### What nobody has measured yet

- the real cost of an API call with Dynarmic, trampoline included;
- how much of portable time is ARM, how much rasterization, how much `glReadPixels`;
- how many code pages mix with data and weigh on SMC.

The first number comes from a micro-benchmark; the other two, from per-frame
telemetry on the core.
