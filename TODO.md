# Dreamyemu — next steps

The fork targets the **HTC Dream** (MSM7201A, bare-metal SPL). The inherited
Zeebo/BREW backlog below the line stays for reference; Dream work comes first.

## Dream bring-up (in order)

- **Serial trap wiring.** Trap `PUTC_ADDR` (`0x3814`) in a CPU backend and feed
  `(r0, r1)` into `SerialTap` (`src/msm7201a_serial.rs`). The interpretador
  backend is the easy first target (plain Rust, PC visible); Dynarmic needs a
  halt/execute hook. Until then, drain `FORMAT_BUF` / ring table from guest RAM
  host-side after each slice.
- **Ring-drain semantics.** Confirm the `+0 = read index` hypothesis against a
  live run (watch `0x3DD4` advance `+4` and the consumer advance `+0`). If the
  SPL spins on a full buffer, the host must advance the read index.
- **Trace the hardware drain.** Find the consumer of the channel 3/4/5 rings:
  which MMIO it writes (UART candidate: no `0xA02…` literal exists, so the base
  comes via RAM device structs `0x882A1254/58/5C` — find their init). Do NOT
  chase `BLOCO_B23` for serial: EBI range, no post-MMU alias, NAND smell.
- **CP15/MMU in the backend.** The SPL enables the MMU (`SCTLR = 0x1005`,
  `TTBR = 0x84000`, `DACR = 1`) 0x40 in. Dynarmic currently has no CP15/MMU
  support (see `src/cpu/dynarmic.rs`); decide: identity-map L1 in the backend
  from `MAPA_SECOES`, or run pre-MMU only and alias `0x88000000 -> 0x0`.
- **Page-table decode check.** `FUN_00000420`'s descriptor flags (`0x40E`-ish)
  are undecoded (AP/domain/TEX/C/B on ARM1136EJ-S). Decode before trusting
  cacheability in emulation.
- **NAND bring-up.** The `0xB23…` driver's protocol (cmd/status/data at
  `+0/+8/+12`) needs a NAND model to get past SPL flash reads. Dump layout from
  a live run, not from guesses.
- **Dream machine loop + session.** A `Machine`-beside-`Machine`: reset vector
  entry, VIC/timer stubs, fault-to-report on unmapped MMIO (each fault names
  the next peripheral to model).
- **CRT of the fork.** Crate/binary renames (`zeebx` → fork name), README,
  `.info` files, updater key: currently all inherited, all TBD in one rename
  commit when installers exist.

## Diagnostics debt (inherited, still true)

These depended on Unicorn hooks and were removed with the old backend instead of
kept as stubs that print nothing. They need redesigning over Dynarmic's
instrumentation and block-invalidation APIs:

- **`--code=0xSTART:0xEND`** recorded each executed instruction inside a range,
  with `r0` and `lr`. It turned the disassembly, which shows every possible path,
  into the path the game actually took.
- **`--watch=0xADDR`** watched reads and writes around an address and logged PC,
  `lr`, size and value of each access. It answered "who initialized, changed, or
  merely read a corrupt or unexpectedly null field". Not to be confused with
  `watch_dirty`, which stays in the backend for renderer-surface invalidation.
- **`--profile`** counted the hottest ARM blocks and timed emulated API method
  time. It separated hot game loops from dispatcher bottlenecks with measurements.
- **`--wall=SECONDS`** stopped after a real-time limit. It served as protection in
  diagnostics and automation when the virtual clock or step budget did not end a
  stuck game quickly.

**`--trace[=filter]` is not part of this debt**: it traces BREW calls in
`Machine`, not backend instructions, and keeps working with Dynarmic.

## Features (inherited backlog, Zeebo UI)

- Save State
- Fast-Forward
- Turbo Mode
- Rewind
- Cheats
