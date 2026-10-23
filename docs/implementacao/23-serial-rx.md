# 23 — Host-to-guest serial RX injection for the `Cmd>` shell

The parked `UART0:Cmd>` shell can now receive host keystrokes: one planted
byte is echoed and consumed per guest `getc`, a full `hi\r` line dispatches
(`Command error !!!` + re-prompt). This document records the measured receive
path, the injection recipe, and what was deliberately left out. Everything
below is live-measured on the `G1OrigBootloader_nocheck/spl.bin` blob
(`sha256 2fa6827e…`, on disk only under `tests/spl/`, never committed);
guesses are marked HYPOTHESIS.

## 1. What the shell actually reads

Trap tracing on the parked shell (Power+Back combo, prompt first appears at
slice 15794 of a 2000-instr/slice run) shows this call chain per keystroke
poll, oldest frame first:

```
0x88004BEC (shell) -> 0x88004AAC (line input, buf=0x8809FE90, max=0x100)
  -> 0x88003654 (channel dispatch, r0=0 -> [0x882A0001] low byte = 3)
  -> 0x88003FA0 (single-shot getc, r0=3, r1=dst)
```

The dispatch wrapper resolves channel 0 to the active-console slot
`[0x882A0001]` (low byte 3 at the park), channels 3–5 fall through to the
same `0x88003FA0` body. `getc` itself never spins; the spin lives in the
line-input loop, which re-polls `0x880047FC` after every empty `getc`
(measured: `0x880047FC` entered from `lr=0x88004B90`, returns in the parked
state — the line never aborts across ~14k observed parked slices, so its
return value is 0 there; the exit path on nonzero return is NOT decoded).

`getc` reads the console UART at the live base `0xB2800000` (slot
`[0x882A1254]` contents, stable from boot — the same base the TX path
programs):

| Register | Semantics in `getc` | Parked value (measured) |
|---|---|---|
| `[0xB2800008]` bit 0 (`0x01`) | RX-data-ready: 1 = a byte is available | 0 (clear) |
| `[0xB2800008]` bits 5–6 (`0x20`/`0x40`) | error: byte discarded, `getc` returns 0 | both SET (`0xFE`) |
| `[0xB280000C]` low byte | RX data byte | `0x3E` (last TX prompt char; TX and RX share the offset) |

The parked `0xFE` is the guest UART init's own value with bit 0 cleared by
the command-ACK plant (the init writes `0xFF`-shaped status, the ACK hook
clears bit 0 when a slice stops in `0x88004274..84`). Error-bit identities
(overrun vs framing) are UNKNOWN — the blob only shows "treat as no-data".

The older `0x88016590` RX-test words (`[0xB2F00834]`/`[0xB2E00C20]`) and the
`0xA8081C00` flag gate an *earlier* boot stage, not this shell: planting them
is unnecessary at the `Cmd>` park (proven: the full line cycle works with
only the `0xB2800000` plant). No `0xB2800008` polling was observed anywhere
except `getc`; the TX path uses direct writes (`str r6,[r4,#0xC]`) and never
reads the RX-ready bit in its taken (direct-TX, `[+0x14]=1`) mode.

A second consumer detail matters for the host display: the line-input echo
goes out through `PUTC(0, c)`, whose raw `r0=0` the serial tap records as
**channel 0**, while the prompt and error text arrive on channel 3. Typed
`hi` therefore lands in the tap as `(0, "hi")`, and `Command error !!!` as
`(3, ...)`. The harness `novos` stream now forwards both (channel 3 then
channel 0 per slice); the bulk ring path (`saida`/`texto`) carries nothing
on this path (measured empty).

## 2. Why a naive plant floods

Planting ready + byte and leaving them (per-slice re-assertion, no consume
hook) delivers the byte but never clears the ready bit — real silicon clears
it when the data register is read, the stub never does. The guest's own
post-read re-check (`ldr` status at `0x8800403C`, `tst bit0`, `bne` drain at
`0x88004044`) then sees a stuck-ready bit and rings the same byte until the
4 KiB ring fills (`ENQ ch=3 byte=0x68 lr=0x88004058`, the drain loop at
`0x8800404C..60`). Every later `getc` dequeues ring bytes instead of polling
hardware, so one plant produced ~47 `h` echoes *per slice*, forever
(measured through slice 29999 with no line completion). The byte is consumed,
but the line never ends.

## 3. The injection recipe (what the code does)

Three cooperating pieces, all fenced `TEMP/RX work` in `src/msm7201a.rs`
(+ a 16-line SDL hook):

1. **Queue** (`rx_enfileira`, public): host keystroke bytes in, filtered to
   what line input accepts (printable `0x20..=0x7E`, `0x08`, `0x0D`; anything
   else dropped; cap 64). Empty queue = zero behavior change.
2. **Per-slice plant** (Budget arm, next to the UART TX-complete plant):
   while no byte is in flight and `[0xB2800008]` bit 0 is clear, shift one
   byte and plant it: `[+8] = (status | 1) & ~0x60` (error bits cleared, all
   other guest status bits preserved), `[+0xC] = (old & ~0xFF) | byte`.
   Logged as `RXPLANT byte=0x..`.
3. **Synchronous consume trap** (armed once at setup, `0x88004034` — the
   `ldr r3,[r4,#0xC]` data load inside `getc`, `r4` = UART base): when it
   fires with `r4 == 0xB2800000` and a byte in flight, clear
   `[0xB2800008]` bit 0 immediately, so the post-read re-check exits with
   exactly one byte and no drain. Logged as `RXCONSUME byte=0x..`.

The choice of `0x88004034` (rather than the error-discard loads at
`0x88004018/28`, or the ring-drain load at `0x8800404C`) is what makes it
exact: that PC executes only on the delivering path. The ch4/ch5 gate
(`r4`-check) keeps the other UARTs on stub behavior.

SDL wiring (`frontends/sdl/src/main.rs`): `video.text_input().start()` plus
an `Event::TextInput` arm that enqueues each typed byte (`\n` -> `\r`).
`TextInput` — not `KeyDown` — carries printable characters, so the
P/S/H/B/T power-button shortcuts keep working untouched.

Measured line cycle (probe enqueue of `h`, `i`, `\r` at park+300 slices):

```
SER f=15794 "\r\nUART0:Cmd>"      <- parked prompt
SER f=16101 "h"                   <- echo, 7 slices after enqueue
SER f=16119 "i"
SER f=16137 "\r\nCommand er"
SER f=16138 "ror !!!\r\n\r\nUART0:Cmd>"   <- dispatch + re-prompt
RXPLANT/RXCONSUME strictly alternating (0x68, 0x69, 0x0d), one each
```

`cargo test -p zeebx --lib`: 719 passed + the 1 by-design discovery-test
failure (unchanged); `cargo build --release --locked -p zeebx-sdl`: clean.
Idle runs (empty queue) behave exactly as before: no plants, the trap never
acts (in-flight is `None`), the only cost is one mutex lock per slice.

## 4. What was tried and discarded

- **Planting without the consume trap** (ready bit re-asserted per slice):
  works once, then the `h` flood above — the stuck-ready drain rings the
  same byte ~4 KiB deep. Discarded for the trap.
- **Planting the `0xB2E0_0C20` ready words / clearing `0xA8081C00`** (the
  older RX-test path): advances an earlier boot stage one step but produces
  no serial output and is unnecessary at the `Cmd>` park. Not planted.
- **Reading the data byte from a neighbor of the flag** (`help\r` at
  `0xA8081C01`): no effect — the char buffer is not adjacent to the flag.
  The data address is `[0xB280000C]`, found by trapping the post-ready
  consumer instead of guessing neighbors.
- **KeyDown-based SDL wiring**: conflicts with the P/S/H/B/T button
  shortcuts (same physical keys). `TextInput` avoids the clash entirely.

## 5. Open questions

- `0x880047FC`'s nonzero-return path (line abort / channel switch) is never
  taken at the park but is not decoded — a real channel-change event (USB
  attach, HYPOTHESIS) may exercise it, and the injected line would abort.
- Long lines are untested: line input caps at `maxlen-1` (255) chars, then
  takes the buffer-exhausted retry path (return 0, HYPOTHESIS: re-prompt).
  A 64-byte queue cap bounds the host side; the guest side needs a typing
  run past 255 chars to observe.
- Backspace (`0x08`) is accepted by the queue and decoded in the blob
  (cursor-back only, no space-overwrite erase — display-minimal), but no
  backspace keystroke has been injected live yet.
- The `0x8800404C` ring-drain load is not consume-trapped: in direct-TX
  mode (forced `[+0x14]=1`) that path is unreachable, but if TX ever takes
  ring mode with a byte in flight, the same stuck-ready flood would return
  through that door. HYPOTHESIS only — no evidence either way.
