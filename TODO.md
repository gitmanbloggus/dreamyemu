# Dreamyemu — next steps

The fork targets the **HTC Dream** (MSM7201A, bare-metal SPL). The inherited
Zeebo/BREW backlog below the line stays for reference; Dream work comes first.
`src/brew/` is **frozen** (Dream runs Linux, not BREW): no extensions, refactors
or fixes there for Dream work; removal, if ever, belongs with the fork-rename
commit.

## Dream bring-up (in order)

- **Serial trap wiring, interpretador half — DONE.** `trap_pc`/`untrap_pc`
  (`src/cpu/interpretador.rs`, test
  `armadilha_pc_observa_r0_r1_e_nao_muda_o_guest`) feeds `(r0, r1)` into
  `SerialTap`. The live run traps post-MMU `PUTC_ADDR_POS_MMU`
  (`0x88003814`): serial output happens at the VA, not pre-MMU `0x3814`.
  Dynarmic half is OPEN — another agent is on it, do not implement here.
- **Emit routing — decoded from the blob (evidence).** `0x880018D4`
  dispatches on channel state: state A at `[0x882A1CD0]`, state B at
  `[0x882A9584]`. `CH_WRITE` (`0x88003890`) drops channels 0–2, byte-writes
  3–5 via `PUTC`, channel 6 bulk via `0x333B8`. `CH_PUTC` (`0x880040A4`)
  selects direct-TX vs ring-enqueue by the device `+20` bit; device `+8` is
  TX-ready (polled, spins at `0x880040E4` while clear). Provenance:
  disassembly of the three functions; path B (`[0x882A1CD0] == 2` →
  `mov r0, #3`, direct channel-3 byte output) proven live by the
  `spl_vivo_primeiro_byte_na_serial` frontier test.
- **Ring layout — decoded from `0x88003DD4` (evidence).** `RING_TABLE`
  `0x882A94FC`, 16 bytes/channel (`channel << 4`); data base `[0x882A24FC]`
  + `channel * 4 KiB` buffers; `+0` read index, `+4` write index (wraps at
  `0x1000`), `+8` full/blocked flag, `+12` ready. Ring init `0x3CEC` zeroes
  `+0/+4/+8` and sets `+12 = 1`. Host-side drain per slice (advance read to
  write, clear `+8`) works — implemented inline in the `b2a00c10` discovery
  test — but is not yet a reusable harness: extracting it is OPEN.
- **CP15/MMU in the backend — interpretador DONE, mapping question OPEN.**
  Flat-model MCR/MRC (`arm_coproc` in `src/cpu/interpretador.rs`): accepted
  and stored, mapping unchanged since both aliases are pre-mapped; the
  MMU-enable sequence (`SCTLR = 0x1005`, `TTBR = 0x84000`, `DACR = 1`) runs
  through. OPEN: whether physical post-MMU accesses (`0xA8081000`, heap
  `0xA8780000`) are identity or alias (sparse-L1+L2 hypothesis) — the
  section table maps that range only at VA `0x92400000` / `0x90D00000`.
- **Frontier (live run, interpretador). SPL reaches its `UART0:Cmd>` shell
  and parks in a two-site input-wait loop (delay callers `0x880305C4` +
  `0x88030790` cycling; tap frozen across runs). Full narrative in the tap
  (114K): DMOV init (16 channels) + `flashn_dm_init done.`, NAND whitelist
  (`maker_id=EC, device_id=AA` → entry 8), MISC partition + SKU writethrough
  attempts (stub failures, non-fatal), `SKUID addr=0xA8081BF9` (header-parse
  copies into the `0xA8081000` peripheral stub), `Initialize wlan data
  success`, `Clearing RAM...`, `Load Recoveryimg header, addr=0x502C0000`
  (`taget=0xA8100000`, sic) served page-by-page from the entry-8 image, then
  `Boot image is not exist` (0xAA fill is no valid image — graceful abort),
  `szCPLDstrlen=0x5`, `UART0:Cmd>`. The run is delay-bound but progressing
  until the prompt; host keystrokes now reach the shell through
  RX injection (queue + `[0xB2800008]` bit 0 / `[0xB280000C]`
  data byte, cleared synchronously at the `getc` load `0x88004034`;
  SDL text input wired; verified live, see
  `docs/implementacao/23-serial-rx.md`). Open RX leftovers:
  decode `0x880047FC`'s nonzero-return path (never taken at park),
  live-test a >255-char line and a backspace keystroke.
  Stubs so far (all zeroed RAM windows answering "what comes after?"): cold
  probe, `0xB5400000`, `0xAA0FC000` (+ready bit forced at `+0x44`),
  `0xA8081000`, `0xBD000000`, `0xB2A00C00` (+`CMD_PTR_RDY` `0xB2A00C10` /
  +`STATUS` `0xB2A00E10`, per-channel `+4N` pre-set), `0xB2800000`
  (+TX-ready `+8`, +TX-complete `+0x14`). Demand-mapped on first fault
  (never pre-mapped): `0xB5300000`, `0xB2300000` (NAND controller proper),
  `0xB3200000`, `0xAA0F3000` (WLAN), `0xA8280000`/`0xA8290000`
  (literal-pair devices, 64 KiB apart), `0xB1D0000` (magic-fill
  `0x47EF4/0x3C00/...`, WLAN-adjacent), `0xA8230000`/`0xA8240000` (computed
  from the `0xA8240000` pool; the fault pc lies — data fault, stale pc —
  trust the address), `0xA8000000` (register block: literals `+0/+4` x4-6,
  `+10/+1010/+1020`; doubly aliased at VA `0x90D00000` + `0x93C00000`).
  Plants (harness-only; BSS-zeroed, so planted after the zero loops): DMOV
  count `[0x882F79F8] = 1`, emit path B `[0x882A1CD0] = 2`, ring data base
  `[0x882A24FC] = 0x88081000`. Heap window `0xA8780000` mapped from SPL
  printout evidence (`flash_driver_phys_buffer=0xA8780000, ..._SIZE=0x3400`).
  Partition-staging RAM `0xA6000000 x8` mapped from address arithmetic
  (`dst = (arg & 0x1FFFF) - 0x5A000000 + 0x740000` at `0x88009D50/68`) plus
  the live `str r3, [ip]` fault at `0x88015704` (`ip = 0xA6740000`).
  Post-WLAN clear/memset targets mapped from the guest's own loader calls:
  `0xA6C00000 x0x4B000` (live MEMSET trap: dst/len/lr `0x88002244`) and
  `0xA8100000 x0x20000` (recovery chunk: live REC trap at the `0x88008238`
  entry showed `src=0x502C0000 dst=0xA8100000 len=0x20000`; the copies run
  through the served core-loop memcpy `0x88008360`, staging `0x882A9DEC`).
  Calibrated-delay elision: the `0x88004330` counter loop never exits on
  stubs, so the host resumes slices stopping in `0x880042C0..0x88004358`
  at the loop exit (`0x88004358`, "time passes instantly"), with a 40-round
  force+step pump per slice so bounded 1000-retry polls (e.g. the
  `[0xB1D00018]` bit poll) clear in ~25 slices. OPEN interpretador
  question: planting the counter exactly (`[0xB5400020] = r4+0x10000`;
  live r4=0, r5=0x4B00, plant lands, code byte-exact, `alu`/`condicao`
  review correct) still never exits — evidence preserved in the elision
  comment in `src/msm7201a.rs`. The serial ring is drained once more
  after the loop so FAIL-path prints one instruction before a fault are
  not lost. Device-completion plants (all "report instant completion",
  all verified by the run advancing past the wait): `[0xB1D00018] |= 0x8000`
  (1000-retry poll + caller `blt` retry = silent infinite loop; OR not
  assign — guest magic-fill never touches `+0x18`); UART `[0xB2800008]`
  bit 0 cleared pc-gated in the `0x88004180`-init spin `0x88004274..84`
  (live SPIN probe: r0=`0xB2800000`); UART `[0xB2800014] |= 1` per slice
  (the `0x880040D4`-loop's exit A; one-shot setup was insufficient — the
  loop is newly reached post-init; phase 2 re-set of `+8` subsumed).
  Harness lesson (now a doc comment on `trap_pc_mem`): same-address hooks
  REPLACE — a second hook silently evicts the first (observed once: a
  length probe evicted the serve-state hook, dead serve, pre-`Clearing
  RAM` stall).
- **Trace the hardware drain — OPEN.** The consumer of the channel 3/4/5
  rings: which MMIO it writes (UART candidate: no `0xA02…` literal exists,
  so the base comes via RAM device structs `0x882A1254/58/5C` — find their
  init). UNKNOWN kept: UART-vs-USB channel assignment; drain consumer
  identity; `0x882A1254/58/5C` init. Do NOT chase `BLOCO_B23` for serial:
  EBI range, no post-MMU alias, NAND smell.
- **Page-table decode check — OPEN.** `FUN_00000420`'s descriptor flags
  (`0x40E`-ish) are undecoded (AP/domain/TEX/C/B on ARM1136EJ-S). Decode
  before trusting cacheability in emulation; the sparse-L1+L2 shape is a
  hypothesis, not a fact.
- **NAND bring-up — in progress.** The `0xB2…` driver's protocol (cmd/status
  at `+0/+8`, data at `+12`, per-channel instances at `+4N`) needs a NAND
  model to get past SPL flash reads. Dump layout from a live run, not from
  guesses.
- **Current stop: parked at the `UART0:Cmd>` shell — NEEDS UART RX.**
  After `Boot image is not exist` the SPL prints `szCPLDstrlen=0x5` and
  `UART0:Cmd>`, then polls for serial input in a nested two-delay loop
  (delay callers `0x880305C4` + `0x88030790` cycling; the `0x8803075C`
  command check exits when its `[flag+#0xC00]` byte is clear). No input
  model exists, so it waits forever. Next workstream: model UART RX
  (deliver bytes to the flag/ring the `0x8803075C` loop checks) or drive
  autoboot past the prompt — then the boot-image load path.
- **Screen (framebuffer proven pixel-perfect, host rendering OPEN).**
  With a VALID boot image the SPL reaches the display path instead of the
  shell: it NAND-loads the 0x4B000 splash (`0x50140000` → guest blocks
  `0x12A-0x12C`, second image `0x50200000` → `0x130-0x132`) to `0x80200000`,
  blits it to the framebuffer `0xA6C00000` x0x4B000 (320x480 RGB565,
  `lr=0x88027274`), and calls the display init `0x8802ED68` (fb + 320x480
  geometry) which fills panel registers (strh storm to `0xA824…` +
  `0x88017350` bit-banger) after enabling `0xAA000000` (+0/+4 = 2). The
  stock asset (`assets/Default_US.raw565`) served from
  `ferramentas/nand_conteudo.py`-patched blocks lands **pixel-perfect** in
  the fb (post-run dump byte-identical; rendered PNG shows the T-Mobile G1
  splash). Host window DONE: `frontends/sdl` (`zeebx-sdl` binary, sdl2
  crate) reuses the same live harness (`executa_spl_vivo`, extracted from
  the discovery test into a shared pub fn + `VivoFim`, with a per-slice
  frame/serial callback and early-stop) and shows the fb live at 2x with
  serial on stdout (verified on-screen: splash in a "Dream SPL" window).
  New `interpretador` lib feature (opt-in; desktop default untouched,
  libretro core unaffected) compiles the backend outside tests/wasm/ios.
  The SPL never programs MDP (no `0xAA200000`+/VA-alias faults on
  any path). The run continues to the kernel handoff (`0x10008000` fetch,
  `ANDROID!` header validated, cmdline + partitions parsed). Still open:
  (1) MDP programming source — a real boot.img booting Linux (kernel mdp
  driver) or an undiscovered SPL branch (the SPL's own screen path ends
  at panel init; nothing tells MDP where the fb is); (2) input (shell
  waits at `UART0:Cmd>`, window has buttons but no input path yet). The
  `ram_banco1_fis` PA mirror (`0x10000000` x64, section-table VA+0x70000000)
  lets the handoff land in real image bytes (serve hook mirrors VA-bank
  writes to PA).
- **Virtual buttons — DONE (v1, headless-verified).** `Botoes`
  (pure data, ungated) + `executa_spl_vivo_com_botoes` (same harness +
  shared button state; `interpretador`-gated like the run itself — this
  also repaired `cargo test -p zeebx-cli`, which the ungated harness had
  broken). The SDL window grew a 6-cell button bar (PWR/SHUT/HOME/BACK/
  TRCK/RBT; click or P/S/H/B/T, R/Enter = reboot with combo held, Esc/Q
  = quit) plus `--botao <shutter|home|back|trackball> --sair` for
  headless runs. Mechanism: MISC planted race-free in a `memcmp`
  (`0x88015B80`) trap (per-slice plants lose to the guest's NAND refill —
  proven by the retired MISCCMP witness); power
  (`[0xAA000000+0xC0]`) + reset-reason (`[0xAA0FC080]`, page pre-mapped)
  planted per slice. MISC fields decoded: `0x882F3398` takes
  `boot-recovery`→3, `update-radio`→4, `update-hboot`→5;
  `0x882F3398-0x7F0` takes `EnterBootloader`→6, `EnterFastboot`→2. Live
  results (all diverge from the no-button kernel-jump baseline):
  shutter→HBOOT wait init writes 3/0x100 to `0xB1600000` (new
  `perif_b160_stub`, identity UNKNOWN) then joins the `UART0:Cmd>` shell
  spin; back→same shell spin (fastboot path, needs USB); home→same
  kernel jump but `boot reason=0x77665502` flows into the cmdline
  (`androidboot.reason`, length 268→298); trackball→RADIO path reads
  NAND blocks `0x38E+` then falls through to the kernel jump. The
  reset-reason low byte per physical key is a HYPOTHESIS (no keypad
  driver found; indexed slots `[0xAA000000+(idx<<4)+0xD0]` NOT wired —
  reader `0x88014B28` has no ARM `bl` caller). Next: UART RX input for
  the `Cmd>` shell, USB for fastboot, SD/FAT32 (`DREAIMG.nbh`, user has
  the NBH) for the HBOOT NAND-flash path.
- **HBOOT SD flash — read chain DONE, flash decision mapped, item
  writes not yet firing.** `ferramentas/cria_sd.py` builds a self-consistent
  FAT32 image (MBR type `0x0B` — the SPL's FAT32-only opener *rejects*
  1/4/6/0x0E at `0x8801C7F8`, proven live; `FAT32   ` VBR string; 8.3
  `DREAIMG NBH` entry; file bytes streamed from
  `assets/DREAIMG/DREAIMG-RC29.zip`, never extracted into the repo;
  readback sha256-verified) at `tests/spl/sd.img` (93 MB, gitignored).
  Harness serves sectors at `0x8800D644/D488/D67C` (arity pinned live)
  and fakes detect/init (`0x8802E534`→1, `0x8800D11C`→6=HC); host
  memset/memcpy skips (`0x880155D4/0x8801566C`) were required — the NBH
  flow memsets the whole 91 MB staging buffer otherwise. Proven live
  (shutter button + SD): MBR→VBR→root dir→FAT walk→91 MB into
  `0x80200000` (needs the `ram_banco2` 46 MB pre-map), `NBH header
  correct`, TOC walk prints all 7 items, per-item RUU checks run
  (`0x8800A094` ×7). Gates forced: device model UTF-16LE at `0x882F2A48`
  (sync trap at `0x880190E8` — a same-slice guest refill beats per-slice
  plants, same class as MISC) and need-update `[0x882AD65C]=1` (virgin
  NAND reads as "no update"). Stall point, precisely mapped: `ChkImg`
  returns `0x27` ("Wrong Image") after the update UI and `1ACC8` bails
  to normal boot; the per-item updater (`0x8801A67C` → `0x880194FC`
  → `0x88008F80`) never runs — its only callers (`0x8801B20C/43C`
  wrappers) are never invoked in any traced flow, and flagB
  (`[0x882AD614]`, the 1AC18-update-UI gate) is never set by the guest
  (forcing it takes an early-abort 0x27 path with no flash). NAND
  write-through at `0x88008F80` + `--salvar-nand` + reboot-with-same-NAND
  are wired and capture the normal-boot writethroughs (verified by
  image diff); no NBH item writes have landed yet. Next: find what
  invokes the per-item updater — likely an HBOOT-UI key confirmation
  (`0x88003444` waits for input?) or the 0x27-is-success reading is
  wrong; then flash SPL/radio/boot/recovery/splash/system and reboot
  into them.
- **Linux loading — boots to early mm init, then dies twice.** Real
  `boot.img` kernel + ramdisk patched into NAND guest blocks
  (`ferramentas/nand_linux.py`: header+kernel+ramdisk over the
  recovery blocks; self-check PASS). Handoff verified live:
  r0=0, r1=1440 (`0x5A0` trout), r2=`0x10000100`, r3=`0x10008000`.
  CPU Main ID seeded at reset (`0x4117B360` ARM1136EJ-S — the
  kernel's procinfo lookup needs `(id & 0x7F000)==0x7B000`);
  `CPS` (incl. `cpsid i`) + `MOVS pc,lr` implemented in the
  interpretador (flat model: plain branch, no SPSR); kernel VA
  window demand-paged on fault (`0xC0000000..0xCC000000`, seeded
  from the PA alias; ioremap probes get zeros); GPT/DGT
  free-run on host time + VIC STATUS (`0xE0000080` bank0) recomputed
  per slice from COUNT/MATCH/INT_EN (INT_EN kernel-owned, never
  planted; handler gate `[dev+0x2C]!=0`); jiffies (`0xC02AB638`)
  +1/slice until the first real tick completes, then once per
  tick (per `/tmp/opencode/irqspec.md`: VIC `0xE0000000`, GPT irq
  7/DGT irq 8, ack purely VIC INT_CLEAR, ISR `0xC002AAD0` is a
  5-insn tail-call, backend has NO IRQ support — option B
  host-side ISR call recommended first). ATAG page mirrored
  VA `0x80000100`→PA `0x10000100` at the trampoline (per
  `/tmp/opencode/memfix.md`: trout fixup hardcodes one bank
  `{0x10000000,0x06500000}`, SPL never emits ATAG_MEM, tag check
  reads VA `0xC0000100`; verified live: `ATAGRD va0=0x2
  va1=0x54410001`). Full ARM IRQ path landed in the
  interpretador (banked R13/R14 + SPSR per mode,
  `troca_modo`, IRQ entry with high-vector select, WFI
  sleep-until-line (budget-bounded), `msr`/`mrs` SPSR,
  `ldm^`/`movs pc,lr` restore via `retorno_excecao`;
  `IRQ_VEC_PEND_RD` planted ahead of the entry-macro loads;
  verified by 6 new unit tests + zero behavior change on the
  live boot — delivery stays inert until `setup_irq` runs,
  which is past the current crash frontier). Kernel serial captured
  two ways: THR drain per UART (`kernel_tx`) + end-of-run
  `printk` buffer scan (`kernel_log`, `VivoFim` fields printed
  by SDL as `kernel:`/`klog:`). First kernel logs, live
  (`/tmp/opencode/klog_boot2.txt`, boot 2's buffer):
  `Linux version 2.6.25-01843-gfea26b0 ... #6 PREEMPT`,
  `CPU: ARMv6-compatible processor [4117b360]`, `Machine:
  trout`, `Warning: bad configuration page`, `Ignoring
  unrecognised tag 0x00000000`, `Memory policy: ECC disabled,
  Data cache writeback` — then silence (dies in mm init,
  pre-console; `msm_putc` was the wrong address, THR drain
  used instead; decompressor prints nothing — no UART
  faults). Two deaths, both pre-console, same run: boot 1
  reaches scheduler-ish code then returns through lr=0
  (`0xC0021A7C movs pc,lr` with a zeroed exception frame,
  entered via A `0xC00405D0` → B `0xC0021A84` without an
  exception — `JUMPBACK fatia=90797 de=0xc0106520 para=0x438`)
  and reboots through vector 0; boot 2 faults walking a
  sorted resource/list insert at `0xC001202C` (`r1=0xC02EBC44
  [r1]=0x10000000`, next=NULL → `list_entry` gives
  `0xFFFFFFE8` → unmapped). `[0xC02EBC44]=0x10000000` is
  written fresh per boot (~slice 87775, mm init) — not
  stale. ATAG page gets reused by boot 1's mm init
  (bootmem `alloc_bootmem_node` + `INIT_LIST_HEAD` at
  `0xC0000100` via `zone_wait_table_init` — zone wait-table,
  legitimate first-fit; caught live), so the ATAG VA page is
  re-planted from the snapshot at every trampoline crossing —
  otherwise boot 2 reads stale content despite the fresh PA
  mirror. Boot 1's own death is earlier and independent, now
  identified (static IDs in `/tmp/opencode/crash_ids.md`):
  scheduler slow-path tail A (`0xC00405D0`: finish_task_switch
  + preempt_enable + conditional preempt_schedule, sole caller
  the exception-return path at `0xC0021A80`) returns via its
  stacked pc into B (`0xC0021A40-0xC0021A9C`, entry-armv.S
  restore tail: `cpsid; ldr lr,[sp,#60]; msr SPSR; ldmdb;
  movs pc,lr`), which restores a zeroed frame
  (`[sp+60]=lr=0`, virgin demand-mapped stack page) and jumps
  through `lr=0` into the reset vector — the path was entered
  with no exception ever taken, so no frame was ever pushed
  (no abort-vector traffic). The walked list is bootmem
  `bdata_list` (head `0xC02AFC00`, file-initialized empty);
  boot 2's walk fault is stale-head + fresh node, secondary
  to the reboot. Next: option-B ISR call once setup_irq is
  reached; the exception-return path needs a real frame or
  the scheduler path must not be taken.
- **Dream machine loop + session — OPEN.** A `Machine`-beside-`Machine`:
  reset vector entry, VIC/timer stubs, fault-to-report on unmapped MMIO
  (each fault names the next peripheral to model).
- **CRT of the fork — OPEN.** Crate/binary renames (`zeebx` → fork name),
  README, `.info` files, updater key: currently all inherited, all TBD in
  one rename commit when installers exist.

## IRQ completion (Dream, open — live evidence 2026-10-23)

Timer IRQs deliver once then go silent; the boot parks after `neigh_init`
(idle loop, no more context switches). Proven live so far:

- `cpsid`/`cpsie` were inverted TWICE: the first \"fix\" matched a
  swapped objdump print table (F108 shown as `cpsie`) and kept the
  inversion live — every guest disable enabled and vice versa. The
  real mapping (verified by assembling both mnemonics with
  arm-none-eabi-as: `cpsie i`=0xF1080080/imod 2/CLEAR,
  `cpsid i`=0xF10C0080/imod 3/SET) landed 2026-10-23 with the
  regression test corrected the same way. This inversion was the
  sched.c:4032 BUG_ON: __do_softirq's post-loop cpsid left I
  clear instead of set.
- First-tick catch-up loop (`-ETIME` from wall-clock COUNT) broken by
  forcing `clockevents_program_event` success (TICKBRK).
- Nested-tick `BUG_ON` fixed with a rising-edge delivery latch
  (`ANTES7`/`ANTES8` in `vic_irq_pendente`); the STATUS-bit variant
  stole the first edge (zero TICKH) and was reverted.
- Guest dispatch reads `VIC_IRQ_STATUS` (`0xE0000000`); the zeroed
  stub took the spurious path, so one VIDX/DISP never reached
  `msm_timer_interrupt` (TICKH). Served pending bits there per slice.
- `TIMERSTATE` carries live CPSR `I=` + `modo=` (via
  `estado_completo`); samples show `I=0` SVC in idle, yet every
  initcall reports "returned with disabled interrupts".
- Dispatch reads `VICVECTADDR` (`0xE00000D0`, then `0xD4`, uses the
  second), expecting the pending IRQ **number** or `0xFFFFFFFF`
  when idle — not `IRQSTATUS`. Proven by disassembling `__irq_svc`
  (`0xC00215E0`) + `msm_init_irq` (`0xC000E298`); served per slice
  and synchronously on every MATCH/EN write in `es_mem`.
- Delivery gate split into level (`vic_nivel`, used by all plants)
  vs edge (`deve_entregar`, delivery-gated so a non-delivering
  poll can never consume the edge); plus one-shot-per-MATCH
  (`ULTIMO_ALVO`) so a frozen MATCH can never refire. `IRQLINHA`
  samples the I-bit directly instead of polling the line.
- Guest-paced counters (`CONTAGEM_GPT` +4/slice, `CONTAGEM_DGT`
  +72/slice ≈ 0.1 ms/slice at 19.2 MHz) replacing wall-clock
  `epoca`: MATCH deltas stay in the future. TICKBRK started as a
  pure success-forcer, went observe-only for the -ETIME
  diagnosis, and is now a host-side re-arm (see below).
- Restored the wide `udelay` skip (a duplicate same-address trap
  had evicted it; every driver `mdelay` was executing flat-out).

Still open (2026-10-23 evening):

- The sched.c:4032 BUG_ON is GONE: root cause was our own cps
  polarity inversion (second one — the first "fix" matched a swapped
  objdump table). GAS-proven now: cpsie=0xF1080080, cpsid=0xF10C0080.
  PREENT passes I=1/preempt=0 repeatedly. Frontier moved to
  t≈1.48s: boot walks driver initcalls (smd, hw3d, H2W, ashmem,
  yaffs, io scheduler), survives `mdp_init` (4 MMIO windows
  stubbed: 0xE001/2/5/60000, table loop of 562 pairs), then the
  1.48s idle spiral: "timer late, reprogram it" + "no smem clock"
  repeat every idle entry (widened 128 KB log_buf dump proves it;
  the 16 KB v2 dump looked frozen). Self-sustaining: each fbcon
  render makes the next deadline late. WAIT/DONE completions all
  pair (no kthread hang); SCHED activity continues past 91k
  (uncapped run proved it). The CONDRV text tap proves the flush backlog (t=0.0s
  messages still draining at f=82k); the widened 128 KB dump shows
  the spiral tail. Root cause, proven 2026-10-23/24: (1) consecutive
  PROGEV sampling + disassembly showed the passed expiry FROZEN
  while now advanced +10M/call — the old plant bypassed
  set_next_event, freezing dev->next_event; the +1-period lead in
  the PROGEV mirror made program_event succeed FOR REAL (was_r0=0),
  and with the plant removed the guest drives 10ms MATCH deltas
  itself (klog 1.48→1.65s). (2) Deliveries then froze past f≈100k:
  the 64-instruction poll counter strides over the brief unmasked
  windows (deterministic aliasing). Landed event-driven delivery
  (unmask flags irq_pendente, served at next loop top) + dirty
  tracking + livre-gated latch + wake-time delivery; verified
  nent 150→151 with unit tests. (3) Root cause of the freeze: the
  registered clockevent handler was hrtimer_interrupt
  (oneshot/NO_HZ), whose path never programs the next event — no
  periodic ticks, no unmask, no reprogram, frozen MATCH. Fix:
  append `nohz=off highres=off` to ATAG_CMDLINE at handoff (tag
  grown 75->83 words, tail shifted; VA src + PA mirror + VA kernel
  copy). The tick is now PERIODIC.
- SDCC DONE (2026-10-24): mmc0 (PIO, eject=1) and mmc1 (DMA,
  eject=0) both probe cleanly on the 0xE1000000 stub; mmc1 even
  reports a handled Command timeout and boot continues past both
  into ram_console/Bluetooth/clocks/RTC (t=34.79s). No TRACE stop
  on 0xE100 since the stub landed. Card contents not needed: the
  rootfs is the boot.img ramdisk (initramfs, /init present), not
  SD/YAFFS — no block-device data path on the critical path to
  first shell.
- Frontier t≈54s, BLOCKED on recurring tick BUG (2026-10-24):
  `kernel BUG at kernel/posix-cpu-timers.c:1325!` (MemoryFault pc
  0xC00251F8) fires at racy initcalls (recent_mt_init in one run,
  msmsdcc_dbg_init in the next) — timing-dependent, not tied to one
  driver. Full SPL cmdline now logged (ATAGCMD0): board_trout.* +
  androidboot.* + no_console_suspend=1, NO init=/root=/console=
  (hence the `init=/init` append; ramdisk has /init but none of the
  kernel's 4 fallbacks). IRQ-gating the kick did NOT stop the BUG,
  so the kick is exonerated as sole cause. New prime suspect:
  the TICKBRK `regs[0]=0` force — a one-shot-era leftover firing on
  EVERY periodic tick inside tick_handle_periodic — removed
  (observe-only now; was_r0 in the next run tells whether the
  PROGEV mirror alone keeps program_event succeeding). If the BUG
  persists, next suspects: the mode-blind loop-top delivery paths
  (nested entra_irq during outer softirq clobbers spsr_irq?),
  PROGEV mirror (+10M lead corrupting the alarm path?) and the
  handler-swap write.
  DIAGNOSED 2026-10-24: disassembly of run_posix_cpu_timers entry
  proves the BUG_ON: `mrs r3,CPSR; tst r3,#128; bne ok; bl __bug`
  = BUG_ON(!irqs_disabled()); fault cpsr confirms I=0; stack shows
  scheduler_tick+0x1f0 → run_posix_cpu_timers+0x38. Root cause is
  OURS: all loop-top delivery paths checked only I==0, never the
  mode — during an outer ISR's softirq (mode=IRQ, I re-enabled by
  do_softirq) a pending edge caused NESTED entra_irq, clobbering
  the single spsr_irq and corrupting the outer return until
  scheduler_tick runs with I=0. Racy + timing-dependent (different
  initcall each run), amplified by the kick planting a fresh edge
  every 100 slices. Fix: `pode_irq` gate (I==0 AND mode in
  USR/SVC/SYS) on all four delivery paths (WFI-wake, unmask-edge,
  dirty, 64-poll); deferred polls use livre=false so level
  tracking stays fresh without consuming the MATCH one-shot.
  EXPERIMENT (in flight): BUG gone + klog past 54s toward Freeing
  init memory / Run /init (init=/init appended; ramdisk /init
  verified present).
  CORRECTION 2026-10-24: the observe-only run (282/283) proved the
  force is LOAD-BEARING — without regs[0]=0, program_event returns
  -ETIME forever, MATCH frozen, kernel dead from t≈0 (28-line klog,
  guest time dragged by the watchdog to a 335s posix BUG). So 283
  could NOT validate the mode gate (no progress to nest on). The
  "program_event succeeds on its own" verdict from the one-shot era
  was wrong — the force was masking -ETIME at the retry site all
  along. Combined test in flight: force restored + pode_irq gate —
  if the BUG is gone past 54s, the gate fixed the nesting and the
  force stays until /init; if the BUG recurs, suspects return to
  force-corruption vs residual nesting.
  CORRECTION-2 2026-10-24: identical nent trajectories with/without
  the mode gate (246/490/734) prove nesting-during-softirq was
  NEVER the mechanism — the gate is a no-op in practice. REVISED
  mechanism: the kick's UNCONDITIONAL set_cpsr unmask violates
  guest irqsave critical sections (mode is SVC there — no mode
  gate can see it); delivery into the violated section corrupts
  state until scheduler_tick runs with I=0 → BUG. Fix: unmask ONLY
  after 30 consecutive masked kick-samples (≈6M masked
  instructions — the parked-idle signature; critical sections
  never survive it). Plant + handler-pin + dirty stay
  unconditional (a pending edge while masked is harmless — served
  at the guest's own unmask). EXPERIMENT (in flight): BUG gone
  past 27s/54s toward Freeing init memory / Run /init.
  CONFIRMED 2026-10-24 (linux285): clean Budget stop, NO BUG,
  klog to 57.27s with initcalls flowing (alarm_late_init,
  tcp_congestion_default return 0), KICK-UNMASK fired exactly
  once, ticks healthy (nent 5777, I=0). The critical-section
  violation was the BUG mechanism.
- Wall at t≈57s: NO new printks for 900k slices while ticks/sched
  stay alive — a silent poll. Halt trace names it:
  flush_endpoint_hw (0xC0154E08-1C) + __const_udelay alternating:
  guest writes mask to [QH+0x1B4] to initiate, polls for the
  controller to clear ([r2+0x1B4]/+0x1B8 & mask) with udelay(10M)
  between. QH lives in vmalloc RAM (0xC68061B4=0xFFFFFFFF
  forever) — no USB engine modeled. Lively deadlock (ticks
  preempt the spin; init's workqueue flush never drains).
  EXPERIMENT (in flight): host-side completion (write 0 to both
  status words on every 0xC0154E14 hit), then Freeing init memory
  / Run /init as init.
- USB flush COMPLETED (linux287): endpoints set up, evdev/mousedev
  return, boot reaches synaptics_ts_init (touchscreen,
  i2c_register_driver) at t≈3.3s — which never returns. Only 173
  schedule switches ever; init parks once in schedule_timeout
  (f≈103k, lr schedule_timeout+0x98) and never wakes; system
  otherwise idles healthily (msm_arch_idle + timer softirqs,
  nent 6093). Frozen-stack unwind names the chain:
  kernel_init → synaptics_ts_init → i2c_register_driver →
  driver_register → bus_add_driver → driver_attach →
  bus_for_each_dev → __driver_attach → driver_probe_device →
  i2c_device_probe → parked at synaptics_ts_probe+0xc.
  EXPERIMENT (in flight): wait_for_common entry trap now COMPLETES
  the synaptics wait (compl 0xC6017B84, on init's stack — exact
  address from WFC#1: timeout 0x64, task init, lr
  wait_for_completion_timeout+0x14) host-side on entry. Probe
  proceeds as if its event arrived (reads unmodeled device state
  → graceful -ENODEV or dead input device both unblock boot).
  LESSON 2026-10-24: trap_pc_mem REPLACES per address — a new trap
  on an occupied pc silently evicts the old one (my SCHTO trap
  killed nothing and logged nothing because the ancient STIME trap
  squatted on 0xC02133D0 with a dead cap). Merged: single STIME
  trap, cap 300, late stack dumps.
  PROGRESS (linux293): probe reads product info (major 3, minor 1,
  property/device-control/irq-enable all 1) then the probe LOOPS
  on the same completion (WFC#7-10, f=103308-23: fake-wake →
  condition still false → re-wait), then parks in a 5th wait past
  the log cap. Faking the SIGNAL isn't enough; the underlying
  CONDITION (ATTN IRQ / i2c data-ready) never becomes true.
  EXPERIMENT (in flight): WFC cap 10→300 to see the 5th+ waits
  (same completion loop vs new wait). FOUND (linux294): same
  completion loops (WFC#8-12, compl 0xC6017B84) then a SECOND
  completion 0xC6017C74 parks — the probe steps through per-stage
  on-stack completions for the same unmodeled event (ATTN IRQ /
  i2c done). Fix in flight: complete ANY finite wait from the
  init thread (task 0xC6013C00), logging each new address.
- MILESTONE (linux295): `Freeing init memory: 100K` — all
  initcalls done — then Exception at flush_pfn_alias+0x78
  (pc 0xC00273B4 = STC p15 0xEC442F0E, a cache-preload hint on the
  /init exec path via flush_dcache_page). Backend gap, not device
  gap: the flat model has no caches (GuestMemory directly
  coherent), so LDC/STC p15 are NOPs. Fix: accept LDC/STC class
  to CP#15 in arm_coproc, still fault other coprocessors (VFP
  data would corrupt) + unit test.
- Next wall (linux296): MemoryFault in __clear_user+0x34 on user
  VA 0x1FCE0 — the ELF loader mapped /init's pages in the user
  pgd, which the flat MMU never consulted. Fix: guest PT walk
  (TTBR0, key 0x100) on user faults < 0xC0000000 outside SPL-alias
  and known windows — resolve VA->PA (small-page/section/large),
  mirror the 4 KiB physical page seeded from PA, track uncapped,
  repeats still stop. Needs le_cp15 accessor (added).
  EXPERIMENT (in flight): UFAULT run — pages mapping + Run /init
  as init process. DIAGNOSIS: PTWALK miss — L1 unreadable at the
  table PA (TTBR0=0x1615C008 valid). Root cause: GuestMemory's PA
  bank goes stale post-MMU (guest builds tables via VA writes;
  PA copies never updated). Fix: le_ram_fisica — read everything
  through the lowmem alias (VA = PA + 0xB0000000, live contents),
  mapping + seeding the VA page on demand; RAM-gated
  (0x10000000..0x20000000) so device PAs still stop the run
  instead of shadowing the model. Walk + page seeding both use
  it. DIAGNOSIS-2: walk now reads (alias works) but L1[0]=0 is
  REAL — no mapping yet. On real HW this exact instruction
  faults into do_page_fault (demand paging); our model never
  delivers aborts. Reimplementing the handler host-side is
  strictly worse than letting the kernel run it. Implemented
  DATA/PREFETCH ABORT DELIVERY (entra_aborto: mode ABT, I+A
  masked, FAR key 0x300 / DFSR 0x280 / IFSR 0x281, lr=fault+8,
  vector via SCTLR bit13, ABT stack fallback, TOTAL_ABORTOS,
  entry audit, unit test — which caught a bank-swap clobber of
  lr, fixed to entra_irq's order). Harness: user-VA walk-miss →
  vector sanity (ldr pc shape) → deliver; 2nd fault same page =
  stop; no delivery from ABT/FIQ. fsr fixed 0x5 (translation
  fault). Fetch faults (addr==pc) → prefetch abort. Flow per new
  page: fault → abort → guest installs PTEs → fault → walk hits
  → mirror → proceed. EXPERIMENT (in flight): full demand-paging
  loop toward Run /init. DIAGNOSIS-3: mirror landed
  (pte=0x160C305F ok=true) but the retry's walk still said "bad
  L2" — 0b11 is a VALID small page with XN=1 (non-executable
  .bss), which the walk rejected (only 0b10). Fix: accept any
  descriptor with bit 1 set as small page. DIAGNOSIS-4: no walk
  output at all on retry — map_zeroed FAILED SILENTLY on overlap:
  user VA 0x1F000 collides with the stale SPL image mapping
  (0x0-0x80000, read-only). Fix: GuestMemory::desmapeia_intervalo
  (carve [base,base+len), splitting survivors with content+flags,
  rebuild order index; unit-tested) + CpuBackend hook; fault arm
  carves before mapping (only after a walk HIT, so wild accesses
  still stop). DIAGNOSIS-5: vector entry confirmed for both
  aborts, but no PTE install on the stack fault — and VEC lr was
  fault+4, not the abort-correct fault+8 (r15 sits AT the fault
  for fault traps, unlike IRQ delivery where it's advanced past;
  proven by VEC lr). Wrong lr corrupts the retry (subs returns to
  fault-4). Fix: lr = r15+8; unit test updated. PLUS: DABT entry
  trap (addr+fsr as received) to distinguish "no VMA / bad area"
  bail from a broken entry path.
  DIAGNOSIS-6 (the big one): guest executes SPL BYTES as /init —
  the stale SPL low image (0x0-0x80000, mapped+executable) shadows
  all of userspace text, which therefore never faults (executes
  garbage; sp corrupts downstream; SIGSEGVs are "correct" for the
  wrong binary). Proven: bytes at 0x809C match spl.bin, not the
  ELF. Fix: carve 0x0-0x80000 wholesale on the first user fault
  (kernel runs from high mappings; high vectors stay).
  DIAGNOSIS-7 (Thumb): prefetch-LR split (data fault+8, prefetch
  fault+4 — guest resumes via subs pc,lr,#8/#4). Wrong prefetch lr
  skipped the faulting ldr and branched on stale ip=0 to address 0.
  Fix: lr=r15+8 data, r15+4 prefetch + unit test both variants.
  GOTVAL then correct (0x15119) and init dispatches into Thumb code.
  DIAGNOSIS-8 (Thumb resume): run() sets T from pc bit0, but Thumb
  fault pcs are even — bare pc_falta resumes ARM and mis-executes
  Thumb bytes as ARM (0x15118 Thumb slid into garbage, jumped to
  0x195311C with sp untouched). Same loss at every Budget slice
  boundary in Thumb. Fix: preserve T via pc bit0 from estado_cpsr
  on the UFAULT resume and the Budget resume. CONFIRMED
  (linux324): wild jump gone, Thumb init runs (11 UFAULT pages),
  stops at 0x12660 str to [r0=8]. The 0x1259c getter does
  r0=[0xFFFF0FF0]+8 (pool 0xFFFF0FF0) and reads 0: the kuser page
  at 0xFF0 is zero in our map. Template has helpers at
  0xF00-0xF60 (__kuser_helper_start 0xC000BF80); 0xFF0 content
  depends on the vectors-page copy. EXPERIMENT (in flight,
  linux325): ABORT cap 8→16 (see the addr-8 delivery #9) +
  KUSERW watch (stores to [0xFFFF0F00,0xFFFF1000)) — silent means
  the helper copy never lands through our map.
  DIAGNOSIS-9 (Thumb BL base): old-Thumb BL first half must use
  the UNMASKED pc+4 — the `& !2` sent pairs at pc≡2 (mod 4) two
  bytes early. Init's bl at 0x8ECE (base must be 0x8ED2) landed on
  0x8DB2 padding (0xFFFF = BL-second-half shape), which consumed
  the stale odd LR (0x8ED3) → target 0x8ED3+0xFFE = 0x9ED1, odd-pc
  fetch Exception. Fix: drop the mask + discriminating unit test
  (pair at 0x02 → exact 0x100). CONFIRMED (linux327/328):
  init runs deep into userspace (syscalls flowing, 20+ pages),
  new wall is a kernel copy_from_user loop faulting on user page
  0xBEC0A000 (page above the mapped stack page).
  DIAGNOSIS-10 (abortadas too coarse): keyed page-only, so a
  legitimate SECOND touch of a page (kernel uaccess fixup returns
  -EFAULT and the caller moves on; a later retry or a different
  copy phase refaults the same page) stopped the run as a "loop".
  Fix: key (page, pc) — same-instruction retry still stops;
  different-pc progress delivers. ABORT cap 16→40, UDECIDE cap
  40→80. In flight (linux329). REFINED (linux331): even
  (page,pc) stop-on-2nd is wrong — klog proves init is ALIVE
  (`init: cannot open '/initlogo.rle'`, yaffs mounting mtdblock3),
  so a same-pc refault is a recurring incident (fixup -EFAULT +
  caller retries), not a livelock. Fix: per-(page,pc) delivery
  budget of 10 (tight loops still stop via ABORT-LOOP); UDECIDE
  miss-only.
  DIAGNOSIS-11 (init abort): exit_group(127) via ARM wrapper at
  0xBE10, lr=0x1275B (Thumb caller does movs r0,#127; blx after
  blx 0xCAC0=getpid?/kill path — actually the sequence at
  0x12722+ is sigaction(SIGABRT)/getpid/kill/abort). So init
  calls abort(): sigaction/getpid/kill(SIGABRT)/exit(127). The
  abort is guarded by a [r0]==[r7] check at 0xA6F4 (0xA6F4:
  ldr; 0xA6F6: ldr; 0xA6F8: cmp; 0xA6FA: beq skip; 0xA6FC: bl
  fatal): r0=0xBEC09CAC (stack) [r0]=0xAA2D vs r7=0x201A8
  (.bss) [r7]=0xFF0A0000. The 0x126C4 "assert" trap's r1
  (property message) is PROVEN stale (function overwrites all
  arg regs before first use) — the property error is
  coincidental timing, not proven cause. BSSWR shows NO guest
  write to 0x201A8: the 0xFF0A0000 came from the mirror SEED
  (stale lowmem alias — anonymous .bss zeroed via fixmap
  kmap_atomic is invisible to our alias walk). Leading theory:
  stale .bss seed breaks the check (whatever it guards).
  EXPERIMENT (in flight, linux341): CHK trap forces the check
  to pass (r15=0xA700, the beq target) — if init proceeds to
  console/adbd, the check was the sole gate; the proper fix is
  fixmap-coherent zeroing (mirror clear_highpage/copy_user_
  highpage into the lowmem alias) or anonymous-zero seeding.
  DIAGNOSIS-12 (check named: stack guard; stale-seed DISPROVEN):
  BSSWR (linux343) caught the guest ITSELF writing 0x201A8
  byte-by-byte (00 00 0A FF at 0x127B4-0x127BA) — the .bss word
  is the /dev/urandom fallback of a canary seeder (0x1277C:
  open/urandom, read 4 into guard, close; on failure write
  00 00 0A FF). The 0xA5E4 function is stack-guarded: prologue
  (0xA5E6-0xA5FA) copies [GOT+0x1C] to sp+0x1074 in a 4220-byte
  frame; epilogue (0xA6E6-0xA6FA) compares stack copy vs
  [GOT+0x1C] and calls 0x126C4 on mismatch (second site 0xAB72
  in another guarded function). [r0]=0xAA2D vs [r7]=0xFF0A0000
  is a REAL pocket veto: canary copied pre-seed (or slot never
  written) vs guard post-seed. RESOLVED (linux341→): the skip
  is NOT a gate pass — init proceeds past the property stage
  then faults jumping to 0xFF0A0000 itself (TRACE: ...0xA700,
  0xA702, 0xA704 pop {r4-r7,pc}, then pc=0xFF0A0000): the saved
  return address IS the guard value, i.e. frame/sp corruption
  (wrong pop slot) or a mid-function guard reseed, not a
  decision to bypass. Ramdisk hack (linux352, nand_proptest.img
  with pre-created data/property): property error GONE but the
  SAME 0xFF0A0000 fault — the missing dir is PROVEN not the
  cause (and the 0x126C4 r1 message is stale by construction).
  Stack slot 0xBEC09CAC has exactly ONE es_mem writer (0x15150,
  value 0x0001F48C, not the canary) — the prologue str at
  0xA5FA never lands there, pointing at sp drift across the
  function's syscalls (read/write/open wrappers 0xBF30/50/70)
  rather than a guest overflow. EXPERIMENT (in flight,
  linux355): CENTRY (sp/lr/pools at 0xA5E4) + CCOPY (dst/value
  at 0xA5FA) + extended CHK (sp/r4-r6) — CHK sp vs CCOPY sp
  decides sp-corruption (emulator SVC-path bug) vs overwrite
  (guest stack smash); CCOPY dst vs CHK r0 decides frame-math
  error.
  RESOLVED (linux355-356): emulator bug, frame math CORRECT.
  CCOPY dst (0xBEC09CC4) == sp+0x1074 exactly; but CHK sp is
  -24 vs CCOPY sp, so r0 reads 24 below the true slot and the
  epilogue pops the guard itself into pc (0xFF0A0000 fault).
  Cause: Thumb `push` committed sp BEFORE the stores — a
  mid-push fault (demand-paged stack growth across the 4220-B
  frame) left sp decremented, and the resume re-executed the
  push (double-apply; ARM stm/ldm already commit last and are
  safe). Fix: roll sp back on store failure inside thumb_push
  + unit test push_thumb_falhado_restaura_sp (mid-push fault
  restores sp). Live: CHK now [r0]==[r7]==0xFF0A0000, sp
  stable, clean Budget stop — no abort, no fault, no panic.
  linux356 klog advances PAST the property error (non-fatal, as
  predicted): init disables console/servicemanager/mountd/
  debuggerd/rild/zygote/media/bootsound/dbus/installd/
  flash_recovery/akmd — all `cannot find '/system/bin/*'`
  because yaffs mounts fail on empty NAND (no yaffs content in
  image). Canary probe cluster retired (CHK skip, CENTRY,
  CCOPY, BSSWR/BSSRD, STKWR, VALWR).
  NAND second wall (independent, after canary): yaffs
  refuses all mounts (`NAND geometry problems: chunk size 2048,
  type is yaffs2, inbandTags 0` = oobsize < 32 — kernel-phase
  MTD reads hit zeroed stubs, no ID/partition/data path yet;
  SPL-phase serve only covers the SPL's own loads). OPEN watch
  confirms init reaches mknod /dev/mtd/mtd0.. but never a
  working /system or /data.
  MILESTONE (linux331): clean Budget stop with init RUNNING —
  `Freeing init memory`, `/initlogo.rle` missing (non-fatal),
  yaffs mounts on mtdblock3/5/4, then `init: Unable to open
  persistent property directory /data/property errno: 2` and
  `Kernel panic - not syncing: Attempted to kill init!`
  (do_exit fired, task=init, no SIGSEGV — voluntary exit).
  Ramdisk has no /sbin/recovery (adbd only), normal init.rc
  (zygote etc.): init attempts a normal boot with empty /system.
  NAND image has no yaffs content (only SPL boot blocks +
  kernel/ramdisk), so mounts can't succeed. Open: is the exit
  caused by empty mounts, or by a mis-emulated syscall on the
  path? EXPERIMENT (in flight, linux332): SVC cap 12→300 to
  catch the late syscalls (mount/open/execve/exit) and name the
  killer. RESOLVED the exit call chain (linux333-335):
  init calls exit_group(127) via a tiny ARM wrapper at 0xBE10
  (push/mov r7,#248/svc/pop/bxpl), with lr=0x1275B — a Thumb
  caller doing `movs r0,#127; blx 0xBE10` unconditionally after
  `blx 0xCAC0` (reached via BLX-immediate, which the first scan
  missed; no BL/B/pool reference exists). Open: parent (init
  itself deliberately exiting?) vs forked service child (execve
  failed on empty /system → _exit 127) — FATAL says task=init
  died, but no fork/clone/execve appeared in the logged SVC
  window. EXPERIMENT (in flight, linux336): EXITCAL extended to
  fork/clone (r7=2/120) + lr.
  RESOLVED (2.6.25 traps.c, verified from source): set_tls writes
  the TLS value DIRECTLY to *((unsigned int *)0xffff0ff0) when
  neither HAS_TLS_REG nor TLS_REG_EMUL is set — FF0 is the TLS
  slot, not padding. Our svc() stubbed ALL syscalls to r0=0, so
  set_tls "succeeded" without writing FF0 → [FF0]=0 → r0=8 →
  SIGSEGV. Fix: entra_svc — USR-mode SVC delivery to the guest's
  vector_swi (mode SVC, I masked, lr=fault+4 ARM/fault+2 Thumb,
  vector via SCTLR, SVC stack fallback, TOTAL_SVC, audit, unit
  test). Routing by immediate (semihosting: 0x123456/0xAB/SPL's
  0xCDAB89; else USR→guest, privileged→legacy stub) so the SPL
  and the semihosting unit test are untouched. EXPERIMENT (in
  flight, linux326): first guest-handled syscall.
  DIAGNOSIS-2: no ABORT#/UFAULT
  at all — the vector sanity check rejected a VALID vector
  (`b 0xFFFF0280`, not `ldr pc`): ABORT-NOVET fired, check was
  too strict. Widened to accept branches. In flight again.
- The first tick now COMPLETES (periodic ticks flow: klog
  timestamps advance 1.39→1.47s, PREENT passes repeatedly,
  schedule activity). The old `-ETIME` treadmill analysis below
  belonged to the inverted-polarity era and is retired — the
  host-side re-arm is gone too (plant removed 2026-10-24 once
  program_event succeeded on its own; the guest programs its own
  ~COUNT+327 matches now, TICKBRK only logs + forces r0=0 as a
  no-op safety net).
- The `genl_init`/`synchronize_rcu` park is BEHIND the tick:
  without a completing first tick there is no RCU progress at all
  (klog frozen at `console [tty0]`, 27 lines — the 61-line
  initcall walks belonged to the no-tick watchdog era).
  Unblocks when program_event succeeds.
- The initcall-disables notices: revisit once ticks flow
  (fork-frame CPSR inheritance vs msr-restore path).
- Live probes to retire on the fix: CPSIE/MSRIE/RETX/ENTRA,
  TICKBRK, BNE/EDGE/HIE/ACT/RESEND/DISPIRQ/VIDX, RPX, STIME/
  NINITCALL, DESCWR/DESCCHG, PROGEV, VICST (keep the model
  plants + TIMERSTATE). Retired 2026-10-24: PCSAMP (the Budget
  stop now prints the parked pc + stack + pc history via
  `imprime_trace`, which subsumes it).

## Radio / ARM9 modem + audio (future workstream, NOT blocking first shell)

- The modem is a separate ARM9 (+ QDSP) running its own AMSS firmware;
  the AP side talks to it over SMD/smem (`smd_alloc_channel`, `sync_smem_clock`,
  `SMEM`/`smem` prints). There is deliberately NO ARM9 emulation yet.
- Current strategy (working so far): absent modem with graceful AP-side
  degradation. Evidence it holds: `smd_alloc_channel() cid ... does not
  exist` errors continue past probe; `no smem clock` prints instead of
  hanging; mddi init times out then fails -ENODEV and boot continues.
- Do NOT spin up radio emulation (or subagents for it) until first shell:
  the AP interface requirements are still unknown, and parallel work now
  would integrate against guesses. Reassess after userspace: check whether
  `rild` hard-blocks init (likely not — init/adbd/shell don't need it),
  and whether audio matters for the shell goal (it doesn't).
- If radio ever becomes necessary, prefer host-side SMD/smem responses
  (fake the mailbox) over emulating the ARM9 core — orders of magnitude
  cheaper, same observable behavior for the AP.

## Stall after `neigh_init` (Dream, on hold behind the tick)

Earlier (no-tick watchdog era) klog walked initcalls through
`neigh_init` then parked in `genl_init`'s `synchronize_rcu` wait.
With timer delivery working, the frontier moved earlier: a single
`TICKH` enters, but its catch-up loop never completes
(`program_event` → `-ETIME` forever, see IRQ section), so the run
stays inside the first tick and klog freezes at `console [tty0]`
(27 lines). The `genl_init` analysis stays valid for after the
tick completes — no action needed on it now.

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
