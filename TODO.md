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
- Frontier moved to t≈27s (2026-10-24): with periodic ticks +
  host kick (MATCH plant when stale + unmask + dirty every 100
  slices) boot walks driver initcalls: mddi_pmdh init fails
  gracefully (-ENODEV, unsupported version 0x0 on stubbed regs),
  msm_serial detected, loop/PPP, ashmem, yaffs, io scheduler,
  mmc1 SDCC probe (0xE1000000 stubbed), then parks in
  msm_dmov_exec_cmd wait_for_completion. DMA completions are faked
  per-call-site (lr 0xC002B570 only) until a real ADM model exists.
  New stubs this round: 0xFFC00000 (MDDI), 0xE0200000 (CAMIF PAD),
  0xE1000000 (SDCC). Open: verify the DMA waiter wakes and boot
  proceeds past mmc; then retire the kick/mirror/skip TEMP
  scaffolding.
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
