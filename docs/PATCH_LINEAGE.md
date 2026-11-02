# Patch lineage (each step builds on the previous; hashes are sha256 prefixes)

Pristine: `AVR1710_USB(V002_23).fw` `396f14e3`. STM32F4 Cortex-M4, base `0x08000000`, 6291456 bytes.

| # | sha | What | Where / script |
|---|-----|------|----------------|
| 1 | `954d0e34` | query-status fix + V002.24 version bump | `appliers/legacy/apply_*.py` |
| 2 | `df17e021` | + CEC Active Source fix | `appliers/legacy/` |
| 3 | `0f27feda` | + sleep-disable (WFI -> NOP at `0x08064e0e`) | `appliers/legacy/` |
| 4 | `286e67cb` | + CEC additive hook at `0x0809b44a` | `appliers/legacy/` |
| 5 | `2031965e` | + first "universal" power-off fix | superseded |
| 6 | `98a1b5db` | patch #4: no-op trampoline | superseded |
| 7 | `a39f47f2` | patch #4 + volmute fix = **baseline for Option 4b** | `firmware/baselines/` |
| X | `a5bd8747` | patch #5 "shutdown gap closure": BROKEN (device never slept), reverted | `firmware/history/*broken*` |
| 8 | `37ba4f65` | **Option 4b r3** (reviewed CLEAN, applied) | `appliers/apply_cec_sleep_fix_4b.py`, `harness/build_candidate_4b.py` |
| 9 | `85c78bc9` | **r3 + O1** (one byte `0x08010a57` d1->e0; disables the 1 h sleep->deep timer, live-observed on r3). Reviewed CLEAN, applied | `harness/build_candidate_4c.py`, `appliers/apply_o1_disable_1h_deep.py` |

Superseded 4b candidates (kept as negative controls): r1 `629cd9a7`, r2 `33e62c4a` (callback trampoline skipped the dispatcher tail -> double entry with Auto Power Off).

## Option 4b in one paragraph
RAM `0x2001c038` bit 7 is the "go DEEP" marker. `FUN_08019638` (shutdown entry) sets `bfb8`=300 if it is set, else 250; the sequencer `FUN_08013c0c` step `0xaf` goes DEEP
(red LED, network dead) if set, else normal reachable "Device sleep". The stock CEC dispatcher `FUN_0802d230` sets it in its Zone-2-OFF blocks. r3 replaces those two blocks with a call
to a 64-byte helper at `0x080c8d58` (`harness/cec_sleep_helper.S`): if Zone 2 ok, clear the marker, clear c2b5/c2b6, and either defer (`c2b5=100`, ~2 s) or call `FUN_080192e2` (normal sleep).
The 3 `FUN_08019638` call sites and the callback hook `0x0809b44a` are restored to stock; the old cave `0x080c8a0e..35` is erased to 0xFF.
r3 vs deliverable: 199 bytes in 18 ranges. r3 vs pristine: 1057 bytes in 18 ranges.

## Residual risks (documented, not fixed)
R1 c2b5 deferral + c2b6 armed by another source may double-enter (closed for CEC paths by the helper; not for exotic sources).
R2 stock 1 h `bfd8` sleep->deep timer: observed live on r3, fixed by O1 (soak-pending).  R3 stock network `power-off` failed live 3x on pristine (unexplained).
R4 `FUN_0809b3fc` callback-only Standby unproven.  R5 emulator limits (no ISRs / boot / CEC chip / real timing).
R6 cosmetic "switched off." text for ~2 s.  R7 Auto Power Off / long-press / forced-deep paths still go deep by design.
