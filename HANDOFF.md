# HANDOFF — read this first

## State
- Goal ("Option 4b"): CEC `<Standby>` should put the AVR into reachable "Device sleep" instead of the stock deep power-down (red LED, network dead).
- r3 (`37ba4f65…`, reviewed CLEAN) flashed: **live-confirmed CEC standby now sleeps.** The stock 1-hour sleep->deep timer was then **observed live** (receiver went deep after ~1 h).
- **O1 (`85c78bc916a2c6bf3f100a08292972b76bc6e4a5ccf2b7c9826f0139331d0507`, 1 byte `0x08010a57` d1->e0) fixes it: reviewed CLEAN (r3+O1) and APPLIED to the live deliverable** `~/AVR1710_USB(V002_23)_patched.fw` (= `firmware/AVR1710_USB(V002_23)_patched.fw`). Applier `appliers/apply_o1_disable_1h_deep.py`; r3 backup `*.pre-o1-*.bak` (also in `firmware/history/`).
  Evidence: `bfd8` (0x2001bfd8) has exactly one reader (FUN_0801074c timer); all other accesses are stores of 0xe10 or 0. Verdict reasoning in this session's reviewer turn 5 (summarised in `analysis/review/reviewer-verdict_O1_CLEAN.txt`).
- **O1 is NOT yet live-confirmed.** Soak test required: Auto Power Off + Zone 2 off, CEC "Device sleep", poll from HA for 75 min; reachable at 65 and 75 min; then wake via CEC/HA and check normal operation.
- Emulator validation of r3: 0 failures, negative controls fail as they must, fresh-Ghidra clean. r3+O1: `quick_new` 0 failures, `test_o1.py` 0 failures.

## Rules the user works by
No guesses; every claim file-verified; say what is unproven. No applying a patch before a clean review verdict. Never two Ghidra jobs at once. Original files stay put (copy, don't move).
Real device: 192.168.0.65. Use `tools/live/` for probing.

## Live checklist (report results back; anything unexpected = stop and investigate, do not guess)
1. TV standby: "Your device is going to sleep." ~2 s, then reachable "Device sleep" (HA reachable).
2. Power button: normal sleep. CEC standby, then power button: no deep shutdown.
3. TV/CEC wake and HA `power-on` from sleep work.
4. **Most informative:** Zone 2 off, Auto Power Off disabled: wake, send broadcast `<Standby>` ~1 s later, repeat ~1.2 s later; report display/LED and HA reachability at +3 s and +5 s. Expected: normal reachable sleep, not red-LED deep.
5. Zone 2 on/off with directed and broadcast `<Standby>`.
6. HA `power-off` retest (stock failed 3x live; unexplained).
7. If Auto Power Off is enabled, let it expire right after a Standby; check at +5 s (stock policy may go deep by design).
8. Long-press power may still go deep. **75-minute soak (O1 check):** see State above; the 1 h sleep->deep deep-down must no longer happen.

## Known limits (not fixed)
R1-R7 in `docs/PATCH_LINEAGE.md`. Notably: callback-only `<Standby>` (via `FUN_0809b3fc`) keeps stock no-sleep behaviour; APO / long-press / forced-deep still go deep by design.
**O1** (applied; builder `harness/build_candidate_4c.py`, `./pipeline.sh o1`, applier `appliers/apply_o1_disable_1h_deep.py`) removes the 1 h sleep->deep expiry. To revert to r3: flash `*.pre-o1-*.bak` (r3, `37ba4f65`).

## If something fails live
1. Restore the known-good baseline `firmware/baselines/AVR1710_patch4_volmute_a39f47f2.fw` (a39f47f2, previously live-tested) and flash it.
2. Find the cause from evidence (`analysis/subsystem-findings.md`, Ghidra via `ghidra/ghr.sh`), fix `harness/build_candidate_4b.py`, rebuild, re-run `test`, `negctl`, `ghidra-verify`, `apply-dry`, write a delta review pack, get a fresh independent review (give the reviewer `analysis/review/REVIEW_PACK_4b_r3.txt` and the prior verdicts), only then apply.

## Prompt for a new model/session
"Read HANDOFF.md, README.md, docs/PATCH_LINEAGE.md and analysis/subsystem-findings.md in this folder. Option 4b r3 (sha 37ba4f65...) is reviewed CLEAN and applied to the deliverable but not yet live-tested. Run ./pipeline.sh all-quick to confirm the pipeline, then help me interpret the live checklist results. Never guess; verify from files."
