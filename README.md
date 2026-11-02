# AVR1710 firmware project (Harman Kardon AVR1710, stock V002.23)

Contains the Unicorn emulation harness, appliers, Ghidra scripts, analysis and byte-level patch deltas for the AVR1710 firmware.

## Firmware is not included
Harman Kardon's firmware (and images derived from it) are copyrighted, so this repo contains no `.fw` files, Ghidra project or raw disassembly dumps. Supply your own stock `AVR1710_USB(V002_23).fw` (sha256 `396f14e3aea394685647b5a366107fd7e4150283a2c42a04428c955ce3cdf34b`) in `firmware/`. The `pipeline.sh` targets that build or test candidates also need the author's local `firmware/baselines/` image, so they only run in the full working copy.

## Builds (as deltas)
`patches/` holds each build as the changed bytes only (about 1 KB each), checked against the stock and result SHA-256. Flashing firmware can brick a receiver; use at your own risk.
```
python3 tools/firmware_delta.py apply "firmware/AVR1710_USB(V002_23).fw" patches/avr1710_v002_23_r3_plus_o1.json out.fw
```
- `avr1710_v002_23_r3.json` gives sha `37ba4f65...` (query-status fix, V002.24 bump, CEC Active Source fix, sleep-disable, volmute fix, CEC standby to "Device sleep").
- `avr1710_v002_23_r3_plus_o1.json` gives sha `85c78bc9...` (r3 plus O1, which disables the stock 1-hour sleep to deep timer). This is the build the author flashed.

## Quick start
```
./pipeline.sh env            # .venv with capstone 5.0.9 + unicorn 2.1.4 (no make / Xcode tools needed)
./pipeline.sh status         # hash + label every image; is Option 4b applied?
./pipeline.sh all-quick      # env + candidate + quick tests + applier dry run + path check
./pipeline.sh help           # every target
```
Pipeline targets: `candidate` (build from frozen baseline; must give sha `37ba4f65...50e6`), `test-quick` (~2 min), `test` (N=25 seed 1234, ~9 min, must end `TOTAL FAILURES: 0`),
`test-full` (N=60 seed 98765, ~14 min), `negctl` (controls that MUST fail), `ghidra-smoke`, `ghidra-verify` (fresh import, ~3 min), `apply-dry`, `apply` (needs `CONFIRM=yes`), `o1` (optional patch).
Never run two Ghidra jobs at the same time.

## Layout
- `firmware/` (local only, not in the repo): pristine, `baselines/` (frozen builder input a39f47f2), live `..._patched.fw`, `candidates/`, `history/` (.bak backups per lineage step). **Never commit/publish: Harman copyrighted code (`.gitignore` covers it).**
- `harness/` Unicorn emulator + tests (`paths.py` resolves everything from the project root; env overrides `AVR_ROOT AVR_BUILD AVR_PRISTINE AVR_BASELINE AVR_DELIVERABLE`; `known_images.py` labels every sha). `harness/legacy/` provenance only.
- `appliers/apply_cec_sleep_fix_4b.py` guarded applier (dry run by default, `--apply` writes backup + post-verify). `appliers/legacy/` older appliers.
- `ghidra/` `env.sh` (finds Ghidra/JDK; override `GHIDRA_HOME`/`JAVA_HOME`), `ghr.sh` (script on analysed pristine project), `ghfresh.sh` (fresh import of any image), `scripts/` (138), `project/` (pristine analysed project).
- `analysis/subsystem-findings.md` master findings doc; `analysis/review/` review packs, reviewer verdicts (r0-r2 FIX FIRST, r3 CLEAN); `analysis/logs/`.
- `tools/` live probes against the receiver, state-mirror simulator, QEMU validation env. `ha-integration/` snapshot of the HA repo. `history/` checkpoints, user requests, todos. `docs/PATCH_LINEAGE.md`.

## Tool versions used
Ghidra 12.2, OpenJDK 25, Python 3.15.2 (Homebrew), capstone 5.0.9, unicorn 2.1.4, arm-none-eabi binutils.
See `HANDOFF.md` for current state, rules and the live-test checklist.
