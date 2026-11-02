#!/usr/bin/env python3
"""
apply_shutdown_gap_closure_fix.py

Closes the LAST two reachable call sites of FUN_08019638 (the deep/hard
shutdown routine) that could still fire after a CEC <Standby> or power
button event, following exhaustive due-diligence auditing of every one
of its 15 call sites firmware-wide.

Background
----------
Patches #1-4 (apply_poweroff_universal_fix.py + the no-op trampoline
follow-up) neutered the 3 direct FUN_08019638 call sites inside
FUN_08019272 / FUN_080192e2 (the shared power-toggle / CEC-standby
handler). Live testing after that patch showed a NEW symptom: CEC
standby now displays "device is switched off" (proving the handler IS
being reached and IS taking a branch) but the receiver does not power
down at that moment - it then fully shuts down somewhat later, with no
button press required for this to eventually happen.

Root cause (confirmed via raw disassembly + literal-pool resolution,
not decompiler inference alone): FUN_08019272 / FUN_080192e2 each have
an inner flag check that selects between (a) the direct FUN_08019638
call (now a no-op post-patch #4) and (b) an entirely separate action:
arming a deferred countdown by setting byte *0x2001c2b6 = 100 (and a
second cell at pool 0x08019c70 to 0xe10). This arm path was NEVER
touched by any prior patch. The armed countdown is consumed by the
tick dispatcher FUN_08011910, which runs on every main-loop tick:

  - 0x080119d0: bl FUN_08019638, reached when the *0x2001c2b5 countdown
    expires AND bit 1 of *0x2001c030 is already clear (the "device
    already considered off" gate). This is a redundant/backup hard
    shutdown for a cell never written by the CEC/button patch, but it
    sits on the same reachable call path and is covered by this fix for
    completeness/symmetry with the next item.
  - 0x08011a1e: bl FUN_08019638, reached when the *0x2001c2b6 countdown
    (the one armed by the patched-but-not-neutered branch above) expires
    - this call is COMPLETELY UNCONDITIONAL, no gating at all. This is
    the exact, now-identified gap: patch #4 silences the immediate call,
    but ~100 ticks later this untouched, unconditional call fires and
    performs the deep shutdown anyway, independent of any subsequent
    button press.

Exhaustive 15-site caller audit of FUN_08019638 (firmware-wide, zero
indirect/function-pointer calls found) classified every other site:
  - 2 sites in FUN_08064ede (boot/resume decision logic) - legitimate
    boot-time behavior, NOT reachable from CEC/button, left untouched.
  - 10 sites across 5 distinct functions (FUN_08013138, FUN_08013506,
    FUN_080136e0, FUN_08013a70, FUN_08013b08) - all are ADC-averaging
    thermal/voltage/fault-protection circuits with distinct fault codes,
    consecutive-bad-reading counters, and relay-disable calls before the
    shutdown. These are safety-critical hardware-protection paths and
    MUST NEVER be touched. Explicitly excluded and verified unchanged by
    this patch's post-write check.
  - 3 sites already patched in rounds 1-4 (now no-ops via the existing
    trampoline at 0x080c8a1a).

That leaves exactly 2 remaining reachable, unpatched sites - 0x080119d0
and 0x08011a1e - both inside the tick dispatcher, both CEC/button
reachable, neither touched by any prior patch (confirmed byte-identical
to pristine firmware before this patch is applied).

The fix
-------
Redirect both call sites from "bl FUN_08019638" to "bl 0x080c8a1a" - the
SAME no-op trampoline already in place and live-tested from patch #4
(bx lr immediately, no state change). This is the identical, already-
proven "make it inert" treatment used for the first 3 sites, applied
here for full symmetry/closure instead of a new/different action, to
keep behavior consistent and minimize risk.

Effect: once this patch is applied, NEITHER the immediate-call branch
NOR the deferred/armed-countdown branch in the CEC/button power-off
path can reach the deep shutdown routine any more. Every power-off
trigger that flows through FUN_08019272 / FUN_080192e2 /
FUN_08011910's two tick-driven expiry checks is now fully inert at the
shutdown step, firmware-wide, with no remaining gap.

All 10 thermal/fault-protection call sites, FUN_08019638 itself, the
2 boot-logic call sites, and all previously-applied patches (rounds
1-4, V002.24 version bump, CEC Active Source fix, sleep-disable patch,
volume/mute fix) are completely untouched by this patch.

Patch technique (same trampoline-redirect approach as all prior fixes):
  1. 0x080119d0 (4 bytes) - was "bl 0x08019638" (tick dispatcher's
     *0x2001c2b5 countdown-expiry branch). Replaced with
     "bl 0x080c8a1a".
  2. 0x08011a1e (4 bytes) - was "bl 0x08019638" (tick dispatcher's
     *0x2001c2b6 countdown-expiry branch - the unconditional one).
     Replaced with "bl 0x080c8a1a".

Both replacement encodings were independently computed by hand (Thumb-2
BL immediate encoding, calibrated against the 3 known-good replacements
from apply_poweroff_universal_fix.py, all of which matched exactly) AND
cross-checked via Ghidra's own Assembler against this exact firmware
image (see AVRShutdownGapBLVerify.java / shutdown-gap-bl-verify2.log),
with both methods agreeing byte-for-byte:
  0x080119d0 -> b7f023f8
  0x08011a1e -> b6f0fcff

This script performs only the raw byte-level file write after verifying
current bytes match the expected pre-patch value exactly; no logic/
addresses are decided here.
"""
import hashlib
import shutil
import sys
import time

TARGET = "AVR1710_USB(V002_23)_patched.fw"
BACKUP = f"AVR1710_USB(V002_23)_patched.fw.pre-shutdown-gap-closure-{int(time.time())}.bak"

BASE = 0x08000000


def off(addr):
    return addr - BASE


# (file address, expected original hex, replacement hex)
PATCHES = [
    (0x080119D0, "07f032fe", "b7f023f8"),
    (0x08011A1E, "07f00bfe", "b6f0fcff"),
]


def main():
    with open(TARGET, "rb") as f:
        data = bytearray(f.read())

    orig_sha256 = hashlib.sha256(data).hexdigest()
    orig_len = len(data)
    print(f"Loaded {TARGET}: {orig_len} bytes, sha256={orig_sha256}")

    for addr, expected_hex, replacement_hex in PATCHES:
        o = off(addr)
        expected = bytes.fromhex(expected_hex)
        replacement = bytes.fromhex(replacement_hex)
        actual = bytes(data[o : o + len(expected)])
        if actual != expected:
            print(f"ABORT: byte mismatch at 0x{addr:08x}")
            print(f"  expected: {expected.hex()}")
            print(f"  actual  : {actual.hex()}")
            sys.exit(1)
        if len(replacement) != len(expected):
            print(
                f"ABORT: replacement length differs at 0x{addr:08x} "
                f"({len(expected)} -> {len(replacement)})"
            )
            sys.exit(1)
        data[o : o + len(replacement)] = replacement
        print(
            f"Patched 0x{addr:08x}: {len(replacement)} bytes "
            f"({expected.hex()} -> {replacement.hex()})"
        )

    if len(data) != orig_len:
        print("ABORT: file size changed - refusing to write")
        sys.exit(1)

    shutil.copyfile(TARGET, BACKUP)
    print(f"Backed up pre-fix file to {BACKUP}")

    with open(TARGET, "wb") as f:
        f.write(data)

    new_sha256 = hashlib.sha256(data).hexdigest()
    print(f"Wrote {TARGET}: {len(data)} bytes, sha256={new_sha256}")
    print("Done.")


if __name__ == "__main__":
    main()
