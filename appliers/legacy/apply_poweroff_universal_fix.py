#!/usr/bin/env python3
"""
apply_poweroff_universal_fix.py

Applies the UNIVERSAL power-off fix to the already-patched
AVR1710_USB(V002_23)_patched.fw (which already contains the query-status
fix, V002.24 version bump, CEC Active Source fix, sleep-disable patch,
and the now-confirmed-inert CEC standby additive patch from the prior
round).

Background
----------
Deep static tracing this round confirmed:
  - FUN_0809b3fc (what the prior CEC-standby patch modified) has NO
    discoverable caller anywhere in the firmware - it is unreachable for
    this TV/firmware pairing, which is why that patch had zero effect on
    real hardware.
  - The REAL, confirmed-reachable CEC <Standby> handler is FUN_0804c39c
    (called every main-loop tick via FUN_08010184 -> FUN_0801074c). Its
    own opcode 0x36 branch already calls FUN_0802d230(4), which in turn
    conditionally calls FUN_080192e2 - the SAME shared power-off handler
    used by button/IR/network/zone2 paths - with NO patch needed for
    that call to happen.
  - FUN_080192e2 (and its sibling FUN_08019272, "power-toggle") has 3
    internal branches gated by a countdown + 2 state-bit variables. Only
    ONE of the 3 branches is "safe" (sets a fade/deferral target and
    returns without shutting down - this is what produces the "sleep
    displayed, still reachable" behavior seen from button presses, and
    is also what network power-off was separately found to hit, per the
    earlier "network power-off root-caused" investigation). The OTHER
    TWO branches (in FUN_080192e2) plus the other unsafe branch (in
    FUN_08019272) call FUN_08019638 directly - the ~150-line deep/full
    shutdown routine that mutes the amp, resets dozens of state vars,
    and (per live testing) appears to also cut the network interface,
    producing the "red light only, fully unreachable" deep power-down.

Which branch is taken depends on live gating-variable state at call
time, which could not be conclusively traced further via static analysis
alone (prior "network power-off" investigation already hit this same
wall and reached the same conclusion for the network-specific case).

The fix
-------
Rather than chase the exact state producer further, this patch makes the
three known "unsafe" call sites (2 in FUN_080192e2, 1 in FUN_08019272)
ALWAYS take the same safe action the properly-gated branch already does
(set the two fade/deferral RAM cells: byte at 0x2001c2b6 = 100, word at
0x2001bfd8 = 0xe10) instead of calling FUN_08019638. This is a drop-in
behavioral replacement for FUN_08019638 at exactly these 3 call sites
only - FUN_08019638 itself, and every OTHER direct caller of it elsewhere
in the firmware (if any), is completely untouched.

Effect: every power-off trigger that flows through these two shared
functions (CEC, network, button, IR, zone2-adjacent) should now
consistently converge on the same "sleep displayed, still reachable"
behavior already proven safe via 5+ minutes of live testing, instead of
sometimes reaching the deep/network-dark shutdown.

Trade-off (documented, confirmed with the user before building): the
receiver will very likely never reach its original deeper/lower-power
"fully powers down" standby again, for ANY trigger - it will always stay
in the lighter, reachable standby instead.

Patch technique (same trampoline approach as all prior fixes):
  1. 0x0801930e (4 bytes) - was "bl 0x08019638" (FUN_080192e2's
     countdown<100 unsafe branch). Replaced with "bl 0x080c8a1a".
  2. 0x08019348 (4 bytes) - was "bl 0x08019638" (FUN_080192e2's
     countdown>=100-but-bit3-set unsafe branch). Replaced with
     "bl 0x080c8a1a".
  3. 0x08019294 (4 bytes) - was "bl 0x08019638" (FUN_08019272's
     countdown<100 unsafe branch). Replaced with "bl 0x080c8a1a".
  4. 0x080c8a1a (28 bytes) - previously free flash space (confirmed
     0xFF-filled, immediately after all prior trampolines). Written
     with a new shared trampoline:
       movw r0,#0xc2b6   ; movt r0,#0x2001   -> r0 = 0x2001c2b6
       movs r1,#0x64
       strb r1,[r0,#0x0]                      ; *0x2001c2b6 = 100
       movw r0,#0xbfd8   ; movt r0,#0x2001   -> r0 = 0x2001bfd8
       movw r1,#0xe10
       str r1,[r0,#0x0]                       ; *0x2001bfd8 = 0xe10
       bx lr                                   ; return to caller, same
                                                ;   as a normal FUN_08019638
                                                ;   call would have

All replacement bytes were produced and round-trip-validated by Ghidra's
own Assembler against this exact firmware image (see
AVRPowerOffFixBuild.java / power-off-fix-build.log for the full
derivation). This script performs only the raw byte-level file write; no
logic/addresses are decided here.
"""
import hashlib
import shutil
import sys

TARGET = "AVR1710_USB(V002_23)_patched.fw"
BACKUP = "AVR1710_USB(V002_23)_patched.fw.pre-poweroff-universal-fix.bak"

BASE = 0x08000000


def off(addr):
    return addr - BASE


# (file address, expected original hex, replacement hex)
PATCHES = [
    (0x0801930E, "00f093f9", "aff084fb"),
    (0x08019348, "00f076f9", "aff067fb"),
    (0x08019294, "00f0d0f9", "aff0c1fb"),
    (
        0x080C8A1A,
        "ff" * 28,
        "4cf2b620c2f20100642101704bf6d870c2f2010040f6106101607047",
    ),
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
