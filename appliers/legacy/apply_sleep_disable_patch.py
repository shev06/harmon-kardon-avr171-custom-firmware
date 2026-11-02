#!/usr/bin/env python3
"""
apply_sleep_disable_patch.py

Applies the "disable STOP-mode sleep" patch IN-PLACE to the already-patched/
already-flashed AVR1710_USB(V002_23)_patched.fw (which already contains the
query-status fix, the V002.24 version bump, and the CEC Active Source fix).

Why
---
User-requested: keep the TCP:10025 control port (and therefore the Home
Assistant integration) reachable whenever the receiver has mains power,
instead of going dark once it enters real standby.

Due diligence performed before writing this patch (this session):
  - Re-extracted FUN_08064de8's raw bytes directly from the CURRENT
    patched .fw (not just relying on older analysis of the pristine
    original), and fully re-disassembled it with arm-none-eabi-objdump.
  - Confirmed there is exactly ONE occurrence of the PWR_CR register
    literal (0x40007000) anywhere in the entire 6 MiB image, and it
    belongs to this exact function - i.e. this is provably the only place
    in the firmware that configures the CPU for STM32F4 STOP mode.
  - Confirmed the only two WFI/WFE instructions within 64 bytes of that
    literal (i.e. actually part of this function) are at 0x08064e0e and
    0x08064e12 - every other raw WFI/WFE-looking byte pattern elsewhere in
    the image is either misaligned (not a real instruction boundary) or
    not associated with any PWR_CR configuration, so it cannot be a STOP-
    mode entry (shallow Cortex-M "wait for interrupt" at full power, used
    for an idle busy-wait, does not gate peripheral clocks - unrelated to
    the observed "port goes completely dark" behavior).
  - Checked for an independent watchdog (IWDG, base 0x40003000) that could
    make "never truly sleeping" risky; the one raw byte match for that
    address is at a non-2-byte-aligned offset surrounded by nonsense
    disassembly - a coincidental match inside a data region, not real
    code. No IWDG dependency found.
  - Confirmed FUN_08064de8 is a void-like leaf-ish function (push {r4} /
    ... / pop {r4} / bx lr, no return value setup) - callers cannot be
    depending on a "did it actually sleep" result.

What this patches
------------------
FUN_08064de8 is the sole STM32 STOP-mode sleep-entry routine (configures
PWR_CR's LPDS/PDDS bits, sets SCB->SCR SLEEPDEEP, then executes WFI or WFE
depending on its second argument, then clears SLEEPDEEP on wake). Full
disassembly of the relevant section (addresses are in the CURRENT patched
.fw, unchanged from the pristine original since nothing has touched this
region before):

    8064e08: b2c9        uxtb r1, r1
    8064e0a: 2901        cmp  r1, #1
    8064e0c: d101        bne.n 0x8064e12
    8064e0e: bf30        wfi            <- PATCH POINT 1: replaced with nop
    8064e10: e000        b.n  0x8064e14
    8064e12: bf20        wfe            <- PATCH POINT 2: replaced with nop
    8064e14: 4b04        ldr  r3, [pc, #16]   (SCB->SCR)
    ...                                  (clears SLEEPDEEP, pops, returns)

Both WFI (0xbf30) and WFE (0xbf20) are single 16-bit Thumb instructions,
replaced in place with the canonical 16-bit Thumb NOP (0xbf00). This is a
same-size, zero-trampoline, two-instruction patch: every other instruction
in the function - the PWR_CR read/modify/write, the SLEEPDEEP set, the
branch that chooses WFI vs WFE, and the SLEEPDEEP clear + GPIO/clock
restore done by the caller afterwards - is completely untouched and keeps
running exactly as before. The only behavioral change: the CPU no longer
actually halts its clock at that point, so execution falls straight
through to the SLEEPDEEP-clear step immediately, as if it had woken
instantly. The caller's post-wake GPIO-restore and peripheral-clock
re-enable (already unconditionally executed right after this function
returns) then run right away, keeping every peripheral bus - including
whatever feeds the network-facing bridge chip - continuously clocked.

What this does NOT touch (by design, to keep the patch minimal and its
effects predictable): the countdown-arm mechanism that decides *when* to
call this routine, the pre-sleep/post-wake GPIO reconfiguration, and the
separate DAT_08019354-gated logic that actually powers down the amplifier/
display/relay outputs (FUN_080192ce/FUN_080192e2) are all unmodified - the
receiver should still visually/audibly appear to turn off exactly as
before; only the MCU's own clock-gating stops happening.

Residual uncertainty (being transparent, not just optimistic): there is no
schematic-level pin mapping available to 100% rule out some other subtle
effect of the CPU never truly halting (e.g. slightly higher standby power
draw/heat is the expected, accepted trade-off; anything beyond that has
not been observed because this cannot be tested without real hardware).
This should be tested live after flashing before relying on it.
"""
import hashlib
import shutil
import sys

TARGET = "AVR1710_USB(V002_23)_patched.fw"
BACKUP = "AVR1710_USB(V002_23)_patched.fw.pre-sleep-disable-fix.bak"

BASE = 0x08000000


def off(addr):
    return addr - BASE


# (file address, expected original hex, replacement hex)
PATCHES = [
    (0x08064E0E, "30bf", "00bf"),  # wfi -> nop
    (0x08064E12, "20bf", "00bf"),  # wfe -> nop
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
