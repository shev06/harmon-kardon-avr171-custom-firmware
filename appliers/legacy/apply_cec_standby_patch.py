#!/usr/bin/env python3
"""
apply_cec_standby_patch.py

Applies an ADDITIVE fix to the CEC <Standby> (0x36) receive handler in the
already-patched AVR1710_USB(V002_23)_patched.fw (which already contains
the query-status fix, V002.24 version bump, CEC Active Source fix, and
the sleep-disable patch).

Background
----------
Live testing showed the receiver has two distinct "off" states:
  - A lighter "sleep displayed" standby (triggered by the front-panel
    button or the network power-off command), which keeps the network
    control port reachable. This path is handled by FUN_080192e2, a
    shared power-off routine (also used by ~8 other call sites) that
    implements a graceful countdown/fade-deferral before fully shutting
    down via FUN_08019638.
  - A deeper "fully powers down" state (red light only, no on-screen
    text), observed to happen from CEC <Standby> commands sent by the
    TV. This state makes the receiver fully unreachable at the network/
    ARP layer, not just the control port.

Static tracing confirmed FUN_0809b3fc (the CEC RX command handler) does
NOT call FUN_080192e2 for <Standby>. Instead it calls a completely
different, CEC-exclusive function, FUN_0808c9c8(1), which only sets a
single state-flag byte (CEC state struct + offset 0xa = 3) consumed
elsewhere in the CEC/audio subsystem as a "pause normal processing"
guard. No explicit "flag==3 -> hard shutdown" trigger was found; none of
17 literal-pool copies of this struct's base pointer live anywhere near
the main power-sequencing code region that FUN_080192e2 belongs to -
confirming CEC's path is architecturally separate from button/network.

The fix
--------
Rather than guessing at / removing the CEC-internal flag mechanism (which
may still be needed for CEC-protocol bookkeeping), this patch ADDS a call
to the proven, extensively live-tested FUN_080192e2 right alongside the
existing FUN_0808c9c8(1) call in the <Standby> branch. FUN_080192e2 is
self-gating (its very first check is "is the device currently on"; it is
a no-op otherwise), so this call is safe to add unconditionally. If
FUN_080192e2's graceful countdown/fade logic is really what produces the
reachable "soft standby" for button/network, routing CEC through the same
function should make CEC-triggered standby converge to the same
behavior.

Patch technique (same trampoline approach as prior fixes):
  1. 0x0809b44a (4 bytes) - was "bl 0x0808c9c8" (the CEC flag-setter call,
     reached only when the <Standby> operand length byte == 0, i.e. a
     valid frame). Replaced with "bl 0x080c8a0e" (exact 4-byte swap, BL
     for BL, no padding needed).
  2. 0x080c8a0e (12 bytes) - previously free flash space (confirmed
     0xFF-filled, immediately after the existing CEC Active-Source-fix
     trampoline which ends at 0x080c8a0e). Written with:
       bl 0x0808c9c8   ; reproduce the original call (r0 is still 1,
                       ;   preserved from the untouched "movs r0,#0x1"
                       ;   two instructions before the patch site)
       bl 0x080192e2    ; THE FIX: also invoke the proven network/button
                        ;   power-off handler
       b.w 0x0809b44e    ; return to the original next instruction
                         ;   ("b 0x0809b456", unchanged)

All other CEC opcodes (<Routing Change>, <Routing Information>,
<Active Source>, <Set Stream Path>) and the <Standby> invalid-length
error path are untouched - the patch site is exclusive to the valid-
length <Standby> success branch.

All replacement bytes were produced and round-trip-validated by Ghidra's
own Assembler against this exact firmware image (see
AVRCecStandbyPatchBuild.java / cec-standby-patch-build.log for the full
derivation). This script performs only the raw byte-level file write; no
logic/addresses are decided here.
"""
import hashlib
import shutil
import sys

TARGET = "AVR1710_USB(V002_23)_patched.fw"
BACKUP = "AVR1710_USB(V002_23)_patched.fw.pre-cec-standby-fix.bak"

BASE = 0x08000000


def off(addr):
    return addr - BASE


# (file address, expected original hex, replacement hex)
PATCHES = [
    (
        0x0809B44A,
        "f1f7bdfa",
        "2df0e0fa",
    ),
    (
        0x080C8A0E,
        "ff" * 12,
        "c3f7dbff50f766fcd2f71abd",
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
