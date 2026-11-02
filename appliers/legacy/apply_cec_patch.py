#!/usr/bin/env python3
"""
apply_cec_patch.py

Applies the CEC "Active Source validation bypass" fix IN-PLACE to the
already-patched/already-flashed AVR1710_USB(V002_23)_patched.fw (which
already contains the query-status fix and the V002.24 version bump).

What this patches
------------------
FUN_0809b3fc is the incoming-CEC-command handler for <Standby> (0x36),
<Routing Change> (0x80), <Routing Information> (0x81), <Active Source>
(0x82), and <Set Stream Path> (0x86). Each opcode validates an operand-
length byte before trusting the operand data - except <Active Source>:

    if (sVar3 == 0x82) {
        if (param_1[0x14] != 2) {
            FUN_0809b394(DAT_0809b678);   // reports "wrong length"...
        }
        FUN_0808cde0(*param_1 >> 4, CONCAT11(param_1[4],param_1[5]));  // ...but runs anyway
    }

Confirmed at the disassembly level: the "wrong length" path falls straight
through into the same FUN_0808cde0 call used by the valid-length path -
there is no skip/return on error, unlike every other opcode in this
function. Impact (traced precisely): FUN_0808cde0 only writes the parsed
(possibly garbage) source logical address + physical address into the
"last known active source" tracking slot - it does not itself trigger an
input switch (that path, <Set Stream Path>, independently re-checks the
same length byte and is unaffected). So a non-conformant <Active Source>
frame from a CEC peer corrupts an internal tracking value; it does not
reach the real switch logic.

Patch technique (same trampoline approach as the query-status fix):
  1. 0x0809b4bc (4 bytes) - was "beq 0x0809b4c4 ; ldr r0,[0x0809b678]"
     (the length-check branch + the start of the error-report call).
     Replaced with "b.w 0x080c89f8" (exact 4-byte swap, no padding).
  2. 0x080c89f8 (22 bytes) - previously free flash space (confirmed empty,
     0xFF-filled, directly adjacent to the existing query-status
     trampoline which ends at 0x080c89f8). Written with:
       beq.w 0x0809b4c4      ; re-test the SAME flags from the untouched
                             ;   "cmp r0,#0x2" two instructions earlier
                             ;   (branches don't affect flags, so they're
                             ;   still valid when we land here)
       movw r0,#0x9678       ; rebuild the literal-pool address 0x0809b678
       movt r0,#0x0809       ;   (too far from this trampoline for a
                             ;   relocated PC-relative ldr to reach)
       ldr  r0,[r0]          ; dereference -> r0 = error string pointer
                             ;   (replicates the displaced "ldr r0,[...]" )
       bl   0x0809b394       ; report the error (replicates original call)
       b.w  0x0809b4d8       ; THE FIX: skip FUN_0808cde0 entirely on the
                             ;   error path, resume at the shared tail that
                             ;   <Set Stream Path> also uses (which
                             ;   independently re-checks length==2 and
                             ;   already correctly gates the real switch)

The valid-length (==2) path is completely unchanged in behavior - it still
reaches the same code, just via one extra unconditional jump through the
trampoline's first instruction (negligible, a few cycles on a CEC message
handler).

All replacement bytes were produced and round-trip-validated by Ghidra's
own Assembler against this exact firmware image (see AVRCecPatchBuild.java
/ cec-patch-build.log for the full derivation). This script performs only
the raw byte-level file write; no logic/addresses are decided here.
"""
import hashlib
import shutil
import sys

TARGET = "AVR1710_USB(V002_23)_patched.fw"
BACKUP = "AVR1710_USB(V002_23)_patched.fw.pre-cec-fix.bak"

BASE = 0x08000000


def off(addr):
    return addr - BASE


# (file address, expected original hex, replacement hex)
PATCHES = [
    (
        0x0809b4bc,
        "02d06e48",
        "2df09cba",
    ),
    (
        0x080c89f8,
        "ff" * 22,
        "12f464ad49f27860c0f609000068d2f7c5fcd2f765bd",
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
