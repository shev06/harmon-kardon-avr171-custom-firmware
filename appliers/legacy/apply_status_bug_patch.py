#!/usr/bin/env python3
"""
apply_status_bug_patch.py

Applies the FUN_08044dc4 "query-status zone/para always empty" fix to a COPY
of the original AVR1710 firmware. Never touches the original file.

What this patches
------------------
FUN_08044dc4(param_1, param_2, param_3) builds every TCP:10025 query-status
XML reply as:
    <name>{param_1}</name><zone></zone><para></para>
param_2 ("zone") and param_3 ("para") are received into registers/stack but
the original code never concatenates them into the output buffer - they are
silently dropped. For the `power` and `source` query-status branches, the
dispatcher *does* compute a real, meaningful param_3 (e.g. "on"/"off", or a
resolved source name) and pass it in - but it's thrown away by this bug.

This patch inserts two small NULL-guarded blocks (in a 68-byte trampoline
placed in previously-erased/free flash space) that actually concatenate
param_2/param_3 into the reply when they are non-zero, and leaves every
existing call site that passes a literal 0 (the overwhelming majority -
volume, mute, playback, heart-alive, and all button-style commands)
completely unaffected, byte-for-byte.

Patch sites (both addresses are STM32 flash / Cortex-M Thumb-2 code):
  1. 0x08044e24 (6 bytes) - was "add r0,sp,#0 ; bl 0x08077bac" (the start of
     the original "</zone><para>" concat step, i.e. instructions I31+I32 of
     FUN_08044dc4). Replaced with "b.w 0x080c89b4 ; nop".
  2. 0x080c89b4 (68 bytes) - previously erased (0xFF) free flash space.
     Written with the new trampoline: NULL-guarded param_2 insert, then the
     original "</zone><para>" concat (reproduced, since site 1 overwrote it),
     then NULL-guarded param_3 insert, then "b.w 0x08044e34" to resume the
     original function exactly where it left off (I37 onward, unmodified).

All replacement bytes were produced and round-trip-validated by Ghidra's own
Assembler against this exact firmware image (see AVRAssemblerValidate.java /
AVRPatchBuild.java and assembler-validate.log / patch-build.log for the full
derivation and validation). This script performs only the raw byte-level
file write; no logic/addresses are decided here.
"""
import hashlib
import sys

SRC = "AVR1710_USB(V002_23).fw"
DST = "AVR1710_USB(V002_23)_patched.fw"

BASE = 0x08000000


def off(addr):
    return addr - BASE


# (file address, expected original hex, replacement hex)
PATCHES = [
    (
        0x08044e24,
        "00a832f0c1fe",
        "83f0c6bd00bf",
    ),
    (
        0x080c89b4,
        "ff" * 68,
        "ddf8040440b100a8aff7f6f8ddf8041400aa8018aff71af9"
        "00a8aff7edf8414600aa8018aff712f9"
        "ddf8080440b100a8aff7e2f8ddf8081400aa8018aff706f9"
        "7cf71eba",
    ),
]


def main():
    with open(SRC, "rb") as f:
        data = bytearray(f.read())

    orig_sha256 = hashlib.sha256(data).hexdigest()
    orig_len = len(data)

    print(f"Loaded {SRC}: {orig_len} bytes, sha256={orig_sha256}")

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
            print(f"ABORT: replacement length differs at 0x{addr:08x} "
                  f"({len(expected)} -> {len(replacement)})")
            sys.exit(1)
        data[o : o + len(replacement)] = replacement
        print(f"Patched 0x{addr:08x}: {len(replacement)} bytes "
              f"({expected.hex()} -> {replacement.hex()})"
              if len(expected) <= 16 else
              f"Patched 0x{addr:08x}: {len(replacement)} bytes")

    if len(data) != orig_len:
        print("ABORT: file size changed - this must never happen for an "
              "in-place binary patch")
        sys.exit(1)

    new_sha256 = hashlib.sha256(data).hexdigest()
    with open(DST, "wb") as f:
        f.write(data)

    print()
    print(f"Wrote {DST}: {len(data)} bytes, sha256={new_sha256}")
    print(f"Original sha256: {orig_sha256}")
    print(f"Patched  sha256: {new_sha256}")

    # Full byte-level diff report vs the original, for the record.
    with open(SRC, "rb") as f:
        orig = f.read()
    diffs = []
    i = 0
    while i < len(orig):
        if orig[i] != data[i]:
            j = i
            while j < len(orig) and orig[j] != data[j]:
                j += 1
            diffs.append((i, j))
            i = j
        else:
            i += 1
    print(f"\nTotal differing byte ranges: {len(diffs)}")
    for s, e in diffs:
        print(f"  0x{s+BASE:08x}-0x{e-1+BASE:08x} ({e-s} bytes): "
              f"{orig[s:e].hex()} -> {data[s:e].hex()}")


if __name__ == "__main__":
    main()
