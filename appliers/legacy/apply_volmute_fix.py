#!/usr/bin/env python3
"""
apply_volmute_fix.py

Applies the volume/mute query-status fix. Targets whatever file path is
passed as argv[1] (defaults to a scratch copy, NOT the real deliverable,
so this can be run safely while the user's receiver is mid-flashing a
previous patch from a separate USB-stick copy of the real file).

Background
----------
query-status replies for volume and mute are structurally empty because
their dispatcher call sites (0x0804ae70, 0x0804ae8e) pass literal 0 for
both the value-string pointer and an unused flag, unlike power/source
(fixed previously) which pass a real computed string pointer. CEC's own
audio-status function FUN_0802d174 already reads the real live state
from RAM (mute/mode flag 0x2001c038 bit4 OR standby-like flag
0x2001c1dc; raw volume byte 0x2001c290, 0-180 scale, raw==1 special-
cased to 1%) - this patch reuses those exact same addresses/formula so
the network reply matches what CEC/OSD would already show.

Design (zero RAM writes, consistent with every other existing
query-status reply in this firmware - always a pre-existing fixed flash
literal, never a dynamically-formatted string):
  - A new 101-entry (0-100) null-terminated ASCII percentage string
    table + 4-byte-aligned pointer table in free flash.
  - A volume trampoline: reads the raw 0-180 byte, computes
    raw*100/180 via hardware udiv (special-cased raw==1 -> 1%, mirroring
    FUN_0802d174's own special case), indexes the pointer table.
  - A mute trampoline: reads the same two live flag bits
    FUN_0802d174 ORs together, and picks the SAME pre-existing "on"/
    "off" flash literals (0x0804b038/0x0804b03c) the power branch
    already uses - zero new risk, same proven pattern.
  - Two 4-byte patch-site replacements (both "bl <trampoline>").

IMPORTANT - rebased from the original design: the original free-space
base (0x080c8a1c) was consumed by the later, separate universal
power-off fix (CEC/network/button deep-shutdown patch, trampoline at
0x080c8a1a-0x080c8a35). This version is rebased to start at 0x080c8a38
(the next free address after that trampoline), confirmed free via a
fresh-import byte-level check against the CURRENT deliverable (see
AVRVolMuteBuild.java / vol-mute-build-v2.log). All byte values below
come directly from that rebuilt plan (volmute_patch_plan_v2.txt).

All replacement bytes were produced and round-trip-validated by Ghidra's
own Assembler against this exact firmware image. This script performs
only the raw byte-level file write; no logic/addresses are decided here.
"""
import hashlib
import sys

BASE = 0x08000000


def off(addr):
    return addr - BASE


STRINGS_HEX = "300031003200330034003500360037003800390031300031310031320031330031340031350031360031370031380031390032300032310032320032330032340032350032360032370032380032390033300033310033320033330033340033350033360033370033380033390034300034310034320034330034340034350034360034370034380034390035300035310035320035330035340035350035360035370035380035390036300036310036320036330036340036350036360036370036380036390037300037310037320037330037340037350037360037370037380037390038300038310038320038330038340038350038360038370038380038390039300039310039320039330039340039350039360039370039380039390031303000"
TABLE_HEX = "388a0c083a8a0c083c8a0c083e8a0c08408a0c08428a0c08448a0c08468a0c08488a0c084a8a0c084c8a0c084f8a0c08528a0c08558a0c08588a0c085b8a0c085e8a0c08618a0c08648a0c08678a0c086a8a0c086d8a0c08708a0c08738a0c08768a0c08798a0c087c8a0c087f8a0c08828a0c08858a0c08888a0c088b8a0c088e8a0c08918a0c08948a0c08978a0c089a8a0c089d8a0c08a08a0c08a38a0c08a68a0c08a98a0c08ac8a0c08af8a0c08b28a0c08b58a0c08b88a0c08bb8a0c08be8a0c08c18a0c08c48a0c08c78a0c08ca8a0c08cd8a0c08d08a0c08d38a0c08d68a0c08d98a0c08dc8a0c08df8a0c08e28a0c08e58a0c08e88a0c08eb8a0c08ee8a0c08f18a0c08f48a0c08f78a0c08fa8a0c08fd8a0c08008b0c08038b0c08068b0c08098b0c080c8b0c080f8b0c08128b0c08158b0c08188b0c081b8b0c081e8b0c08218b0c08248b0c08278b0c082a8b0c082d8b0c08308b0c08338b0c08368b0c08398b0c083c8b0c083f8b0c08428b0c08458b0c08488b0c084b8b0c084e8b0c08518b0c08548b0c08578b0c085a8b0c08"
VOL_CODE_HEX = "4cf29023c2f201031b78012b06d0642000fb03f3b420b3fbf0f300e0012348f66032c0f60c029b00d25800217047"
MUTE_CODE_HEX = "4cf23803c2f201031b7803f01003002b06d14cf2dc13c2f201031b78002b04d04bf23802c0f6040203e04bf23c02c0f6040200217047"

# (file address, expected original hex, replacement hex)
PATCHES = [
    # 2-byte padding gap left exactly as free (0xFF) - not written.
    (0x080C8A38, "ff" * 294, STRINGS_HEX),
    (0x080C8B60, "ff" * 404, TABLE_HEX),
    (0x080C8CF4, "ff" * 46, VOL_CODE_HEX),
    (0x080C8D22, "ff" * 54, MUTE_CODE_HEX),
    (0x0804AE70, "00220021", "7df040ff"),  # bl 0x080c8cf4 (volume trampoline)
    (0x0804AE8E, "00220021", "7df048ff"),  # bl 0x080c8d22 (mute trampoline)
]


def main():
    if len(sys.argv) < 3:
        print("usage: apply_volmute_fix.py <input.fw> <output.fw>")
        sys.exit(1)
    src = sys.argv[1]
    dst = sys.argv[2]

    with open(src, "rb") as f:
        data = bytearray(f.read())

    orig_sha256 = hashlib.sha256(data).hexdigest()
    orig_len = len(data)
    print(f"Loaded {src}: {orig_len} bytes, sha256={orig_sha256}")

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
            f"({len(expected)} bytes region)"
        )

    if len(data) != orig_len:
        print("ABORT: file size changed - refusing to write")
        sys.exit(1)

    with open(dst, "wb") as f:
        f.write(data)

    new_sha256 = hashlib.sha256(data).hexdigest()
    print(f"Wrote {dst}: {len(data)} bytes, sha256={new_sha256}")
    print("Done.")


if __name__ == "__main__":
    main()
