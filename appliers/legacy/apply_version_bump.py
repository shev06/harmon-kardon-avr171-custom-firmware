#!/usr/bin/env python3
"""
apply_version_bump.py

Bumps the AVR 1710 firmware's displayed version string from "V002.23" to
"V002.24" in-place within the already-patched build
(AVR1710_USB(V002_23)_patched.fw), so the receiver's on-screen system-info
version is visibly distinguishable from stock after flashing.

Background:
- The entire 6,291,456-byte image contains exactly ONE version-like string:
  a 16-byte, space-padded ASCII field "V002.23" at flash address 0x080c4c78
  (file offset is identical, since this firmware uses a simple identity
  address<->file-offset mapping: file_offset = address - 0x08000000).
- This field is pure OSD display data: it is read (not written) by the
  version-formatting routine (FUN_08044c1c) and is never used in any
  comparison/logic path anywhere in the firmware (confirmed by an exhaustive
  xref + whole-image string scan). Changing it carries no functional risk.
- Only the final digit changes ("23" -> "24"), so the field's total length
  is unchanged (still 7 visible characters + padding) -- no other offsets
  anywhere in the file are affected.

Safety checks (same discipline as apply_status_bug_patch.py):
- Operates only on a file path given on the command line (defaults to the
  already-patched build, never the pristine original).
- Verifies the exact original bytes before writing.
- Verifies file size is unchanged after the write.
- Prints a full diff report of exactly what changed.
"""
import sys

VERSION_FIELD_ADDR = 0x080C4C78
BASE_ADDR = 0x08000000
FIELD_LEN = 16

ORIGINAL_FIELD = b"V002.23         "   # 7 chars + 9 spaces = 16 bytes
NEW_FIELD = b"V002.24         "        # same length, only the last digit changes


def main():
    in_path = sys.argv[1] if len(sys.argv) > 1 else "AVR1710_USB(V002_23)_patched.fw"

    with open(in_path, "rb") as f:
        data = bytearray(f.read())

    orig_size = len(data)
    off = VERSION_FIELD_ADDR - BASE_ADDR

    actual = bytes(data[off:off + FIELD_LEN])
    if actual != ORIGINAL_FIELD:
        print(f"ABORT: expected {ORIGINAL_FIELD!r} at offset {hex(off)}, found {actual!r}.")
        print("Refusing to patch -- file does not match expected pre-image.")
        sys.exit(1)

    data[off:off + FIELD_LEN] = NEW_FIELD

    if len(data) != orig_size:
        print(f"ABORT: size changed ({orig_size} -> {len(data)}). Not writing.")
        sys.exit(1)

    with open(in_path, "wb") as f:
        f.write(data)

    print(f"Patched {in_path} in place.")
    print(f"  offset {hex(off)} (addr {hex(VERSION_FIELD_ADDR)}):")
    print(f"    before: {ORIGINAL_FIELD!r}")
    print(f"    after:  {NEW_FIELD!r}")
    print(f"  file size unchanged: {orig_size} bytes")


if __name__ == "__main__":
    main()
