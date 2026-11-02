import hashlib
import shutil
import sys

TARGET = "/Users/allisonbulner/AVR1710_USB(V002_23)_patched.fw"
BACKUP = TARGET + ".pre-poweroff-noop-fix.bak"

TRAMPOLINE_ADDR = 0x080c8a1a
BASE = 0x08000000
OFF = TRAMPOLINE_ADDR - BASE

# Exact bytes currently at the trampoline (the "safe action" that arms the
# fatal countdown) -- read fresh from the real file immediately before, for
# the verify-before-write check.
EXPECTED_OLD = bytes.fromhex("4cf2b620c2f20100642101704bf6d870c2f2010040f6106101607047")
assert len(EXPECTED_OLD) == 28, f"unexpected old-bytes length {len(EXPECTED_OLD)}"

# New body: bx lr (immediate return, no RAM writes at all) + NOP padding to
# keep the exact same 28-byte footprint (no relocation of anything else).
NEW_BYTES = bytes.fromhex("7047") + bytes.fromhex("00bf") * 13
assert len(NEW_BYTES) == 28, f"unexpected new-bytes length {len(NEW_BYTES)}"

with open(TARGET, "rb") as f:
    data = bytearray(f.read())

orig_size = len(data)
print(f"Opened {TARGET}, size={orig_size}")

actual_old = bytes(data[OFF:OFF+28])
print(f"Bytes currently at 0x{TRAMPOLINE_ADDR:08x} (file off 0x{OFF:x}): {actual_old.hex()}")
if actual_old != EXPECTED_OLD:
    print("ABORT: current bytes do not match expected pre-patch trampoline. Not writing.")
    sys.exit(1)

shutil.copy2(TARGET, BACKUP)
print(f"Backup written: {BACKUP}")

data[OFF:OFF+28] = NEW_BYTES

if len(data) != orig_size:
    print("ABORT: size changed unexpectedly, not writing.")
    sys.exit(1)

with open(TARGET, "wb") as f:
    f.write(data)

with open(TARGET, "rb") as f:
    verify = f.read()
assert len(verify) == orig_size
assert verify[OFF:OFF+28] == NEW_BYTES, "post-write verification failed!"
print("Post-write verification OK.")
print(f"New bytes at trampoline: {verify[OFF:OFF+28].hex()}")
print("New file sha256:", hashlib.sha256(verify).hexdigest())
print("Old file (backup) sha256:", hashlib.sha256(open(BACKUP,'rb').read()).hexdigest())
