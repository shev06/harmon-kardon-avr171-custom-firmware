import hashlib
import shutil
import sys

TARGET = "/Users/allisonbulner/AVR1710_USB(V002_23)_patched.fw"
SCRATCH = "/tmp/volmute_scratch_test_v2.fw"
BACKUP = TARGET + ".pre-volmute-fix.bak"
BASE = 0x08000000

# Regions proven (by full diff + reference scan) to belong solely to the
# volume/mute fix, independent of the power-off trampoline region which must
# be left as its current no-op content.
REGIONS = [
    (0x0804ae70, 0x0804ae73),
    (0x0804ae8e, 0x0804ae91),
    (0x080c8a38, 0x080c8b5d),
    (0x080c8b60, 0x080c8d57),
]

EXPECTED_OLD = {
    0x0804ae70: bytes.fromhex("00220021"),
    0x0804ae8e: bytes.fromhex("00220021"),
}

with open(TARGET, "rb") as f:
    data = bytearray(f.read())
with open(SCRATCH, "rb") as f:
    scratch = f.read()

orig_size = len(data)
assert len(scratch) == orig_size, "scratch/real size mismatch"
print(f"Opened target ({orig_size} bytes) and scratch ({len(scratch)} bytes)")

# Verify-before-write checks
for addr, expect in EXPECTED_OLD.items():
    o = addr - BASE
    actual = bytes(data[o:o+len(expect)])
    print(f"0x{addr:08x}: current={actual.hex()} expected={expect.hex()}")
    if actual != expect:
        print("ABORT: patch site doesn't match expected pre-patch bytes.")
        sys.exit(1)

for start, end in REGIONS:
    o_start, o_end = start - BASE, end - BASE
    if start >= 0x080c8a38:  # free-space regions must currently be blank
        region = data[o_start:o_end+1]
        if any(b != 0xFF for b in region):
            print(f"ABORT: free-space region 0x{start:08x}-0x{end:08x} is not blank.")
            sys.exit(1)
        print(f"0x{start:08x}-0x{end:08x}: confirmed blank ({len(region)} bytes)")

shutil.copy2(TARGET, BACKUP)
print(f"Backup written: {BACKUP}")

for start, end in REGIONS:
    o_start, o_end = start - BASE, end - BASE
    data[o_start:o_end+1] = scratch[o_start:o_end+1]

if len(data) != orig_size:
    print("ABORT: size changed unexpectedly, not writing.")
    sys.exit(1)

# Sanity: power-off trampoline region must be UNTOUCHED (still the no-op we verified)
NOOP_TRAMPOLINE = bytes.fromhex("7047") + bytes.fromhex("00bf") * 13
po_off = 0x080c8a1a - BASE
if bytes(data[po_off:po_off+28]) != NOOP_TRAMPOLINE:
    print("ABORT: power-off no-op trampoline region changed unexpectedly!")
    sys.exit(1)
print("Power-off no-op trampoline region confirmed unchanged.")

with open(TARGET, "wb") as f:
    f.write(data)

with open(TARGET, "rb") as f:
    verify = f.read()
assert len(verify) == orig_size
for start, end in REGIONS:
    o_start, o_end = start - BASE, end - BASE
    assert verify[o_start:o_end+1] == scratch[o_start:o_end+1], f"verify failed at 0x{start:08x}"
assert verify[po_off:po_off+28] == NOOP_TRAMPOLINE
print("Post-write verification OK (all regions + power-off trampoline).")
print("New file sha256:", hashlib.sha256(verify).hexdigest())
print("Backup sha256:", hashlib.sha256(open(BACKUP,'rb').read()).hexdigest())
