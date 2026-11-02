fw_path = "/Users/allisonbulner/AVR1710_USB(V002_23).fw"
with open(fw_path, "rb") as f:
    data = f.read()

BASE = 0x08000000

def read_cstr(file_off, maxlen=64):
    if file_off < 0 or file_off >= len(data):
        return None
    end = data.find(b"\x00", file_off, file_off + maxlen)
    if end == -1:
        end = file_off + maxlen
    raw = data[file_off:end]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return repr(raw)

def read_u32(file_off):
    return int.from_bytes(data[file_off:file_off+4], "little")

def resolve(sym):
    direct = sym.startswith("&")
    addr = int(sym.split("DAT_")[1], 16)
    file_off = addr - BASE
    if direct:
        return addr, None, read_cstr(file_off)
    ptr = read_u32(file_off)
    ptr_off = ptr - BASE
    s = read_cstr(ptr_off)
    if s is None or not all(32 <= ord(c) < 127 for c in s):
        # value at this address is the raw inline string bytes, not a pointer (e.g. short "on"/"off")
        raw = data[file_off:file_off+4].rstrip(b"\x00")
        try:
            s2 = raw.decode("ascii")
            return addr, None, s2
        except UnicodeDecodeError:
            pass
    return addr, ptr, s

def emit(title, syms):
    print(f"\n# --- {title} ---")
    for sym in syms:
        addr, ptr, s = resolve(sym)
        if ptr is not None:
            print(f"{sym:20s} addr=0x{addr:08x} -> ptr=0x{ptr:08x} -> {s!r}")
        else:
            print(f"{sym:20s} addr=0x{addr:08x} (inline) -> {s!r}")

command_syms = """&DAT_0804a0cc
&DAT_0804a440
&DAT_0804a484
&DAT_0804a5d8
&DAT_0804a5dc
&DAT_0804a5e0
&DAT_0804a774
&DAT_0804ad44
&DAT_0804aeb0
&DAT_0804aeb8
DAT_0804a96c
DAT_0804a970
DAT_0804a978
DAT_0804a984
DAT_0804a994
DAT_0804ad48
DAT_0804ad4c
DAT_0804ade4
DAT_0804ade8
DAT_0804aea0
DAT_0804aea4
DAT_0804aea8
DAT_0804aeb4
DAT_0804aebc
DAT_0804aec0
DAT_0804b034
DAT_0804b040
DAT_0804b044
DAT_0804b050
DAT_0804b054
DAT_0804b058
DAT_0804b05c
DAT_0804b060
DAT_0804b064
DAT_0804b06c
DAT_0804b078
DAT_0804b07c
DAT_0804b080
DAT_0804b084
DAT_0804b088
DAT_0804b08c
DAT_0804b094
DAT_0804b098
DAT_0804b0ac
DAT_0804b0b4
DAT_0804b0b8
DAT_0804b0bc
DAT_0804b0c0
DAT_0804b0c4
DAT_0804b0c8
DAT_0804b0cc
DAT_0804b0d0
DAT_0804b0d4
DAT_0804b0d8
DAT_0804b0dc
DAT_0804b0e0
DAT_0804b0e4
DAT_0804b0e8
DAT_0804b0ec
DAT_0804b0f0
DAT_0804b0f4
DAT_0804b0f8
DAT_0804b0fc
DAT_0804b100
DAT_0804b104
DAT_0804b108
DAT_0804b10c
DAT_0804b110
DAT_0804b128""".split("\n")

response_only_syms = """DAT_0804b038
DAT_0804b03c
DAT_0804b114
&DAT_0804b048
&DAT_0804b04c
DAT_0804b118
DAT_0804b11c
DAT_0804b120
&DAT_0804b068
DAT_0804b124
&DAT_0804b070
&DAT_0804b074""".split("\n")

print("# FUN_08049d90 (TCP:10025 XML/HTTP command dispatcher) -- full command-literal resolution")
print("# Method: every DAT_xxxx / &DAT_xxxx operand passed as the 2nd arg to FUN_08077c44 (strcmp-style")
print("# comparator) inside the decompiled body of FUN_08049d90 (request-pipeline.log lines 1146-2094)")
print("# was resolved by direct, read-only byte-read of the original .fw file:")
print("#   file_offset = address - 0x08000000")
print("#   indirect (DAT_xxxx):  read 4 bytes LE at file_offset -> pointer -> read C-string at (ptr-0x08000000)")
print("#   direct (&DAT_xxxx):   read C-string directly at file_offset (string bytes stored in place)")
print("#   inline-short:         4-byte slot itself holds the raw ASCII bytes (e.g. 'on'/'off'), no pointer")
print(f"# Source firmware: {fw_path} (untouched, opened \"rb\" read-only)")

emit("69 command/zone/source/query-para comparison literals (dispatch conditions)", command_syms)
emit("12 additional response-only literals (query-status power on/off + source numeric-index 0-13 table)", response_only_syms)
