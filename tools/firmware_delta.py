#!/usr/bin/env python3
"""Publish/apply a firmware build as a byte-level delta against the stock image.

The delta stores only the changed bytes (offset + new bytes) plus the SHA-256 of
the stock image it applies to and of the image it produces, so no Harman Kardon
firmware is distributed.

  firmware_delta.py make  STOCK.fw PATCHED.fw OUT.json "description"
  firmware_delta.py apply STOCK.fw DELTA.json OUT.fw
"""
import hashlib
import json
import os
import sys

MERGE_GAP = 16


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def make(stock_path, patched_path, out_path, description):
    stock = open(stock_path, "rb").read()
    patched = open(patched_path, "rb").read()
    if len(stock) != len(patched):
        sys.exit("size mismatch: delta supports same-size images only")
    changes, start, last = [], None, None
    for i in range(len(stock)):
        if stock[i] == patched[i]:
            continue
        if start is None:
            start = i
        elif i - last > MERGE_GAP:
            changes.append((start, last + 1))
            start = i
        last = i
    if start is not None:
        changes.append((start, last + 1))
    doc = {
        "description": description,
        "size": len(stock),
        "source_sha256": sha256(stock),
        "result_sha256": sha256(patched),
        "changes": [{"offset": f"0x{a:x}", "new": patched[a:b].hex()} for a, b in changes],
    }
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print(f"{out_path}: {len(changes)} ranges, {sum(b - a for a, b in changes)} bytes, result {doc['result_sha256'][:8]}")


def apply(stock_path, delta_path, out_path):
    doc = json.load(open(delta_path))
    stock = bytearray(open(stock_path, "rb").read())
    if sha256(bytes(stock)) != doc["source_sha256"]:
        sys.exit("refusing: input is not the stock image this delta was made for (sha256 mismatch)")
    if os.path.exists(out_path):
        sys.exit(f"refusing to overwrite {out_path}")
    for c in doc["changes"]:
        off, new = int(c["offset"], 16), bytes.fromhex(c["new"])
        stock[off:off + len(new)] = new
    if sha256(bytes(stock)) != doc["result_sha256"]:
        sys.exit("refusing: result sha256 mismatch, nothing written")
    with open(out_path, "wb") as f:
        f.write(stock)
    print(f"wrote {out_path} (sha256 {doc['result_sha256'][:8]}... verified)")


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 5 and a[0] == "make":
        make(a[1], a[2], a[3], a[4])
    elif len(a) == 4 and a[0] == "apply":
        apply(a[1], a[2], a[3])
    else:
        sys.exit(__doc__)
