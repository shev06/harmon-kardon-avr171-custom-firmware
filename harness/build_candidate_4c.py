"""Candidate 4c = candidate 4b + optional patch O1 (disable the stock 1-hour sleep->deep expiry).

O1: 0x08010a56  bne 0x08010a80 (13d1)  ->  b 0x08010a80 (13e0)   (2 bytes, inside FUN_0801074c).
usage: build_candidate_4c.py [<base.fw> [<out.fw>]]   base default: the 4b candidate rebuilt from the deliverable
"""
import hashlib
import sys

import build_candidate_4b as bc
import paths

DELIVERABLE = paths.BASELINE
O1_SITE = 0x08010A56
O1_STOCK = bytes.fromhex('13d1')
O1_NEW = bytes.fromhex('13e0')


def apply_o1(img):
    data = bytearray(img)
    o = O1_SITE - bc.BASE
    assert bytes(data[o:o + 2]) == O1_STOCK, 'unexpected bytes at the O1 site'
    data[o:o + 2] = O1_NEW
    return bytes(data)


if __name__ == '__main__':
    base_path = sys.argv[1] if len(sys.argv) > 1 else None
    out_path = sys.argv[2] if len(sys.argv) > 2 else paths.build('candidate4c.fw')
    base = open(base_path, 'rb').read() if base_path else bc.build(open(DELIVERABLE, 'rb').read())
    out = apply_o1(base)
    open(out_path, 'wb').write(out)
    print('wrote', out_path, len(out), 'bytes sha256', hashlib.sha256(out).hexdigest())
    print('diff vs base:', [hex(bc.BASE + i) for i in range(len(out)) if out[i] != base[i]])
