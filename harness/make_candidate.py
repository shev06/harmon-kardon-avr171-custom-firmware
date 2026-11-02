"""Builds build/candidate4b.fw (r3) from the frozen pre-4b baseline and prints the diff accounting. Exits 1 if the result is
not the reviewed r3 image (known_images.EXPECT_CANDIDATE). Never writes the deliverable.
usage: make_candidate.py [out.fw]"""
import hashlib
import sys

import build_candidate_4b as bc
import known_images
import paths

DELIVERABLE = paths.BASELINE  # the frozen pre-4b image; the live deliverable changes once the fix is applied
OUT = sys.argv[1] if len(sys.argv) > 1 else paths.build('candidate4b.fw')


def ranges(idx):
    out = []
    for i in idx:
        if out and i == out[-1][1]:
            out[-1][1] = i + 1
        else:
            out.append([i, i + 1])
    return out


deliv = open(DELIVERABLE, 'rb').read()
pristine = open(bc.PRISTINE_PATH, 'rb').read()
new = bc.build(deliv)
assert len(new) == len(deliv) == len(pristine) == 6291456
open(OUT, 'wb').write(new)
print('wrote', OUT, 'sha256', hashlib.sha256(new).hexdigest())
d = [i for i in range(len(new)) if new[i] != deliv[i]]
p = [i for i in range(len(new)) if new[i] != pristine[i]]
print('bytes differing from deliverable: %d in %d ranges' % (len(d), len(ranges(d))))
for a, b in ranges(d):
    print('   %08x..%08x (%d)' % (bc.BASE + a, bc.BASE + b - 1, b - a))
print('bytes differing from pristine:    %d in %d ranges' % (len(p), len(ranges(p))))
for a, b in ranges(p):
    print('   %08x..%08x (%d)' % (bc.BASE + a, bc.BASE + b - 1, b - a))
outside = [bc.BASE + i for i in d if not any(lo <= bc.BASE + i < hi for lo, hi in bc.CHANGED_RANGES)]
print('bytes outside builder CHANGED_RANGES:', outside)
hook = new[bc.CALLBACK_HOOK - bc.BASE:bc.CALLBACK_HOOK - bc.BASE + 4]
print('hook 0x%08x bytes %s == pristine %s' % (bc.CALLBACK_HOOK, hook.hex(), hook == pristine[bc.CALLBACK_HOOK - bc.BASE:bc.CALLBACK_HOOK - bc.BASE + 4]))
t0 = 0x080c8a0e - bc.BASE
print('cave 0x080c8a0e..35 all 0xFF:', new[t0:t0 + 40] == b'\xff' * 40)
got = hashlib.sha256(new).hexdigest()
ok = got == known_images.EXPECT_CANDIDATE
print('sha256 == reviewed r3 candidate (%s...): %s' % (known_images.EXPECT_CANDIDATE[:12], ok))
sys.exit(0 if ok else 1)
