"""Negative control: the new countdown tests must FAIL on the pre-fix 4b helper (60 bytes, no c2b5/c2b6 clear)."""
import sys
import build_candidate_4b as b
import paths

OLD_HELPER = bytes.fromhex(
    '10b50a4c207880070ed5094c20787f2108402070074c2068642802d250f7b5fa'
    '10bd054c6420207010bd00bf30c0012038c00120b8bf0120b5c20120')
assert len(OLD_HELPER) == 60
deliv = open(paths.BASELINE, 'rb').read()
b.HELPER_BYTES = OLD_HELPER
img = b.build(deliv)
PREFIX = paths.build('candidate4b_prefix.fw')
open(PREFIX, 'wb').write(img)

sys.argv = ['negctl', PREFIX]
import test4b as T

print('=== NEGATIVE CONTROL: pre-fix helper ===')
f1 = T.countdown_unit()
f2 = T.reviewer_trace()
f3 = T.countdown_seq(400)
print('\nNEGATIVE CONTROL failures (expected > 0): unit=%d trace=%d seq=%d' % (f1, f2, f3))
