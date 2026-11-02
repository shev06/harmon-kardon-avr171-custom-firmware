"""Known AVR1710 firmware images (sha256 -> label) and the `make status` report.

usage: python harness/known_images.py
"""
import hashlib
import os

import paths

PRISTINE = '396f14e3aea394685647b5a366107fd7e4150283a2c42a04428c955ce3cdf34b'
BASELINE = 'a39f47f29a43eb4124abe20031fc5f09a12728c3ef9bd25ec7d01dfb2d94898e'
R3 = '37ba4f65aa35b1a43bc0c8f6b45c5b346d1ed33bd262f543c579c394681f50e6'
# make_candidate.py fails when the builder no longer produces this image; update it (and the applier) for a new revision
EXPECT_CANDIDATE = R3

KNOWN = {
    PRISTINE: 'PRISTINE stock V002.23 (reference for every diff)',
    BASELINE: 'patch #4 (CEC no-op trampoline) + volmute = builder baseline / deliverable BEFORE Option 4b',
    R3: 'Option 4b r3 (reviewed CLEAN; live-confirmed CEC standby sleeps; before O1)',
    '33e62c4ac32709edc6af869680be19f34ac4c7b55f6b4fd8d75d6317e06c5f99': 'Option 4b r2 (SUPERSEDED; negative control for the callback hook)',
    '85c78bc916a2c6bf3f100a08292972b76bc6e4a5ccf2b7c9826f0139331d0507': 'Option 4b r3 + O1 (1-hour deep timer disabled; reviewed CLEAN; current deliverable)',
    '629cd9a756c4d74069682ad0302f2b865495e00bf29ccd5a72d6dc7f96c0c66f': 'Option 4 r1 candidate (SUPERSEDED)',
    # lineage, oldest first; each state includes every earlier fix (see analysis/subsystem-findings.md)
    '954d0e348b6ff6792256635342a392c5a001a5d5eb57f5006c2414b4c6f39264': 'lineage 1: query-status fix + V002.24 version bump (backup before the CEC Active Source fix)',
    'df17e021f450017036e5e2656c3c7008dcff02433f48aabcd78ea0e89ddb6bd7': 'lineage 2: + CEC Active Source fix (backup before the sleep-disable fix)',
    '0f27feda9f3a84c3bc30d6a04f356400ce37cfd08e455c93c87e68df23bdf590': 'lineage 3: + sleep-disable WFI->NOP (backup before the CEC additive standby patch)',
    '286e67cb4f7793b439896582da7aa52d108164f0d53b940014824e42d14559c8': 'lineage 4: + CEC additive standby hook at 0x0809b44a (backup before the "universal" power-off fix)',
    '2031965e083f559a265aa441f4ff087d09eb3a7f3e93af5deee0d746909ef6fb': 'lineage 5: + first "universal" power-off fix (backup before the no-op variant)',
    '98a1b5db5506892d05ceaf668b4df796afb913963b952e15a97ec174bebab553': 'lineage 6: patch #4 no-op trampoline (backup before the volmute fix)',
    'a5bd87474cd75f59752b9627eefecdf2acc1548233e88ea87b37eda6537269a7': 'patch #5 "shutdown gap closure" (BROKEN: device never slept; reverted)',
    '7c0fda746734fbdea2f26b180699de6469720f53405d58eb8790c2b63b1de06a': 'earliest 14-byte test image (0x080c34a4..b3), ~/Documents/..._TEST.fw',
}


def sha256(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    rows = []
    for top in ('firmware', 'build'):
        for dirpath, _, files in sorted(os.walk(os.path.join(paths.ROOT, top))):
            for name in sorted(files):
                if '.fw' in name:
                    p = os.path.join(dirpath, name)
                    rows.append((os.path.relpath(p, paths.ROOT), sha256(p)))
    for rel, h in rows:
        print('%s  %-78s %s' % (h[:12], rel, KNOWN.get(h, '(unlabelled)')))
    live = sha256(paths.DELIVERABLE)
    print()
    print('live deliverable : %s' % KNOWN.get(live, 'UNKNOWN image %s' % live))
    if live == BASELINE:
        print('Option 4b       : NOT applied (the deliverable is still the pre-4b baseline)')
    elif live == R3:
        print('Option 4b       : r3 APPLIED to the deliverable (O1 not applied: the 1-hour sleep->deep timer is live)')
    elif live.startswith('85c78bc916a2'):
        print('Option 4b       : r3 + O1 APPLIED to the deliverable')


if __name__ == '__main__':
    main()
