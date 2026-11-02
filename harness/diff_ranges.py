"""Read-only: list differing byte ranges between two images."""
import sys


def ranges(a, b, gap=0):
    out = []
    start = None
    last = None
    for i in range(len(a)):
        if a[i] != b[i]:
            if start is None:
                start = i
            elif i - last > gap + 1:
                out.append((start, last))
                start = i
            last = i
    if start is not None:
        out.append((start, last))
    return out


base = 0x08000000
a = open(sys.argv[1], 'rb').read()
b = open(sys.argv[2], 'rb').read()
assert len(a) == len(b)
r = ranges(a, b)
tot = sum(e - s + 1 for s, e in r)
print('%d differing bytes in %d ranges' % (tot, len(r)))
for s, e in r:
    print('  0x%08x..0x%08x  (%d B)' % (base + s, base + e, e - s + 1))
