"""Probe: for the 96 'DIFF' entries (RAM equal, events differ) print the exact event differences."""
import sys, random, collections
import test4b as T
from test4b import *

rng = random.Random(4242)
N = 5
cats = collections.Counter()
only_c = collections.Counter()
only_r = collections.Counter()
order_ok = 0
total = 0
examples = []
for marker in (0, 1):
    for zone2 in (0, 1):
        for bfb8 in (0, 40, 99, 100, 150, 200):
            for c050 in (0x00, 0x20, 0x08, 0x88):
                for i in range(N // 5 + 1):
                    init, over = make_init(rng, marker, zone2, bfb8, c050)
                    deferred = (bfb8 >= 100) and not (c050 & 0x08)
                    if not deferred:
                        continue
                    for case in (4, 0x20):
                        cand, evc = run(CAND, [('call', 'FUN_0802d230', (case,)), ('ticks', NTICKS)], over=over, init_bytes=init)
                        over_ref = dict(over)
                        over_ref['c038'] = over['c038'] & 0x7F
                        ref_entry = ('call', 'FUN_0802d230', (case,)) if zone2 else ('call', 'FUN_080192e2')
                        steps = [ref_entry, ('poke8', A['b2b5'], 100), ('ticks', NTICKS)]
                        ref, evr = run(PRISTINE, steps, over=over_ref, init_bytes=init)
                        nc, nr = norm2(evc), norm2(evr)
                        same_ram = ram_nodisp(cand) == ram_nodisp(ref)
                        total += 1
                        if nc == nr:
                            cats['equal'] += 1
                            continue
                        cc, cr = collections.Counter(nc), collections.Counter(nr)
                        dc = cc - cr
                        dr = cr - cc
                        for k, v in dc.items():
                            only_c[k] += v
                        for k, v in dr.items():
                            only_r[k] += v
                        # remove the cand-only events (as a multiset) and check the remaining sequences are identical
                        rem = list(nc)
                        for k in dc:
                            for _ in range(dc[k]):
                                rem.remove(k)
                        if rem == nr and not dr:
                            order_ok += 1
                        cats[('differs', same_ram)] += 1
                        if len(examples) < 2:
                            examples.append((marker, zone2, bfb8, hex(c050), hex(case), dc, dr))

print('deferred runs:', total)
print('categories:', dict(cats))
print('events only in candidate:', dict(only_c))
print('events only in reference:', dict(only_r))
print('cases where removing cand-only events makes sequences identical:', order_ok)
for e in examples:
    print('example', e)
