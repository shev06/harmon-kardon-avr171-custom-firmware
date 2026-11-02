import sys
from collections import defaultdict, deque
from blscan import bl_targets
from fastscan import func_of

t = bl_targets()
g = defaultdict(set)
for tgt, lst in t.items():
    callee = func_of(tgt)
    for a, k in lst:
        caller = func_of(a)
        if caller != '?' and callee != '?' and caller != callee:
            g[caller].add(callee)

def reach(roots):
    seen = {}
    q = deque()
    for r in roots:
        seen[r] = None
        q.append(r)
    while q:
        x = q.popleft()
        for y in g.get(x, ()):
            if y not in seen:
                seen[y] = x
                q.append(y)
    return seen

def path(seen, y):
    p = []
    while y is not None:
        p.append(y)
        y = seen[y]
    return ' <- '.join(p)

if __name__ == '__main__':
    roots = sys.argv[1].split(',')
    targets = sys.argv[2].split(',')
    seen = reach(roots)
    print('reachable funcs from roots:', len(seen))
    for tg in targets:
        print(tg, 'REACHED via', path(seen, tg) if tg in seen else 'NOT reached')
