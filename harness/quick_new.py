import sys
import paths
cand = sys.argv[1] if len(sys.argv) > 1 else paths.build('candidate4b.fw')
sys.argv = ['t', cand]
import test4b as T
tot = 0
tot += T.structure()
tot += T.hook_equiv(N=30)
tot += T.tail_oracle(5)
tot += T.apo()
print('QUICK TOTAL', tot)
