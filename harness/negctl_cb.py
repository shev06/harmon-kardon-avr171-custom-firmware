"""Negative control for the r3 callback-hook fix: the new tests must FAIL on the r2 candidate (hook -> cave trampoline -> helper,
which skipped the dispatcher's Auto-Power-Off timer reset) and reproduce the reviewer's deep-shutdown trace."""
import sys
import paths
r2 = sys.argv[1] if len(sys.argv) > 1 else paths.R2_CANDIDATE
sys.argv = ['negctl_cb', r2]
import test4b as T

print('=== NEGATIVE CONTROL: r2 candidate (%s) ===' % r2)
f1 = T.structure()
f2 = T.hook_equiv(N=30)
# the reviewer's reproduction: CEC callback path, then Auto Power Off with c050 bit2 set and its timer about to expire
for cond in (0, 1):
    emu, ev = T.run(T.CAND, [('path', T.HOOK, T.HOOK + 4), ('call', T.APO), ('ticks', T.NTICKS)],
                    over=dict(c050=0x04, c09c=0, bfb8=0, c038=0, b2b5=0, b2b6=0, bfd8=0),
                    init_bytes=T.apo_init(c160=1, c15e=1), wl=T.WLA, stub_ret={'FUN_08043504': cond})
    sd = [e[2] for e in ev if e[0] == 'W' and e[1] == 'bfb8' and e[2] in (250, 300)]
    print('  callback path + APO (cond=%d): bfb8 shutdown writes %s, deep=%s, marker_clean=%s, entries=%d'
          % (cond, sd, T.deep(emu, ev), T.marker_clean(emu), T.shutdowns(ev)))
print('\nNEGATIVE CONTROL failures (expected > 0): structure=%d hook_equiv=%d' % (f1, f2))
