"""Every path the harness, builders and appliers use, resolved relative to the project root (the parent of harness/),
so the project folder can live anywhere. Each one can be overridden with an environment variable."""
import os

HARNESS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get('AVR_ROOT', os.path.dirname(HARNESS))
BUILD = os.environ.get('AVR_BUILD', os.path.join(ROOT, 'build'))

PRISTINE = os.environ.get('AVR_PRISTINE', os.path.join(ROOT, 'firmware', 'AVR1710_USB(V002_23).fw'))
# Input of every builder: the frozen pre-4b image (patch #4 + volmute). Unlike DELIVERABLE it never changes, so the
# pipeline stays reproducible after the fix has been applied.
BASELINE = os.environ.get('AVR_BASELINE', os.path.join(ROOT, 'firmware', 'baselines', 'AVR1710_patch4_volmute_a39f47f2.fw'))
# The image the applier writes and the user flashes (the same bytes as BASELINE until Option 4b is applied).
DELIVERABLE = os.environ.get('AVR_DELIVERABLE', os.path.join(ROOT, 'firmware', 'AVR1710_USB(V002_23)_patched.fw'))
R2_CANDIDATE = os.path.join(ROOT, 'firmware', 'candidates', 'AVR1710_4b_r2_33e62c4a_SUPERSEDED.fw')  # negative control
FUNCRANGES = os.path.join(HARNESS, 'funcranges.txt')


def build(name):
    """Path of a generated artifact inside the (git-ignored) build/ directory, which is created on demand."""
    os.makedirs(BUILD, exist_ok=True)
    return os.path.join(BUILD, name)
