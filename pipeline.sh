#!/bin/bash
# AVR1710 firmware patch pipeline. Usage: ./pipeline.sh <target>   (./pipeline.sh help)
# Pure bash: no make / Xcode tools needed. Everything is relative to this folder.
set -u
cd "$(dirname "$0")" || exit 2
ROOT=$(pwd)
PY=.venv/bin/python
BASELINE=firmware/baselines/AVR1710_patch4_volmute_a39f47f2.fw
CAND=build/candidate4b.fw
LOGS=build/logs
mkdir -p "$LOGS"

find_python() {
  for p in "${PYTHON:-}" /opt/homebrew/bin/python3.15 /opt/homebrew/bin/python3 python3; do
    [ -n "$p" ] && command -v "$p" >/dev/null 2>&1 && "$p" -c 'import venv,sys;sys.exit(0)' 2>/dev/null && { echo "$p"; return; }
  done
  return 1
}

t_help() { sed -n 's/^#T //p' "$0"; }
#T env            create .venv with capstone + unicorn
t_env() {
  local p; p=$(find_python) || { echo "no working python3 found (set PYTHON=...)"; return 2; }
  "$p" -m venv .venv && $PY -m pip install --quiet --upgrade pip && $PY -m pip install --quiet -r requirements.txt \
    && $PY -c "import sys,capstone,unicorn; print('python',sys.version.split()[0],'capstone',capstone.__version__,'unicorn',unicorn.__version__)"
}
#T status         hash + label every firmware image; show whether Option 4b is applied
t_status() { $PY harness/known_images.py; }
#T candidate      build build/candidate4b.fw from the frozen baseline; must equal the reviewed r3 sha
t_candidate() { $PY harness/make_candidate.py; }
#T test-quick     quick subset of the checks (~2 min)
t_test-quick() { t_candidate && $PY -u harness/quick_new.py $CAND; }
#T test           full validation N=25 seed 1234 (~9 min; must end TOTAL FAILURES: 0)
t_test() { t_candidate && $PY -u harness/test4b.py $CAND 25 1234 2>&1 | tee $LOGS/test4b_n25.log | tail -20; }
#T test-full      full validation N=60 seed 98765 (~14 min)
t_test-full() { t_candidate && $PY -u harness/test4b.py $CAND 60 98765 2>&1 | tee $LOGS/test4b_n60.log | tail -20; }
#T negctl         negative controls (each MUST report failures: r2 candidate, old helper)
t_negctl() {
  $PY -u harness/negctl_cb.py 2>&1 | tee $LOGS/negctl_cb.log | tail -8
  $PY -u harness/negctl.py 2>&1 | tee $LOGS/negctl_oldhelper.log | tail -4
}
#T o1             build + test optional patch O1 (NOT part of r3)
t_o1() { t_candidate && $PY harness/build_candidate_4c.py $CAND build/candidate4c.fw && $PY harness/test_o1.py $CAND build/candidate4c.fw; }
#T ghidra-smoke   check Ghidra + the analysed pristine project (~1 min)
t_ghidra-smoke() {
  ghidra/ghr.sh $LOGS/ghidra-smoke.log AVRSmoke.java
  grep SMOKE $LOGS/ghidra-smoke.log; grep -q "SMOKE dispatcher=FUN_0802d230" $LOGS/ghidra-smoke.log
}
#T ghidra-verify  fresh Ghidra import of the candidate + AVRCecSleep4bVerify.java (~3 min)
t_ghidra-verify() {
  t_candidate && ghidra/ghfresh.sh $CAND $LOGS/fresh-candidate4b.log AVRCecSleep4bVerify.java
  grep -E "PASS|FAIL|OK|MISMATCH|ABORT" $LOGS/fresh-candidate4b.log | tail -40
}
#T apply-dry      applier dry run against the frozen baseline (writes nothing)
t_apply-dry() { AVR_DELIVERABLE=$BASELINE $PY appliers/apply_cec_sleep_fix_4b.py; }
#T apply          APPLY to the live deliverable (firmware/..._patched.fw). Needs CONFIRM=yes. Review verdict first!
t_apply() {
  [ "${CONFIRM:-}" = yes ] || { echo "refusing: re-run as CONFIRM=yes ./pipeline.sh apply (see HANDOFF.md)"; return 2; }
  t_candidate && $PY appliers/apply_cec_sleep_fix_4b.py --apply
}
#T check-paths    fail if any runnable file still references /tmp/avrwork, /tmp/avrenv or /Users/<name>/AVR1710
t_check-paths() {
  if grep -rIl -E "/tmp/avrwork|/tmp/avrenv|/Users/[A-Za-z0-9_]+/AVR1710" harness appliers/apply_cec_sleep_fix_4b.py ghidra/*.sh --exclude-dir=legacy --exclude-dir=__pycache__; then
    echo "dangling absolute paths found"; return 1
  fi
  echo "no dangling absolute paths"
}
#T all-quick      env candidate test-quick apply-dry check-paths
t_all-quick() { t_env && t_candidate && t_test-quick && t_apply-dry && t_check-paths; }

tgt="${1:-help}"
if declare -F "t_$tgt" >/dev/null; then "t_$tgt"; else echo "unknown target: $tgt"; t_help; exit 2; fi
