#!/bin/bash
# usage: ghr.sh <logfile> <Script.java> [args...]
# Runs a read-only script on the analysed PRISTINE project (ghidra/project, program "AVR1710_USB(V002_23).fw"). Fast: no re-import.
# Never run two Ghidra jobs at the same time.
LOG="$1"; SCRIPT="$2"; shift 2
source "$(dirname "$0")/env.sh" || exit 2
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$GHIDRA_DIR/project" AVR1710_Ghidra \
  -process "AVR1710_USB(V002_23).fw" -noanalysis -readOnly \
  -scriptPath "$SCRIPT_PATH" \
  -postScript "$SCRIPT" "$@" > "$LOG" 2>&1
echo "EXIT: $?"
