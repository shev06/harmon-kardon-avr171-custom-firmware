#!/bin/bash
# usage: ghfresh.sh <firmware file> <logfile> <Script.java> [args...]
# FRESH import (full auto-analysis, ~2-3 min) of an image into a throw-away project, runs a script, deletes the project.
# Used to verify a candidate/deliverable independently of the analysed pristine project. Never run two Ghidra jobs at once.
FW="$1"; LOG="$2"; SCRIPT="$3"; shift 3
source "$(dirname "$0")/env.sh" || exit 2
TMPD=$(mktemp -d /tmp/ghfresh.XXXXXX)
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$TMPD" fresh_verify \
  -import "$FW" \
  -loader BinaryLoader -loader-baseAddr 0x08000000 -processor "ARM:LE:32:Cortex" \
  -readOnly \
  -scriptPath "$SCRIPT_PATH" \
  -postScript "$SCRIPT" "$@" \
  -deleteProject > "$LOG" 2>&1
echo "EXIT: $?"
rm -rf "$TMPD"
