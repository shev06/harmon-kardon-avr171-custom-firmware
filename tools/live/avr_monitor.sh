#!/bin/bash
# Standby reachability monitor: checks TCP:10025 at increasing intervals
# after the receiver was sent power-off, using a hard per-check OS-level
# timeout (10s) so a hung connection/close can never stall the whole test.
CHECKPOINTS=(10 30 60 90 120 150 180 240 300 360)
LAST=0
for CP in "${CHECKPOINTS[@]}"; do
  SLEEP=$((CP - LAST))
  LAST=$CP
  sleep "$SLEEP"
  TS=$(date +%H:%M:%S)
  OUT=$(timeout 12 python3 /tmp/avr_check_once.py "+${CP}s" 2>&1)
  echo "$TS $OUT"
done
echo "$(date +%H:%M:%S) === monitor complete ==="
