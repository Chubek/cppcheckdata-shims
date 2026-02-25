#!/bin/bash
# energy_measure.sh — Run a program N times and report average energy
PROGRAM="$1"
N="${2:-10}"
TOTAL_UJ=0

for i in $(seq 1 $N); do
    BEFORE=$(cat /sys/class/powercap/intel-rapl:0/energy_uj)
    $PROGRAM > /dev/null 2>&1
    AFTER=$(cat /sys/class/powercap/intel-rapl:0/energy_uj)
    DELTA=$(( AFTER - BEFORE ))
    TOTAL_UJ=$(( TOTAL_UJ + DELTA ))
    echo "Run $i: ${DELTA} µJ"
done

AVG=$(( TOTAL_UJ / N ))
echo "Average over $N runs: ${AVG} µJ  ($(echo "scale=6; $AVG / 1000000" | bc) J)"
