#!/usr/bin/env bash
# Symbolic execution with Mythril (manuscript Section 4.1.1). Produces logs/mythril_*.
# Uses Docker by default (reliable on Apple Silicon); set MYTH_NATIVE=1 to use a local `myth`.
#   docker pull mythril/myth:0.23.22
# Parameters are logged; report exactly these values in the manuscript.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs
TX_COUNT="${MYTH_TX_COUNT:-3}"            # symbolic transaction sequence length
MAX_DEPTH="${MYTH_MAX_DEPTH:-128}"        # max symbolic-execution depth (Mythril default 128)
TIMEOUT="${MYTH_TIMEOUT:-3600}"           # seconds
IMAGE="${MYTH_IMAGE:-mythril/myth:0.23.22}"
ARGS=(analyze contracts/EHRRegistry.sol:EHRRegistry --solv 0.8.20 --solc-json security/mythril-solc.json
      -t "$TX_COUNT" --max-depth "$MAX_DEPTH" --execution-timeout "$TIMEOUT")
echo "mythril params: tx-count=$TX_COUNT max-depth=$MAX_DEPTH execution-timeout=${TIMEOUT}s image=$IMAGE native=${MYTH_NATIVE:-0}" | tee logs/mythril_params.txt
date -u >> logs/mythril_params.txt
if [[ "${MYTH_NATIVE:-0}" == "1" ]]; then
  myth version >> logs/mythril_params.txt
  myth "${ARGS[@]}" -o markdown > logs/mythril_report.md 2> logs/mythril_stderr.log
  myth "${ARGS[@]}" -o jsonv2 > logs/mythril_report.json 2>> logs/mythril_stderr.log
else
  docker run --rm "$IMAGE" version >> logs/mythril_params.txt 2>&1
  docker run --rm -v "$PWD":/src -w /src "$IMAGE" "${ARGS[@]}" -o markdown > logs/mythril_report.md 2> logs/mythril_stderr.log
  docker run --rm -v "$PWD":/src -w /src "$IMAGE" "${ARGS[@]}" -o jsonv2 > logs/mythril_report.json 2>> logs/mythril_stderr.log
fi
echo "mythril exit code: $?" | tee -a logs/mythril_params.txt
echo "Mythril logs written to logs/mythril_*"
