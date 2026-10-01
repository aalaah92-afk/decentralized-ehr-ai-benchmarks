#!/usr/bin/env bash
# Static analysis with Slither (manuscript Section 4.1.1). Produces logs/slither_*.
#   pipx install slither-analyzer==0.10.0   (or: pip install slither-analyzer==0.10.0)
#   pip install solc-select && solc-select install 0.8.20 && solc-select use 0.8.20
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs
{ echo "slither $(slither --version)"; echo "solc: $(solc --version | tail -1)"; date -u; } > logs/slither_versions.txt
npx hardhat compile --quiet
# Full detector run against the Hardhat build (dependencies = OpenZeppelin excluded from findings)
slither . --hardhat-ignore-compile --filter-paths "node_modules" \
  --json logs/slither_results.json --checklist > logs/slither_report.md 2> logs/slither_stdout.log
echo "slither exit code: $? (non-zero means findings were reported, see logs/slither_report.md)" | tee -a logs/slither_stdout.log
slither . --hardhat-ignore-compile --filter-paths "node_modules" --print human-summary > logs/slither_human_summary.log 2>&1 || true
slither . --hardhat-ignore-compile --filter-paths "node_modules" --print function-summary > logs/slither_function_summary.log 2>&1 || true
echo "Slither logs written to logs/slither_*"
