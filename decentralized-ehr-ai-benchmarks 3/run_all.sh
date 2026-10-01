#!/usr/bin/env bash
# Reproduce every smart-contract / cryptography artefact reported in the manuscript and write
# raw execution logs to ./logs. Each step is independent: a failing optional step is recorded
# in logs/run_all_summary.txt and the script continues.
#
# Prerequisites: Node >= 18, npm; Foundry (forge); Python 3 + slither-analyzer 0.10.0 + solc-select;
# Docker (for Mythril). Optional: Kubo `ipfs daemon` for the IPFS benchmark.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p logs
SUMMARY=logs/run_all_summary.txt
: > "$SUMMARY"

step() {  # step <name> <logfile> <command...>
  local name="$1" log="$2"; shift 2
  echo "==> $name" | tee -a "$SUMMARY"
  local start=$(date +%s)
  if "$@" 2>&1 | tee "logs/$log"; then
    echo "    OK   ($(( $(date +%s) - start )) s) -> logs/$log" | tee -a "$SUMMARY"
  else
    echo "    FAILED ($(( $(date +%s) - start )) s) -> logs/$log" | tee -a "$SUMMARY"
  fi
}

# ---------------------------------------------------------------- environment record
{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "os: $(uname -a)"
  if [[ "$(uname)" == "Darwin" ]]; then
    echo "cpu: $(sysctl -n machdep.cpu.brand_string)"; echo "mem_bytes: $(sysctl -n hw.memsize)"
  else
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"; echo "mem: $(grep MemTotal /proc/meminfo)"
  fi
  echo "node: $(node -v)"; echo "npm: $(npm -v)"
  echo "forge: $(forge --version 2>/dev/null | head -1 || echo 'not installed')"
  echo "slither: $(slither --version 2>/dev/null || echo 'not installed')"
  echo "docker: $(docker --version 2>/dev/null || echo 'not installed')"
  echo "ipfs: $(ipfs version 2>/dev/null || echo 'not installed')"
  echo "contract_sha256: $(shasum -a 256 contracts/EHRRegistry.sol 2>/dev/null || sha256sum contracts/EHRRegistry.sol)"
  echo "git_commit: $(git rev-parse HEAD 2>/dev/null || echo 'n/a')"
} > logs/environment.txt
cat logs/environment.txt

# ---------------------------------------------------------------- install + compile
[[ -d node_modules ]] || step "npm install" npm_install.log npm install --no-audit --no-fund
step "compile (solc 0.8.20)" compile.log npx hardhat compile --force
[[ -f artifacts/contracts/EHRRegistry.sol/EHRRegistry.json ]] && \
  node -e 'const a=require("./artifacts/contracts/EHRRegistry.sol/EHRRegistry.json");console.log("bytecode_bytes:",(a.deployedBytecode.length-2)/2)' >> logs/environment.txt

# ---------------------------------------------------------------- functional + adversarial tests
step "hardhat tests + gas reporter" hardhat_test.log env REPORT_GAS=1 npx hardhat test

# ---------------------------------------------------------------- benchmarks
step "gas benchmark (${GAS_ITERATIONS:-1000} iterations)" gas_benchmark.log npx hardhat run scripts/benchmark-gas.js
step "concurrent throughput benchmark" throughput_benchmark.log npx hardhat run scripts/benchmark-throughput.js
step "crypto micro-benchmark" crypto_benchmark.log node scripts/benchmark-crypto.js
step "end-to-end latency (hardhat)" e2e_latency_hardhat.log npx hardhat run scripts/e2e-latency.js
if curl -s -X POST "${IPFS_API:-http://127.0.0.1:5001}/api/v0/version" >/dev/null 2>&1; then
  step "IPFS benchmark (Kubo)" ipfs_benchmark.log node scripts/benchmark-ipfs.js
else
  echo "==> IPFS benchmark skipped (no Kubo daemon at ${IPFS_API:-http://127.0.0.1:5001})" | tee -a "$SUMMARY"
fi

# ---------------------------------------------------------------- off-chain modules, simulations, AI self-test
step "off-chain tests (AES-GCM, ECIES, Shamir, stealth)" offchain_tests.log node --test --test-reporter=spec offchain-tests/crypto.test.js offchain-tests/primitives.test.js offchain-tests/shamir.test.js offchain-tests/stealth.test.js
step "IPFS availability simulation" ipfs_availability_run.log python3 simulations/ipfs_availability.py
step "linkability simulation" linkability_run.log python3 simulations/linkability.py
step "AI evaluation self-test (synthetic)" ai_selftest_run.log python3 ai/synthetic_selftest.py

# ---------------------------------------------------------------- Foundry fuzz + invariants
if command -v forge >/dev/null; then
  [[ -d lib/forge-std ]] || step "forge-std install" forge_install.log forge install --no-git foundry-rs/forge-std@v1.9.4
  step "foundry fuzz + invariant tests" foundry_test.log forge test -vv
else
  echo "==> Foundry skipped (forge not installed: curl -L https://foundry.paradigm.xyz | bash && foundryup)" | tee -a "$SUMMARY"
fi

# ---------------------------------------------------------------- static analysis / symbolic execution
if command -v slither >/dev/null; then step "slither" slither_run.log bash security/run_slither.sh
else echo "==> Slither skipped (pip install slither-analyzer==0.10.0 solc-select)" | tee -a "$SUMMARY"; fi
if command -v docker >/dev/null || command -v myth >/dev/null; then step "mythril" mythril_run.log bash security/run_mythril.sh
else echo "==> Mythril skipped (install Docker or mythril)" | tee -a "$SUMMARY"; fi

# ---------------------------------------------------------------- integrity of the log set
( cd logs && files=$(ls | grep -v "^SHA256SUMS.txt$") && (shasum -a 256 $files 2>/dev/null || sha256sum $files) > SHA256SUMS.txt )
echo; echo "Summary:"; cat "$SUMMARY"
