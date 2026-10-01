# Execution logs — provenance

| Log | Produced by | Where / when |
|---|---|---|
| `offchain_tests.log` | `node --test offchain-tests/*.test.js` (21 tests: AES-256-GCM, ECIES, keccak/secp256k1 vectors, Shamir (3,5), ERC-5564 stealth addresses) | Claude cloud sandbox, see `environment_sandbox.txt` |
| `ipfs_availability.{md,csv,png}`, `ipfs_availability_run.log` | `simulations/ipfs_availability.py` (Monte-Carlo, 100,000 trials per cell, seed 2026) | Claude cloud sandbox |
| `linkability.{md,csv}`, `linkability_run.log` | `simulations/linkability.py` (seed 2026) | Claude cloud sandbox |
| `ai_selftest*.log`, `ai_eval_selftest_synthetic.*`, `fig_*_selftest_synthetic.png` | `ai/synthetic_selftest.py` — **software self-test on synthetic data, not study results** | Claude cloud sandbox |
| `ci/**` | `.github/workflows/reproduce.yml`: Hardhat tests + gas reporter, security matrix, gas/throughput/latency benchmarks, crypto and IPFS (Kubo) benchmarks, Foundry fuzz/invariants, Slither, Mythril, optional Sepolia | GitHub-hosted runners; exact run linked in `ci/PROVENANCE.md` (created automatically after the first push) |

`environment_sandbox.txt` lists the SHA-256 of every source file used for the sandbox logs.
Every log in this folder was produced by executing the code in this repository; none was written by hand.
