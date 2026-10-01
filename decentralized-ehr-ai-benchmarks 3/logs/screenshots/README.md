# Screenshots of executed runs

Each PNG is a rendering of the exact stdout/stderr captured from the command shown on its first line,
executed in the Claude cloud sandbox (host, date and exit code in the footer). They correspond to the
text logs in `logs/`. Screenshots of the smart-contract test, gas, Slither, Mythril and Foundry runs are
produced from the GitHub Actions run (see `logs/ci/PROVENANCE.md` after the first push).

| File | Content |
|---|---|
| 01_offchain_crypto_protocol.png | AES-256-GCM, ECIES, digests, CID, keccak/secp256k1 known-answer tests |
| 02_shamir_key_recovery.png | (3,5) Shamir key recovery tests (Section 3.5) |
| 03_stealth_addresses.png | ERC-5564 stealth-address tests (Section 5.3) |
| 04_ipfs_availability_simulation.png | 20-node IPFS availability Monte-Carlo (Section 4.2) |
| 05_linkability_simulation.png | Recipient linkability simulation (Section 5.3) |
| 06_ai_evaluation_selftest_SYNTHETIC.png | Evaluation-code self-test on synthetic data — not study results |
