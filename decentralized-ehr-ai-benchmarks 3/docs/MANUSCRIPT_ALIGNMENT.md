# Manuscript ↔ code alignment checklist

Keep this file out of the public repository if you prefer; it lists the edits needed so that the
revised manuscript, the response letter and `EHRRegistry.sol` describe the same system.

## 1. Function names and signatures (use these everywhere)

| Manuscript currently says | Code (final) | Where to edit |
|---|---|---|
| `addRecord()` | `registerRecord(RecordInput, signature)` | Table 4, Table 7 (Stage 3), §4.1 text, response R2-c3 |
| `logIntegrityViolation(recordID, violationType)` and `reportIntegrityViolation(recordID, targetCID, hashExpected, hashObserved)` | `reportIntegrityViolation(patient, recordId, violationType, expectedDigest, observedDigest)` | §3.3, response R3-c4 |
| `revokeAccess(clinicianAddress, recordID)` (§5.4.1) | `revokeAccess(recordId, clinician)` | §5.4.1 |
| `getRecordKey()` | `getRecordKey(patient, recordId)` → returns the caller's 93-byte wrapped key for the current version | Table 5, response R3-c2 |
| `grantAccess()` "grants view or edit access" | `grantAccess(recordId, clinician, canEdit, wrappedKey)` — grant and key delivery are one transaction | Table 4, §3.3 |
| — | `updateRecord(RecordInput, signature, recipients[], wrappedKeys[])` — new version, fresh key, wraps only for current CanView holders | §3.3 (fresh-version workflow) |
| — | `appendDiagnosticAI(DiagnosticAuthorization, signature)` — clinician-signed, relayable | Table 4, §3.7 |
| — | `approveModel(modelHash)` / `revokeModel` — governance (owner) only; has no power over patient permissions | §3.7, §5.5 |
| `AIInferenceRecord { … uint256 timestamp; }` (response R3-c1) | `{ bytes32 aiPayloadHash; string encryptedAiCID; bytes32 modelVersionHash; address reviewingClinician; uint64 timestamp; uint64 recordVersion; }` | response R3-c1 |
| Figure 2: separate "Rvoked" flag | No separate flag: revoked = `CanView = CanEdit = false`, `epoch += 1`, current-version wrapped key deleted. CanEdit implies CanView; they coexist when `canEdit = true`. Re-grant = `grantAccess` again (new epoch, new wrapped key). | Figure 2 + caption, §3.3 (also fix typo "Rvoked") |
| Error `UnauthorizedAccess` (Table 5) | `Unauthorized` | Table 5 |
| Eq. (2) revoke requires M(p,r,c)=1 | implemented (`AccessNotGranted`) | – |
| Key-Access Monotonicity uses `IsActive(r)` | no such state; use `exists(r)` | §3.3.1 |

## 2. Cryptographic description (§3.4, Table 3, Figure 3)

- **Signature scope.** Replace "ECDSA signature covers H_P‖H_C‖RecordID‖Timestamp" with: *the patient signs an EIP-712 typed-data structure RecordAttestation(patient, recordId, version, CID, H_P, H_C, timestamp) under the domain (name "EHRRegistry", version "1", chainId, contract address); the contract verifies the signature and rejects replays across records, versions, chains and deployments.*
- **ECIES step 4.** The code derives a single 128-bit wrapping key (HKDF-SHA256, salt = R, info = "EHR-Key-Wrap") and uses AES-128-GCM with AAD = recordId‖version‖clinicianAddress. There is no separate K_mac (GCM already authenticates). WK = R(33)‖IV_wrap(12)‖C_key(32)‖T_key(16) = 93 bytes.
- **Where wrapped keys live.** On-chain, in `wrappedKeys[patient][recordId][version][clinician]` (ciphertext only). Replace "stored on IPFS/smart contract".
- **Key binding.** Clinician encryption key = the clinician's secp256k1 account key; the patient client checks `address == keccak256(PK)[12:]` before wrapping.
- **Bundle order.** "The IV is prepended" → "C, IV and T are concatenated as C‖IV‖T".
- **CSPRNG.** Code uses Node.js `crypto.randomBytes()` (OpenSSL). Remove `crypto.getRandomValues()`.
- **Inference commitment.** Hash_infer = SHA-256(Vector_AI‖Salt), Vector_AI = 14 float32 big-endian, Salt = 32 random bytes.
- **"Zero-knowledge commitment hashes"** (§5.4 and STRIDE list) → "salted hash commitments". They are not zero-knowledge proofs.
- **Table 3, Integrity row.** Say "H_C = SHA-256(C‖IV‖T‖CID) and H_P = SHA-256(P) recorded on-chain".

## 3. Table 5 (adversarial matrix)

Replace the table with `logs/security_test_matrix.md`, which the tests generate automatically. Differences from the current draft:

- ST-02: detection is client-side; "key request blocked" means the *client* stops before calling `getRecordKey`. The alert comes from a separate successful `reportIntegrityViolation` transaction.
- ST-03: the contract makes no external calls in access-control functions (checked by opcode trace), and `nonReentrant` (OpenZeppelin ReentrancyGuard) guards all state-changing record functions. Describe it as "no re-entrancy surface, verified by trace", not as "recursive call reverted".
- ST-04: replay protection = per-clinician nonce + deadline + permission epoch + record version + EIP-712 domain. There is no "timestamp epoch".
- ST-05: `registerRecord` is intentionally open (any patient registers records in their own namespace). Unauthorized key insertion means a non-owner calling `grantAccess`/`updateRecord`.

## 4. Numbers that must come from the logs

These values in the current draft conflict with each other or were not produced by this code. Replace each one with the logged value, or remove it:

| Manuscript value | Replace with |
|---|---|
| Table 4 and §4.1: three different gas sets (deploy 1,842,510 vs 1,420,518; register 142,380 / 84,210 / 68,412; grant 44,721 / 45,320; revoke 29,150 / 29,104; append 168,010) | `logs/gas_benchmark.md` (one set) |
| USD costs ($1.70, $2.57, $1.68, $1.09, $53.27) | recompute from the logged gas; label them as projections at the stated gwei/ETH price |
| L2: 96.8 % reduction, < $0.05, < $0.005, 1,850 TPS; consortium 142 TPS / 48 TPS (§4.1.2) | not measured by any script → remove, or label clearly as literature-based extrapolation |
| 42 TPS, failure 0.1 % / 1.2 % | `logs/throughput_benchmark.md` (state the boundary: single-process Hardhat) |
| Sepolia "finality 12.1 s (1 block)" | `logs/e2e_latency_sepolia.md`; 1 confirmation = *inclusion*. Finality (`finalized` tag) is ~2 epochs and should be reported separately |
| Ledger growth 216 bytes/record | "State growth" column of `logs/gas_benchmark.md` |
| Slither "2 Low (unlocked pragma ^0.8.20)" | `logs/slither_report.md`. The pragma is locked at `0.8.20`, so this finding cannot appear |
| Mythril "depth 12", function list incl. `addRecord` | `logs/mythril_params.txt` and `logs/mythril_report.md` |
| Foundry "10⁵ fuzz runs" | `foundry.toml` + `logs/foundry_test.log` (fuzz 100,000 runs per property; invariants 1,000 × 100 calls) |
| Tables 6 and 7 (i7-12700K) | `logs/crypto_benchmark.md`, `logs/ipfs_benchmark.md`, `logs/e2e_latency_*.md`. If you run on a different machine, change the hardware description in §3.8 |
| §4.2 "total < 1.5 s for 10–30 MB" vs Table 7 total 38.4 s; 100 MB encryption 0.957 s vs 0.88 s | one consistent set from the logs |

## 5-6. Design-vs-implementation items and AI-section inconsistencies

Resolved in `docs/MANUSCRIPT_REVISION_TEXT.md` (also provided as a Word file): Shamir key recovery and
stealth addresses are now implemented and tested; relayed submission is implemented; ERC-4337
infrastructure and Merkle batching are reworded as design; the IPFS availability claims are replaced by a
reproducible Monte-Carlo simulation; usability and CheXpert text is given in two versions (with data /
as future work); epoch, ECE, test-set size and AUPRC inconsistencies are listed with replacement text.
