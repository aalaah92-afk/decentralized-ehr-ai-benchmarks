---
title: "Replacement text for the revised manuscript"
subtitle: "Design-vs-implementation fixes and AI-section consistency (MDPI Computers revision)"
---

**How to use this document.** Each item gives the location, what is wrong, and ready-to-paste text. Values in **[square brackets]** must be copied from the named log file after the code has run. They are left blank on purpose: they cannot be known before the code runs.

# Part A. Components that were described but not implemented

## A1. Section 3.5 — Key-loss recovery (now implemented and tested)

**Issue.** The section described a (3,5) Shamir scheme with "valid cryptographic proofs", an "escrow smart contract enclave" and on-chain auditing of recovery requests, but no code existed. A smart contract cannot hold a secret share: its storage is public.

**Replace the whole paragraph of Section 3.5 with:**

> To prevent permanent loss of access after private-key loss, the framework includes a (k, n) = (3, 5) threshold key-escrow module based on Shamir's Secret Sharing over GF(2^8). The patient's 32-byte secp256k1 private key K_master is shared byte-wise using independent random polynomials of degree k − 1 = 2, evaluated at x = 1, …, 5. One share is issued to each of five guardians: the primary healthcare provider, an accredited identity authority, a designated family delegate, an institutional escrow service, and an offline backup vault. At split time, a commitment c_i = SHA-256("EHR-SSS" ‖ i ‖ s_i) of every share is recorded, so a guardian cannot contribute a modified share without detection. Any three valid shares reconstruct K_master by Lagrange interpolation at x = 0. The recovered key is accepted only if its public key maps to the patient's registered Ethereum address. The implementation (lib/shamir.js) reconstructed the key for all C(5,3) = 10 guardian triples. It rejected a modified share through its commitment, and it restored access to a record key that had previously been ECIES-wrapped for the patient. A chi-square test over 65,536 independent splits found no dependence between any two shares and the secret (all χ² statistics below the critical value of 330.5, df = 255, α = 0.001; logs/offchain_tests.log). Guardian identity verification, on-chain logging of recovery requests, and patient notification are deployment controls that were not implemented in the prototype.

**Section 5.5 (Key Recovery Security Boundaries), last sentence — replace with:**

> To counter collusion risks, a deployment should add multi-factor identity verification of guardians, auditable logging of every reconstruction request, and automated patient notification; these controls were not implemented in the present prototype.

**Limitation 6 — replace with:**

> 6- Key-Loss and Key-Recovery Risks: Key recovery is implemented as an off-chain (3,5) threshold module. Guardian onboarding, guardian identity verification and auditable logging of recovery requests were not implemented, and a coalition of three guardians could reconstruct the patient key.

## A2. Section 5.3 — Metadata side-channel countermeasures

**Issue.** The text said the protocol "implements" stealth addresses (BIP-32 / ERC-5564), ERC-4337 relayers and Merkle batching, and the response letter promised a linkability simulation. None of this existed.

**Replace the numbered list in Section 5.3 with:**

> 1. Stealth recipient addresses (implemented). Following the ERC-5564 secp256k1 scheme, each clinician publishes a stealth meta-address (P_spend, P_view). For every access grant, the patient derives a fresh one-time recipient address P_stealth = P_spend + keccak256(r·P_view)·G from an ephemeral key r. The patient calls grantAccess() for that address and wraps the record key for P_stealth, publishing R = r·G and a one-byte view tag. Only the clinician's viewing key can recognise the grant, and only the spending key can derive the one-time private key that signs and unwraps. Because permissions are keyed by address, no contract change is required (lib/stealth.js; logs/offchain_tests.log).
> 2. Relayed submission (implemented) and account abstraction (design). AI commitments are authorised by the clinician's EIP-712 signature rather than by msg.sender. Any relayer can therefore submit appendDiagnosticAI() and pay the gas, so one-time clinician addresses never need funding transactions that would link them. Full ERC-4337 infrastructure (bundlers, paymasters) is compatible with this design but was not implemented.
> 3. Batch aggregation (design only). Aggregating state updates into periodic Merkle-root commitments would flatten temporal access patterns; it was not implemented or evaluated.

**Add after the list:**

> We simulated recipient linkability for 20 clinicians, 200 patients and 5,000 access grants over 30 days, with clinician popularity following a Zipf distribution (s = 1.1) (simulations/linkability.py, seed 2026). With static clinician addresses, an observer who clusters grants by recipient address links 100% of same-clinician grant pairs (precision 1.000, recall 1.000), and each grant's recipient is uniquely identified. With stealth addresses, address clustering links no pairs: the anonymity set of each grant is all 20 clinicians, and the observer's residual uncertainty equals the prior entropy of 3.498 bits. Adding a timing heuristic that links grants issued by the same patient within 24 h recovered only 0.05% of same-clinician pairs (recall 0.0005, precision 0.141) (logs/linkability.md). The simulation does not cover patient-address linkability (patients keep one address per record namespace) or network-level correlation.

**STRIDE list, "Information Disclosure"** — replace "zero-knowledge commitment hashes" with "salted hash commitments". Make the same change in Section 5.4 ("zero-knowledge commitment hashes" → "salted SHA-256 commitments").

## A3. Section 4.2 — IPFS availability (now simulated; the claimed numbers were not attainable)

**Issue.** The text reports a "20-node testbed" with k = 3 cluster pinning giving "100% retrieval at a 40% node failure rate". Under independent failures, the probability that all three replicas are offline at f = 0.4 is 0.4³ = 6.4%. Availability is therefore at most 93.6%, not 100%.

**Replace the IPFS availability paragraph and its three bullets with:**

> To quantify availability under node churn, we simulated a 20-node IPFS network (Monte-Carlo, 100,000 trials per configuration, seed 2026; simulations/ipfs_availability.py). We used three failure models: independent node failures, a fixed fraction of offline nodes, and correlated failures across four failure domains of five nodes each. A record bundle is retrievable if at least one node holding it is online. Without pinning (origin node only), availability equals the origin's uptime: it fell from 89.9% to 50.0% as the independent failure rate increased from 10% to 50%. IPFS Cluster pinning with replication factor k = 3 kept 93.6% availability at a 40% failure rate (closed form 1 − 0.4³ = 93.6%). The same configuration reached 95.1% when exactly 8 of the 20 nodes were offline and 92.9% under correlated failures. Rack-aware placement (one replica per failure domain) raised the correlated-failure value to 95.4%, and k = 5 raised it to 97.9% (Figure X, logs/ipfs_availability.md). Monte-Carlo estimates agreed with closed-form values to within 0.4 percentage points. Third-party pinning services were not tested; their availability is bounded by the provider's service-level agreement.

Insert `logs/ipfs_availability.png` as the new figure. In the response to Reviewer 2 (comment 1), replace the three bullets with the same numbers and delete "maintains 99.98%" and "100% success across 100 retrieval trials".

## A4. Sections 3.8 and 4.4 — Usability study

**Issue.** The manuscript reports a React/Ethers.js/MetaMask client, N = 8 participants, task times and SUS = 86.5, but no client code or study data exist. A study with human participants also needs an ethics approval or exemption statement (MDPI Institutional Review Board Statement and Informed Consent Statement).

**If the study was actually conducted:** keep Section 4.4, add the anonymised task-time/SUS data and the client source to the repository, and add the ethics statements.

**If it was not conducted (recommended wording):** delete the last paragraph of Section 3.8 and replace Section 4.4 with:

> **4.4. Interaction Complexity of Consent Management.** In the prototype, all protocol operations are executed by scripted clients (repository scripts/ and test/). Granting access to a clinician is a single patient-signed transaction that also delivers the recipient's wrapped key (grantAccess). Revocation is a single transaction (revokeAccess). Retrieval requires one read of the record pointer and wrapped key, followed by local verification and decryption, with no transaction. A graphical client and a formal usability evaluation with patients and clinicians (task completion time, error rate, System Usability Scale) are left to future work.

Keep Limitation 10 as it is. In the response to Reviewer 2 (comment 5), state that the usability evaluation is identified as future work and that the interaction steps are now quantified in Section 4.4.

## A5. Section 4.3 — CheXpert out-of-distribution evaluation

**Issue.** The CheXpert AUROC values (macro 0.784, etc.) have no code or logs behind them.

**If you ran the evaluation:** re-run it with `ai/chexpert_eval.py` and copy the numbers from `logs/ai_eval_chexpert.md` into the text.

**If not, replace the CheXpert paragraph with:**

> External validation on a second dataset was not performed in this study. A script for zero-shot evaluation on CheXpert is provided in the repository (ai/chexpert_eval.py). It evaluates frontal images on the seven pathologies shared with ChestX-ray14, excludes uncertain labels, and reuses the NIH-validation operating thresholds.

Then restore Limitation 1 as written, delete Limitation 4, and in the response to Reviewer 2 (comment 4) state that cross-dataset validation remains future work and the evaluation script is released.

# Part B. Inconsistencies in the AI section

## B1. Epoch 23 vs. epoch 28

Section 3.7 says early stopping "terminated training at epoch 23". The same section, Table 8 and the code-availability statement use the checkpoint "at epoch 28". A checkpoint cannot come from an epoch after training stopped. With patience 7, training stops 7 epochs after the best epoch, so if the best checkpoint is epoch 28, training ended at epoch 35. Check your training log. **Replace the last sentence of the regularisation paragraph in Section 3.7 with:**

> Early stopping (patience of 7 epochs on validation loss) ended training at epoch **[stop_epoch]**. The checkpoint with the lowest validation loss, from epoch **[best_epoch]**, was used for all reported evaluations and for system integration (SHA-256 **[checkpoint_sha256]**, registered on-chain as modelVersionHash).

Source: `logs/train_summary.json` written by `ai/train.py`. If your original log shows best = 28, then stop_epoch = 35. Also fix Section 3.6 (±7°) vs. Section 3.7 (±10°) rotation: use one value.

## B2. ECE 0.018 vs. 0.008 (and a third value in Table 8)

There are three different ECE statements: 0.018 ± 0.003 (Section 4.3), 0.008 (Section 5.3), and a Table 8 macro row of 3.2%. The fourteen per-class values printed in Table 8 average 3.0%. Two ECE definitions give different numbers for the same predictions: the mean of the per-class ECEs (macro) and the ECE over all image-label pairs pooled. In the synthetic self-test, the same model gave macro 0.0083 and pooled 0.0023. **Report both, clearly defined. Replace the calibration paragraph of Section 4.3 with:**

> Probability calibration was evaluated on the held-out test set (N = 11,212 images) with 10 equal-width bins. The macro-averaged Expected Calibration Error (mean of the 14 per-class ECEs) was **[ece_macro]**, and the ECE computed over all image-label pairs pooled was **[ece_pooled]**. The Brier score was **[brier]** and the negative log-likelihood **[nll]** (Figure 6).

Source: `logs/ai_eval_nih.md` (section "Calibration"). **In Section 5.3,** delete the sentences "achieving an Expected Calibration Error (ECE) of 0.008" and "a predicted diagnostic likelihood of 80% corresponds directly to an 80% empirical risk". The second claim overstates what calibration on a retrospective dataset with noisy labels shows (Reviewer 3, comment 8). Replace them with:

> Calibration on the retrospective test set (Section 4.3) indicates how closely predicted probabilities match observed label frequencies in this cohort; it does not establish calibrated clinical risk in other populations.

**Figure references:** the reliability diagram is Figure 6. Change "Supplementary Figure S2" (Section 4.3) and "As illustrated in Figure 5" (Section 5.3) to Figure 6, and "Precision-Recall dynamics in Figure 6" (Section 5.3) to Figure 5.

## B3. Test set N = 11,212 vs. 25,596

The patient-level test split (Section 3.6, Table 8) contains 3,081 patients and 11,212 images. 25,596 is the size of the official NIH test list, which is a different, non-patient-level partition. **In the calibration paragraph, replace N = 25,596 with N = 11,212** (already done in the B2 text above). Also verify the split counts: a patient-level split rarely gives exactly the same image count (11,212) for validation and test. Run `ai/split_patients.py` and copy the integer counts from `logs/split_summary.md` into Section 3.6.

## B4. AUPRC values in the text vs. Table 8

The values quoted in the text do not match Table 8:

| Location | Text says | Table 8 says |
|---|---|---|
| §4.3, 1st paragraph | Emphysema AUROC 0.881 | 0.895 |
| §4.3, after Table 8 | Pneumonia AUPRC 0.142 | 0.462 |
| §4.3, after Table 8 | Fibrosis AUPRC 0.215 | 0.264 |
| §4.3, after Table 8 | Effusion AUPRC 0.582 | 0.441 |
| §5.2 | Cardiomegaly AUPRC 0.512 | 0.395 |
| §5.2 | Pneumonia AUPRC 0.142 | 0.462 |

Table 8 is also internally inconsistent:

- The 14 AUROC values average 0.825, but the macro row says 0.821.
- The prevalences average 5.2%, but the macro row says 4.0%.
- The per-class ECEs average 3.0%, but the macro row says 3.2%.
- The macro AUPRC interval in the table (0.360–0.408) differs from the text (0.342–0.388).
- For the same pathology, the threshold, sensitivity and specificity in Table 8 differ from Table 9 (e.g., Cardiomegaly 0.38 / 83.5% / 82.1% vs. 0.28 / 84.2% / 83.5%).

Editing the text to match Table 8 would not fix this, because the table itself does not come from one computation. Reviewers 1 and 3 already caught one such error. **Regenerate Tables 8 and 9 and Figures 4–6 in one run of `ai/evaluate.py` on your saved validation and test predictions.** Replace the tables with `logs/ai_eval_nih.md`, the figures with `logs/fig_roc_nih.png`, `logs/fig_pr_nih.png` and `logs/fig_reliability_nih.png`, and remove the threshold/sensitivity/specificity columns from Table 8 (they belong in Table 9). Then use this text:

**§4.3, first paragraph (last three sentences):**

> The model achieved a macro-average AUROC of **[macro_auroc]** (95% CI **[lo–hi]**, patient-cluster bootstrap, 1,000 resamples). The highest discrimination was observed for **[top three classes with AUROC from Table 8]**. Table 8 reports class-wise AUROC and AUPRC with 95% confidence intervals and prevalence.

**§4.3, paragraph after Table 8:**

> The unweighted macro-average AUPRC across the 14 findings was **[macro_auprc]** (95% CI **[lo–hi]**), computed as the arithmetic mean of the class-wise values within each bootstrap replicate. AUPRC was lowest for **[two lowest classes, with prevalence and AUPRC from Table 8]** and highest for **[two highest classes]**, reflecting the dependence of precision on prevalence. The intervals quantify test-sample uncertainty conditional on the trained checkpoint, not variability across training runs.

**§5.2 — replace the AUPRC sentences with values copied from the regenerated Table 8, e.g.:**

> Class-wise performance varied with prevalence and radiological salience: Cardiomegaly (AUROC **[ ]**, AUPRC **[ ]**) … whereas rare findings such as Pneumonia (prevalence **[ ]**%, AUPRC **[ ]**) showed the lowest precision-recall performance.

If the saved predictions or the epoch-28 checkpoint are no longer available, these numbers cannot be reproduced. In that case the model must be retrained with `ai/train.py` before the AI results are reported.

# Part C. Section 3.7, last paragraph, and Code Availability

**Section 3.7, last paragraph — replace with:**

> For each image the model produces a 14-dimensional probability vector. The vector and a random 32-byte salt are encrypted off-chain (AES-256-GCM) and stored on IPFS. Only the salted SHA-256 commitment, the IPFS CID of the encrypted object, the model checkpoint hash, the record version and the reviewing clinician's address are recorded on-chain, through an EIP-712-signed appendDiagnosticAI() call.

**Code and Artifact Availability — replace with:**

> The smart contract, off-chain cryptographic client, key-recovery and stealth-address modules, simulations, AI training/evaluation scripts, patient-level split manifests and all execution logs are available at https://github.com/**[your-account]**/decentralized-ehr-ai-benchmarks. Contract, security-analysis and benchmark logs are generated by the repository's GitHub Actions workflow; the run that produced the reported values is linked in logs/ci/PROVENANCE.md.

# Part D. Values still to be copied from the automatic logs

| Manuscript location | Log file |
|---|---|
| Table 4 and all gas / USD figures in Section 4.1 | `logs/ci/hardhat/gas_benchmark.md` |
| Table 5 (adversarial matrix) | `logs/ci/hardhat/security_test_matrix.md` |
| Throughput, failure rate (Section 4.1) | `logs/ci/hardhat/throughput_benchmark.md` |
| Ledger growth per record | "State growth" column of `gas_benchmark.md` |
| Slither / Mythril / Foundry statements (Section 4.1.1) | `logs/ci/slither/`, `logs/ci/mythril/`, `logs/ci/foundry/foundry_test.log` |
| Table 6 crypto and IPFS timings, hardware description (Section 3.8) | `logs/ci/offchain/crypto_benchmark.md`, `ipfs_benchmark.md`, `environment_*.txt` |
| Table 7 end-to-end latency | `logs/ci/hardhat/e2e_latency_hardhat.md` (Sepolia: `logs/ci/sepolia/`) |
| Section 4.1.2 L2 / consortium TPS and costs (1,850 TPS, 142 TPS, < $0.005) | not measured: delete or label as literature-based extrapolation |
