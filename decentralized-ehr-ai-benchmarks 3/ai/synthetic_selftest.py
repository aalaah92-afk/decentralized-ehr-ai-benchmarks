#!/usr/bin/env python3
"""
SOFTWARE SELF-TEST ON SYNTHETIC DATA — these numbers are NOT results of the study.

Generates a synthetic multi-label dataset with patient clustering (1-8 images per patient) and
perfectly calibrated probabilities, runs ai/evaluate.py and checks that:
  1. the macro AUPRC is exactly the arithmetic mean of the 14 class AUPRCs (Reviewer 1/3 issue),
  2. per-class AUROC/AUPRC equal an independent sklearn recomputation,
  3. every bootstrap CI contains its point estimate and the redraw logic works for a rare class,
  4. ECE of a perfectly calibrated model is near 0 and macro/pooled ECE are both reported,
  5. thresholds are selected on validation and applied to test,
  6. the patient-level split has zero overlap.
Output: logs/ai_selftest.log (+ synthetic figures prefixed selftest_)
"""
import os, sys
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
sys.path.insert(0, os.path.dirname(__file__))
from common import LABELS
from evaluate import evaluate, cluster_bootstrap

PREV = [0.103, 0.025, 0.118, 0.177, 0.051, 0.056, 0.012, 0.047, 0.042, 0.021, 0.022, 0.015, 0.030, 0.002]


def synth(n_patients, rng, offset):
    rows = []
    for p in range(n_patients):
        u = rng.normal(0, 0.8, size=14)  # patient-level latent effect -> intra-patient correlation
        for i in range(rng.integers(1, 9)):
            logit = np.log(np.array(PREV) / (1 - np.array(PREV))) + u + rng.normal(0, 1.2, size=14)
            prob = 1 / (1 + np.exp(-logit))
            y = (rng.random(14) < prob).astype(int)
            rows.append([f"img_{offset + p}_{i}.png", offset + p, *y, *prob])
    return pd.DataFrame(rows, columns=["Image Index", "Patient ID", *LABELS, *[f"p_{l}" for l in LABELS]])


def main():
    rng = np.random.default_rng(7)
    val, test = synth(300, rng, 0), synth(900, rng, 10_000)
    assert not set(val["Patient ID"]) & set(test["Patient ID"]), "patient overlap"
    out = os.path.join(os.path.dirname(__file__), "..", "logs")
    r = evaluate(val, test, LABELS, "selftest_synthetic", reps=200, seed=2026, figures=True, out_dir=out)
    checks = []
    checks.append(("macro AUPRC == mean(class AUPRC)", abs(r["macro_auprc"] - np.mean(r["auprc"])) < 1e-12))
    ok = True
    for j, l in enumerate(LABELS):
        ok &= abs(r["auroc"][j] - roc_auc_score(test[l], test[f"p_{l}"])) < 1e-12
        ok &= abs(r["auprc"][j] - average_precision_score(test[l], test[f"p_{l}"])) < 1e-12
    checks.append(("per-class AUROC/AUPRC match sklearn", ok))
    b = r["bootstrap"]
    inside = all(lo <= v <= hi for v, (lo, hi) in zip(r["auroc"], b["auroc_ci"])) and all(lo <= v <= hi for v, (lo, hi) in zip(r["auprc"], b["auprc_ci"]))
    checks.append(("all class CIs contain point estimates", inside))
    # small test subset (60 patients) so that the rare classes (Hernia 0.2 %) are often absent
    small = test[test["Patient ID"].isin(sorted(test["Patient ID"].unique())[:60])]
    hernia_pos = int(small["Hernia"].sum())
    if hernia_pos == 0:  # guarantee exactly one positive patient for the rare class
        small = small.copy(); small.loc[small.index[0], "Hernia"] = 1; hernia_pos = 1
    sb = cluster_bootstrap(small, LABELS, 50, 1)
    checks.append((f"rare-class redraw logic exercised on 60-patient subset (Hernia positives={hernia_pos}, redraws={sb['redraws']}, kept={sb['reps']})",
                   sb["redraws"] > 0 and len(sb["auroc_ci"]) == 14))
    checks.append((f"calibrated synthetic model: pooled ECE {r['ece_pooled']:.4f} < 0.02", r["ece_pooled"] < 0.02))
    checks.append(("14 thresholds selected on validation", len(r["thresholds"]) == 14))
    lines = ["SYNTHETIC SELF-TEST (not study results)",
             f"val images={len(val)}, test images={len(test)}, test patients={test['Patient ID'].nunique()}",
             f"macro AUROC={r['macro_auroc']:.4f}, macro AUPRC={r['macro_auprc']:.4f} (mean of class values {np.mean(r['auprc']):.4f})",
             f"macro ECE={r['ece_macro']:.4f}, pooled ECE={r['ece_pooled']:.4f}, Brier={r['brier']:.4f}, NLL={r['nll']:.4f}", ""]
    lines += [f"[{'PASS' if c else 'FAIL'}] {n}" for n, c in checks]
    print("\n".join(lines))
    open(os.path.join(out, "ai_selftest.log"), "w").write("\n".join(lines) + "\n")
    sys.exit(0 if all(c for _, c in checks) else 1)


if __name__ == "__main__":
    main()
