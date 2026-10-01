#!/usr/bin/env python3
"""
Evaluation of saved predictions (manuscript Section 4.3, Tables 8-9, Figures 4-6).
Everything reported for the classifier is computed here from ONE pair of prediction files, so the
tables, figures and macro metrics are always consistent with each other.

  python ai/evaluate.py --val ai/predictions/val_predictions.csv \
                        --test ai/predictions/test_predictions.csv --tag nih

Definitions
  AUROC           sklearn roc_auc_score per class; macro = unweighted mean of the class values
  AUPRC           average precision (sklearn average_precision_score, step-wise, no interpolation);
                  macro = unweighted mean of the 14 class values
  95% CI          patient-cluster bootstrap on the TEST set: resample patients with replacement
                  (all their images together), B=1000, seed 2026, percentile interval (2.5, 97.5);
                  macro metrics are computed inside each replicate; a replicate in which any class
                  has no positive or no negative image is discarded and re-drawn (count logged).
                  The CI reflects test-sample uncertainty conditional on the trained checkpoint,
                  not variability across training runs.
  Thresholds      Youden J = sens + spec - 1 maximised on the VALIDATION predictions, then applied
                  unchanged to the test set (sensitivity, specificity, PPV, NPV, F1)
  ECE             10 equal-width bins; per-class ECE; macro ECE = mean of per-class ECEs;
                  pooled ECE = ECE over all (image, label) pairs flattened
  Brier / NLL     mean over all (image, label) pairs
Outputs: logs/ai_eval_<tag>.{md,json}, logs/fig_roc_<tag>.png, logs/fig_pr_<tag>.png,
         logs/fig_reliability_<tag>.png
"""
import argparse, json, os, time
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve, precision_recall_curve
try:
    from common import LABELS, BOOTSTRAP_REPS, BOOTSTRAP_SEED
except ImportError:  # when imported from another directory
    from ai.common import LABELS, BOOTSTRAP_REPS, BOOTSTRAP_SEED

LOGS = os.path.join(os.path.dirname(__file__), "..", "logs")


def ece(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.sum() / len(p) * abs(y[m].mean() - p[m].mean())
    return float(total)


def reliability(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    return [(float(p[idx == b].mean()) if (idx == b).any() else None,
             float(y[idx == b].mean()) if (idx == b).any() else None, int((idx == b).sum())) for b in range(bins)]


def class_arrays(df, labels):
    Y = df[labels].values.astype(float)
    P = df[[f"p_{l}" for l in labels]].values.astype(float)
    return Y, P


def point_metrics(Y, P):
    au, ap = [], []
    for j in range(Y.shape[1]):
        m = ~np.isnan(Y[:, j])
        au.append(roc_auc_score(Y[m, j], P[m, j])); ap.append(average_precision_score(Y[m, j], P[m, j]))
    return np.array(au), np.array(ap)


def cluster_bootstrap(df, labels, reps, seed):
    Y, P = class_arrays(df, labels)
    groups = df.groupby("Patient ID").indices
    pids = np.array(list(groups.keys()))
    rng = np.random.default_rng(seed)
    AU, AP, redraws = [], [], 0
    while len(AU) < reps:
        take = rng.choice(len(pids), size=len(pids), replace=True)
        idx = np.concatenate([groups[pids[t]] for t in take])
        y, p = Y[idx], P[idx]
        ok = True
        for j in range(y.shape[1]):
            yj = y[:, j][~np.isnan(y[:, j])]
            if yj.min() == yj.max():
                ok = False; break
        if not ok:
            redraws += 1; continue
        au, ap = point_metrics(y, p)
        AU.append(au); AP.append(ap)
    AU, AP = np.array(AU), np.array(AP)
    ci = lambda a: (float(np.percentile(a, 2.5)), float(np.percentile(a, 97.5)))
    return dict(
        auroc_ci=[ci(AU[:, j]) for j in range(len(labels))], auprc_ci=[ci(AP[:, j]) for j in range(len(labels))],
        macro_auroc_ci=ci(AU.mean(1)), macro_auprc_ci=ci(AP.mean(1)), redraws=redraws, reps=reps,
    )


def youden_thresholds(val, labels):
    Y, P = class_arrays(val, labels); th = []
    for j in range(len(labels)):
        m = ~np.isnan(Y[:, j]); fpr, tpr, t = roc_curve(Y[m, j], P[m, j])
        k = int(np.argmax(tpr - fpr)); th.append(float(min(t[k], 1.0)))
    return th


def threshold_metrics(Y, P, th):
    rows = []
    for j, t in enumerate(th):
        m = ~np.isnan(Y[:, j]); y = Y[m, j].astype(int); pred = (P[m, j] >= t).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
        fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
        sens = tp / (tp + fn) if tp + fn else float("nan"); spec = tn / (tn + fp) if tn + fp else float("nan")
        ppv = tp / (tp + fp) if tp + fp else float("nan"); npv = tn / (tn + fn) if tn + fn else float("nan")
        f1 = 2 * ppv * sens / (ppv + sens) if (ppv + sens) else float("nan")
        rows.append(dict(threshold=t, sensitivity=sens, specificity=spec, ppv=ppv, npv=npv, f1=f1, tp=tp, fp=fp, tn=tn, fn=fn))
    return rows


def evaluate(val, test, labels, tag, reps=BOOTSTRAP_REPS, seed=BOOTSTRAP_SEED, figures=True, out_dir=LOGS):
    t0 = time.time()
    Y, P = class_arrays(test, labels)
    au, ap = point_metrics(Y, P)
    boot = cluster_bootstrap(test, labels, reps, seed)
    th = youden_thresholds(val, labels)
    thr = threshold_metrics(Y, P, th)
    mask = ~np.isnan(Y)
    per_ece = [ece(Y[mask[:, j], j], P[mask[:, j], j]) for j in range(len(labels))]
    yf, pf = Y[mask], np.clip(P[mask], 1e-7, 1 - 1e-7)
    res = dict(
        tag=tag, n_test_images=int(len(test)), n_test_patients=int(test["Patient ID"].nunique()),
        n_val_images=int(len(val)), labels=labels,
        prevalence=[float(np.nanmean(Y[:, j])) for j in range(len(labels))],
        auroc=au.tolist(), auprc=ap.tolist(), macro_auroc=float(au.mean()), macro_auprc=float(ap.mean()),
        bootstrap=boot, thresholds=thr, ece_per_class=per_ece, ece_macro=float(np.mean(per_ece)),
        ece_pooled=ece(yf, pf), brier=float(np.mean((pf - yf) ** 2)),
        nll=float(-np.mean(yf * np.log(pf) + (1 - yf) * np.log(1 - pf))),
        reliability_pooled=reliability(yf, pf), runtime_s=time.time() - t0,
    )
    os.makedirs(out_dir, exist_ok=True)
    json.dump(res, open(os.path.join(out_dir, f"ai_eval_{tag}.json"), "w"), indent=2)
    write_markdown(res, os.path.join(out_dir, f"ai_eval_{tag}.md"))
    if figures:
        make_figures(test, labels, res, tag, out_dir)
    return res


def write_markdown(r, path):
    L = r["labels"]; b = r["bootstrap"]
    f3 = lambda x: f"{x:.3f}"
    lines = [f"# Classifier evaluation `{r['tag']}` (auto-generated by ai/evaluate.py)", "",
             f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}  ",
             f"Test: {r['n_test_images']} images / {r['n_test_patients']} patients; validation (thresholds): {r['n_val_images']} images  ",
             f"Bootstrap: patient-cluster, B={b['reps']}, percentile 95% CI, discarded+redrawn replicates: {b['redraws']}", "",
             "## Table 8 - discrimination", "",
             "| Pathology | Prevalence (%) | AUROC (95% CI) | AUPRC (95% CI) | ECE (%) |", "|---|---|---|---|---|"]
    for j, l in enumerate(L):
        lines.append(f"| {l.replace('_', ' ')} | {100 * r['prevalence'][j]:.1f} | {f3(r['auroc'][j])} ({f3(b['auroc_ci'][j][0])}-{f3(b['auroc_ci'][j][1])}) | "
                     f"{f3(r['auprc'][j])} ({f3(b['auprc_ci'][j][0])}-{f3(b['auprc_ci'][j][1])}) | {100 * r['ece_per_class'][j]:.1f} |")
    lines.append(f"| **Macro average** | {100 * np.mean(r['prevalence']):.1f} | {f3(r['macro_auroc'])} ({f3(b['macro_auroc_ci'][0])}-{f3(b['macro_auroc_ci'][1])}) | "
                 f"{f3(r['macro_auprc'])} ({f3(b['macro_auprc_ci'][0])}-{f3(b['macro_auprc_ci'][1])}) | {100 * r['ece_macro']:.1f} |")
    lines += ["", "## Table 9 - operating points (Youden threshold chosen on validation, applied to test)", "",
              "| Pathology | Threshold | Sensitivity | Specificity | PPV | NPV | F1 |", "|---|---|---|---|---|---|---|"]
    for l, t in zip(L, r["thresholds"]):
        lines.append(f"| {l.replace('_', ' ')} | {t['threshold']:.3f} | {f3(t['sensitivity'])} | {f3(t['specificity'])} | {f3(t['ppv'])} | {f3(t['npv'])} | {f3(t['f1'])} |")
    lines += ["", "## Calibration", "",
              f"- Macro ECE (mean of per-class, 10 bins): {r['ece_macro']:.4f}",
              f"- Pooled ECE (all image-label pairs, 10 bins): {r['ece_pooled']:.4f}",
              f"- Brier score: {r['brier']:.4f}", f"- NLL: {r['nll']:.4f}", ""]
    open(path, "w").write("\n".join(lines))


def make_figures(test, labels, r, tag, out_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    Y, P = class_arrays(test, labels)
    cmap = plt.get_cmap("tab20")
    for kind in ("roc", "pr"):
        fig, ax = plt.subplots(figsize=(7, 6.5), dpi=150)
        for j, l in enumerate(labels):
            m = ~np.isnan(Y[:, j])
            if kind == "roc":
                x, y, _ = roc_curve(Y[m, j], P[m, j]); lab = f"{l.replace('_', ' ')} ({r['auroc'][j]:.3f})"
            else:
                y, x, _ = precision_recall_curve(Y[m, j], P[m, j]); lab = f"{l.replace('_', ' ')} ({r['auprc'][j]:.3f})"
            ax.plot(x, y, lw=1.1, color=cmap(j), label=lab)
        if kind == "roc":
            ax.plot([0, 1], [0, 1], "k--", lw=0.8)
            ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate")
            ax.set_title(f"ROC, {len(labels)} findings (macro AUROC {r['macro_auroc']:.3f})", fontsize=10)
        else:
            ax.set_xlabel("Recall"); ax.set_ylabel("Precision")
            ax.set_title(f"Precision-recall, {len(labels)} findings (macro AUPRC {r['macro_auprc']:.3f})", fontsize=10)
        ax.legend(fontsize=6.5, frameon=False, loc="lower right" if kind == "roc" else "upper right"); ax.grid(alpha=0.3)
        fig.tight_layout(); fig.savefig(os.path.join(out_dir, f"fig_{kind}_{tag}.png")); plt.close(fig)
    rel = r["reliability_pooled"]
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(5.5, 6.5), dpi=150, gridspec_kw=dict(height_ratios=[3, 1]), sharex=True)
    xs = [c for c, _, n in rel if n]; ys = [o for _, o, n in rel if n]
    a1.plot([0, 1], [0, 1], "k--", lw=0.8); a1.plot(xs, ys, "o-", color="#2e86c1")
    a1.set_ylabel("Observed frequency"); a1.set_title(f"Reliability (pooled, 10 bins), ECE {r['ece_pooled']:.4f}", fontsize=10); a1.grid(alpha=0.3)
    a2.bar([(i + 0.5) / 10 for i in range(10)], [n for _, _, n in rel], width=0.09, color="#9aa0a6"); a2.set_yscale("log")
    a2.set_xlabel("Predicted probability"); a2.set_ylabel("Count")
    fig.tight_layout(); fig.savefig(os.path.join(out_dir, f"fig_reliability_{tag}.png")); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--val", required=True); ap.add_argument("--test", required=True)
    ap.add_argument("--tag", default="nih"); ap.add_argument("--labels", nargs="*", default=LABELS)
    ap.add_argument("--reps", type=int, default=BOOTSTRAP_REPS); ap.add_argument("--seed", type=int, default=BOOTSTRAP_SEED)
    a = ap.parse_args()
    r = evaluate(pd.read_csv(a.val), pd.read_csv(a.test), a.labels, a.tag, a.reps, a.seed)
    print(open(os.path.join(LOGS, f"ai_eval_{a.tag}.md")).read())


if __name__ == "__main__":
    main()
