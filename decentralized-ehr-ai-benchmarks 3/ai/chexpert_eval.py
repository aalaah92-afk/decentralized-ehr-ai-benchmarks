#!/usr/bin/env python3
"""
Out-of-distribution evaluation on CheXpert without fine-tuning (manuscript Section 4.3).

  python ai/chexpert_eval.py --chexpert-root /path/to/CheXpert-v1.0-small --csv valid.csv \
      --checkpoint ai/checkpoints/densenet121_best.pth [--max-images 5000]

- Frontal views only; the 7 pathologies shared with ChestX-ray14 (common.CHEXPERT_MAP).
- Uncertain labels (-1) are EXCLUDED per class (U-ignore); blank = negative.
- "Patient ID" is parsed from the path (patientXXXXX) so the patient-cluster bootstrap applies.
- Operating thresholds are taken from the NIH validation set (no CheXpert tuning).
Outputs: ai/predictions/chexpert_predictions.csv and logs/ai_eval_chexpert.{md,json} + figures.
"""
import argparse, os
import numpy as np
import pandas as pd
from common import CHEXPERT_MAP, LABELS


def build_manifest(root, csv_name, max_images, seed=42):
    df = pd.read_csv(os.path.join(root, csv_name))
    df = df[df["Frontal/Lateral"] == "Frontal"].copy()
    df["Patient ID"] = df["Path"].str.extract(r"(patient\d+)")[0]
    df["Image Index"] = df["Path"]  # relative to the parent directory of --chexpert-root
    for src, dst in CHEXPERT_MAP.items():
        v = df[src].fillna(0.0)
        df[dst] = v.where(v != -1.0, np.nan)
    for lab in LABELS:
        if lab not in df.columns: df[lab] = np.nan
    if max_images and len(df) > max_images:
        pts = df["Patient ID"].unique(); rng = np.random.default_rng(seed); rng.shuffle(pts)
        keep, n = [], 0
        for p in pts:
            k = (df["Patient ID"] == p).sum()
            if n + k > max_images: break
            keep.append(p); n += k
        df = df[df["Patient ID"].isin(keep)]
    return df[["Image Index", "Patient ID"] + LABELS]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chexpert-root", required=True); ap.add_argument("--csv", default="valid.csv")
    ap.add_argument("--checkpoint", required=True); ap.add_argument("--max-images", type=int, default=0)
    ap.add_argument("--nih-val-predictions", default="ai/predictions/val_predictions.csv")
    a = ap.parse_args()
    man = build_manifest(a.chexpert_root, a.csv, a.max_images)
    os.makedirs("ai/manifests", exist_ok=True); man.to_csv("ai/manifests/chexpert.csv", index=False)
    img_dir = os.path.dirname(os.path.abspath(a.chexpert_root))
    os.system(f"python {os.path.dirname(__file__)}/predict.py --images '{img_dir}' --manifest ai/manifests/chexpert.csv "
              f"--checkpoint '{a.checkpoint}' --out ai/predictions/chexpert_predictions.csv")
    from evaluate import evaluate
    shared = list(CHEXPERT_MAP.values())
    evaluate(pd.read_csv(a.nih_val_predictions), pd.read_csv("ai/predictions/chexpert_predictions.csv"), shared, "chexpert")
    print(open("logs/ai_eval_chexpert.md").read())


if __name__ == "__main__":
    main()
