#!/usr/bin/env python3
"""
Write per-image probabilities for a manifest (validation, test, or CheXpert).

  python ai/predict.py --images /path/to/images --manifest ai/manifests/test.csv \
      --checkpoint ai/checkpoints/densenet121_best.pth --out ai/predictions/test_predictions.csv

Output columns: Image Index, Patient ID, <14 labels>, p_<label> for each of the 14 labels.
Also measures per-image GPU inference latency (T_AI in manuscript Eq. 3) -> logs/inference_latency.json.
"""
import argparse, json, os, time
import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader
from common import LABELS
from train import CXR, build_model, transforms_for, sha256_file

LOGS = os.path.join(os.path.dirname(__file__), "..", "logs")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--images", required=True); ap.add_argument("--manifest", required=True)
    ap.add_argument("--checkpoint", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--batch", type=int, default=64); ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = build_model().to(dev); model.load_state_dict(torch.load(a.checkpoint, map_location=dev)); model.eval()
    ds = CXR(a.manifest, a.images, transforms_for(False))
    dl = DataLoader(ds, batch_size=a.batch, shuffle=False, num_workers=a.workers)
    probs, names = [], []
    with torch.no_grad():
        for x, _, n in dl:
            probs.append(torch.sigmoid(model(x.to(dev))).cpu().numpy()); names += list(n)
    P = np.concatenate(probs)
    out = ds.df.copy()
    for j, l in enumerate(LABELS): out[f"p_{l}"] = P[:, j]
    os.makedirs(os.path.dirname(a.out), exist_ok=True); out.to_csv(a.out, index=False)

    # single-image latency (batch 1, 200 timed runs after 20 warm-up)
    x = ds[0][0].unsqueeze(0).to(dev); ts = []
    with torch.no_grad():
        for i in range(220):
            if dev.type == "cuda": torch.cuda.synchronize()
            t = time.perf_counter(); model(x)
            if dev.type == "cuda": torch.cuda.synchronize()
            if i >= 20: ts.append(time.perf_counter() - t)
    ts = np.array(ts)
    os.makedirs(LOGS, exist_ok=True)
    json.dump(dict(device=str(dev), gpu=torch.cuda.get_device_name(0) if dev.type == "cuda" else None,
                   mean_s=float(ts.mean()), ci95_s=float(1.96 * ts.std(ddof=1) / np.sqrt(len(ts))), runs=len(ts),
                   checkpoint_sha256=sha256_file(a.checkpoint)),
              open(os.path.join(LOGS, "inference_latency.json"), "w"), indent=2)
    print(f"wrote {a.out} ({len(out)} rows)")


if __name__ == "__main__":
    main()
