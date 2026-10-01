#!/usr/bin/env python3
"""
DenseNet121 multi-label training (manuscript Section 3.7).

  python ai/train.py --images /path/to/images --manifests ai/manifests --out ai/checkpoints

Configuration (matches the manuscript):
  ImageNet-pretrained DenseNet121, global average pooling, dropout p=0.20, 14-unit linear head
  (sigmoid applied in the loss / at inference); BCEWithLogitsLoss with pos_weight = N_neg/N_pos per
  class (training split); Adam(beta1=0.9, beta2=0.999, eps=1e-8), lr 1e-4, weight decay 1e-5;
  ReduceLROnPlateau(factor=0.1, patience=2) on validation loss; batch 32; max 50 epochs; early
  stopping patience 7 on validation loss; checkpoint = lowest validation BCE.
  Augmentation: horizontal flip, rotation +/-10 deg, brightness +/-15 %, translation +/-5 %.
  Input 320x320, ImageNet normalisation.
Every epoch is logged to logs/train_log.csv. At the end logs/train_summary.json records
best_epoch (checkpoint) and stop_epoch (= best_epoch + 7 if early stopping fired) and the
SHA-256 of the checkpoint file (this value is modelVersionHash on-chain).
"""
import argparse, hashlib, json, os, random, time
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from PIL import Image
from torch.utils.data import DataLoader, Dataset
from torchvision import models, transforms
from common import IMAGE_SIZE, IMAGENET_MEAN, IMAGENET_STD, LABELS

LOGS = os.path.join(os.path.dirname(__file__), "..", "logs")


class CXR(Dataset):
    def __init__(self, manifest, image_dir, tf):
        self.df = pd.read_csv(manifest); self.dir = image_dir; self.tf = tf
    def __len__(self): return len(self.df)
    def __getitem__(self, i):
        r = self.df.iloc[i]
        img = Image.open(os.path.join(self.dir, r["Image Index"])).convert("RGB")
        return self.tf(img), torch.tensor(r[LABELS].values.astype(np.float32)), r["Image Index"]


def build_model():
    m = models.densenet121(weights=models.DenseNet121_Weights.IMAGENET1K_V1)
    m.classifier = nn.Sequential(nn.Dropout(p=0.20), nn.Linear(m.classifier.in_features, len(LABELS)))
    return m


def transforms_for(train):
    norm = [transforms.ToTensor(), transforms.Normalize(IMAGENET_MEAN, IMAGENET_STD)]
    if not train:
        return transforms.Compose([transforms.Resize((IMAGE_SIZE, IMAGE_SIZE))] + norm)
    return transforms.Compose([
        transforms.Resize((IMAGE_SIZE, IMAGE_SIZE)), transforms.RandomHorizontalFlip(),
        transforms.RandomAffine(degrees=10, translate=(0.05, 0.05)), transforms.ColorJitter(brightness=0.15),
    ] + norm)


def seed_all(s):
    random.seed(s); np.random.seed(s); torch.manual_seed(s); torch.cuda.manual_seed_all(s)
    torch.backends.cudnn.deterministic = True; torch.backends.cudnn.benchmark = False


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--images", required=True); ap.add_argument("--manifests", default="ai/manifests")
    ap.add_argument("--out", default="ai/checkpoints"); ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--epochs", type=int, default=50); ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    seed_all(a.seed); os.makedirs(a.out, exist_ok=True); os.makedirs(LOGS, exist_ok=True)
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    tr = CXR(os.path.join(a.manifests, "train.csv"), a.images, transforms_for(True))
    va = CXR(os.path.join(a.manifests, "val.csv"), a.images, transforms_for(False))
    g = torch.Generator(); g.manual_seed(a.seed)
    dl_tr = DataLoader(tr, batch_size=a.batch, shuffle=True, num_workers=a.workers, generator=g, pin_memory=True)
    dl_va = DataLoader(va, batch_size=a.batch, shuffle=False, num_workers=a.workers, pin_memory=True)

    pos = tr.df[LABELS].values.sum(0); neg = len(tr.df) - pos
    model = build_model().to(dev)
    crit = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(neg / np.maximum(pos, 1), dtype=torch.float32, device=dev))
    opt = torch.optim.Adam(model.parameters(), lr=1e-4, betas=(0.9, 0.999), eps=1e-8, weight_decay=1e-5)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="min", factor=0.1, patience=2)

    best, best_epoch, bad, stop_epoch, early = float("inf"), 0, 0, a.epochs, False
    ckpt = os.path.join(a.out, "densenet121_best.pth")
    log_path = os.path.join(LOGS, "train_log.csv")
    with open(log_path, "w") as fh: fh.write("epoch,train_loss,val_loss,lr,seconds,is_best\n")
    for epoch in range(1, a.epochs + 1):
        t0 = time.time(); model.train(); tl = 0.0
        for x, y, _ in dl_tr:
            x, y = x.to(dev, non_blocking=True), y.to(dev, non_blocking=True)
            opt.zero_grad(); loss = crit(model(x), y); loss.backward(); opt.step(); tl += loss.item() * len(x)
        model.eval(); vl = 0.0
        with torch.no_grad():
            for x, y, _ in dl_va:
                x, y = x.to(dev), y.to(dev); vl += crit(model(x), y).item() * len(x)
        tl /= len(tr); vl /= len(va); sched.step(vl)
        is_best = vl < best
        if is_best:
            best, best_epoch, bad = vl, epoch, 0; torch.save(model.state_dict(), ckpt)
        else:
            bad += 1
        with open(log_path, "a") as fh:
            fh.write(f"{epoch},{tl:.6f},{vl:.6f},{opt.param_groups[0]['lr']:.2e},{time.time() - t0:.1f},{int(is_best)}\n")
        print(f"epoch {epoch}: train {tl:.4f} val {vl:.4f} {'*' if is_best else ''}", flush=True)
        if bad >= 7:
            stop_epoch, early = epoch, True; break
    summary = dict(best_epoch=best_epoch, best_val_loss=best, stop_epoch=stop_epoch, early_stopping_fired=early,
                   checkpoint=ckpt, checkpoint_sha256=sha256_file(ckpt), seed=a.seed, device=str(dev),
                   torch=torch.__version__, n_train=len(tr), n_val=len(va))
    json.dump(summary, open(os.path.join(LOGS, "train_summary.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
