# AI module (DenseNet121, NIH ChestX-ray14, CheXpert OOD)

All numbers in Tables 8-9 and Figures 4-6 must come from `evaluate.py` run on ONE set of saved predictions.

| Step | Command | Needs | Output |
|---|---|---|---|
| 1 split | `python ai/split_patients.py --data-entry Data_Entry_2017.csv` | NIH metadata CSV | `ai/manifests/*.csv`, `logs/split_summary.md` |
| 2 train | `python ai/train.py --images <NIH images>` | GPU, PyTorch, torchvision | checkpoint, `logs/train_log.csv`, `logs/train_summary.json` (best_epoch, stop_epoch, SHA-256) |
| 3 predict | `python ai/predict.py --images <dir> --manifest ai/manifests/val.csv --checkpoint <ckpt> --out ai/predictions/val_predictions.csv` (repeat for test.csv) | checkpoint + images | prediction CSVs, `logs/inference_latency.json` |
| 4 evaluate | `python ai/evaluate.py --val ai/predictions/val_predictions.csv --test ai/predictions/test_predictions.csv --tag nih` | prediction CSVs only (CPU) | `logs/ai_eval_nih.md/json`, ROC/PR/reliability figures |
| 5 CheXpert | `python ai/chexpert_eval.py --chexpert-root <CheXpert-v1.0-small> --checkpoint <ckpt>` | CheXpert + checkpoint | `logs/ai_eval_chexpert.md` |
| self-test | `python ai/synthetic_selftest.py` | nothing | `logs/ai_selftest.log` (synthetic data — not study results) |

If you still have the validation and test prediction files from your original model, put them in
`ai/predictions/` and step 4 regenerates every AI table and figure (it also runs in GitHub Actions if you
add a job for it). The prediction CSV format is: `Image Index, Patient ID, <14 labels>, p_<label> x 14`.
