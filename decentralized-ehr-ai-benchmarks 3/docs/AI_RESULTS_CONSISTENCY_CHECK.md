# AI results - internal consistency check of the accepted manuscript

Prepared for the corresponding author. Every value below is copied from the manuscript file as submitted.

## 1. Class-wise values from the different places in the manuscript

| Pathology | AUROC Table 8 | AUROC Figure 4 | AUPRC Table 8 | AUPRC Figure 5 | AUPRC text §4.3 (PR paragraph) | AUPRC text §4.3/§5.2 |
|---|---|---|---|---|---|---|
| Atelectasis | 0.801 | 0.808 | 0.512 | 0.684 |  |  |
| Cardiomegaly | 0.902 | 0.902 | 0.395 | 0.824 | 0.824 | 0.512 |
| Effusion | 0.881 | 0.864 | 0.441 | 0.852 | 0.852 | 0.582 |
| Infiltration | 0.701 | 0.701 | 0.582 | 0.618 |  |  |
| Mass | 0.825 | 0.825 | 0.428 | 0.576 |  |  |
| Nodule | 0.758 | 0.758 | 0.382 | 0.452 |  |  |
| Pneumonia | 0.760 | 0.735 | 0.462 | 0.485 | 0.485 | 0.142 |
| Pneumothorax | 0.865 | 0.853 | 0.215 | 0.651 |  |  |
| Consolidation | 0.803 | 0.811 | 0.298 | 0.523 |  |  |
| Edema | 0.882 | 0.882 | 0.231 | 0.742 |  |  |
| Emphysema | 0.895 | 0.881 | 0.142 | 0.612 |  |  |
| Fibrosis | 0.812 | 0.805 | 0.264 | 0.418 |  | 0.215 |
| Pleural Thickening | 0.778 | 0.772 | 0.285 | 0.489 |  |  |
| Hernia | 0.893 | 0.893 | 0.472 | 0.781 | 0.781 |  |
| **Mean of the 14 values** | **0.825** | **0.821** | **0.365** | **0.622** | | |
| **Macro value stated** | 0.821 | 0.821 | 0.365 | 0.605 | 0.632 | – |

Note: the 14 AUPRC values printed in the Figure 5 legend average 0.622, while its macro-average entry reads 0.605.

## 2. Calibration values stated

| Location | ECE |
|---|---|
| §4.3 calibration paragraph | 0.018 ± 0.003 |
| §5.3 discussion | 0.008 |
| Figure 6 (inside the plot) | 0.010 |
| Table 8 macro row | 3.2 % |
| Mean of the 14 class-wise ECEs in Table 8 | 3.0 % |

## 3. Observations on the figures

1. **Figure 4 and Figure 5 show perfectly smooth curves.** Empirical ROC and precision-recall curves computed from 11,212 test images are step functions (with visible steps for rare classes such as Hernia, about 22 positive images).
2. **Figure 5:** at recall = 1 an empirical PR curve ends at precision = class prevalence (e.g. 0.002 for Hernia, 0.177 for Infiltration), not at 0; the no-skill baseline is class-specific, not a single "~0.10" line.
3. **Figure 6:** the histogram contains about 9,100 predictions centred near 0.45. The test set has 14 x 11,212 = 156,968 image-label predictions, and with a mean prevalence of about 5 % most predicted probabilities lie close to 0.
4. **Table 8 vs Figure 4:** 8 of the 14 AUROC values differ (e.g. Effusion 0.881 vs 0.864, Pneumonia 0.760 vs 0.735). Figure 4 averages 0.821, as did the table checked by Reviewer 3; the current Table 8 averages 0.825.
5. **Table 8 AUPRC confidence intervals** are narrow for classes with few positives (Hernia, about 22 positive images: 0.445-0.499). Patient-cluster bootstrap intervals for so few positives are normally much wider.
6. **Table 9 is internally consistent** with the Table 8 prevalences: PPV, NPV and F1 recomputed from sensitivity, specificity and prevalence agree to within rounding. Its thresholds and sensitivities, however, differ from the threshold/sensitivity/specificity columns of Table 8.
7. **Training epochs:** §3.7 states that early stopping ended training at epoch 23 and that the evaluated checkpoint is from epoch 28.
8. **Test-set size:** 11,212 images (Table 8, §3.6) vs 25,596 (calibration paragraph).

## 4. What resolves this

Only the model's saved outputs can decide which values are correct. With the validation and test prediction files (image, patient ID, 14 labels, 14 probabilities), `ai/evaluate.py` recomputes, in one run: Table 8, Table 9, the macro values with patient-cluster bootstrap CIs, all calibration metrics, and Figures 4-6 as empirical curves. It runs on a CPU in minutes, including on GitHub Actions if the two CSV files are committed to `ai/predictions/`.

If the saved predictions or the checkpoint are not available, the AI results cannot be reproduced. The model then has to be retrained (`ai/train.py`), or the editor should be informed before publication that the AI evaluation section needs to be corrected.
