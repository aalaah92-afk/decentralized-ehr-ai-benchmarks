"""Shared constants for the DenseNet121 ChestX-ray14 pipeline."""
LABELS = [
    "Atelectasis", "Cardiomegaly", "Effusion", "Infiltration", "Mass", "Nodule", "Pneumonia",
    "Pneumothorax", "Consolidation", "Edema", "Emphysema", "Fibrosis", "Pleural_Thickening", "Hernia",
]
# CheXpert column -> ChestX-ray14 label (pathologies present in both datasets)
CHEXPERT_MAP = {
    "Atelectasis": "Atelectasis", "Cardiomegaly": "Cardiomegaly", "Consolidation": "Consolidation",
    "Edema": "Edema", "Pleural Effusion": "Effusion", "Pneumonia": "Pneumonia", "Pneumothorax": "Pneumothorax",
}
SPLIT_SEED = 42
BOOTSTRAP_SEED = 2026
BOOTSTRAP_REPS = 1000
IMAGE_SIZE = 320
IMAGENET_MEAN = [0.485, 0.456, 0.406]
IMAGENET_STD = [0.229, 0.224, 0.225]
