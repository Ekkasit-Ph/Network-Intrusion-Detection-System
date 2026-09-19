"""Central path definitions so every script agrees on where things live.

Nothing here creates files on import; call `ensure_dirs()` explicitly from
entry-point scripts.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Raw dataset. The NF-ToN-IoT-v2 CSV currently ships inside Dataset/data/
# (BagIt export); data/raw/ is the canonical place future scripts should
# read from — either drop/symlink the CSV there or pass --input explicitly.
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
LEGACY_DATASET_CSV = PROJECT_ROOT / "Dataset" / "data" / "NF-ToN-IoT-v2.csv"

PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"
CONFIGURATION_DIR = PROJECT_ROOT / "configuration"

TRAIN_PARQUET = PROCESSED_DATA_DIR / "train.parquet"
VAL_PARQUET = PROCESSED_DATA_DIR / "val.parquet"
TEST_PARQUET = PROCESSED_DATA_DIR / "test.parquet"
PREPROCESSING_REPORT = PROCESSED_DATA_DIR / "preprocessing_report.json"
FEATURE_COLUMNS_JSON = PROCESSED_DATA_DIR / "feature_columns.json"

# artifacts/ is split in two:
#   preprocessing/  -- scaler + encoders fit from the CURRENT data/processed/
#                      (one set, shared by whatever model(s) train on that data)
#   models/<name>/  -- everything a single train.py/tune.py run produces.
# `models/default/` is just the out-of-the-box name for that one slot; a
# later experiment (different architecture, different search space, a
# retrain after reprocessing the data, ...) gets its own by passing
# `--artifacts-dir artifacts/models/<some-other-name>` to train.py/tune.py/
# threshold.py/evaluate.py -- same layout inside, nothing else to change.
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
PREPROCESSING_ARTIFACTS_DIR = ARTIFACTS_DIR / "preprocessing"
MODELS_DIR = ARTIFACTS_DIR / "models"
DEFAULT_MODEL_DIR = MODELS_DIR / "default"

SCALER_PATH = PREPROCESSING_ARTIFACTS_DIR / "scaler.pkl"
CATEGORICAL_ENCODERS_PATH = PREPROCESSING_ARTIFACTS_DIR / "categorical_encoders.json"

MODEL_PATH = DEFAULT_MODEL_DIR / "model.pt"
MODEL_CONFIG_PATH = DEFAULT_MODEL_DIR / "model_config.json"
THRESHOLD_PATH = DEFAULT_MODEL_DIR / "threshold.json"
TUNING_RESULTS_PATH = DEFAULT_MODEL_DIR / "tuning_results.csv"
TRAINING_HISTORY_PATH = DEFAULT_MODEL_DIR / "training_history.json"
METRICS_REPORT_PATH = DEFAULT_MODEL_DIR / "metrics_report.json"

SEARCH_SPACE_YAML = CONFIGURATION_DIR / "search_space.yaml"


def ensure_dirs() -> None:
    for d in (RAW_DATA_DIR, PROCESSED_DATA_DIR, PREPROCESSING_ARTIFACTS_DIR, DEFAULT_MODEL_DIR, CONFIGURATION_DIR):
        d.mkdir(parents=True, exist_ok=True)


def resolve_raw_csv() -> Path:
    """Best-effort lookup: prefer data/raw/, fall back to the BagIt export."""
    candidates = sorted(RAW_DATA_DIR.glob("*.csv"))
    if candidates:
        return candidates[0]
    if LEGACY_DATASET_CSV.exists():
        return LEGACY_DATASET_CSV
    raise FileNotFoundError(
        f"No CSV found in {RAW_DATA_DIR} and legacy path {LEGACY_DATASET_CSV} "
        "does not exist either. Pass --input explicitly."
    )
