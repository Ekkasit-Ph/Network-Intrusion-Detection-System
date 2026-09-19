"""GET /meta — everything the dashboard needs to interpret a number.

The API stores standardized features (`flows.features_json` holds z-scores,
because that is what the model consumes). A z of +4.2 says a feature is far
from normal but not *what it is*, and "IN_BYTES z=+4.2" is not something an
analyst can act on. This endpoint hands over the constants needed to invert
the transform, so the explanation panel can show the real quantity next to
the z.

Inverting is exact rather than approximate, because the forward path is
known exactly: log1p (for the columns in LOG_TRANSFORM_COLS) then
StandardScaler. So raw = expm1(z * scale + mean), or z * scale + mean where
no log was applied.

Two feature kinds cannot be inverted into a physical unit, and are labelled
rather than fudged:

  * `frequency` -- L7_PROTO is frequency-encoded, so its "raw" value is how
    common that protocol was in training, not a protocol id. Showing 0.83
    as though it were a port number would be worse than showing nothing.
  * `onehot` -- PROTOCOL_6.0 and friends invert to 0 or 1, which is
    meaningful but is a flag, not a measurement.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

from source.common import paths
from source.common.constants import LOG_TRANSFORM_COLS

router = APIRouter()
log = logging.getLogger(__name__)

_cache: dict | None = None


def _preprocessing_dir(processed_dir: Path) -> Path:
    """data/processed_w50 -> artifacts/preprocessing_w50, the pairing the
    preprocessing run produced. Mirrors live_capture.py's default."""
    override = os.environ.get("NIDS_PREPROCESSING_DIR")
    if override:
        return Path(override)
    suffix = processed_dir.name.removeprefix("processed")
    return paths.ARTIFACTS_DIR / f"preprocessing{suffix}"


def build_meta() -> dict:
    import joblib

    processed_dir = Path(os.environ.get("NIDS_PROCESSED_DIR", str(paths.PROCESSED_DATA_DIR)))
    artifacts_dir = Path(os.environ.get("NIDS_MODEL_DIR", str(paths.DEFAULT_MODEL_DIR)))
    prep_dir = _preprocessing_dir(processed_dir)

    feature_cols: list[str] = json.loads((processed_dir / "feature_columns.json").read_text())
    scaler = joblib.load(prep_dir / "scaler.pkl")
    encoders = json.loads((prep_dir / "categorical_encoders.json").read_text())

    frequency_cols = {c for c, spec in encoders.items() if spec["strategy"] == "frequency"}
    onehot_prefixes = tuple(f"{c}_" for c, spec in encoders.items() if spec["strategy"] == "onehot")
    logged = set(LOG_TRANSFORM_COLS)

    features = {}
    for i, col in enumerate(feature_cols):
        if col in frequency_cols:
            kind = "frequency"
        elif col.startswith(onehot_prefixes):
            kind = "onehot"
        else:
            kind = "numeric"
        features[col] = {
            "mean": float(scaler.mean_[i]),
            "scale": float(scaler.scale_[i]),
            "log": col in logged,
            "kind": kind,
        }

    threshold = json.loads((artifacts_dir / "threshold.json").read_text())
    meta = {
        "model": artifacts_dir.name,
        "feature_columns": feature_cols,
        "features": features,
        "threshold": threshold["value"],
        "threshold_criterion": threshold.get("selection_criterion", ""),
    }

    # Headline metrics for the footer. Absent on a model that has not been
    # evaluated yet, which is a legitimate state -- the dashboard just
    # leaves that line out rather than inventing numbers.
    report = artifacts_dir / "metrics_report.json"
    if report.exists():
        try:
            overall = json.loads(report.read_text())["overall"]
            meta["metrics"] = {
                "recall": overall["attack_class"]["recall"],
                "fpr": overall["fpr"],
                "precision": overall["attack_class"]["precision"],
                "n_test_rows": json.loads(report.read_text()).get("n_test_rows"),
            }
        except (KeyError, ValueError):
            log.warning("metrics_report.json present but unreadable; footer metrics omitted")
    return meta


@router.get("/meta")
def get_meta() -> dict:
    # Built once: the scaler is a few KB but loading joblib per request
    # would put a disk read in front of a page that polls every 2 seconds.
    global _cache
    if _cache is None:
        try:
            _cache = build_meta()
        except FileNotFoundError as e:
            raise HTTPException(
                status_code=503,
                detail=f"preprocessing artifacts not found ({e}); "
                       f"set NIDS_PROCESSED_DIR / NIDS_PREPROCESSING_DIR",
            ) from e
    return _cache
