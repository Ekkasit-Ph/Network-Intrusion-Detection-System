"""Final test-set evaluation (MODEL_DEVELOPMENT.md section 4, step 5).

Run exactly once, after model + threshold are both frozen. Reports more
than accuracy, per PROJECT.md's non-negotiable constraint: the dataset is
imbalanced (benign 36% / attack 64%, some classes <0.1%), so precision,
recall, F1 and FPR are reported overall (macro + weighted) *and* per attack
class — rare classes like Ransomware, MITM, Backdoor are exactly the ones a
single accuracy number would hide.

    python -m source.model.evaluate

Optionally also reports metrics on a resampled *view* of the same test set
at a different benign:attack ratio (e.g. 50/50) — useful because this
project's val/test splits end up far more attack-heavy than real traffic
(all attack data is held out of training; only 30% of the abundant benign
pool goes to val+test — see PROJECT.md's split design), which inflates
precision relative to what a live deployment would see. This is a
supplementary diagnostic only: it must never be used to re-pick the model
or threshold, both of which stay frozen from tune.py/threshold.py, and it
writes to a separate file so it can never be mistaken for the one official,
touched-once evaluation.

    python -m source.model.evaluate --resample-benign-fraction 0.5 --resample-label balanced
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from source.common import paths
from source.common.constants import ATTACK_COL, LABEL_COL, RANDOM_SEED
from source.model.dataset import load_split, make_loader
from source.model.ensemble import load_scoring_models
from source.model.inference import compute_ensemble_reconstruction_errors
from source.model.train import get_device

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def binary_metrics(labels: np.ndarray, preds: np.ndarray) -> dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(labels) if len(labels) else 0.0

    out: dict[str, Any] = {"accuracy": accuracy, "fpr": fpr, "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}
    for avg in ("macro", "weighted"):
        p, r, f1, _ = precision_recall_fscore_support(labels, preds, average=avg, zero_division=0)
        out[avg] = {"precision": p, "recall": r, "f1": f1}
    p, r, f1, _ = precision_recall_fscore_support(labels, preds, average="binary", pos_label=1, zero_division=0)
    out["attack_class"] = {"precision": p, "recall": r, "f1": f1}
    return out


def per_class_detection_rate(attack_names: np.ndarray, preds: np.ndarray) -> dict[str, Any]:
    """For each true class (incl. Benign), fraction flagged as anomaly.

    For attack classes this is the detection rate (recall); for Benign it's
    the false-positive rate restricted to that class (identical to the
    overall FPR since Benign is the only negative class here, but reported
    per-class for symmetry / consistency with the per-class table)."""
    out: dict[str, Any] = {}
    for cls in sorted(np.unique(attack_names)):
        mask = attack_names == cls
        n = int(mask.sum())
        detected = int(preds[mask].sum())
        out[str(cls)] = {"n_samples": n, "n_flagged_anomaly": detected, "detection_rate": detected / n if n else 0.0}
    return out


def resample_to_benign_fraction(labels: np.ndarray, benign_fraction: float, seed: int = RANDOM_SEED) -> np.ndarray:
    """Row indices for a subset where `benign_fraction` of rows are benign
    (e.g. 0.5 for a balanced 50/50 view), built by downsampling whichever
    class is over-represented relative to that target. Never upsamples /
    duplicates rows, so the returned subset is always a subset of the real
    data -- no synthetic rows, just a different mix of the ones that exist.
    """
    if not 0 < benign_fraction < 1:
        raise ValueError("benign_fraction must be strictly between 0 and 1")
    rng = np.random.default_rng(seed)
    benign_idx = np.flatnonzero(labels == 0)
    attack_idx = np.flatnonzero(labels == 1)
    attack_fraction = 1 - benign_fraction

    # Try keeping all benign rows and downsampling attack to hit the ratio;
    # if that would need more attack rows than exist, downsample benign
    # instead (keeping all attack rows) and recompute from that side.
    n_attack_needed = int(round(len(benign_idx) * attack_fraction / benign_fraction))
    if n_attack_needed <= len(attack_idx):
        n_benign, n_attack = len(benign_idx), n_attack_needed
    else:
        n_attack = len(attack_idx)
        n_benign = min(len(benign_idx), int(round(n_attack * benign_fraction / attack_fraction)))

    chosen = np.concatenate([
        rng.choice(benign_idx, size=n_benign, replace=False),
        rng.choice(attack_idx, size=n_attack, replace=False),
    ])
    rng.shuffle(chosen)
    return chosen


def _load_model_and_score_test_set(
    processed_dir: Path, artifacts_dir: Path,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any], int]:
    """Shared by `run` and `run_resampled`: load the frozen model(s) +
    threshold once and score the full test set once. Returns
    (errors, labels, attack_names, threshold, n_test_rows)."""
    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    threshold = json.loads((artifacts_dir / "threshold.json").read_text())
    device = get_device()
    # Uses an ensemble/ under artifacts_dir automatically if one exists
    # (see source/model/ensemble.py), else the single model.pt.
    models = load_scoring_models(artifacts_dir, device)

    test_df = load_split(processed_dir / "test.parquet", feature_cols)
    labels = test_df[LABEL_COL].to_numpy()
    attack_names = test_df[ATTACK_COL].to_numpy()
    loader = make_loader(test_df, feature_cols, batch_size=512, shuffle=False, device=device)
    errors = compute_ensemble_reconstruction_errors(models, loader, device)

    return errors, labels, attack_names, threshold, len(test_df)


def _log_report(report: dict[str, Any]) -> None:
    log.info("Overall: acc=%.4f macro_f1=%.4f fpr=%.4f", report["overall"]["accuracy"], report["overall"]["macro"]["f1"], report["overall"]["fpr"])
    for cls, m in sorted(report["per_class"].items(), key=lambda kv: kv[1]["detection_rate"]):
        log.info("  %-12s n=%-8d detection_rate=%.4f", cls, m["n_samples"], m["detection_rate"])


def run(
    processed_dir: Path,
    artifacts_dir: Path,
    resample_benign_fraction: float | None = None,
    resample_label: str = "resampled",
    resample_seed: int = RANDOM_SEED,
) -> dict[str, Any]:
    errors, labels, attack_names, threshold, n_test_rows = _load_model_and_score_test_set(processed_dir, artifacts_dir)
    preds = (errors > threshold["value"]).astype(int)

    report: dict[str, Any] = {
        "threshold_used": threshold,
        "n_test_rows": n_test_rows,
        "overall": binary_metrics(labels, preds),
        "per_class": per_class_detection_rate(attack_names, preds),
    }

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    (artifacts_dir / "metrics_report.json").write_text(json.dumps(report, indent=2))
    log.info("=== Natural test-set distribution (%d rows, %.1f%% benign) ===", n_test_rows, 100 * (labels == 0).mean())
    _log_report(report)

    if resample_benign_fraction is not None:
        idx = resample_to_benign_fraction(labels, resample_benign_fraction, seed=resample_seed)
        sub_labels, sub_preds, sub_attack_names = labels[idx], preds[idx], attack_names[idx]
        resampled_report: dict[str, Any] = {
            "note": "Supplementary diagnostic only -- NOT used to re-pick model/threshold, which stay frozen.",
            "threshold_used": threshold,
            "target_benign_fraction": resample_benign_fraction,
            "actual_benign_fraction": float((sub_labels == 0).mean()),
            "n_rows": int(len(idx)),
            "overall": binary_metrics(sub_labels, sub_preds),
            "per_class": per_class_detection_rate(sub_attack_names, sub_preds),
        }
        out_path = artifacts_dir / f"metrics_report_{resample_label}.json"
        out_path.write_text(json.dumps(resampled_report, indent=2))
        log.info(
            "=== Resampled to %.0f%% benign (%d rows) -> %s ===",
            100 * resample_benign_fraction, len(idx), out_path.name,
        )
        _log_report(resampled_report)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--artifacts-dir", type=Path, default=paths.DEFAULT_MODEL_DIR)
    parser.add_argument("--resample-benign-fraction", type=float, default=None, help="e.g. 0.5 for a balanced 50/50 supplementary report; omit to skip")
    parser.add_argument("--resample-label", type=str, default="resampled", help="Output filename suffix: metrics_report_<label>.json")
    parser.add_argument("--resample-seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()
    run(
        args.processed_dir, args.artifacts_dir,
        resample_benign_fraction=args.resample_benign_fraction,
        resample_label=args.resample_label,
        resample_seed=args.resample_seed,
    )


if __name__ == "__main__":
    main()
