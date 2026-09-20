"""Threshold determination (MODEL_DEVELOPMENT.md section 4).

Run only after a model has been chosen by tune.py/train.py. Computes the
percentile-based threshold (primary method) and a Gaussian-KDE-based
threshold (secondary comparison, per Kim et al. 2025) from *benign-only*
validation reconstruction errors, then scores every candidate on the full
validation set (benign+attack) and picks the highest-recall candidate whose
FPR stays at or under `--max-fpr` (default 5%) — see `select_threshold`'s
docstring for why FPR, not precision/F-beta, is the axis to constrain here.

Test set is never touched here.

    python -m source.model.threshold
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import gaussian_kde
from sklearn.metrics import confusion_matrix, precision_recall_curve, roc_curve

from source.common import paths
from source.common.constants import LABEL_COL
from source.model.dataset import load_split, make_loader
from source.model.ensemble import load_scoring_models
from source.model.inference import compute_ensemble_reconstruction_errors
from source.model.train import get_device

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

PERCENTILES = (90, 95, 97, 99)


def percentile_thresholds(benign_errors: np.ndarray, percentiles=PERCENTILES) -> dict[int, float]:
    return {p: float(np.percentile(benign_errors, p)) for p in percentiles}


def kde_intersection_threshold(benign_errors: np.ndarray, attack_errors: np.ndarray, grid_size: int = 2000) -> float | None:
    """Point where the attack-error KDE overtakes the benign-error KDE,
    searching past the benign distribution's peak. Returns None if the
    distributions don't cross in range (e.g. too few attack samples)."""
    if len(attack_errors) < 2 or len(benign_errors) < 2:
        return None
    try:
        benign_kde = gaussian_kde(benign_errors)
        attack_kde = gaussian_kde(attack_errors)
    except np.linalg.LinAlgError:
        return None  # degenerate (near-zero variance) distribution

    lo = float(min(benign_errors.min(), attack_errors.min()))
    hi = float(max(benign_errors.max(), attack_errors.max()))
    grid = np.linspace(lo, hi, grid_size)
    benign_density = benign_kde(grid)
    attack_density = attack_kde(grid)

    benign_peak_idx = int(np.argmax(benign_density))
    for i in range(benign_peak_idx, grid_size):
        if attack_density[i] > benign_density[i]:
            return float(grid[i])
    return None


def evaluate_threshold(errors: np.ndarray, labels: np.ndarray, thr: float) -> dict[str, float]:
    preds = (errors > thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(labels) if len(labels) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr, "accuracy": accuracy}


def select_threshold(
    candidates: list[dict[str, Any]],
    errors: np.ndarray,
    labels: np.ndarray,
    max_fpr: float = 0.05,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Pick the candidate with the highest recall among those whose FPR is
    at or below `max_fpr` (falls back to the lowest-FPR candidate if none
    qualify).

    FPR is the right axis to constrain, not precision or an F-beta score:
    FPR is computed purely from the benign population's behavior, so it
    means the same thing regardless of how the validation set happens to
    be composed. Precision (and anything derived from it, like F-beta)
    mixes in the *attack* population's size too -- and this project's
    val/test sets are deliberately attack-heavy (~86% attack rows, since
    all attack data is held out of training; see MODEL_DEVELOPMENT.md's
    split design), nothing like the overwhelmingly-benign traffic a
    deployed system will actually see.

    Concretely, this is why an earlier F-beta-based version of this
    function picked the KDE candidate: it flagged reconstruction error
    above ~1e-5 as anomalous, which is essentially "flag everything" --
    recall 1.0 but FPR 50.9%, i.e. it would false-alarm on roughly half of
    all real benign traffic. Precision on the (attack-heavy) validation
    set still came out to 0.92 for that candidate purely because attack
    rows outnumbered benign ones ~6:1 there, which made the F-beta score
    look like a win. FPR isn't fooled by that: 50.9% is disqualifying
    regardless of how the validation set is composed, and picking by
    FPR-then-recall never surfaces a candidate like that as "best".
    """
    scored = []
    for c in candidates:
        metrics = evaluate_threshold(errors, labels, c["value"])
        scored.append({**c, "metrics": metrics})

    within_cap = [c for c in scored if c["metrics"]["fpr"] <= max_fpr]
    if within_cap:
        best = max(within_cap, key=lambda c: (c["metrics"]["recall"], -c["metrics"]["fpr"]))
    else:
        # Nothing meets the cap -- best effort: least-bad FPR available.
        best = min(scored, key=lambda c: (c["metrics"]["fpr"], -c["metrics"]["recall"]))

    scored.sort(key=lambda c: c["metrics"]["recall"], reverse=True)
    return best, scored


def _downsample(*arrays: np.ndarray, max_points: int) -> tuple[np.ndarray, ...]:
    """Evenly-spaced downsample of same-length arrays to at most
    `max_points` (endpoints always kept). No-op if already small."""
    n = len(arrays[0])
    if n <= max_points:
        return arrays
    idx = np.unique(np.linspace(0, n - 1, max_points).astype(int))
    return tuple(a[idx] for a in arrays)


def curve_data(errors: np.ndarray, labels: np.ndarray, max_points: int = 500) -> dict[str, list[float]]:
    """ROC and PR curve points for plotting, downsampled to at most
    `max_points` each.

    sklearn's roc_curve/precision_recall_curve return one point per
    near-unique score value -- with 6M+ validation rows of float
    reconstruction error, nearly every value is unique, so this was
    writing millions of points (threshold_analysis.json exceeded 100MB) for
    a curve no thesis figure will ever render at more than a few hundred
    points of resolution anyway.
    """
    fpr, tpr, roc_thr = roc_curve(labels, errors)
    prec, rec, pr_thr = precision_recall_curve(labels, errors)

    fpr, tpr, roc_thr = _downsample(fpr, tpr, roc_thr, max_points=max_points)
    # precision_recall_curve's thresholds array is one shorter than
    # precision/recall (sklearn quirk -- it appends a final (1, 0) point
    # with no corresponding threshold), so it's downsampled on its own.
    prec, rec = _downsample(prec, rec, max_points=max_points)
    (pr_thr,) = _downsample(pr_thr, max_points=max_points)

    return {
        "roc": {"fpr": fpr.tolist(), "tpr": tpr.tolist(), "thresholds": roc_thr.tolist()},
        "pr": {"precision": prec.tolist(), "recall": rec.tolist(), "thresholds": pr_thr.tolist()},
    }


def run(processed_dir: Path, artifacts_dir: Path, max_fpr: float = 0.05) -> dict[str, Any]:
    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    device = get_device()
    # Uses an ensemble/ under artifacts_dir automatically if one exists
    # (see source/model/ensemble.py), else the single model.pt.
    models = load_scoring_models(artifacts_dir, device)

    val_df = load_split(processed_dir / "val.parquet", feature_cols)
    val_labels = val_df[LABEL_COL].to_numpy()
    val_loader = make_loader(val_df, feature_cols, batch_size=512, shuffle=False, device=device)
    errors = compute_ensemble_reconstruction_errors(models, val_loader, device)

    benign_errors = errors[val_labels == 0]
    attack_errors = errors[val_labels == 1]

    candidates: list[dict[str, Any]] = [
        {"method": "percentile", "percentile": p, "value": v}
        for p, v in percentile_thresholds(benign_errors).items()
    ]
    kde_thr = kde_intersection_threshold(benign_errors, attack_errors)
    if kde_thr is not None:
        candidates.append({"method": "kde", "percentile": None, "value": kde_thr})

    best, scored = select_threshold(candidates, errors, val_labels, max_fpr=max_fpr)

    result = {
        "method": best["method"],
        "value": best["value"],
        "percentile": best.get("percentile"),
        "selection_criterion": f"max recall on validation set among candidates with FPR <= {max_fpr}",
        "val_metrics_at_selected_threshold": best["metrics"],
        # What the benign error distribution looked like when this threshold
        # was fitted, so a running deployment has something to compare
        # against. Drift is the reason a model needs retraining, and without
        # a record of the distribution it was calibrated on there is nothing
        # to notice drift *from* -- the operator is left inferring it from
        # the alert count, which also moves when the network is merely busy.
        # Labels are not needed to make the comparison, which matters: a
        # deployment has none.
        "calibration_reference": {
            "benign_error_percentiles": {
                str(p): float(np.percentile(benign_errors, p))
                for p in (50, 75, 90, 95, 99)
            },
            "benign_error_mean": float(np.mean(benign_errors)),
            "expected_flag_rate_on_benign": float(np.mean(benign_errors > best["value"])),
            "n_val_benign": int(len(benign_errors)),
        },
    }

    analysis = {
        "candidates": scored,
        "curves": curve_data(errors, val_labels),
        "n_val_benign": int(len(benign_errors)),
        "n_val_attack": int(len(attack_errors)),
    }

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    (artifacts_dir / "threshold.json").write_text(json.dumps(result, indent=2))
    (artifacts_dir / "threshold_analysis.json").write_text(json.dumps(analysis, indent=2))
    log.info("Selected threshold: %s", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--artifacts-dir", type=Path, default=paths.DEFAULT_MODEL_DIR)
    parser.add_argument("--max-fpr", type=float, default=0.05, help="Cap on false-positive rate; pick highest recall among candidates at or under this")
    args = parser.parse_args()
    run(args.processed_dir, args.artifacts_dir, max_fpr=args.max_fpr)


if __name__ == "__main__":
    main()
