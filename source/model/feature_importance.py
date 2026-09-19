"""Permutation feature importance for the trained autoencoder (diagnostic
tool, not part of the pipeline) -- answers "is every input feature
actually pulling weight", quantitatively rather than by assertion.

Method (Breiman 2001, adapted to an unsupervised reconstruction-error
score): for each feature column, shuffle its values across rows in the
validation set -- this destroys that one feature's association with the
rest of each row while leaving its marginal distribution untouched -- and
recompute:
  - AUC drop (attack vs benign, using reconstruction error as the score):
    how much *discriminative* signal that column was carrying. AUC only
    needs a ranking, which reconstruction error provides without the
    autoencoder ever having used attack labels to train -- this is why AUC
    (not raw loss) is what MODEL_DEVELOPMENT.md uses for hyperparameter
    selection too.
  - recall-at-the-frozen-operating-threshold drop: the metric that
    actually matters given this project's FPR<=5% constraint -- a feature
    can move AUC without moving the specific point on the ROC curve
    threshold.json picked.
  - benign reconstruction-error increase: how much the model *relies* on
    that column to reconstruct what it considers normal (a column the
    model barely uses for reconstruction will barely move when shuffled).

Uses the validation set, not test -- this is a supplementary analysis, not
a re-evaluation, and the project's discipline is to touch test exactly
once (see evaluate.py's docstring).

    python -m source.model.feature_importance --artifacts-dir artifacts/models/behavioral
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import torch
from sklearn.metrics import roc_auc_score

from source.common import paths
from source.common.constants import LABEL_COL, RANDOM_SEED
from source.model.dataset import load_split
from source.model.ensemble import load_scoring_models
from source.model.train import get_device

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


@torch.no_grad()
def _score(x: torch.Tensor, models: list[torch.nn.Module], device: torch.device, batch_size: int = 16384) -> np.ndarray:
    """Ensemble-averaged per-row reconstruction error, batched manually
    (not via TensorBatchLoader) so repeated calls in the permutation loop
    below don't pay DataFrame/loader construction overhead 46 times over."""
    n = x.shape[0]
    out = np.empty(n, dtype=np.float32)
    for start in range(0, n, batch_size):
        batch = x[start : start + batch_size].to(device)
        per_model = []
        for m in models:
            x_hat, _ = m(batch)
            per_model.append(torch.nn.functional.mse_loss(x_hat, batch, reduction="none").mean(dim=1))
        out[start : start + batch_size] = torch.stack(per_model).mean(dim=0).cpu().numpy()
    return out


def run(
    processed_dir: Path,
    artifacts_dir: Path,
    seed: int = RANDOM_SEED,
) -> dict[str, Any]:
    feature_cols: list[str] = json.loads((processed_dir / "feature_columns.json").read_text())
    device = get_device()
    models = load_scoring_models(artifacts_dir, device)
    for m in models:
        m.eval()

    threshold = json.loads((artifacts_dir / "threshold.json").read_text())["value"]

    val_df = load_split(processed_dir / "val.parquet", feature_cols + [LABEL_COL])
    labels = val_df[LABEL_COL].to_numpy()
    x = torch.tensor(val_df[feature_cols].to_numpy(dtype=np.float32))
    try:
        x = x.to(device)
    except RuntimeError:
        device = torch.device("cpu")  # dataset too large for VRAM -- fall back, like TensorBatchLoader

    rng = np.random.default_rng(seed)

    log.info("Scoring baseline (unpermuted) validation set...")
    baseline_errors = _score(x, models, device)
    baseline_auc = roc_auc_score(labels, baseline_errors)
    baseline_recall = float(((baseline_errors >= threshold) & (labels == 1)).sum() / (labels == 1).sum())
    baseline_benign_error = float(baseline_errors[labels == 0].mean())
    log.info("Baseline: AUC=%.4f recall@threshold=%.4f benign_mean_error=%.6f", baseline_auc, baseline_recall, baseline_benign_error)

    results = []
    for i, col in enumerate(feature_cols):
        original_col = x[:, i].clone()
        perm = torch.tensor(rng.permutation(x.shape[0]), device=x.device)
        x[:, i] = x[perm, i]

        errors = _score(x, models, device)
        auc = roc_auc_score(labels, errors)
        recall = float(((errors >= threshold) & (labels == 1)).sum() / (labels == 1).sum())
        benign_error = float(errors[labels == 0].mean())

        x[:, i] = original_col  # restore before permuting the next column

        results.append({
            "feature": col,
            "auc_drop": baseline_auc - auc,
            "recall_drop": baseline_recall - recall,
            "benign_error_increase": benign_error - baseline_benign_error,
        })
        log.info("%-32s auc_drop=%+.4f recall_drop=%+.4f benign_error_increase=%+.6f", col, results[-1]["auc_drop"], results[-1]["recall_drop"], results[-1]["benign_error_increase"])

    results.sort(key=lambda r: r["auc_drop"], reverse=True)
    report = {
        "baseline": {"auc": baseline_auc, "recall_at_threshold": baseline_recall, "benign_mean_error": baseline_benign_error, "threshold": threshold},
        "features": results,
    }
    out_path = artifacts_dir / "feature_importance.json"
    out_path.write_text(json.dumps(report, indent=2))
    log.info("Wrote %s", out_path)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--processed-dir", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--artifacts-dir", type=Path, default=paths.DEFAULT_MODEL_DIR)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()
    run(processed_dir=args.processed_dir, artifacts_dir=args.artifacts_dir, seed=args.seed)


if __name__ == "__main__":
    main()
