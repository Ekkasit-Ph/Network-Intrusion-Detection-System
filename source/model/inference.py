"""Shared reconstruction-error computation, used by train/tune/threshold/evaluate.

Kept in one place so "anomaly score == mean per-row MSE" is defined exactly
once and can't drift between training-time early stopping, AUC-based
tuning, threshold selection, and final test evaluation.
"""

from __future__ import annotations

import numpy as np
import torch
from torch import nn

from source.model.dataset import TensorBatchLoader


@torch.no_grad()
def compute_reconstruction_errors(
    model: nn.Module,
    loader: TensorBatchLoader,
    device: torch.device,
) -> np.ndarray:
    model.eval()
    errors = []
    for (batch,) in loader:
        batch = batch.to(device)
        x_hat, _ = model(batch)
        per_row_mse = nn.functional.mse_loss(x_hat, batch, reduction="none").mean(dim=1)
        errors.append(per_row_mse.cpu().numpy())
    return np.concatenate(errors) if errors else np.array([])


@torch.no_grad()
def compute_ensemble_reconstruction_errors(
    models: list[nn.Module],
    loader: TensorBatchLoader,
    device: torch.device,
) -> np.ndarray:
    """Mean per-row reconstruction error across an ensemble of models —
    the standard way to turn several anomaly detectors into one score
    (e.g. Aggarwal, *Outlier Analysis*, 2017, ch. 6; averaging tends to
    reduce the score's variance without needing the models to agree on
    *which* rows are anomalous, just to jointly reconstruct benign data
    well). `models` of length 1 degenerates to plain
    `compute_reconstruction_errors`, so callers can use this
    unconditionally instead of branching on whether an ensemble exists.

    Requires `loader` to yield the same rows in the same order across
    repeated iteration (true for `TensorBatchLoader(shuffle=False)`, which
    is what threshold.py/evaluate.py use) — each model gets its own full
    pass over `loader`, and errors are averaged row-for-row, so a shuffling
    loader would silently average mismatched rows together.
    """
    if len(models) == 1:
        return compute_reconstruction_errors(models[0], loader, device)

    total = None
    for model in models:
        errors = compute_reconstruction_errors(model, loader, device)
        total = errors if total is None else total + errors
    return total / len(models)
