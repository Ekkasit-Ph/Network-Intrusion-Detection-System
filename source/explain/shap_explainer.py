"""Kernel SHAP wrapper for on-demand reconstruction-error explanation
(module 4).

**On-demand only** — instantiate once per backend process (loading the
model + building the background sample happens once, up front); call
`.explain()` per flow only when a user asks, never automatically per flow.
Kernel SHAP is model-agnostic (works directly against reconstruction error
as a scalar function, no autoencoder-specific SHAP variant needed) but is
computationally expensive — see PROJECT.md constraints.

The scalar function being explained is the model's reconstruction error
(averaged across ensemble members if one exists — same score
threshold.py/evaluate.py use), *not* a class probability: SHAP values here
say "this feature pushed the reconstruction error up/down by this much",
which is what makes a flow look anomalous or not.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np
import shap
import torch

from source.common.constants import LABEL_COL
from source.model.dataset import load_split
from source.model.ensemble import load_scoring_models
from source.model.train import get_device

# shap logs its internal solver state (kernel weights, raw phi arrays) at
# INFO, so any app that calls logging.basicConfig(level=INFO) -- which the
# backend does -- ends up with pages of numpy dumps per explain request.
# `silent=True` on shap_values() suppresses its progress bar but not this.
# Nothing here needs shap's INFO chatter; warnings and errors still get
# through.
logging.getLogger("shap").setLevel(logging.WARNING)


class ShapExplainer:
    def __init__(
        self,
        processed_dir: Path,
        artifacts_dir: Path,
        background_size: int = 100,
        seed: int = 0,
    ) -> None:
        self.feature_cols: list[str] = json.loads((processed_dir / "feature_columns.json").read_text())
        self.device = get_device()
        self.models = load_scoring_models(artifacts_dir, self.device)
        for m in self.models:
            m.eval()

        # Background set = a sample of scaled *benign* training rows (the
        # model's own definition of "normal" -- what reconstruction error
        # is being measured against).
        train_df = load_split(processed_dir / "train.parquet", self.feature_cols + [LABEL_COL])
        benign = train_df[train_df[LABEL_COL] == 0]
        n = min(background_size, len(benign))
        background = benign[self.feature_cols].sample(n=n, random_state=seed).to_numpy(dtype=np.float32)

        self.explainer = shap.KernelExplainer(self._score_fn, background)
        # `KernelExplainer.explain()` keeps its working state on the
        # instance (self.fx, self.nsamples, self.varyingInds, self.M, ...),
        # so it is not reentrant. The /explain endpoint is a sync `def`,
        # which FastAPI runs in a threadpool -- two dashboard users
        # clicking Explain at the same time would interleave inside the
        # solver and each receive attributions computed partly from the
        # other's flow, with nothing raised to signal it. Serializing is
        # the right trade here: an explain takes a few seconds, requests
        # are rare and user-initiated, and a queued-but-correct
        # explanation beats a fast wrong one in a tool whose entire
        # purpose is to be trusted.
        self._lock = threading.Lock()

    @torch.no_grad()
    def _score_fn(self, x: np.ndarray) -> np.ndarray:
        """x: (n, n_features) standardized features -> (n,) reconstruction
        error, averaged across ensemble members if there is more than one.
        This is exactly what SHAP treats as "the model output" to attribute
        across features."""
        t = torch.tensor(x, dtype=torch.float32, device=self.device)
        per_model = []
        for m in self.models:
            x_hat, _ = m(t)
            err = torch.nn.functional.mse_loss(x_hat, t, reduction="none").mean(dim=1)
            per_model.append(err.cpu().numpy())
        return np.mean(per_model, axis=0)

    def explain(self, feature_vector: dict[str, float], nsamples: int = 100) -> dict[str, Any]:
        """`feature_vector` must already be in the standardized (post-scaler)
        space -- the same values stored in `flows.features_json`, not raw
        NetFlow values. `nsamples` trades accuracy for latency; 100 keeps
        this to a few seconds, appropriate for an interactive dashboard
        click rather than a batch/offline analysis."""
        x = np.array([[feature_vector[c] for c in self.feature_cols]], dtype=np.float32)
        t0 = time.time()
        with self._lock:  # see __init__: KernelExplainer is not reentrant
            shap_values = self.explainer.shap_values(x, nsamples=nsamples, silent=True)
            base_value = float(np.asarray(self.explainer.expected_value).reshape(-1)[0])
        elapsed_ms = (time.time() - t0) * 1000

        values = np.asarray(shap_values).reshape(-1)
        return {
            "shap_values": {col: float(v) for col, v in zip(self.feature_cols, values)},
            "base_value": base_value,
            "computation_time_ms": elapsed_ms,
        }
