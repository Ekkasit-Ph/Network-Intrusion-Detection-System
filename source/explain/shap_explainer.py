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
import os
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np
import shap
import torch

from source.common.constants import LABEL_COL
from source.model.ensemble import load_scoring_models
from source.model.train import get_device

# shap logs its internal solver state (kernel weights, raw phi arrays) at
# INFO, so any app that calls logging.basicConfig(level=INFO) -- which the
# backend does -- ends up with pages of numpy dumps per explain request.
# `silent=True` on shap_values() suppresses its progress bar but not this.
# Nothing here needs shap's INFO chatter; warnings and errors still get
# through.
logging.getLogger("shap").setLevel(logging.WARNING)

# How many feature coalitions Kernel SHAP samples per explanation. Raised
# from 100 after measuring that 100 does not converge -- see
# ShapExplainer.explain and documentation/explanation-quality.md.
# NIDS_SHAP_NSAMPLES overrides it: lower for a memory-constrained board,
# higher when an explanation is going into a report rather than a screen.
DEFAULT_NSAMPLES = int(os.environ.get("NIDS_SHAP_NSAMPLES", "2000"))



def _sample_benign_background(
    train_path: Path, feature_cols: list[str], size: int, seed: int,
) -> np.ndarray:
    """A uniform random sample of `size` benign training rows, read without
    holding the split in memory.

    Reading the whole thing and calling `.sample(100)` on it is the obvious
    way to write this, and it was how this worked. It cost 2,054 MB of
    resident memory to end up keeping 18 KB -- 4.27M rows by 48 columns
    through pandas -- and the allocator does not hand that back afterwards,
    so the process carried the high-water mark for its whole life. It put
    the serving footprint above 2.5 GB, which is what a Raspberry Pi 4
    class board has in total, and it is the reason a 1 GB memory budget
    could not start the service at all.

    Reservoir sampling over Arrow batches draws from exactly the same
    population -- every benign row has the same probability of ending up in
    the sample -- with memory bounded by one batch. The rows it picks for a
    given seed differ from the old code's, so `base_value` moves slightly;
    that is a different draw from the same distribution, not a different
    definition of the background.
    """
    import pyarrow.parquet as pq

    rng = np.random.default_rng(seed)
    reservoir = np.empty((size, len(feature_cols)), dtype=np.float32)
    seen = 0

    # 16k rows per batch: measured on the 4.27M-row training split, this
    # reads in 0.83s holding 8 MB, against 0.73s holding 332 MB at 64k and
    # 1.98s at 4k. The knee is sharp and it sits here.
    for batch in pq.ParquetFile(train_path).iter_batches(
        batch_size=16_384, columns=feature_cols + [LABEL_COL]
    ):
        frame = batch.to_pandas()
        # The training split is benign-only by construction -- it is the
        # first of PROJECT.md's non-negotiable constraints -- so this filter
        # should never drop a row. It stays because the constraint is worth
        # enforcing at the point of use rather than assuming.
        benign = frame.loc[frame[LABEL_COL] == 0, feature_cols]
        if benign.empty:
            continue
        rows = benign.to_numpy(dtype=np.float32)

        take = min(size - seen, len(rows))
        if take > 0:  # still filling the reservoir
            reservoir[seen:seen + take] = rows[:take]
            seen += take
            rows = rows[take:]
        if len(rows) == 0:
            continue

        # Standard reservoir step for the rest of this batch: row i of the
        # stream (0-based) replaces a uniformly chosen slot with probability
        # size/(i+1), which leaves every row equally likely to survive.
        indices = seen + np.arange(len(rows))
        keep = rng.integers(0, indices + 1)
        chosen = keep < size
        if chosen.any():
            reservoir[keep[chosen]] = rows[chosen]
        seen += len(rows)

    if seen == 0:
        raise ValueError(f"{train_path} contains no benign rows to build a SHAP background from")
    return reservoir[:min(size, seen)]

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
        background = _sample_benign_background(
            processed_dir / "train.parquet", self.feature_cols, background_size, seed)

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

    def explain(self, feature_vector: dict[str, float],
                nsamples: int | None = None) -> dict[str, Any]:
        """`feature_vector` must already be in the standardized (post-scaler)
        space -- the same values stored in `flows.features_json`, not raw
        NetFlow values.

        `nsamples` is how many feature coalitions Kernel SHAP samples, and
        it decides whether the answer means anything. Default was 100, which
        is fast (14 ms) and does not converge: measured over 8 anomalous
        flows explained 8 times each, 75% of features changed sign between
        runs, the top-5 matched a converged reference 25% of the time
        against a 11% coin-flip baseline, and the mean error was 2.4x the
        mean attribution itself. Two clicks on the same row gave two
        different explanations.

        DEFAULT_NSAMPLES is 2000: 164 ms, sign flips down to 35%, top-5
        agreement with the reference up to 78%. See
        documentation/explanation-quality.md for the full curve and for why
        not 5000 -- it is better still, but it needs more than 1.2 GB where
        2000 fits in 1 GB, and the resource benchmark had just established
        that the whole service runs in 600 MB.
        """
        if nsamples is None:
            nsamples = DEFAULT_NSAMPLES
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
