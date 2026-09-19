"""Turns a preprocessed parquet split into tensors / batch iterators.

Kept deliberately thin: preprocessing already did scaling/encoding, so this
module's only job is the DataFrame -> torch.Tensor boundary, plus batching.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import torch

from source.common.constants import LABEL_COL


def load_split(path: str | Path, feature_cols: list[str]) -> pd.DataFrame:
    df = pd.read_parquet(path)
    missing = set(feature_cols) - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing expected feature columns: {sorted(missing)}")
    return df


def features_to_tensor(df: pd.DataFrame, feature_cols: list[str]) -> torch.Tensor:
    return torch.tensor(df[feature_cols].to_numpy(dtype=np.float32))


class TensorBatchLoader:
    """Drop-in iterator over an in-memory feature tensor, yielding `(batch,)`
    tuples the same shape as `TensorDataset` + `DataLoader` would.

    For a model this small, `torch.utils.data.DataLoader`'s per-sample
    `__getitem__` overhead -- not GPU compute -- dominates wall-clock time:
    benchmarked training the autoencoder on the full 4.27M-row training set,
    GPU utilization sat at ~10% under a standard DataLoader. Keeping the
    whole tensor resident on `device` (this dataset is ~700MB, comfortably
    inside a 4GB GPU) and slicing batches with a single fancy-index op
    instead measured 2-20x faster per epoch depending on batch size (bigger
    batches amortize more, since the win is per-*batch* overhead, not
    per-row). `train_model`/`compute_reconstruction_errors` still call
    `.to(device)` on each yielded batch; that's a no-op once it's already
    there, so nothing downstream needs to change to benefit from this.

    Falls back to keeping the tensor on CPU (still batching this way,
    still far cheaper than DataLoader, just paying a per-batch host->device
    transfer) if it doesn't fit on `device` -- relevant for much larger
    datasets or smaller GPUs than the one this was tuned against.
    """

    def __init__(self, tensor: torch.Tensor, batch_size: int, shuffle: bool, device: torch.device):
        self.batch_size = batch_size
        self.shuffle = shuffle
        self.device = device
        try:
            self.tensor = tensor.to(device)
        except RuntimeError:
            self.tensor = tensor  # OOM on device (e.g. dataset too large for VRAM) -- stay on CPU

    def __iter__(self):
        n = self.tensor.shape[0]
        index_device = self.tensor.device
        order = (
            torch.randperm(n, device=index_device) if self.shuffle
            else torch.arange(n, device=index_device)
        )
        for i in range(0, n, self.batch_size):
            batch = self.tensor[order[i : i + self.batch_size]]
            yield (batch.to(self.device),)

    def __len__(self) -> int:
        return (self.tensor.shape[0] + self.batch_size - 1) // self.batch_size


def make_loader(
    df: pd.DataFrame,
    feature_cols: list[str],
    batch_size: int,
    shuffle: bool,
    benign_only: bool = False,
    device: torch.device | None = None,
) -> TensorBatchLoader:
    """Build a batch iterator yielding just the feature tensor (autoencoder
    input == target). Set `benign_only=True` for the training loader.

    `device` defaults to CUDA if available, else CPU -- pass `torch.device("cpu")`
    explicitly for the resource-constrained-gateway benchmark (see train.py's
    `--cpu` flag), since this loader keeping the tensor resident on the
    training device is exactly the optimization that benchmark needs to
    measure the *absence* of.
    """
    if benign_only:
        df = df[df[LABEL_COL] == 0]
    x = features_to_tensor(df, feature_cols)
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return TensorBatchLoader(x, batch_size=batch_size, shuffle=shuffle, device=device)
