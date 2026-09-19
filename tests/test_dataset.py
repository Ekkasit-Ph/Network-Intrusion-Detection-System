import pandas as pd
import torch

from source.model.dataset import TensorBatchLoader, make_loader


def test_tensor_batch_loader_covers_every_row_exactly_once():
    x = torch.arange(37 * 3, dtype=torch.float32).reshape(37, 3)  # awkward size: forces a partial last batch
    loader = TensorBatchLoader(x, batch_size=8, shuffle=False, device=torch.device("cpu"))

    assert len(loader) == 5  # ceil(37/8)
    seen_rows = []
    for (batch,) in loader:
        seen_rows.append(batch)
    seen = torch.cat(seen_rows, dim=0)
    assert seen.shape == x.shape
    # shuffle=False -> batches appear in original order, concatenation reproduces x exactly
    assert torch.equal(seen, x)


def test_tensor_batch_loader_shuffle_is_a_permutation_not_a_subset():
    x = torch.arange(50 * 2, dtype=torch.float32).reshape(50, 2)
    loader = TensorBatchLoader(x, batch_size=16, shuffle=True, device=torch.device("cpu"))

    seen = torch.cat([batch for (batch,) in loader], dim=0)
    assert seen.shape == x.shape
    # every original row appears exactly once, just reordered
    seen_sorted = seen[seen[:, 0].argsort()]
    assert torch.equal(seen_sorted, x)


def test_make_loader_benign_only_filters_to_label_zero(raw_df):
    from source.common.constants import LABEL_COL, NETFLOW_FEATURES

    feature_cols = [c for c in NETFLOW_FEATURES if c not in ("IPV4_SRC_ADDR", "IPV4_DST_ADDR")]
    loader = make_loader(raw_df, feature_cols, batch_size=32, shuffle=False, benign_only=True, device=torch.device("cpu"))

    n_rows = sum(batch.shape[0] for (batch,) in loader)
    assert n_rows == int((raw_df[LABEL_COL] == 0).sum())
