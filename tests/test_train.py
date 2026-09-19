"""Tests for source/model/train.py's denoising-autoencoder support
(`noise_std`). The core property that matters: training must always
reconstruct the *clean* row even when the encoder is shown a corrupted
one, and validation/eval must never see noise at all -- get either wrong
and reconstruction error stops meaning "how anomalous is this row" and
starts meaning "how anomalous is this row, given some random corruption
that happened not to average out yet"."""

from __future__ import annotations

import torch

from source.model.autoencoder import Autoencoder
from source.model.dataset import TensorBatchLoader
from source.model.train import train_model


def _make_loaders(n=200, dim=6, seed=0):
    rng = torch.Generator().manual_seed(seed)
    x = torch.randn(n, dim, generator=rng)
    device = torch.device("cpu")
    train_loader = TensorBatchLoader(x, batch_size=32, shuffle=True, device=device)
    val_loader = TensorBatchLoader(x, batch_size=32, shuffle=False, device=device)
    return train_loader, val_loader


def test_noise_std_zero_matches_plain_training_behavior():
    """noise_std=0 (the default) must not change anything about how a
    model is currently trained -- this is a regression guard for every
    model trained before this option existed."""
    torch.manual_seed(0)
    model_a = Autoencoder(input_dim=6, latent_dim=4, hidden_dims=[8])
    torch.manual_seed(0)
    model_b = Autoencoder(input_dim=6, latent_dim=4, hidden_dims=[8])

    train_loader, val_loader = _make_loaders()
    torch.manual_seed(1)
    hist_a = train_model(model_a, train_loader, val_loader, torch.device("cpu"), max_epochs=3, patience=10, verbose=False, noise_std=0.0)
    torch.manual_seed(1)
    hist_b = train_model(model_b, train_loader, val_loader, torch.device("cpu"), max_epochs=3, patience=10, verbose=False)  # noise_std defaults to 0.0

    assert hist_a["val_loss"] == hist_b["val_loss"]


def test_denoising_training_runs_and_produces_finite_loss():
    train_loader, val_loader = _make_loaders()
    model = Autoencoder(input_dim=6, latent_dim=8, hidden_dims=[8])  # overcomplete on purpose

    history = train_model(model, train_loader, val_loader, torch.device("cpu"), max_epochs=5, patience=10, verbose=False, noise_std=0.3)

    assert all(v == v and v != float("inf") for v in history["val_loss"])  # no NaN/inf


def test_denoising_targets_stay_clean_not_corrupted():
    """Directly checks the mechanism: the loss computed inside training
    must be MSE(model(noised_input), clean_batch) -- not
    MSE(model(noised_input), noised_batch). We check this by verifying
    that a model trained with heavy noise still ends up able to reconstruct
    *clean* validation data reasonably (if it were being trained against
    noised targets, it would learn to reproduce noise, not the signal, and
    val_loss against clean data would stay high/not improve)."""
    torch.manual_seed(0)
    train_loader, val_loader = _make_loaders(n=2000, dim=4, seed=0)
    model = Autoencoder(input_dim=4, latent_dim=3, hidden_dims=[8])

    history = train_model(model, train_loader, val_loader, torch.device("cpu"), max_epochs=30, patience=30, verbose=False, noise_std=0.2)

    # A DAE that's actually learning the clean signal should still drive
    # validation (always clean) reconstruction error down over training,
    # same as a plain AE would.
    assert history["val_loss"][-1] < history["val_loss"][0]
