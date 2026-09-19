"""Tests for ensemble training and ensemble-aware scoring."""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
import torch

from source.common.constants import ATTACK_COL, LABEL_COL, MODEL_FEATURES
from source.model import ensemble
from source.model.autoencoder import Autoencoder
from source.model.dataset import make_loader
from source.model.inference import compute_ensemble_reconstruction_errors, compute_reconstruction_errors


def _make_tiny_split(n_benign: int, n_attack: int, seed: int) -> pd.DataFrame:
    rng = torch.Generator().manual_seed(seed)
    n = n_benign + n_attack
    data = {col: torch.randn(n, generator=rng).numpy() for col in MODEL_FEATURES}
    df = pd.DataFrame(data)
    df[LABEL_COL] = [0] * n_benign + [1] * n_attack
    df[ATTACK_COL] = ["Benign"] * n_benign + ["Scanning"] * n_attack
    return df


def test_compute_ensemble_reconstruction_errors_matches_single_model_for_one_model():
    torch.manual_seed(0)
    model = Autoencoder(input_dim=5, latent_dim=2, hidden_dims=[8])
    device = torch.device("cpu")
    x = torch.randn(20, 5)
    loader = make_loader(
        pd.DataFrame({f"f{i}": x[:, i].numpy() for i in range(5)} | {LABEL_COL: 0}),
        [f"f{i}" for i in range(5)], batch_size=4, shuffle=False, device=device,
    )
    single = compute_reconstruction_errors(model, loader, device)
    ensembled = compute_ensemble_reconstruction_errors([model], loader, device)
    assert np.allclose(single, ensembled)


def test_compute_ensemble_reconstruction_errors_is_the_mean_across_models():
    torch.manual_seed(0)
    device = torch.device("cpu")
    models = [Autoencoder(input_dim=5, latent_dim=2, hidden_dims=[8]) for _ in range(3)]
    x = torch.randn(16, 5)
    cols = [f"f{i}" for i in range(5)]
    df = pd.DataFrame({c: x[:, i].numpy() for i, c in enumerate(cols)} | {LABEL_COL: 0})
    loader = make_loader(df, cols, batch_size=4, shuffle=False, device=device)

    individual = [compute_reconstruction_errors(m, loader, device) for m in models]
    expected_mean = np.mean(individual, axis=0)
    ensembled = compute_ensemble_reconstruction_errors(models, loader, device)
    assert np.allclose(ensembled, expected_mean)


def test_train_ensemble_and_load_scoring_models_roundtrip(tmp_path):
    processed_dir = tmp_path / "processed"
    artifacts_dir = tmp_path / "artifacts"
    processed_dir.mkdir()

    train_df = _make_tiny_split(n_benign=64, n_attack=0, seed=0)
    val_df = _make_tiny_split(n_benign=32, n_attack=32, seed=1)
    train_df.to_parquet(processed_dir / "train.parquet", index=False)
    val_df.to_parquet(processed_dir / "val.parquet", index=False)
    (processed_dir / "feature_columns.json").write_text(json.dumps(MODEL_FEATURES))

    source_config = {
        "input_dim": len(MODEL_FEATURES), "latent_dim": 4, "hidden_dims": [8],
        "dropout": 0.0, "lr": 1e-2, "batch_size": 16,
    }
    ensemble_config = ensemble.train_ensemble(
        processed_dir=processed_dir, artifacts_dir=artifacts_dir, source_config=source_config,
        n_models=3, seed_base=0, epochs=2, patience=2, device=torch.device("cpu"),
    )
    assert ensemble_config["n_models"] == 3
    assert len(ensemble_config["members"]) == 3

    ensemble_dir = artifacts_dir / "ensemble"
    assert (ensemble_dir / "ensemble_config.json").exists()
    for i in range(3):
        assert (ensemble_dir / f"model_{i}.pt").exists()

    models = ensemble.load_scoring_models(artifacts_dir, torch.device("cpu"))
    assert len(models) == 3
    for m in models:
        assert isinstance(m, Autoencoder)
        assert m.latent_dim == 4


def test_load_scoring_models_falls_back_to_single_model_without_ensemble(tmp_path):
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    model = Autoencoder(input_dim=len(MODEL_FEATURES), latent_dim=4, hidden_dims=[8])
    torch.save(model.state_dict(), artifacts_dir / "model.pt")
    (artifacts_dir / "model_config.json").write_text(json.dumps(model.config()))

    models = ensemble.load_scoring_models(artifacts_dir, torch.device("cpu"))
    assert len(models) == 1
    assert isinstance(models[0], Autoencoder)
