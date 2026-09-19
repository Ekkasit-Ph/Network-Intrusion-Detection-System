"""Integration test for the tuning sweep, covering the two bugs found
running it for real: GPU memory growing every trial (loaders were rebuilt
per-config instead of reused), and losing all results on a mid-sweep crash
(the CSV used to be written once at the end instead of incrementally)."""

from __future__ import annotations

import csv
import json

import numpy as np
import pandas as pd
import pytest
import torch
from sklearn.metrics import roc_auc_score

from source.common.constants import ATTACK_COL, LABEL_COL, MODEL_FEATURES
from source.model import tune


def _make_tiny_split(n_benign: int, n_attack: int, seed: int) -> pd.DataFrame:
    rng = torch.Generator().manual_seed(seed)
    n = n_benign + n_attack
    data = {col: torch.randn(n, generator=rng).numpy() for col in MODEL_FEATURES}
    df = pd.DataFrame(data)
    df[LABEL_COL] = [0] * n_benign + [1] * n_attack
    df[ATTACK_COL] = ["Benign"] * n_benign + ["Scanning"] * n_attack
    return df


def test_run_sweep_writes_incremental_results_and_best_model(tmp_path, monkeypatch):
    processed_dir = tmp_path / "processed"
    artifacts_dir = tmp_path / "artifacts"
    processed_dir.mkdir()

    train_df = _make_tiny_split(n_benign=64, n_attack=0, seed=0)
    val_df = _make_tiny_split(n_benign=32, n_attack=32, seed=1)
    train_df.to_parquet(processed_dir / "train.parquet", index=False)
    val_df.to_parquet(processed_dir / "val.parquet", index=False)
    (processed_dir / "feature_columns.json").write_text(json.dumps(MODEL_FEATURES))

    search_space = {
        "latent_dim": [2, 4],
        "hidden_dims": [[8]],
        "learning_rate": [1e-2],
        "batch_size": [16, 32],
        "dropout": [0.0],
    }

    results = tune.run_sweep(
        processed_dir=processed_dir,
        artifacts_dir=artifacts_dir,
        search_space=search_space,
        mode="random",
        n_trials=3,
        epochs=2,
        patience=2,
        seed=0,
        device=torch.device("cpu"),
    )

    assert len(results) == 3
    for r in results:
        assert "val_auc" in r and 0.0 <= r["val_auc"] <= 1.0

    csv_path = artifacts_dir / "tuning_results.csv"
    assert csv_path.exists()
    with csv_path.open() as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 3  # one row per trial, written incrementally -- not just at the end

    assert (artifacts_dir / "model.pt").exists()
    assert (artifacts_dir / "model_config.json").exists()
    assert (artifacts_dir / "training_history.json").exists()

    best_config = json.loads((artifacts_dir / "model_config.json").read_text())
    assert best_config["latent_dim"] in search_space["latent_dim"]
    assert best_config["batch_size"] in search_space["batch_size"]


def test_recall_at_max_fpr_matches_naive_threshold_scan():
    rng = np.random.default_rng(0)
    n = 500
    labels = rng.integers(0, 2, size=n)
    errors = rng.random(n) + labels * 0.4  # attacks skew higher, imperfectly

    got = tune.recall_at_max_fpr(labels, errors, max_fpr=0.05)

    # Naive reference: scan every observed error as a candidate threshold,
    # keep the one with FPR<=0.05 and the highest recall.
    best_recall = 0.0
    for t in np.unique(errors):
        preds = (errors >= t).astype(int)
        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()
        fn = ((preds == 0) & (labels == 1)).sum()
        tn = ((preds == 0) & (labels == 0)).sum()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        if fpr <= 0.05:
            best_recall = max(best_recall, recall)

    assert got == pytest.approx(best_recall, abs=1e-6)


def test_recall_at_max_fpr_disagrees_with_auc_on_a_constructed_example():
    """The exact property that motivates --selection-metric recall_at_fpr:
    two score arrays can rank oppositely by AUC vs. by recall-at-low-FPR.
    Both arrays are deterministic (no RNG) so the inequality holds by
    construction, not by luck of a particular random seed."""
    labels = np.array([0] * 100 + [1] * 100)
    benign = np.arange(100, dtype=float)

    # Model A: every attack score is benign+18 -> a modest, *uniform* lead
    # across the whole range gives it the better full-curve AUC, but nothing
    # separates cleanly enough to clear a strict low-FPR threshold well.
    errors_a = np.concatenate([benign, benign + 18.0])

    # Model B: 20 attacks score far above *any* benign value (trivially
    # separable, dominate the low-FPR region) while the other 80 are
    # numerically identical to 80 benign scores (fully overlapping,
    # indistinguishable) -- this drags B's full-curve AUC well below A's,
    # even though those 20 easy wins let B beat A at FPR<=0.05.
    errors_b = np.concatenate([benign, 1000.0 + np.arange(20), benign[:80]])

    auc_a = roc_auc_score(labels, errors_a)
    auc_b = roc_auc_score(labels, errors_b)
    recall_a = tune.recall_at_max_fpr(labels, errors_a, max_fpr=0.05)
    recall_b = tune.recall_at_max_fpr(labels, errors_b, max_fpr=0.05)

    assert auc_a > auc_b  # A wins on full-curve AUC
    assert recall_b > recall_a  # but B wins at the low-FPR operating point that matters


def test_run_sweep_selection_metric_recall_at_fpr_is_recorded(tmp_path):
    processed_dir = tmp_path / "processed"
    artifacts_dir = tmp_path / "artifacts"
    processed_dir.mkdir()

    train_df = _make_tiny_split(n_benign=64, n_attack=0, seed=0)
    val_df = _make_tiny_split(n_benign=32, n_attack=32, seed=1)
    train_df.to_parquet(processed_dir / "train.parquet", index=False)
    val_df.to_parquet(processed_dir / "val.parquet", index=False)
    (processed_dir / "feature_columns.json").write_text(json.dumps(MODEL_FEATURES))

    search_space = {
        "latent_dim": [2, 4], "hidden_dims": [[8]], "learning_rate": [1e-2],
        "batch_size": [16], "dropout": [0.0], "noise_std": [0.0, 0.1],
    }
    results = tune.run_sweep(
        processed_dir=processed_dir, artifacts_dir=artifacts_dir, search_space=search_space,
        mode="grid", epochs=2, patience=2, seed=0, device=torch.device("cpu"),
        selection_metric="recall_at_fpr", max_fpr=0.05,
    )

    for r in results:
        assert "recall_at_fpr" in r and 0.0 <= r["recall_at_fpr"] <= 1.0
        assert "noise_std" in r

    best_config = json.loads((artifacts_dir / "model_config.json").read_text())
    assert best_config["selected_by"] == "recall_at_fpr"
    assert "recall_at_fpr" in best_config
    assert "noise_std" in best_config


def test_run_optuna_sweep_writes_results_and_best_model(tmp_path):
    processed_dir = tmp_path / "processed"
    artifacts_dir = tmp_path / "artifacts"
    processed_dir.mkdir()

    train_df = _make_tiny_split(n_benign=64, n_attack=0, seed=0)
    val_df = _make_tiny_split(n_benign=32, n_attack=32, seed=1)
    train_df.to_parquet(processed_dir / "train.parquet", index=False)
    val_df.to_parquet(processed_dir / "val.parquet", index=False)
    (processed_dir / "feature_columns.json").write_text(json.dumps(MODEL_FEATURES))

    search_space = {
        "latent_dim": [2, 4],
        "hidden_dims": [[8], [4, 4]],
        "learning_rate": [1e-2],
        "batch_size": [16, 32],
        "dropout": [0.0],
        "noise_std": [0.0, 0.1],
    }

    results = tune.run_optuna_sweep(
        processed_dir=processed_dir,
        artifacts_dir=artifacts_dir,
        search_space=search_space,
        n_trials=3,
        epochs=2,
        patience=2,
        seed=0,
        device=torch.device("cpu"),
        selection_metric="recall_at_fpr",
    )

    assert len(results) == 3
    for r in results:
        assert "val_auc" in r and 0.0 <= r["val_auc"] <= 1.0
        assert "recall_at_fpr" in r and 0.0 <= r["recall_at_fpr"] <= 1.0
        assert r["hidden_dims"] in (json.dumps([8]), json.dumps([4, 4]))

    csv_path = artifacts_dir / "tuning_results.csv"
    assert csv_path.exists()
    with csv_path.open() as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 3

    best_config = json.loads((artifacts_dir / "model_config.json").read_text())
    assert best_config["latent_dim"] in search_space["latent_dim"]
    assert best_config["selected_by"] == "recall_at_fpr"
    assert (artifacts_dir / "model.pt").exists()


def test_run_sweep_clears_stale_results_csv_from_a_previous_run(tmp_path):
    processed_dir = tmp_path / "processed"
    artifacts_dir = tmp_path / "artifacts"
    processed_dir.mkdir()
    artifacts_dir.mkdir()

    train_df = _make_tiny_split(n_benign=48, n_attack=0, seed=2)
    val_df = _make_tiny_split(n_benign=24, n_attack=24, seed=3)
    train_df.to_parquet(processed_dir / "train.parquet", index=False)
    val_df.to_parquet(processed_dir / "val.parquet", index=False)
    (processed_dir / "feature_columns.json").write_text(json.dumps(MODEL_FEATURES))

    # Simulate leftover output from an earlier (e.g. crashed) sweep run.
    stale_csv = artifacts_dir / "tuning_results.csv"
    stale_csv.write_text(
        "latent_dim,hidden_dims,learning_rate,batch_size,dropout,noise_std,val_auc,recall_at_fpr,val_loss,best_epoch,train_seconds\n" * 6
    )

    search_space = {
        "latent_dim": [2], "hidden_dims": [[4]], "learning_rate": [1e-2],
        "batch_size": [16], "dropout": [0.0],
    }
    tune.run_sweep(
        processed_dir=processed_dir, artifacts_dir=artifacts_dir, search_space=search_space,
        mode="grid", epochs=1, patience=1, seed=0, device=torch.device("cpu"),
    )

    with stale_csv.open() as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1  # the stale 6-row file must not have been appended to
