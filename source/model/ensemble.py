"""Train an ensemble of independently-initialized models from one already-
chosen hyperparameter config, for the reconstruction-error averaging
`inference.compute_ensemble_reconstruction_errors` does.

Run *after* tune.py has already picked a winning config — this reads that
config rather than searching hyperparameters itself, and trains with a full
epoch budget (not tune.py's reduced sweep budget), since ensemble members
are meant to be final/production models, not quick comparisons:

    python -m source.model.ensemble --source-config artifacts/models/expanded-search/model_config.json \\
        --artifacts-dir artifacts/models/expanded-search --n-models 5

Each member differs only in random seed (weight init + train-loader
shuffle order) — same architecture, same optimizer settings. Saves to
artifacts_dir/ensemble/, alongside (not replacing) the single-model
model.pt/model_config.json that train.py/tune.py already wrote:

    artifacts_dir/ensemble/
    ├── model_0.pt ... model_{n-1}.pt   # state_dicts
    └── ensemble_config.json             # shared architecture + per-member training summary

threshold.py and evaluate.py check for this folder and use it automatically
when present (see `load_scoring_models` in this module), falling back to
the single model.pt otherwise — nothing else needs to change to benefit
from an ensemble once one exists.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import torch

from source.common import paths
from source.common.constants import RANDOM_SEED
from source.model.autoencoder import Autoencoder
from source.model.dataset import load_split, make_loader
from source.model.train import get_device, train_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def train_ensemble(
    processed_dir: Path,
    artifacts_dir: Path,
    source_config: dict[str, Any],
    n_models: int = 5,
    seed_base: int = RANDOM_SEED,
    epochs: int = 100,
    patience: int = 10,
    device: torch.device | None = None,
) -> dict[str, Any]:
    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    train_df = load_split(processed_dir / "train.parquet", feature_cols)
    val_df = load_split(processed_dir / "val.parquet", feature_cols)
    device = device or get_device()

    batch_size = source_config["batch_size"]
    train_loader = make_loader(train_df, feature_cols, batch_size, shuffle=True, device=device)
    val_benign_loader = make_loader(val_df, feature_cols, batch_size, shuffle=False, benign_only=True, device=device)

    ensemble_dir = artifacts_dir / "ensemble"
    ensemble_dir.mkdir(parents=True, exist_ok=True)

    members: list[dict[str, Any]] = []
    for i in range(n_models):
        seed = seed_base + i
        torch.manual_seed(seed)
        model = Autoencoder(
            input_dim=source_config["input_dim"],
            latent_dim=source_config["latent_dim"],
            hidden_dims=source_config["hidden_dims"],
            dropout=source_config.get("dropout", 0.0),
        )
        t0 = time.time()
        history = train_model(
            model, train_loader, val_benign_loader, device,
            lr=source_config["lr"], max_epochs=epochs, patience=patience, verbose=False,
        )
        elapsed = time.time() - t0
        torch.save(model.state_dict(), ensemble_dir / f"model_{i}.pt")
        members.append({"seed": seed, "best_epoch": history["best_epoch"], "best_val_loss": history["best_val_loss"], "train_seconds": elapsed})
        log.info("[%d/%d] seed=%d best_val_loss=%.6f best_epoch=%d (%.1fs)", i + 1, n_models, seed, history["best_val_loss"], history["best_epoch"], elapsed)

    ensemble_config = {
        "n_models": n_models,
        "seed_base": seed_base,
        "architecture": {k: source_config[k] for k in ("input_dim", "latent_dim", "hidden_dims", "dropout")},
        "lr": source_config["lr"],
        "batch_size": batch_size,
        "members": members,
    }
    (ensemble_dir / "ensemble_config.json").write_text(json.dumps(ensemble_config, indent=2))
    log.info("Saved %d-model ensemble to %s", n_models, ensemble_dir)
    return ensemble_config


def load_scoring_models(artifacts_dir: Path, device: torch.device) -> list[Autoencoder]:
    """Load whatever this artifacts_dir has for scoring: an ensemble if
    `ensemble/` exists, else the single model.pt/model_config.json.
    Returned list is what `inference.compute_ensemble_reconstruction_errors`
    expects (length 1 degenerates to the single-model case)."""
    ensemble_dir = artifacts_dir / "ensemble"
    ensemble_config_path = ensemble_dir / "ensemble_config.json"
    if ensemble_config_path.exists():
        ensemble_config = json.loads(ensemble_config_path.read_text())
        arch = ensemble_config["architecture"]
        models = []
        for i in range(ensemble_config["n_models"]):
            model = Autoencoder.from_config(arch)
            model.load_state_dict(torch.load(ensemble_dir / f"model_{i}.pt", map_location="cpu"))
            model.to(device)
            models.append(model)
        return models

    model_config = json.loads((artifacts_dir / "model_config.json").read_text())
    model = Autoencoder.from_config(model_config)
    model.load_state_dict(torch.load(artifacts_dir / "model.pt", map_location="cpu"))
    model.to(device)
    return [model]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--artifacts-dir", type=Path, default=paths.DEFAULT_MODEL_DIR)
    parser.add_argument("--source-config", type=Path, default=None, help="model_config.json to replicate; defaults to <artifacts-dir>/model_config.json")
    parser.add_argument("--n-models", type=int, default=5)
    parser.add_argument("--seed-base", type=int, default=RANDOM_SEED)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--patience", type=int, default=10)
    args = parser.parse_args()

    source_config_path = args.source_config or (args.artifacts_dir / "model_config.json")
    source_config = json.loads(source_config_path.read_text())
    train_ensemble(
        processed_dir=args.processed_dir,
        artifacts_dir=args.artifacts_dir,
        source_config=source_config,
        n_models=args.n_models,
        seed_base=args.seed_base,
        epochs=args.epochs,
        patience=args.patience,
    )


if __name__ == "__main__":
    main()
