"""Training loop for the autoencoder (module 3).

    python -m source.model.train --latent-dim 16 --hidden-dims 32 --epochs 100

Early stopping and LR scheduling are both driven by validation reconstruction
error computed on *benign-only* validation rows — attack rows are expected
to reconstruct poorly, so mixing them into the monitored loss would reward
a model that overfits to nothing in particular (see MODEL_DEVELOPMENT.md
rule 4: never pick hyperparameters from training loss / mixed val loss
alone).
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import time
from pathlib import Path
from typing import Any

import torch
from torch import nn, optim
from torch.utils.data import DataLoader

from source.common import paths
from source.common.constants import LABEL_COL, RANDOM_SEED
from source.model.autoencoder import Autoencoder
from source.model.dataset import load_split, make_loader

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def get_device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def train_model(
    model: nn.Module,
    train_loader: DataLoader,
    val_benign_loader: DataLoader,
    device: torch.device,
    lr: float = 1e-3,
    max_epochs: int = 100,
    patience: int = 10,
    verbose: bool = True,
    noise_std: float = 0.0,
) -> dict[str, Any]:
    """Trains in place; returns {"train_loss": [...], "val_loss": [...], "best_epoch": int}.

    `noise_std` > 0 turns this into a *denoising* autoencoder (Vincent et
    al. 2008): Gaussian noise (std=`noise_std`, in the already-standardized
    feature space, so it's directly comparable across features) is added to
    the encoder's input during training, but the loss is still computed
    against the clean, un-noised batch -- the model has to reconstruct what
    the row *actually* was, not the corrupted version it was shown. This is
    a more direct fix than dropout for the "latent_dim >= input_dim lets an
    overcomplete autoencoder approximate the identity function" failure
    mode: dropout regularizes indirectly (randomly disabling units), while
    noise injection makes the trivial identity mapping *itself* a bad
    solution (the input it copies from isn't the target), regardless of
    how much spare bottleneck capacity there is. Validation/inference are
    never noised -- reconstruction error there means exactly what it
    always has: how well the model reconstructs the *actual* observed row.
    """
    model.to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=3)
    loss_fn = nn.MSELoss(reduction="none")

    history: dict[str, list[float]] = {"train_loss": [], "val_loss": []}
    best_val = float("inf")
    best_state = copy.deepcopy(model.state_dict())
    best_epoch = 0
    epochs_no_improve = 0

    for epoch in range(1, max_epochs + 1):
        model.train()
        running_loss, n_seen = 0.0, 0
        for (batch,) in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            model_input = batch + torch.randn_like(batch) * noise_std if noise_std > 0 else batch
            x_hat, _ = model(model_input)
            per_row = loss_fn(x_hat, batch).mean(dim=1)  # reconstruct the *clean* row
            loss = per_row.mean()
            loss.backward()
            optimizer.step()
            running_loss += loss.item() * batch.size(0)
            n_seen += batch.size(0)
        train_loss = running_loss / max(n_seen, 1)

        model.eval()
        val_running, val_n = 0.0, 0
        with torch.no_grad():
            for (batch,) in val_benign_loader:
                batch = batch.to(device)
                x_hat, _ = model(batch)
                per_row = loss_fn(x_hat, batch).mean(dim=1)
                val_running += per_row.sum().item()
                val_n += batch.size(0)
        val_loss = val_running / max(val_n, 1)

        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        scheduler.step(val_loss)

        if verbose:
            log.info("epoch %3d/%d train_loss=%.6f val_loss=%.6f", epoch, max_epochs, train_loss, val_loss)

        if val_loss < best_val - 1e-8:
            best_val = val_loss
            best_state = copy.deepcopy(model.state_dict())
            best_epoch = epoch
            epochs_no_improve = 0
        else:
            epochs_no_improve += 1
            if epochs_no_improve >= patience:
                if verbose:
                    log.info("Early stopping at epoch %d (best epoch %d, val_loss=%.6f)", epoch, best_epoch, best_val)
                break

    model.load_state_dict(best_state)
    history["best_epoch"] = best_epoch
    history["best_val_loss"] = best_val
    return history


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--artifacts-dir", type=Path, default=paths.DEFAULT_MODEL_DIR)
    parser.add_argument("--latent-dim", type=int, default=16)
    parser.add_argument("--hidden-dims", type=int, nargs="*", default=[32])
    parser.add_argument("--dropout", type=float, default=0.0)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument(
        "--noise-std", type=float, default=0.0,
        help="Gaussian noise std added to inputs during training only (denoising autoencoder); 0 disables it.",
    )
    parser.add_argument("--subsample-train", type=int, default=None, help="Cap #benign training rows (RAM-limited runs)")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--cpu", action="store_true", help="Force CPU even if CUDA is available (resource-constrained gateway benchmark)")
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    feature_cols = json.loads((args.processed_dir / "feature_columns.json").read_text())

    train_df = load_split(args.processed_dir / "train.parquet", feature_cols)
    val_df = load_split(args.processed_dir / "val.parquet", feature_cols)
    if args.subsample_train and len(train_df) > args.subsample_train:
        train_df = train_df.sample(n=args.subsample_train, random_state=args.seed).reset_index(drop=True)

    device = torch.device("cpu") if args.cpu else get_device()
    # device= here matters, not just cosmetically: it's what lets
    # TensorBatchLoader keep the whole split resident on the training
    # device instead of transferring per batch (see dataset.py) -- and for
    # --cpu it keeps the resource-constrained-gateway benchmark honest by
    # not silently parking data on a GPU it's supposed to be measuring
    # without.
    train_loader = make_loader(train_df, feature_cols, args.batch_size, shuffle=True, device=device)
    val_benign_loader = make_loader(val_df, feature_cols, args.batch_size, shuffle=False, benign_only=True, device=device)

    log.info("Training on device=%s, train_rows=%d (benign only), input_dim=%d", device, len(train_df), len(feature_cols))

    model = Autoencoder(
        input_dim=len(feature_cols),
        latent_dim=args.latent_dim,
        hidden_dims=args.hidden_dims,
        dropout=args.dropout,
    )

    t0 = time.time()
    history = train_model(
        model, train_loader, val_benign_loader, device,
        lr=args.lr, max_epochs=args.epochs, patience=args.patience,
        noise_std=args.noise_std,
    )
    elapsed = time.time() - t0
    history["train_seconds"] = elapsed
    history["device"] = str(device)
    history["n_train_rows"] = len(train_df)

    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), args.artifacts_dir / "model.pt")

    model_config = model.config()
    model_config.update({"lr": args.lr, "batch_size": args.batch_size, "seed": args.seed, "noise_std": args.noise_std})
    (args.artifacts_dir / "model_config.json").write_text(json.dumps(model_config, indent=2))
    (args.artifacts_dir / "training_history.json").write_text(json.dumps(history, indent=2))

    log.info("Saved model.pt / model_config.json / training_history.json to %s (%.1fs)", args.artifacts_dir, elapsed)


if __name__ == "__main__":
    main()
