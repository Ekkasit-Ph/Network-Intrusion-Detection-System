"""Hyperparameter sweep (module 3, MODEL_DEVELOPMENT.md section 3).

Grid (default) or random search over configuration/search_space.yaml.

Each config is scored two ways: validation ROC-AUC (reconstruction error
vs. true Label on the *full* val set, benign+attack — never reconstruction
loss alone, since low loss can just mean the latent size is big enough to
memorize anomalies too, see MODEL_DEVELOPMENT.md rule 4) AND recall at
FPR<=`--max-fpr` (default 0.05, matching threshold.py's default and this
project's operating constraint). `--selection-metric` picks which one
`run_sweep` actually optimizes for; both are always computed and logged
per trial either way.

Why this distinction matters, empirically (not just in theory): a
same-architecture denoising-autoencoder run scored val_auc=0.9224 -- *lower*
than a config this sweep's AUC-based selection had picked (val_auc=0.9314)
-- yet had *higher* recall at FPR<=0.05 (59.5% vs 57.1%). AUC integrates
ranking quality across the *entire* ROC curve, including FPR regions this
project will never operate in; two configs can disagree on which is
"better" depending on which one you ask. Selecting by AUC is a reasonable
default when the eventual operating threshold isn't known yet (which is
why it was the original choice here), but once there's a hard operating
constraint (FPR<=5%, non-negotiable per this project's requirements),
optimizing directly for what will actually be deployed is strictly more
aligned than optimizing for a proxy that provably disagrees with it.

    python -m source.model.tune --epochs 30 --patience 5
    python -m source.model.tune --mode random --n-trials 15
    python -m source.model.tune --selection-metric recall_at_fpr --max-fpr 0.05

Writes artifacts/tuning_results.csv incrementally, one row per config as it
finishes (so a crash partway through doesn't lose completed trials), then
saves model.pt / model_config.json / training_history.json for the overall
best config, exactly like train.py would for a single run.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import logging
import random
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
import yaml
from sklearn.metrics import roc_auc_score, roc_curve

from source.common import paths
from source.common.constants import LABEL_COL, RANDOM_SEED
from source.model.autoencoder import Autoencoder
from source.model.dataset import load_split, make_loader
from source.model.inference import compute_reconstruction_errors
from source.model.train import get_device, train_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def recall_at_max_fpr(labels: np.ndarray, errors: np.ndarray, max_fpr: float) -> float:
    """Max true-positive rate achievable among ROC operating points with
    FPR<=`max_fpr` -- i.e. the recall threshold.py would actually end up
    selecting for this exact error array, computed directly via
    `roc_curve` rather than threshold.py's percentile-candidate search
    (cheaper: no candidate generation, and exact rather than
    percentile-grid-limited -- appropriate here since this runs once per
    sweep trial, dozens of times, and only needs the number, not the full
    threshold-selection metadata threshold.py's `select_threshold` returns
    for the one model that actually gets deployed)."""
    fpr, tpr, _ = roc_curve(labels, errors)
    eligible = tpr[fpr <= max_fpr]
    return float(eligible.max()) if len(eligible) else 0.0


def load_search_space(path: Path) -> dict[str, list[Any]]:
    return yaml.safe_load(path.read_text())


def iter_grid(space: dict[str, list[Any]]):
    keys = list(space.keys())
    for combo in itertools.product(*(space[k] for k in keys)):
        yield dict(zip(keys, combo))


def iter_random(space: dict[str, list[Any]], n_trials: int, seed: int):
    rng = random.Random(seed)
    keys = list(space.keys())
    for _ in range(n_trials):
        yield {k: rng.choice(space[k]) for k in keys}


def _train_and_score(
    cfg: dict[str, Any],
    feature_cols: list[str],
    train_loader,
    val_benign_loader,
    val_full_loader,
    val_labels: np.ndarray,
    device: torch.device,
    epochs: int,
    patience: int,
    max_fpr: float,
    seed: int,
) -> tuple[dict[str, Any], dict[str, torch.Tensor], dict[str, Any]]:
    """One trial's worth of work, shared by both `run_sweep` (grid/random)
    and `run_optuna_sweep` -- train one config, score it both ways
    (val_auc and recall_at_fpr), return a CSV-row dict plus the model
    state (already moved to CPU) and training history so the caller can
    decide whether this trial becomes the new best."""
    torch.manual_seed(seed)
    train_loader.batch_size = cfg["batch_size"]
    val_benign_loader.batch_size = cfg["batch_size"]
    val_full_loader.batch_size = cfg["batch_size"]
    noise_std = cfg.get("noise_std", 0.0)

    model = Autoencoder(
        input_dim=len(feature_cols),
        latent_dim=cfg["latent_dim"],
        hidden_dims=cfg["hidden_dims"],
        dropout=cfg.get("dropout", 0.0),
    )
    t0 = time.time()
    history = train_model(
        model, train_loader, val_benign_loader, device,
        lr=cfg["learning_rate"], max_epochs=epochs, patience=patience, verbose=False,
        noise_std=noise_std,
    )
    elapsed = time.time() - t0

    val_errors = compute_reconstruction_errors(model, val_full_loader, device)
    val_auc = roc_auc_score(val_labels, val_errors)
    recall_fpr = recall_at_max_fpr(val_labels, val_errors, max_fpr)

    row = {
        "latent_dim": cfg["latent_dim"],
        "hidden_dims": json.dumps(cfg["hidden_dims"]),
        "learning_rate": cfg["learning_rate"],
        "batch_size": cfg["batch_size"],
        "dropout": cfg.get("dropout", 0.0),
        "noise_std": noise_std,
        "val_auc": val_auc,
        "recall_at_fpr": recall_fpr,
        "val_loss": history["best_val_loss"],
        "best_epoch": history["best_epoch"],
        "train_seconds": elapsed,
    }
    model_state = {k: v.cpu() for k, v in model.state_dict().items()}
    del model
    torch.cuda.empty_cache()
    return row, model_state, history


CSV_FIELDNAMES = [
    "latent_dim", "hidden_dims", "learning_rate", "batch_size", "dropout",
    "noise_std", "val_auc", "recall_at_fpr", "val_loss", "best_epoch", "train_seconds",
]


def _save_best(artifacts_dir: Path, feature_cols: list[str], best: dict[str, Any], selection_metric: str, max_fpr: float, seed: int) -> None:
    log.info(
        "Best config (selected by %s): %s (val_auc=%.4f, recall@fpr<=%.2f=%.4f)",
        selection_metric, best["config"], best["val_auc"], max_fpr, best["recall_at_fpr"],
    )
    torch.save(best["model_state"], artifacts_dir / "model.pt")
    model_config = {
        "input_dim": len(feature_cols),
        "latent_dim": best["config"]["latent_dim"],
        "hidden_dims": best["config"]["hidden_dims"],
        "dropout": best["config"].get("dropout", 0.0),
        "lr": best["config"]["learning_rate"],
        "batch_size": best["config"]["batch_size"],
        "noise_std": best["config"].get("noise_std", 0.0),
        "seed": seed,
        "selected_by": selection_metric,
        "max_fpr": max_fpr,
        "val_auc": best["val_auc"],
        "recall_at_fpr": best["recall_at_fpr"],
    }
    (artifacts_dir / "model_config.json").write_text(json.dumps(model_config, indent=2))
    (artifacts_dir / "training_history.json").write_text(json.dumps(best["history"], indent=2))


def run_sweep(
    processed_dir: Path,
    artifacts_dir: Path,
    search_space: dict[str, list[Any]],
    mode: str = "grid",
    n_trials: int = 20,
    epochs: int = 30,
    patience: int = 5,
    seed: int = RANDOM_SEED,
    device: torch.device | None = None,
    selection_metric: str = "val_auc",
    max_fpr: float = 0.05,
) -> list[dict[str, Any]]:
    """Grid or random search -- every config is chosen without looking at
    any previous trial's result. See `run_optuna_sweep` for an
    adaptive/Bayesian alternative that does use that information."""
    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    train_df = load_split(processed_dir / "train.parquet", feature_cols)
    val_df = load_split(processed_dir / "val.parquet", feature_cols)
    val_labels = val_df[LABEL_COL].to_numpy()
    device = device or get_device()

    configs = list(iter_grid(search_space)) if mode == "grid" else list(iter_random(search_space, n_trials, seed))
    log.info("Running %d configs on device=%s", len(configs), device)

    # Build the GPU-resident loaders ONCE, not per-trial. train_df/val_df
    # are the same across every config in the sweep -- only batch_size
    # varies -- so recreating them per trial just re-uploads the same
    # ~1.8GB of tensors 20 times over, and (worse, on a 4GB card) the
    # previous trial's tensors aren't freed until Python's refcounting
    # catches up *after* the new ones are already allocated, briefly
    # doubling GPU memory at exactly the moment it's tightest. This OOM'd
    # in practice on trial 2 of a real sweep. TensorBatchLoader.batch_size
    # is just reassigned per trial instead -- no reallocation at all.
    batch_size_placeholder = search_space["batch_size"][0]
    train_loader = make_loader(train_df, feature_cols, batch_size_placeholder, shuffle=True, device=device)
    val_benign_loader = make_loader(val_df, feature_cols, batch_size_placeholder, shuffle=False, benign_only=True, device=device)
    val_full_loader = make_loader(val_df, feature_cols, batch_size_placeholder, shuffle=False, device=device)

    assert selection_metric in ("val_auc", "recall_at_fpr"), selection_metric

    results: list[dict[str, Any]] = []
    best = {"score": -1.0, "model_state": None, "config": None, "history": None}
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    results_path = artifacts_dir / "tuning_results.csv"
    results_path.unlink(missing_ok=True)  # start clean -- a stale file from a previous (e.g. crashed) run must not get appended to

    for i, cfg in enumerate(configs, start=1):
        row, model_state, history = _train_and_score(
            cfg, feature_cols, train_loader, val_benign_loader, val_full_loader,
            val_labels, device, epochs, patience, max_fpr, seed,
        )
        results.append(row)
        log.info(
            "[%d/%d] %s -> val_auc=%.4f recall@fpr<=%.2f=%.4f val_loss=%.6f (%.1fs)",
            i, len(configs), cfg, row["val_auc"], max_fpr, row["recall_at_fpr"], row["val_loss"], row["train_seconds"],
        )

        # Append immediately rather than writing the whole file once at the
        # end: a crash (or another OOM) partway through a long sweep should
        # not throw away every trial that already finished.
        write_header = not results_path.exists()
        with results_path.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            if write_header:
                writer.writeheader()
            writer.writerow(row)

        score = row["val_auc"] if selection_metric == "val_auc" else row["recall_at_fpr"]
        if score > best["score"]:
            best.update(score=score, val_auc=row["val_auc"], recall_at_fpr=row["recall_at_fpr"], model_state=model_state, config=cfg, history=history)

    _save_best(artifacts_dir, feature_cols, best, selection_metric, max_fpr, seed)
    return results


def run_optuna_sweep(
    processed_dir: Path,
    artifacts_dir: Path,
    search_space: dict[str, list[Any]],
    n_trials: int = 20,
    epochs: int = 30,
    patience: int = 5,
    seed: int = RANDOM_SEED,
    device: torch.device | None = None,
    selection_metric: str = "recall_at_fpr",
    max_fpr: float = 0.05,
) -> list[dict[str, Any]]:
    """Adaptive (Bayesian/TPE) search over the same discrete search_space
    grid/random would use, via Optuna's default sampler
    (TPESampler -- Tree-structured Parzen Estimator). Unlike `run_sweep`,
    each trial's hyperparameters are chosen using what every *previous*
    trial in this run scored, biasing later trials toward the regions
    that have looked promising so far (while still sometimes exploring
    elsewhere) -- for the same trial budget, this generally reaches a
    better config than blind grid/random search (Bergstra & Bengio 2012
    motivates random over grid; Bergstra et al. 2011 introduces TPE as a
    further improvement over random by using trial history).

    Categorical (not continuous) suggestions are used for every
    hyperparameter -- `trial.suggest_categorical(name, search_space[name])`
    -- deliberately keeping this constrained to the exact same discrete
    values grid/random search would draw from, so results stay comparable
    across `--mode` choices rather than introducing a wider continuous
    range that was never validated as sensible."""
    import optuna

    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    train_df = load_split(processed_dir / "train.parquet", feature_cols)
    val_df = load_split(processed_dir / "val.parquet", feature_cols)
    val_labels = val_df[LABEL_COL].to_numpy()
    device = device or get_device()

    batch_size_placeholder = search_space["batch_size"][0]
    train_loader = make_loader(train_df, feature_cols, batch_size_placeholder, shuffle=True, device=device)
    val_benign_loader = make_loader(val_df, feature_cols, batch_size_placeholder, shuffle=False, benign_only=True, device=device)
    val_full_loader = make_loader(val_df, feature_cols, batch_size_placeholder, shuffle=False, device=device)

    assert selection_metric in ("val_auc", "recall_at_fpr"), selection_metric
    log.info("Running %d Optuna (TPE) trials on device=%s, selecting by %s", n_trials, device, selection_metric)

    results: list[dict[str, Any]] = []
    best = {"score": -1.0, "model_state": None, "config": None, "history": None}
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    results_path = artifacts_dir / "tuning_results.csv"
    results_path.unlink(missing_ok=True)

    def objective(trial: "optuna.Trial") -> float:
        cfg = {
            "latent_dim": trial.suggest_categorical("latent_dim", search_space["latent_dim"]),
            # optuna needs hashable choices -- hidden_dims (a list) is
            # suggested as its JSON string and decoded back below.
            "hidden_dims": json.loads(trial.suggest_categorical(
                "hidden_dims", [json.dumps(h) for h in search_space["hidden_dims"]]
            )),
            # Same reasoning as noise_std below: learning_rate is continuous,
            # not architectural, so it gets suggest_float too -- on a log
            # scale, since its effect is roughly multiplicative (0.001 vs
            # 0.002 matters about as much as 0.02 vs 0.04, not as little as
            # the equal-sized-on-a-linear-scale 0.021 vs 0.022 would
            # suggest). Bounds come from the configured list's min/max, same
            # convention as noise_std.
            "learning_rate": trial.suggest_float(
                "learning_rate", min(search_space["learning_rate"]), max(search_space["learning_rate"]), log=True
            ),
            "batch_size": trial.suggest_categorical("batch_size", search_space["batch_size"]),
            "dropout": trial.suggest_categorical("dropout", search_space.get("dropout", [0.0])),
            # noise_std, unlike the architecture choices above, is a
            # genuinely continuous quantity -- suggest_categorical could
            # only ever return exactly the handful of values listed in the
            # YAML, no matter how many trials run (confirmed empirically:
            # 25 trials over [0.0,0.05,0.1,0.15,0.2,0.3] never touched the
            # 0.2-0.3 gap and the observed mean-recall curve peaks right at
            # the edge of that gap). suggest_float over [min, max] of the
            # configured list lets TPE actually explore that continuum.
            "noise_std": trial.suggest_float(
                "noise_std", min(search_space.get("noise_std", [0.0])), max(search_space.get("noise_std", [0.0]))
            ),
        }

        row, model_state, history = _train_and_score(
            cfg, feature_cols, train_loader, val_benign_loader, val_full_loader,
            val_labels, device, epochs, patience, max_fpr, seed,
        )
        results.append(row)
        log.info(
            "[%d/%d] %s -> val_auc=%.4f recall@fpr<=%.2f=%.4f val_loss=%.6f (%.1fs)",
            trial.number + 1, n_trials, cfg, row["val_auc"], max_fpr, row["recall_at_fpr"], row["val_loss"], row["train_seconds"],
        )

        write_header = not results_path.exists()
        with results_path.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            if write_header:
                writer.writeheader()
            writer.writerow(row)

        score = row["val_auc"] if selection_metric == "val_auc" else row["recall_at_fpr"]
        if score > best["score"]:
            best.update(score=score, val_auc=row["val_auc"], recall_at_fpr=row["recall_at_fpr"], model_state=model_state, config=cfg, history=history)
        return score

    optuna.logging.set_verbosity(optuna.logging.WARNING)  # tune.py's own per-trial log line above is enough
    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=seed))
    study.optimize(objective, n_trials=n_trials)

    _save_best(artifacts_dir, feature_cols, best, selection_metric, max_fpr, seed)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--artifacts-dir", type=Path, default=paths.DEFAULT_MODEL_DIR)
    parser.add_argument("--search-space", type=Path, default=paths.SEARCH_SPACE_YAML)
    parser.add_argument("--mode", choices=["grid", "random", "optuna"], default="grid")
    parser.add_argument("--n-trials", type=int, default=20, help="Used by --mode random/optuna")
    parser.add_argument("--epochs", type=int, default=30, help="Reduced epoch budget per config during sweep")
    parser.add_argument("--patience", type=int, default=5)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument(
        "--selection-metric", choices=["val_auc", "recall_at_fpr"], default="val_auc",
        help="What to pick the best config by. 'recall_at_fpr' directly optimizes the deployed "
             "operating point (recall at FPR<=--max-fpr) instead of using full-curve AUC as a proxy "
             "for it -- the two can disagree (see module docstring); use 'recall_at_fpr' once there's "
             "a hard FPR ceiling to design for.",
    )
    parser.add_argument("--max-fpr", type=float, default=0.05, help="Only used by --selection-metric recall_at_fpr")
    args = parser.parse_args()

    space = load_search_space(args.search_space)
    if args.mode == "optuna":
        run_optuna_sweep(
            processed_dir=args.processed_dir,
            artifacts_dir=args.artifacts_dir,
            search_space=space,
            n_trials=args.n_trials,
            epochs=args.epochs,
            patience=args.patience,
            seed=args.seed,
            selection_metric=args.selection_metric,
            max_fpr=args.max_fpr,
        )
    else:
        run_sweep(
            processed_dir=args.processed_dir,
            artifacts_dir=args.artifacts_dir,
            search_space=space,
            mode=args.mode,
            n_trials=args.n_trials,
            epochs=args.epochs,
            patience=args.patience,
            seed=args.seed,
            selection_metric=args.selection_metric,
            max_fpr=args.max_fpr,
        )


if __name__ == "__main__":
    main()
