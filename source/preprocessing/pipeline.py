"""End-to-end preprocessing entry point (module 2).

    python -m source.preprocessing.pipeline --input Dataset/data/NF-ToN-IoT-v2.csv
    python -m source.preprocessing.pipeline --nrows 200000   # quick dev run

Produces, under data/processed/ and artifacts/:
    train.parquet, val.parquet, test.parquet
    preprocessing_report.json
    feature_columns.json           (final model input columns, in order)
    artifacts/scaler.pkl
    artifacts/categorical_encoders.json
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from source.common import paths
from source.common.constants import (
    ATTACK_COL,
    IDENTIFIER_COLS,
    LABEL_COL,
    RANDOM_SEED,
)
from source.preprocessing.clean import clean_pipeline, encode_categoricals, load_raw_csv, log_transform
from source.preprocessing.engineer_features import DEFAULT_WINDOW, add_behavioral_features
from source.preprocessing.scale import fit_scaler, save_scaler, transform
from source.preprocessing.split import split_data

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def run(
    input_csv: Path,
    output_dir: Path,
    artifacts_dir: Path,
    nrows: int | None = None,
    scaler_kind: str = "standard",
    seed: int = RANDOM_SEED,
    behavioral_window: int | None = DEFAULT_WINDOW,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"input_csv": str(input_csv), "nrows_requested": nrows, "seed": seed}

    log.info("Loading raw CSV%s...", f" (first {nrows} rows)" if nrows else "")
    df = load_raw_csv(input_csv, nrows=nrows)
    report["rows_loaded"] = len(df)

    log.info("Cleaning (dedup, inf/missing handling)...")
    # copy=False: this function owns `df` outright from here on (nothing
    # else references the object load_raw_csv returned), so the cleaning
    # steps can mutate it in place instead of defensively copying at each
    # stage. On the full 16.9M-row file that's the difference between a
    # handful of ~3GB reallocations compounding on top of each other and
    # just doing the work -- see clean_pipeline/optimize_dtypes docstrings.
    df, clean_report = clean_pipeline(df, copy=False)
    report["cleaning"] = clean_report

    if behavioral_window:
        log.info("Engineering causal behavioral features (window=%d)...", behavioral_window)
        # Must run on the still-deduped-but-unshuffled frame, using
        # IDENTIFIER_COLS as grouping/lookup keys, before either of those
        # columns disappears -- see engineer_features.py's module
        # docstring for why order matters here.
        df, behavioral_report = add_behavioral_features(df, window=behavioral_window)
        report["behavioral_features"] = behavioral_report

    # Identifier columns are dropped for modeling purposes right after
    # dedup — they must never reach the model (see PROJECT.md constraints).
    # A live-serving backend (module 5/6) keeps them out-of-band instead,
    # joining detection results back to source/dst IP at the DB layer.
    # inplace=True for the same reason as copy=False above: avoid another
    # full-frame reallocation we don't need.
    df.drop(columns=IDENTIFIER_COLS, inplace=True)

    log.info("Splitting train/val/test...")
    train_df, val_df, test_df, split_report = split_data(df, seed=seed)
    report["split"] = split_report
    # The combined cleaned dataset is now fully partitioned into
    # train/val/test; nothing downstream needs it, so drop the reference
    # before the next (also memory-heavy) stage starts allocating.
    del df
    gc.collect()

    log.info("Encoding categoricals (fit on train only)...")
    train_df, encoders = encode_categoricals(train_df, fit=True)
    val_df, _ = encode_categoricals(val_df, fit=False, encoders=encoders)
    test_df, _ = encode_categoricals(test_df, fit=False, encoders=encoders)

    log.info("Log-transforming skewed columns...")
    train_df = log_transform(train_df)
    val_df = log_transform(val_df)
    test_df = log_transform(test_df)

    feature_cols = [c for c in train_df.columns if c not in (LABEL_COL, ATTACK_COL)]
    # val/test must have exactly the same feature columns, same order.
    val_df = val_df[feature_cols + [LABEL_COL, ATTACK_COL]]
    test_df = test_df[feature_cols + [LABEL_COL, ATTACK_COL]]
    train_df = train_df[feature_cols + [LABEL_COL, ATTACK_COL]]

    log.info("Fitting %s scaler on train features only...", scaler_kind)
    scaler = fit_scaler(train_df, feature_cols, kind=scaler_kind)
    train_df = transform(train_df, scaler, feature_cols)
    val_df = transform(val_df, scaler, feature_cols)
    test_df = transform(test_df, scaler, feature_cols)

    log.info("Writing parquet outputs...")
    train_df.to_parquet(output_dir / "train.parquet", index=False)
    val_df.to_parquet(output_dir / "val.parquet", index=False)
    test_df.to_parquet(output_dir / "test.parquet", index=False)

    save_scaler(scaler, artifacts_dir / "scaler.pkl")
    (artifacts_dir / "categorical_encoders.json").write_text(json.dumps(encoders, indent=2))
    (output_dir / "feature_columns.json").write_text(json.dumps(feature_cols, indent=2))

    report["feature_columns"] = feature_cols
    report["n_features"] = len(feature_cols)
    (output_dir / "preprocessing_report.json").write_text(json.dumps(report, indent=2, default=str))

    log.info(
        "Done. train=%d val=%d test=%d, %d model features.",
        len(train_df), len(val_df), len(test_df), len(feature_cols),
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=None, help="Path to raw NF-ToN-IoT-v2 CSV")
    parser.add_argument("--output-dir", type=Path, default=paths.PROCESSED_DATA_DIR)
    parser.add_argument("--artifacts-dir", type=Path, default=paths.PREPROCESSING_ARTIFACTS_DIR)
    parser.add_argument("--nrows", type=int, default=None, help="Load only the first N rows (dev/smoke-test)")
    parser.add_argument("--scaler", choices=["standard", "robust"], default="standard")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument(
        "--behavioral-window", type=int, default=DEFAULT_WINDOW,
        help="Trailing-window size (in flows from the same source) for the causal "
             "fan-out behavioral features; 0 disables them entirely.",
    )
    args = parser.parse_args()

    input_csv = args.input or paths.resolve_raw_csv()
    run(
        input_csv=input_csv,
        output_dir=args.output_dir,
        artifacts_dir=args.artifacts_dir,
        nrows=args.nrows,
        scaler_kind=args.scaler,
        seed=args.seed,
        behavioral_window=args.behavioral_window or None,
    )


if __name__ == "__main__":
    main()
