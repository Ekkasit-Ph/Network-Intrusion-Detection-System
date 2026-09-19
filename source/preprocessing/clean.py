"""Data cleaning for NF-ToN-IoT-v2 (module 2, step 1-4 of MODEL_DEVELOPMENT.md).

Handles, in order: dtype loading, +-inf replacement, duplicate removal,
protocol-specific NaN fill, categorical encoding, and log1p skew reduction.
Every function returns `(df, report_fragment)` so the caller can accumulate
a full `preprocessing_report.json` without re-scanning the data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from source.common.constants import (
    ATTACK_COL,
    CATEGORICAL_COLS,
    INF_PRONE_COLS,
    LABEL_COL,
    LOG_TRANSFORM_COLS,
    NETFLOW_FEATURES,
    ONE_HOT_CARDINALITY_LIMIT,
    PROTOCOL_SPECIFIC_COLS,
)

# Columns NF-ToN-IoT-v2 ships as floats/ints that are safe to downcast,
# trimming memory well below pandas' default int64/float64 for a 16.9M-row
# file. IPV4 addresses and Attack/PROTOCOL-ish text stay as-is.
_NUMERIC_COLS = [c for c in NETFLOW_FEATURES if c not in ("IPV4_SRC_ADDR", "IPV4_DST_ADDR")]


def _read_dtypes() -> dict[str, str]:
    """Compact dtypes passed straight to pd.read_csv's `dtype=`.

    Specifying these upfront (rather than loading with pandas' default
    float64/int64/object and downcasting afterwards) is what actually
    matters for a 16.9M-row file: the default read alone peaks at well
    over the size of the machine's RAM before any downcasting code gets a
    chance to run. float32 covers every numeric column here (including
    ones the source CSV formats with a trailing ".0", which an int dtype
    would fail to parse); IPV4/Attack go to `category` since they're a
    small set of values repeated millions of times.

    Exception: INF_PRONE_COLS stay float64 at read time. A small fraction
    of rows (~0.002%, correlated with a FLOW_DURATION_MILLISECONDS value
    suspiciously close to 2**32/1000 -- a 32-bit-overflow signature in the
    exporter) hold finite-but-absurd values up to ~1e304 in
    SRC_TO_DST_SECOND_BYTES/DST_TO_SRC_SECOND_BYTES. Casting those straight
    to float32 at parse time silently overflows them to +inf before
    `handle_missing_and_inf` ever gets a chance to cap them -- so they're
    read wide, capped, *then* downcast (see `clean_pipeline`'s ordering).
    """
    dtypes: dict[str, str] = {col: "float32" for col in _NUMERIC_COLS}
    for col in INF_PRONE_COLS:
        dtypes[col] = "float64"
    dtypes["IPV4_SRC_ADDR"] = "category"
    dtypes["IPV4_DST_ADDR"] = "category"
    dtypes[ATTACK_COL] = "category"
    dtypes[LABEL_COL] = "int8"
    return dtypes


def load_raw_csv(path: str | Path, nrows: int | None = None) -> pd.DataFrame:
    """Load the raw NF-ToN-IoT-v2 CSV.

    `nrows` is for dev/smoke-testing on a slice of the 16.9M-row file; leave
    it None for a real run. dtypes are pinned via `dtype=` (see
    `_read_dtypes`) so the parser itself stays memory-efficient — with all
    43+2 columns typed upfront, pandas never needs the "scan first, infer
    consistent type" pass that `low_memory=False` exists for, so we
    deliberately leave `low_memory` at its (chunked, lower-peak-memory)
    default instead of forcing it off.
    """
    usecols = NETFLOW_FEATURES + [LABEL_COL, ATTACK_COL]
    df = pd.read_csv(path, usecols=usecols, nrows=nrows, dtype=_read_dtypes())
    # Reorder to the canonical schema regardless of on-disk column order.
    return df[usecols]


def optimize_dtypes(df: pd.DataFrame, copy: bool = True) -> pd.DataFrame:
    """Downcast any columns still holding a wider dtype than needed.

    In practice this now only touches INF_PRONE_COLS: `_read_dtypes`
    already pins every other numeric column to float32 at CSV-parse time,
    and those four are deliberately read as float64 so
    `handle_missing_and_inf` can inspect their true (uncapped) values
    before this runs (see that function's docstring). Skipping columns
    already at the target dtype -- instead of unconditionally calling
    `pd.to_numeric` on all ~40 numeric columns -- avoids that many pointless
    full-column reallocations on a 16.9M-row frame; each one briefly holds
    old+new simultaneously, and freed pandas/numpy buffers this large are
    not reliably returned to the OS mid-process, so those reallocations
    were inflating *peak* memory for the rest of the run, not just the
    moment they happened.

    `copy=False` mutates the given DataFrame in place instead of
    defensively copying it first — safe (and meaningfully cheaper on the
    full dataset) when the caller exclusively owns `df` and doesn't need
    the pre-call version preserved, e.g. `pipeline.py`'s single linear
    load-clean-split run. Direct/test callers should keep the default.
    """
    if copy:
        df = df.copy()
    for col in _NUMERIC_COLS:
        if col not in df.columns:
            continue
        if df[col].dtype == np.float64:
            df[col] = df[col].astype(np.float32)
        elif df[col].dtype == np.int64:
            df[col] = pd.to_numeric(df[col], downcast="integer")
    if LABEL_COL in df.columns and df[LABEL_COL].dtype != np.int8:
        df[LABEL_COL] = df[LABEL_COL].astype("int8")
    return df


def handle_missing_and_inf(df: pd.DataFrame, copy: bool = True) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Replace +-inf and float32-unsafe extreme values in throughput/rate
    columns, and fill protocol-specific NaNs.

    Throughput columns can be +-inf when FLOW_DURATION_MILLISECONDS == 0
    (division by zero at extraction time). SRC_TO_DST_SECOND_BYTES /
    DST_TO_SRC_SECOND_BYTES additionally carry a small number of
    finite-but-nonsensical values (up to ~1e304 -- see `_read_dtypes`) from
    what looks like a 32-bit overflow artifact in the exporter. Both
    symptoms get the same treatment: cap at the column's 99th percentile
    computed from the *other* (sane) rows, rather than blanket-zeroing, so
    large-but-real throughput isn't clipped the same as a corrupt reading.
    "Extreme" is defined as exceeding float32's representable range, since
    no real byte/rate counter for a single flow legitimately gets close to
    that, and these columns get downcast to float32 right after this runs.

    `copy=False` mutates in place — see `optimize_dtypes` for why/when.
    """
    if copy:
        df = df.copy()
    report: dict[str, Any] = {"extreme_values_capped": {}, "nan_filled": {}}
    float32_max = float(np.finfo(np.float32).max)

    for col in INF_PRONE_COLS:
        is_bad = ~np.isfinite(df[col]) | (df[col].abs() > float32_max)
        n_bad = int(is_bad.sum())
        if n_bad:
            finite_vals = df.loc[~is_bad, col]
            cap = float(finite_vals.quantile(0.99)) if len(finite_vals) else 0.0
            df.loc[is_bad, col] = cap
        report["extreme_values_capped"][col] = n_bad

    # Any remaining inf elsewhere (defensive) -> NaN, so it's caught below.
    # Deliberately one column at a time rather than the equivalent
    # `df[_NUMERIC_COLS] = df[_NUMERIC_COLS].replace(...)`: measured on a
    # 2M-row slice, that whole-frame ~41-column form added +562MB of peak
    # RSS (subset-extract + .replace() each materialize their own
    # ~41-column copy); looping per-column touches one array at a time and
    # added ~0. None of these are expected to actually hold inf once
    # INF_PRONE_COLS above are capped -- this is a cheap safety net, not
    # the primary handling path.
    for col in _NUMERIC_COLS:
        col_is_inf = np.isinf(df[col])
        if col_is_inf.any():
            df.loc[col_is_inf, col] = np.nan

    for col in PROTOCOL_SPECIFIC_COLS:
        n_nan = int(df[col].isna().sum())
        report["nan_filled"][col] = n_nan
        if n_nan:
            df[col] = df[col].fillna(0)

    # Same reasoning: per-column .isna().sum() instead of a ~41-column
    # subset. PROTOCOL_SPECIFIC_COLS are already clean from the loop above,
    # so they simply report 0 here rather than being special-cased out.
    nan_filled_other: dict[str, int] = {}
    for col in _NUMERIC_COLS:
        n_nan = int(df[col].isna().sum())
        if n_nan:
            # Any other stray NaNs (unexpected) are filled with 0 and
            # reported rather than silently dropped, so it surfaces here.
            nan_filled_other[col] = n_nan
            df[col] = df[col].fillna(0)
    if nan_filled_other:
        report["nan_filled_other"] = nan_filled_other

    return df, report


def drop_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Remove exact-duplicate rows via row hashing rather than
    `DataFrame.drop_duplicates()`.

    Measured on a 2M-row slice: pandas' own `drop_duplicates()` peaks at
    +834MB over the frame's actual size (~4.7x), even when it removes zero
    rows -- comparing all ~45 columns row-by-row internally allocates
    roughly frame-sized scratch space. Hashing every row down to a single
    uint64 first (`pd.util.hash_pandas_object`, ~8 bytes/row -- 135MB for
    the full 16.9M-row file) and deduplicating *that* costs +47MB instead,
    an ~18x reduction, which is what makes running this against the full
    file rather than a subsample feasible at all on this machine's RAM.

    Trade-off: a 64-bit hash collision could in principle make two
    genuinely different rows look identical. Across 16.9M rows the
    birthday-bound probability of *any* collision is ~1 in 130,000, and
    even then the cost is misclassifying one row out of 16.9M as a
    duplicate -- negligible next to the memory cost of ruling it out via a
    full row-equality re-check, so this deliberately doesn't do one.
    """
    n_before = len(df)
    row_hashes = pd.util.hash_pandas_object(df, index=False)
    is_dup = row_hashes.duplicated()
    del row_hashes
    df = df.loc[~is_dup.values].reset_index(drop=True)
    n_after = len(df)
    report = {"rows_before": n_before, "rows_after": n_after, "duplicates_removed": n_before - n_after}
    return df, report


def encode_categoricals(
    df: pd.DataFrame,
    fit: bool,
    encoders: dict[str, Any] | None = None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """One-hot encode low-cardinality categoricals, else frequency-encode.

    `fit=True` (train split) decides the strategy and vocabulary; `fit=False`
    (val/test/inference) must be given the `encoders` dict produced by the
    fit call, and reuses it verbatim so val/test never leak into encoding.
    """
    df = df.copy()
    encoders = {} if fit else dict(encoders or {})

    for col in CATEGORICAL_COLS:
        if fit:
            n_unique = df[col].nunique()
            if n_unique <= ONE_HOT_CARDINALITY_LIMIT:
                categories = sorted(df[col].dropna().unique().tolist())
                encoders[col] = {"strategy": "onehot", "categories": categories}
            else:
                freq = df[col].value_counts(normalize=True).to_dict()
                encoders[col] = {"strategy": "frequency", "freq_map": freq}

        spec = encoders[col]
        if spec["strategy"] == "onehot":
            for cat in spec["categories"]:
                df[f"{col}_{cat}"] = (df[col] == cat).astype("int8")
            # Unseen category at inference time -> all-zero row, which is
            # the standard one-hot "unknown" representation.
            df = df.drop(columns=[col])
        else:  # frequency
            df[col] = df[col].map(_numeric_keys(spec["freq_map"])).fillna(0.0).astype("float32")

    return df, encoders


def _numeric_keys(freq_map: dict[Any, float]) -> dict[float, float]:
    """JSON has no numeric dict keys, so a freq_map that has been through
    `categorical_encoders.json` comes back with keys like `"7.0"` while the
    column holds `7.0`. `.map()` then matches nothing, `.fillna(0.0)` turns
    the entire column into a constant, and nothing raises -- the feature is
    simply gone, replaced by a value that is itself legitimate.

    This only bites when the encoders are *reloaded* (any inference or
    re-run), never during the fit that created them in memory, which is why
    it survived until online.py was compared against this path on real
    data. Coercing here rather than at every call site keeps the two paths
    from disagreeing again.
    """
    coerced: dict[float, float] = {}
    for key, value in freq_map.items():
        try:
            coerced[float(key)] = float(value)
        except (TypeError, ValueError):
            # A genuinely non-numeric category: keep it as-is so string
            # categoricals still work if CATEGORICAL_COLS ever grows one.
            coerced[key] = float(value)
    return coerced


def log_transform(df: pd.DataFrame, cols: list[str] | None = None) -> pd.DataFrame:
    """np.log1p on heavily right-skewed quantity columns (in place copy).

    The `astype(np.float64)` is not cosmetic. `optimize_dtypes` picks the
    narrowest integer type each column's *observed range* allows, and numpy
    derives log1p's output type from that input width: int32 gives float64,
    int16 gives float32, and int8 gives **float16** -- three decimal digits.
    So the precision of a model feature would depend on how wide the values
    happened to be in whichever slice was processed. On the full 16.9M rows
    nothing lands in int8, but a `--nrows` development run does: on a 30k
    slice MIN_IP_PKT_LEN fits in int8, and log1p(78) comes back as 4.37
    instead of 4.3694478 -- a 1e-3 error in a feature, silently, in a run
    whose whole purpose is to stand in for the real one.

    Fixing it here rather than in `optimize_dtypes` keeps the memory saving
    (the narrow integer columns are what make the 16.9M-row load fit) while
    making this stage's output depend only on the values, not their storage.
    """
    cols = cols or LOG_TRANSFORM_COLS
    df = df.copy()
    for col in cols:
        # Values here are non-negative counts/bytes/durations by
        # construction; clip defensively in case of upstream artifacts.
        df[col] = np.log1p(df[col].clip(lower=0).astype(np.float64))
    return df


def clean_pipeline(df: pd.DataFrame, copy: bool = True) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Run steps 1-2 of MODEL_DEVELOPMENT.md (missing/inf handling + dedup).

    Categorical encoding and log-transform are applied later, per-split, by
    `pipeline.py` (encoding must fit on train only; log-transform is
    split-agnostic but kept separate so it's easy to toggle per experiment).

    Order matters here: `handle_missing_and_inf` must run *before*
    `optimize_dtypes`. INF_PRONE_COLS are read as float64 (see
    `_read_dtypes`) specifically so the extreme-value capping in
    `handle_missing_and_inf` sees their true finite values instead of
    already-overflowed +inf; downcasting to float32 first would silently
    reintroduce the exact corruption it's meant to fix.

    `copy=False` propagates to every step below and mutates `df` in place
    (see `optimize_dtypes`'s docstring for when that's safe). `drop_duplicates`
    is exempt: pandas has no way to remove rows without allocating a new
    result, `copy` or not, so there's nothing to pass through to it.
    """
    report: dict[str, Any] = {}
    df, dup_report = drop_duplicates(df)
    report["duplicates"] = dup_report
    df, missing_report = handle_missing_and_inf(df, copy=copy)
    report["missing_and_inf"] = missing_report
    df = optimize_dtypes(df, copy=copy)
    report["class_distribution"] = df[ATTACK_COL].value_counts().to_dict()
    return df, report
