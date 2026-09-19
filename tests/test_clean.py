import numpy as np
import pandas as pd
import pytest

from source.common.constants import ATTACK_COL, LABEL_COL
from source.preprocessing.clean import clean_pipeline, encode_categoricals, log_transform


def test_clean_pipeline_removes_duplicates_and_inf(raw_df):
    n_before = len(raw_df)
    cleaned, report = clean_pipeline(raw_df)

    assert len(cleaned) < n_before  # the two duplicated rows were dropped
    assert report["duplicates"]["duplicates_removed"] == 2
    assert not np.isinf(cleaned["SRC_TO_DST_AVG_THROUGHPUT"]).any()
    assert not np.isinf(cleaned["DST_TO_SRC_AVG_THROUGHPUT"]).any()
    assert cleaned["DNS_QUERY_ID"].isna().sum() == 0


def test_encode_categoricals_reused_on_new_split(raw_df):
    cleaned, _ = clean_pipeline(raw_df)
    train = cleaned.iloc[:80]
    val = cleaned.iloc[80:]

    train_enc, encoders = encode_categoricals(train, fit=True)
    val_enc, _ = encode_categoricals(val, fit=False, encoders=encoders)

    assert "PROTOCOL" not in train_enc.columns  # replaced by one-hot columns
    # val must produce exactly the same encoded columns as train, in the
    # same shape, even if it doesn't contain every category.
    onehot_cols = [c for c in train_enc.columns if c.startswith("PROTOCOL_") or c.startswith("L7_PROTO_")]
    for c in onehot_cols:
        assert c in val_enc.columns


def test_log_transform_is_nonnegative_and_monotonic(raw_df):
    cleaned, _ = clean_pipeline(raw_df)
    transformed = log_transform(cleaned, cols=["IN_BYTES"])
    assert (transformed["IN_BYTES"] >= 0).all()
    # log1p is monotonic: larger raw value -> larger transformed value.
    # Use rank (Spearman) correlation, not Pearson -- log1p is nonlinear,
    # so a linear correlation coefficient understates a perfectly
    # monotonic relationship on wide-range data.
    assert transformed["IN_BYTES"].corr(cleaned["IN_BYTES"], method="spearman") == 1.0


# --------------------------------------------------------------------------
# Two bugs found by comparing the offline path against online.py on real
# data. Both were silent: no exception, no warning, and a feature value
# that is itself perfectly legitimate.
# --------------------------------------------------------------------------

def test_frequency_encoding_survives_a_json_round_trip():
    """JSON has no numeric dict keys, so a reloaded freq_map has keys like
    "7.0" while the column holds 7.0. `.map()` then matches nothing and
    `.fillna(0.0)` turns the whole column into a constant -- the feature
    silently disappears, replaced by a value the model has seen plenty of.

    This never bites during the fit that creates the encoders in memory,
    only when they are reloaded, which is every inference path."""
    import json as _json

    from source.preprocessing.clean import encode_categoricals

    df = pd.DataFrame({
        "PROTOCOL": [6.0] * 30,
        "L7_PROTO": [float(i % 25) for i in range(30)],  # > ONE_HOT_CARDINALITY_LIMIT
    })
    _, encoders = encode_categoricals(df.copy(), fit=True)
    assert encoders["L7_PROTO"]["strategy"] == "frequency", "fixture must exercise frequency encoding"

    reloaded = _json.loads(_json.dumps(encoders))  # exactly what the artifact file does
    out, _ = encode_categoricals(df.copy(), fit=False, encoders=reloaded)

    assert out["L7_PROTO"].nunique() > 1, "the column collapsed to a constant"
    in_memory, _ = encode_categoricals(df.copy(), fit=False, encoders=encoders)
    assert out["L7_PROTO"].to_numpy() == pytest.approx(in_memory["L7_PROTO"].to_numpy())


def test_log_transform_precision_does_not_depend_on_the_columns_storage_type():
    """`optimize_dtypes` picks the narrowest int the observed range allows,
    and numpy derives log1p's output width from it: int8 gives float16 --
    three decimal digits. So a --nrows development run could produce a
    measurably different feature than the full run, from identical values."""
    from source.preprocessing.clean import log_transform

    values = [78, 100, 120, 44, 48]
    narrow = pd.DataFrame({"IN_BYTES": pd.array(values, dtype="int8")})
    wide = pd.DataFrame({"IN_BYTES": pd.array(values, dtype="int64")})

    a = log_transform(narrow, cols=["IN_BYTES"])["IN_BYTES"].to_numpy(dtype=float)
    b = log_transform(wide, cols=["IN_BYTES"])["IN_BYTES"].to_numpy(dtype=float)

    assert a == pytest.approx(b, rel=1e-12), "storage width changed the feature's value"
    assert a == pytest.approx(np.log1p(np.array(values, dtype=float)), rel=1e-12)


def test_log_transform_still_clips_negatives_before_the_log():
    from source.preprocessing.clean import log_transform

    out = log_transform(pd.DataFrame({"IN_BYTES": [-5.0, 0.0, 10.0]}), cols=["IN_BYTES"])
    assert np.isfinite(out["IN_BYTES"]).all()
    assert out["IN_BYTES"].iloc[0] == 0.0
