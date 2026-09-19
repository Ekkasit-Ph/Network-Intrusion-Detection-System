"""The online pipeline must reproduce the offline one exactly.

This is the only test that matters much here. `pipeline.py` and
`online.py` compute the same features by different routes -- one reads
whole columns, the other keeps incremental state -- and any disagreement
between them is train/serve skew, which produces no error, no warning, and
a perfectly reasonable-looking number. So the offline result is computed on
the same rows and the two are compared value by value.
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest

from source.common.constants import (
    CATEGORICAL_COLS,
    IDENTIFIER_COLS,
    LABEL_COL,
    LOG_TRANSFORM_COLS,
    NETFLOW_FEATURES,
)
from source.preprocessing.clean import encode_categoricals, log_transform
from source.preprocessing.engineer_features import (
    DST_DISTINCT_SRC_IPS_COL,
    SRC_DISTINCT_DST_IPS_COL,
    SRC_DISTINCT_DST_PORTS_COL,
    add_behavioral_features,
)
from source.preprocessing.online import (
    BehavioralState,
    OnlineFeaturePipeline,
    TrailingDistinctWindow,
)
from source.preprocessing.scale import fit_scaler, save_scaler

WINDOW = 5


def make_raw_rows(n: int = 120, seed: int = 0) -> pd.DataFrame:
    """Rows shaped like sensor.py's output, with enough repetition in the
    address columns that the trailing windows actually fill and evict."""
    rng = np.random.default_rng(seed)
    sources = [f"192.168.1.{i}" for i in range(1, 6)]
    destinations = [f"10.0.0.{i}" for i in range(1, 9)]

    data: dict[str, object] = {}
    for col in NETFLOW_FEATURES:
        data[col] = rng.integers(0, 5000, n).astype(float)
    data["IPV4_SRC_ADDR"] = rng.choice(sources, n)
    data["IPV4_DST_ADDR"] = rng.choice(destinations, n)
    data["L4_SRC_PORT"] = rng.integers(1024, 65535, n)
    data["L4_DST_PORT"] = rng.choice([80, 443, 22, 53, 8080], n)
    data["PROTOCOL"] = rng.choice([6.0, 17.0, 1.0], n)
    # More than ONE_HOT_CARDINALITY_LIMIT distinct values, so the encoder
    # picks frequency encoding for L7_PROTO exactly as it does on the real
    # dataset (161 distinct values there). With only a handful it would
    # one-hot instead, and the test would be exercising a code path that
    # never ships.
    data["L7_PROTO"] = rng.choice(
        [0.0, 5.0, 7.0, 91.0, 92.0, 244.0, 7.178, 89.7] + [float(i) for i in range(100, 120)], n
    )
    return pd.DataFrame(data)[NETFLOW_FEATURES]


@pytest.fixture
def artifacts(tmp_path):
    """Run the offline path once to produce feature_columns.json, the
    encoders and the scaler -- the same three files serving loads."""
    raw = make_raw_rows()
    engineered, _ = add_behavioral_features(raw, window=WINDOW)
    engineered = engineered.drop(columns=IDENTIFIER_COLS)

    encoded, encoders = encode_categoricals(engineered, fit=True)
    encoded = log_transform(encoded)
    feature_cols = [c for c in encoded.columns if c != LABEL_COL]
    scaler = fit_scaler(encoded, feature_cols, kind="standard")

    processed_dir = tmp_path / "processed"
    prep_dir = tmp_path / "prep"
    processed_dir.mkdir()
    prep_dir.mkdir()
    (processed_dir / "feature_columns.json").write_text(json.dumps(feature_cols))
    (prep_dir / "categorical_encoders.json").write_text(json.dumps(encoders))
    save_scaler(scaler, prep_dir / "scaler.pkl")

    offline = pd.DataFrame(scaler.transform(encoded[feature_cols]), columns=feature_cols)
    return {"raw": raw, "offline": offline, "feature_cols": feature_cols,
            "processed_dir": processed_dir, "prep_dir": prep_dir}


# --------------------------------------------------------------------------
# the equivalence that matters
# --------------------------------------------------------------------------

def test_online_reproduces_the_offline_features_exactly(artifacts):
    pipeline = OnlineFeaturePipeline(
        artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW
    )
    rows = artifacts["raw"].to_dict(orient="records")
    online = pd.DataFrame([pipeline.transform(r) for r in rows])[artifacts["feature_cols"]]

    offline = artifacts["offline"]
    for col in artifacts["feature_cols"]:
        assert online[col].to_numpy() == pytest.approx(offline[col].to_numpy(), rel=1e-9, abs=1e-9), col


def test_the_behavioral_columns_specifically_agree(artifacts):
    """Called out separately from the check above: these three are the only
    features computed by genuinely different algorithms in the two paths,
    so a failure here means something different from a failure anywhere
    else."""
    raw = artifacts["raw"]
    offline, _ = add_behavioral_features(raw, window=WINDOW)

    state = BehavioralState(window=WINDOW)
    online = [state.observe(r["IPV4_SRC_ADDR"], r["IPV4_DST_ADDR"], r["L4_DST_PORT"])
              for r in raw.to_dict(orient="records")]

    for col in (SRC_DISTINCT_DST_IPS_COL, SRC_DISTINCT_DST_PORTS_COL, DST_DISTINCT_SRC_IPS_COL):
        assert [o[col] for o in online] == offline[col].tolist(), col


def test_the_windows_actually_evict(artifacts):
    """If the window never filled, the test above would pass while proving
    nothing about the eviction path."""
    raw = artifacts["raw"]
    offline, _ = add_behavioral_features(raw, window=WINDOW)
    per_source = raw.groupby("IPV4_SRC_ADDR").size()
    assert per_source.max() > WINDOW, "no source exceeds the window; eviction is untested"
    assert offline[SRC_DISTINCT_DST_IPS_COL].max() <= WINDOW


# --------------------------------------------------------------------------
# the window primitive
# --------------------------------------------------------------------------

def test_trailing_window_counts_distinct_values_within_the_window():
    w = TrailingDistinctWindow(window=3)
    assert w.observe("a") == 1
    assert w.observe("b") == 2
    assert w.observe("a") == 2   # repeat, still two distinct
    assert w.observe("c") == 3
    # "a" from position 0 has now fallen out, but the one at position 2
    # keeps it alive -- a naive set would have dropped it.
    assert w.observe("d") == 3


def test_trailing_window_forgets_a_value_once_every_copy_leaves():
    w = TrailingDistinctWindow(window=2)
    w.observe("a")
    w.observe("b")
    assert w.observe("c") == 2  # "a" gone
    assert w.observe("d") == 2  # "b" gone


# --------------------------------------------------------------------------
# bounded memory
# --------------------------------------------------------------------------

def test_state_evicts_least_recently_used_keys():
    state = BehavioralState(window=WINDOW, max_tracked_keys=3)
    for i in range(10):
        state.observe(f"src-{i}", "10.0.0.1", 80)
    assert state.tracked_sources == 3
    assert state.evictions == 7


def test_a_recently_seen_source_survives_eviction():
    """LRU, not FIFO: a source still sending traffic must keep its window
    even as new sources appear, or a sustained scan would have its own
    history dropped out from under it."""
    state = BehavioralState(window=WINDOW, max_tracked_keys=3)
    state.observe("busy", "10.0.0.1", 80)
    for i in range(5):
        state.observe(f"other-{i}", "10.0.0.2", 80)
        state.observe("busy", f"10.0.0.{i + 10}", 80)

    # "busy" has touched several distinct destinations and remembers them.
    counts = state.observe("busy", "10.0.0.99", 80)
    assert counts[SRC_DISTINCT_DST_IPS_COL] > 1


# --------------------------------------------------------------------------
# refusing to serve something wrong
# --------------------------------------------------------------------------

def test_construction_fails_when_a_feature_cannot_be_produced(artifacts):
    """Better to refuse at startup than to feed the model a column that is
    silently 0.0 on every flow."""
    path = artifacts["processed_dir"] / "feature_columns.json"
    cols = json.loads(path.read_text()) + ["A_FEATURE_THAT_DOES_NOT_EXIST"]
    path.write_text(json.dumps(cols))

    with pytest.raises(RuntimeError, match="cannot produce"):
        OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)


def test_construction_fails_on_mismatched_artifacts(artifacts, tmp_path):
    """A scaler from one preprocessing run and columns from another would
    standardize every feature by the wrong constants."""
    path = artifacts["processed_dir"] / "feature_columns.json"
    cols = json.loads(path.read_text())
    path.write_text(json.dumps(cols[:-1]))

    with pytest.raises(RuntimeError, match="different preprocessing runs"):
        OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)


def test_a_missing_netflow_column_is_named(artifacts):
    pipeline = OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)
    row = artifacts["raw"].iloc[0].to_dict()
    del row["MIN_TTL"]
    with pytest.raises(KeyError, match="MIN_TTL"):
        pipeline.transform(row)


def test_non_finite_values_are_counted_not_swallowed(artifacts):
    pipeline = OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)
    row = artifacts["raw"].iloc[0].to_dict()
    row["SRC_TO_DST_AVG_THROUGHPUT"] = float("inf")
    pipeline.transform(row)
    assert pipeline.non_finite_inputs == 1


def test_an_unseen_protocol_leaves_every_one_hot_column_at_zero(artifacts):
    """The standard one-hot "unknown" -- and what the batch encoder does,
    so serving must not invent a different convention."""
    pipeline = OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)
    row = artifacts["raw"].iloc[0].to_dict()
    row["PROTOCOL"] = 132.0  # SCTP, absent from the fixture
    out = pipeline.transform(row)

    scaler_mean = dict(zip(pipeline.feature_cols, pipeline._mean))
    scaler_scale = dict(zip(pipeline.feature_cols, pipeline._scale))
    for col in pipeline.feature_cols:
        if col.startswith("PROTOCOL_"):
            expected = (0.0 - scaler_mean[col]) / scaler_scale[col]
            assert out[col] == pytest.approx(expected), col


def test_log_transformed_columns_are_logged_before_scaling(artifacts):
    """Getting this order backwards would still produce finite, plausible
    numbers on every flow."""
    pipeline = OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)
    logged = [c for c in pipeline.feature_cols if c in LOG_TRANSFORM_COLS]
    assert logged, "fixture should exercise at least one log-transformed column"

    row = artifacts["raw"].iloc[0].to_dict()
    out = pipeline.transform(row)
    col = logged[0]
    i = pipeline.feature_cols.index(col)
    expected = (np.log1p(float(row[col])) - pipeline._mean[i]) / pipeline._scale[i]
    assert out[col] == pytest.approx(expected)


def test_identifier_columns_never_reach_the_model(artifacts):
    """PROJECT.md's hard constraint: the model must not see addresses or
    ports, or it learns which testbed machine it is looking at."""
    pipeline = OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)
    out = pipeline.transform(artifacts["raw"].iloc[0].to_dict())
    for col in IDENTIFIER_COLS:
        assert col not in out
    assert set(out) == set(pipeline.feature_cols)


def test_categorical_source_columns_are_replaced_not_passed_through(artifacts):
    pipeline = OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)
    assert set(pipeline._onehot) == {"PROTOCOL"}, "fixture must match production's encoder choice"
    assert set(pipeline._freq_maps) == {"L7_PROTO"}

    out = pipeline.transform(artifacts["raw"].iloc[0].to_dict())
    assert "PROTOCOL" not in out           # replaced by PROTOCOL_* one-hots
    assert "L7_PROTO" in out               # frequency-encoded in place
    assert any(c.startswith("PROTOCOL_") for c in out)


def test_an_unseen_l7_proto_falls_back_to_zero_frequency(artifacts):
    """Matches `encode_categoricals`' .fillna(0.0). A protocol nDPI names
    but the encoder never saw must not become a value the model has no
    reference for -- see source/extraction/README.md on why this boundary
    is the only one L7_PROTO actually encodes."""
    pipeline = OnlineFeaturePipeline(artifacts["processed_dir"], artifacts["prep_dir"], window=WINDOW)
    row = artifacts["raw"].iloc[0].to_dict()
    row["L7_PROTO"] = 999.0
    out = pipeline.transform(row)

    i = pipeline.feature_cols.index("L7_PROTO")
    expected = (0.0 - pipeline._mean[i]) / pipeline._scale[i]
    assert out["L7_PROTO"] == pytest.approx(expected)


def test_eviction_warns_once_when_it_starts():
    """Past the cap the features stop matching the batch pipeline for
    evicted keys. Degrading beats dying, but a sensor quietly reporting
    different features than the model was trained on must say so."""
    import logging

    state = BehavioralState(window=WINDOW, max_tracked_keys=2)
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logger = logging.getLogger("source.preprocessing.online")
    logger.addHandler(handler)
    try:
        for i in range(20):
            state.observe(f"src-{i}", "10.0.0.1", 80)
    finally:
        logger.removeHandler(handler)

    assert state.evictions > 0
    warnings = [r for r in records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1, "warn once, not once per evicted key"
    assert "max_tracked_keys" in warnings[0].getMessage()


@pytest.mark.parametrize("kwargs", [{"window": 0}, {"max_tracked_keys": 0}])
def test_degenerate_configuration_is_refused(kwargs):
    """max_tracked_keys=0 would evict the key just inserted, so every flow
    would report a fan-out of 1 -- a plausible number produced by tracking
    nothing."""
    with pytest.raises(ValueError):
        BehavioralState(**{"window": WINDOW, "max_tracked_keys": 10, **kwargs})
