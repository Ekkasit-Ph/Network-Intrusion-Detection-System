"""Tests for source/preprocessing/engineer_features.py.

Correctness here matters more than usual: a bug that lets a row's feature
value depend on flows that come *after* it (in the pseudo-time row order)
would silently reintroduce the exact train/val/test leakage
add_behavioral_features exists to avoid. See that module's docstring.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from source.preprocessing.engineer_features import (
    DST_DISTINCT_SRC_IPS_COL,
    SRC_DISTINCT_DST_IPS_COL,
    SRC_DISTINCT_DST_PORTS_COL,
    _rolling_distinct_count,
    _rolling_distinct_counts,
    add_behavioral_features,
)


def test_rolling_distinct_counts_matches_naive_reference():
    rng = np.random.default_rng(0)
    ip_codes = rng.integers(0, 8, size=200)
    port_codes = rng.integers(0, 5, size=200)
    window = 6

    out_ip, out_port = _rolling_distinct_counts(ip_codes, port_codes, window)

    for i in range(len(ip_codes)):
        lo = max(0, i - window + 1)
        assert out_ip[i] == len(set(ip_codes[lo : i + 1]))
        assert out_port[i] == len(set(port_codes[lo : i + 1]))


def test_rolling_distinct_counts_never_exceeds_window():
    rng = np.random.default_rng(1)
    ip_codes = rng.integers(0, 1000, size=500)  # all-distinct-ish
    port_codes = rng.integers(0, 1000, size=500)
    window = 10

    out_ip, out_port = _rolling_distinct_counts(ip_codes, port_codes, window)

    assert out_ip.max() <= window
    assert out_port.max() <= window


def test_rolling_distinct_counts_is_strictly_causal():
    """Changing a value far in the future must not change an earlier
    position's rolling count -- the property the whole design relies on."""
    rng = np.random.default_rng(2)
    ip_codes = rng.integers(0, 8, size=100)
    port_codes = rng.integers(0, 5, size=100)
    window = 6

    out_before, _ = _rolling_distinct_counts(ip_codes, port_codes, window)

    mutated_ip = ip_codes.copy()
    mutated_ip[50:] = 9999  # blow up everything from position 50 onward
    out_after, _ = _rolling_distinct_counts(mutated_ip, port_codes, window)

    assert np.array_equal(out_before[:50], out_after[:50])


def _make_flows(rows: list[tuple[str, str, int]]) -> pd.DataFrame:
    """rows: list of (src_ip, dst_ip, dst_port)."""
    return pd.DataFrame(
        {
            "IPV4_SRC_ADDR": [r[0] for r in rows],
            "IPV4_DST_ADDR": [r[1] for r in rows],
            "L4_DST_PORT": [r[2] for r in rows],
        }
    )


def test_add_behavioral_features_basic_scan_burst_shows_up():
    # Source "A": 3 normal flows to the same destination, then a burst
    # touching 5 distinct ports on 5 distinct hosts (a scan-like burst).
    rows = [
        ("A", "10.0.0.1", 80), ("A", "10.0.0.1", 80), ("A", "10.0.0.1", 80),
        ("A", "10.0.0.2", 21), ("A", "10.0.0.3", 22), ("A", "10.0.0.4", 23),
        ("A", "10.0.0.5", 24), ("A", "10.0.0.6", 25),
    ]
    df = _make_flows(rows)
    out, report = add_behavioral_features(df, window=4)

    assert report["window"] == 4
    assert report["n_sources"] == 1
    # During the repetitive prefix, fan-out stays low.
    assert out.iloc[2][SRC_DISTINCT_DST_IPS_COL] == 1
    assert out.iloc[2][SRC_DISTINCT_DST_PORTS_COL] == 1
    # By the end of the burst, the trailing window (last 4 flows) is all
    # distinct destinations -- exactly the signal scanning should trip.
    assert out.iloc[-1][SRC_DISTINCT_DST_IPS_COL] == 4
    assert out.iloc[-1][SRC_DISTINCT_DST_PORTS_COL] == 4


def test_add_behavioral_features_does_not_mix_sources():
    # Interleaved sources: each source's own window must ignore the
    # other's flows entirely.
    rows = [
        ("A", "10.0.0.1", 80),
        ("B", "10.0.0.9", 9), ("B", "10.0.0.8", 8), ("B", "10.0.0.7", 7),
        ("A", "10.0.0.2", 81),
        ("A", "10.0.0.3", 82),
    ]
    df = _make_flows(rows)
    out, _ = add_behavioral_features(df, window=10)

    a_rows = out[out["IPV4_SRC_ADDR"] == "A"]
    # A's 3rd flow (last row) should see fan-out 3 (only A's own 3 flows),
    # not 6 (which would mean B's flows leaked into A's window).
    assert a_rows.iloc[-1][SRC_DISTINCT_DST_IPS_COL] == 3
    assert a_rows.iloc[-1][SRC_DISTINCT_DST_PORTS_COL] == 3


def test_add_behavioral_features_preserves_row_order_and_length():
    rng = np.random.default_rng(3)
    n = 300
    srcs = rng.choice(["A", "B", "C"], size=n)
    dsts = rng.choice([f"10.0.0.{i}" for i in range(20)], size=n)
    ports = rng.integers(1, 1000, size=n)
    df = pd.DataFrame({"IPV4_SRC_ADDR": srcs, "IPV4_DST_ADDR": dsts, "L4_DST_PORT": ports})

    out, _ = add_behavioral_features(df, window=5)

    assert len(out) == n
    assert list(out.index) == list(df.index)
    assert (out["IPV4_SRC_ADDR"].to_numpy() == srcs).all()


def test_rolling_distinct_count_single_target_matches_naive_reference():
    rng = np.random.default_rng(4)
    codes = rng.integers(0, 8, size=200)
    window = 6

    out = _rolling_distinct_count(codes, window)

    for i in range(len(codes)):
        lo = max(0, i - window + 1)
        assert out[i] == len(set(codes[lo : i + 1]))


def test_add_behavioral_features_dst_fanin_basic_ddos_burst_shows_up():
    # Destination "V": 3 flows from the same attacker, then a burst from
    # 5 distinct sources (a DDoS-like convergence).
    rows = [
        ("attacker", "V", 80), ("attacker", "V", 80), ("attacker", "V", 80),
        ("bot1", "V", 80), ("bot2", "V", 80), ("bot3", "V", 80),
        ("bot4", "V", 80), ("bot5", "V", 80),
    ]
    df = _make_flows(rows)
    out, report = add_behavioral_features(df, window=4)

    assert report["n_destinations"] == 1
    # During the repetitive prefix (same attacker), fan-in stays at 1.
    assert out.iloc[2][DST_DISTINCT_SRC_IPS_COL] == 1
    # By the end of the burst, the trailing window (last 4 flows) is all
    # distinct sources -- exactly the DDoS convergence signal.
    assert out.iloc[-1][DST_DISTINCT_SRC_IPS_COL] == 4


def test_add_behavioral_features_dst_fanin_does_not_mix_destinations():
    rows = [
        ("s1", "V1", 80),
        ("s2", "V2", 80), ("s3", "V2", 80), ("s4", "V2", 80),
        ("s5", "V1", 80),
        ("s6", "V1", 80),
    ]
    df = _make_flows(rows)
    out, _ = add_behavioral_features(df, window=10)

    v1_rows = out[out["IPV4_DST_ADDR"] == "V1"]
    # V1's 3rd flow (last row) should see fan-in 3 (only V1's own sources),
    # not 6 (which would mean V2's sources leaked into V1's window).
    assert v1_rows.iloc[-1][DST_DISTINCT_SRC_IPS_COL] == 3


def test_add_behavioral_features_no_future_leakage_under_shuffle():
    """The defining property: computing on the full (pre-split) frame,
    then handing rows to whichever split they land in, must give each row
    the exact same feature value it would have gotten standing alone --
    i.e. later rows in the file must not affect earlier rows' values, so a
    train row can never be influenced by a val/test row of the same
    source that happens to sit later in the file."""
    rows = [
        ("A", "10.0.0.1", 80), ("A", "10.0.0.1", 80),
        ("A", "10.0.0.2", 21), ("A", "10.0.0.3", 22),
    ]
    df_full = _make_flows(rows)
    out_full, _ = add_behavioral_features(df_full, window=10)

    # Truncate to just the first 2 rows and recompute -- this simulates
    # "what if the later rows didn't exist / hadn't happened yet".
    df_prefix = df_full.iloc[:2].reset_index(drop=True)
    out_prefix, _ = add_behavioral_features(df_prefix, window=10)

    assert out_full.iloc[0][SRC_DISTINCT_DST_IPS_COL] == out_prefix.iloc[0][SRC_DISTINCT_DST_IPS_COL]
    assert out_full.iloc[1][SRC_DISTINCT_DST_IPS_COL] == out_prefix.iloc[1][SRC_DISTINCT_DST_IPS_COL]
