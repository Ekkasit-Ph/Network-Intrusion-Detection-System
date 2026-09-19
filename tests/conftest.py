"""Shared fixtures: a small synthetic NF-ToN-IoT-v2-shaped DataFrame so
tests don't need the real 2.5GB CSV."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from source.common.constants import ATTACK_COL, LABEL_COL, NETFLOW_FEATURES


@pytest.fixture
def raw_df() -> pd.DataFrame:
    rng = np.random.default_rng(0)
    n_benign, n_attack = 120, 30
    n = n_benign + n_attack

    data = {}
    for col in NETFLOW_FEATURES:
        if col in ("IPV4_SRC_ADDR", "IPV4_DST_ADDR"):
            data[col] = [f"10.0.0.{i % 254 + 1}" for i in range(n)]
        elif col == "PROTOCOL":
            data[col] = rng.choice([6, 17, 1], size=n)
        elif col == "L7_PROTO":
            data[col] = rng.choice([0.0, 7.0, 91.0], size=n)
        else:
            data[col] = rng.integers(0, 1000, size=n).astype(float)

    # Inject a couple of inf values into a throughput column, and a couple
    # of NaNs into a protocol-specific column, to exercise clean.py.
    data["SRC_TO_DST_AVG_THROUGHPUT"][0] = np.inf
    data["DST_TO_SRC_AVG_THROUGHPUT"][1] = -np.inf
    data["DNS_QUERY_ID"] = pd.array(data["DNS_QUERY_ID"])
    data["DNS_QUERY_ID"][2] = np.nan

    labels = np.array([0] * n_benign + [1] * n_attack)
    attack_names = np.array(
        ["Benign"] * n_benign
        + rng.choice(["Scanning", "DDoS", "Ransomware"], size=n_attack).tolist()
    )
    data[LABEL_COL] = labels
    data[ATTACK_COL] = attack_names

    df = pd.DataFrame(data)
    # Duplicate a couple of rows so drop_duplicates has something to remove.
    df = pd.concat([df, df.iloc[[5, 10]]], ignore_index=True)
    return df
