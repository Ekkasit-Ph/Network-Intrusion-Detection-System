"""Causal, per-source/per-destination behavioral (aggregate) features --
targets scanning and DDoS/password-spray detection specifically, where a
single flow's own fields look almost identical to a normal short connection
but a *burst of many such flows touching many destinations* (scanning) or
*many sources converging on one destination* (DDoS/spray) is the actual
attack signature. A per-flow autoencoder has no way to see that pattern
unless it's handed a feature that already summarizes recent cross-flow
behavior.

**Design constraint driving this file (read before changing anything):**
NF-ToN-IoT-v2 ships only ~10 physical testbed hosts generating ~94% of all
16.9M rows, and the *same* host produces both benign traffic and several
attack types (e.g. 192.168.1.31 alone: 2.29M benign + 798K ddos + 651K
scanning + ...). A *global* per-source aggregate (e.g. "total distinct
destinations this IP ever contacted across the whole file") would therefore
be close to a constant per IP, and the model would learn to recognize
*which testbed machine this is* rather than genuine scanning behavior --
exactly the "testbed-specific shortcut" IDENTIFIER_COLS is already dropped
to prevent (see constants.py). It would also leak: a benign row's feature
value would be influenced by that same source's attack flows elsewhere in
the dataset, including ones that later land in val/test.

The fix is a **bounded trailing window per source**: "how many distinct
destination IPs/ports has this source touched in its last W flows,
including this one". This varies row-by-row even for the same physical
host -- low during normal operation, spiking during a scan burst -- so it
carries genuine behavioral signal instead of host identity. It's also
exactly what a live deployment would maintain as a rolling counter per
source, so the offline (batch) and online (streaming) computations are the
same feature, not just similar.

**Causal ordering caveat**: NF-ToN-IoT-v2 has no flow-start timestamp
column at all (verified against the raw CSV header), so "trailing window"
here means the *original CSV row order* (pandas' row order right after
`drop_duplicates`, before any shuffling) is used as a pseudo-chronological
proxy -- a NetFlow exporter appends completed flows roughly in
time/export order, but this is an approximation, not a guarantee. This is
why `add_behavioral_features` must run *before* `split_data` (which
shuffles rows): every row's feature value is finalized, using only that
row's own source's *earlier-in-this-order* flows, before train/val/test
assignment ever happens -- so no split can leak into another split's
feature values regardless of which rows end up where.
"""

from __future__ import annotations

from collections import deque
from typing import Any

import numpy as np
import pandas as pd

# Trailing window size (in flows from the same source). Chosen as a rough
# "recent burst" horizon: large enough to smooth over single-flow noise,
# small enough that it doesn't dilute a scan burst inside a huge history
# for the handful of dominant hosts (some sources have millions of flows --
# an *unbounded* count would saturate near the dataset's total distinct
# destination count and stop discriminating, see module docstring).
DEFAULT_WINDOW = 50

SRC_DISTINCT_DST_IPS_COL = "SRC_DISTINCT_DST_IPS_LAST_W"
SRC_DISTINCT_DST_PORTS_COL = "SRC_DISTINCT_DST_PORTS_LAST_W"
# Fan-in, mirroring fan-out: per *destination*, how many distinct sources
# have hit it in its trailing window -- the DDoS/password-spray signature
# (many sources -> one victim) rather than the scanning signature (one
# source -> many destinations). Same causal-windowed design, same
# leakage rationale -- see module docstring.
DST_DISTINCT_SRC_IPS_COL = "DST_DISTINCT_SRC_IPS_LAST_W"
BEHAVIORAL_FEATURE_COLS = [SRC_DISTINCT_DST_IPS_COL, SRC_DISTINCT_DST_PORTS_COL, DST_DISTINCT_SRC_IPS_COL]


def _rolling_distinct_counts(
    dst_ip_codes: np.ndarray, dst_port_codes: np.ndarray, window: int
) -> tuple[np.ndarray, np.ndarray]:
    """For one source's flows, in order: at each position, the number of
    distinct values seen in `dst_ip_codes`/`dst_port_codes` within the
    trailing `window` positions (including the current one).

    O(n) per call (each element enters and leaves the window's dict/deque
    exactly once), not O(n*window) -- matters here since a handful of
    sources have multi-million-row histories.
    """
    n = len(dst_ip_codes)
    out_ip = np.empty(n, dtype=np.int32)
    out_port = np.empty(n, dtype=np.int32)

    ip_counts: dict[int, int] = {}
    port_counts: dict[int, int] = {}
    ip_dq: deque[int] = deque()
    port_dq: deque[int] = deque()
    ip_distinct = 0
    port_distinct = 0

    for i in range(n):
        ip = dst_ip_codes[i]
        c = ip_counts.get(ip, 0)
        if c == 0:
            ip_distinct += 1
        ip_counts[ip] = c + 1
        ip_dq.append(ip)
        if len(ip_dq) > window:
            old = ip_dq.popleft()
            oc = ip_counts[old] - 1
            if oc == 0:
                del ip_counts[old]
                ip_distinct -= 1
            else:
                ip_counts[old] = oc
        out_ip[i] = ip_distinct

        port = dst_port_codes[i]
        c = port_counts.get(port, 0)
        if c == 0:
            port_distinct += 1
        port_counts[port] = c + 1
        port_dq.append(port)
        if len(port_dq) > window:
            old = port_dq.popleft()
            oc = port_counts[old] - 1
            if oc == 0:
                del port_counts[old]
                port_distinct -= 1
            else:
                port_counts[old] = oc
        out_port[i] = port_distinct

    return out_ip, out_port


def _rolling_distinct_count(codes: np.ndarray, window: int) -> np.ndarray:
    """Single-target version of `_rolling_distinct_counts`, for the
    DST-side fan-in feature (only one target -- distinct SRC_IP -- instead
    of two)."""
    n = len(codes)
    out = np.empty(n, dtype=np.int32)
    counts: dict[int, int] = {}
    dq: deque[int] = deque()
    distinct = 0
    for i in range(n):
        c = codes[i]
        cnt = counts.get(c, 0)
        if cnt == 0:
            distinct += 1
        counts[c] = cnt + 1
        dq.append(c)
        if len(dq) > window:
            old = dq.popleft()
            oc = counts[old] - 1
            if oc == 0:
                del counts[old]
                distinct -= 1
            else:
                counts[old] = oc
        out[i] = distinct
    return out


def _grouped_rolling_distinct(
    group_values: np.ndarray, target_codes: np.ndarray, window: int, n: int
) -> np.ndarray:
    """Shared driver for both the SRC-side and DST-side single-target
    features: groups rows by `group_values` (preserving each group's
    original row order -- the pseudo-chronological proxy, see module
    docstring), runs the causal rolling-distinct-count within each group,
    and scatters results back into an array shaped like the original
    (ungrouped) dataframe."""
    out = np.empty(n, dtype=np.int32)
    positions_by_group = pd.Series(np.arange(n)).groupby(group_values, sort=False).indices
    for _, positions in positions_by_group.items():
        pos = np.asarray(positions)
        out[pos] = _rolling_distinct_count(target_codes[pos], window)
    return out


def add_behavioral_features(
    df: pd.DataFrame,
    window: int = DEFAULT_WINDOW,
    src_col: str = "IPV4_SRC_ADDR",
    dst_ip_col: str = "IPV4_DST_ADDR",
    dst_port_col: str = "L4_DST_PORT",
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Adds three causal trailing-window columns:
      - SRC_DISTINCT_DST_IPS_LAST_W / SRC_DISTINCT_DST_PORTS_LAST_W (fan-out
        -- one source touching many destinations: the scanning signature)
      - DST_DISTINCT_SRC_IPS_LAST_W (fan-in -- many sources hitting one
        destination: the DDoS/password-spray signature)

    Must be called on the full (pre-split) dataframe, in its current row
    order, *before* `split_data` shuffles it and *before* IDENTIFIER_COLS
    are dropped -- see module docstring for why both matter. `df`'s row
    order and index are preserved; only three new int32 columns are added.
    """
    n = len(df)

    # Factorize once up front: integer codes hash/compare faster than the
    # category/float values the inner loops would otherwise touch
    # repeatedly.
    dst_ip_codes, _ = pd.factorize(df[dst_ip_col].to_numpy())
    dst_port_codes, _ = pd.factorize(df[dst_port_col].to_numpy())
    src_ip_codes, _ = pd.factorize(df[src_col].to_numpy())

    out_ip = np.empty(n, dtype=np.int32)
    out_port = np.empty(n, dtype=np.int32)
    src_values = df[src_col].to_numpy()
    positions_by_src = pd.Series(np.arange(n)).groupby(src_values, sort=False).indices
    n_sources = len(positions_by_src)
    for _, positions in positions_by_src.items():
        pos = np.asarray(positions)
        ip_result, port_result = _rolling_distinct_counts(
            dst_ip_codes[pos], dst_port_codes[pos], window
        )
        out_ip[pos] = ip_result
        out_port[pos] = port_result

    dst_values = df[dst_ip_col].to_numpy()
    out_src_fanin = _grouped_rolling_distinct(dst_values, src_ip_codes, window, n)
    n_destinations = len(pd.unique(dst_values))

    df = df.copy()
    df[SRC_DISTINCT_DST_IPS_COL] = out_ip.astype(np.float32)
    df[SRC_DISTINCT_DST_PORTS_COL] = out_port.astype(np.float32)
    df[DST_DISTINCT_SRC_IPS_COL] = out_src_fanin.astype(np.float32)

    report = {
        "window": window,
        "n_sources": int(n_sources),
        "n_destinations": int(n_destinations),
        "src_distinct_dst_ips_last_w": {
            "mean": float(out_ip.mean()), "max": int(out_ip.max()),
        },
        "src_distinct_dst_ports_last_w": {
            "mean": float(out_port.mean()), "max": int(out_port.max()),
        },
        "dst_distinct_src_ips_last_w": {
            "mean": float(out_src_fanin.mean()), "max": int(out_src_fanin.max()),
        },
    }
    return df, report
