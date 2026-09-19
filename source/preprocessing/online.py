"""Module 2 at inference time: one raw NetFlow row in, one model-ready
feature vector out.

`pipeline.py` does this for a whole file, in an order that only makes sense
in batch (fit the scaler, split, then transform). Serving has to reproduce
*exactly* the same arithmetic one row at a time, using the artifacts that
batch run saved. Anything that differs between the two is train/serve skew,
which is invisible by construction -- the model still returns a number, and
every stage downstream handles that number correctly.

The order below mirrors `pipeline.run()` step for step:

    1. behavioral features   from rolling state, needs the identifier columns
    2. drop identifiers      they must never reach the model (PROJECT.md)
    3. encode categoricals   with the saved encoders, never re-fit
    4. log1p                 the same LOG_TRANSFORM_COLS
    5. scale                 with the saved scaler, never re-fit

Step 1 is the one that cannot be copied from `pipeline.py`, because the
batch version reads a whole column at once. `engineer_features.py` computes
"distinct destinations in this source's last W flows" by grouping the file
by source and walking each group; serving keeps one bounded window per
source instead, updated as flows arrive. Same feature, same numbers --
`tests/test_online.py` asserts the two agree row for row on the same input
sequence, because "same idea, slightly different number" is precisely the
failure this file exists to avoid.
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from source.common.constants import (
    CATEGORICAL_COLS,
    IDENTIFIER_COLS,
    LOG_TRANSFORM_COLS,
    NETFLOW_FEATURES,
)
from source.preprocessing.engineer_features import (
    DEFAULT_WINDOW,
    DST_DISTINCT_SRC_IPS_COL,
    SRC_DISTINCT_DST_IPS_COL,
    SRC_DISTINCT_DST_PORTS_COL,
)
from source.preprocessing.scale import load_scaler

log = logging.getLogger(__name__)

# A long-running sensor sees unboundedly many source and destination
# addresses, and each one would otherwise hold a window forever. Least-
# recently-used keys are evicted past this. Eviction is not free -- an
# evicted source restarts its window empty, so its next flow reports a
# fan-out of 1 -- but a sensor that runs out of memory reports nothing at
# all. The default holds every host in a /16 several times over.
DEFAULT_MAX_TRACKED_KEYS = 100_000


class TrailingDistinctWindow:
    """Distinct values among the last `window` observations.

    The same bookkeeping as `engineer_features._rolling_distinct_counts`,
    kept incremental: each observation enters and leaves exactly once, so
    `observe` is O(1) and the whole thing is O(window) in memory.
    """

    __slots__ = ("_window", "_recent", "_counts")

    def __init__(self, window: int) -> None:
        self._window = window
        self._recent: deque[Any] = deque()
        self._counts: dict[Any, int] = {}

    def observe(self, value: Any) -> int:
        """Record `value`, then return the distinct count including it."""
        self._counts[value] = self._counts.get(value, 0) + 1
        self._recent.append(value)
        if len(self._recent) > self._window:
            evicted = self._recent.popleft()
            remaining = self._counts[evicted] - 1
            if remaining:
                self._counts[evicted] = remaining
            else:
                del self._counts[evicted]
        return len(self._counts)


class BehavioralState:
    """The rolling windows behind the three engineered features: fan-out
    per source (distinct destination IPs, distinct destination ports) and
    fan-in per destination (distinct sources)."""

    def __init__(self, window: int = DEFAULT_WINDOW,
                 max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS) -> None:
        if window < 1:
            raise ValueError(f"window must be at least 1, got {window}")
        if max_tracked_keys < 1:
            # With 0 the just-inserted key would be evicted immediately and
            # every flow would report a fan-out of 1 -- a plausible-looking
            # number produced by tracking nothing at all.
            raise ValueError(f"max_tracked_keys must be at least 1, got {max_tracked_keys}")
        self.window = window
        self.max_tracked_keys = max_tracked_keys
        self._by_source: OrderedDict[Any, tuple[TrailingDistinctWindow, TrailingDistinctWindow]] = OrderedDict()
        self._by_destination: OrderedDict[Any, TrailingDistinctWindow] = OrderedDict()
        self.evictions = 0
        self._warned_about_eviction = False

    def _touch(self, store: OrderedDict, key: Any, factory) -> Any:
        existing = store.get(key)
        if existing is None:
            existing = factory()
            store[key] = existing
            if len(store) > self.max_tracked_keys:
                store.popitem(last=False)
                self.evictions += 1
                if not self._warned_about_eviction:
                    # Said once, at the moment it starts mattering. Past
                    # this point the three behavioural features no longer
                    # match what the batch pipeline would have computed:
                    # an evicted source resumes with an empty window, so
                    # its next flow reports a fan-out of 1 no matter what
                    # it has really been doing. Measured on a 400-source
                    # stream capped at 200, 59% of rows disagreed with the
                    # offline values. Nothing raises -- degrading beats
                    # dying -- but a sensor silently reporting different
                    # features than the model was trained on is exactly
                    # the failure this project keeps finding, so it says so.
                    self._warned_about_eviction = True
                    log.warning(
                        "Tracking more than %d keys; evicting least-recently-used state. "
                        "The behavioural features will now differ from the batch pipeline's "
                        "for evicted sources/destinations. Raise max_tracked_keys if this "
                        "network really has this many endpoints.",
                        self.max_tracked_keys,
                    )
        else:
            store.move_to_end(key)
        return existing

    def observe(self, src_ip: Any, dst_ip: Any, dst_port: Any) -> dict[str, float]:
        ip_window, port_window = self._touch(
            self._by_source, src_ip,
            lambda: (TrailingDistinctWindow(self.window), TrailingDistinctWindow(self.window)),
        )
        fan_in = self._touch(
            self._by_destination, dst_ip, lambda: TrailingDistinctWindow(self.window)
        )
        return {
            SRC_DISTINCT_DST_IPS_COL: float(ip_window.observe(dst_ip)),
            SRC_DISTINCT_DST_PORTS_COL: float(port_window.observe(dst_port)),
            DST_DISTINCT_SRC_IPS_COL: float(fan_in.observe(src_ip)),
        }

    @property
    def tracked_sources(self) -> int:
        return len(self._by_source)

    @property
    def tracked_destinations(self) -> int:
        return len(self._by_destination)


class OnlineFeaturePipeline:
    """Raw NetFlow row (the 43 columns `sensor.py` emits) -> the feature
    vector the model expects, in `feature_columns.json` order."""

    def __init__(
        self,
        processed_dir: Path,
        preprocessing_dir: Path,
        window: int = DEFAULT_WINDOW,
        max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS,
    ) -> None:
        self.feature_cols: list[str] = json.loads((processed_dir / "feature_columns.json").read_text())
        self.encoders: dict[str, Any] = json.loads((preprocessing_dir / "categorical_encoders.json").read_text())
        self.scaler = load_scaler(preprocessing_dir / "scaler.pkl")
        self.state = BehavioralState(window=window, max_tracked_keys=max_tracked_keys)

        self._log_cols = frozenset(LOG_TRANSFORM_COLS)
        # Frequency maps arrive from JSON with string keys; the values they
        # are looked up by are floats.
        # float32 deliberately: `encode_categoricals` casts the frequency
        # column to float32, so keeping full float64 precision here would
        # feed the model a subtly different number than training used
        # (~3e-8 in z-space -- harmless on its own, but the point of this
        # file is that the two paths agree exactly, and an exception made
        # once is an exception that gets made again somewhere it matters).
        self._freq_maps = {
            col: {float(k): float(np.float32(v)) for k, v in spec["freq_map"].items()}
            for col, spec in self.encoders.items() if spec["strategy"] == "frequency"
        }
        self._onehot = {
            col: [(f"{col}_{cat}", float(cat)) for cat in spec["categories"]]
            for col, spec in self.encoders.items() if spec["strategy"] == "onehot"
        }
        self._mean = np.asarray(self.scaler.mean_, dtype=np.float64)
        self._scale = np.asarray(self.scaler.scale_, dtype=np.float64)

        self._verify_columns_are_reachable()
        self.non_finite_inputs = 0

    def _verify_columns_are_reachable(self) -> None:
        """Every feature the model wants must be producible from a raw row,
        an encoder, or the behavioral state. A column that silently ends up
        0.0 forever is exactly the kind of skew this module exists to stop,
        so it is refused at construction rather than discovered in
        production."""
        producible = set(NETFLOW_FEATURES) - set(IDENTIFIER_COLS) - set(CATEGORICAL_COLS)
        producible |= {SRC_DISTINCT_DST_IPS_COL, SRC_DISTINCT_DST_PORTS_COL, DST_DISTINCT_SRC_IPS_COL}
        producible |= set(self._freq_maps)
        for columns in self._onehot.values():
            producible |= {name for name, _ in columns}

        missing = [c for c in self.feature_cols if c not in producible]
        if missing:
            raise RuntimeError(
                f"the model expects feature(s) this pipeline cannot produce: {missing}. "
                f"Serving them as a constant would be train/serve skew -- fix the mapping "
                f"or re-run preprocessing so the two agree."
            )
        if len(self._mean) != len(self.feature_cols):
            raise RuntimeError(
                f"scaler was fitted on {len(self._mean)} features but "
                f"feature_columns.json lists {len(self.feature_cols)} -- these artifacts "
                f"are from different preprocessing runs"
            )

    def transform(self, row: dict[str, Any]) -> dict[str, float]:
        """One raw row -> {feature name: standardized value}. Mutates the
        pipeline's rolling state, so rows must be fed in arrival order and
        exactly once."""
        missing = [c for c in NETFLOW_FEATURES if c not in row]
        if missing:
            raise KeyError(f"raw row is missing NetFlow column(s): {missing}")

        values: dict[str, float] = {}
        for col in NETFLOW_FEATURES:
            if col in IDENTIFIER_COLS or col in CATEGORICAL_COLS:
                continue
            values[col] = self._as_finite_float(row[col], col)

        values.update(self.state.observe(row["IPV4_SRC_ADDR"], row["IPV4_DST_ADDR"], row["L4_DST_PORT"]))

        for col, freq_map in self._freq_maps.items():
            # An id the encoder never saw maps to 0.0, matching
            # `encode_categoricals`' .fillna(0.0) on unseen values.
            values[col] = freq_map.get(self._as_finite_float(row[col], col), 0.0)
        for col, columns in self._onehot.items():
            observed = self._as_finite_float(row[col], col)
            for name, category in columns:
                # An unseen category leaves every column 0, which is the
                # standard one-hot "unknown" and what the batch encoder does.
                values[name] = 1.0 if observed == category else 0.0

        vector = np.empty(len(self.feature_cols), dtype=np.float64)
        for i, col in enumerate(self.feature_cols):
            v = values[col]
            vector[i] = np.log1p(max(v, 0.0)) if col in self._log_cols else v
        vector = (vector - self._mean) / self._scale
        return {col: float(v) for col, v in zip(self.feature_cols, vector)}

    def transform_many(self, rows: Iterable[dict[str, Any]]) -> list[dict[str, float]]:
        return [self.transform(r) for r in rows]

    def _as_finite_float(self, value: Any, col: str) -> float:
        """`sensor.py::_rate` already returns 0 rather than dividing by a
        zero duration, so the inf values `clean.py` has to repair in the
        raw CSV shouldn't arise from our own extractor. This is the safety
        net for that assumption, counted rather than silently swallowed --
        a rising `non_finite_inputs` means the extractor changed."""
        try:
            v = float(value)
        except (TypeError, ValueError):
            v = float("nan")
        if not np.isfinite(v):
            self.non_finite_inputs += 1
            return 0.0
        return v
