"""ShapExplainer.explain() must not let two callers into shap at once.

`shap.KernelExplainer.explain()` keeps its working state on the instance
-- self.fx, self.nsamples, self.M, self.varyingInds, self.maskMatrix --
so it is not reentrant. The /explain endpoint is a sync `def`, which
FastAPI runs in a threadpool, so two people clicking Explain at the same
time really can land inside the solver together. The failure is silent:
both requests return, with attributions computed partly from each other's
flow. In a tool whose purpose is to justify a detection, a wrong-but-
plausible explanation is worse than a slow one.

These tests drive the real `ShapExplainer.explain` against a stub
explainer object, so they exercise the actual locking code without
loading a model or the training data.
"""

from __future__ import annotations

import threading
import time

import numpy as np
import pytest

pytest.importorskip("shap", reason="explainer module needs shap installed")

from source.explain.shap_explainer import ShapExplainer  # noqa: E402


class ReentrancyDetectingExplainer:
    """Stands in for shap.KernelExplainer, and records whether two threads
    were ever inside `shap_values` simultaneously."""

    def __init__(self, n_features: int, dwell: float = 0.05):
        self.expected_value = np.array([0.5])
        self._n = n_features
        self._dwell = dwell
        self._inside = 0
        self._guard = threading.Lock()
        self.max_concurrent = 0
        self.calls = 0

    def shap_values(self, x, nsamples=100, silent=True):
        with self._guard:
            self._inside += 1
            self.calls += 1
            self.max_concurrent = max(self.max_concurrent, self._inside)
        # Hold the "solver" open long enough that an unguarded second
        # caller would certainly overlap.
        time.sleep(self._dwell)
        with self._guard:
            self._inside -= 1
        # Echo the input back so a caller can tell whose values it got.
        return np.asarray(x, dtype=float).reshape(-1)[: self._n]


def _explainer_with(stub, feature_cols) -> ShapExplainer:
    """Build a ShapExplainer without running __init__ (which would load a
    model and the training split); only the attributes explain() touches
    are populated."""
    obj = ShapExplainer.__new__(ShapExplainer)
    obj.feature_cols = feature_cols
    obj.explainer = stub
    obj._lock = threading.Lock()
    return obj


def test_two_concurrent_explains_never_overlap_inside_shap():
    cols = ["a", "b", "c"]
    stub = ReentrancyDetectingExplainer(len(cols))
    explainer = _explainer_with(stub, cols)

    def call(v):
        explainer.explain({c: float(v) for c in cols})

    threads = [threading.Thread(target=call, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert stub.calls == 4, "every request must still be served"
    assert stub.max_concurrent == 1, (
        f"{stub.max_concurrent} threads were inside KernelExplainer at once; "
        "its per-call state on self would be interleaved between them"
    )


class StateOnSelfExplainer:
    """Mimics the specific thing that makes KernelExplainer unsafe: it
    stashes the current call's data on `self` and reads it back after
    doing work. `self.fx` in the real class is exactly this shape."""

    def __init__(self, n_features: int):
        self.expected_value = np.array([0.5])
        self._n = n_features
        self.fx = None  # same attribute name the real class uses

    def shap_values(self, x, nsamples=100, silent=True):
        self.fx = np.asarray(x, dtype=float).reshape(-1)[: self._n]
        time.sleep(0.05)  # the solver's actual work happens here
        return self.fx


def test_concurrent_callers_each_get_their_own_flows_attributions():
    """The observable consequence of the bug: caller A receiving values
    derived from caller B's feature vector."""
    cols = ["a", "b", "c"]
    stub = StateOnSelfExplainer(len(cols))
    explainer = _explainer_with(stub, cols)

    results: dict[int, list[float]] = {}

    def call(v):
        out = explainer.explain({c: float(v) for c in cols})
        results[v] = [out["shap_values"][c] for c in cols]

    threads = [threading.Thread(target=call, args=(i,)) for i in range(1, 5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for v, values in results.items():
        assert values == [float(v)] * len(cols), (
            f"caller {v} got {values}, which came from a different request"
        )


def test_the_lock_is_released_when_shap_raises():
    """A solver error must not wedge every later explain request -- the
    dashboard would go from 'one broken explanation' to 'no explanations
    at all' until restart."""
    cols = ["a", "b"]

    class Boom(ReentrancyDetectingExplainer):
        def shap_values(self, x, nsamples=100, silent=True):
            raise ValueError("solver blew up")

    explainer = _explainer_with(Boom(len(cols)), cols)
    with pytest.raises(ValueError):
        explainer.explain({c: 1.0 for c in cols})

    # A working explainer on the same lock must still get through.
    explainer.explainer = ReentrancyDetectingExplainer(len(cols), dwell=0.0)
    out = explainer.explain({c: 2.0 for c in cols})
    assert out["shap_values"]["a"] == 2.0


def test_base_value_is_read_under_the_same_lock():
    """expected_value is read off the same shared object; taking it
    outside the lock would let it be read while another call is mutating
    the explainer, pairing one flow's attributions with another's base."""
    import inspect

    src = inspect.getsource(ShapExplainer.explain)
    lock_at = src.index("with self._lock")
    assert "expected_value" in src[lock_at:], (
        "base_value must be read inside the lock block"
    )
