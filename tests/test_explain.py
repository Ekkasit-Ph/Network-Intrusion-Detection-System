"""Tests for module 4's explainer (source/explain/shap_explainer.py).

The router that serves explanations is covered in test_explain_router.py;
this file is about the piece underneath it, and specifically about the
background set.

That set is the model's definition of "normal" -- SHAP attributes a flow's
reconstruction error relative to it -- so it has to be a uniform draw from
the benign training rows. It used to get that for free by reading the split
into pandas and calling .sample(100), which cost 2,054 MB of resident
memory to keep 18 KB and put the serving footprint out of reach of a
small board. The streaming reservoir that replaced it has to earn the same
property, so these tests check the distribution rather than trusting the
implementation.
"""

from __future__ import annotations

# ── background sampling ───────────────────────────────────────────────────

def test_background_sample_is_uniform_over_benign_rows(tmp_path):
    """The background set must be a uniform draw from the benign training
    rows. Reading the split whole and calling .sample() gave that for free
    but cost 2 GB of RSS to keep 18 KB; the streaming reservoir has to earn
    it, so this checks the distribution rather than trusting the algorithm.
    """
    import numpy as np
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq

    from source.common.constants import LABEL_COL
    from source.explain.shap_explainer import _sample_benign_background

    n_benign, keep, trials = 200, 20, 1500
    path = tmp_path / "train.parquet"
    frame = pd.DataFrame({
        "f0": list(range(n_benign)) + [-999] * 100,
        LABEL_COL: [0] * n_benign + [1] * 100,
    })
    # Several row groups, so iter_batches really does cross batch boundaries
    # -- the reservoir's index bookkeeping is what could go wrong there.
    pq.write_table(pa.Table.from_pandas(frame), path, row_group_size=37)

    counts = np.zeros(n_benign, dtype=int)
    for seed in range(trials):
        drawn = _sample_benign_background(path, ["f0"], keep, seed).ravel().astype(int)
        assert drawn.shape == (keep,)
        assert -999 not in drawn, "an attack-labelled row reached the background set"
        counts[drawn] += 1

    expected = trials * keep / n_benign
    # Binomial spread; 5 sigma is loose enough never to flake and tight
    # enough to catch an index-off-by-one that skews toward either end.
    sigma = (trials * (keep / n_benign) * (1 - keep / n_benign)) ** 0.5
    assert abs(counts.mean() - expected) < sigma
    assert counts.min() > expected - 5 * sigma
    assert counts.max() < expected + 5 * sigma


def test_background_sample_smaller_than_requested(tmp_path):
    """Fewer benign rows than asked for is not an error -- the background is
    just smaller. Returning a half-filled array of zeros would silently
    teach SHAP that normal traffic is all-zeros."""
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq

    from source.common.constants import LABEL_COL
    from source.explain.shap_explainer import _sample_benign_background

    path = tmp_path / "tiny.parquet"
    pq.write_table(pa.Table.from_pandas(
        pd.DataFrame({"f0": [1.0, 2.0, 3.0], LABEL_COL: [0, 0, 1]})), path)

    background = _sample_benign_background(path, ["f0"], 100, seed=0)
    assert background.shape == (2, 1)
    assert sorted(background.ravel().tolist()) == [1.0, 2.0]


# ── sampling budget ───────────────────────────────────────────────────────

def test_explain_defaults_to_the_converged_sampling_budget():
    """The number of coalitions Kernel SHAP samples is the difference
    between an explanation and a draw from a distribution. At the old
    default of 100, 75% of features changed sign between two runs on the
    same flow and the top-5 matched a converged reference 25% of the time --
    a dashboard showing that is showing noise with a legend.

    This pins the default reaching shap, and that an explicit argument still
    wins, without paying for a real explain: the arithmetic is checked in
    scripts/evaluate_explanations.py, the wiring is checked here.
    """
    import numpy as np

    from source.explain import shap_explainer as module

    seen: list[int] = []

    class RecordingKernelExplainer:
        expected_value = 0.0

        def shap_values(self, x, nsamples, silent):  # noqa: ARG002
            seen.append(nsamples)
            return np.zeros((1, x.shape[1]), dtype=np.float64)

    explainer = module.ShapExplainer.__new__(module.ShapExplainer)
    explainer.feature_cols = ["A", "B"]
    explainer.explainer = RecordingKernelExplainer()
    explainer._lock = __import__("threading").Lock()

    explainer.explain({"A": 0.0, "B": 0.0})
    explainer.explain({"A": 0.0, "B": 0.0}, nsamples=250)

    assert seen == [module.DEFAULT_NSAMPLES, 250]
    assert module.DEFAULT_NSAMPLES >= 1000, (
        "below ~1000 the attributions do not converge; see "
        "documentation/explanation-quality.md"
    )
