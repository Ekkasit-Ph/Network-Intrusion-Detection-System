import numpy as np

from source.model.threshold import curve_data, evaluate_threshold, percentile_thresholds, select_threshold


def test_percentile_thresholds_are_increasing():
    benign_errors = np.abs(np.random.default_rng(0).normal(size=1000))
    thresholds = percentile_thresholds(benign_errors, percentiles=(90, 95, 99))
    assert thresholds[90] < thresholds[95] < thresholds[99]


def test_higher_threshold_never_increases_recall():
    rng = np.random.default_rng(1)
    errors = np.concatenate([rng.normal(0, 1, 200), rng.normal(4, 1, 50)])
    labels = np.concatenate([np.zeros(200), np.ones(50)])

    low = evaluate_threshold(errors, labels, thr=1.0)
    high = evaluate_threshold(errors, labels, thr=3.0)
    assert high["recall"] <= low["recall"]
    assert high["fpr"] <= low["fpr"]


def test_select_threshold_excludes_candidates_above_the_fpr_cap():
    rng = np.random.default_rng(2)
    errors = np.concatenate([rng.normal(0, 1, 200), rng.normal(5, 1, 50)])
    labels = np.concatenate([np.zeros(200), np.ones(50)])

    candidates = [
        {"method": "percentile", "percentile": 50, "value": 0.0},   # ~50% FPR -- flags half of benign traffic
        {"method": "percentile", "percentile": 99, "value": 4.5},    # sits between the two clusters -> low FPR
    ]
    best, scored = select_threshold(candidates, errors, labels, max_fpr=0.05)
    assert best["value"] == 4.5
    assert best["metrics"]["fpr"] <= 0.05


def test_select_threshold_does_not_pick_flag_everything_despite_perfect_recall():
    """Regression test for the bug this replaced: on an attack-heavy
    validation set, an F-beta/precision-based criterion picked a
    near-zero threshold with recall=1.0 but FPR~0.5 (it "won" because
    precision looked fine purely due to attack rows outnumbering benign
    ones in validation, not because the threshold was actually useful).
    FPR-capped selection must never pick this over a real operating point."""
    rng = np.random.default_rng(3)
    # Deliberately attack-heavy, like this project's actual val/test splits
    # (~86% attack, since train takes most benign and none of the attack).
    benign_errors = rng.normal(0, 1, 100)
    attack_errors = rng.normal(3, 1.5, 600)
    errors = np.concatenate([benign_errors, attack_errors])
    labels = np.concatenate([np.zeros(100), np.ones(600)])

    candidates = [
        {"method": "kde", "percentile": None, "value": -3.0},  # flags ~everything: recall~1.0, fpr~1.0
        {"method": "percentile", "percentile": 95, "value": float(np.percentile(benign_errors, 95))},
    ]
    best, scored = select_threshold(candidates, errors, labels, max_fpr=0.05)
    assert best["value"] != -3.0
    assert best["metrics"]["fpr"] <= 0.05


def test_curve_data_is_downsampled_on_large_input():
    rng = np.random.default_rng(4)
    n = 50_000  # every value effectively unique -> sklearn would return ~n curve points
    errors = rng.normal(size=n)
    labels = rng.integers(0, 2, size=n)

    curves = curve_data(errors, labels, max_points=200)
    assert len(curves["roc"]["fpr"]) <= 200
    assert len(curves["roc"]["fpr"]) == len(curves["roc"]["tpr"]) == len(curves["roc"]["thresholds"])
    assert len(curves["pr"]["precision"]) <= 200
    assert len(curves["pr"]["precision"]) == len(curves["pr"]["recall"])


def test_curve_data_leaves_small_curves_untouched():
    errors = np.array([0.1, 0.5, 0.9, 1.5])
    labels = np.array([0, 0, 1, 1])
    curves = curve_data(errors, labels, max_points=500)
    # Nothing to downsample -- should just be whatever sklearn returned.
    assert len(curves["roc"]["fpr"]) <= 5
