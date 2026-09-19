import numpy as np

from source.model.evaluate import resample_to_benign_fraction


def test_resample_to_benign_fraction_hits_target_ratio_when_attack_is_scarce():
    # 100 benign, only 20 attack -> attack is the limiting class
    labels = np.array([0] * 100 + [1] * 20)
    idx = resample_to_benign_fraction(labels, benign_fraction=0.5, seed=0)
    sub = labels[idx]
    assert (sub == 1).sum() == 20  # all attack rows kept (it's the scarce class)
    assert (sub == 0).sum() == 20  # benign downsampled to match
    assert abs((sub == 0).mean() - 0.5) < 1e-9


def test_resample_to_benign_fraction_hits_target_ratio_when_benign_is_scarce():
    # This project's actual val/test shape: benign is the scarce class.
    labels = np.array([0] * 50 + [1] * 500)
    idx = resample_to_benign_fraction(labels, benign_fraction=0.5, seed=0)
    sub = labels[idx]
    assert (sub == 0).sum() == 50  # all benign rows kept
    assert (sub == 1).sum() == 50  # attack downsampled to match
    assert abs((sub == 0).mean() - 0.5) < 1e-9


def test_resample_never_duplicates_rows():
    labels = np.array([0] * 30 + [1] * 300)
    idx = resample_to_benign_fraction(labels, benign_fraction=0.5, seed=1)
    assert len(idx) == len(set(idx.tolist()))  # every index appears at most once


def test_resample_rejects_degenerate_fractions():
    labels = np.array([0, 0, 1, 1])
    for bad in (0.0, 1.0, -0.1, 1.5):
        try:
            resample_to_benign_fraction(labels, benign_fraction=bad)
            assert False, f"expected ValueError for benign_fraction={bad}"
        except ValueError:
            pass
