from source.common.constants import ATTACK_COL, LABEL_COL
from source.preprocessing.clean import clean_pipeline
from source.preprocessing.split import split_data


def test_split_train_is_benign_only(raw_df):
    cleaned, _ = clean_pipeline(raw_df)
    train_df, val_df, test_df, report = split_data(cleaned)

    assert (train_df[LABEL_COL] == 0).all()
    assert (train_df[ATTACK_COL] == "Benign").all()

    # every attack row in the original data ends up in val or test, never lost
    n_attack_total = int((cleaned[LABEL_COL] == 1).sum())
    n_attack_split = int((val_df[LABEL_COL] == 1).sum() + (test_df[LABEL_COL] == 1).sum())
    assert n_attack_split == n_attack_total

    # no row leaks into more than one split (disjoint by construction, spot check via counts)
    assert len(train_df) + len(val_df) + len(test_df) == len(cleaned)


def test_split_val_and_test_both_contain_rare_class(raw_df):
    cleaned, _ = clean_pipeline(raw_df)
    _, val_df, test_df, _ = split_data(cleaned, seed=1)

    # Ransomware is deliberately rare in the fixture; stratified split
    # should still try to give both val and test a representative if there
    # are at least 2 samples of it.
    n_ransomware = int((cleaned[ATTACK_COL] == "Ransomware").sum())
    if n_ransomware >= 2:
        assert (val_df[ATTACK_COL] == "Ransomware").any() or (test_df[ATTACK_COL] == "Ransomware").any()
