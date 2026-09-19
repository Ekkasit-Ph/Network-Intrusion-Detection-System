"""Train/val/test split for the unsupervised anomaly-detection setup.

Per MODEL_DEVELOPMENT.md step 5 / PROJECT.md "Train/val/test split":
- train: benign only (Autoencoder must never see attack rows while training)
- val:   remaining benign + a stratified slice of every attack class
         (used to pick hyperparameters and the detection threshold)
- test:  remaining benign + the rest of the attack rows, touched exactly
         once, at the very end, for the final reported metrics
"""

from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.model_selection import train_test_split

from source.common.constants import (
    ATTACK_COL,
    LABEL_COL,
    RANDOM_SEED,
    TEST_ATTACK_FRAC,
    TEST_BENIGN_FRAC,
    TRAIN_BENIGN_FRAC,
    VAL_ATTACK_FRAC,
    VAL_BENIGN_FRAC,
)


def split_data(
    df: pd.DataFrame,
    train_benign_frac: float = TRAIN_BENIGN_FRAC,
    val_benign_frac: float = VAL_BENIGN_FRAC,
    test_benign_frac: float = TEST_BENIGN_FRAC,
    val_attack_frac: float = VAL_ATTACK_FRAC,
    test_attack_frac: float = TEST_ATTACK_FRAC,
    seed: int = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    fracs_ok = abs(train_benign_frac + val_benign_frac + test_benign_frac - 1.0) < 1e-6
    if not fracs_ok:
        raise ValueError("train/val/test benign fractions must sum to 1.0")
    if abs(val_attack_frac + test_attack_frac - 1.0) > 1e-6:
        raise ValueError("val/test attack fractions must sum to 1.0")

    # No .reset_index() on these: sklearn's train_test_split doesn't care
    # about index values (it splits positionally), everything downstream
    # writes parquet with index=False, and the val/test concats below
    # already rebuild a clean index via ignore_index=True. Each
    # .reset_index(drop=True) is otherwise a full-frame copy for nothing --
    # on the full 16.9M-row file that's real memory for no behavioral
    # difference.
    benign_df = df[df[LABEL_COL] == 0]
    attack_df = df[df[LABEL_COL] == 1]

    # Benign: train vs (val+test), then split (val+test) into val/test.
    benign_train, benign_rest = train_test_split(
        benign_df, train_size=train_benign_frac, random_state=seed, shuffle=True,
    )
    rest_val_share = val_benign_frac / (val_benign_frac + test_benign_frac)
    benign_val, benign_test = train_test_split(
        benign_rest, train_size=rest_val_share, random_state=seed, shuffle=True,
    )

    # Attack rows: never in train. Stratify by Attack class so rare classes
    # (e.g. Ransomware < 0.1%) still get representatives in both val & test.
    class_counts = attack_df[ATTACK_COL].value_counts()
    stratifiable = attack_df[ATTACK_COL].isin(class_counts[class_counts >= 2].index)
    strat_df = attack_df[stratifiable]
    unstratifiable_df = attack_df[~stratifiable]  # singleton classes -> all go to test

    if len(strat_df):
        attack_val, attack_test = train_test_split(
            strat_df,
            train_size=val_attack_frac,
            random_state=seed,
            shuffle=True,
            stratify=strat_df[ATTACK_COL],
        )
    else:
        attack_val = strat_df.iloc[0:0]
        attack_test = strat_df.iloc[0:0]
    attack_test = pd.concat([attack_test, unstratifiable_df], ignore_index=True)

    train_df = benign_train  # index values unused downstream (see note above)
    # ignore_index=True on .sample() folds the shuffle-then-reset into one
    # allocation instead of two (.sample() followed by a separate
    # .reset_index(drop=True)).
    val_df = pd.concat([benign_val, attack_val], ignore_index=True).sample(
        frac=1.0, random_state=seed, ignore_index=True,
    )
    test_df = pd.concat([benign_test, attack_test], ignore_index=True).sample(
        frac=1.0, random_state=seed, ignore_index=True,
    )

    report = {
        "train_rows": len(train_df),
        "val_rows": len(val_df),
        "test_rows": len(test_df),
        "train_class_distribution": {"Benign": len(train_df)},
        "val_class_distribution": val_df[ATTACK_COL].value_counts().to_dict(),
        "test_class_distribution": test_df[ATTACK_COL].value_counts().to_dict(),
    }
    return train_df, val_df, test_df, report
