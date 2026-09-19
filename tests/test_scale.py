import numpy as np

from source.preprocessing.scale import fit_scaler, transform


def test_scaler_fit_on_train_only_matches_manual_standardization(raw_df):
    feature_cols = ["IN_BYTES", "OUT_BYTES"]
    train = raw_df.iloc[:80]
    val = raw_df.iloc[80:]

    scaler = fit_scaler(train, feature_cols)
    train_scaled = transform(train, scaler, feature_cols)
    val_scaled = transform(val, scaler, feature_cols)

    # train features should be ~standardized (mean 0, std 1)
    assert abs(train_scaled["IN_BYTES"].mean()) < 1e-6
    assert abs(train_scaled["IN_BYTES"].std(ddof=0) - 1.0) < 1e-6

    # val is transformed with train's statistics, not re-fit -> its mean
    # need not be 0 unless train and val happen to share distribution
    manual = (val["IN_BYTES"] - train["IN_BYTES"].mean()) / train["IN_BYTES"].std(ddof=0)
    assert np.allclose(val_scaled["IN_BYTES"].to_numpy(), manual.to_numpy(), atol=1e-6)
