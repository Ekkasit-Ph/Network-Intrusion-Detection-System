"""Feature scaling: fit on train only, reuse everywhere else.

Fitting a second time on val/test/inference data would leak distribution
information into evaluation and is explicitly forbidden by both
PROJECT.md and MODEL_DEVELOPMENT.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import joblib
import pandas as pd
from sklearn.preprocessing import RobustScaler, StandardScaler

ScalerKind = Literal["standard", "robust"]


def fit_scaler(df: pd.DataFrame, feature_cols: list[str], kind: ScalerKind = "standard"):
    scaler = StandardScaler() if kind == "standard" else RobustScaler()
    scaler.fit(df[feature_cols])
    return scaler


def transform(df: pd.DataFrame, scaler, feature_cols: list[str]) -> pd.DataFrame:
    df = df.copy()
    df[feature_cols] = scaler.transform(df[feature_cols])
    return df


def save_scaler(scaler, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, path)


def load_scaler(path: str | Path):
    return joblib.load(path)
