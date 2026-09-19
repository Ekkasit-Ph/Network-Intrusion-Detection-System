"""Measure what module 1's `L7_PROTO` train/serve skew actually costs.

    python -m source.extraction.verify_skew
    python -m source.extraction.verify_skew --output artifacts/models/<run>/l7_skew.json

`source/extraction/README.md` documents a disagreement we cannot explain:
the training data holds `L7_PROTO = 0` (Unknown) for 2.31M of 2.37M UDP/53
flows, while our nfstream reports `"DNS"` for the same traffic and so
encodes `5.0`. Arguing about it is pointless; the question that matters is
what it does to detections, and that is measurable exactly.

It is measurable because `L7_PROTO` is **frequency-encoded** (see
`artifacts/preprocessing_*/categorical_encoders.json`). The model never
sees a protocol id -- it sees how common that id was in training,
standardized. So the skew is a pure column substitution on the frozen test
set: write the value our extractor would produce, re-score with the same
frozen model and threshold, read off the difference.

Two consequences of that encoding are worth knowing before reading the
numbers:

  * z(Unknown) = +0.44 but z(any rare id) = -2.36, while z(an id the
    encoder never saw) = -2.37. The rare ids are 0.009 apart -- i.e. the
    only distinction the model can draw from this feature is
    "Unknown vs. not". Mis-mapping one rare protocol for another is free;
    crossing the Unknown boundary costs 2.80 standard deviations.
  * That also means the mapping degrades gracefully: `l7_proto.py` knows
    492 names but the encoder only ever saw 161 values, and the 331 it
    cannot represent land within 0.009 of a correctly-mapped rare id.

The scenarios below bracket the damage rather than guessing at it. S1 is
the disagreement we actually observed; S2 assumes every Unknown row in the
data flips, which is a ceiling no realistic sensor reaches; S3 applies the
one remedy that needs neither retraining nor new data.

S4 measures a different, already-fixed skew, kept here because it is the
evidence that the fix was worth making. NFStream's byte counters default
to whole ethernet frames while nProbe wrote the training columns at the IP
layer, so before `sensor.py` set `accounting_mode=1` every byte and
packet-length column ran 14 bytes per packet high -- ten features at once,
on every single flow, not 16.5% of them.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from source.common.constants import ATTACK_COL, LABEL_COL
from source.model.dataset import load_split, make_loader
from source.model.ensemble import load_scoring_models
from source.model.inference import compute_ensemble_reconstruction_errors
from source.model.threshold import percentile_thresholds, select_threshold
from source.model.train import get_device

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

UDP_ONEHOT_COL = "PROTOCOL_17.0"
UNKNOWN_ID = 0.0
DNS_ID = 5.0


def _one_hot_mask(df: pd.DataFrame, col: str) -> np.ndarray:
    """The one-hot columns were standardized along with every other
    feature, so `== 1` matches nothing. The column still holds exactly two
    distinct values; the larger one is the 1."""
    values = df[col].to_numpy()
    distinct = np.unique(values)
    if len(distinct) != 2:
        raise RuntimeError(f"{col} has {len(distinct)} distinct values, expected a two-valued one-hot")
    return values == distinct[1]


ETHERNET_HEADER_BYTES = 14

# Byte/length columns, and how many ethernet headers each carried when
# NFStream was counting whole frames: one per packet in that direction for
# the totals, one for a single-packet measurement.
_PER_PACKET_TOTALS = {"IN_BYTES": "IN_PKTS", "OUT_BYTES": "OUT_PKTS"}
_SINGLE_PACKET_LENGTHS = ("SHORTEST_FLOW_PKT", "LONGEST_FLOW_PKT", "MAX_IP_PKT_LEN")
# Rates are IN_BYTES/OUT_BYTES over the same duration, so they inherit the
# inflation proportionally rather than by a fixed offset.
_DERIVED_RATES = {
    "SRC_TO_DST_SECOND_BYTES": "IN_BYTES", "SRC_TO_DST_AVG_THROUGHPUT": "IN_BYTES",
    "DST_TO_SRC_SECOND_BYTES": "OUT_BYTES", "DST_TO_SRC_AVG_THROUGHPUT": "OUT_BYTES",
}


class _Codec:
    """Round-trips one column between the model's space and raw NetFlow
    values. Every column touched here is log1p'd and then standardized, so
    inverting is exact rather than approximate."""

    def __init__(self, feature_cols: list[str], scaler) -> None:
        self._idx = {c: i for i, c in enumerate(feature_cols)}
        self._scaler = scaler

    def decode(self, df: pd.DataFrame, col: str) -> np.ndarray:
        i = self._idx[col]
        return np.expm1(df[col].to_numpy(dtype=np.float64) * self._scaler.scale_[i] + self._scaler.mean_[i])

    def encode(self, values: np.ndarray, col: str) -> np.ndarray:
        i = self._idx[col]
        return (np.log1p(np.clip(values, 0, None)) - self._scaler.mean_[i]) / self._scaler.scale_[i]


def assert_codec_round_trips(df: pd.DataFrame, codec: _Codec, columns: tuple[str, ...]) -> float:
    """A lossy decode/encode would quietly turn this whole measurement into
    a measurement of the codec instead. Checked rather than assumed."""
    worst = 0.0
    for col in columns:
        original = df[col].to_numpy(dtype=np.float64)
        drift = float(np.abs(codec.encode(codec.decode(df, col), col) - original).max())
        worst = max(worst, drift)
    if worst > 1e-5:  # float32 storage puts the honest floor near 1e-8
        raise RuntimeError(
            f"decode/encode is not an identity (max drift {worst:.2e}); any skew "
            f"measured through it would be partly the codec's own error"
        )
    return worst


def _apply_ethernet_framing_bug(df: pd.DataFrame, codec: _Codec) -> pd.DataFrame:
    """Re-inflate the byte columns the way NFStream's default accounting
    mode did, so the cost of that bug can be read off the same test set."""
    out = df.copy()
    raw = {c: codec.decode(df, c) for c in
           (*_PER_PACKET_TOTALS, *_PER_PACKET_TOTALS.values(), *_SINGLE_PACKET_LENGTHS,
            "MIN_IP_PKT_LEN", *_DERIVED_RATES)}

    inflated: dict[str, np.ndarray] = {}
    for col, pkt_col in _PER_PACKET_TOTALS.items():
        inflated[col] = raw[col] + ETHERNET_HEADER_BYTES * raw[pkt_col]
    for col in _SINGLE_PACKET_LENGTHS:
        inflated[col] = raw[col] + ETHERNET_HEADER_BYTES
    # MIN_IP_PKT_LEN carried a second bug: the old code reported the real
    # minimum on one-directional flows, where nProbe writes 0.
    inflated["MIN_IP_PKT_LEN"] = raw["SHORTEST_FLOW_PKT"] + ETHERNET_HEADER_BYTES
    for col, byte_col in _DERIVED_RATES.items():
        scale = np.divide(inflated[byte_col], raw[byte_col],
                          out=np.ones_like(raw[byte_col]), where=raw[byte_col] > 0)
        inflated[col] = raw[col] * scale

    for col, values in inflated.items():
        out[col] = codec.encode(values, col).astype(np.float32)
    return out


def _metrics(errors: np.ndarray, labels: np.ndarray, threshold: float) -> dict[str, Any]:
    preds = (errors > threshold).astype(int)
    tp = int(((preds == 1) & (labels == 1)).sum())
    fp = int(((preds == 1) & (labels == 0)).sum())
    fn = int(((preds == 0) & (labels == 1)).sum())
    tn = int(((preds == 0) & (labels == 0)).sum())
    return {
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "_preds": preds,
    }


def run(processed_dir: Path, artifacts_dir: Path, preprocessing_dir: Path,
        max_fpr: float = 0.05) -> dict[str, Any]:
    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    frozen_threshold = json.loads((artifacts_dir / "threshold.json").read_text())["value"]
    encoders = json.loads((preprocessing_dir / "categorical_encoders.json").read_text())
    freq_map = {float(k): v for k, v in encoders["L7_PROTO"]["freq_map"].items()}
    scaler = joblib.load(preprocessing_dir / "scaler.pkl")

    idx = feature_cols.index("L7_PROTO")
    to_z = lambda freq: float((freq - scaler.mean_[idx]) / scaler.scale_[idx])  # noqa: E731
    z_unknown = to_z(freq_map[UNKNOWN_ID])
    z_dns = to_z(freq_map[DNS_ID])
    z_unseen = to_z(0.0)  # the encoder's fallback for an id it never saw

    device = get_device()
    models = load_scoring_models(artifacts_dir, device)

    def score(df: pd.DataFrame) -> np.ndarray:
        loader = make_loader(df, feature_cols, batch_size=4096, shuffle=False, device=device)
        return compute_ensemble_reconstruction_errors(models, loader, device)

    test_df = load_split(processed_dir / "test.parquet", feature_cols)
    labels = test_df[LABEL_COL].to_numpy()
    attacks = test_df[ATTACK_COL].to_numpy()
    is_udp = _one_hot_mask(test_df, UDP_ONEHOT_COL)
    is_unknown = np.isclose(test_df["L7_PROTO"].to_numpy(), z_unknown)
    flip = is_udp & is_unknown

    log.info("test rows %d | UDP %d | Unknown %d | both (the flip set) %d (%.1f%%)",
             len(test_df), is_udp.sum(), is_unknown.sum(), flip.sum(), 100 * flip.mean())
    log.info("z: Unknown %+.3f | DNS %+.3f | never-seen id %+.3f "
             "(Unknown-vs-rare gap %.2f SD; rare-vs-unseen gap %.3f SD)",
             z_unknown, z_dns, z_unseen, abs(z_unknown - z_dns), abs(z_dns - z_unseen))

    scenarios: dict[str, np.ndarray] = {"S0_baseline": score(test_df)}

    shifted = test_df.copy()
    shifted.loc[flip, "L7_PROTO"] = np.float32(z_dns)
    scenarios["S1_our_convention"] = score(shifted)
    del shifted

    ceiling = test_df.copy()
    ceiling.loc[is_unknown, "L7_PROTO"] = np.float32(z_unseen)
    scenarios["S2_every_unknown_flips"] = score(ceiling)
    del ceiling

    codec = _Codec(feature_cols, scaler)
    round_trip_drift = assert_codec_round_trips(
        test_df, codec,
        (*_PER_PACKET_TOTALS, *_PER_PACKET_TOTALS.values(),
         *_SINGLE_PACKET_LENGTHS, "MIN_IP_PKT_LEN", *_DERIVED_RATES),
    )
    log.info("codec round-trip drift %.1e (identity within float32)", round_trip_drift)
    framed = _apply_ethernet_framing_bug(test_df, codec)
    scenarios["S4_ethernet_framing_bug"] = score(framed)
    del framed

    results = {name: _metrics(err, labels, frozen_threshold) for name, err in scenarios.items()}

    # S3: the threshold is a percentile of *benign* reconstruction errors,
    # so it is only valid for the distribution it was fitted on. Re-fit it
    # on a val set carrying the same shift -- no retraining, no new data.
    val_df = load_split(processed_dir / "val.parquet", feature_cols)
    val_labels = val_df[LABEL_COL].to_numpy()
    val_flip = _one_hot_mask(val_df, UDP_ONEHOT_COL) & np.isclose(val_df["L7_PROTO"].to_numpy(), z_unknown)
    val_df.loc[val_flip, "L7_PROTO"] = np.float32(z_dns)
    val_errors = score(val_df)
    candidates = [{"method": "percentile", "percentile": p, "value": v}
                  for p, v in percentile_thresholds(val_errors[val_labels == 0]).items()]
    best, _ = select_threshold(candidates, val_errors, val_labels, max_fpr=max_fpr)
    refit_threshold = best["value"]
    results["S3_our_convention_refit_threshold"] = _metrics(
        scenarios["S1_our_convention"], labels, refit_threshold)

    baseline_preds = results["S0_baseline"]["_preds"]
    report: dict[str, Any] = {
        "flip_set_rows": int(flip.sum()),
        "flip_set_fraction": float(flip.mean()),
        "encoding": {
            "z_unknown": z_unknown, "z_dns": z_dns, "z_never_seen": z_unseen,
            "unknown_vs_rare_sd": abs(z_unknown - z_dns),
            "rare_vs_unseen_sd": abs(z_dns - z_unseen),
            "encoder_known_values": len(freq_map),
        },
        "codec_round_trip_drift": round_trip_drift,
        "frozen_threshold": frozen_threshold,
        "refit_threshold": refit_threshold,
        "scenarios": {},
    }

    for name, m in results.items():
        preds = m.pop("_preds")
        report["scenarios"][name] = {
            **m,
            "recall_delta_pts": m["recall"] - results["S0_baseline"]["recall"],
            "fpr_delta_pts": m["fpr"] - results["S0_baseline"]["fpr"],
            "predictions_changed": int((preds != baseline_preds).sum()),
            "per_class_detection_rate": {
                str(c): float(preds[attacks == c].mean()) for c in sorted(set(attacks[labels == 1]))
            },
        }
        log.info("%-34s recall %7.2f%%  FPR %5.2f%%  precision %6.2f%%",
                 name, 100 * m["recall"], 100 * m["fpr"], 100 * m["precision"])

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--processed-dir", type=Path, default=Path("data/processed_w50"))
    parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts/models/optuna-denoising-50"))
    parser.add_argument("--preprocessing-dir", type=Path, default=Path("artifacts/preprocessing_w50"))
    parser.add_argument("--max-fpr", type=float, default=0.05,
                        help="Cap used when re-fitting the threshold in scenario S3")
    parser.add_argument("--output", type=Path, default=None, help="Write the full report as JSON")
    args = parser.parse_args()

    report = run(args.processed_dir, args.artifacts_dir, args.preprocessing_dir, args.max_fpr)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2))
        log.info("Wrote %s", args.output)


if __name__ == "__main__":
    main()
