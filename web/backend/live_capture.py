"""Live detection: capture -> features -> model -> dashboard.

This is what `replay_demo.py` stands in for. Same destination (the SQLite
DB the dashboard reads), same frozen model and threshold, but the flows
come off a network interface or a pcap instead of out of the held-out test
split, and every feature is computed rather than looked up.

    python -m web.backend.live_capture --source eth0
    python -m web.backend.live_capture --source capture.pcap --rate 5

Live capture needs packet-capture privileges; reading a pcap needs none:

    sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python)")"

The chain it wires together, and where each link is defined:

    module 1  source/extraction/sensor.py    NFStream -> 43 raw NetFlow columns
    module 2  source/preprocessing/online.py rolling features, encoders, scaler
    module 3  source/model/inference.py      reconstruction error vs threshold
    module 5  web/backend/database.py        row the dashboard polls

Two things worth knowing before trusting what appears on the dashboard.

**The threshold may need re-fitting.** It is a percentile of benign
reconstruction errors, valid only for the distribution it was fitted on.
`source/extraction/README.md` documents a measured L7_PROTO disagreement
between what nProbe wrote for DNS traffic and what our nDPI reports, which
pushes FPR from 4.97% to 5.44% -- past the project's 5% ceiling -- unless
the threshold is re-fitted on a val set carrying the same shift. Pass
`--threshold` to use a re-fitted one; the default is the frozen value and
is logged as such, never silently.

**No ground truth.** Replayed rows carry the true label, so the dashboard's
dev mode can show whether a detection was right. Live flows have no such
column and nothing is written to `replay_ground_truth` -- an unverifiable
detection must not be dressed up as a verified one.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

from source.common import paths
from source.model.ensemble import load_scoring_models
from source.model.train import get_device
from source.preprocessing.engineer_features import DEFAULT_WINDOW
from source.preprocessing.online import DEFAULT_MAX_TRACKED_KEYS, OnlineFeaturePipeline
from web.backend import database
from web.database.initialize_database import initialize_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

_PROTOCOL_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


@torch.no_grad()
def score_one(models: list, features: dict[str, float], feature_cols: list[str],
              device: torch.device) -> float:
    """Mean reconstruction error across the ensemble -- the same quantity
    threshold.py and evaluate.py score with, so a live number is directly
    comparable to a reported one."""
    x = torch.tensor([[features[c] for c in feature_cols]], dtype=torch.float32, device=device)
    errors = []
    for model in models:
        x_hat, _ = model(x)
        errors.append(float(torch.nn.functional.mse_loss(x_hat, x, reduction="none").mean().item()))
    return float(np.mean(errors))


def run(
    source: str,
    processed_dir: Path,
    artifacts_dir: Path,
    preprocessing_dir: Path,
    db_path: Path,
    threshold_override: float | None = None,
    window: int = DEFAULT_WINDOW,
    max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS,
    limit: int | None = None,
    rate: float = 0.0,
    idle_timeout: int = 15,
    active_timeout: int = 120,
) -> dict[str, int]:
    from source.extraction.sensor import extract  # imported here so --help works without nfstream

    if not db_path.exists():
        log.info("No DB at %s yet, initializing from schema...", db_path)
        initialize_database(db_path)

    pipeline = OnlineFeaturePipeline(processed_dir, preprocessing_dir,
                                     window=window, max_tracked_keys=max_tracked_keys)
    device = get_device()
    models = load_scoring_models(artifacts_dir, device)
    for model in models:
        model.eval()

    frozen = json.loads((artifacts_dir / "threshold.json").read_text())
    threshold = frozen["value"] if threshold_override is None else threshold_override
    if threshold_override is None:
        log.warning(
            "Using the frozen threshold %.9f. It was fitted on the training distribution, and "
            "the measured L7_PROTO skew puts FPR at 5.44%% with it -- past this project's 5%% "
            "ceiling. See source/extraction/README.md.",
            threshold,
        )
        # Telling the operator to "use a re-fitted threshold" without saying
        # where one comes from is not advice, it is a dead end. verify_skew.py
        # computes it; if that report is sitting next to the model, name the
        # number so the fix is a copy-paste rather than a research project.
        report = artifacts_dir / "l7_skew.json"
        if report.exists():
            try:
                refit = json.loads(report.read_text())["refit_threshold"]
                log.warning("    A re-fitted threshold is available: --threshold %.9f  (from %s)",
                            refit, report)
            except (KeyError, ValueError):
                pass
        else:
            log.warning("    Produce one with:  python -m source.extraction.verify_skew "
                        "--output %s", report)
    else:
        log.info("Using supplied threshold %.9f (frozen value was %.9f)", threshold, frozen["value"])

    log.info("Capturing from %s (%d model(s), device=%s, window=%d)...",
             source, len(models), device, window)

    delay = 1.0 / rate if rate > 0 else 0.0
    counts = {"flows": 0, "anomalies": 0}
    try:
        with database.get_connection(db_path) as conn:
            for row in extract(source, idle_timeout=idle_timeout, active_timeout=active_timeout):
                features = pipeline.transform(row)
                error = score_one(models, features, pipeline.feature_cols, device)
                is_anomaly = error > threshold

                counts["flows"] += 1
                counts["anomalies"] += int(is_anomaly)

                database.insert_flow(
                    conn,
                    flow_id=f"live-{uuid.uuid4().hex[:12]}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    # Identifiers are stored for the dashboard only; the
                    # model never saw them (see PROJECT.md's constraint and
                    # engineer_features.py on why).
                    src_ip=row["IPV4_SRC_ADDR"],
                    dst_ip=row["IPV4_DST_ADDR"],
                    src_port=int(row["L4_SRC_PORT"]),
                    dst_port=int(row["L4_DST_PORT"]),
                    protocol=_PROTOCOL_NAMES.get(int(row["PROTOCOL"]), f"proto-{int(row['PROTOCOL'])}"),
                    reconstruction_error=error,
                    threshold_used=threshold,
                    is_anomaly=is_anomaly,
                    features=features,
                )
                # Nothing is written to replay_ground_truth: a live flow has
                # no label, and inventing one would make the dashboard's dev
                # mode lie about accuracy.

                log.info(
                    "[%5d] %-15s:%-5d -> %-15s:%-5d %-5s  error=%.6f  %s",
                    counts["flows"], row["IPV4_SRC_ADDR"], row["L4_SRC_PORT"],
                    row["IPV4_DST_ADDR"], row["L4_DST_PORT"],
                    _PROTOCOL_NAMES.get(int(row["PROTOCOL"]), row["PROTOCOL"]),
                    error, "ANOMALY" if is_anomaly else "normal",
                )
                if delay:
                    time.sleep(delay)
                if limit and counts["flows"] >= limit:
                    break
    except KeyboardInterrupt:
        log.info("Stopped by user.")
    except PermissionError:
        log.error(
            "Live capture needs packet-capture privileges. Run as root, or grant them once:\n"
            "    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))"
        )
        raise SystemExit(1)

    rate_pct = 100 * counts["anomalies"] / counts["flows"] if counts["flows"] else 0.0
    log.info("Done. %d flow(s), %d flagged anomalous (%.1f%%). Tracking %d source(s), "
             "%d destination(s); %d key(s) evicted, %d non-finite input(s).",
             counts["flows"], counts["anomalies"], rate_pct,
             pipeline.state.tracked_sources, pipeline.state.tracked_destinations,
             pipeline.state.evictions, pipeline.non_finite_inputs)
    return counts


def main() -> None:
    default_processed_dir = Path(os.environ.get("NIDS_PROCESSED_DIR", str(paths.PROCESSED_DATA_DIR)))
    default_artifacts_dir = Path(os.environ.get("NIDS_MODEL_DIR", str(paths.DEFAULT_MODEL_DIR)))

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, help="Interface name (live) or path to a .pcap file")
    parser.add_argument("--processed-dir", type=Path, default=default_processed_dir)
    parser.add_argument("--artifacts-dir", type=Path, default=default_artifacts_dir)
    parser.add_argument("--preprocessing-dir", type=Path, default=None,
                        help="Where scaler.pkl and categorical_encoders.json live "
                             "(default: artifacts/preprocessing_<processed dir suffix>)")
    parser.add_argument("--db-path", type=Path, default=database.DEFAULT_DB_PATH)
    parser.add_argument("--threshold", type=float, default=None,
                        help="Override the frozen detection threshold -- use a value re-fitted "
                             "for live traffic, see this module's docstring")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW,
                        help="Trailing window for the behavioral features; must match the one "
                             "preprocessing was run with, or those three features mean something else")
    parser.add_argument("--max-tracked-keys", type=int, default=DEFAULT_MAX_TRACKED_KEYS)
    parser.add_argument("--limit", type=int, default=None, help="Stop after N flows")
    parser.add_argument("--rate", type=float, default=0.0,
                        help="Throttle to N flows/sec (0 = as fast as they arrive). Useful when "
                             "replaying a pcap, which otherwise finishes before anyone can watch")
    parser.add_argument("--idle-timeout", type=int, default=15)
    parser.add_argument("--active-timeout", type=int, default=120)
    args = parser.parse_args()

    preprocessing_dir = args.preprocessing_dir
    if preprocessing_dir is None:
        # data/processed_w50 -> artifacts/preprocessing_w50, so the pairing
        # that preprocessing produced stays together by default rather than
        # being re-specified (and eventually mis-specified) by hand.
        suffix = args.processed_dir.name.removeprefix("processed")
        preprocessing_dir = paths.ARTIFACTS_DIR / f"preprocessing{suffix}"
        log.info("Using preprocessing artifacts from %s", preprocessing_dir)

    run(
        source=args.source,
        processed_dir=args.processed_dir,
        artifacts_dir=args.artifacts_dir,
        preprocessing_dir=preprocessing_dir,
        db_path=args.db_path,
        threshold_override=args.threshold,
        window=args.window,
        max_tracked_keys=args.max_tracked_keys,
        limit=args.limit,
        rate=args.rate,
        idle_timeout=args.idle_timeout,
        active_timeout=args.active_timeout,
    )


if __name__ == "__main__":
    main()


