"""Demo data feeder: replays real (held-out, touched-once) test-set flows
through the frozen model at a controlled pace, writing detections into the
SQLite DB as if they were arriving live.

Live capture now exists — see `web/backend/live_capture.py`. Replay is kept
because it is the only feeder with *ground truth*: every row is a labelled
held-out test flow, so the dashboard's dev mode can show whether a detection
was actually right. Live traffic carries no labels and never will.

It is not fabricated: every row is a genuine test-set flow scored by the
frozen model, on exactly the path evaluate.py uses. The synthetic parts are
cosmetic — src/dst IP and port, since those columns are stripped before the
model sees a row (PROJECT.md's constraint). Say plainly in the demo which
feeder is running; replay is labelled data replayed, not live capture.

    python -m web.backend.replay_demo --n-flows 500 --rate 2.0

Ctrl+C stops cleanly at any point; already-inserted flows stay in the DB.
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
from source.common.constants import ATTACK_COL, LABEL_COL
from source.model.evaluate import resample_to_benign_fraction
from source.model.dataset import load_split, make_loader
from source.model.ensemble import load_scoring_models
from source.model.inference import compute_ensemble_reconstruction_errors
from source.model.train import get_device
from web.backend import database
from web.database.initialize_database import initialize_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

_PROTOCOL_NAMES = {1.0: "ICMP", 2.0: "IGMP", 6.0: "TCP", 17.0: "UDP", 58.0: "ICMPv6"}
_DEMO_SRC_IPS = [f"192.168.1.{i}" for i in range(10, 60)]
_DEMO_DST_IPS = [f"10.0.0.{i}" for i in range(1, 30)]


def _protocol_columns(feature_cols: list[str]) -> list[tuple[str, float]]:
    """[(column_name, protocol_code), ...] for the one-hot PROTOCOL_* columns."""
    out = []
    for col in feature_cols:
        if col.startswith("PROTOCOL_"):
            out.append((col, float(col.removeprefix("PROTOCOL_"))))
    return out


def _guess_protocol_name(row: dict, protocol_cols: list[tuple[str, float]]) -> str:
    """Argmax across the (standardized) one-hot PROTOCOL_* columns for this
    row -- cosmetic only, for a readable dashboard column; not used by the
    model or the detection decision."""
    if not protocol_cols:
        return "N/A"
    best_col, best_code = max(protocol_cols, key=lambda pc: row[pc[0]])
    return _PROTOCOL_NAMES.get(best_code, f"proto-{best_code:.0f}")


DEFAULT_BENIGN_FRACTION = 0.98


def run(
    processed_dir: Path,
    artifacts_dir: Path,
    db_path: Path,
    n_flows: int = 500,
    rate: float = 2.0,
    seed: int = 0,
    loop: bool = False,
    benign_fraction: float | None = DEFAULT_BENIGN_FRACTION,
    reset: bool = False,
) -> None:
    if not db_path.exists():
        log.info("No DB at %s yet, initializing from schema...", db_path)
        initialize_database(db_path)
    if reset:
        with database.get_connection(db_path) as conn:
            removed = database.clear_flows(conn)
        log.info("Cleared previous data: %s",
                 ", ".join(f"{n} {t}" for t, n in removed.items() if n))

    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    threshold = json.loads((artifacts_dir / "threshold.json").read_text())
    device = get_device()
    models = load_scoring_models(artifacts_dir, device)
    log.info("Loaded %d model(s) for scoring (device=%s)", len(models), device)

    test_df = load_split(processed_dir / "test.parquet", feature_cols)

    # The test split is ~86% attack by construction -- it was built to
    # measure detection, not to look like a network. Replaying it straight
    # puts the dashboard's anomaly rate near 80%, which is not what an
    # operator would ever see and quietly flatters the model: at that base
    # rate almost anything flagged really is an attack.
    #
    # Downsampling to `benign_fraction` uses the same helper evaluate.py
    # uses for metrics_report_realistic95.json, so "realistic mix" means one
    # thing across the project. It only ever *removes* rows -- every flow
    # shown is still a genuine, correctly-labelled test flow.
    #
    # Worth saying out loud when demonstrating this: at 98% benign the
    # arithmetic is 0.98 x 4.97% FPR = 4.9% of all flows flagged wrongly
    # against 0.02 x 87.6% recall = 1.8% flagged rightly, so most alerts on
    # the screen are false positives. That is the base-rate effect, it is
    # what makes the 5% FPR ceiling the number that mattered, and hiding it
    # behind an attack-heavy replay would be the more misleading choice.
    if benign_fraction is not None:
        labels = test_df[LABEL_COL].to_numpy()
        keep = resample_to_benign_fraction(labels, benign_fraction, seed=seed)
        test_df = test_df.iloc[keep].reset_index(drop=True)
        actual = float((test_df[LABEL_COL] == 0).mean())
        log.info("Resampled the test split to %.1f%% benign (%.1f%% actual, %d rows available)",
                 100 * benign_fraction, 100 * actual, len(test_df))
    else:
        log.info("Using the test split's natural mix (%.1f%% benign) -- not a realistic base rate",
                 100 * float((test_df[LABEL_COL] == 0).mean()))

    protocol_cols = _protocol_columns(feature_cols)
    delay = 1.0 / rate if rate > 0 else 0.0

    # --loop exists so a presenter never has to compute n_flows * (1/rate)
    # against "however long the exam Q&A runs" -- it just keeps replaying
    # fresh (differently-sampled, via pass_i in the seed) batches until
    # killed. Ctrl+C stops cleanly between flows either way; already
    # -inserted rows stay in the DB regardless of how a pass ends.
    pass_i = 0
    while True:
        sample = test_df.sample(n=min(n_flows, len(test_df)), random_state=seed + pass_i).reset_index(drop=True)

        loader = make_loader(sample, feature_cols, batch_size=512, shuffle=False, device=device)
        errors = compute_ensemble_reconstruction_errors(models, loader, device)
        preds = errors > threshold["value"]

        rng = np.random.default_rng(seed + pass_i)
        log.info(
            "Replaying %d flows at %.1f flows/sec (threshold=%.6f)%s...",
            len(sample), rate, threshold["value"], f" [pass {pass_i + 1}]" if loop else "",
        )
        n_anomaly = 0
        with database.get_connection(db_path) as conn:
            for i in range(len(sample)):
                row = sample.iloc[i]
                row_dict = {c: float(row[c]) for c in feature_cols}
                flow_id = f"demo-{uuid.uuid4().hex[:12]}"
                timestamp = datetime.now(timezone.utc).isoformat()
                is_anomaly = bool(preds[i])
                n_anomaly += int(is_anomaly)

                database.insert_flow(
                    conn,
                    flow_id=flow_id,
                    timestamp=timestamp,
                    src_ip=str(rng.choice(_DEMO_SRC_IPS)),
                    dst_ip=str(rng.choice(_DEMO_DST_IPS)),
                    src_port=int(rng.integers(1024, 65535)),
                    dst_port=int(rng.choice([80, 443, 22, 21, 23, 3389, 8080])),
                    protocol=_guess_protocol_name(row_dict, protocol_cols),
                    reconstruction_error=float(errors[i]),
                    threshold_used=float(threshold["value"]),
                    is_anomaly=is_anomaly,
                    features=row_dict,
                )

                # These rows come from the labelled test split, so record
                # what each one actually was. That turns the dashboard into
                # something you can *check* during development ("it flagged
                # this, and it really was scanning") instead of only
                # something you can watch. Nothing outside replay writes
                # here -- see schema.sql's note on the table.
                database.insert_ground_truth(
                    conn,
                    flow_id=flow_id,
                    true_label=int(row[LABEL_COL]),
                    true_attack=str(row[ATTACK_COL]),
                )

                true_label = "attack" if row[LABEL_COL] == 1 else "benign"
                true_attack = row[ATTACK_COL]
                flag = "ANOMALY" if is_anomaly else "normal "
                correct = "correct" if is_anomaly == (row[LABEL_COL] == 1) else "MISS"
                log.info(
                    "[%4d/%4d] %s  error=%.5f  true=%-7s (%-10s)  %s  %-7s",
                    i + 1, len(sample), flow_id, errors[i], true_label, true_attack, flag, correct,
                )
                if delay:
                    time.sleep(delay)

        log.info("Done. %d/%d flows flagged anomalous (%.1f%%).", n_anomaly, len(sample), 100 * n_anomaly / len(sample))
        if not loop:
            break
        pass_i += 1


def main() -> None:
    # Same NIDS_MODEL_DIR / NIDS_PROCESSED_DIR env vars web/backend/main.py
    # reads -- so running this against whatever model the backend actually
    # has loaded doesn't require repeating --processed-dir/--artifacts-dir
    # by hand (and doesn't silently point at data/processed/'s 39-feature
    # schema when the running backend is serving a 46-feature model, e.g.
    # in the Docker image, which only bakes in data/processed_w50/).
    default_processed_dir = Path(os.environ.get("NIDS_PROCESSED_DIR", str(paths.PROCESSED_DATA_DIR)))
    default_artifacts_dir = Path(os.environ.get("NIDS_MODEL_DIR", str(paths.DEFAULT_MODEL_DIR)))

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=default_processed_dir)
    parser.add_argument("--artifacts-dir", type=Path, default=default_artifacts_dir)
    parser.add_argument("--db-path", type=Path, default=database.DEFAULT_DB_PATH)
    parser.add_argument("--n-flows", type=int, default=500)
    parser.add_argument("--rate", type=float, default=2.0, help="Flows per second (0 = as fast as possible)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--benign-fraction", type=float, default=DEFAULT_BENIGN_FRACTION,
        help="Share of replayed flows that should be benign (default %(default)s). The test "
             "split is ~86%% attack because it was built to measure detection, not to resemble "
             "a network; this downsamples it to something an operator would recognise. Rows are "
             "only removed, never invented")
    parser.add_argument(
        "--natural-mix", action="store_true",
        help="Replay the test split's own attack-heavy mix instead of resampling")
    parser.add_argument(
        "--reset", action="store_true",
        help="Empty flows, ground truth, explanations and firewall checks before replaying")
    parser.add_argument(
        "--loop", action="store_true",
        help="Keep replaying fresh batches indefinitely instead of stopping after --n-flows -- "
             "for a live presentation, so the dashboard never goes quiet mid-demo just because "
             "n_flows/rate ran out before the audience Q&A did. Ctrl+C to stop.",
    )
    args = parser.parse_args()
    run(args.processed_dir, args.artifacts_dir, args.db_path, args.n_flows, args.rate,
        args.seed, args.loop,
        benign_fraction=None if args.natural_mix else args.benign_fraction,
        reset=args.reset)


if __name__ == "__main__":
    main()
