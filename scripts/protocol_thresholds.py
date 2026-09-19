"""Does a per-protocol detection threshold beat one global threshold?

The resource and dataset work found the model calibrated differently for
TCP than for UDP: at the deployed threshold, benign TCP is flagged 4.65% of
the time and benign UDP 6.69%. One cut point is being asked to serve two
populations whose reconstruction-error distributions do not line up, so UDP
spends more of the false-positive budget than its share and the classes
that live there (dos is 85.5% UDP) pay for it in recall.

Three policies, all fitted on validation and then applied unchanged to
test:

    global      one threshold, the deployed policy -- the baseline
    equal-fpr   each protocol cut at its own 95th benign percentile
    budgeted    the 5% budget split across protocols to maximise recall

`budgeted` is the one worth the trouble. Equalising FPR per protocol sounds
principled but is not optimal: the budget should go where it buys the most
detections, which is a Lagrangian allocation, not an equal one.

    python -m scripts.protocol_thresholds

Nothing here refits the model, and no threshold is chosen using test data.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from source.common import paths  # noqa: E402
from source.common.constants import LABEL_COL  # noqa: E402

DEFAULT_OUTPUT = paths.ARTIFACTS_DIR / "protocol-thresholds.json"
ATTACK_COL = "Attack"


def score_split(path: Path, feature_cols: list[str], models, device,
                batch_rows: int = 200_000) -> dict[str, np.ndarray]:
    """Reconstruction error, label, attack name and protocol group for every
    row, read in batches so a 6.3M-row split never lands in memory at once."""
    import pyarrow.parquet as pq
    import torch

    proto_cols = [c for c in feature_cols if c.startswith("PROTOCOL_")]
    wanted = feature_cols + [LABEL_COL, ATTACK_COL]
    errors, labels, attacks, protos = [], [], [], []

    for batch in pq.ParquetFile(path).iter_batches(batch_size=batch_rows, columns=wanted):
        frame = batch.to_pandas()
        x = frame[feature_cols].to_numpy(dtype=np.float32)
        with torch.no_grad():
            tensor = torch.from_numpy(x).to(device)
            per_model = []
            for model in models:
                out, _ = model(tensor)
                per_model.append(
                    torch.nn.functional.mse_loss(out, tensor, reduction="none")
                    .mean(dim=1).cpu().numpy())
        errors.append(np.mean(per_model, axis=0))
        labels.append(frame[LABEL_COL].to_numpy())
        attacks.append(frame[ATTACK_COL].to_numpy())
        # One-hot columns are standardized, so "is this protocol set" is
        # "is it above the midpoint of its two values" rather than "== 1".
        block = frame[proto_cols].to_numpy(dtype=np.float32)
        protos.append(np.array([c.replace("PROTOCOL_", "") for c in proto_cols])[block.argmax(axis=1)])

    return {
        "error": np.concatenate(errors),
        "label": np.concatenate(labels),
        "attack": np.concatenate(attacks),
        "protocol": np.concatenate(protos),
    }


def group_protocols(raw: np.ndarray, keep: tuple[str, ...] = ("6.0", "17.0")) -> np.ndarray:
    """TCP and UDP separately, everything else together. ICMP and the rest
    are 0.04% of the test split -- too few to fit a threshold on without
    fitting to noise, and splitting them out would buy nothing."""
    names = {"6.0": "tcp", "17.0": "udp"}
    return np.array([names.get(p, "other") for p in raw])


# ── policies ──────────────────────────────────────────────────────────────

def fit_global(val: dict[str, np.ndarray], max_fpr: float) -> dict[str, float]:
    benign = val["error"][val["label"] == 0]
    return {"__all__": float(np.quantile(benign, 1 - max_fpr))}


def fit_equal_fpr(val: dict[str, np.ndarray], groups: np.ndarray,
                  max_fpr: float) -> dict[str, float]:
    out = {}
    for g in np.unique(groups):
        benign = val["error"][(val["label"] == 0) & (groups == g)]
        out[g] = float(np.quantile(benign, 1 - max_fpr)) if len(benign) else float("inf")
    return out


def fit_budgeted(val: dict[str, np.ndarray], groups: np.ndarray, max_fpr: float,
                 grid_size: int = 4000) -> dict[str, float]:
    """Spend the false-positive budget where it buys the most detections.

    For a price lambda on false positives, each protocol independently picks
    the threshold maximising TP - lambda*FP; sweeping lambda traces the
    optimal frontier, and bisection finds the lambda whose total FP lands on
    the budget. Equalising FPR per protocol is the special case where every
    protocol happens to have the same marginal return, which these do not.

    Bisection alone leaves budget unspent -- the argmax jumps between grid
    points, so the first lambda that fits can fit with room to spare (3.75%
    of a 5% budget, the first time this ran, which would have compared a
    half-spent policy against a fully-spent one and called it a loss). The
    greedy top-up afterwards buys the remaining budget one grid step at a
    time, always from whichever protocol returns the most detections per
    false positive.
    """
    names = list(np.unique(groups))
    budget = max_fpr * float((val["label"] == 0).sum())
    per_group: dict[str, dict[str, np.ndarray] | None] = {}
    for g in names:
        mask = groups == g
        benign = np.sort(val["error"][mask & (val["label"] == 0)])
        attack = np.sort(val["error"][mask & (val["label"] == 1)])
        if len(benign) == 0:
            per_group[g] = None
            continue
        # Candidate cuts: quantiles of this protocol's benign errors, so the
        # grid is dense exactly where the decision is delicate.
        cuts = np.unique(np.quantile(benign, np.linspace(0.0, 1.0, grid_size)))
        fp = (len(benign) - np.searchsorted(benign, cuts, side="left")).astype(float)
        tp = (len(attack) - np.searchsorted(attack, cuts, side="left")).astype(float)
        per_group[g] = {"cuts": cuts, "fp": fp, "tp": tp}

    live = {g: d for g, d in per_group.items() if d is not None}

    def allocate(lmbda: float) -> tuple[dict[str, int], float]:
        idx, total_fp = {}, 0.0
        for g, d in live.items():
            i = int(np.argmax(d["tp"] - lmbda * d["fp"]))
            idx[g] = i
            total_fp += d["fp"][i]
        return idx, total_fp

    lo, hi = 0.0, 1.0
    while allocate(hi)[1] > budget and hi < 1e9:
        hi *= 4
    for _ in range(80):
        mid = (lo + hi) / 2
        if allocate(mid)[1] > budget:
            lo = mid
        else:
            hi = mid
    idx, spent = allocate(hi)

    # Greedy top-up: move whichever protocol's cut down one step, as long as
    # it fits, picking the best detections-per-false-positive each time.
    while True:
        best, best_gain = None, 0.0
        for g, d in live.items():
            i = idx[g]
            if i == 0:
                continue
            d_fp = d["fp"][i - 1] - d["fp"][i]
            if d_fp <= 0 or spent + d_fp > budget:
                continue
            gain = (d["tp"][i - 1] - d["tp"][i]) / d_fp
            if gain > best_gain:
                best, best_gain = g, gain
        if best is None:
            break
        idx[best] -= 1
        spent += live[best]["fp"][idx[best]] - live[best]["fp"][idx[best] + 1]

    chosen = {g: float("inf") for g, d in per_group.items() if d is None}
    chosen.update({g: float(live[g]["cuts"][i]) for g, i in idx.items()})
    return chosen


def apply(thresholds: dict[str, float], errors: np.ndarray,
          groups: np.ndarray) -> np.ndarray:
    if "__all__" in thresholds:
        return errors > thresholds["__all__"]
    cut = np.array([thresholds[g] for g in groups])
    return errors > cut


def evaluate(flagged: np.ndarray, data: dict[str, np.ndarray],
             groups: np.ndarray) -> dict[str, Any]:
    label = data["label"]
    benign, attack = label == 0, label == 1
    tp = int((flagged & attack).sum()); fn = int((~flagged & attack).sum())
    fp = int((flagged & benign).sum()); tn = int((~flagged & benign).sum())
    recall = tp / (tp + fn) if tp + fn else float("nan")
    per_protocol = {
        g: {
            "fpr": float(flagged[benign & (groups == g)].mean()),
            "recall": float(flagged[attack & (groups == g)].mean()),
            "n_benign": int((benign & (groups == g)).sum()),
            "n_attack": int((attack & (groups == g)).sum()),
        }
        for g in np.unique(groups)
    }
    per_class = {
        str(c): float(flagged[data["attack"] == c].mean())
        for c in np.unique(data["attack"]) if c != "Benign"
    }
    return {
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "recall": recall,
        "fpr": fp / (fp + tn) if fp + tn else float("nan"),
        "precision": tp / (tp + fp) if tp + fp else float("nan"),
        "per_protocol": per_protocol,
        "per_class": per_class,
    }


def render_markdown(report: dict[str, Any]) -> str:
    rows = report["policies"]
    classes = sorted(rows[0]["test"]["per_class"], key=lambda c: -rows[0]["test"]["per_class"][c])
    lines = [
        "# Per-protocol thresholds",
        "",
        "Fitted on validation, applied unchanged to test. The model is calibrated "
        "differently for TCP than for UDP, so one cut point spends the false-positive "
        "budget unevenly between them.",
        "",
        "| policy | thresholds | recall | FPR | precision | TCP FPR | UDP FPR |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        t = row["test"]
        thr = row["thresholds"]
        shown = (f"{thr['__all__']:.6f}" if "__all__" in thr
                 else " / ".join(f"{k} {v:.6f}" for k, v in sorted(thr.items())))
        lines.append(
            f"| {row['name']} | {shown} | {t['recall'] * 100:.2f}% | {t['fpr'] * 100:.2f}% "
            f"| {t['precision'] * 100:.2f}% | {t['per_protocol']['tcp']['fpr'] * 100:.2f}% "
            f"| {t['per_protocol']['udp']['fpr'] * 100:.2f}% |"
        )
    lines += ["", "## Per-class detection rate", "",
              "| class | " + " | ".join(r["name"] for r in rows) + " |",
              "|---" * (len(rows) + 1) + "|"]
    for c in classes:
        cells = " | ".join(f"{r['test']['per_class'][c] * 100:.2f}%" for r in rows)
        lines.append(f"| {c} | {cells} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--processed-dir", default=str(paths.PROJECT_ROOT / "data" / "processed_w50"))
    parser.add_argument("--artifacts-dir", default=str(paths.MODELS_DIR / "optuna-denoising-50"))
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    import torch
    from source.model.ensemble import load_scoring_models

    processed_dir = Path(args.processed_dir)
    artifacts_dir = Path(args.artifacts_dir)
    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())
    device = torch.device("cpu")
    models = load_scoring_models(artifacts_dir, device)
    for model in models:
        model.eval()

    print("scoring validation …", flush=True)
    val = score_split(processed_dir / "val.parquet", feature_cols, models, device)
    val_groups = group_protocols(val["protocol"])
    print("scoring test …", flush=True)
    test = score_split(processed_dir / "test.parquet", feature_cols, models, device)
    test_groups = group_protocols(test["protocol"])

    policies = [
        ("global", fit_global(val, args.max_fpr)),
        ("equal-fpr", fit_equal_fpr(val, val_groups, args.max_fpr)),
        ("budgeted", fit_budgeted(val, val_groups, args.max_fpr)),
    ]
    results = []
    for name, thresholds in policies:
        results.append({
            "name": name,
            "thresholds": thresholds,
            "validation": evaluate(apply(thresholds, val["error"], val_groups), val, val_groups),
            "test": evaluate(apply(thresholds, test["error"], test_groups), test, test_groups),
        })
        t = results[-1]["test"]
        print(f"  {name:10s} test recall {t['recall'] * 100:6.2f}%  FPR {t['fpr'] * 100:5.2f}%", flush=True)

    report = {
        "max_fpr": args.max_fpr,
        "fitted_on": "validation",
        "n_val": int(len(val["error"])),
        "n_test": int(len(test["error"])),
        "policies": results,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nwrote {args.output}")

    table = render_markdown(report)
    target = args.markdown or args.output.with_suffix(".md")
    target.write_text(table)
    print(f"wrote {target}\n")
    print(table)


if __name__ == "__main__":
    main()
