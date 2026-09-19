"""Evaluate module 4's explanations -- the fourth of PROJECT.md's four
evaluation tracks, and the only one that asks whether the project's
headline feature actually works.

Building an explainer is not the same as showing its output can be trusted,
so this measures four properties an explanation has to have before a report
may claim it explains anything.

    local accuracy   base_value + sum(shap) == reconstruction_error
    stability        the same flow, explained twice, gives the same answer
    accuracy         the deployed nsamples lands where a converged run would
    convergence      how nsamples trades latency for the first three

    python -m scripts.evaluate_explanations
    python -m scripts.evaluate_explanations --nsamples-grid 100,1000,5000

Stability is the one that matters most for the dashboard. Kernel SHAP
estimates attributions by sampling feature coalitions, so two clicks on the
same row are two draws from a distribution, not one answer looked up twice.
Whether that distribution is tight enough for the answer to mean anything
is an empirical question, and this file is where it gets asked.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from itertools import combinations
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from source.common import paths  # noqa: E402

DEFAULT_OUTPUT = paths.ARTIFACTS_DIR / "explanation-evaluation.json"


def _attributions(explainer, feature_vector: dict[str, float], nsamples: int) -> np.ndarray:
    """One explain call -> the 46 attributions as an array, in feature order.

    Every caller goes through here. Writing the comprehension inline reads
    naturally as

        np.array([explainer.explain(fv, n)["shap_values"][c] for c in cols])

    and calls explain() once per *column* -- 46 explanations, each
    contributing a single feature, at 46x the cost and with the per-feature
    values drawn from different runs. It stayed invisible because the result
    still has the right shape and roughly the right magnitudes; what gave it
    away was 478ms for a call the benchmark had measured at 10.
    """
    out = explainer.explain(feature_vector, nsamples=nsamples)
    return np.array([out["shap_values"][c] for c in explainer.feature_cols])


def _load_flows(processed_dir: Path, feature_cols: list[str], threshold: float,
                score_fn, n_anomalous: int, n_benign: int, pool: int,
                seed: int) -> tuple[np.ndarray, np.ndarray]:
    import pyarrow.parquet as pq

    batch = next(pq.ParquetFile(processed_dir / "test.parquet")
                 .iter_batches(batch_size=pool, columns=feature_cols))
    rows = batch.to_pandas().to_numpy(dtype=np.float32)
    errors = score_fn(rows)
    rng = np.random.default_rng(seed)

    def pick(mask: np.ndarray, k: int) -> np.ndarray:
        idx = np.flatnonzero(mask)
        if len(idx) == 0:
            return np.empty((0, rows.shape[1]), dtype=np.float32)
        return rows[rng.choice(idx, min(k, len(idx)), replace=False)]

    return pick(errors > threshold, n_anomalous), pick(errors <= threshold, n_benign)


# ── 1. local accuracy ─────────────────────────────────────────────────────

def measure_local_accuracy(explainer, flows: np.ndarray, nsamples: int) -> dict[str, Any]:
    """SHAP's defining guarantee: the attributions sum to the gap between
    the model's output on this flow and its average output on the
    background. The dashboard shows this sum, so if it did not hold the
    panel would be displaying a number that does not add up."""
    cols = explainer.feature_cols
    residuals = []
    for row in flows:
        out = explainer.explain({c: float(v) for c, v in zip(cols, row)}, nsamples=nsamples)
        total = out["base_value"] + sum(out["shap_values"].values())
        residuals.append(abs(total - float(explainer._score_fn(row[None, :])[0])))
    return {
        "n_flows": len(flows),
        "nsamples": nsamples,
        "residual_max": float(np.max(residuals)),
        "residual_mean": float(np.mean(residuals)),
    }


# ── 2. stability ──────────────────────────────────────────────────────────

def _spearman(a: np.ndarray, b: np.ndarray) -> float:
    ra = np.argsort(np.argsort(a)).astype(float)
    rb = np.argsort(np.argsort(b)).astype(float)
    ra -= ra.mean(); rb -= rb.mean()
    denom = float(np.linalg.norm(ra) * np.linalg.norm(rb))
    return float(ra @ rb / denom) if denom else float("nan")


def _top_k_overlap_baseline(n_features: int, k: int) -> float:
    """Two independent random k-subsets of n features share k*k/n on
    average, so this is the score a coin flip would get. Without it, "the
    top 5 agreed 20% of the time" reads as a weak result rather than as
    barely distinguishable from noise."""
    return (k / n_features)


def measure_stability(explainer, flows: np.ndarray, nsamples: int,
                      repeats: int, top_k: int) -> dict[str, Any]:
    cols = explainer.feature_cols
    rel_spread, overlaps, rhos, sign_flips = [], [], [], []

    for row in flows:
        fv = {c: float(v) for c, v in zip(cols, row)}
        runs = []
        for _ in range(repeats):
            runs.append(_attributions(explainer, fv, nsamples))
        stacked = np.stack(runs)

        scale = float(np.abs(stacked).mean())
        rel_spread.append(float(stacked.std(axis=0).max() / scale) if scale else float("nan"))

        tops = [frozenset(np.argsort(-r)[:top_k]) for r in stacked]
        pairs = list(combinations(range(repeats), 2))
        overlaps.append(float(np.mean([len(tops[i] & tops[j]) / top_k for i, j in pairs])))
        rhos.append(float(np.mean([_spearman(stacked[i], stacked[j]) for i, j in pairs])))
        # A feature that argues for the alert in one run and against it in
        # the next is worse than an imprecise magnitude: the panel would
        # move it between the drivers list and the rest.
        sign_flips.append(float(np.mean(np.sign(stacked).std(axis=0) > 0)))

    return {
        "n_flows": len(flows),
        "nsamples": nsamples,
        "repeats": repeats,
        "top_k": top_k,
        "relative_spread": float(np.mean(rel_spread)),
        "top_k_overlap": float(np.mean(overlaps)),
        "top_k_overlap_if_random": _top_k_overlap_baseline(len(cols), top_k),
        "spearman": float(np.mean(rhos)),
        "sign_flip_rate": float(np.mean(sign_flips)),
    }


# ── 3. accuracy against a converged reference ─────────────────────────────

def measure_accuracy_vs_reference(explainer, flows: np.ndarray, grid: list[int],
                                  reference_nsamples: int, reference_repeats: int,
                                  top_k: int) -> dict[str, Any]:
    """How far the deployed estimate sits from the converged one.

    This replaced a masking/deletion test, which does not work on this
    model and is worth saying so. Masking the features SHAP blames and
    re-scoring made the reconstruction error rise by more than 15x, whether
    the mask came from the background mean or from a real background row.
    Two reasons, both structural rather than fixable: a vector that is part
    attack and part benign is off the manifold the autoencoder was fitted
    to, so it reconstructs worse than either parent; and a Shapley value is
    an average of marginal contributions over every ordering, so what one
    particular coalition does to the score is not something its definition
    predicts.

    What is well posed is estimator accuracy. Kernel SHAP converges to the
    exact Shapley values as nsamples grows, so a high-nsamples average is a
    reference the deployed setting can be scored against -- and "is the
    number on the dashboard the number a converged run would have shown" is
    the question a reader of that dashboard actually has.
    """
    cols = explainer.feature_cols
    per_setting: dict[int, dict[str, list[float]]] = {
        n: {"spearman": [], "top_k": [], "rel_error": []} for n in grid
    }

    for row in flows:
        fv = {c: float(v) for c, v in zip(cols, row)}
        reference = np.mean([_attributions(explainer, fv, reference_nsamples)
                             for _ in range(reference_repeats)], axis=0)
        ref_top = frozenset(np.argsort(-reference)[:top_k])
        scale = float(np.abs(reference).mean())

        for nsamples in grid:
            estimate = _attributions(explainer, fv, nsamples)
            per_setting[nsamples]["spearman"].append(_spearman(estimate, reference))
            per_setting[nsamples]["top_k"].append(
                len(frozenset(np.argsort(-estimate)[:top_k]) & ref_top) / top_k)
            per_setting[nsamples]["rel_error"].append(
                float(np.abs(estimate - reference).mean() / scale) if scale else float("nan"))

    return {
        "n_flows": len(flows),
        "reference_nsamples": reference_nsamples,
        "reference_repeats": reference_repeats,
        "top_k": top_k,
        "settings": [
            {
                "nsamples": n,
                "spearman_vs_reference": float(np.mean(v["spearman"])),
                "top_k_overlap_vs_reference": float(np.mean(v["top_k"])),
                "mean_abs_error_over_mean_abs_shap": float(np.mean(v["rel_error"])),
            }
            for n, v in per_setting.items()
        ],
    }


# ── 4. convergence ────────────────────────────────────────────────────────

def measure_convergence(explainer, flows: np.ndarray, grid: list[int],
                        repeats: int, top_k: int) -> list[dict[str, Any]]:
    rows = []
    for nsamples in grid:
        started = time.perf_counter()
        stability = measure_stability(explainer, flows, nsamples, repeats, top_k)
        elapsed = (time.perf_counter() - started) / (len(flows) * repeats) * 1000
        stability["ms_per_explain"] = round(elapsed, 1)
        rows.append(stability)
        print(f"  nsamples={nsamples:<6} {elapsed:7.1f} ms  spearman={stability['spearman']:.3f}"
              f"  top{top_k}={stability['top_k_overlap'] * 100:.0f}%", flush=True)
    return rows


def render_markdown(report: dict[str, Any]) -> str:
    conv = report["convergence"]
    top_k = conv[0]["top_k"]
    chance = conv[0]["top_k_overlap_if_random"] * 100
    acc = report["accuracy_vs_reference"]
    lines = [
        "# Explanation quality",
        "",
        f"Kernel SHAP, background {report['background_size']} benign training rows, "
        f"{report['n_features']} features. Deployed setting is nsamples="
        f"{report['deployed_nsamples']}.",
        "",
        "## Local accuracy",
        "",
        f"`base_value + sum(shap) == reconstruction_error` holds to "
        f"{report['local_accuracy']['residual_max']:.2e} at worst over "
        f"{report['local_accuracy']['n_flows']} flows.",
        "",
        "## Stability: the same flow, explained repeatedly",
        "",
        f"| nsamples | ms/explain | spread / mean\\|shap\\| | top-{top_k} agreement | Spearman | sign flips |",
        "|---|---|---|---|---|---|",
    ]
    for row in conv:
        lines.append(
            f"| {row['nsamples']} | {row['ms_per_explain']} | {row['relative_spread']:.2f} "
            f"| {row['top_k_overlap'] * 100:.0f}% | {row['spearman']:.3f} "
            f"| {row['sign_flip_rate'] * 100:.0f}% |"
        )
    lines += [
        "",
        f"Two independent random {top_k}-subsets would agree {chance:.0f}% of the time, "
        "which is the line any of these numbers has to clear to mean anything.",
        "",
        "## Accuracy against a converged reference",
        "",
        f"Reference is the mean of {acc['reference_repeats']} runs at nsamples="
        f"{acc['reference_nsamples']}.",
        "",
        f"| nsamples | Spearman vs reference | top-{top_k} vs reference | mean abs error / mean\\|shap\\| |",
        "|---|---|---|---|",
    ]
    for row in acc["settings"]:
        lines.append(
            f"| {row['nsamples']} | {row['spearman_vs_reference']:.3f} "
            f"| {row['top_k_overlap_vs_reference'] * 100:.0f}% "
            f"| {row['mean_abs_error_over_mean_abs_shap']:.2f} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--processed-dir", default=str(paths.PROJECT_ROOT / "data" / "processed_w50"))
    parser.add_argument("--artifacts-dir", default=str(paths.MODELS_DIR / "optuna-denoising-50"))
    parser.add_argument("--nsamples-grid", default="100,500,1000,2000,5000")
    parser.add_argument("--deployed-nsamples", type=int, default=100)
    parser.add_argument("--n-anomalous", type=int, default=6)
    parser.add_argument("--n-benign", type=int, default=2)
    parser.add_argument("--pool", type=int, default=8000, help="Test rows to draw the sample from")
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--reference-nsamples", type=int, default=20000)
    parser.add_argument("--reference-repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    from source.explain.shap_explainer import ShapExplainer

    processed_dir = Path(args.processed_dir)
    artifacts_dir = Path(args.artifacts_dir)
    threshold = json.loads((artifacts_dir / "threshold.json").read_text())["value"]

    print("building explainer …", flush=True)
    explainer = ShapExplainer(processed_dir, artifacts_dir)
    anomalous, benign = _load_flows(processed_dir, explainer.feature_cols, threshold,
                                    explainer._score_fn, args.n_anomalous, args.n_benign,
                                    args.pool, args.seed)
    flows = np.concatenate([anomalous, benign]) if len(benign) else anomalous
    print(f"  {len(anomalous)} anomalous + {len(benign)} benign flows", flush=True)

    grid = [int(n) for n in args.nsamples_grid.split(",")]

    print("local accuracy …", flush=True)
    local = measure_local_accuracy(explainer, flows, args.deployed_nsamples)

    print("accuracy against a converged reference …", flush=True)
    accuracy = measure_accuracy_vs_reference(explainer, anomalous, grid,
                                             args.reference_nsamples, args.reference_repeats,
                                             args.top_k)

    print("stability / convergence …", flush=True)
    convergence = measure_convergence(explainer, anomalous, grid, args.repeats, args.top_k)

    report = {
        "n_features": len(explainer.feature_cols),
        "background_size": int(explainer.explainer.data.data.shape[0]),
        "deployed_nsamples": args.deployed_nsamples,
        "n_anomalous": len(anomalous),
        "n_benign": len(benign),
        "local_accuracy": local,
        "accuracy_vs_reference": accuracy,
        "convergence": convergence,
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
