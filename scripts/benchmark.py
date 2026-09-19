"""Resource benchmark for the detection path -- one of the four evaluation
tracks PROJECT.md commits to.

Measures the four stages separately, because the interesting question is
not "how fast is the model" (it is 28,526 parameters; it was never going to
be the bottleneck) but "which stage runs out of headroom first".

    stage 1  extract    pcap packets  -> raw NetFlow rows     (nfstream + nDPI)
    stage 2  transform  raw rows      -> 46 standardized feats (module 2 online)
    stage 3  score      feature vecs  -> reconstruction error  (module 3)
    stage 4  explain    one flow      -> 46 SHAP values        (module 4)

Stages 1-2 run on a generated pcap (scripts/synthetic_pcap.py) because the
project has no capture of its own yet; stages 3-4 run on real rows from the
test split, so their numbers reflect the data the model actually sees.

    python -m scripts.benchmark                      # one run, current machine
    python -m scripts.benchmark --suite              # CPU 1/2/all cores, + GPU

Every result carries the machine it was measured on. A throughput figure
without that is unfalsifiable, and this file exists to produce numbers that
go into a report.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from source.common import paths  # noqa: E402

DEFAULT_OUTPUT = paths.ARTIFACTS_DIR / "benchmark.json"


# ── environment ───────────────────────────────────────────────────────────

def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _total_ram_gb() -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / 1024 / 1024
    except OSError:
        pass
    return float("nan")


def _gpu_name() -> str | None:
    if not shutil.which("nvidia-smi"):
        return None
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip().splitlines()[0] if out.returncode == 0 and out.stdout.strip() else None
    except (subprocess.SubprocessError, OSError):
        return None


def _affinity_count() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def describe_environment() -> dict[str, Any]:
    import torch
    return {
        "cpu": _cpu_model(),
        "cpu_cores_logical": os.cpu_count(),
        "cpu_cores_available": _affinity_count(),
        "ram_gb": round(_total_ram_gb(), 1),
        "gpu": _gpu_name(),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "torch": torch.__version__,
        "torch_threads": torch.get_num_threads(),
    }


def _rss_mb(field: str = "VmRSS") -> float:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(field + ":"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return float("nan")


# ── timing helpers ────────────────────────────────────────────────────────

def _time_once(fn: Callable[[], Any]) -> tuple[float, Any]:
    start = time.perf_counter()
    result = fn()
    return time.perf_counter() - start, result


def _throughput(fn: Callable[[], int], repeats: int, warmup: int = 3) -> dict[str, Any]:
    """Median of `repeats` timed passes. Median, not mean: one pass that
    lands on a GC pause or a CPU frequency dip should not move the reported
    figure, and with a handful of repeats the mean is not robust to it.

    Three warm-up passes, not one: torch defers thread-pool and MKL setup to
    the first forward, and a single warm-up left that cost inside the first
    timed pass. With few repeats the median could not reject it, and the
    scoring stage read 7.5k flow/s against a true 2.6M."""
    for _ in range(warmup):
        fn()
    rates, seconds = [], []
    for _ in range(repeats):
        elapsed, n = _time_once(fn)
        seconds.append(elapsed)
        rates.append(n / elapsed if elapsed > 0 else float("inf"))
    return {
        "items": int(n),
        "seconds_median": round(statistics.median(seconds), 4),
        "per_second": round(statistics.median(rates), 1),
        "repeats": repeats,
    }


def _latency(fn: Callable[[int], Any], n: int, warmup: int = 20) -> dict[str, Any]:
    """Per-call latency, timed individually so the percentiles are real
    rather than inferred from a batch average."""
    for i in range(warmup):
        fn(i)
    samples = []
    for i in range(n):
        start = time.perf_counter()
        fn(i)
        samples.append((time.perf_counter() - start) * 1000)
    samples.sort()
    pick = lambda q: samples[min(int(q * len(samples)), len(samples) - 1)]
    return {
        "n": n,
        "ms_p50": round(pick(0.50), 3),
        "ms_p95": round(pick(0.95), 3),
        "ms_p99": round(pick(0.99), 3),
        "ms_max": round(samples[-1], 3),
    }


# ── stages ────────────────────────────────────────────────────────────────

def stage_extract(pcap: Path, repeats: int) -> dict[str, Any]:
    from source.extraction.sensor import extract
    rows_holder: list[list[dict[str, Any]]] = []

    def run() -> int:
        rows = list(extract(str(pcap)))
        rows_holder.append(rows)
        return len(rows)

    result = _throughput(run, repeats)
    result["note"] = "nfstream metering + nDPI classification, single meter process"
    return result, rows_holder[-1]


def stage_transform(rows: list[dict[str, Any]], processed_dir: Path,
                    preprocessing_dir: Path, repeats: int) -> dict[str, Any]:
    from source.preprocessing.online import OnlineFeaturePipeline

    def run() -> int:
        # A fresh pipeline each pass: the behavioural window is stateful, so
        # reusing one would measure a warm cache on every repeat but a cold
        # one on the first, and the repeats would not be comparable.
        pipeline = OnlineFeaturePipeline(processed_dir, preprocessing_dir)
        for row in rows:
            pipeline.transform(row)
        return len(rows)

    result = _throughput(run, repeats)
    result["note"] = "includes the 50-flow behavioural window and the scaler"
    return result


def load_vectors(path: Path, feature_cols: list[str], n: int) -> np.ndarray:
    """Only the rows the benchmark scores. `load_split` reads the whole
    parquet, and 6.3M rows of it dwarfs everything this file is trying to
    measure -- it put 2.5GB of pandas into the RSS figure and made the
    model look like it cost that."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    batches, taken = [], 0
    for batch in pq.ParquetFile(path).iter_batches(batch_size=65536, columns=feature_cols):
        batches.append(batch)
        taken += batch.num_rows
        if taken >= n:
            break
    table = pa.Table.from_batches(batches)
    return table.to_pandas().to_numpy(dtype=np.float32)[:n]


def stage_score(models: list[Any], vectors: np.ndarray, device_name: str,
                repeats: int, batch_size: int, latency_n: int) -> dict[str, Any]:
    import torch

    device = torch.device(device_name)
    tensor = torch.from_numpy(vectors).to(device)

    def batched() -> int:
        with torch.no_grad():
            for start in range(0, len(tensor), batch_size):
                chunk = tensor[start:start + batch_size]
                for model in models:
                    out, _ = model(chunk)
                    torch.nn.functional.mse_loss(out, chunk, reduction="none").mean(dim=1)
        if device.type == "cuda":
            torch.cuda.synchronize()
        return len(tensor)

    def single(i: int) -> None:
        with torch.no_grad():
            one = tensor[i % len(tensor)].unsqueeze(0)
            for model in models:
                out, _ = model(one)
                torch.nn.functional.mse_loss(out, one, reduction="none").mean(dim=1)
        if device.type == "cuda":
            torch.cuda.synchronize()

    return {
        "batched": {**_throughput(batched, repeats), "batch_size": batch_size},
        "single_flow": _latency(single, latency_n),
        "model_parameters": sum(p.numel() for p in models[0].parameters()),
        "ensemble_members": len(models),
    }


def stage_explain(vectors: np.ndarray, feature_cols: list[str], processed_dir: Path,
                  artifacts_dir: Path, device_name: str, n: int, nsamples: int) -> dict[str, Any]:
    import torch
    from source.explain.shap_explainer import ShapExplainer

    explainer = ShapExplainer(processed_dir, artifacts_dir)
    # ShapExplainer picks its own device at construction; override so the
    # explain stage is measured on the same one as the scoring stage.
    device = torch.device(device_name)
    explainer.device = device
    explainer.models = [m.to(device) for m in explainer.models]

    def one(i: int) -> None:
        row = vectors[i % len(vectors)]
        explainer.explain({c: float(v) for c, v in zip(feature_cols, row)}, nsamples=nsamples)

    result = _latency(one, n, warmup=2)
    result["nsamples"] = nsamples
    result["background_size"] = len(explainer.explainer.data.data)
    return result


# ── driver ────────────────────────────────────────────────────────────────

def run_one(args: argparse.Namespace) -> dict[str, Any]:
    processed_dir = Path(args.processed_dir)
    artifacts_dir = Path(args.artifacts_dir)
    preprocessing_dir = Path(args.preprocessing_dir)
    feature_cols = json.loads((processed_dir / "feature_columns.json").read_text())

    rss_start = _rss_mb()
    record: dict[str, Any] = {
        "label": args.label,
        "device": args.device,
        "environment": describe_environment(),
        "stages": {},
        "memory_mb": {"rss_at_start": round(rss_start, 1)},
    }

    pcap = Path(args.pcap) if args.pcap else None
    if pcap is None:
        from scripts.synthetic_pcap import build
        pcap = Path(args.work_dir) / f"bench-{args.n_flows}.pcap"
        pcap.parent.mkdir(parents=True, exist_ok=True)
        if not pcap.exists():
            build(pcap, args.n_flows)
        record["pcap"] = {"path": str(pcap), "synthetic": True, "flows_requested": args.n_flows}
    else:
        record["pcap"] = {"path": str(pcap), "synthetic": False}

    print(f"[{args.label}] stage 1/4 extract …", flush=True)
    extract_result, rows = stage_extract(pcap, args.repeats)
    record["stages"]["extract"] = extract_result

    print(f"[{args.label}] stage 2/4 transform …", flush=True)
    record["stages"]["transform"] = stage_transform(rows, processed_dir, preprocessing_dir, args.repeats)

    print(f"[{args.label}] stage 3/4 score …", flush=True)
    vectors = load_vectors(processed_dir / "test.parquet", feature_cols, args.n_score)
    record["memory_mb"]["rss_with_bench_data"] = round(_rss_mb(), 1)

    # Model load measured on its own. What a deployment pays for the model
    # is this delta, not the RSS of a process that also holds the benchmark's
    # test rows.
    import torch
    from source.model.ensemble import load_scoring_models
    before_model = _rss_mb()
    load_seconds, models = _time_once(lambda: load_scoring_models(artifacts_dir, torch.device(args.device)))
    for model in models:
        model.eval()
    record["memory_mb"]["model_only"] = round(_rss_mb() - before_model, 1)
    record["model_load_seconds"] = round(load_seconds, 3)

    record["stages"]["score"] = stage_score(models, vectors, args.device,
                                            args.repeats, args.batch_size, args.latency_n)

    if args.skip_shap:
        record["stages"]["explain"] = {"skipped": True}
    else:
        print(f"[{args.label}] stage 4/4 explain …", flush=True)
        record["stages"]["explain"] = stage_explain(vectors, feature_cols, processed_dir,
                                                    artifacts_dir, args.device,
                                                    args.shap_n, args.shap_nsamples)

    record["memory_mb"]["rss_peak"] = round(_rss_mb("VmHWM"), 1)
    record["measured_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return record


def _suite_configs(gpu_available: bool) -> list[tuple[str, list[str], str, dict[str, str]]]:
    total = os.cpu_count() or 1
    configs: list[tuple[str, list[str], str, dict[str, str]]] = []
    for cores in (1, 2, total):
        if cores > total:
            continue
        label = f"cpu-{cores}core" if cores < total else f"cpu-{total}core-all"
        taskset = ["taskset", "-c", f"0-{cores - 1}"] if shutil.which("taskset") else []
        configs.append((label, taskset, "cpu",
                        {"CUDA_VISIBLE_DEVICES": "", "OMP_NUM_THREADS": str(cores),
                         "MKL_NUM_THREADS": str(cores)}))
    if gpu_available:
        configs.append(("gpu", [], "cuda", {}))
    return configs


def run_suite(args: argparse.Namespace) -> list[dict[str, Any]]:
    import torch
    results = []
    for label, prefix, device, env in _suite_configs(torch.cuda.is_available()):
        cmd = prefix + [sys.executable, "-m", "scripts.benchmark",
                        "--label", label, "--device", device,
                        "--output", str(Path(args.work_dir) / f"part-{label}.json"),
                        "--processed-dir", args.processed_dir,
                        "--artifacts-dir", args.artifacts_dir,
                        "--preprocessing-dir", args.preprocessing_dir,
                        "--n-flows", str(args.n_flows), "--n-score", str(args.n_score),
                        "--repeats", str(args.repeats), "--batch-size", str(args.batch_size),
                        "--latency-n", str(args.latency_n), "--shap-n", str(args.shap_n),
                        "--work-dir", args.work_dir]
        if args.skip_shap:
            cmd.append("--skip-shap")
        print(f"\n=== {label} ===", flush=True)
        proc = subprocess.run(cmd, env={**os.environ, **env})
        if proc.returncode != 0:
            print(f"  {label} failed (exit {proc.returncode}), skipping", file=sys.stderr)
            continue
        results.append(json.loads((Path(args.work_dir) / f"part-{label}.json").read_text()))
    return results


def render_markdown(runs: list[dict[str, Any]]) -> str:
    env = runs[0]["environment"]
    lines = [
        "# Resource benchmark",
        "",
        f"**{env['cpu']}** · {env['cpu_cores_logical']} logical cores · {env['ram_gb']} GB RAM"
        + (f" · {env['gpu']}" if env.get("gpu") else "")
        + f" · torch {env['torch']} · {env['os']}",
        "",
        "Stages 1-2 run on a generated pcap; stages 3-4 on real rows from the test split.",
        "",
        "| configuration | extract (flow/s) | transform (flow/s) | score batched (flow/s) "
        "| score 1 flow p50 / p95 (ms) | SHAP p50 / p95 (ms) | model RSS (MB) |",
        "|---|---|---|---|---|---|---|",
    ]
    for run in runs:
        st = run["stages"]
        shap = st.get("explain", {})
        shap_cell = "—" if shap.get("skipped") else f"{shap['ms_p50']} / {shap['ms_p95']}"
        lines.append(
            f"| {run['label']} | {st['extract']['per_second']:,.0f} "
            f"| {st['transform']['per_second']:,.0f} "
            f"| {st['score']['batched']['per_second']:,.0f} "
            f"| {st['score']['single_flow']['ms_p50']} / {st['score']['single_flow']['ms_p95']} "
            f"| {shap_cell} | {run['memory_mb']['model_only']:,.1f} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--suite", action="store_true", help="Run CPU 1/2/all-core and GPU configurations")
    parser.add_argument("--label", default="default")
    parser.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    parser.add_argument("--pcap", help="Use this capture instead of generating one")
    parser.add_argument("--n-flows", type=int, default=3000, help="Flows in the generated pcap")
    parser.add_argument("--n-score", type=int, default=20000, help="Test rows fed to the scoring stage")
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--latency-n", type=int, default=500)
    parser.add_argument("--shap-n", type=int, default=40)
    parser.add_argument("--shap-nsamples", type=int, default=100)
    parser.add_argument("--skip-shap", action="store_true")
    parser.add_argument("--processed-dir", default=str(paths.PROJECT_ROOT / "data" / "processed_w50"))
    parser.add_argument("--artifacts-dir", default=str(paths.MODELS_DIR / "optuna-denoising-50"))
    parser.add_argument("--preprocessing-dir", default=str(paths.ARTIFACTS_DIR / "preprocessing_w50"))
    parser.add_argument("--work-dir", default="/tmp/nids-benchmark")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path, help="Also write a table here")
    args = parser.parse_args()

    Path(args.work_dir).mkdir(parents=True, exist_ok=True)
    runs = run_suite(args) if args.suite else [run_one(args)]
    if not runs:
        sys.exit("every configuration failed")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = runs[0] if len(runs) == 1 and not args.suite else {"runs": runs}
    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"\nwrote {args.output}")

    if args.suite or args.markdown:
        table = render_markdown(runs)
        target = args.markdown or args.output.with_suffix(".md")
        target.write_text(table)
        print(f"wrote {target}\n")
        print(table)


if __name__ == "__main__":
    main()
