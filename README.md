# NIDS with Autoencoder + Explainable AI (SHAP)

Full project spec, constraints, and design decisions live in
[`documentation/PROJECT.md`](documentation/PROJECT.md) and
[`documentation/MODEL_DEVELOPMENT.md`](documentation/MODEL_DEVELOPMENT.md)
— read those first. This file is a developer quick-start: how to set up the
environment and run what's implemented.

| module | status |
|---|---|
| 1 — flow extraction (NFStream) | built, wired to scoring ([README](source/extraction/README.md)) |
| 2 — preprocessing | built |
| 3 — autoencoder train/tune/threshold/evaluate | built |
| 4 — SHAP explanation | built, on-demand only |
| 5 — dashboard (FastAPI + HTML/JS) | built, runs in Docker |
| 6 — firewall verification | built ([README](source/firewall_check/README.md)) |
| network simulation (Mininet + Ryu) | written; not runnable here — Mininet needs root, Ryu needs Python ≤3.9 ([README](network_simulation/README.md)) |

Measured caveats on every reported number:
[`documentation/dataset-limitations.md`](documentation/dataset-limitations.md).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Folder map

```
├── documentation/                       # PROJECT.md, MODEL_DEVELOPMENT.md — full spec, read first
├── configuration/
│   └── search_space.yaml              # hyperparameter grid for source/model/tune.py
├── data/
│   ├── raw/                            # put/symlink the NF-ToN-IoT-v2 CSV here
│   └── processed/                      # output of source/preprocessing/pipeline.py
├── artifacts/                          # see "Artifacts produced" below and artifacts/models/README.md
├── source/                                 # ML / network pipeline
│   ├── common/                         # constants.py (schema/feature lists), paths.py
│   ├── preprocessing/                  # module 2 — clean, split, scale, pipeline
│   ├── model/                          # module 3 — autoencoder, train, tune, threshold, evaluate
│   └── extraction/, explain/, firewall_check/   # modules 1, 4, 6 — see each folder's README
├── web/                                 # dashboard app + shared storage — see web/README.md
│   ├── backend/                        # module 5 backend (FastAPI routers, replay_demo)
│   ├── frontend/                       # module 5 frontend (HTML/JS + Chart.js)
│   └── database/                        # SQLite schema + init script
├── network_simulation/                  # Mininet topology, Ryu app, reference firewall policy
├── notebooks/                          # EDA / experiments, import from source/ rather than duplicating logic
└── tests/                              # pytest, run on synthetic data (no need for the real 2.5GB CSV)
```

## Running the pipeline

All commands run as modules from the project root (so `source` resolves as a
package) — no `pip install -e .` needed.

```bash
# 1. Point at the raw CSV (or place/symlink it under data/raw/)
python -m source.preprocessing.pipeline --input Dataset/data/NF-ToN-IoT-v2.csv

# Quick dev run on a slice instead of all 16.9M rows:
python -m source.preprocessing.pipeline --nrows 200000

# 2. Train a single config
python -m source.model.train --latent-dim 16 --hidden-dims 32 --epochs 100

# 2b. Or sweep the grid in configuration/search_space.yaml (selects by validation ROC-AUC)
python -m source.model.tune --epochs 30 --patience 5
python -m source.model.tune --mode random --n-trials 15   # faster, samples the grid

# 2c. Optional: once a winning config is known, train an ensemble of it
# (several random inits, reconstruction error averaged across members —
# see source/model/ensemble.py's docstring). threshold.py/evaluate.py use
# it automatically if present, no other change needed.
python -m source.model.ensemble --n-models 5

# 3. Pick a detection threshold from the trained model (validation set only)
python -m source.model.threshold

# 4. Final, one-time evaluation on the held-out test set
python -m source.model.evaluate
```

Each step reads/writes the paths defined in
[`source/common/paths.py`](source/common/paths.py) — override with `--processed-dir` /
`--artifacts-dir` for parallel experiment runs (e.g. a second model version;
see `artifacts/models/README.md`).

### Artifacts produced

```
artifacts/
├── preprocessing/                            # from source/preprocessing/pipeline.py
│   ├── scaler.pkl
│   └── categorical_encoders.json
└── models/
    └── default/                              # one folder per model version — see artifacts/models/README.md
        ├── model.pt, model_config.json        # from train.py or tune.py
        ├── training_history.json, tuning_results.csv
        ├── ensemble/                            # optional — from source/model/ensemble.py
        │   ├── model_0.pt ... model_{n-1}.pt
        │   └── ensemble_config.json
        ├── threshold.json, threshold_analysis.json
        └── metrics_report.json                 # final test-set metrics (accuracy, precision/recall/F1/FPR, per-class)
```

## Database

SQLite, shared by the dashboard (module 5) and firewall verification
(module 6). The backend re-runs the schema on every boot, so an existing
database picks up new tables automatically; to create one up front:

```bash
python -m web.database.initialize_database          # creates data/nids.db
```

See [`web/README.md`](web/README.md) for how `web/backend`, `web/frontend`,
and `web/database` fit together.

## Running live detection

Capture -> features -> model -> dashboard, the chain `replay_demo` stands in for:

```bash
# offline, from a capture file (no privileges needed)
python -m web.backend.live_capture --source capture.pcap --processed-dir data/processed_w50 \
    --artifacts-dir artifacts/models/optuna-denoising-50

# live (needs packet-capture privileges)
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python)")"
python -m web.backend.live_capture --source eth0
```

Then check what the firewall already covered (module 6, read-only — it never
changes a rule):

```bash
python -m network_simulation.firewall_rules --format ryu --output flows.json
python -m source.firewall_check.ryu_log_compare --rules flows.json --default-action allow
```

The frozen threshold is fitted to the training distribution; see
[`source/extraction/README.md`](source/extraction/README.md) for the measured
skew and when to pass `--threshold` with a re-fitted value.

## Running the demo in Docker

For the presentation machine, where a from-scratch Python/CUDA setup isn't
worth the risk: the image bakes in the deployed champion model
(`artifacts/models/optuna-denoising-50`) and just enough of
`data/processed_w50/` to serve and replay from (see the `Dockerfile` header
for exactly what and why). CPU-only PyTorch on purpose — no GPU/NVIDIA
container runtime dependency on demo day.

```bash
docker compose up -d --build      # builds + starts the backend on :8000
docker compose exec app python -m web.backend.replay_demo --n-flows 500 --rate 2.0
# open http://localhost:8000/
```

`docker compose down` then `up` again keeps prior alerts (the SQLite DB
lives in a named volume, `nids-data`, separate from the image's read-only
reference data) — `docker compose down -v` to actually reset it.

Plain `docker run` works too if compose isn't available: `docker build -t
flowsentry . && docker run -p 8000:8000 flowsentry` (DB then lives inside
the container's own filesystem, gone on `docker rm`).

## Tests

```bash
pytest
```

Tests use a small synthetic DataFrame shaped like NF-ToN-IoT-v2
([`tests/conftest.py`](tests/conftest.py)) — they don't require the real
dataset and run in seconds.

## Non-negotiable constraints (see `documentation/PROJECT.md` for the full list)

- Autoencoder trains on **benign-only** data; attack rows are used only for
  validation/test.
- Never fit the scaler / pick hyperparameters / pick the threshold using
  the test set — only validation.
- SHAP (module 4) is on-demand only, never run per-flow in real time.
- The firewall verification module (module 6) never auto-blocks — it only
  logs coverage gaps.
