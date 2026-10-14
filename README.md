# FlowSentry — Network Intrusion Detection with an Autoencoder + SHAP

Flags anomalous network flows without ever being shown an attack, then
explains each alert feature by feature.

A denoising autoencoder learns what normal traffic looks like from benign
flows only. Anything it reconstructs poorly is flagged. Kernel SHAP then
answers the question an analyst actually asks — *why this flow?* — and
module 6 cross-checks each alert against the firewall policy to surface the
ones that would have been let through.

Senior project, CP354771 · Khon Kaen University.

## Results

Held-out test set, 6,335,435 flows, threshold frozen on validation only.

| | |
|---|---|
| **Recall** (attacks caught) | **87.59%** |
| **False positive rate** | **4.97%** — under the 5% budget this project was designed around |
| Precision | 99.05% *(on the raw test split — see the caveat below)* |
| Macro F1 | 0.819 |
| AUROC | 0.9586 |
| Model size | 115 KB · 28,526 parameters |
| SHAP latency | 8–28 ms per flow, median 24 ms |

**Per-class detection rate**

| class | rate | | class | rate |
|---|---|---|---|---|
| backdoor | 99.92% | | injection | 92.55% |
| ransomware | 99.71% | | scanning | 87.17% |
| password | 99.10% | | dos | 80.81% |
| ddos | 98.88% | | mitm | 78.97% |
| | | | xss | 74.04% |

**Read these two caveats before quoting any number above.**

*Precision depends on how much of the traffic is attack.* The raw test split
is 85.6% attack, which no real network is. Hold recall and FPR fixed and vary
only the mix:

| attack rate | recall | precision |
|---|---|---|
| 85.6% (raw split) | 87.59% | 99.05% |
| 50% | 87.57% | 94.62% |
| **5% (realistic)** | **87.79%** | **48.15%** |

Recall and FPR do not move. Precision collapses. On a real network roughly
half the alerts would be false — that is the base-rate effect, not a defect
in the model, and it is why this project reports recall and FPR rather than
accuracy or precision alone.

*Some labels are wrong, and it costs the model recall it did not lose.*
ToN-IoT labels by attack *session*, so every flow a host produced during an
attack window inherits that label — including its ordinary DNS lookups. The
clearest case: **51% of flows labelled `xss` are DNS**, and XSS is an HTTP
payload, which is always TCP. Restricted to the TCP flows in that class the
detection rate is **99.35%**, the highest of any class.

Excluding UDP entirely and re-scoring at the same frozen threshold:

| | recall | FPR | macro F1 |
|---|---|---|---|
| full test set | 87.59% | 4.97% | 0.819 |
| UDP excluded | **94.10%** | 4.81% | **0.9025** |

Read 87.59% as the headline and 94.10% as what the detector does on traffic
whose labels can be trusted. The full analysis (`dataset-limitations.md`) and
every evaluation report live on the **`development`** branch.

## Quick start

Everything needed to run is in the repository: the deployed model and a
small committed demo sample (`data/demo_sample/`). No 2.5 GB dataset, no GPU —
it builds and runs straight from a clone.

> **The bundled model is a reference, not a plug-and-play detector for your
> network.** It is trained on NF-ToN-IoT-v2 and is what powers the demo below
> (replaying that dataset's test flows, where it gets 87.59% recall). An
> autoencoder learns one network's definition of "normal" — point it at a
> *different* network and its scores can collapse (AUROC fell to 0.000 in our
> tests until retrained). **Before using it on real traffic, retrain on a
> week or two of your own benign flows** — no attack labels needed. Steps:
> [`documentation/guides/deployment-runbook.md`](documentation/guides/deployment-runbook.md).

### Docker — fastest, nothing to install

```bash
docker compose up -d --build     # first build takes a few minutes (CPU torch wheel)
docker compose exec app python -m web.backend.replay_demo --reset --n-flows 400 --rate 2 --loop
```

Open <http://localhost:8000>.

```bash
docker compose down        # keeps the database (named volume `nids-data`)
docker compose down -v     # wipes it too
```

### Local virtualenv

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu   # CPU wheel; skip for GPU
pip install -r requirements.txt

NIDS_MODEL_DIR=artifacts/models/optuna-denoising-50 \
NIDS_PROCESSED_DIR=data/demo_sample \
python -m uvicorn web.backend.main:app --port 8000
```

Both environment variables are **required** — the built-in defaults point at
`artifacts/models/default/`, which this project does not use. Startup takes
25–30 s while the SHAP explainer loads; poll `/health` until it returns 200.
Then feed it traffic in a second terminal:

```bash
source .venv/bin/activate
python -m web.backend.replay_demo --reset --n-flows 400 --rate 2 --loop \
  --processed-dir data/demo_sample --artifacts-dir artifacts/models/optuna-denoising-50
```

Full install-on-another-machine guide, env-var reference, running against the
full dataset and troubleshooting:
[`documentation/how-to-run.md`](documentation/how-to-run.md).

## What the dashboard shows

| tab | question it answers |
|---|---|
| **Live** | What is happening now, and how far past the threshold is each flow? Click any flow for its SHAP breakdown. |
| **Trend** | How has the anomaly rate moved over time? Drag to drill into a window. |
| **Firewall gaps** | Which anomalous flows would the firewall have let through? |

The SHAP panel shows each feature's contribution **in its original units**
— bytes, milliseconds, packet counts — not the standardised values the model
sees, and displays `base_value + Σshap = reconstruction_error` so the
explanation can be checked rather than taken on faith.

## The six modules

| # | module | what it does | status |
|---|---|---|---|
| 1 | [extraction](source/extraction/README.md) | NFStream → 46 features, matching the training schema | built |
| 2 | preprocessing | clean, encode, log1p, scale; 43 dataset features + 3 behavioural | built |
| 3 | model | denoising autoencoder; train / tune / threshold / evaluate | built |
| 4 | explain | Kernel SHAP, **on request only** — never per-flow in real time | built |
| 5 | [web](web/README.md) | FastAPI + SQLite + a dependency-free frontend | built |
| 6 | [firewall_check](source/firewall_check/README.md) | compares alerts against the policy; **read-only, never blocks** | built |

The reference firewall policy module 6 consumes lives in
[`network_simulation/firewall_rules.py`](network_simulation/firewall_rules.py).

All six modules were also run end to end on a live virtual network — first on
Mininet (OpenFlow switch + Ryu firewall, synthetic benign + three attacks),
then on a GNS3 topology running **real Alpine Linux OS** on each node, with a
DDoS botnet and the firewall enforcing OpenFlow drop rules. The sensor sees
traffic passively through a mirror port and never blocks. That surfaced the
domain-shift collapse (the NF-ToN-IoT-v2 model scored AUROC 0.000 on the new
network until retrained), the hub's immunity to fan-in detection, and the
near-benign shape of SSH brute-force. The simulation code, the GNS3 lab and
the write-ups of those runs live on the **`development`** branch — they are
testing tools, not part of what you install (`git checkout development`).

## Three features we added ourselves

The dataset's 43 features describe each flow in isolation, so a single scan
flow looks like any short connection. What separates them is *behaviour
across* flows, so we added three, computed over a **sliding window of the
last 50 flows per source**:

| feature | catches |
|---|---|
| `SRC_DISTINCT_DST_IPS_LAST_W` | one host touching many destinations — fan-out |
| `SRC_DISTINCT_DST_PORTS_LAST_W` | one host touching many ports — port scanning |
| `DST_DISTINCT_SRC_IPS_LAST_W` | many hosts converging on one target — fan-in, DDoS |

The window is deliberately bounded rather than cumulative. In this dataset
10 source IPs generate 94% of all traffic, and the same machines generate
both benign and attack flows — a cumulative per-IP counter would be nearly
constant per host, and the model would learn *which machine this is* instead
of *what it is doing*.

Measured effect: recall rose from 29.59% to 45.87% at a matched FPR when
these were added incrementally.

## Reproducing from scratch

The dataset and the derived splits are **not in this repository** — 2.5 GB
raw plus ~2 GB of parquet. Download NF-ToN-IoT-v2, put it in `data/raw/`,
then:

```bash
# 1. Preprocess  (--nrows 200000 for a fast dev slice)
python -m source.preprocessing.pipeline --input data/raw/NF-ToN-IoT-v2.csv

# 2. Search for a configuration, optimising the metric this project cares about
python -m source.model.tune --selection-metric recall_at_fpr --max-fpr 0.05

# 3. Pick the threshold  (validation set only — never the test set)
python -m source.model.threshold

# 4. Final one-time evaluation on the held-out test set
python -m source.model.evaluate
```

Step 2's `--selection-metric` matters. The CLI default is `val_auc`, which
rewards ranking quality across the whole ROC curve including FPR regions
this system will never operate in. The deployed model was selected with
`recall_at_fpr` at `max_fpr 0.05`.

Every step reads and writes the paths in
[`source/common/paths.py`](source/common/paths.py); pass `--processed-dir` /
`--artifacts-dir` to run experiments side by side without overwriting the
deployed model. See [`artifacts/models/README.md`](artifacts/models/README.md).

## Layout

```
source/
├── common/              constants.py (schema, feature lists), paths.py
├── preprocessing/       module 2 — clean, split, scale, pipeline
├── model/               module 3 — autoencoder, train, tune, threshold, evaluate
├── extraction/          module 1 — NFStream metering
├── explain/             module 4 — Kernel SHAP
└── firewall_check/      module 6 — policy comparison
web/
├── backend/             FastAPI routers, replay_demo, live_capture
├── frontend/            HTML/CSS/JS — no framework, no build step
└── database/            SQLite schema + init
network_simulation/      reference firewall policy (module 6's input)
artifacts/               trained model, scaler, encoders, metrics reports
documentation/           full spec, model development log, limitations, run guide
```

## Tests

The test suite (24 modules, driven by a small synthetic DataFrame shaped like
NF-ToN-IoT-v2 — no dataset or trained model needed) lives on the
**`development`** branch, alongside the simulation and benchmark tooling:

```bash
git checkout development
pytest
```

## Rules this project does not break

- The autoencoder trains on **benign flows only**. Attack rows appear in
  validation and test, never in training.
- The scaler, the hyperparameters, and the threshold are **never** fitted or
  chosen using the test set. Validation only.
- SHAP runs **on request**, never per flow in real time — it costs ~24 ms,
  which is fine for one alert an analyst clicked and ruinous at line rate.
- Module 6 **never blocks traffic**. It reports coverage gaps and stops.
- Everything rendered into the dashboard goes through `esc()`. Flow records
  carry attacker-controlled strings — IPs, ports, protocol names.

## Documentation

Start at the index — [`documentation/README.md`](documentation/README.md).
The ones worth opening first:

| file | what's in it |
|---|---|
| [`how-to-run.md`](documentation/how-to-run.md) | install on another machine — Docker and venv, env vars, troubleshooting |
| [`PROJECT.md`](documentation/PROJECT.md) | full specification and design decisions |
| [`deployment-runbook.md`](documentation/guides/deployment-runbook.md) | deploy for real: first run, and retraining when the network changes |
| [`dashboard-spec.md`](documentation/guides/dashboard-spec.md) | what the dashboard shows and how it is laid out |

The model-development log, the measured dataset caveats and every evaluation
report (benchmarks, SHAP quality, per-class metrics) are on the
**`development`** branch.
