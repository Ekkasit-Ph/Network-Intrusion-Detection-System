# artifacts/models/ — one folder per model version

Each subfolder here is a complete, self-contained output of one
`train.py`/`tune.py` run (plus whatever `threshold.py`/`evaluate.py` runs
were pointed at it afterward):

```
artifacts/models/<name>/
├── model.pt                  # state_dict of the trained/selected model
├── model_config.json         # {input_dim, latent_dim, hidden_dims, dropout, lr, batch_size, noise_std, ...}
├── training_history.json     # loss per epoch, for the winning config
├── tuning_results.csv        # every config tried (tune.py only — absent if trained via train.py)
├── ensemble/                  # optional — from source/model/ensemble.py
│   ├── model_0.pt ... model_{n-1}.pt   # n independently-trained models, same architecture
│   └── ensemble_config.json             # shared config + per-member training summary
├── threshold.json            # {method, value, ...} — from threshold.py
├── threshold_analysis.json   # ROC/PR curve points + all candidate thresholds considered
├── metrics_report.json       # final test-set metrics (the one official, touched-once evaluation)
└── metrics_report_<label>.json  # optional supplementary evaluate.py --resample-* runs (e.g. "balanced")
```

## Current layout (as of the 50-trial full-epoch Optuna search)

```
artifacts/models/
├── optuna-denoising-50/  # DEPLOYED CHAMPION. 50-trial Optuna/TPE sweep, full epoch budget
│                          # (epochs=100, patience=10 per trial -- not a reduced sweep budget,
│                          # this model.pt is already deployment-grade), selected by
│                          # recall_at_fpr @ max_fpr=0.05. Winning config: latent_dim=64,
│                          # hidden_dims=[128] (single layer -- simpler than every
│                          # hand-picked architecture tried before it), noise_std=0.217,
│                          # lr=0.0004, batch_size=256. Trained on data/processed_w50/
│                          # (46 features incl. SRC/DST fan-out+fan-in).
│                          #   recall@FPR<=5% = 87.59%  |  macro F1 = 0.819
│                          # Every attack class improved over every prior config, no
│                          # regressions -- see tuning_results.csv: the top ~7/10 trials by
│                          # recall_at_fpr independently converged on the same
│                          # architecture neighborhood, which is why this isn't treated as
│                          # a lucky single trial.
├── optuna-fpr1pct/       # side experiment: same search, but max_fpr=0.01 instead of 0.05,
│                          # to see whether a model *tuned for* a stricter ceiling beats
│                          # naively re-thresholding optuna-denoising-50 down to 1% FPR
│                          # (which collapsed to 9.9% recall -- the ROC curve is steep
│                          # below ~2% FPR). Not a deployment candidate under the project's
│                          # FPR<=5% constraint; exploratory only.
└── experiments/          # superseded / comparison-only runs, kept for the paper trail:
    ├── default, expanded-search, expanded-search-single   # pre-behavioral-features baselines
    ├── behavioral                                          # first behavioral-features attempt (SRC fan-out only, no DST fan-in)
    ├── w20, w50, w100, w200                                 # window sweep (w50 won, later superseded by optuna-denoising-50)
    ├── scoped-retune, optuna-denoising                      # earlier, smaller retunes superseded by the 50-trial sweep
    ├── final, final-dropout05, denoising, optuna-final      # dropout=0 / hand-picked denoising / 25-trial-sweep variants, all beaten by optuna-denoising-50
    └── denoising-retune                                     # an aborted random-search retune (killed after 1 trial in favor of the Optuna version)
```

**Progression** (recall @ FPR<=5%, test set): 29.60% (baseline) → 45.87% (+behavioral
features) → 59.50% (+hand-picked denoising) → **87.59%** (+50-trial Optuna search,
recall_at_fpr objective). See `optuna-denoising-50/metrics_report.json` for the full
per-class breakdown and `optuna-denoising-50/metrics_report_realistic95.json` for
precision under a realistic (95% benign) traffic composition.

`data/processed_w50/` and `artifacts/preprocessing_w50/` (scaler +
categorical encoders for that exact feature set) are the active
preprocessing outputs paired with every model above except the
`experiments/` baselines that predate behavioral features, which pair
with `data/processed/` + `artifacts/preprocessing/` instead.
`data/processed_experiments/` and `artifacts/preprocessing_experiments/`
hold the other window sizes' (w20/w100/w200) and the first
behavioral-features attempt's preprocessing outputs — needed only if
re-evaluating those specific archived models.

If `ensemble/` exists, `threshold.py` and `evaluate.py` use it automatically
(reconstruction error averaged across all members) instead of the single
`model.pt` — see `source/model/ensemble.py`'s docstring. `model.pt` /
`model_config.json` stay untouched either way, so anything reading just
those two files keeps working whether or not an ensemble exists alongside
them.

To keep a new version around instead of overwriting an existing one (a
different architecture, a different search space, a retrain after
reprocessing the data, ...), point every step at a new folder name:

```bash
python -m source.model.tune       --artifacts-dir artifacts/models/latent32-wide
python -m source.model.threshold  --artifacts-dir artifacts/models/latent32-wide
python -m source.model.evaluate   --artifacts-dir artifacts/models/latent32-wide
```

`train.py`/`tune.py`/`threshold.py`/`evaluate.py` all default to
`artifacts/models/default/` (see `DEFAULT_MODEL_DIR` in
[`source/common/paths.py`](../../source/common/paths.py)) — that constant is
the one place to change if you want a different default instead of passing
`--artifacts-dir` every time. The demo backend (`web/backend/main.py`) reads
`NIDS_MODEL_DIR` / `NIDS_PROCESSED_DIR` env vars instead, currently pointed
at `artifacts/models/optuna-denoising-50` / `data/processed_w50`.

`scaler.pkl` and `categorical_encoders.json` live one level up, per
preprocessing run (e.g. `artifacts/preprocessing_w50/`), not per model
version — they're properties of the *data* a given feature set was fit on,
shared by every model trained against that same processed dataset. If you
ever reprocess the data with different preprocessing choices, treat that as
invalidating every model version trained against the old scaler.
