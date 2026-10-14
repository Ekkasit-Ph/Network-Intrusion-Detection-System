# artifacts/models/

On `main` this holds the **deployed model only** — the files the running
system loads:

```
artifacts/models/optuna-denoising-50/   # DEPLOYED CHAMPION
├── model.pt             # state_dict of the trained denoising autoencoder
├── model_config.json    # {input_dim, latent_dim=64, hidden_dims=[128], noise_std=0.217, lr=4e-4, ...}
├── threshold.json       # {method, value} — the reconstruction-error cutoff
└── metrics_report.json  # final test-set metrics; the dashboard footer reads recall/FPR/precision from here
```

`web/backend/main.py` reads this folder via `NIDS_MODEL_DIR` (and the paired
preprocessing in `artifacts/preprocessing_w50/`: `scaler.pkl` +
`categorical_encoders.json`, properties of the *data* the feature set was fit
on). The preprocessing must always travel with the model — swapping one
without the other fails silently.

**How the champion was chosen:** 50-trial Optuna/TPE sweep (full budget,
epochs=100, patience=10), selected by recall @ FPR≤5%. Winning config above.
recall 87.59% · macro F1 0.819. Progression: 29.60% (baseline) → 45.87%
(+behavioural features) → 59.50% (+denoising) → **87.59%** (Optuna search).

The rest of the artifact set — training history, tuning results, the
supplementary metrics reports, threshold analysis, feature importance, and
every superseded/experiment model — is **not on `main`**. It lives on the
**`development`** branch together with the training/evaluation scripts that
produced it (`git checkout development`).

## Retraining into a new version

Point every step at a new folder name so the deployed one is never
overwritten (do this on the `development` branch, which has the training
code and the full dataset setup):

```bash
python -m source.model.tune       --artifacts-dir artifacts/models/<new-name>
python -m source.model.threshold  --artifacts-dir artifacts/models/<new-name>
python -m source.model.evaluate   --artifacts-dir artifacts/models/<new-name>
```

Then deploy it by pointing `NIDS_MODEL_DIR` at the new folder and restarting
the backend. See [`guides/deployment-runbook.md`](../../documentation/guides/deployment-runbook.md).
