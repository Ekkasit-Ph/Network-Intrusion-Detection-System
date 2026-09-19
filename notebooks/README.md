# notebooks

EDA and one-off model experiments go here. Keep notebooks read-only
consumers of `source/` — import functions from `source.preprocessing.*` /
`source.model.*` instead of copy-pasting logic into a cell, so fixes made
during experimentation flow back into the pipeline automatically.

Suggested starting points once `data/processed/*.parquet` exists:
- `01_eda.ipynb` — class balance, missing/inf value audit, feature
  distributions before/after log-transform (see
  [`../documentation/MODEL_DEVELOPMENT.md`](../documentation/MODEL_DEVELOPMENT.md))
- `02_latent_dim_sweep.ipynb` — visualize `artifacts/models/default/tuning_results.csv`
  from `source/model/tune.py` (val_auc vs. latent_dim, per Song et al. 2021)
- `03_threshold_analysis.ipynb` — plot `artifacts/models/default/threshold_analysis.json`
  ROC/PR curves and the benign-vs-attack error distributions from
  `source/model/threshold.py`
