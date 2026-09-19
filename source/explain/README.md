# explain (module 4 — not yet implemented)

Kernel SHAP wrapper around the trained autoencoder's reconstruction error.
**On-demand only** — must be triggered by `POST /explain/{flow_id}`
(backend), never run against every flow in real time (Kernel SHAP is
expensive; see
[`../../documentation/PROJECT.md`](../../documentation/PROJECT.md)
constraints).

Expected shape once built:

```
source/explain/
└── shap_explainer.py
    # load artifacts/models/default/model.pt + artifacts/preprocessing/scaler.pkl
    # (same paths source/model uses — see source/common/paths.py), wrap
    # reconstruction-error as the scalar function KernelExplainer explains,
    # background set = a sample of scaled benign training rows.
```

Input to the explainer is the already-extracted, already-scaled feature
vector stored in `flows.features_json` (see `web/database/schema.sql`) — do not
recompute features from raw traffic here.
