# backend — not yet implemented

FastAPI app (module 5 backend). See
[`../../documentation/PROJECT.md`](../../documentation/PROJECT.md)
"API endpoints" for the exact contract to implement:

| Method | Path | Purpose |
|---|---|---|
| GET | `/alerts?since=<timestamp>` | latest detections, for dashboard polling |
| GET | `/flow/{flow_id}` | single flow detail |
| POST | `/explain/{flow_id}` | trigger Kernel SHAP on demand, persist + return |
| GET | `/firewall-gaps` | gaps found by `source/firewall_check` |
| GET | `/stats?window=1h` | summary counters for dashboard cards |

Expected shape once built:

```
web/backend/
├── main.py            # FastAPI app instantiation
├── database.py          # thin wrapper around web/database (sqlite3 connection helpers)
└── routers/
    ├── alerts.py
    ├── flows.py
    ├── explain.py
    ├── firewall_gaps.py
    └── stats.py
```

Load the model the same way `source/model/evaluate.py` does — from
`artifacts/models/default/model.pt` + `model_config.json` + `threshold.json`,
plus `artifacts/preprocessing/scaler.pkl` (see `source/common/paths.py` for
the canonical constants: `DEFAULT_MODEL_DIR`, `PREPROCESSING_ARTIFACTS_DIR`)
— so the backend and the offline evaluation are always looking at the same
frozen model. If multiple model versions ever exist side by side (see
`artifacts/models/README.md`), the backend should pin one explicitly rather
than assuming `default/`.
