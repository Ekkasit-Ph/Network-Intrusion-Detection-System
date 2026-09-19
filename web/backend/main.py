"""FastAPI app for the dashboard backend (module 5).

    uvicorn web.backend.main:app --port 8000

Serves both the API (routers below) and the static frontend
(web/frontend/) from one process -- no CORS setup needed for the demo.

Which model version to load is configurable via the NIDS_MODEL_DIR env var
(defaults to artifacts/models/default/) — point it at
artifacts/models/<name>/ to serve a different trained version without any
code change; see artifacts/models/README.md. NIDS_PROCESSED_DIR must be
set alongside it whenever that model was trained on a different feature
set than data/processed/ (e.g. artifacts/models/denoising was trained on
data/processed_w50/, which has 46 feature columns instead of the older
default's -- feature_columns.json must match what the model was actually
trained on, or ShapExplainer will hand it the wrong number of inputs).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from source.common import paths
from source.explain.shap_explainer import ShapExplainer
from web.backend import database
from web.backend.routers import alerts, explain, firewall_gaps, flows, meta, stats
from web.database.initialize_database import initialize_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
MODEL_ARTIFACTS_DIR = Path(os.environ.get("NIDS_MODEL_DIR", str(paths.DEFAULT_MODEL_DIR)))
PROCESSED_DATA_DIR = Path(os.environ.get("NIDS_PROCESSED_DIR", str(paths.PROCESSED_DATA_DIR)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run unconditionally, not just when the file is missing: schema.sql is
    # all CREATE ... IF NOT EXISTS, so this is idempotent, and running it
    # every start is what lets an *existing* database (a Docker volume that
    # survived a redeploy, say) pick up tables added since it was created.
    # Gating on "file doesn't exist" instead would leave older DBs missing
    # newer tables, and the failure shows up as a 500 mid-demo rather than
    # at startup.
    log.info("Ensuring database schema at %s ...", database.DEFAULT_DB_PATH)
    initialize_database(database.DEFAULT_DB_PATH)

    log.info("Loading SHAP explainer from %s (processed_dir=%s) ...", MODEL_ARTIFACTS_DIR, PROCESSED_DATA_DIR)
    try:
        app.state.explainer = ShapExplainer(PROCESSED_DATA_DIR, MODEL_ARTIFACTS_DIR)
        log.info("SHAP explainer ready.")
    except Exception:
        log.exception("Failed to load SHAP explainer -- /explain will return 503 until fixed.")
        app.state.explainer = None
    yield


app = FastAPI(title="NIDS Dashboard API", lifespan=lifespan)

app.include_router(alerts.router)
app.include_router(flows.router)
app.include_router(explain.router)
app.include_router(firewall_gaps.router)
app.include_router(stats.router)
app.include_router(meta.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_dir": str(MODEL_ARTIFACTS_DIR)}


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
