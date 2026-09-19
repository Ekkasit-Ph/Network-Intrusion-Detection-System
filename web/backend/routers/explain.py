"""POST /explain/{flow_id} — trigger Kernel SHAP on demand, persist + return.

On-demand only, per PROJECT.md constraints: this is the only place SHAP
ever runs, triggered by a single user click on a single flow — never
computed automatically for every flow. The `ShapExplainer` itself is built
once at app startup (see main.py) since constructing it (loading the model
+ background sample) costs a few seconds; only `.explain()` runs per
request.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from web.backend import database

log = logging.getLogger(__name__)

router = APIRouter()


@router.post("/explain/{flow_id}")
def explain_flow(flow_id: str, request: Request) -> dict:
    with database.get_connection() as conn:
        flow = database.get_flow(conn, flow_id)
        if flow is None:
            raise HTTPException(status_code=404, detail=f"flow_id {flow_id!r} not found")

        explainer = request.app.state.explainer
        if explainer is None:
            raise HTTPException(status_code=503, detail="explainer not available (failed to load at startup)")

        # A row whose features_json is malformed, or is missing columns the
        # loaded model expects, is a *data* problem with that one flow --
        # answer with a specific 422 the dashboard can show verbatim rather
        # than letting KeyError/JSONDecodeError surface as a bare 500. The
        # mismatch case is worth spelling out: it's exactly what happens when
        # the backend is pointed at a model trained on a different feature
        # set than the flows in the DB were scored with.
        try:
            features = json.loads(flow["features_json"])
        except (TypeError, ValueError) as e:
            raise HTTPException(status_code=422, detail=f"flow {flow_id!r} has unreadable features_json: {e}") from e

        missing = [c for c in explainer.feature_cols if c not in features]
        if missing:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"flow {flow_id!r} is missing {len(missing)} feature(s) the loaded model needs "
                    f"(e.g. {', '.join(missing[:3])}) — it was probably scored by a different model version"
                ),
            )

        try:
            result = explainer.explain(features)
        except Exception as e:  # noqa: BLE001 -- surface as 500 but with the flow id attached
            log.exception("SHAP explain failed for flow %s", flow_id)
            raise HTTPException(status_code=500, detail=f"explain failed for flow {flow_id!r}: {e}") from e

        requested_at = datetime.now(timezone.utc).isoformat()
        database.insert_explanation(
            conn,
            flow_id=flow_id,
            requested_at=requested_at,
            shap_values=result["shap_values"],
            base_value=result["base_value"],
            computation_time_ms=result["computation_time_ms"],
        )

    return {
        "flow_id": flow_id,
        "requested_at": requested_at,
        "base_value": result["base_value"],
        "reconstruction_error": flow["reconstruction_error"],
        "threshold_used": flow["threshold_used"],
        "is_anomaly": bool(flow["is_anomaly"]),
        # Present only for replayed (labelled) flows -- None for anything
        # captured live, which is every flow in a real deployment.
        "true_label": flow["true_label"],
        "true_attack": flow["true_attack"],
        "shap_values": result["shap_values"],
        # The scaled feature values themselves, so the dashboard can say
        # *what was unusual* ("bytes-out sat 3.2 SD above normal"), not just
        # which column mattered. They're StandardScaler output, so each one
        # already reads as a z-score against the benign training data.
        "features": features,
        "computation_time_ms": result["computation_time_ms"],
    }
