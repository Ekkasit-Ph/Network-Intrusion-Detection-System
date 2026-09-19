"""GET /alerts — detections, either as a polling cursor or over a time range."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from web.backend import database

router = APIRouter()


@router.get("/alerts")
def get_alerts(
    since: str | None = Query(default=None, description="ISO8601; only flows after this"),
    until: str | None = Query(default=None, description="ISO8601; with `since`, selects a closed range"),
    limit: int = Query(default=200, le=1000),
    anomalies_only: bool = Query(default=False, description="Range mode only"),
) -> dict:
    """Two modes, because the dashboard asks two different questions.

    Without `until` this is a forward cursor: the *oldest* `limit` flows
    after `since`, newest-first, so a poller that advances to the newest row
    it received never steps over a burst (see `get_recent_flows`).

    With `until` it is a range query for the trend chart's drag-to-select
    drill-down, ordered by reconstruction error rather than time -- a
    selection spanning thousands of flows is only useful if whatever drove
    the spike is at the top.
    """
    if until is not None and since is None:
        raise HTTPException(status_code=422, detail="`until` requires `since`")

    with database.get_connection() as conn:
        if until is not None:
            if until < since:
                raise HTTPException(status_code=422, detail="`until` must not precede `since`")
            flows = database.get_flows_between(
                conn, since=since, until=until, limit=limit, anomalies_only=anomalies_only
            )
            return {"flows": flows, "count": len(flows), "mode": "range"}
        flows = database.get_recent_flows(conn, since=since, limit=limit)
    return {"flows": flows, "count": len(flows), "mode": "cursor"}
