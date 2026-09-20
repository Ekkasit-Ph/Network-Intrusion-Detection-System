"""GET /incidents -- anomalous flows grouped into things that happened.

The dashboard's Live tab answers "what is arriving". This answers the
question an operator actually has to act on, which is "what is going on",
and the two are not the same list. A port sweep is one decision and four
hundred rows; at the measured 4.97% false-positive rate a network carrying
100,000 flows a day produces about 9,100 alerts, which is nineteen people
reading full time. See source/alerting/aggregate.py for what gets grouped
and documentation/alert-aggregation.md for what that is worth measured on
real traffic -- including where it does not help.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query

from source.alerting import aggregate
from web.backend import database

router = APIRouter()

_WINDOWS = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440}


@router.get("/incidents")
def get_incidents(
    window: str = Query(default="1h", description="One of 15m, 1h, 6h, 24h"),
    gap_seconds: int = Query(default=aggregate.DEFAULT_GAP_SECONDS, ge=10, le=86400),
    min_distinct: int = Query(default=aggregate.DEFAULT_MIN_DISTINCT, ge=2, le=1000),
    outlier_z: float = Query(default=aggregate.DEFAULT_OUTLIER_Z, ge=0.0, le=20.0,
                             description="How far above the typical key a count must sit. "
                                         "0 disables the test and reports every group that "
                                         "clears min_distinct -- which on structureless "
                                         "traffic is nearly all of them."),
    limit: int = Query(default=20000, ge=100, le=200000),
) -> dict:
    if window not in _WINDOWS:
        raise HTTPException(status_code=422,
                            detail=f"`window` must be one of {sorted(_WINDOWS)}")

    since = (datetime.now(timezone.utc) - timedelta(minutes=_WINDOWS[window])).isoformat()
    with database.get_connection() as conn:
        flows = database.get_anomalous_flows_since(conn, since=since, limit=limit)

    incidents = aggregate.group_incidents(
        flows, min_distinct=min_distinct, gap_seconds=gap_seconds, outlier_z=outlier_z)
    summary = aggregate.summarise(incidents, len(flows))
    return {
        "window": window,
        "since": since,
        # A caller that hit the guard is looking at a partial window, and a
        # count derived from a truncated read would understate the burst it
        # exists to describe.
        "truncated": len(flows) >= limit,
        "summary": summary,
        "incidents": [i.to_dict() for i in incidents],
    }
