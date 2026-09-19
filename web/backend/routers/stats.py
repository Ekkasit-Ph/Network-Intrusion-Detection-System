"""GET /stats?window=1h — summary counters for dashboard cards."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query

from web.backend import database

router = APIRouter()

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_WINDOW_RE = re.compile(r"^(\d+)([smhd])$")


def parse_window(window: str) -> int:
    match = _WINDOW_RE.match(window)
    if not match:
        raise ValueError(f"invalid window {window!r}, expected e.g. '1h', '30m', '10s', '1d'")
    n, unit = match.groups()
    return int(n) * _UNIT_SECONDS[unit]


@router.get("/stats")
def get_stats(window: str = Query(default="1h")) -> dict:
    try:
        seconds = parse_window(window)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    since = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with database.get_connection() as conn:
        stats = database.get_stats(conn, since=since)
    stats["window"] = window
    return stats


@router.get("/stats/trend")
def get_trend(window: str = Query(default="5m"), buckets: int = Query(default=40, ge=5, le=200)) -> dict:
    """Time-bucketed anomaly rate over `window` -- backs the dashboard's
    range-selectable trend chart. Reads straight from the DB (not from
    whatever a given browser tab has polled since it was opened), so
    switching to a longer range works even on a tab opened seconds ago."""
    try:
        seconds = parse_window(window)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    until_dt = datetime.now(timezone.utc)
    since_dt = until_dt - timedelta(seconds=seconds)
    with database.get_connection() as conn:
        bucket_rows = database.get_trend_buckets(conn, since=since_dt.isoformat(), until=until_dt.isoformat(), n_buckets=buckets)
    return {"window": window, "buckets": bucket_rows}
