"""GET /firewall-gaps — coverage gaps found by module 6 (firewall_check).

Read-only reporting endpoint. This never triggers a firewall change itself
— module 6 is post-hoc verification only (see PROJECT.md constraints); this
endpoint just surfaces whatever firewall_checks module 6 already wrote.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from web.backend import database

router = APIRouter()


@router.get("/firewall-gaps")
def get_firewall_gaps(
    limit: int = Query(default=200, le=1000),
    gaps_only: bool = Query(default=True, description="False also returns covered and undetermined checks"),
) -> dict:
    with database.get_connection() as conn:
        gaps = database.get_firewall_gaps(conn, limit=limit, gaps_only=gaps_only)
    counts = {
        "gap": sum(1 for g in gaps if g["gap_detected"] == 1),
        "covered": sum(1 for g in gaps if g["gap_detected"] == 0),
        "undetermined": sum(1 for g in gaps if g["gap_detected"] is None),
    }
    return {"gaps": gaps, "count": len(gaps), "counts": counts}
