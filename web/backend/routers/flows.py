"""GET /flow/{flow_id} — single flow detail."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from web.backend import database

router = APIRouter()


@router.get("/flow/{flow_id}")
def get_flow(flow_id: str) -> dict:
    with database.get_connection() as conn:
        flow = database.get_flow(conn, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"flow_id {flow_id!r} not found")
    return flow
