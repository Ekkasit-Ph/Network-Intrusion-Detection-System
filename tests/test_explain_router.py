"""Tests for POST /explain/{flow_id}'s failure paths.

The success path needs a real trained model + processed data, so it isn't
covered here (evaluate.py and the live smoke tests cover scoring). What
these do cover is every way the endpoint can *fail*, because those are the
paths a live demo actually trips over -- and a bare 500 in front of an
audience says nothing about what went wrong. Each failure should carry a
status code and a message specific enough to act on.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from web.backend import database
from web.backend.routers import explain
from web.database.initialize_database import initialize_database


class StubExplainer:
    """Stands in for ShapExplainer: same two attributes the router uses."""

    def __init__(self, feature_cols, raises=None):
        self.feature_cols = feature_cols
        self._raises = raises

    def explain(self, features):
        if self._raises:
            raise self._raises
        return {"shap_values": {c: 0.1 for c in self.feature_cols}, "base_value": 0.5, "computation_time_ms": 12.0}


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    # The router calls `database.get_connection()` with no argument, and
    # that default is bound to DEFAULT_DB_PATH at import time -- so
    # rebinding the module attribute would have no effect here. Patch the
    # function itself to point every no-arg call at the temp DB.
    real_get_connection = database.get_connection

    @contextmanager
    def get_test_connection(path: Path = db_path):
        with real_get_connection(path) as conn:
            yield conn

    monkeypatch.setattr(database, "get_connection", get_test_connection)

    app = FastAPI()
    app.include_router(explain.router)
    app.state.explainer = StubExplainer(feature_cols=["A", "B"])

    with TestClient(app) as c:
        c.db_path = db_path
        yield c


def _insert(db_path: Path, flow_id: str, features_json: str) -> None:
    with database.get_connection(db_path) as conn:
        conn.execute(
            """INSERT INTO flows (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                                  protocol, reconstruction_error, threshold_used, is_anomaly, features_json)
               VALUES (?, '2026-01-01T00:00:00+00:00', 'a', 'b', 1, 2, 'TCP', 0.5, 0.1, 1, ?)""",
            (flow_id, features_json),
        )
        conn.commit()


def test_unknown_flow_returns_404(client):
    res = client.post("/explain/nope")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"]


def test_explainer_unavailable_returns_503(client):
    _insert(client.db_path, "f1", json.dumps({"A": 1.0, "B": 2.0}))
    client.app.state.explainer = None

    res = client.post("/explain/f1")

    assert res.status_code == 503
    assert "explainer not available" in res.json()["detail"]


def test_unreadable_features_json_returns_422_not_500(client):
    _insert(client.db_path, "f2", "{not valid json")

    res = client.post("/explain/f2")

    assert res.status_code == 422
    assert "unreadable features_json" in res.json()["detail"]


def test_missing_features_returns_422_naming_the_mismatch(client):
    # Scored by some other model version: the row simply lacks column "B".
    _insert(client.db_path, "f3", json.dumps({"A": 1.0}))

    res = client.post("/explain/f3")

    assert res.status_code == 422
    detail = res.json()["detail"]
    assert "missing 1 feature" in detail
    assert "B" in detail
    assert "different model version" in detail


def test_explainer_blowing_up_returns_500_with_the_flow_id(client):
    _insert(client.db_path, "f4", json.dumps({"A": 1.0, "B": 2.0}))
    client.app.state.explainer = StubExplainer(["A", "B"], raises=RuntimeError("CUDA is on fire"))

    res = client.post("/explain/f4")

    assert res.status_code == 500
    detail = res.json()["detail"]
    assert "f4" in detail  # which flow failed, not just "Internal Server Error"
    assert "CUDA is on fire" in detail


def test_successful_explain_persists_and_returns_values(client):
    _insert(client.db_path, "f5", json.dumps({"A": 1.0, "B": 2.0}))

    res = client.post("/explain/f5")

    assert res.status_code == 200
    body = res.json()
    assert body["flow_id"] == "f5"
    assert body["shap_values"] == {"A": 0.1, "B": 0.1}
    assert body["reconstruction_error"] == 0.5

    # the explanation is written to its own table, not folded into flows
    with database.get_connection(client.db_path) as conn:
        row = conn.execute("SELECT * FROM explanations WHERE flow_id = 'f5'").fetchone()
    assert row is not None
    assert json.loads(row["shap_values_json"]) == {"A": 0.1, "B": 0.1}


def test_schema_init_is_idempotent_and_adds_tables_to_an_existing_db(tmp_path):
    """The backend runs schema.sql on every startup so a database created
    by an older version picks up newly added tables. Guards the case that
    actually bites: an existing Docker volume surviving a redeploy."""
    import sqlite3

    db_path = tmp_path / "existing.db"
    # Simulate an older DB: only the original `flows` table exists.
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE flows (
               flow_id TEXT PRIMARY KEY, timestamp DATETIME NOT NULL,
               src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
               protocol TEXT, reconstruction_error REAL NOT NULL,
               threshold_used REAL NOT NULL, is_anomaly INTEGER NOT NULL,
               features_json TEXT NOT NULL)"""
    )
    conn.execute(
        "INSERT INTO flows VALUES ('keep', '2026-01-01T00:00:00+00:00', 'a', 'b', 1, 2, 'TCP', 0.5, 0.1, 1, '{}')"
    )
    conn.commit()
    conn.close()

    initialize_database(db_path)  # what lifespan() now does on every boot

    with database.get_connection(db_path) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        surviving = c.execute("SELECT COUNT(*) AS n FROM flows").fetchone()["n"]

    assert "replay_ground_truth" in tables  # newly added table appears
    assert surviving == 1  # and existing rows are left alone
