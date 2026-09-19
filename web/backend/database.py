"""Thin SQLite access layer for the backend (module 5).

Uses the schema in web/database/schema.sql — run
`python -m web.database.initialize_database` first if data/nids.db doesn't
exist yet. Kept as plain sqlite3 (no ORM): the schema is small, fixed, and
already fully specified in PROJECT.md, so an ORM would add a dependency and
an indirection layer without buying anything here.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from source.common.paths import PROJECT_ROOT

# Overridable via NIDS_DB_PATH (e.g. pointing at a Docker volume mount that
# persists across container restarts, separate from the read-only reference
# data baked into the image) -- see docker-compose.yml.
DEFAULT_DB_PATH = Path(os.environ.get("NIDS_DB_PATH", str(PROJECT_ROOT / "data" / "nids.db")))


@contextmanager
def get_connection(db_path: Path = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def insert_flow(
    conn: sqlite3.Connection,
    flow_id: str,
    timestamp: str,
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    protocol: str | None,
    reconstruction_error: float,
    threshold_used: float,
    is_anomaly: bool,
    features: dict[str, Any],
) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO flows
           (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
            reconstruction_error, threshold_used, is_anomaly, features_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
         reconstruction_error, threshold_used, int(is_anomaly), json.dumps(features)),
    )
    conn.commit()


def insert_ground_truth(conn: sqlite3.Connection, flow_id: str, true_label: int, true_attack: str) -> None:
    """Record what a replayed flow actually was. Only replay_demo.py calls
    this -- see the table's comment in schema.sql for why it's kept out of
    `flows`."""
    conn.execute(
        "INSERT OR REPLACE INTO replay_ground_truth (flow_id, true_label, true_attack) VALUES (?, ?, ?)",
        (flow_id, int(true_label), true_attack),
    )
    # Commit here rather than riding on the next insert_flow's commit:
    # without it the final row of a replay is still uncommitted when the
    # connection closes, and sqlite rolls it back -- leaving exactly one
    # flow mysteriously missing its label.
    conn.commit()


# LEFT JOIN, never INNER: a flow with no ground-truth row is the normal
# case for anything that didn't come from replay_demo (and will be the
# only case once module 1 feeds live capture in), so it must still be
# returned -- just with true_label/true_attack as NULL.
_FLOW_SELECT = """
    SELECT f.*, g.true_label, g.true_attack
    FROM flows f
    LEFT JOIN replay_ground_truth g ON g.flow_id = f.flow_id
"""


def get_flows_between(conn: sqlite3.Connection, since: str, until: str,
                      limit: int = 200, anomalies_only: bool = False) -> list[dict[str, Any]]:
    """Flows inside a closed time range, worst reconstruction error first.

    Backs the trend chart's drag-to-select drill-down, which asks a
    different question from `get_recent_flows`: not "what arrived next"
    but "what was the worst thing in this span". Ordering by error rather
    than time is the point -- a selection covering thousands of flows is
    only useful if the ones that drove the spike are at the top.
    """
    clause = " AND f.is_anomaly = 1" if anomalies_only else ""
    rows = conn.execute(
        _FLOW_SELECT + f" WHERE f.timestamp >= ? AND f.timestamp <= ?{clause}"
        " ORDER BY f.reconstruction_error DESC, f.rowid ASC LIMIT ?",
        (since, until, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_recent_flows(conn: sqlite3.Connection, since: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """Newest-first, always. `since` turns this into a forward cursor: it
    returns the *oldest* `limit` flows after that timestamp, so a caller
    advancing its cursor to the newest row it received never steps over
    anything.

    The direction matters. Selecting the newest `limit` rows after `since`
    instead -- the obvious reading of "latest detections" -- silently drops
    flows whenever a burst is larger than `limit`: the caller jumps its
    cursor to the newest row and the older ones in that same burst are
    never returned by any later poll. The dashboard hits this on
    `replay_demo --rate 0` and when resuming after Pause, and the loss is
    invisible, because the table keeps scrolling and only the counts are
    wrong.

    Ties on timestamp are broken by rowid so paging is deterministic;
    a `since` cursor could still skip a row sharing the exact microsecond
    of the last one returned, which single-writer ISO timestamps don't
    produce in practice.
    """
    if since:
        rows = conn.execute(
            _FLOW_SELECT + " WHERE f.timestamp > ? ORDER BY f.timestamp ASC, f.rowid ASC LIMIT ?",
            (since, limit),
        ).fetchall()
        rows = list(reversed(rows))
    else:
        rows = conn.execute(
            _FLOW_SELECT + " ORDER BY f.timestamp DESC, f.rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def clear_flows(conn: sqlite3.Connection) -> dict[str, int]:
    """Empty every table that holds observations, leaving the schema alone.

    Deletes children before parents: `firewall_checks` and `explanations`
    both reference `flows`, and `replay_ground_truth` is keyed by flow_id.
    Truncating rather than deleting the database file is what makes this
    work against a Docker volume, where the file is a mount point.
    """
    removed = {}
    for table in ("firewall_checks", "explanations", "replay_ground_truth", "flows"):
        removed[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    return removed


def get_flow(conn: sqlite3.Connection, flow_id: str) -> dict[str, Any] | None:
    row = conn.execute(_FLOW_SELECT + " WHERE f.flow_id = ?", (flow_id,)).fetchone()
    return dict(row) if row else None


def get_stats(conn: sqlite3.Connection, since: str) -> dict[str, Any]:
    """Summary counters for flows with timestamp > `since` (ISO8601)."""
    total = conn.execute("SELECT COUNT(*) AS n FROM flows WHERE timestamp > ?", (since,)).fetchone()["n"]
    anomalies = conn.execute(
        "SELECT COUNT(*) AS n FROM flows WHERE timestamp > ? AND is_anomaly = 1", (since,)
    ).fetchone()["n"]
    avg_error_row = conn.execute(
        "SELECT AVG(reconstruction_error) AS avg_error FROM flows WHERE timestamp > ?", (since,)
    ).fetchone()
    return {
        "since": since,
        "total_flows": total,
        "anomalies": anomalies,
        "anomaly_rate": anomalies / total if total else 0.0,
        "avg_reconstruction_error": avg_error_row["avg_error"] or 0.0,
    }


def get_trend_buckets(
    conn: sqlite3.Connection, since: str, until: str, n_buckets: int = 40
) -> list[dict[str, Any]]:
    """Anomaly rate over `[since, until]` (both ISO8601), split into
    `n_buckets` equal-width time buckets -- backs the range-selectable
    trend chart (GET /stats/trend). A bucket with zero flows in it reports
    `anomaly_rate: None` (not 0.0 -- "no traffic" and "traffic, all
    benign" are different facts, and collapsing them to the same 0%
    floor would misrepresent quiet buckets as reassuring ones).

    Bucketing is done in Python, not SQL date arithmetic: SQLite's
    strftime-based bucketing gets fiddly across arbitrary (non-whole-unit)
    bucket widths, and at demo scale (a live capture/replay session, not
    months of production traffic) the full row scan this does is cheap.
    """
    since_dt = datetime.fromisoformat(since)
    until_dt = datetime.fromisoformat(until)
    total_seconds = max((until_dt - since_dt).total_seconds(), 1.0)
    bucket_seconds = total_seconds / n_buckets

    counts = [0] * n_buckets
    anomalies = [0] * n_buckets
    rows = conn.execute(
        "SELECT timestamp, is_anomaly FROM flows WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp",
        (since, until),
    ).fetchall()
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        idx = int((ts - since_dt).total_seconds() / bucket_seconds)
        idx = min(max(idx, 0), n_buckets - 1)
        counts[idx] += 1
        anomalies[idx] += row["is_anomaly"]

    buckets = []
    for i in range(n_buckets):
        bucket_start = since_dt + timedelta(seconds=i * bucket_seconds)
        rate = anomalies[i] / counts[i] if counts[i] else None
        buckets.append({"t": bucket_start.isoformat(), "count": counts[i], "anomaly_rate": rate})
    return buckets


def insert_explanation(
    conn: sqlite3.Connection,
    flow_id: str,
    requested_at: str,
    shap_values: dict[str, float],
    base_value: float,
    computation_time_ms: float,
) -> int:
    cur = conn.execute(
        """INSERT INTO explanations (flow_id, requested_at, shap_values_json, base_value, computation_time_ms)
           VALUES (?, ?, ?, ?, ?)""",
        (flow_id, requested_at, json.dumps(shap_values), base_value, computation_time_ms),
    )
    conn.commit()
    return cur.lastrowid


def get_latest_explanation(conn: sqlite3.Connection, flow_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM explanations WHERE flow_id = ? ORDER BY requested_at DESC LIMIT 1", (flow_id,)
    ).fetchone()
    return dict(row) if row else None


def insert_firewall_check(
    conn: sqlite3.Connection,
    flow_id: str,
    firewall_rule_matched: bool | None,
    firewall_action_logged: str | None,
    gap_detected: bool | None,
) -> None:
    conn.execute(
        """INSERT INTO firewall_checks (flow_id, firewall_rule_matched, firewall_action_logged, gap_detected)
           VALUES (?, ?, ?, ?)""",
        (flow_id, None if firewall_rule_matched is None else int(firewall_rule_matched),
         firewall_action_logged, None if gap_detected is None else int(gap_detected)),
    )
    conn.commit()


def get_firewall_gaps(conn: sqlite3.Connection, limit: int = 200,
                      gaps_only: bool = True) -> list[dict[str, Any]]:
    """Module 6's verdicts, newest first.

    `gaps_only` (the default) returns just the coverage failures, which is
    what an operator asks for. The dashboard passes False, because the
    three verdicts are only meaningful next to each other: "26 gaps" alone
    invites the reader to supply their own denominator, and
    `gap_detected IS NULL` -- coverage that could not be determined --
    disappears entirely, which reads as though every flow were classified.
    """
    clause = " WHERE fc.gap_detected = 1" if gaps_only else ""
    rows = conn.execute(
        f"""SELECT fc.*, f.timestamp, f.src_ip, f.dst_ip, f.dst_port, f.protocol,
                   f.reconstruction_error, f.threshold_used, f.is_anomaly
           FROM firewall_checks fc JOIN flows f ON fc.flow_id = f.flow_id{clause}
           ORDER BY f.timestamp DESC, fc.check_id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
