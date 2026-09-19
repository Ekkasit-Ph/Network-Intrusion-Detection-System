"""Tests for web/backend/database.py's get_trend_buckets -- the query
backing the dashboard's range-selectable trend chart. Correctness matters
here specifically around two easy-to-get-wrong points: bucket boundary
assignment (off-by-one would silently misattribute rows to the wrong
bucket) and empty buckets reporting `None` rather than `0.0` (collapsing
"no traffic" into "0% anomalies" would misrepresent a quiet period as a
reassuring one)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from web.backend import database
from web.database.initialize_database import initialize_database


@pytest.fixture
def conn(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    with database.get_connection(db_path) as c:
        yield c


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_get_trend_buckets_splits_evenly_and_assigns_rows_correctly(conn):
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until = since + timedelta(seconds=100)  # 10-second buckets over 10 buckets

    # One flow 1s into bucket 0, one 1s into bucket 5, all anomalies.
    database.insert_flow(
        conn, flow_id="f1", timestamp=_iso(since + timedelta(seconds=1)),
        src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
        reconstruction_error=0.1, threshold_used=0.05, is_anomaly=True, features={},
    )
    database.insert_flow(
        conn, flow_id="f2", timestamp=_iso(since + timedelta(seconds=51)),
        src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
        reconstruction_error=0.1, threshold_used=0.05, is_anomaly=True, features={},
    )

    buckets = database.get_trend_buckets(conn, since=_iso(since), until=_iso(until), n_buckets=10)

    assert len(buckets) == 10
    assert buckets[0]["count"] == 1
    assert buckets[0]["anomaly_rate"] == 1.0
    assert buckets[5]["count"] == 1
    assert buckets[5]["anomaly_rate"] == 1.0
    # every other bucket saw no flows at all
    for i in [1, 2, 3, 4, 6, 7, 8, 9]:
        assert buckets[i]["count"] == 0


def test_get_trend_buckets_empty_bucket_reports_none_not_zero(conn):
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until = since + timedelta(seconds=10)

    buckets = database.get_trend_buckets(conn, since=_iso(since), until=_iso(until), n_buckets=5)

    for b in buckets:
        assert b["count"] == 0
        assert b["anomaly_rate"] is None  # not 0.0 -- "no data" != "all benign"


def test_get_trend_buckets_mixed_anomaly_and_benign_rate(conn):
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until = since + timedelta(seconds=10)

    for i, is_anomaly in enumerate([True, True, False, False]):
        database.insert_flow(
            conn, flow_id=f"f{i}", timestamp=_iso(since + timedelta(seconds=1)),
            src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
            reconstruction_error=0.1, threshold_used=0.05, is_anomaly=is_anomaly, features={},
        )

    buckets = database.get_trend_buckets(conn, since=_iso(since), until=_iso(until), n_buckets=1)

    assert buckets[0]["count"] == 4
    assert buckets[0]["anomaly_rate"] == pytest.approx(0.5)


def _insert_flow(conn, flow_id: str, is_anomaly: bool = True) -> None:
    database.insert_flow(
        conn, flow_id=flow_id, timestamp="2026-01-01T00:00:00+00:00",
        src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
        reconstruction_error=0.5, threshold_used=0.1, is_anomaly=is_anomaly, features={},
    )


def test_flows_without_ground_truth_are_still_returned(conn):
    """The LEFT JOIN must not turn into a filter: live-captured flows never
    have a ground-truth row, and dropping them would empty the dashboard in
    exactly the deployment that matters."""
    _insert_flow(conn, "no_truth")

    rows = database.get_recent_flows(conn)
    single = database.get_flow(conn, "no_truth")

    assert [r["flow_id"] for r in rows] == ["no_truth"]
    assert rows[0]["true_label"] is None
    assert rows[0]["true_attack"] is None
    assert single["true_label"] is None


def test_ground_truth_is_joined_when_present(conn):
    _insert_flow(conn, "labelled")
    database.insert_ground_truth(conn, flow_id="labelled", true_label=1, true_attack="scanning")
    conn.commit()

    row = database.get_flow(conn, "labelled")

    assert row["true_label"] == 1
    assert row["true_attack"] == "scanning"


def test_ground_truth_survives_a_closed_connection(tmp_path):
    """Regression: insert_ground_truth used to leave the write uncommitted
    and rely on some later insert_flow to flush it, so the last labelled
    flow of a replay run was silently rolled back on close."""
    db_path = tmp_path / "commit.db"
    initialize_database(db_path)

    with database.get_connection(db_path) as c:
        database.insert_flow(
            c, flow_id="last", timestamp="2026-01-01T00:00:00+00:00",
            src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
            reconstruction_error=0.5, threshold_used=0.1, is_anomaly=True, features={},
        )
        database.insert_ground_truth(c, flow_id="last", true_label=1, true_attack="ddos")
        # deliberately no explicit commit here -- the connection just closes

    with database.get_connection(db_path) as c:
        row = database.get_flow(c, "last")

    assert row["true_attack"] == "ddos"


def test_ground_truth_mixed_presence_keeps_every_flow(conn):
    _insert_flow(conn, "with_truth")
    _insert_flow(conn, "without_truth")
    database.insert_ground_truth(conn, flow_id="with_truth", true_label=0, true_attack="Benign")
    conn.commit()

    rows = {r["flow_id"]: r for r in database.get_recent_flows(conn)}

    assert set(rows) == {"with_truth", "without_truth"}
    assert rows["with_truth"]["true_attack"] == "Benign"
    assert rows["without_truth"]["true_attack"] is None


def test_get_trend_buckets_row_exactly_at_until_is_not_dropped(conn):
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until = since + timedelta(seconds=10)

    database.insert_flow(
        conn, flow_id="f1", timestamp=_iso(until),
        src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
        reconstruction_error=0.1, threshold_used=0.05, is_anomaly=False, features={},
    )

    buckets = database.get_trend_buckets(conn, since=_iso(since), until=_iso(until), n_buckets=5)

    total_count = sum(b["count"] for b in buckets)
    assert total_count == 1
    # the row lands exactly on the boundary of the last bucket, not overflowed past it
    assert buckets[-1]["count"] == 1


# --------------------------------------------------------------------------
# get_recent_flows as a polling cursor
#
# The dashboard polls `/alerts?since=<newest timestamp it has seen>`. That
# only works if the endpoint hands back the *oldest* flows after the cursor:
# returning the newest ones instead means a burst bigger than `limit` is
# partly skipped forever, because the caller's cursor jumps past flows it
# was never given. The loss is invisible in the UI -- rows keep scrolling,
# only the counts are quietly wrong -- so it needs a test rather than an eye.
# --------------------------------------------------------------------------

def _insert_sequence(conn, start: datetime, n: int, prefix: str = "f") -> list[str]:
    """n flows, one second apart, oldest first. Returns their ids in order."""
    ids = []
    for i in range(n):
        flow_id = f"{prefix}{i:03d}"
        database.insert_flow(
            conn, flow_id=flow_id, timestamp=_iso(start + timedelta(seconds=i)),
            src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
            reconstruction_error=0.1, threshold_used=0.05, is_anomaly=False, features={},
        )
        ids.append(flow_id)
    return ids


def test_polling_with_a_cursor_loses_no_flows_when_the_burst_exceeds_the_limit(conn):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    inserted = _insert_sequence(conn, start, 25)

    # The client has seen the first flow and now polls with a limit well
    # under the size of the backlog -- the replay_demo --rate 0 case.
    cursor = _iso(start)
    collected: list[str] = []
    for _ in range(20):  # generous bound; the loop should finish long before
        batch = database.get_recent_flows(conn, since=cursor, limit=10)
        if not batch:
            break
        collected.extend(b["flow_id"] for b in batch)
        cursor = batch[0]["timestamp"]  # newest of the batch, as the UI does

    assert collected == [] or len(collected) == len(set(collected)), "duplicated rows"
    assert sorted(collected) == sorted(inserted[1:]), (
        f"cursor polling lost flows: got {len(collected)} of {len(inserted) - 1}"
    )


def test_a_cursor_batch_is_still_returned_newest_first(conn):
    """The frontend prepends rows by walking the response backwards and
    reads `flows[0]` as the latest flow, so the ordering contract has to
    survive the pagination fix."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    _insert_sequence(conn, start, 5)

    batch = database.get_recent_flows(conn, since=_iso(start), limit=10)
    timestamps = [b["timestamp"] for b in batch]
    assert timestamps == sorted(timestamps, reverse=True)


def test_a_cursor_batch_is_the_oldest_pending_flows_not_the_newest(conn):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    inserted = _insert_sequence(conn, start, 10)

    batch = database.get_recent_flows(conn, since=_iso(start), limit=3)
    got = sorted(b["flow_id"] for b in batch)
    assert got == inserted[1:4], f"expected the 3 oldest pending, got {got}"


def test_without_a_cursor_the_newest_flows_are_returned(conn):
    """No `since` means "show me the current state", which is the newest
    rows -- the opposite end from the paginating case."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    inserted = _insert_sequence(conn, start, 10)

    batch = database.get_recent_flows(conn, limit=3)
    assert [b["flow_id"] for b in batch] == list(reversed(inserted[-3:]))
