"""Create (or update) the SQLite database from schema.sql.

    python -m web.database.initialize_database
    python -m web.database.initialize_database --database-path data/nids.db
"""

from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
# Same NIDS_DB_PATH override as web/backend/database.py -- kept consistent
# so this CLI and the backend agree on where the DB lives without both
# needing --database-path/db_path passed explicitly (relevant in Docker,
# where the DB is a separate persisted volume from the image's baked-in
# reference data -- see docker-compose.yml).
DEFAULT_DATABASE_PATH = Path(
    os.environ.get("NIDS_DB_PATH", str(Path(__file__).resolve().parents[2] / "data" / "nids.db"))
)


def initialize_database(database_path: Path = DEFAULT_DATABASE_PATH) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(database_path)
    try:
        conn.executescript(SCHEMA_PATH.read_text())
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-path", type=Path, default=DEFAULT_DATABASE_PATH)
    args = parser.parse_args()
    initialize_database(args.database_path)
    print(f"Initialized {args.database_path}")


if __name__ == "__main__":
    main()
