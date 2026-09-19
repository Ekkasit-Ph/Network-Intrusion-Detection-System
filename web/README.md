# web/ — dashboard application (module 5) + shared storage layer

Everything that serves or stores the detection results lives here, grouped
apart from the ML pipeline in [`source/`](../source/):

```
web/
├── backend/     # FastAPI app — see backend/README.md for the API contract
├── frontend/    # HTML/JS + Chart.js dashboard — see frontend/README.md
└── database/    # SQLite schema + init script, shared by backend, module 6
                 # (firewall_check), and eventually module 4 (explain)
```

None of these are implemented yet except `database/`, whose schema is fully
specified in [`../documentation/PROJECT.md`](../documentation/PROJECT.md) and
safe to materialize ahead of time:

```bash
python -m web.database.initialize_database                       # creates data/nids.db
python -m web.database.initialize_database --database-path some/other.db
```

`source/model/`, `source/preprocessing/`, `source/extraction/`, `source/explain/`, and
`source/firewall_check/` stay under `source/` — they're the ML/network pipeline,
not the web app, even though `explain` and `firewall_check` write into the
same `web/database/schema.sql` tables.
