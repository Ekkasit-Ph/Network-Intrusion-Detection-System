-- SQLite schema for module 5/6, verbatim from PROJECT.md "Database schema".
-- `explanations` is a separate table from `flows` because SHAP is
-- on-demand, per-flow, not computed for every row -- do not fold SHAP
-- columns into `flows` directly.

CREATE TABLE IF NOT EXISTS flows (
    flow_id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    reconstruction_error REAL NOT NULL,
    threshold_used REAL NOT NULL,
    is_anomaly INTEGER NOT NULL CHECK (is_anomaly IN (0, 1)),
    features_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_checks (
    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL REFERENCES flows(flow_id),
    firewall_rule_matched INTEGER CHECK (firewall_rule_matched IN (0, 1)),
    firewall_action_logged TEXT,
    gap_detected INTEGER CHECK (gap_detected IN (0, 1))
);

CREATE TABLE IF NOT EXISTS explanations (
    explanation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL REFERENCES flows(flow_id),
    requested_at DATETIME NOT NULL,
    shap_values_json TEXT NOT NULL,
    base_value REAL NOT NULL,
    computation_time_ms REAL
);

-- Development/demo scaffolding, deliberately NOT part of the schema
-- PROJECT.md specifies above.
--
-- replay_demo.py replays *labelled* held-out test rows, so during
-- development we happen to know each flow's true class and can check
-- whether a detection (and its SHAP explanation) matches reality. A live
-- deployment has no such thing: module 1 captures unlabelled traffic, and
-- nothing will ever write to this table there. Keeping it separate from
-- `flows` is the point -- folding a `true_label` column into `flows` would
-- imply the production pipeline has ground truth, which it does not, and
-- would invite code that quietly depends on it.
CREATE TABLE IF NOT EXISTS replay_ground_truth (
    flow_id TEXT PRIMARY KEY REFERENCES flows(flow_id),
    true_label INTEGER NOT NULL CHECK (true_label IN (0, 1)),  -- 0 benign, 1 attack
    true_attack TEXT NOT NULL                                   -- class name, "Benign" for benign rows
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_firewall_checks_flow_id ON firewall_checks(flow_id);
CREATE INDEX IF NOT EXISTS idx_explanations_flow_id ON explanations(flow_id);
