"""Single source of truth for schema constants shared across the pipeline.

Every module (preprocessing, model, future extraction/explain/db) should
import feature/column names from here instead of hardcoding strings, so the
43-feature NetFlow v2 schema stays consistent end to end (see PROJECT.md
"non-negotiable constraints" — train/serve skew must not happen).
"""

from __future__ import annotations

RANDOM_SEED = 42

# --- NF-ToN-IoT-v2 schema -----------------------------------------------
# Exact column names, exact order, as specified in PROJECT.md. Do not
# reorder/rename — NFStream extraction (module 1) must match this schema
# character-for-character.
NETFLOW_FEATURES: list[str] = [
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL", "L7_PROTO",
    "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "DURATION_IN", "DURATION_OUT",
    "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS", "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES", "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
]
assert len(NETFLOW_FEATURES) == 43

LABEL_COL = "Label"       # 0 = benign, 1 = attack
ATTACK_COL = "Attack"     # class name, "Benign" for benign rows
BENIGN_LABEL_NAME = "Benign"

# Identifier columns: kept for DB/dashboard joins, but stripped before the
# model sees the data so it can't learn testbed-specific shortcuts.
IDENTIFIER_COLS: list[str] = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT"]

# The 39 features actually fed to the autoencoder.
MODEL_FEATURES: list[str] = [c for c in NETFLOW_FEATURES if c not in IDENTIFIER_COLS]
assert len(MODEL_FEATURES) == 39

# Low-cardinality categorical columns -> one-hot (falls back to frequency
# encoding at fit time if a column turns out to have >20 unique values).
CATEGORICAL_COLS: list[str] = ["PROTOCOL", "L7_PROTO"]

# Bitmask columns: kept numeric/scaled, not one-hot encoded.
TCP_FLAG_COLS: list[str] = ["TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS"]

# Protocol-specific columns that are legitimately 0/absent for flows that
# don't use that protocol (ICMP/DNS/FTP) — missing values here mean "not
# applicable", not "unknown", so they are filled with 0 rather than imputed.
PROTOCOL_SPECIFIC_COLS: list[str] = [
    "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
]

# Columns that can hold +-inf (throughput divides by duration, which can be
# 0), plus SRC_TO_DST_SECOND_BYTES/DST_TO_SRC_SECOND_BYTES, which carry a
# small fraction (~0.002%, observed empirically) of finite-but-absurd
# values up to ~1e304 -- a 32-bit-overflow signature in the exporter,
# correlated with FLOW_DURATION_MILLISECONDS landing near 2**32/1000.
# All four need the same extreme-value handling before anything else (see
# source/preprocessing/clean.py's handle_missing_and_inf/_read_dtypes).
INF_PRONE_COLS: list[str] = [
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
]

# Heavily right-skewed quantity columns -> np.log1p before standardization.
LOG_TRANSFORM_COLS: list[str] = [
    "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
]

# Split ratios (fractions of the *benign* pool). See MODEL_DEVELOPMENT.md
# step 5: train = benign only, val/test = remaining benign + attack.
TRAIN_BENIGN_FRAC = 0.70
VAL_BENIGN_FRAC = 0.15
TEST_BENIGN_FRAC = 0.15
# split fractions for attack rows between val/test (no attack goes to train)
VAL_ATTACK_FRAC = 0.50
TEST_ATTACK_FRAC = 0.50

# One-hot vs frequency-encoding cutoff for categorical columns.
ONE_HOT_CARDINALITY_LIMIT = 20
