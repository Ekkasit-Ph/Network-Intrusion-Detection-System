# extraction — module 1

Live flow feature extraction: NFStream + a custom `NFPlugin` that computes
the NF-ToN-IoT-v2 fields NFStream doesn't expose natively.

```
source/extraction/
├── nfplugin.py     # NetFlowV2Fields: the 19 packet-level fields
├── l7_proto.py      # nDPI protocol name -> the training data's numeric encoding
└── sensor.py        # runs NFStream, maps a flow onto the 43-column schema
```

## Running it

```bash
python -m source.extraction.sensor --source capture.pcap --output flows.csv   # offline
python -m source.extraction.sensor --source eth0 --limit 100                   # live
```

Reading a pcap needs no privileges. Live capture does:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python)")"
```

## Where the 43 fields come from

| Source | Count | Notes |
|---|---|---|
| NFStream directly | 16 | addresses, ports, byte/packet counts, durations, packet-size extremes |
| Arithmetic on those | 7 | the three TCP flag bitmasks, the two byte-rate and two throughput fields |
| `nfplugin.py` parsing raw headers | 19 | TTL, TCP window, retransmissions, size histogram, ICMP, DNS, FTP |
| `l7_proto.py` name → id mapping | 1 | `L7_PROTO` — see caveat below |

NFStream's per-packet object has no `.ttl` or `.window`, but it does carry
`.ip_packet` (the raw IP bytes), so the plugin parses those headers itself.

## Five semantics bugs, and what each cost

Four came from the code review, the fifth from wiring live scoring. Every
one produced a *plausible* value — right column, right
type, sane magnitude — which is the failure mode this module is most
exposed to, because every stage downstream would then process the wrong
number perfectly correctly. Each is now pinned by a test that fails on the
old code.

**1. Byte counters were measuring ethernet frames, not IP packets.**
NFStream's `accounting_mode` defaults to 0 (whole frame); nProbe wrote the
training data at the IP layer. The training data settles it: there,
`SHORTEST_FLOW_PKT` bottoms out at 40 — a bare TCP header — and never at
the 54/60 that ethernet framing would floor it at. Ten columns were
inflated by 14 bytes per packet: `IN_BYTES`, `OUT_BYTES`, all four
length columns, and the two byte-rate and two throughput columns derived
from them. Fixed with `accounting_mode=1`.

This was by far the most serious of the four. Replayed through the frozen
model, it costs **FPR 4.97% → 96.43%** — the detector would have flagged
almost every benign flow. Measured, not estimated: `verify_skew.py`
scenario S4.

**2. `MIN_IP_PKT_LEN` was reported on one-directional flows.** nProbe
writes 0 there. Measured across 3M training rows: the column equals
`SHORTEST_FLOW_PKT` on every row with `OUT_PKTS > 0`, is 0 on all
2,278,969 rows with `OUT_PKTS == 0` (one exception), and is **never once
greater** than `SHORTEST_FLOW_PKT` — which is what rules out the obvious
alternative reading, that it is a reverse-direction minimum. 76% of
training rows carry that 0. `MAX_IP_PKT_LEN` has no such behaviour.

**3. An answered ping erased itself.** `_observe_icmp` was
last-packet-wins, so an echo reply (type 0, code 0) overwrote the request
and encoded to 0 — the same value `on_init` uses for "this flow carried
no ICMP at all". A normal ping, a flow with no ICMP, and a scan whose
pings went unanswered all became the same row. Now first-packet-wins, with
an explicit `_icmp_seen` flag, since the field itself cannot represent the
difference. That also matches the training data, where echo request
appears 2,293 times against 42 for echo reply.

**4. DNS over TCP was parsed as if it were DNS over UDP.** TCP frames each
message with a 2-byte length (RFC 1035 §4.2.2), so every offset shifted by
two and the length itself was read out as the query id. Only 0.09% of
training rows are TCP/53, so the blast radius is small — but the values it
produced were pure garbage, and `strip_tcp_dns_length_prefix` only strips
the prefix when the length it declares actually matches what follows, so
a continuation segment isn't silently shortened by two real bytes.

**5. The rate columns were computed as rates.** Found while wiring live
scoring, not by the review. `SRC_TO_DST_SECOND_BYTES`,
`DST_TO_SRC_SECOND_BYTES` and the two `*_AVG_THROUGHPUT` columns are not
rates in this dataset, despite their names. Measured over 3M training rows:

| column | what nProbe actually wrote | match |
|---|---|---|
| `SRC_TO_DST_SECOND_BYTES` | `IN_BYTES` | 99.85% |
| `DST_TO_SRC_SECOND_BYTES` | `OUT_BYTES` | 99.95% |
| `SRC_TO_DST_AVG_THROUGHPUT` | `IN_BYTES × 8000` | 99.58% |
| `DST_TO_SRC_AVG_THROUGHPUT` | `OUT_BYTES × 8000` | 99.87% |

Dividing by duration — what the names suggest, and what this code did —
matches **0.00%** of rows. The reason is in the data:
`FLOW_DURATION_MILLISECONDS` is 0 on **98.4%** of flows, so the exporter's
per-second figure collapses onto the byte total. The rows matching neither
formula carry durations near 4,294,935 ms — a 32-bit counter wrap — and are
the same corrupt readings `clean.py` caps.

Four features, essentially every flow. Two consequences worth stating in
the write-up: these columns carry almost no information beyond
`IN_BYTES`/`OUT_BYTES` in this dataset, and reproducing that is a
deliberate choice — the model was fitted on it, so emitting a genuine rate
would be skew even though it would be the more correct number.

One thing checked and found *correct*: packets larger than 1514 are
deliberately counted in no size bucket. nProbe does the same — across the
13 rows in 3M with `LONGEST_FLOW_PKT > 1514`, its buckets always sum short
of the packet count.

## `L7_PROTO`: mapping built, one caveat open

The training data stores nProbe's numeric `master.app` encoding; NFStream
reports the protocol *name* (`"DNS"`, `"TLS.Google"`). `l7_proto.py` closes
that by rebuilding the name → id table from the `NDPI_PROTOCOL_*` constants
the **loaded** nDPI library exports, rather than transcribing a table that
would rot on the next nfstream upgrade.

Verified against the training CSV:

- 12 of 12 well-known ids match the protocol implied by their dominant
  port (`7`↔80, `91`↔443, `5`↔53, `92`↔22, `89`↔5900, …).
- The `master.app` encoding is digit-concatenation, not a fraction:
  `HTTP.AMAZON` → `7.178` and `VNC.HTTP` → `89.7` reproduce the CSV's
  `7.177999973297119` and `89.69999694824219` exactly.
- **98.08%** of training rows hold an L7_PROTO value this mapping can
  produce.

**The caveat — an unexplained disagreement on DNS.** 2.31M of the 2.37M
UDP/53 rows in the training data are `L7_PROTO = 0` (Unknown), while our
nfstream reports `"DNS"` for UDP/53 and so encodes `5.0`. The obvious
explanation — that the unclassified flows are one-way queries nDPI never
saw a reply for — **is contradicted by the data**: those flows are
*less* one-directional than the classified ones (2.2% vs 3.1%), and both
groups sit at a median of 1 packet each way. Why nProbe left them
unclassified is currently unknown.

The 98.08% figure above measures that values are *reproducible*, not that
we would assign the *same* one to comparable traffic — so it does not
cover this. What it costs is measured instead, by
[`verify_skew.py`](verify_skew.py).

## What the skew costs (measured, not estimated)

```bash
python -m source.extraction.verify_skew
```

`L7_PROTO` is **frequency-encoded**, not fed in as an id: the model sees
how common that id was in training, standardized. So the skew is a pure
column substitution on the frozen test set — write the value our extractor
would produce, re-score with the same frozen model and threshold.

Two facts about that encoding shape everything below:

- `z(Unknown) = +0.44`, `z(any rare id) = -2.36`, `z(id the encoder never
  saw) = -2.37`. The rare ids sit **0.010 SD** apart, so the only
  distinction the model can draw from this feature is *Unknown vs. not*.
  Mis-mapping one rare protocol for another is free; crossing the Unknown
  boundary costs **2.80 SD** — and that boundary is exactly where we
  disagree.
- It also means the mapping degrades gracefully. `l7_proto.py` knows 492
  names, the encoder only ever saw 161 values, and the 331 it can't
  represent land within 0.010 SD of a correctly-mapped rare id.

The flip set is 1,045,144 rows — 16.5% of the test set.

| scenario | recall | FPR |
|---|---|---|
| S0 — baseline, as trained | 87.59% | 4.97% |
| S1 — our convention (UDP Unknown → DNS) | 86.51% | **5.44%** |
| S2 — ceiling: *every* Unknown row flips | 86.43% | 5.81% |
| S3 — our convention + threshold re-fit | 85.93% | **4.99%** |
| S4 — the ethernet-framing bug, since fixed | 91.82% | **96.43%** |

S4 is there for contrast: it is what a skew looks like when it is
genuinely dangerous. It touches ten features on every flow rather than one
feature on 16.5% of them, and it does not degrade the detector so much as
switch it off. The simulation decodes the scaled columns back to raw
NetFlow values, re-applies the bug, and re-encodes; that round-trip is
asserted to be an identity before any number is reported, because a lossy
codec would produce an equally believable table.

Three things this settles:

1. **The aggregate cost is small** (−1.09 pts recall) and S2 is barely
   worse than S1, so the realistic case is already near the ceiling.
2. **But S1 breaks the ≤5% FPR requirement** (5.44%). That, not the recall
   loss, is the reason this can't just be waved through.
3. **The fix needs no retraining.** The threshold is a percentile of
   benign reconstruction errors, valid only for the distribution it was
   fitted on; re-fitting it on a val set carrying the same shift puts FPR
   back under the cap (S3, 4.99%) for 1.66 pts of recall in total.

The damage is not spread evenly — it concentrates in two classes, which is
worth knowing before trusting a live deployment:

| class | S0 | S3 | |
|---|---|---|---|
| dos | 80.81% | 61.01% | **−19.80** |
| mitm | 78.97% | 67.03% | **−11.94** |
| every other class | | | within ±0.6 |

Full report: `artifacts/models/<run>/l7_skew.json`.

The skew also lands on DNS, separately the least trustworthy traffic in
this dataset: 95% of UDP flows are DNS, 78.3% of them are labelled attack,
and excluding UDP raises recall from 87.59% to 94.10% at the same
threshold.

## Connected to detection

```bash
python -m web.backend.live_capture --source capture.pcap
python -m web.backend.live_capture --source eth0            # needs capture privileges
```

`sensor.py` stays transform-free on purpose — it emits raw NetFlow values,
exactly as the training CSV holds them.
[`web/backend/live_capture.py`](../../web/backend/live_capture.py) feeds
those rows through
[`source/preprocessing/online.py`](../preprocessing/online.py), which is
module 2 at inference time: the rolling fan-out/fan-in state, the saved
encoders, log1p, and the saved scaler, in that order.

The part that could not be copied from the batch pipeline is the
behavioural state.
[`engineer_features.py`](../preprocessing/engineer_features.py) computes
"distinct destinations in this source's last W flows" by grouping a whole
file; serving keeps one bounded window per source, updated as flows
arrive. Same feature by a different algorithm, which is exactly the kind of
pair that drifts silently — so `tests/test_online.py` (on the `development`
branch) runs both over the same rows and asserts they agree to 1e-9, feature
by feature.

Two things worth knowing before trusting live output:

- **The threshold may need re-fitting.** It is a percentile of benign
  reconstruction errors, valid only for the distribution it was fitted on.
  The L7_PROTO skew above puts FPR at 5.44% with the frozen value; pass
  `--threshold` with one re-fitted on a val set carrying the same shift
  (S3, 4.99%). `live_capture` logs which it is using, never silently.
- **No ground truth.** Live flows are unlabelled and nothing is written to
  `replay_ground_truth`, so the dashboard's dev mode has nothing to check
  against — by design. Replay remains the only feeder that can show
  whether a detection was right.

## Tests

`tests/test_extraction.py` (on the `development` branch) builds a pcap
whose every header value is chosen by the test, then asserts each extracted
field against a known number — a parser that returns a plausible-but-wrong
value is exactly the failure this module has to be protected from, since
every downstream stage would process it correctly and silently.
