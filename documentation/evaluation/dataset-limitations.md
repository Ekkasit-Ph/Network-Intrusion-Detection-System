# NF-ToN-IoT-v2: measured limitations

Findings about the dataset itself, each with the measurement behind it.
None of these are reasons to abandon it — it is a reasonable choice for
this project — but every reported number is bounded by them, and a result
quoted without them overstates what was shown.

Reproduce with `python -m source.extraction.verify_skew` and the scripts
referenced per section.

---

## 1. UDP is 95% DNS, and 78.3% of it is labelled attack

The single largest distortion. In this dataset, "is it UDP" is very nearly
"is it an attack", and a detector can score well on UDP without learning
anything about attacks.

| | |
|---|---|
| UDP flows that are DNS | 95% |
| UDP flows labelled attack | 78.3% |
| `xss`-labelled flows that are DNS | 51% |
| true positives that are UDP/DNS | 11.9% |

Excluding UDP entirely and re-scoring at the **same frozen threshold**:

| | recall | FPR | macro F1 |
|---|---|---|---|
| full test set | 87.59% | 4.97% | 0.819 |
| UDP excluded | **94.10%** | 4.81% | **0.9025** |

The model gets substantially *better* when the most contaminated protocol
is removed, which is the opposite of what a genuinely learned UDP
signature would produce. Read 87.59% as the headline number and 94.10% as
what the detector does on traffic whose labels can be trusted.

This is a diagnostic view, not a re-tune: the threshold was frozen before
the split was made, and nothing was re-selected on it.

## 2. Session-level labelling contaminates individual flows

ToN-IoT labels by attack *session*, not by flow. Every flow a host produced
during an attack window inherits that window's label, including the ones
that were the host doing something ordinary.

The clearest instance: **`xss` is 51% DNS**. A cross-site scripting attack
is an HTTP payload. Those DNS flows are the attacking host's name lookups,
labelled `xss` because they happened during the session.

Two consequences:

- Some "false positives" are the model correctly identifying benign traffic
  that carries an attack label. The reported FPR is therefore an
  upper bound on the real one.
- Some "true positives" are the model flagging a DNS lookup that is only
  nominally an attack. Reported recall is correspondingly generous.

Neither can be corrected without re-labelling, which is out of scope. They
push in opposite directions and do not cancel.

## 3. Anomalous is not the same as attack

This is a property of the approach, not of the dataset, but the dataset
makes it visible. An autoencoder flags what does not reconstruct like
benign training data. A benign flow that is unusual — a backup starting, a
new device appearing — is anomalous and is not an attack.

The project's own earlier version hit exactly this: normal flows occurring
during an attack window scored as anomalous, correctly, because they *were*
unusual. Nothing in an unsupervised detector can close that distinction;
what module 4 (SHAP) provides is the ability for an operator to see *why* a
flow was flagged and make the call themselves.

## 4. `FLOW_DURATION_MILLISECONDS` is 0 on 98.4% of flows

The exporter did not meaningfully populate it. Consequences:

- The two `*_SECOND_BYTES` and two `*_AVG_THROUGHPUT` columns are not
  rates. Measured over 3M rows, `SRC_TO_DST_SECOND_BYTES == IN_BYTES` on
  99.85% and `SRC_TO_DST_AVG_THROUGHPUT == IN_BYTES × 8000` on 99.58%.
  Dividing by duration matches **0.00%** of rows. So four of the 46
  features carry almost nothing beyond `IN_BYTES`/`OUT_BYTES`.
- The rows that do carry a duration include values near 4,294,935 ms — a
  32-bit counter wrap — alongside finite-but-nonsensical byte rates up to
  ~1e304, which `source/preprocessing/clean.py` caps at the 99th
  percentile.

Detail and method: [`../source/extraction/README.md`](../../source/extraction/README.md).

## 5. `L7_PROTO` is unclassified on 97.5% of UDP/53 flows

2.31M of 2.37M UDP/53 rows carry `L7_PROTO = 0` (Unknown), while a current
nDPI build labels the same traffic `DNS`. **Why is unexplained.** The
obvious hypothesis — that the unclassified flows are one-way queries whose
replies were never captured — is contradicted by the data: those flows are
*less* one-directional than the classified ones (2.2% vs 3.1%), with both
groups at a median of one packet each way.

The consequence for deployment is measured rather than argued: it moves FPR
from 4.97% to 5.44%, past this project's 5% ceiling, and re-fitting the
threshold on a val set carrying the same shift restores it to 4.99% at a
cost of 1.66 points of recall.

## 6. Ten hosts produce 94% of 16.9M rows

The testbed is small, and the *same* host generates both benign and attack
traffic (192.168.1.31 alone: 2.29M benign, 798K ddos, 651K scanning).

This is why identifier columns are dropped before the model sees a row, and
why the engineered behavioural features use a **bounded trailing window per
source** rather than a global per-IP aggregate. A global aggregate would be
near-constant per host, and the model would learn to recognise *which
testbed machine this is* rather than any behaviour — and a benign row's
feature value would be influenced by the same host's attack flows elsewhere
in the file, including ones that later land in val/test.

Reasoning in full:
[`../source/preprocessing/engineer_features.py`](../../source/preprocessing/engineer_features.py).

## 7. No flow-start timestamp

The CSV has no timestamp column at all. The behavioural features need a
causal ordering, so **original CSV row order** is used as a
pseudo-chronological proxy — a NetFlow exporter appends completed flows in
roughly export order, but this is an approximation, not a guarantee.

It is the reason `add_behavioral_features` must run before `split_data`:
each row's value is finalised from that source's earlier-in-order flows
before any train/val/test assignment exists, so no split can leak into
another's feature values regardless of where rows land.

---

## What to say about results

- Quote **87.59% recall at 4.97% FPR** as the headline, on the full test
  set at a threshold fixed on validation data.
- Quote **94.10%** as the clean-subset figure, stating that UDP was
  excluded and why.
- State that FPR is an upper bound, because session-level labelling means
  some flagged flows are benign traffic wearing an attack label.
- Do not claim the system distinguishes attack from merely-unusual. It
  distinguishes usual from unusual, and module 4 exists so a human can make
  the rest of the judgement.
