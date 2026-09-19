# Resource benchmark

**11th Gen Intel(R) Core(TM) i5-11320H @ 3.20GHz** · 8 logical cores · 15.4 GB RAM · NVIDIA GeForce GTX 1650 · torch 2.13.0+cu130 · Linux 7.0.11-76070011-generic

Stages 1-2 run on a generated pcap; stages 3-4 on real rows from the test split.

CPU-time budgets under cgroup v2, torch kernels `default`. A scaled-down x86: memory bandwidth, cache and instruction set are this machine's, not a board's.

| configuration | extract (flow/s) | transform (flow/s) | score batched (flow/s) | score 1 flow p50 / p95 (ms) | SHAP p50 / p95 (ms) | model RSS (MB) |
|---|---|---|---|---|---|---|
| quota-25pct | 289 | 2,459 | 105,053 | 0.067 / 0.226 | 114.25 / 191.014 | 2.9 |
| quota-50pct | 623 | 9,095 | 670,316 | 0.066 / 0.236 | 27.797 / 79.664 | 2.9 |
| quota-100pct | 1,829 | 20,486 | 999,298 | 0.071 / 0.076 | 17.617 / 18.783 | 2.9 |
| quota-200pct | 5,145 | 19,792 | 1,494,123 | 0.068 / 0.082 | 14.825 / 15.834 | 2.9 |
| quota-400pct | 7,886 | 20,311 | 1,602,623 | 0.066 / 0.076 | 10.323 / 11.302 | 2.9 |
