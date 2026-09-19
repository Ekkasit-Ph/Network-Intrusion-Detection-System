# Resource benchmark

**11th Gen Intel(R) Core(TM) i5-11320H @ 3.20GHz** · 8 logical cores · 15.4 GB RAM · NVIDIA GeForce GTX 1650 · torch 2.13.0+cu130 · Linux 7.0.11-76070011-generic

Stages 1-2 run on a generated pcap; stages 3-4 on real rows from the test split.

| configuration | extract (flow/s) | transform (flow/s) | score batched (flow/s) | score 1 flow p50 / p95 (ms) | SHAP p50 / p95 (ms) | model RSS (MB) |
|---|---|---|---|---|---|---|
| cpu-1core | 4,460 | 20,098 | 1,341,822 | 0.065 / 0.071 | 13.409 / 14.697 | 3.0 |
| cpu-2core | 5,530 | 19,962 | 1,790,638 | 0.067 / 0.101 | 10.684 / 12.178 | 3.1 |
| cpu-8core-all | 8,796 | 20,385 | 2,131,340 | 0.067 / 0.083 | 8.716 / 10.191 | 3.1 |
| gpu | 8,630 | 20,178 | 5,033,637 | 0.136 / 0.149 | 6.461 / 7.006 | 90.8 |
