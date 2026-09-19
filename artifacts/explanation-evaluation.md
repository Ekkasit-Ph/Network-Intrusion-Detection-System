# Explanation quality

Kernel SHAP, background 100 benign training rows, 46 features. Deployed setting is nsamples=100.

## Local accuracy

`base_value + sum(shap) == reconstruction_error` holds to 1.13e-17 at worst over 10 flows.

## Stability: the same flow, explained repeatedly

| nsamples | ms/explain | spread / mean\|shap\| | top-5 agreement | Spearman | sign flips |
|---|---|---|---|---|---|
| 100 | 8.8 | 5.78 | 23% | 0.418 | 75% |
| 500 | 40.9 | 3.25 | 39% | 0.530 | 66% |
| 1000 | 85.7 | 2.59 | 61% | 0.679 | 52% |
| 2000 | 166.6 | 2.37 | 72% | 0.777 | 35% |
| 5000 | 389.5 | 1.66 | 85% | 0.843 | 25% |

Two independent random 5-subsets would agree 11% of the time, which is the line any of these numbers has to clear to mean anything.

## Accuracy against a converged reference

Reference is the mean of 3 runs at nsamples=20000.

| nsamples | Spearman vs reference | top-5 vs reference | mean abs error / mean\|shap\| |
|---|---|---|---|
| 100 | 0.385 | 25% | 2.44 |
| 500 | 0.583 | 52% | 0.96 |
| 1000 | 0.715 | 60% | 0.68 |
| 2000 | 0.774 | 78% | 0.50 |
| 5000 | 0.839 | 88% | 0.31 |

