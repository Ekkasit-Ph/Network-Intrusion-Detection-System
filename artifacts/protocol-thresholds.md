# Per-protocol thresholds

Fitted on validation, applied unchanged to test. The model is calibrated differently for TCP than for UDP, so one cut point spends the false-positive budget unevenly between them.

| policy | thresholds | recall | FPR | precision | TCP FPR | UDP FPR |
|---|---|---|---|---|---|---|
| global | 0.001944 | 87.59% | 4.97% | 99.05% | 4.65% | 6.69% |
| equal-fpr | other 0.010213 / tcp 0.001844 / udp 0.002418 | 86.36% | 4.96% | 99.04% | 4.98% | 4.81% |
| budgeted | other 1.514246 / tcp 0.001924 / udp 0.001823 | 87.72% | 4.97% | 99.05% | 4.73% | 7.64% |

## Per-class detection rate

| class | global | equal-fpr | budgeted |
|---|---|---|---|
| backdoor | 99.92% | 99.83% | 99.98% |
| ransomware | 99.71% | 99.77% | 99.71% |
| password | 99.10% | 99.26% | 99.15% |
| ddos | 98.88% | 98.38% | 98.99% |
| injection | 92.55% | 92.60% | 92.73% |
| scanning | 87.17% | 87.54% | 87.23% |
| dos | 80.81% | 61.87% | 81.37% |
| mitm | 78.97% | 65.42% | 79.88% |
| xss | 74.04% | 73.88% | 74.17% |
