# frontend — module 5

Implementation of the `NIDS Dashboard.dc.html` canvas from the Claude Design
project *ออกแบบ Web UI สำหรับ NIDS*.

```
web/frontend/
├── index.html          # structure
├── style.css           # Modernist design-system tokens + dashboard layout
├── app.js              # all behaviour, against the real API
└── feature-labels.js   # Thai names for the 46 model inputs + per-class expectations
```

No framework, no build step, no CDN. The page is served as static files by
`web/backend/main.py` and must work inside a Docker image with no network.

## Where this departs from the canvas, and why

The design mock generates its own flows in the browser. Three of its
controls only make sense against fabricated data, and shipping them would
mean the dashboard lying about the one thing it exists to report:

| canvas | here |
|---|---|
| "Switch to live / replay" button | The banner is **derived** from the data — ground truth present means replay. A button claiming to change the data source without changing it is a lie in the worst possible place. |
| "Simulate outage" button | Removed. Stall detection is real: it fires when no flow has actually arrived for 15s. |
| Placeholder feature names (CIC-IDS style) | The project's own 46 NF-ToN-IoT columns, with the Thai labels from `feature-labels.js`. |

Chart.js is gone: the canvas draws the trend as inline SVG, which removes a
vendored dependency rather than adding one.

The design asks the explanation panel to show each feature "in its real
unit, de-standardized with the training mean and σ". `GET /meta` exists for
that — it serves the scaler constants and each column's kind, so the panel
inverts `log1p → StandardScaler` exactly. Frequency- and one-hot-encoded
columns have no physical unit and say so (`5.06% of training`, `yes`/`no`)
rather than being dressed up as measurements.

## Two invariants worth keeping

**Everything reaching `innerHTML` goes through `esc()`.** This page renders
attacker-controlled strings — IPs, ports, protocol names, firewall rule
text. An XSS here would be delivered by the tool meant to detect it.

**A silent bucket is never drawn as 0%.** `anomaly_rate: null` means the
model saw nothing; 0.0 means it saw traffic and flagged none. The chart
hatches the first and plots the second, and the legend names both. Merging
them would make a dead sensor look like a clean network.

## Verifying a change

`tests/` covers the backend. The page itself is checked by driving a
headless browser over CDP: load it, assert no console errors and no failed
requests, then exercise each tab, the SHAP panel, the keyboard shortcuts,
the filters and the trend drag-select. Two bugs in this implementation were
caught that way and by nothing else — a `const` colliding with
`feature-labels.js` (which killed the whole script), and a `*/` inside a CSS
comment that swallowed the entire `:root` token block while leaving the
layout working, so the page rendered but had no colour at all.
