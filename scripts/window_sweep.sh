#!/usr/bin/env bash
# Sequential window-size sweep for the behavioral (fan-out/fan-in) features.
# For each W: rebuild the full processed dataset, train the current-best
# architecture (latent=48, hidden=[128,64]) on it, pick a threshold at
# FPR<=5%, and evaluate on test -- so W is chosen empirically instead of
# staying at the first value that happened to work (50).
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

for W in 20 50 100 200; do
  echo "=== W=$W: preprocessing ==="
  python -m source.preprocessing.pipeline \
    --output-dir "data/processed_w${W}" \
    --artifacts-dir "artifacts/preprocessing_w${W}" \
    --behavioral-window "$W"

  echo "=== W=$W: training ==="
  python -m source.model.train \
    --processed-dir "data/processed_w${W}" \
    --artifacts-dir "artifacts/models/w${W}" \
    --latent-dim 48 --hidden-dims 128 64 \
    --lr 0.001 --batch-size 1024 --dropout 0.05 \
    --epochs 100 --patience 10 --seed 42

  echo "=== W=$W: threshold ==="
  python -m source.model.threshold \
    --processed-dir "data/processed_w${W}" \
    --artifacts-dir "artifacts/models/w${W}"

  echo "=== W=$W: evaluate ==="
  python -m source.model.evaluate \
    --processed-dir "data/processed_w${W}" \
    --artifacts-dir "artifacts/models/w${W}"

  echo "=== W=$W: DONE ==="
done

echo "=== window sweep complete ==="
