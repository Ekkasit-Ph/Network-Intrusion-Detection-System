# FlowSentry demo container — serves the FastAPI backend + static dashboard
# (web/backend/main.py) from one process, pre-loaded with the deployed
# champion model (artifacts/models/optuna-denoising-50) and just enough of
# data/processed_w50/ to run: train.parquet for the SHAP background sample,
# test.parquet for replay_demo.py's live-flow feed. val.parquet is
# deliberately not copied in -- it's only used by threshold.py/evaluate.py,
# never at serve time (see .dockerignore).
#
# CPU-only PyTorch on purpose: the deployed model is tiny (see
# artifacts/models/README.md), inference is a few ms either way, and CPU
# avoids depending on the presentation machine having a GPU + NVIDIA
# container runtime set up correctly on exam day.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install torch's CPU wheel explicitly first -- otherwise pip's default
# resolution for `torch>=2.2` in requirements.txt below pulls the much
# larger CUDA-bundled wheel (~2GB+) even though this image never uses a GPU.
COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

# Application code.
COPY source/ source/
COPY web/ web/
# Only firewall_rules.py, and only because module 6 needs a rule file to
# compare against -- `python -m network_simulation.firewall_rules --format ryu`
# is a step in the demo. The rest of the simulation (topology.py, ryu_app.py,
# the GNS3 lab, attack scripts) needs Mininet and Ryu and lives on the
# `development` branch, not in this image.
COPY network_simulation/__init__.py network_simulation/firewall_rules.py network_simulation/

# Deployed model + its paired preprocessing artifacts (scaler, encoders) --
# see artifacts/models/README.md for what each of these is.
COPY artifacts/models/optuna-denoising-50/ artifacts/models/optuna-denoising-50/
COPY artifacts/preprocessing_w50/ artifacts/preprocessing_w50/

# Just the processed-data files actually read at serve time (see header
# comment) -- explicit per-file COPY so val.parquet (176MB, never used here)
# doesn't end up in the image even by accident.
COPY data/processed_w50/feature_columns.json data/processed_w50/train.parquet data/processed_w50/test.parquet \
     data/processed_w50/

# SQLite DB lives here at runtime (created on first write by
# web/backend/database.py) -- must exist and be writable.
RUN mkdir -p data

ENV NIDS_MODEL_DIR=/app/artifacts/models/optuna-denoising-50
ENV NIDS_PROCESSED_DIR=/app/data/processed_w50
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "web.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
