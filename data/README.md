# data/

- `raw/` — put (or symlink) the NF-ToN-IoT-v2 CSV here, e.g.:
  `ln -s ../../Dataset/data/NF-ToN-IoT-v2.csv data/raw/NF-ToN-IoT-v2.csv`
  `source/preprocessing/pipeline.py` looks here first and falls back to
  `Dataset/data/NF-ToN-IoT-v2.csv` if `raw/` is empty.
- `processed/` — output of `python -m source.preprocessing.pipeline`:
  `train.parquet`, `val.parquet`, `test.parquet`, `feature_columns.json`,
  `preprocessing_report.json`.

Both subfolders are gitignored (large/derived data doesn't belong in git).
