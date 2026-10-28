# Training the ML fallback

1. Download the [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)
   and save it as `training/data/raw_ioc_dataset.csv` (not committed).
2. Run from the repository root:

```bash
python training/retrain_m1.py training/data/raw_ioc_dataset.csv app/cti/m1_model.py training/output
```

The script reduces every URL to its bare lower-case host (same rule as the scorer, `www.` removed),
drops hosts with conflicting labels, merges defacement/phishing/malware into one malicious class, splits
80/20 by host (seed 42) so no host is in both sets, computes features with the production
`build_feature_vector()`, trains the seven models and writes models, `training_report.json`,
`sanity_check.json` and charts. Copy the files from `training/output/models/` into `app/models/models/` to deploy.

Reference results are in `results/`. Library versions must match `requirements.txt` for the pickled models to load.
