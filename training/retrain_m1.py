#!/usr/bin/env python3
"""
retrain_m1.py - retrain the Module 1 URL/domain fallback ensemble WITHOUT label leakage.

Why: the original training used `category_weight` (0.0 for benign, 0.9-1.0 for malicious,
i.e. derived from the label) and `risk_score` (which contains category_weight), so every model
scored a perfect 1.0. At inference category_weight is a constant 0.5, so the deployed ensemble
labelled every input (including google.com) as malicious.

What this script does:
  1. Loads raw_ioc_dataset.csv (Kaggle "Malicious URLs dataset": benign / defacement / phishing / malware).
  2. Drops corrupted rows and duplicates; label = 0 for benign, 1 otherwise (same as the original).
  3. Computes features with the SAME build_feature_vector() used at inference (app/cti/m1_model.py),
     minus four features that must not be used:
        category_weight  - leaks the label
        risk_score       - contains category_weight
        url_hash_mod     - hash of the URL, carries no meaning
        ip_int           - raw IP as an integer, arbitrary ordering
  4. Splits 80/20 GROUPED BY DOMAIN, so no domain appears in both train and test.
  5. Trains the same 7 model types with fixed hyper-parameters (no Optuna), equal ensemble weights.
  6. Evaluates each model and the ensemble; writes drop-in model files + training_report.json.

Usage:
  python retrain_m1.py <raw_ioc_dataset.csv> <path/to/m1_model.py> <output_dir>
"""
import importlib.util
import json
import os
import re
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, average_precision_score)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

SEED = 42
DROP = {"category_weight", "risk_score", "url_hash_mod", "ip_int", "has_www"}
ALL_COLS = [
    "url_length", "domain_length", "url_entropy", "domain_entropy", "is_ip", "ip_int", "dot_count",
    "slash_count", "hyphen_count", "underscore_count", "question_count", "equal_count", "and_count",
    "at_count", "digit_ratio", "letter_ratio", "special_char_ratio", "has_https", "has_http",
    "no_protocol", "subdomain_count", "has_www", "path_length", "path_depth", "has_at_symbol",
    "has_double_slash", "consecutive_dots", "has_ip_pattern", "tld_length", "suspicious_tld",
    "category_weight", "url_hash_mod", "risk_score",
]
FEATURES = [c for c in ALL_COLS if c not in DROP]
LABELS = {"benign": 0, "defacement": 1, "phishing": 1, "malware": 1}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalise_host(value: str) -> str:
    """Identical to app/cti/scorer.py::_normalise (value part)."""
    v = value.strip()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].split("?")[0].split(":")[0]
    return v.lower()


def load_m1(path):
    spec = importlib.util.spec_from_file_location("m1_model", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_models(scale_pos):
    from catboost import CatBoostClassifier
    from lightgbm import LGBMClassifier
    from xgboost import XGBClassifier
    return {
        "decision_tree": DecisionTreeClassifier(max_depth=18, min_samples_leaf=10, random_state=SEED),
        "random_forest": RandomForestClassifier(n_estimators=100, max_depth=16, min_samples_leaf=10,
                                                n_jobs=-1, random_state=SEED),
        "extra_trees": ExtraTreesClassifier(n_estimators=100, max_depth=18, min_samples_leaf=10,
                                            n_jobs=-1, random_state=SEED),
        "gradient_boosting": GradientBoostingClassifier(n_estimators=150, max_depth=5, learning_rate=0.1,
                                                        subsample=0.5, random_state=SEED),
        "xgboost": XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.8,
                                 colsample_bytree=0.8, tree_method="hist", n_jobs=-1,
                                 eval_metric="logloss", random_state=SEED),
        "catboost": CatBoostClassifier(iterations=400, depth=7, learning_rate=0.1, thread_count=-1,
                                       random_seed=SEED, verbose=0, allow_writing_files=False),
        "lightgbm": LGBMClassifier(n_estimators=400, num_leaves=63, learning_rate=0.1, subsample=0.8,
                                   subsample_freq=1, colsample_bytree=0.8, n_jobs=-1,
                                   random_state=SEED, verbose=-1),
    }


def metrics(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "auc_roc": round(roc_auc_score(y, p), 4),
        "pr_auc": round(average_precision_score(y, p), 4),
        "fpr": round(fp / max(fp + tn, 1), 4),
        "true_negatives": int(tn), "false_positives": int(fp),
        "false_negatives": int(fn), "true_positives": int(tp),
    }


def main(raw_csv, m1_path, out_dir):
    os.makedirs(os.path.join(out_dir, "models", "catboost"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "data"), exist_ok=True)
    m1 = load_m1(m1_path)

    # 1-2. load + clean
    df = pd.read_csv(raw_csv, encoding="utf-8", encoding_errors="replace", on_bad_lines="skip")
    n_raw = len(df)
    df = df[df["type"].isin(LABELS)].copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]
    df = df[df["url"].map(lambda s: s.isascii())]
    df = df.drop_duplicates(subset="url")
    df["label"] = df["type"].map(LABELS).astype(int)
    n_urls = len(df)
    # Module 1 never sees full URLs at inference: scorer._normalise() reduces every indicator to a
    # bare lower-case host (scheme, path, query and port removed) before calling the model.
    # Train on exactly that representation, one row per host.
    df["url"] = df["url"].map(normalise_host)
    df = df[df["url"].str.len() > 0]
    lab = df.groupby("url")["label"].agg(["min", "max"])
    conflict = set(lab.index[lab["min"] != lab["max"]])   # host seen as both benign and malicious
    df = df[~df["url"].isin(conflict)].drop_duplicates(subset="url")
    df["domain"] = df["url"]
    log(f"rows raw={n_raw} clean_urls={n_urls} hosts={len(df)} (dropped {len(conflict)} conflicting hosts) | "
        f"{df['type'].value_counts().to_dict()}")

    # 3. features with the inference-time function
    t = time.time()
    X = np.vstack([m1.build_feature_vector(u, FEATURES) for u in df["url"].values])
    keep = [i for i in range(X.shape[1]) if np.unique(X[:, i]).size > 1]
    dropped_const = [FEATURES[i] for i in range(X.shape[1]) if i not in keep]
    FEATURES[:] = [FEATURES[i] for i in keep]
    X = X[:, keep]
    log(f"constant on bare hosts, removed: {dropped_const}")
    y = df["label"].values
    groups = df["domain"].values
    log(f"features {X.shape} built in {time.time() - t:.0f}s")

    # 4. domain-grouped split
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr, te = next(gss.split(X, y, groups))
    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]
    assert not set(groups[tr]) & set(groups[te]), "domain overlap between train and test"
    pd.DataFrame(Xte, columns=FEATURES).assign(label=yte, url=df["url"].values[te]).to_csv(
        os.path.join(out_dir, "data", "test_split.csv"), index=False)
    log(f"train={len(tr)} (mal={ytr.sum()}) test={len(te)} (mal={yte.sum()})")

    # 5. train
    models = make_models(scale_pos=(ytr == 0).sum() / max((ytr == 1).sum(), 1))
    results, probs, importances = [], {}, {}
    for name, model in models.items():
        t = time.time()
        model.fit(Xtr, ytr)
        tt = time.time() - t
        t = time.time()
        p = model.predict_proba(Xte)[:, 1]
        et = time.time() - t
        probs[name] = p
        r = {"model": name, **metrics(yte, p), "train_time_s": round(tt, 1), "eval_time_s": round(et, 3)}
        results.append(r)
        imp = getattr(model, "feature_importances_", None)
        if imp is not None:
            imp = np.asarray(imp, dtype=float)
            imp = imp / imp.sum() if imp.sum() else imp
            importances[name] = dict(sorted(zip(FEATURES, map(float, imp)), key=lambda kv: -kv[1]))
        if name == "catboost":
            model.save_model(os.path.join(out_dir, "models", "catboost", "model.cbm"))
        else:
            joblib.dump(model, os.path.join(out_dir, "models", f"{name}.pkl"), compress=3)
        log(f"{name:18s} F1={r['f1']} AUC={r['auc_roc']} FPR={r['fpr']} train={tt:.0f}s")

    # 6. ensemble (equal weights, same rule as URLPredictor.predict)
    weights = {n: round(1 / len(models), 4) for n in models}
    ens = sum(probs[n] * weights[n] for n in models) / sum(weights.values())
    ens_metrics = {"at_0.5": metrics(yte, ens, 0.5), "at_0.6": metrics(yte, ens, 0.6)}
    joblib.dump(weights, os.path.join(out_dir, "models", "ensemble_meta.pkl"))
    np.save(os.path.join(out_dir, "data", "ensemble_test_scores.npy"), np.vstack([yte, ens]))
    with open(os.path.join(out_dir, "data", "feature_columns.json"), "w") as f:
        json.dump(FEATURES, f, indent=2)
    with open(os.path.join(out_dir, "models", "feature_importance.json"), "w") as f:
        json.dump(importances, f, indent=2)

    # 5-fold grouped CV on the training split for the fast learners (stability check)
    cv = {}
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    for name in ("decision_tree", "lightgbm", "xgboost"):
        f1s, aucs = [], []
        for a, b in sgkf.split(Xtr, ytr, groups[tr]):
            m = make_models(1)[name]
            m.fit(Xtr[a], ytr[a])
            pp = m.predict_proba(Xtr[b])[:, 1]
            f1s.append(f1_score(ytr[b], pp >= 0.5)); aucs.append(roc_auc_score(ytr[b], pp))
        cv[name] = {"f1_mean": round(float(np.mean(f1s)), 4), "f1_sd": round(float(np.std(f1s)), 4),
                    "auc_mean": round(float(np.mean(aucs)), 4), "auc_sd": round(float(np.std(aucs)), 4)}
        log(f"CV {name}: F1 {cv[name]['f1_mean']}±{cv[name]['f1_sd']}")

    report = {
        "training_mode": "fixed-hyperparameters, leakage-free (retrain_m1.py)",
        "dataset": "Kaggle Malicious URLs dataset (raw_ioc_dataset.csv): benign/defacement/phishing/malware",
        "label_rule": "benign=0; defacement, phishing, malware=1",
        "removed_features": sorted(DROP),
        "input_representation": "bare host as produced by scorer._normalise (one row per unique host; hosts labelled both benign and malicious dropped)",
        "split": "80/20 GroupShuffleSplit by host (no host in both train and test), seed 42",
        "feature_columns": FEATURES,
        "ensemble_weights": weights,
        "models": results,
        "ensemble": ens_metrics,
        "cv_5fold_grouped_on_train": cv,
        "dataset_info": {
            "raw_rows": int(n_raw), "clean_unique_rows": int(len(df)),
            "train_samples": int(len(tr)), "test_samples": int(len(te)),
            "train_benign": int((ytr == 0).sum()), "train_malicious": int((ytr == 1).sum()),
            "test_benign": int((yte == 0).sum()), "test_malicious": int((yte == 1).sum()),
            "per_type": df["type"].value_counts().to_dict(),
        },
    }
    with open(os.path.join(out_dir, "models", "training_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    log("ENSEMBLE @0.5: " + json.dumps(ens_metrics["at_0.5"]))
    log("ENSEMBLE @0.6: " + json.dumps(ens_metrics["at_0.6"]))
    log("DONE")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
