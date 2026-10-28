
import os
import json
import math
import re
import hashlib
import warnings
from urllib.parse import urlparse
from collections import Counter

import numpy as np
import joblib

warnings.filterwarnings("ignore")

MALICIOUS_THRESHOLD = 0.5


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def extract_domain(url: str) -> str:
    url = str(url).strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        return domain.split(":")[0]
    except Exception:
        url = re.sub(r"^https?://", "", url)
        return url.split("/")[0].split(":")[0]


def is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value.strip()))


def ip_to_int(ip: str) -> int:
    try:
        parts = list(map(int, ip.strip().split(".")))
        if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
            return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        pass
    return 0


def build_feature_vector(url: str, feature_cols: list) -> np.ndarray:
    url = str(url).strip()
    # Retrain fix: a leading "www." is a labelling artefact of the training dataset
    # (5% of benign hosts vs 35% of phishing hosts), so it is removed before features are computed.
    url = re.sub(r"^(https?://)?www\.", r"\1", url, flags=re.IGNORECASE)
    domain = extract_domain(url)
    tld = domain.split(".")[-1] if "." in domain else ""
    suspicious_tlds = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work"]

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(url.split("/", 3)[-1]) if "/" in url else 0,
        "path_depth": url.count("/"),
        "url_entropy": shannon_entropy(url),
        "domain_entropy": shannon_entropy(domain),
        "is_ip": int(is_ip(domain)),
        "ip_int": ip_to_int(domain) if is_ip(domain) else 0,
        "dot_count": url.count("."),
        "slash_count": url.count("/"),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "and_count": url.count("&"),
        "at_count": url.count("@"),
        "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
        "letter_ratio": sum(c.isalpha() for c in url) / max(len(url), 1),
        "special_char_ratio": sum(not c.isalnum() for c in url) / max(len(url), 1),
        "has_https": int("https://" in url.lower()),
        "has_http": int("http://" in url.lower()),
        "no_protocol": int(not url.lower().startswith("http")),
        "subdomain_count": min(domain.count("."), 10),
        "has_www": int(domain.startswith("www.")),
        "has_at_symbol": int("@" in url),
        "has_double_slash": int("//" in url),
        "consecutive_dots": int(".." in url),
        "has_ip_pattern": int(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url))),
        "tld_length": len(tld),
        "suspicious_tld": int(tld in suspicious_tlds),
        "category_weight": 0.5,
        "url_hash_mod": int(hashlib.md5(url.encode()).hexdigest(), 16) % 1000,
        "risk_score": 0.0,
    }

    features["risk_score"] = min(max(
        features["category_weight"] * 0.4
        + features["url_entropy"] / 10 * 0.2
        + features["suspicious_tld"] * 0.2
        + features["has_at_symbol"] * 0.1
        + features["is_ip"] * 0.1,
        0.0,
    ), 1.0)

    vector = np.array([features.get(col, 0.0) for col in feature_cols], dtype=np.float32)
    return vector.reshape(1, -1)


class URLPredictor:
    MODEL_FILES = {
        "decision_tree": ("pkl", "decision_tree.pkl"),
        "random_forest": ("pkl", "random_forest.pkl"),
        "extra_trees": ("pkl", "extra_trees.pkl"),
        "gradient_boosting": ("pkl", "gradient_boosting.pkl"),
        "xgboost": ("pkl", "xgboost.pkl"),
        "catboost": ("cbm", "catboost/model.cbm"),
        "lightgbm": ("pkl", "lightgbm.pkl"),
    }

    def __init__(self, model_dir: str, feature_file: str):
        self.model_dir = model_dir

        with open(feature_file) as f:
            self.feature_cols = json.load(f)

        self.models = {}
        self.meta_weights = joblib.load(os.path.join(model_dir, "ensemble_meta.pkl"))

        for name, (fmt, rel_path) in self.MODEL_FILES.items():
            full_path = os.path.join(model_dir, rel_path)
            if not os.path.exists(full_path):
                continue
            try:
                if fmt == "cbm":
                    from catboost import CatBoostClassifier
                    m = CatBoostClassifier()
                    m.load_model(full_path)
                else:
                    m = joblib.load(full_path)
                self.models[name] = m
            except Exception:
                continue

        if not self.models:
            raise RuntimeError("No models were loaded successfully!")

    def predict(self, url: str, return_details: bool = True) -> dict:
        X = build_feature_vector(url, self.feature_cols)

        model_scores = {}
        weighted_sum = 0.0
        weight_sum_used = 0.0

        for name, model in self.models.items():
            try:
                proba = float(model.predict_proba(X)[0][1])
                model_scores[name] = round(proba, 4)
                w = self.meta_weights.get(name, 1.0 / len(self.models))
                weighted_sum += proba * w
                weight_sum_used += w
            except Exception:
                continue

        ensemble_score = round(float(weighted_sum / weight_sum_used) if weight_sum_used > 0 else 0.0, 4)
        is_malicious = ensemble_score >= MALICIOUS_THRESHOLD
        decision = "MALICIOUS" if is_malicious else "BENIGN"

        distance = abs(ensemble_score - MALICIOUS_THRESHOLD)
        confidence = "HIGH" if distance >= 0.3 else "MEDIUM" if distance >= 0.15 else "LOW"

        result = {
            "url": url,
            "probability": ensemble_score,
            "decision": decision,
            "confidence": confidence,
            "threshold": MALICIOUS_THRESHOLD,
        }

        if return_details:
            result["model_scores"] = model_scores
            result["model_agreement"] = round(
                sum(1 for s in model_scores.values() if (s >= MALICIOUS_THRESHOLD) == is_malicious)
                / len(model_scores), 2
            ) if model_scores else 0.0
            result["meta_weights"] = self.meta_weights

        return result

    def predict_batch(self, urls: list, return_details: bool = False) -> list:
        results = []
        for item in urls:
            url = item if isinstance(item, str) else item.get("url", "")
            if url:
                results.append(self.predict(url, return_details=return_details))
        return results

    def get_model_info(self) -> dict:
        return {
            "num_models": len(self.models),
            "models": list(self.models.keys()),
            "num_features": len(self.feature_cols),
            "threshold": MALICIOUS_THRESHOLD,
            "meta_weights": self.meta_weights,
        }
