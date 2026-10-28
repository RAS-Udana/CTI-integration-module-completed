
import json
import logging
import threading
from functools import lru_cache

from app.settings import settings
from config.category_technique_map import CATEGORY_TECHNIQUE_MAP
from config import malware_family_synonyms as family_synonyms

log = logging.getLogger("mitre_weights")

S_UNKNOWN = settings.S_UNKNOWN
S_MIN_DEFAULT = 0.10

_lock = threading.Lock()
_cache = {}


def _load() -> dict:
    with _lock:
        if "data" in _cache:
            return _cache["data"]
        try:
            with open(settings.SEVERITY_WEIGHTS_PATH) as f:
                data = json.load(f)
        except FileNotFoundError:
            log.error(
                "severity_weights.json not found at %s — run "
                "tools/derive_severity.py first. Falling back to S_UNKNOWN "
                "for every category.",
                settings.SEVERITY_WEIGHTS_PATH,
            )
            data = {"weights": {}, "s_min": S_MIN_DEFAULT, "attack_bundle_version": None}
        _cache["data"] = data
        return data


def get_weights_table() -> dict:
    """Full derived table: weights, raw_counts, bundle version/hash, etc."""
    return _load()


def normalize_category(raw: str) -> str:
    return raw.strip().lower().replace("-", "_").replace(" ", "_")


def compute_severity(threat_category, s_unknown: float = None) -> tuple[float, bool]:
    """Returns (severity_value, was_defaulted).

    threat_category: a single canonical category string, or None.
    """
    s_unknown = S_UNKNOWN if s_unknown is None else s_unknown
    table = _load()
    weights = table.get("weights", {})

    if threat_category is None:
        return s_unknown, True

    key = normalize_category(threat_category)
    if key not in weights:
        log.warning("unmapped threat category: %r", threat_category)
        return s_unknown, True

    return weights[key], False


def category_for_tags(tags: list) -> tuple[str, float, bool]:
    """Match free-text feed tags (URLhaus/ThreatFox 'tags') against the
    MITRE-derived category table.

    Two passes, both preferring the highest-severity match when a tag
    list touches more than one category (e.g. an APT group's own RAT
    resolves to apt, not botnet_c2 — same "worst case wins" tie-break
    either way):

    1. Malware-family / threat-actor name lookup
       (config/malware_family_synonyms.py) — this is what real feed
       tags actually look like ("valleyrat", "silverfox"), not
       category words.
    2. Literal category-word substring match (original behavior) —
       covers feeds that do tag things with the category name itself
       ("ransomware", "phishing").

    Returns (category, severity, was_defaulted).
    """
    table = _load()
    weights = table.get("weights", {})
    if not weights:
        return "unknown", S_UNKNOWN, True

    matched_categories = set()

    for tag in tags:
        cat = family_synonyms.category_for_family_tag(tag)
        if cat and cat in weights:
            matched_categories.add(cat)

    if not matched_categories:
        joined = " ".join(tags).lower().replace("-", "_")
        for cat in weights:
            needle = cat.replace("_", " ")
            if cat in joined or needle in joined:
                matched_categories.add(cat)

    if not matched_categories:
        return "unknown", S_UNKNOWN, True

    best = max(matched_categories, key=lambda c: weights[c])
    return best, weights[best], False


def techniques_for_category(category: str) -> list:
    key = normalize_category(category) if category else ""
    return CATEGORY_TECHNIQUE_MAP.get(key, [])


def all_categories_ranked() -> list:
    """[{category, severity, raw_count, techniques}], sorted high to low.
    Feeds the dashboard's severity-ladder visualization.
    """
    table = _load()
    weights = table.get("weights", {})
    raw = table.get("raw_counts", {})
    out = []
    for cat, sev in weights.items():
        out.append({
            "category": cat,
            "severity": sev,
            "raw_count": raw.get(cat),
            "techniques": CATEGORY_TECHNIQUE_MAP.get(cat, []),
        })
    out.sort(key=lambda r: -r["severity"])
    return out


def bundle_meta() -> dict:
    table = _load()
    return {
        "attack_bundle_version": table.get("attack_bundle_version"),
        "attack_bundle_sha256": table.get("attack_bundle_sha256"),
        "derived_at": table.get("derived_at"),
        "config_version": table.get("config_version"),
        "method": table.get("method"),
        "s_min": table.get("s_min", S_MIN_DEFAULT),
    }
