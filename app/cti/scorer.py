import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.extensions import db
from app.models import IOCScore
from app.settings import settings
from app.cti import feeds, mitre

log = logging.getLogger("cti_scorer")

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_ml_model = None
_ml_load_attempted = False


def _get_ml_model():
    global _ml_model, _ml_load_attempted
    if _ml_load_attempted:
        return _ml_model
    _ml_load_attempted = True
    try:
        from app.cti.m1_model import URLPredictor
        _ml_model = URLPredictor(
            model_dir=settings.ML_MODEL_DIR,
            feature_file=settings.ML_FEATURE_FILE,
        )
        log.info("[ML] URLPredictor loaded (%d sub-models).", len(_ml_model.models))
    except Exception as e:
        log.warning("[ML] URLPredictor unavailable: %s", e)
        _ml_model = None
    return _ml_model


def ml_status() -> dict:
    model = _get_ml_model() if _ml_load_attempted else None
    if not _ml_load_attempted:
        return {"attempted": False, "loaded": False, "models": []}
    return {
        "attempted": True,
        "loaded": model is not None,
        "models": list(model.models.keys()) if model else [],
    }


def _normalise(value: str) -> tuple[str, str]:
    v = value.strip()
    v = re.sub(r"^https?://", "", v, flags=re.IGNORECASE)
    v = v.split("/")[0].split("?")[0].split(":")[0]
    v = v.lower()
    ioc_type = "ip" if _IP_RE.match(v) else "domain"
    return v, ioc_type


def _corroboration_score(feeds_found: int) -> float:
    if feeds_found >= 4:
        return 1.0
    if feeds_found >= 2:
        return 0.8
    if feeds_found == 1:
        return 0.6
    return 0.0


def _freshness_score(first_seen_str: Optional[str]) -> tuple[float, float]:
    if not first_seen_str:
        return 0.5, 9999.0
    try:
        s = first_seen_str.strip()
        if s.endswith(" UTC"):
            s = s[:-4]
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s[:len(fmt)], fmt)
                break
            except ValueError:
                continue
        if dt is None:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - dt).total_seconds() / 86400
        if age_days < 7:
            return 1.0, age_days
        if age_days < 30:
            return 0.7, age_days
        if age_days < 90:
            return 0.5, age_days
        return 0.1, age_days
    except Exception:
        return 0.5, 9999.0


def _ml_fallback(value: str) -> tuple[float, str, dict]:
    model = _get_ml_model()
    if model is None:
        return 0.0, "ml_unavailable", {}
    try:
        result = model.predict(value, return_details=True)
        return round(float(result.get("probability", 0.0)), 4), "url_predictor", result
    except Exception as e:
        log.warning("[ML fallback] Error scoring %s: %s", value, e)
        return 0.0, f"ml_error: {e}", {}


def score_ioc(value: str, direction: str = "outbound", force: bool = False) -> IOCScore:
    clean, ioc_type = _normalise(value)

    existing = IOCScore.query.filter_by(value=clean).first()
    if existing and not force and not existing.is_stale():
        existing.score_source = existing.score_source or "cache"
        if _should_auto_block(existing) and not existing.block_error:
            _try_auto_block(existing)
        return existing

    urlhaus_rec = feeds.query_urlhaus(clean)
    abusech_rec = feeds.query_abusech(clean, ioc_type)

    feeds_found = sum([urlhaus_rec.found, abusech_rec.found])
    all_tags = sorted(set(urlhaus_rec.tags + abusech_rec.tags))
    dates = [d for d in [urlhaus_rec.first_seen, abusech_rec.first_seen] if d]
    first_seen = min(dates) if dates else None

    row = existing or IOCScore(value=clean, ioc_type=ioc_type)
    row.ioc_type = ioc_type
    row.feeds_found = feeds_found
    row.combined_tags = all_tags
    row.first_seen = first_seen
    row.urlhaus_raw = urlhaus_rec.to_dict()
    row.threatfox_raw = abusech_rec.to_dict() if abusech_rec.source == "abuse.ch/threatfox" else None
    row.feodo_raw = abusech_rec.to_dict() if abusech_rec.source == "abuse.ch/feodo" else None

    if feeds_found > 0:
        category, category_weight, defaulted = mitre.category_for_tags(all_tags)
        corr = _corroboration_score(feeds_found)
        fresh, age_days = _freshness_score(first_seen)
        rule_score = round(category_weight * corr * fresh, 4)

        row.category = category
        row.category_weight = category_weight
        row.category_weight_defaulted = defaulted
        row.corroboration_score = corr
        row.freshness_score = fresh
        row.rule_score = rule_score
        row.age_days = age_days
        row.mitre_techniques = mitre.techniques_for_category(category)

        ml_score, ml_source, ml_detail = _ml_fallback(clean)
        row.ml_score = ml_score
        row.ml_used = False
        row.ml_confidence = ml_detail.get("confidence", "")
        row.ml_model_agreement = ml_detail.get("model_agreement", 0.0)
        row.ml_details = ml_detail

        row.final_score = round(rule_score, 4)
        row.score_source = "api"
    else:
        ml_score, ml_source, ml_detail = _ml_fallback(clean)

        row.category = None
        row.category_weight = None
        row.category_weight_defaulted = None
        row.corroboration_score = None
        row.freshness_score = None
        row.rule_score = None
        row.age_days = 9999.0
        row.ml_score = ml_score
        row.ml_used = True
        row.ml_confidence = ml_detail.get("confidence", "")
        row.ml_model_agreement = ml_detail.get("model_agreement", 0.0)
        row.ml_details = ml_detail
        row.mitre_techniques = None

        row.final_score = round(ml_score, 4)
        row.score_source = f"ml_fallback ({ml_source})"

    row.threshold = settings.ENFORCE_THRESHOLD
    row.decision = "ENFORCE" if row.final_score >= settings.ENFORCE_THRESHOLD else "DISCARD"

    ttl = settings.TTL_INBOUND_SECONDS if direction == "inbound" else settings.TTL_OUTBOUND_SECONDS
    row.ttl_seconds = ttl
    row.scored_at = datetime.now(timezone.utc)
    row.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

    if not existing:
        db.session.add(row)
    db.session.commit()

    if _should_auto_block(row):
        _try_auto_block(row)

    return row


def _should_auto_block(row) -> bool:
    return (
        row.decision == "ENFORCE"
        and not row.is_blocked
        and row.block_source != "unblocked"
    )


def _try_auto_block(row):
    from app.enforcement import manager as enforcement_manager
    try:
        enforcement_manager.block_ioc(row, source="auto")
    except enforcement_manager.BlockRefused as e:
        log.info("Auto-block skipped for %s: %s", row.value, e)
    except Exception as e:
        log.warning("Auto-block failed for %s: %s", row.value, e)
