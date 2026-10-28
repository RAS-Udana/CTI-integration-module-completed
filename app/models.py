import json
import uuid
from datetime import datetime, timezone

from app.extensions import db


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc)


class JSONText(db.TypeDecorator):
    """Store arbitrary JSON-serializable data in a TEXT column.

    Keeps us portable across SQLite / MySQL / PostgreSQL without relying
    on a dialect-specific JSON type.
    """
    impl = db.Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return json.dumps(value, default=str)

    def process_result_value(self, value, dialect):
        if not value:
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None


class NetworkRequest(db.Model):
    """One captured (or ingested) network event — the raw traffic log."""

    __tablename__ = "network_requests"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    ts = db.Column(db.DateTime(timezone=True), default=_now, index=True, nullable=False)

    direction = db.Column(db.String(16), index=True, nullable=False)  # inbound | outbound
    protocol = db.Column(db.String(16), nullable=True)                # dns | tls | tcp | http | ingested
    request_type = db.Column(db.String(32), nullable=True)            # dns_query | tls_client_hello | tcp_syn | http_request

    src_ip = db.Column(db.String(64), index=True, nullable=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_ip = db.Column(db.String(64), index=True, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)

    packet_size = db.Column(db.Integer, nullable=True)   # raw packet length in bytes, from scapy len(pkt)
    tcp_flags = db.Column(db.String(16), nullable=True)  # SYN | FIN | SYN-ACK | ... — only for protocol='tcp' events

    domain = db.Column(db.String(255), index=True, nullable=True)
    ioc_value = db.Column(db.String(255), index=True, nullable=True)  # domain if present, else dst/src ip
    ioc_type = db.Column(db.String(16), nullable=True)                # ip | domain

    source_agent = db.Column(db.String(64), nullable=True)  # sniffer | ingest:<name> | manual
    raw_meta = db.Column(JSONText, nullable=True)

    flagged = db.Column(db.Boolean, default=False, index=True)
    score = db.Column(db.Float, nullable=True)
    decision = db.Column(db.String(16), nullable=True, index=True)  # ENFORCE | DISCARD | PENDING

    def to_dict(self):
        return {
            "id": self.id,
            "ts": self.ts.isoformat() if self.ts else None,
            "direction": self.direction,
            "protocol": self.protocol,
            "request_type": self.request_type,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "tcp_flags": self.tcp_flags,
            "domain": self.domain,
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "source_agent": self.source_agent,
            "flagged": self.flagged,
            "score": self.score,
            "decision": self.decision,
        }


class IOCScore(db.Model):
    """Cached CTI scoring result for one IOC value (ip/domain).

    Mirrors CTIResult from the CLI tool, persisted so the dashboard can
    render URLhaus / ThreatFox / Feodo / ML side by side without
    re-querying feeds on every page view, and so TTL-based re-scoring
    (72h inbound / 24h outbound, per DEV-BRIEF-05a) is enforceable.
    """

    __tablename__ = "ioc_scores"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    value = db.Column(db.String(255), unique=True, index=True, nullable=False)
    ioc_type = db.Column(db.String(16), nullable=False)  # ip | domain

    feeds_found = db.Column(db.Integer, default=0)
    combined_tags = db.Column(JSONText, nullable=True)
    first_seen = db.Column(db.String(64), nullable=True)
    age_days = db.Column(db.Float, nullable=True)

    # scoring components (mirrors ScoringComponents dataclass)
    category = db.Column(db.String(32), nullable=True)          # matched MITRE-mapped category
    category_weight = db.Column(db.Float, nullable=True)        # severity from severity_weights.json
    category_weight_defaulted = db.Column(db.Boolean, default=False)
    corroboration_score = db.Column(db.Float, nullable=True)
    freshness_score = db.Column(db.Float, nullable=True)
    rule_score = db.Column(db.Float, nullable=True)

    ml_score = db.Column(db.Float, nullable=True)
    ml_used = db.Column(db.Boolean, default=False)
    ml_confidence = db.Column(db.String(16), nullable=True)
    ml_model_agreement = db.Column(db.Float, nullable=True)
    ml_details = db.Column(JSONText, nullable=True)  # per-model scores + meta weights

    final_score = db.Column(db.Float, nullable=True, index=True)
    decision = db.Column(db.String(16), nullable=True, index=True)
    threshold = db.Column(db.Float, nullable=True)
    ttl_seconds = db.Column(db.Integer, nullable=True)
    score_source = db.Column(db.String(64), nullable=True)  # api | ml_fallback (...) | cache

    urlhaus_raw = db.Column(JSONText, nullable=True)
    threatfox_raw = db.Column(JSONText, nullable=True)
    feodo_raw = db.Column(JSONText, nullable=True)

    mitre_techniques = db.Column(JSONText, nullable=True)  # technique IDs backing the matched category

    # --- network-level enforcement state ---
    is_blocked = db.Column(db.Boolean, default=False, index=True)
    blocked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    blocked_ips = db.Column(JSONText, nullable=True)   # actual IP(s) in the firewall set — for a
                                                          # domain this is its resolved IP(s) at block time
    block_source = db.Column(db.String(16), nullable=True)  # manual | auto
    block_error = db.Column(db.Text, nullable=True)         # last enforcement failure, if any (surfaced to UI)

    scored_at = db.Column(db.DateTime(timezone=True), default=_now)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    def is_stale(self):
        if self.expires_at is None:
            return True
        now = _now()
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp

    def to_dict(self):
        return {
            "value": self.value,
            "ioc_type": self.ioc_type,
            "feeds_found": self.feeds_found,
            "combined_tags": self.combined_tags or [],
            "first_seen": self.first_seen,
            "age_days": self.age_days,
            "components": {
                "category": self.category,
                "category_weight": self.category_weight,
                "category_weight_defaulted": self.category_weight_defaulted,
                "corroboration_score": self.corroboration_score,
                "freshness_score": self.freshness_score,
                "rule_score": self.rule_score,
                "ml_score": self.ml_score,
                "ml_used": self.ml_used,
                "ml_confidence": self.ml_confidence,
                "ml_model_agreement": self.ml_model_agreement,
            },
            "final_score": self.final_score,
            "decision": self.decision,
            "threshold": self.threshold,
            "ttl_seconds": self.ttl_seconds,
            "score_source": self.score_source,
            "feeds": {
                "urlhaus": self.urlhaus_raw,
                "threatfox": self.threatfox_raw,
                "feodo": self.feodo_raw,
            },
            "ml_details": self.ml_details or {},
            "mitre_techniques": self.mitre_techniques or [],
            "block": {
                "is_blocked": self.is_blocked,
                "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
                "blocked_ips": self.blocked_ips or [],
                "block_source": self.block_source,
                "block_error": self.block_error,
            },
            "scored_at": self.scored_at.isoformat() if self.scored_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "stale": self.is_stale(),
        }
