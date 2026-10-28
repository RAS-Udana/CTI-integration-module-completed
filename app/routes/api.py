import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import NetworkRequest, IOCScore
from app.settings import settings
from app.capture.recorder import record_request, queue_depth
from app.cti import scorer, mitre

log = logging.getLogger("api")
bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/stats")
def stats():
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    total = NetworkRequest.query.count()
    total_24h = NetworkRequest.query.filter(NetworkRequest.ts >= since).count()
    flagged = NetworkRequest.query.filter_by(flagged=True).count()
    inbound = NetworkRequest.query.filter_by(direction="inbound").count()
    outbound = NetworkRequest.query.filter_by(direction="outbound").count()
    pending = NetworkRequest.query.filter_by(decision="PENDING").count()

    top_flagged = (
        db.session.query(
            NetworkRequest.ioc_value,
            db.func.count(NetworkRequest.id).label("hits"),
            db.func.max(NetworkRequest.score).label("score"),
        )
        .filter(NetworkRequest.flagged.is_(True), NetworkRequest.ioc_value.isnot(None))
        .group_by(NetworkRequest.ioc_value)
        .order_by(db.desc("hits"))
        .limit(10)
        .all()
    )

    return jsonify({
        "total_requests": total,
        "total_requests_24h": total_24h,
        "flagged_requests": flagged,
        "inbound_requests": inbound,
        "outbound_requests": outbound,
        "pending_scoring": pending,
        "scoring_queue_depth": queue_depth(),
        "top_flagged": [
            {"ioc_value": v, "hits": h, "score": s} for v, h, s in top_flagged
        ],
        "ml_status": scorer.ml_status(),
        "mitre_bundle": mitre.bundle_meta(),
        "capture_mode": settings.CAPTURE_MODE,
    })


@bp.post("/ingest")
def ingest():
    """Push endpoint for external capture agents (proxy/firewall log
    shippers, IDS, etc). Requires X-Ingest-Token to match INGEST_TOKEN.

    Body: a single event object, or {"events": [ ... ]} for a batch.
    Event fields: protocol, request_type, src_ip, src_port, dst_ip,
    dst_port, domain, direction (optional — inferred if omitted),
    packet_size, tcp_flags (both optional — feed these if your agent
    has them, they improve live anomaly-scoring accuracy),
    source_agent (optional, defaults to "ingest").
    """
    token = request.headers.get("X-Ingest-Token", "")
    if not settings.INGEST_TOKEN or token != settings.INGEST_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    events = body.get("events") if "events" in body else [body]
    if not isinstance(events, list) or not events:
        return jsonify({"error": "no events provided"}), 400

    app = current_app._get_current_object()
    ids = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        row_id = record_request(
            app,
            protocol=ev.get("protocol", "ingested"),
            request_type=ev.get("request_type", "ingested"),
            src_ip=ev.get("src_ip"),
            src_port=ev.get("src_port"),
            dst_ip=ev.get("dst_ip"),
            dst_port=ev.get("dst_port"),
            domain=ev.get("domain"),
            direction=ev.get("direction"),
            packet_size=ev.get("packet_size"),
            tcp_flags=ev.get("tcp_flags"),
            source_agent=f"ingest:{ev.get('source_agent', 'unknown')}",
            raw_meta=ev.get("meta"),
        )
        ids.append(row_id)

    return jsonify({"accepted": len(ids), "ids": ids}), 202


@bp.post("/score")
def score_now():
    """On-demand scoring for an arbitrary value typed into the dashboard
    (not necessarily something that's appeared in captured traffic).
    """
    body = request.get_json(silent=True) or {}
    value = (body.get("value") or "").strip()
    direction = body.get("direction", "outbound")
    force = bool(body.get("force", False))
    if not value:
        return jsonify({"error": "value is required"}), 400

    result = scorer.score_ioc(value, direction=direction, force=force)
    return jsonify(result.to_dict())
