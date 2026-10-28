from flask import Blueprint, abort, jsonify, render_template

from app.extensions import db
from app.models import IOCScore, NetworkRequest
from app.cti import scorer
from app.enforcement import manager as enforcement_manager

bp = Blueprint("ioc_view", __name__)


@bp.get("/ioc/<path:value>")
def ioc_page(value):
    return render_template("ioc_detail.html", value=value)


@bp.get("/api/ioc/<path:value>")
def api_ioc(value):
    clean, _ = scorer._normalise(value)
    row = IOCScore.query.filter_by(value=clean).first()
    if not row:
        row = scorer.score_ioc(value)

    related = (
        NetworkRequest.query.filter_by(ioc_value=clean)
        .order_by(NetworkRequest.ts.desc())
        .limit(25)
        .all()
    )

    payload = row.to_dict()
    payload["related_requests"] = [r.to_dict() for r in related]
    return jsonify(payload)


@bp.post("/api/ioc/<path:value>/rescore")
def api_ioc_rescore(value):
    row = scorer.score_ioc(value, force=True)
    return jsonify(row.to_dict())


@bp.post("/api/ioc/<path:value>/block")
def api_ioc_block(value):
    clean, _ = scorer._normalise(value)
    row = IOCScore.query.filter_by(value=clean).first()
    if not row:
        row = scorer.score_ioc(value)

    try:
        ok, msg = enforcement_manager.block_ioc(row, source="manual")
    except enforcement_manager.BlockRefused as e:
        row.block_error = str(e)
        db.session.commit()
        return jsonify({"error": str(e), **row.to_dict()}), 400

    status = 200 if ok else 502
    return jsonify(row.to_dict()), status


@bp.post("/api/ioc/<path:value>/unblock")
def api_ioc_unblock(value):
    clean, _ = scorer._normalise(value)
    row = IOCScore.query.filter_by(value=clean).first()
    if not row:
        return jsonify({"error": "no score on record for this value"}), 404

    ok, msg = enforcement_manager.unblock_ioc(row)
    status = 200 if ok else 502
    return jsonify(row.to_dict()), status
