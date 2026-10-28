from flask import Blueprint, jsonify, render_template, request

from app.models import NetworkRequest

bp = Blueprint("requests_view", __name__)


@bp.get("/requests")
def requests_page():
    return render_template("requests.html")


@bp.get("/api/requests")
def api_requests():
    q = NetworkRequest.query

    ip = request.args.get("ip")
    if ip:
        q = q.filter((NetworkRequest.src_ip == ip) | (NetworkRequest.dst_ip == ip))

    domain = request.args.get("domain")
    if domain:
        q = q.filter(NetworkRequest.domain.ilike(f"%{domain}%"))

    direction = request.args.get("direction")
    if direction in ("inbound", "outbound"):
        q = q.filter_by(direction=direction)

    decision = request.args.get("decision")
    if decision in ("ENFORCE", "DISCARD", "PENDING"):
        q = q.filter_by(decision=decision)

    flagged_only = request.args.get("flagged_only")
    if flagged_only in ("1", "true", "True"):
        q = q.filter_by(flagged=True)

    protocol = request.args.get("protocol")
    if protocol:
        q = q.filter_by(protocol=protocol)

    search = request.args.get("q")
    if search:
        like = f"%{search}%"
        q = q.filter(
            (NetworkRequest.ioc_value.ilike(like))
            | (NetworkRequest.domain.ilike(like))
            | (NetworkRequest.src_ip.ilike(like))
            | (NetworkRequest.dst_ip.ilike(like))
        )

    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 50)), 1), 200)

    q = q.order_by(NetworkRequest.ts.desc())
    total = q.count()
    rows = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "requests": [r.to_dict() for r in rows],
    })
