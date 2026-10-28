from flask import Blueprint, jsonify, render_template, request

from app.anomaly import client as anomaly_client

bp = Blueprint("anomaly_view", __name__)


@bp.get("/anomaly")
def anomaly_page():
    return render_template("anomaly.html")


@bp.get("/api/anomaly/health")
def api_anomaly_health():
    ok, err, body = anomaly_client.health()
    if not ok:
        return jsonify({"error": err, "ready": False}), 502
    return jsonify(body)


@bp.get("/api/anomaly/stats")
def api_anomaly_stats():
    ok, err, body = anomaly_client.stats()
    if not ok:
        return jsonify({"error": err}), 502
    return jsonify(body)


@bp.get("/api/anomaly/recent")
def api_anomaly_recent():
    limit = request.args.get("limit", 50)
    source = request.args.get("source", "all")
    ok, err, body = anomaly_client.recent(limit=limit, source=source)
    if not ok:
        return jsonify({"error": err}), 502
    return jsonify(body)


@bp.post("/api/anomaly/simulate")
def api_anomaly_simulate():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "mixed")
    count = data.get("count", 10)
    magnitude = data.get("magnitude", 4.0)
    seed = data.get("seed")

    ok, err, body = anomaly_client.simulate(mode=mode, count=count, magnitude=magnitude, seed=seed)
    status = 200 if ok else 502
    return jsonify(body if ok else {"error": err}), status
