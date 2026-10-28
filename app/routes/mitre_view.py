from flask import Blueprint, jsonify, render_template

from app.cti import mitre

bp = Blueprint("mitre_view", __name__)


@bp.get("/mitre")
def mitre_page():
    return render_template("mitre.html")


@bp.get("/api/mitre")
def api_mitre():
    return jsonify({
        "bundle": mitre.bundle_meta(),
        "categories": mitre.all_categories_ranked(),
    })
