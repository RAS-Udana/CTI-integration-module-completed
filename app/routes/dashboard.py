from flask import Blueprint, render_template

bp = Blueprint("dashboard", __name__)


@bp.get("/")
def home():
    return render_template("dashboard.html")
