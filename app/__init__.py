import logging

from flask import Flask

from app.settings import settings
from app.extensions import db


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(settings)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    db.init_app(app)

    from app.routes.dashboard import bp as dashboard_bp
    from app.routes.requests_view import bp as requests_bp
    from app.routes.ioc_view import bp as ioc_bp
    from app.routes.mitre_view import bp as mitre_bp
    from app.routes.api import bp as api_bp
    from app.routes.anomaly_view import bp as anomaly_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(requests_bp)
    app.register_blueprint(ioc_bp)
    app.register_blueprint(mitre_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(anomaly_bp)

    with app.app_context():
        db.create_all()

    if settings.CAPTURE_MODE == "sniffer":
        from app.capture.sniffer import start as start_sniffer
        start_sniffer(app)
    elif settings.CAPTURE_MODE == "ingest":
        app.logger.info("Capture mode: ingest — POST events to /api/ingest")
    else:
        app.logger.info("Capture mode: off — dashboard will show no live traffic")

    return app
