import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///soho_cti.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")

    ENFORCE_THRESHOLD = float(os.getenv("ENFORCE_THRESHOLD", "0.6"))
    TTL_INBOUND_SECONDS = int(os.getenv("TTL_INBOUND_SECONDS", str(72 * 3600)))
    TTL_OUTBOUND_SECONDS = int(os.getenv("TTL_OUTBOUND_SECONDS", str(24 * 3600)))
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
    S_UNKNOWN = float(os.getenv("S_UNKNOWN", "0.25"))

    ML_MODEL_DIR = os.getenv("ML_MODEL_DIR", "./app/models/models")
    ML_FEATURE_FILE = os.getenv("ML_FEATURE_FILE", "./app/models/data/feature_columns.json")

    CAPTURE_MODE = os.getenv("CAPTURE_MODE", "ingest")
    CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
    INGEST_TOKEN = os.getenv("INGEST_TOKEN", "")

    ENFORCEMENT_ENABLED = os.getenv("ENFORCEMENT_ENABLED", "1") == "1"
    FIREWALL_APP_URL = os.getenv("FIREWALL_APP_URL", "http://localhost:5000")
    FIREWALL_APP_API_TOKEN = os.getenv("FIREWALL_APP_API_TOKEN", "")
    FIREWALL_APP_TIMEOUT = int(os.getenv("FIREWALL_APP_TIMEOUT", "10"))
    BLOCK_SAFELIST = [
        ip.strip() for ip in os.getenv("BLOCK_SAFELIST", "").split(",") if ip.strip()
    ]

    ANOMALY_SERVER_URL = os.getenv("ANOMALY_SERVER_URL", "http://localhost:5100")
    ANOMALY_SERVER_API_TOKEN = os.getenv("ANOMALY_SERVER_API_TOKEN", "")
    ANOMALY_SERVER_TIMEOUT = int(os.getenv("ANOMALY_SERVER_TIMEOUT", "10"))
    ANOMALY_LIVE_SCORING_ENABLED = os.getenv("ANOMALY_LIVE_SCORING_ENABLED", "0") == "1"

    SEVERITY_WEIGHTS_PATH = os.getenv(
        "SEVERITY_WEIGHTS_PATH",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "severity_weights.json"),
    )


settings = Settings()
