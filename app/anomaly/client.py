
import logging

import requests

from app.settings import settings

log = logging.getLogger("anomaly_client")


def _headers():
    h = {"Content-Type": "application/json"}
    if settings.ANOMALY_SERVER_API_TOKEN:
        h["X-API-Token"] = settings.ANOMALY_SERVER_API_TOKEN
    return h


def _get(path: str, params: dict = None) -> tuple[bool, str, dict]:
    url = settings.ANOMALY_SERVER_URL.rstrip("/") + path
    try:
        resp = requests.get(url, headers=_headers(), params=params, timeout=settings.ANOMALY_SERVER_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return False, f"could not reach anomaly server at {settings.ANOMALY_SERVER_URL}: {e}", {}
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if resp.status_code != 200:
        return False, body.get("error", f"anomaly server returned {resp.status_code}"), body
    return True, "", body


def _post(path: str, payload: dict) -> tuple[bool, str, dict]:
    url = settings.ANOMALY_SERVER_URL.rstrip("/") + path
    try:
        resp = requests.post(url, json=payload, headers=_headers(), timeout=settings.ANOMALY_SERVER_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return False, f"could not reach anomaly server at {settings.ANOMALY_SERVER_URL}: {e}", {}
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if resp.status_code >= 400:
        return False, body.get("error", f"anomaly server returned {resp.status_code}"), body
    return True, "", body


def health():
    return _get("/health")


def stats():
    return _get("/stats")


def recent(limit: int = 50, source: str = "all"):
    return _get("/recent", params={"limit": limit, "source": source})


def simulate(mode: str = "mixed", count: int = 10, magnitude: float = 4.0, seed=None):
    payload = {"mode": mode, "count": count, "magnitude": magnitude, "persist": True}
    if seed is not None:
        payload["seed"] = seed
    return _post("/simulate", payload)


def score(features: dict):
    """POST /score — scores one real feature vector (e.g. built by
    app/anomaly/feature_extractor.py from a captured NetworkRequest).
    Logged server-side as source='live', distinct from /simulate's
    source='simulated'.
    """
    return _post("/score", {"features": features})
