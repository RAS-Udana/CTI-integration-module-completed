
import logging

import requests

from app.settings import settings

log = logging.getLogger("firewall_client")


def _headers():
    return {
        "X-API-Token": settings.FIREWALL_APP_API_TOKEN,
        "Content-Type": "application/json",
    }


def _post(path: str, payload: dict) -> tuple[bool, str, dict]:
    url = settings.FIREWALL_APP_URL.rstrip("/") + path
    try:
        resp = requests.post(url, json=payload, headers=_headers(), timeout=settings.FIREWALL_APP_TIMEOUT)
    except requests.exceptions.ConnectionError:
        return False, f"could not reach firewall app at {settings.FIREWALL_APP_URL}", {}
    except requests.exceptions.Timeout:
        return False, f"firewall app request timed out after {settings.FIREWALL_APP_TIMEOUT}s", {}
    except requests.exceptions.RequestException as e:
        return False, f"firewall app request failed: {e}", {}

    try:
        body = resp.json()
    except ValueError:
        body = {}

    if resp.status_code == 401:
        return False, "firewall app rejected the API token (check FIREWALL_APP_API_TOKEN matches its EXTERNAL_API_TOKEN)", body
    if resp.status_code == 503:
        return False, "firewall app's external API is not configured (its EXTERNAL_API_TOKEN is unset)", body
    if resp.status_code >= 400:
        return False, body.get("error") or body.get("message") or f"firewall app returned {resp.status_code}", body

    return bool(body.get("ok", True)), body.get("message", "") or body.get("error", ""), body


def block(ioc_type: str, value: str, reason: str = "") -> tuple[bool, str, dict]:
    return _post("/api/external/block", {"type": ioc_type, "value": value, "reason": reason})


def unblock(ioc_type: str, value: str) -> tuple[bool, str, dict]:
    return _post("/api/external/unblock", {"type": ioc_type, "value": value})


def status() -> tuple[bool, str, dict]:
    url = settings.FIREWALL_APP_URL.rstrip("/") + "/api/external/status"
    try:
        resp = requests.get(url, headers=_headers(), timeout=settings.FIREWALL_APP_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return False, f"could not reach firewall app: {e}", {}
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if resp.status_code != 200:
        return False, body.get("error", f"firewall app returned {resp.status_code}"), body
    return True, "", body
