
import logging
from dataclasses import dataclass, field

import requests

from app.settings import settings

log = logging.getLogger("cti_feeds")

REQUEST_TIMEOUT = settings.REQUEST_TIMEOUT

REQUEST_HEADERS = {"User-Agent": "SOHO-CTI-Engine/1.0"}
URLHAUS_HEADERS = {"User-Agent": "SOHO-CTI-Engine/1.0", "Auth-Key": settings.ABUSECH_API_KEY}
THREATFOX_HEADERS = {
    "User-Agent": "SOHO-CTI-Engine/1.0",
    "Auth-Key": settings.ABUSECH_API_KEY,
    "Content-Type": "application/json",
}


@dataclass
class APIRecord:
    found: bool = False
    source: str = ""
    tags: list = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: float = 0.0
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "found": self.found,
            "source": self.source,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "raw": self.raw,
        }


def query_urlhaus(value: str) -> APIRecord:
    record = APIRecord(source="urlhaus")
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": value},
            headers=URLHAUS_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
        status = body.get("query_status", "")

        if status == "unauthorized":
            log.error("[URLhaus] Auth-Key rejected — check ABUSECH_API_KEY.")
            return record
        if status == "no_results":
            return record
        if status not in ("ok", "is_host"):
            # "ok" is what the live API actually returns for a host hit;
            # "is_host" is kept for compatibility with older docs/versions.
            log.warning("[URLhaus] Unexpected query_status '%s' for %s", status, value)
            return record

        urls = body.get("urls") or []
        if not urls:
            return record

        record.found = True
        record.raw = body

        tags, dates = set(), []
        for entry in urls:
            for tag in (entry.get("tags") or []):
                tags.add(tag.lower())
            if entry.get("date_added"):
                dates.append(entry["date_added"])
            sig = (entry.get("payload") or {}).get("signature") or ""
            if sig:
                tags.add(sig.lower())

        record.tags = sorted(tags)
        record.first_seen = min(dates) if dates else None
        record.last_seen = max(dates) if dates else None
        record.confidence = min(len(urls) / 10.0, 1.0)

    except requests.exceptions.Timeout:
        log.warning("[URLhaus] Timeout for %s", value)
    except requests.exceptions.RequestException as e:
        log.warning("[URLhaus] Request error for %s: %s", value, e)
    except Exception as e:
        log.warning("[URLhaus] Unexpected error for %s: %s", value, e)

    return record


def query_threatfox(value: str) -> APIRecord:
    record = APIRecord(source="abuse.ch/threatfox")
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": value},
            headers=THREATFOX_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status", "")

        if status == "unauthorized":
            log.error("[ThreatFox] Auth-Key rejected — check ABUSECH_API_KEY.")
            return record
        if status in ("no_result", "illegal_search_term") or status != "ok":
            return record

        iocs = data.get("data") or []
        if not iocs:
            return record

        record.found = True
        record.raw = data

        tags, dates, confidences = set(), [], []
        for ioc in iocs:
            threat_type = (ioc.get("threat_type") or "").lower()
            malware = (ioc.get("malware") or "").lower()
            if threat_type:
                tags.add(threat_type)
            if malware:
                tags.add(malware)

            fs = (ioc.get("first_seen") or "").strip()
            if fs:
                if fs.endswith(" UTC"):
                    fs = fs[:-4]
                dates.append(fs)

            cl = ioc.get("confidence_level")
            if cl is not None:
                confidences.append(int(cl) / 100.0)

        record.tags = sorted(t for t in tags if t)
        record.first_seen = min(dates) if dates else None
        record.last_seen = max(dates) if dates else None
        record.confidence = min(sum(confidences) / len(confidences) if confidences else 0.5, 1.0)

    except requests.exceptions.Timeout:
        log.warning("[ThreatFox] Timeout for %s", value)
    except requests.exceptions.RequestException as e:
        log.warning("[ThreatFox] Request error for %s: %s", value, e)
    except Exception as e:
        log.warning("[ThreatFox] Unexpected error for %s: %s", value, e)

    return record


def query_feodo_ip(ip: str) -> APIRecord:
    record = APIRecord(source="abuse.ch/feodo")
    try:
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        for entry in resp.json():
            if entry.get("ip_address", "").strip() == ip:
                malware = (entry.get("malware") or "unknown").lower()
                record.found = True
                record.tags = ["botnet", "c2", malware]
                record.first_seen = entry.get("first_seen")
                record.last_seen = entry.get("last_online")
                record.confidence = 0.95
                record.raw = entry
                break
    except requests.exceptions.Timeout:
        log.warning("[Feodo] Timeout for %s", ip)
    except Exception as e:
        log.warning("[Feodo] Error for %s: %s", ip, e)

    return record


def query_abusech(value: str, ioc_type: str) -> APIRecord:
    if ioc_type == "ip":
        tf = query_threatfox(value)
        if tf.found:
            return tf
        return query_feodo_ip(value)
    return query_threatfox(value)
