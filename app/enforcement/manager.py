import ipaddress
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.extensions import db
from app.enforcement import firewall_client
from app.settings import settings

log = logging.getLogger("enforcement_manager")


class BlockRefused(Exception):
    pass


def _is_unsafe_to_block(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"'{ip}' is not a valid IP address"

    if addr.is_loopback:
        return "refusing to block a loopback address"
    if addr.is_link_local:
        return "refusing to block a link-local address"
    if addr.is_multicast:
        return "refusing to block a multicast address"
    if addr.is_private:
        return (
            "refusing to block a private/RFC1918 address — this is almost "
            "certainly your own gateway, a LAN device, or a misresolved "
            "domain, not something on the public internet"
        )
    if ip in settings.BLOCK_SAFELIST:
        return f"'{ip}' is in BLOCK_SAFELIST"

    return None


_FEED_DOMAINS = {
    "urlhaus-api.abuse.ch",
    "threatfox-api.abuse.ch",
    "feodotracker.abuse.ch",
    "auth.abuse.ch",
    "abuse.ch",
}


def _own_service_hosts() -> set:
    hosts = set()
    for url in (settings.FIREWALL_APP_URL, settings.ANOMALY_SERVER_URL):
        host = (urlparse(url).hostname or "").lower()
        if host:
            hosts.add(host)
    return hosts


def _is_unsafe_to_block_domain(domain: str) -> str | None:
    d = domain.strip().lower().rstrip(".")
    if d in _FEED_DOMAINS or d.endswith(".abuse.ch"):
        return f"refusing to block '{d}' — it's one of this dashboard's own CTI feeds"
    if d in _own_service_hosts():
        return f"refusing to block '{d}' — it's the firewall app or anomaly server this dashboard talks to"
    if d in settings.BLOCK_SAFELIST:
        return f"'{d}' is in BLOCK_SAFELIST"
    return None


def block_ioc(ioc_score, source: str = "manual"):
    if not settings.ENFORCEMENT_ENABLED:
        raise BlockRefused(
            "ENFORCEMENT_ENABLED is off — set ENFORCEMENT_ENABLED=1 in .env "
            "once FIREWALL_APP_URL/FIREWALL_APP_API_TOKEN are configured and reachable"
        )

    if ioc_score.ioc_type == "ip":
        reason = _is_unsafe_to_block(ioc_score.value)
    else:
        reason = _is_unsafe_to_block_domain(ioc_score.value)
    if reason:
        raise BlockRefused(reason)

    reason_text = (
        f"SOHO-CTI: score={ioc_score.final_score}, "
        f"category={ioc_score.category or 'ml-fallback'}, decision={ioc_score.decision}"
    )
    ok, msg, raw = firewall_client.block(ioc_score.ioc_type, ioc_score.value, reason=reason_text)

    if not ok:
        ioc_score.block_error = msg
        db.session.commit()
        return False, msg

    ioc_score.is_blocked = True
    ioc_score.blocked_at = datetime.now(timezone.utc)
    ioc_score.blocked_ips = raw.get("rules") if ioc_score.ioc_type == "ip" else None
    ioc_score.block_source = source
    ioc_score.block_error = None
    db.session.commit()

    log.info("Blocked %s via firewall app (source=%s)", ioc_score.value, source)
    return True, msg


def unblock_ioc(ioc_score):
    ok, msg, raw = firewall_client.unblock(ioc_score.ioc_type, ioc_score.value)

    ioc_score.is_blocked = False
    ioc_score.blocked_at = None
    ioc_score.blocked_ips = None
    ioc_score.block_source = "unblocked"
    ioc_score.block_error = None if ok else msg
    db.session.commit()

    log.info("Unblocked %s via firewall app (ok=%s)", ioc_score.value, ok)
    return ok, msg
