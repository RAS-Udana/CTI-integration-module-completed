
import ipaddress
import logging

log = logging.getLogger("direction")

_local_ips_cache = None


def local_ips() -> set:
    global _local_ips_cache
    if _local_ips_cache is not None:
        return _local_ips_cache

    ips = set()
    try:
        import psutil
        for _iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name in ("AF_INET", "AF_INET6"):
                    ips.add(addr.address.split("%")[0])  # strip IPv6 zone id
    except Exception as e:
        log.warning("Could not enumerate local interfaces: %s", e)

    ips.add("127.0.0.1")
    ips.add("::1")
    _local_ips_cache = ips
    return ips


def is_local(ip: str) -> bool:
    if not ip:
        return False
    if ip in local_ips():
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def classify(src_ip: str, dst_ip: str) -> str:
    """Best-effort direction classification.

    If src is ours -> outbound (we/our LAN initiated it).
    Else if dst is ours -> inbound (someone reached us).
    Else -> outbound (default: traffic passing through a gateway we're
    monitoring, treated as originating from the LAN side).
    """
    if is_local(src_ip):
        return "outbound"
    if is_local(dst_ip):
        return "inbound"
    return "outbound"
