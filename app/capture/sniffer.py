
import logging
import struct
import threading

from app.capture.recorder import record_request

log = logging.getLogger("sniffer")

_thread = None


def _parse_sni(tcp_payload: bytes) -> str | None:
    
    try:
        if len(tcp_payload) < 5 or tcp_payload[0] != 0x16:  # handshake record
            return None
        pos = 5  # skip TLS record header
        if tcp_payload[pos] != 0x01:  # ClientHello
            return None
        pos += 4  # handshake header (type + length)
        pos += 2 + 32  # version + random
        session_id_len = tcp_payload[pos]
        pos += 1 + session_id_len
        cipher_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
        pos += 2 + cipher_len
        comp_len = tcp_payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(tcp_payload):
            return None
        ext_total_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total_len
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", tcp_payload[pos:pos + 4])
            pos += 4
            if ext_type == 0x00:  # server_name
                sni_list_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
                p = pos + 2
                sni_end = p + sni_list_len
                while p + 3 <= sni_end:
                    name_type = tcp_payload[p]
                    name_len = struct.unpack("!H", tcp_payload[p + 1:p + 3])[0]
                    p += 3
                    if name_type == 0x00:
                        return tcp_payload[p:p + name_len].decode("ascii", errors="ignore")
                    p += name_len
                return None
            pos += ext_len
    except Exception:
        return None
    return None


def start(app):
    global _thread
    if _thread and _thread.is_alive():
        return

    try:
        from scapy.all import AsyncSniffer, DNS, DNSQR, IP, TCP, UDP, Raw
    except ImportError:
        log.error("scapy not installed — CAPTURE_MODE=sniffer unavailable. pip install scapy")
        return

    def handle(pkt):
        try:
            if not pkt.haslayer(IP):
                return
            ip_layer = pkt[IP]
            pkt_len = len(pkt)  # raw packet size in bytes — the anomaly model's packet_size feature

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                udp = pkt[UDP] if pkt.haslayer(UDP) else None
                record_request(
                    app, protocol="dns", request_type="dns_query",
                    src_ip=ip_layer.src, dst_ip=ip_layer.dst,
                    src_port=udp.sport if udp else None, dst_port=udp.dport if udp else None,
                    domain=qname, source_agent="sniffer", packet_size=pkt_len,
                    raw_meta={"qtype": pkt[DNSQR].qtype},
                )
                return

            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                if tcp.dport == 443 or tcp.sport == 443:
                    sni = _parse_sni(bytes(pkt[Raw].load))
                    if sni:
                        record_request(
                            app, protocol="tls", request_type="tls_client_hello",
                            src_ip=ip_layer.src, src_port=tcp.sport,
                            dst_ip=ip_layer.dst, dst_port=tcp.dport,
                            domain=sni, source_agent="sniffer", packet_size=pkt_len,
                            tcp_flags="SYN" if "S" in tcp.flags and "A" not in tcp.flags else None,
                        )
                        return

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                flags = str(tcp.flags)
                
                if flags == "S":
                    tcp_flag_label = "SYN"
                elif flags == "SA":
                    tcp_flag_label = "SYN-ACK"
                elif "F" in flags:
                    tcp_flag_label = "FIN"
                else:
                    return

                record_request(
                    app, protocol="tcp", request_type=f"tcp_{tcp_flag_label.lower().replace('-', '_')}",
                    src_ip=ip_layer.src, src_port=tcp.sport,
                    dst_ip=ip_layer.dst, dst_port=tcp.dport,
                    source_agent="sniffer", packet_size=pkt_len, tcp_flags=tcp_flag_label,
                )
        except Exception as e:
            log.debug("Packet handling error: %s", e)

    from app.settings import settings
    iface = settings.CAPTURE_INTERFACE
    log.info("Starting sniffer on interface %s", iface)

    sniffer = AsyncSniffer(iface=iface, prn=handle, store=False)
    sniffer.start()

    def _keepalive():
        sniffer.join()

    _thread = threading.Thread(target=_keepalive, daemon=True, name="cti-sniffer")
    _thread.start()
