
import logging
import queue
import threading

from app.extensions import db
from app.models import NetworkRequest
from app.capture.direction import classify

log = logging.getLogger("recorder")

_score_queue: "queue.Queue[tuple[str, str, str]]" = queue.Queue(maxsize=5000)
_worker_started = False
_worker_lock = threading.Lock()


def record_request(app, *, protocol, request_type, src_ip=None, src_port=None,
                    dst_ip=None, dst_port=None, domain=None, source_agent="unknown",
                    direction=None, raw_meta=None, packet_size=None, tcp_flags=None) -> str:
    
    direction = direction or classify(src_ip, dst_ip)

    if domain:
        ioc_value, ioc_type = domain.lower().rstrip("."), "domain"
    elif direction == "outbound" and dst_ip:
        ioc_value, ioc_type = dst_ip, "ip"
    elif src_ip:
        ioc_value, ioc_type = src_ip, "ip"
    else:
        ioc_value, ioc_type = None, None

    row = NetworkRequest(
        direction=direction,
        protocol=protocol,
        request_type=request_type,
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        packet_size=packet_size, tcp_flags=tcp_flags,
        domain=domain,
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        source_agent=source_agent,
        raw_meta=raw_meta or {},
        decision="PENDING",
    )
    with app.app_context():
        db.session.add(row)
        db.session.commit()
        row_id = row.id

    if ioc_value:
        try:
            _score_queue.put_nowait((row_id, ioc_value, direction))
        except queue.Full:
            log.warning("Scoring queue full — dropping score request for %s", ioc_value)

    ensure_worker(app)

    from app.anomaly import live_scorer
    live_scorer.enqueue(row_id)
    live_scorer.ensure_worker(app)

    return row_id


def _apply_score_to_requests(ioc_value: str, ioc_score):
    """Backfill score/decision/flagged onto every request row sharing
    this IOC value — not just the one that triggered scoring — so
    historical rows light up once a value is discovered malicious.
    """
    NetworkRequest.query.filter_by(ioc_value=ioc_value).update({
        NetworkRequest.score: ioc_score.final_score,
        NetworkRequest.decision: ioc_score.decision,
        NetworkRequest.flagged: ioc_score.decision == "ENFORCE",
    }, synchronize_session=False)
    db.session.commit()


def _worker_loop(app):
    from app.cti.scorer import score_ioc

    while True:
        row_id, ioc_value, direction = _score_queue.get()
        try:
            with app.app_context():
                result = score_ioc(ioc_value, direction=direction)
                _apply_score_to_requests(ioc_value, result)
        except Exception as e:
            log.warning("Background scoring failed for %s: %s", ioc_value, e)
        finally:
            _score_queue.task_done()


def ensure_worker(app):
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        t = threading.Thread(target=_worker_loop, args=(app,), daemon=True, name="cti-score-worker")
        t.start()
        _worker_started = True
        log.info("Background CTI scoring worker started.")


def queue_depth() -> int:
    return _score_queue.qsize()
