
import logging
import queue
import threading

from app.settings import settings

log = logging.getLogger("live_scorer")

_queue: "queue.Queue[str]" = queue.Queue(maxsize=5000)
_worker_started = False
_worker_lock = threading.Lock()
_expected_columns = None  # cached from the anomaly server's /health


def enqueue(row_id: str):
    if not settings.ANOMALY_LIVE_SCORING_ENABLED:
        return
    try:
        _queue.put_nowait(row_id)
    except queue.Full:
        log.warning("Anomaly scoring queue full — dropping live-score request for %s", row_id)


def _get_expected_columns():
    global _expected_columns
    if _expected_columns is not None:
        return _expected_columns
    from app.anomaly import client
    ok, err, body = client.health()
    if ok and body.get("feature_columns"):
        _expected_columns = body["feature_columns"]
        log.info("Anomaly model expects %d features: %s", len(_expected_columns), _expected_columns)
    else:
        log.warning("Could not fetch anomaly server's feature schema (%s) — live scoring paused", err)
    return _expected_columns


def _worker_loop(app):
    from app.models import NetworkRequest
    from app.anomaly import client, feature_extractor

    while True:
        row_id = _queue.get()
        try:
            with app.app_context():
                cols = _get_expected_columns()
                if not cols:
                    continue  # anomaly server not ready yet — drop silently, will retry on next event

                row = NetworkRequest.query.get(row_id)
                if row is None:
                    continue

                features = feature_extractor.build_features(row, cols)
                ok, err, body = client.score(features)
                if not ok:
                    log.debug("Live anomaly scoring failed for %s: %s", row_id, err)
        except Exception as e:
            log.warning("Live anomaly scoring error for %s: %s", row_id, e)
        finally:
            _queue.task_done()


def ensure_worker(app):
    global _worker_started
    if not settings.ANOMALY_LIVE_SCORING_ENABLED:
        return
    with _worker_lock:
        if _worker_started:
            return
        t = threading.Thread(target=_worker_loop, args=(app,), daemon=True, name="anomaly-live-scorer")
        t.start()
        _worker_started = True
        log.info("Live anomaly-scoring worker started.")


def queue_depth() -> int:
    return _queue.qsize()
