
import logging
from datetime import timedelta

import numpy as np

from app.extensions import db
from app.models import NetworkRequest

log = logging.getLogger("feature_extractor")

WINDOW_SECONDS = 5  # matches the model's packet_count_5s / mean_packet_size naming

# Hardcoded because these are literally what the model was trained on —
# specific lab-network device addresses baked into one-hot columns.
_KNOWN_ONE_HOT_IPS = {
    "src_ip_192.168.1.2": ("src_ip", "192.168.1.2"),
    "src_ip_192.168.1.3": ("src_ip", "192.168.1.3"),
    "dst_ip_192.168.1.5": ("dst_ip", "192.168.1.5"),
    "dst_ip_192.168.1.6": ("dst_ip", "192.168.1.6"),
}
_KNOWN_TCP_FLAG_COLS = {
    "tcp_flags_FIN": "FIN",
    "tcp_flags_SYN": "SYN",
    "tcp_flags_SYN-ACK": "SYN-ACK",
}

_warned_unrecognized = set()


def _windowed_rows(row: NetworkRequest):
    """All rows from the same src_ip in [row.ts - WINDOW_SECONDS, row.ts],
    including row itself, ordered by time. Real query, real data.
    """
    if not row.src_ip:
        return [row]
    since = row.ts - timedelta(seconds=WINDOW_SECONDS)
    return (
        NetworkRequest.query
        .filter(NetworkRequest.src_ip == row.src_ip)
        .filter(NetworkRequest.ts >= since, NetworkRequest.ts <= row.ts)
        .order_by(NetworkRequest.ts.asc())
        .all()
    )


def _inter_arrival_time(row: NetworkRequest) -> float:
    if not row.src_ip:
        return 0.0
    prior = (
        NetworkRequest.query
        .filter(NetworkRequest.src_ip == row.src_ip, NetworkRequest.ts < row.ts)
        .order_by(NetworkRequest.ts.desc())
        .first()
    )
    if prior is None:
        return 0.0  # first-seen event from this source — no prior interval to measure
    return max((row.ts - prior.ts).total_seconds(), 0.0)


def _spectral_features(window_rows: list) -> tuple[float, float]:
    """Normalized spectral entropy + high-frequency energy ratio of the
    windowed packet_size series. Needs at least 2 real samples with a
    known packet_size — with fewer, there's genuinely not enough signal
    to compute a spectrum, so both return 0.0 (honest, not guessed).
    """
    sizes = [r.packet_size for r in window_rows if r.packet_size is not None]
    if len(sizes) < 2:
        return 0.0, 0.0

    signal = np.array(sizes, dtype=np.float64)
    signal = signal - signal.mean()  # remove DC component before FFT
    spectrum = np.fft.rfft(signal)
    power = np.abs(spectrum) ** 2
    total_power = power.sum()

    if total_power <= 0:
        return 0.0, 0.0

    p = power / total_power
    p_nonzero = p[p > 0]
    max_entropy = np.log2(len(p)) or 1.0
    spectral_entropy = float(-(p_nonzero * np.log2(p_nonzero)).sum() / max_entropy)

    mid = len(power) // 2
    frequency_band_energy = float(power[mid:].sum() / total_power)

    return spectral_entropy, frequency_band_energy


def build_features(row: NetworkRequest, expected_columns: list) -> dict:
    """Builds a {column_name: value} dict covering every column in
    expected_columns (the live model's feature_columns from /health),
    using only real data. Raises nothing — unrecognized columns
    default to 0.0 with a one-time warning.
    """
    window_rows = _windowed_rows(row)
    packet_sizes_in_window = [r.packet_size for r in window_rows if r.packet_size is not None]
    spectral_entropy, frequency_band_energy = _spectral_features(window_rows)

    computed = {
        "packet_size": float(row.packet_size or 0),
        "inter_arrival_time": _inter_arrival_time(row),
        "src_port": float(row.src_port or 0),
        "dst_port": float(row.dst_port or 0),
        "packet_count_5s": float(len(window_rows)),
        "mean_packet_size": float(np.mean(packet_sizes_in_window)) if packet_sizes_in_window else 0.0,
        "spectral_entropy": spectral_entropy,
        "frequency_band_energy": frequency_band_energy,
        "protocol_type_TCP": 1.0 if row.protocol in ("tls", "tcp") else 0.0,
        "protocol_type_UDP": 1.0 if row.protocol == "dns" else 0.0,
    }

    for col, (field, expected_val) in _KNOWN_ONE_HOT_IPS.items():
        computed[col] = 1.0 if getattr(row, field, None) == expected_val else 0.0

    for col, expected_flag in _KNOWN_TCP_FLAG_COLS.items():
        computed[col] = 1.0 if row.tcp_flags == expected_flag else 0.0

    features = {}
    for col in expected_columns:
        if col in computed:
            features[col] = computed[col]
        else:
            features[col] = 0.0
            if col not in _warned_unrecognized:
                _warned_unrecognized.add(col)
                log.warning(
                    "Model expects feature '%s' which this extractor doesn't know how to "
                    "compute from real traffic — defaulting to 0.0. Extend "
                    "app/anomaly/feature_extractor.py if this should be real.", col,
                )

    return features
