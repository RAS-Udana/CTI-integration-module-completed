"""Unit, component and timing tests for SOHO Module 1 (CTI & Enforcement).

Run from the soho-cti-dashboard folder:
    python -m pytest -q tests/test_module1.py
No network access is needed: threat feeds and the firewall app are replaced with stubs.
"""
import os
import struct
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.update({
    "DATABASE_URL": "sqlite://",
    "CAPTURE_MODE": "off",
    "ML_MODEL_DIR": os.path.join(ROOT, "app", "models", "models"),
    "ML_FEATURE_FILE": os.path.join(ROOT, "app", "models", "data", "feature_columns.json"),
    "BLOCK_SAFELIST": "8.8.8.8",
    "FIREWALL_APP_URL": "http://127.0.0.1:9",   # nothing listens here
    "FIREWALL_APP_TIMEOUT": "2",
})

from app import create_app                      # noqa: E402
from app.extensions import db                   # noqa: E402
from app.settings import settings               # noqa: E402
from app.cti import scorer, mitre, feeds        # noqa: E402
from app.cti.feeds import APIRecord             # noqa: E402
from app.enforcement import manager, firewall_client  # noqa: E402
from app.capture import direction               # noqa: E402
from app.capture.sniffer import _parse_sni      # noqa: E402

TIMINGS = {}


@pytest.fixture(scope="module")
def app():
    a = create_app()
    with a.app_context():
        yield a


def _days_ago(d):
    return (datetime.now(timezone.utc) - timedelta(days=d)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- MITRE severity
class TestMitre:
    def test_weights_loaded_and_bounded(self):
        w = mitre.get_weights_table()["weights"]
        assert len(w) == 10 and all(0.10 <= v <= 1.0 for v in w.values())

    def test_apt_is_highest_and_floor_is_s_min(self):
        w = mitre.get_weights_table()["weights"]
        assert max(w, key=w.get) == "apt" and min(w.values()) == pytest.approx(0.10)

    def test_family_tag_maps_to_category(self):
        cat, sev, defaulted = mitre.category_for_tags(["valleyrat"])
        assert cat == "botnet_c2" and not defaulted

    def test_category_word_fallback(self):
        cat, _, defaulted = mitre.category_for_tags(["some_ransomware_payload"])
        assert cat == "ransomware" and not defaulted

    def test_worst_case_wins(self):
        cat, _, _ = mitre.category_for_tags(["phishing", "apt29"])
        assert cat == "apt"

    def test_unknown_tag_defaults_to_s_unknown(self):
        cat, sev, defaulted = mitre.category_for_tags(["zzz-not-a-family"])
        assert (cat, sev, defaulted) == ("unknown", settings.S_UNKNOWN, True)

    def test_techniques_returned_for_category(self):
        assert "T1071" in mitre.techniques_for_category("botnet_c2")


# ---------------------------------------------------------------- scoring factors
class TestScoringFactors:
    @pytest.mark.parametrize("n,exp", [(0, 0.0), (1, 0.6), (2, 0.8), (4, 1.0)])
    def test_corroboration(self, n, exp):
        assert scorer._corroboration_score(n) == exp

    @pytest.mark.parametrize("days,exp", [(1, 1.0), (10, 0.7), (60, 0.5), (200, 0.1)])
    def test_freshness_steps(self, days, exp):
        assert scorer._freshness_score(_days_ago(days))[0] == exp

    def test_freshness_unknown_date(self):
        assert scorer._freshness_score(None)[0] == 0.5

    def test_freshness_threatfox_utc_suffix(self):
        assert scorer._freshness_score(_days_ago(2) + " UTC")[0] == 1.0

    @pytest.mark.parametrize("raw,exp", [
        ("HTTPS://Evil.Example.com:8443/a/b?x=1", ("evil.example.com", "domain")),
        ("185.215.113.66", ("185.215.113.66", "ip")),
        ("http://1.2.3.4/bins/x86", ("1.2.3.4", "ip")),
    ])
    def test_normalise(self, raw, exp):
        assert scorer._normalise(raw) == exp


# ---------------------------------------------------------------- end-to-end scoring (feeds stubbed)
class TestScoreIOC:
    def _stub(self, monkeypatch, uh=None, ab=None):
        monkeypatch.setattr(feeds, "query_urlhaus", lambda v: uh or APIRecord(source="urlhaus"))
        monkeypatch.setattr(feeds, "query_abusech", lambda v, t: ab or APIRecord(source="abuse.ch/threatfox"))

    def test_feed_hit_uses_rule_score(self, app, monkeypatch):
        rec = APIRecord(found=True, source="abuse.ch/threatfox", tags=["apt29"], first_seen=_days_ago(1))
        self._stub(monkeypatch, ab=rec)
        row = scorer.score_ioc("apt-c2.example.net", force=True)
        assert row.score_source == "api" and row.ml_used is False
        assert row.final_score == pytest.approx(1.0 * 0.6 * 1.0) and row.decision == "ENFORCE"

    def test_two_feeds_raise_corroboration(self, app, monkeypatch):
        a = APIRecord(found=True, source="urlhaus", tags=["emotet"], first_seen=_days_ago(3))
        b = APIRecord(found=True, source="abuse.ch/threatfox", tags=["botnet_cc"], first_seen=_days_ago(3))
        self._stub(monkeypatch, uh=a, ab=b)
        row = scorer.score_ioc("c2.example.org", force=True)
        assert row.feeds_found == 2 and row.corroboration_score == 0.8 and row.category == "botnet_c2"

    def test_no_feed_hit_uses_ml_fallback(self, app, monkeypatch):
        self._stub(monkeypatch)
        row = scorer.score_ioc("unlisted-host.example", force=True)
        assert row.ml_used is True and row.score_source.startswith("ml_fallback")
        assert 0.0 <= row.final_score <= 1.0

    def test_cache_reused_within_ttl(self, app, monkeypatch):
        calls = []
        monkeypatch.setattr(feeds, "query_urlhaus", lambda v: calls.append(v) or APIRecord(source="urlhaus"))
        monkeypatch.setattr(feeds, "query_abusech", lambda v, t: APIRecord(source="abuse.ch/threatfox"))
        scorer.score_ioc("cache-test.example", force=True)
        scorer.score_ioc("cache-test.example")
        assert len(calls) == 1

    def test_inbound_ttl_longer_than_outbound(self, app, monkeypatch):
        self._stub(monkeypatch)
        a = scorer.score_ioc("ttl-in.example", direction="inbound", force=True).ttl_seconds
        b = scorer.score_ioc("ttl-out.example", direction="outbound", force=True).ttl_seconds
        assert a == 72 * 3600 and b == 24 * 3600

    def test_local_decision_latency(self, app, monkeypatch):
        self._stub(monkeypatch)
        times = []
        for i in range(200):
            t = time.perf_counter()
            scorer.score_ioc(f"lat-{i}.example", force=True)
            times.append((time.perf_counter() - t) * 1000)
        TIMINGS["score_ioc_local_ms"] = times
        assert sorted(times)[len(times) // 2] < 500


# ---------------------------------------------------------------- ML fallback
class TestML:
    def test_all_seven_models_load(self, app):
        assert len(scorer._get_ml_model().models) == 7

    def test_probability_bounded_and_deterministic(self, app):
        m = scorer._get_ml_model()
        a, b = m.predict("example.com")["probability"], m.predict("example.com")["probability"]
        assert 0.0 <= a <= 1.0 and a == b

    def test_www_prefix_ignored(self, app):
        m = scorer._get_ml_model()
        assert m.predict("www.example.com")["probability"] == m.predict("example.com")["probability"]

    def test_inference_latency(self, app):
        m = scorer._get_ml_model()
        hosts = [f"host{i}-test.example" for i in range(200)]
        times = []
        for h in hosts:
            t = time.perf_counter(); m.predict(h); times.append((time.perf_counter() - t) * 1000)
        TIMINGS["ml_predict_ms"] = times
        assert sorted(times)[len(times) // 2] < 500


# ---------------------------------------------------------------- enforcement guards
class TestEnforcement:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.10.1", "224.0.0.251", "192.168.1.1",
                                    "10.0.0.5", "172.16.3.4", "8.8.8.8", "not-an-ip"])
    def test_guard_refuses_unsafe(self, ip):
        assert manager._is_unsafe_to_block(ip) is not None

    def test_guard_allows_public_ip(self):
        assert manager._is_unsafe_to_block("185.215.113.66") is None

    def test_block_refused_when_enforcement_disabled(self, app, monkeypatch):
        monkeypatch.setattr(settings, "ENFORCEMENT_ENABLED", False)
        row = type("R", (), {"ioc_type": "domain", "value": "x.example"})()
        with pytest.raises(manager.BlockRefused):
            manager.block_ioc(row)

    def test_private_ip_refused_before_firewall_call(self, app, monkeypatch):
        monkeypatch.setattr(settings, "ENFORCEMENT_ENABLED", True)
        called = []
        monkeypatch.setattr(firewall_client, "block", lambda *a, **k: called.append(a) or (True, "", {}))
        row = type("R", (), {"ioc_type": "ip", "value": "192.168.1.1"})()
        with pytest.raises(manager.BlockRefused):
            manager.block_ioc(row)
        assert called == []


class TestFirewallClient:
    def test_unreachable_does_not_raise(self):
        ok, msg, _ = firewall_client.block("domain", "x.example")
        assert ok is False and "could not reach" in msg

    @pytest.mark.parametrize("code,needle", [(401, "rejected the API token"), (503, "not configured"),
                                             (500, "returned 500")])
    def test_error_codes_mapped(self, monkeypatch, code, needle):
        class Resp:
            status_code = code
            def json(self): return {}
        monkeypatch.setattr(firewall_client.requests, "post", lambda *a, **k: Resp())
        ok, msg, _ = firewall_client.block("ip", "185.215.113.66")
        assert ok is False and needle in msg

    def test_success_passes_through(self, monkeypatch):
        class Resp:
            status_code = 200
            def json(self): return {"ok": True, "message": "blocked"}
        monkeypatch.setattr(firewall_client.requests, "post", lambda *a, **k: Resp())
        assert firewall_client.block("domain", "x.example")[:2] == (True, "blocked")

    def test_token_header_sent(self, monkeypatch):
        seen = {}
        class Resp:
            status_code = 200
            def json(self): return {"ok": True}
        monkeypatch.setattr(settings, "FIREWALL_APP_API_TOKEN", "t0k")
        monkeypatch.setattr(firewall_client.requests, "post",
                            lambda url, json, headers, timeout: seen.update(headers) or Resp())
        firewall_client.block("domain", "x.example")
        assert seen["X-API-Token"] == "t0k"


# ---------------------------------------------------------------- capture helpers
class TestCapture:
    def test_direction_outbound_from_local(self, monkeypatch):
        monkeypatch.setattr(direction, "_local_ips_cache", {"192.168.1.10", "127.0.0.1", "::1"})
        assert direction.classify("192.168.1.10", "93.184.216.34") == "outbound"

    def test_direction_inbound_to_local(self, monkeypatch):
        monkeypatch.setattr(direction, "_local_ips_cache", {"192.168.1.10", "127.0.0.1", "::1"})
        assert direction.classify("93.184.216.34", "192.168.1.10") == "inbound"

    def test_direction_transit_defaults_outbound(self, monkeypatch):
        monkeypatch.setattr(direction, "_local_ips_cache", {"127.0.0.1", "::1"})
        assert direction.classify("10.0.0.7", "93.184.216.34") == "outbound"

    @staticmethod
    def _client_hello(host: bytes) -> bytes:
        name = b"\x00" + struct.pack("!H", len(host)) + host
        sni = struct.pack("!H", len(name)) + name
        ext = struct.pack("!HH", 0, len(sni)) + sni
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
        body += struct.pack("!H", len(ext)) + ext
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

    def test_sni_parsed(self):
        assert _parse_sni(self._client_hello(b"malicious.example.com")) == "malicious.example.com"

    def test_sni_non_tls_returns_none(self):
        assert _parse_sni(b"GET / HTTP/1.1\r\n") is None

    def test_sni_truncated_returns_none(self):
        assert _parse_sni(self._client_hello(b"a.example")[:20]) is None


def teardown_module(module):
    import json, statistics
    out = {}
    for k, v in TIMINGS.items():
        s = sorted(v)
        out[k] = {"n": len(s), "median": round(statistics.median(s), 2),
                  "p95": round(s[int(len(s) * 0.95) - 1], 2), "max": round(s[-1], 2)}
    with open(os.path.join(ROOT, "tests", "timings.json"), "w") as f:
        json.dump(out, f, indent=2)
