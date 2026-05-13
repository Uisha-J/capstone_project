"""#S3 Flask server adapter — 단위 테스트.

flask test client 사용. 실제 소켓 바인딩 X.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest


def _setup_db():
    td = tempfile.mkdtemp(prefix="srv_s3_")
    os.environ["AISLOP_DB_KEY"] = "srv-s3-test"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )
    return td


def _teardown_db(td):
    import shutil; shutil.rmtree(td, ignore_errors=True)


@pytest.fixture
def client():
    td = _setup_db()
    try:
        # secret 없이 — dev 모드 (HMAC skip)
        os.environ.pop("PKGSENTINEL_HMAC_SECRET", None)
        from pkgsentinel.server.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        yield app.test_client()
    finally:
        _teardown_db(td)


@pytest.fixture
def client_with_secret():
    td = _setup_db()
    try:
        os.environ["PKGSENTINEL_HMAC_SECRET"] = "test-secret"
        from pkgsentinel.server.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        yield app.test_client()
    finally:
        os.environ.pop("PKGSENTINEL_HMAC_SECRET", None)
        _teardown_db(td)


# ─────────────── healthz / readyz / metrics ───────────────

def test_healthz(client):
    print("== /healthz ==")
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["service"] == "pkgsentinel"
    print("  OK")


def test_readyz(client):
    print("\n== /readyz (DB 연결) ==")
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    print("  OK")


def test_metrics_exposition(client):
    print("\n== /metrics — Prometheus 형식 ==")
    # 한 번 healthz 호출 → 카운터 증가
    client.get("/healthz")
    r = client.get("/metrics")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "pkgsentinel_requests_total" in text
    assert "# TYPE" in text
    print(f"  OK ({len(text)} chars)")


def test_404_json(client):
    print("\n== 404 JSON 응답 ==")
    r = client.get("/nonexistent")
    assert r.status_code == 404
    assert r.get_json()["error"] == "not found"
    print("  OK")


def test_405_json(client):
    print("\n== 405 method not allowed ==")
    r = client.get("/api/v1/analyze")
    assert r.status_code == 405
    print("  OK")


# ─────────────── analyze endpoint ───────────────

def test_analyze_400_missing(client):
    print("\n== POST /api/v1/analyze: 필수 누락 → 400 ==")
    r = client.post("/api/v1/analyze", json={})
    assert r.status_code == 400
    print("  OK")


def test_analyze_400_bad_ecosystem(client):
    print("\n== POST /api/v1/analyze: unknown ecosystem → 400 ==")
    r = client.post("/api/v1/analyze",
                    json={"package": "x", "ecosystem": "rubygems"})
    assert r.status_code == 400
    print("  OK")


def test_analyze_hmac_required_but_missing_headers(client_with_secret):
    print("\n== analyze (HMAC 모드): 헤더 없음 → 400 ==")
    r = client_with_secret.post("/api/v1/analyze",
                                json={"package": "x", "ecosystem": "npm"})
    assert r.status_code == 400
    print("  OK")


def test_analyze_hmac_invalid_sig(client_with_secret):
    print("\n== analyze (HMAC 모드): 잘못된 sig → 401 ==")
    body = b'{"package":"x","ecosystem":"npm"}'
    r = client_with_secret.post(
        "/api/v1/analyze",
        data=body,
        content_type="application/json",
        headers={
            "X-AISLOPSQ-Signature": "sha256=deadbeef",
            "X-AISLOPSQ-Timestamp": str(int(time.time() * 1000)),
        },
    )
    assert r.status_code == 401
    print("  OK")


def test_analyze_hmac_valid_full_loop(monkeypatch, client_with_secret):
    print("\n== analyze (HMAC 모드): 정상 signed → 200 ==")
    from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign

    class _FakeVerdict:
        value = "CLEAN"
    class _FakeReport:
        verdict = _FakeVerdict()
        evidence = []
        package_meta = {}

    monkeypatch.setattr("pkgsentinel.pipeline.run_pipeline",
                        lambda **kw: _FakeReport())

    body_dict = {"package": "x", "ecosystem": "npm",
                 "version": "1.0.0", "llm_mode": "stub"}
    body = json.dumps(body_dict).encode("utf-8")
    ts = int(time.time() * 1000)
    sig = hmac_sign("test-secret", ts, body)
    r = client_with_secret.post(
        "/api/v1/analyze",
        data=body,
        content_type="application/json",
        headers={
            "X-AISLOPSQ-Signature": f"sha256={sig}",
            "X-AISLOPSQ-Timestamp": str(ts),
        },
    )
    assert r.status_code == 200
    assert r.get_json()["verdict"] == "CLEAN"
    print("  OK")


# ─────────────── iocs/export endpoint ───────────────

def test_iocs_export_get_empty(client):
    print("\n== GET /api/v1/iocs/export — 빈 DB ==")
    r = client.get("/api/v1/iocs/export")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["count"] == 0
    print("  OK")


def test_iocs_export_get_with_query_filter(client):
    print("\n== GET /api/v1/iocs/export?ioc_type=ip ==")
    from pkgsentinel.db.runtime_intel import LearnedIOC, RuntimeIntelStore
    s = RuntimeIntelStore()
    s.upsert_ioc(LearnedIOC(ioc_type="ip", value="9.9.9.9",
                            confidence=0.95, status="approved"))
    s.upsert_ioc(LearnedIOC(ioc_type="domain", value="evil.example",
                            confidence=0.95, status="approved"))
    with s.db.cursor() as cur:
        cur.execute("UPDATE learned_iocs SET status='approved'")

    r = client.get("/api/v1/iocs/export?ioc_type=ip&min_confidence=0.0")
    assert r.status_code == 200
    body = r.get_json()
    types = {i["type"] for i in body["iocs"]}
    assert types == {"ip"}
    print("  OK")


def test_iocs_export_post_unknown_status(client):
    print("\n== POST /api/v1/iocs/export: unknown status → 400 ==")
    r = client.post("/api/v1/iocs/export", json={"status": "weird"})
    assert r.status_code == 400
    print("  OK")


# ─────────────── runtime-alert smoke ───────────────

def test_runtime_alert_empty_payload(client):
    print("\n== POST /api/v1/runtime-alert: 빈 payload ==")
    r = client.post("/api/v1/runtime-alert", json={})
    # handle_runtime_alert 가 200 or 400 어느 쪽이든 — 5xx 가 아니어야 함
    assert r.status_code < 500
    print(f"  OK (code={r.status_code})")


# ─────────────── body 크기 제한 ───────────────

def test_body_too_large_413(client):
    print("\n== body > 4 MiB → 413 ==")
    big = b'{"x":"' + b"A" * (5 * 1024 * 1024) + b'"}'
    r = client.post("/api/v1/analyze", data=big,
                    content_type="application/json")
    assert r.status_code == 413
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
