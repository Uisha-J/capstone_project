"""S1 (/api/v1/analyze) + S2 (/api/v1/iocs/export) 단위 테스트."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _setup():
    td = tempfile.mkdtemp(prefix="api_s1s2_")
    os.environ["AISLOP_DB_KEY"] = "api-s1s2-test"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )
    return td


def _teardown(td):
    import shutil; shutil.rmtree(td, ignore_errors=True)


# ─────────────── S1 — analyze ───────────────

def test_analyze_missing_required():
    print("== analyze: 필수 필드 누락 → 400 ==")
    from pkgsentinel.api.analyze import handle_analyze
    resp, code = handle_analyze({})
    assert code == 400
    assert "package" in resp.get("error", "").lower()
    print("  OK")


def test_analyze_unknown_ecosystem():
    print("\n== analyze: unknown ecosystem → 400 ==")
    from pkgsentinel.api.analyze import handle_analyze
    resp, code = handle_analyze(
        {"package": "x", "ecosystem": "rubygems"},
    )
    assert code == 400
    assert "ecosystem" in resp.get("error", "").lower()
    print("  OK")


def test_analyze_unknown_llm_mode():
    print("\n== analyze: unknown llm_mode → 400 ==")
    from pkgsentinel.api.analyze import handle_analyze
    resp, code = handle_analyze(
        {"package": "x", "ecosystem": "npm", "llm_mode": "gpt4"},
    )
    assert code == 400
    print("  OK")


def test_analyze_hmac_invalid():
    print("\n== analyze: HMAC 잘못된 sig → 401 ==")
    from pkgsentinel.api.analyze import handle_analyze
    body = b'{"package":"x","ecosystem":"npm"}'
    resp, code = handle_analyze(
        json.loads(body),
        signature_header="sha256=deadbeef",
        timestamp_ms=int(time.time() * 1000),
        raw_body=body,
        shared_secret="my-secret",
    )
    assert code == 401
    print("  OK")


def test_analyze_hmac_valid_then_runs(monkeypatch):
    """HMAC 정상 + run_pipeline mock — 성공 path."""
    print("\n== analyze: HMAC 정상 → pipeline 호출 ==")
    td = _setup()
    try:
        from pkgsentinel.api.analyze import handle_analyze
        from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign

        # run_pipeline 을 mock — pipeline 자체는 본 테스트 범위 외
        class _FakeVerdict:
            value = "MALICIOUS"
        class _FakeReport:
            verdict = _FakeVerdict()
            evidence = []
            package_meta = {"src": "test"}

        monkeypatch.setattr(
            "pkgsentinel.pipeline.run_pipeline",
            lambda **kw: _FakeReport(),
        )

        body_dict = {
            "package": "evil-test", "ecosystem": "npm",
            "version": "0.0.1", "llm_mode": "stub",
        }
        body = json.dumps(body_dict).encode("utf-8")
        ts = int(time.time() * 1000)
        sig = hmac_sign("test-secret", ts, body)
        resp, code = handle_analyze(
            body_dict,
            signature_header=f"sha256={sig}",
            timestamp_ms=ts,
            raw_body=body,
            shared_secret="test-secret",
        )
        assert code == 200
        assert resp["ok"] is True
        assert resp["verdict"] == "MALICIOUS"
        assert resp["cache"]["hit"] is False
        print("  OK")
    finally:
        _teardown(td)


def test_analyze_cache_hit_path(monkeypatch):
    """analyses 테이블에 직접 row 적재 → 캐시 hit 경로."""
    print("\n== analyze: cache hit → pipeline 호출 X ==")
    td = _setup()
    try:
        from pkgsentinel.api.analyze import handle_analyze
        from pkgsentinel.db.analysis_cache import AnalysisCache, CacheKey

        cache = AnalysisCache()
        rep = {
            "verdict": "CLEAN",
            "evidence": [],
            "package_meta": {"x": 1},
        }
        cache.put(CacheKey("test-pkg", "npm", "1.0.0"), rep, verdict="CLEAN")

        # pipeline mock — 호출되면 안 됨
        called = [False]
        def _bad(**kw):
            called[0] = True
            raise RuntimeError("should not call pipeline on cache hit")
        monkeypatch.setattr("pkgsentinel.pipeline.run_pipeline", _bad)

        resp, code = handle_analyze({
            "package": "test-pkg", "ecosystem": "npm", "version": "1.0.0",
        })
        assert code == 200
        assert resp["ok"] is True
        assert resp["verdict"] == "CLEAN"
        assert resp["cache"]["hit"] is True
        assert called[0] is False
        print(f"  OK cache hit, pipeline not invoked")
    finally:
        _teardown(td)


def test_analyze_pipeline_exception_returns_500(monkeypatch):
    print("\n== analyze: pipeline 예외 → 500 + error ==")
    td = _setup()
    try:
        from pkgsentinel.api.analyze import handle_analyze
        monkeypatch.setattr(
            "pkgsentinel.pipeline.run_pipeline",
            lambda **kw: (_ for _ in ()).throw(RuntimeError("pipeline error")),
        )
        resp, code = handle_analyze({
            "package": "x", "ecosystem": "npm", "version": "1",
        })
        assert code == 500
        assert "pipeline error" in resp.get("error", "")
        print("  OK")
    finally:
        _teardown(td)


# ─────────────── S2 — iocs export ───────────────

def test_iocs_export_empty():
    print("\n== iocs export: 빈 DB → 빈 list ==")
    td = _setup()
    try:
        from pkgsentinel.api.iocs_export import handle_iocs_export
        resp, code = handle_iocs_export({})
        assert code == 200
        assert resp["ok"] is True
        assert resp["count"] == 0
        assert resp["iocs"] == []
        print("  OK")
    finally:
        _teardown(td)


def test_iocs_export_returns_approved_only():
    print("\n== iocs export: status=approved 필터 ==")
    td = _setup()
    try:
        from pkgsentinel.db.runtime_intel import (
            LearnedIOC, RuntimeIntelStore,
        )
        s = RuntimeIntelStore()
        # 두 IOC — approved 1개, pending 1개
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="1.1.1.1",
                                confidence=0.95),
                     package_at_version="evil@0.1")
        with s.db.cursor() as cur:
            cur.execute(
                "UPDATE learned_iocs SET status='approved' "
                "WHERE value='1.1.1.1'",
            )
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="2.2.2.2",
                                confidence=0.5),
                     package_at_version="x@1")

        from pkgsentinel.api.iocs_export import handle_iocs_export
        resp, code = handle_iocs_export({"min_confidence": 0.0})
        assert code == 200
        values = {i["value"] for i in resp["iocs"]}
        assert "1.1.1.1" in values
        assert "2.2.2.2" not in values   # pending — 제외
        print(f"  OK approved-only: {values}")
    finally:
        _teardown(td)


def test_iocs_export_since_filter():
    print("\n== iocs export: since 필터 (increment sync) ==")
    td = _setup()
    try:
        from pkgsentinel.db.runtime_intel import (
            LearnedIOC, RuntimeIntelStore,
        )
        s = RuntimeIntelStore()
        # 2 IOC — upsert 후 last_seen 직접 덮어쓰기 (upsert 가 _now() 사용)
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="1.1.1.1",
                                confidence=0.95, status="approved"))
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="2.2.2.2",
                                confidence=0.95, status="approved"))
        with s.db.cursor() as cur:
            cur.execute("UPDATE learned_iocs SET status='approved'")
            cur.execute(
                "UPDATE learned_iocs SET last_seen='2026-05-13T00:00:00Z' "
                "WHERE value='1.1.1.1'",
            )
            cur.execute(
                "UPDATE learned_iocs SET last_seen='2026-05-13T12:00:00Z' "
                "WHERE value='2.2.2.2'",
            )

        from pkgsentinel.api.iocs_export import handle_iocs_export
        resp, code = handle_iocs_export({
            "since": "2026-05-13T06:00:00Z",
        })
        assert code == 200
        values = {i["value"] for i in resp["iocs"]}
        # 2.2.2.2 만 since 이후
        assert "2.2.2.2" in values
        assert "1.1.1.1" not in values
        # high_watermark 가 최대 last_seen
        assert resp["high_watermark"] >= "2026-05-13T12:00:00"
        print("  OK")
    finally:
        _teardown(td)


def test_iocs_export_type_filter():
    print("\n== iocs export: ioc_type 필터 ==")
    td = _setup()
    try:
        from pkgsentinel.db.runtime_intel import (
            LearnedIOC, RuntimeIntelStore,
        )
        s = RuntimeIntelStore()
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="1.1.1.1",
                                confidence=0.9, status="approved"))
        s.upsert_ioc(LearnedIOC(ioc_type="domain", value="x.com",
                                confidence=0.9, status="approved"))
        with s.db.cursor() as cur:
            cur.execute("UPDATE learned_iocs SET status='approved'")

        from pkgsentinel.api.iocs_export import handle_iocs_export
        resp, _ = handle_iocs_export({"ioc_type": "ip"})
        types = {i["type"] for i in resp["iocs"]}
        assert types == {"ip"}
        print("  OK")
    finally:
        _teardown(td)


def test_iocs_export_hmac_invalid():
    print("\n== iocs export: HMAC 잘못된 sig → 401 ==")
    td = _setup()
    try:
        from pkgsentinel.api.iocs_export import handle_iocs_export
        body = b'{}'
        resp, code = handle_iocs_export(
            {},
            signature_header="sha256=bad",
            timestamp_ms=int(time.time() * 1000),
            raw_body=body,
            shared_secret="test-secret",
        )
        assert code == 401
        print("  OK")
    finally:
        _teardown(td)


def test_iocs_export_unknown_status():
    print("\n== iocs export: unknown status → 400 ==")
    td = _setup()
    try:
        from pkgsentinel.api.iocs_export import handle_iocs_export
        resp, code = handle_iocs_export({"status": "weird"})
        assert code == 400
        print("  OK")
    finally:
        _teardown(td)


def main():
    pass


if __name__ == "__main__":
    main()
