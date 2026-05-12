"""TaxiiSink 단위 테스트.

실 TAXII 서버 없이 monkeypatch 로 urllib.request.urlopen 만 가로채 검증.
검증 항목:
  - endpoint URL 빌더 (url 직접 / api_root + collection_id)
  - envelope 형식 (`{"objects": [...]}`)
  - Content-Type / Accept 헤더
  - Basic / Bearer 인증
  - 응답 코드별 ok 판정
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.realtime.sinks.taxii_sink import TaxiiSink


SAMPLE_BUNDLE = {
    "type": "bundle",
    "id": "bundle--abcdef",
    "objects": [
        {"type": "identity", "id": "identity--1"},
        {"type": "indicator", "id": "indicator--2"},
    ],
}


def _mock_urlopen_factory(status_code=202, response_body=None):
    """urllib.request.urlopen 을 가로채 (status, body) 캡처용 MagicMock 반환."""
    captured = {"req": None}
    body_bytes = json.dumps(response_body or {
        "id": "status--1",
        "status": "complete",
        "total_count": 2, "success_count": 2,
        "successes": [], "failures": [], "pendings": [],
    }).encode("utf-8")

    class _Resp:
        def __init__(self):
            self.status = status_code
        def read(self):
            return body_bytes
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    def _urlopen(req, timeout=None):
        captured["req"] = req
        if status_code >= 400:
            import urllib.error
            raise urllib.error.HTTPError(
                req.full_url, status_code, "fake",
                req.header_items(), io.BytesIO(body_bytes),
            )
        return _Resp()

    return _urlopen, captured


def test_endpoint_full_url():
    print("== endpoint: full URL ==")
    s = TaxiiSink(collection_objects_url="https://t.example/c/aislopsq/objects/")
    assert s._endpoint() == "https://t.example/c/aislopsq/objects/"
    # trailing slash 자동 보정
    s2 = TaxiiSink(collection_objects_url="https://t.example/c/aislopsq/objects")
    assert s2._endpoint().endswith("/")
    print("  OK")


def test_endpoint_api_root_plus_collection():
    print("\n== endpoint: api_root + collection_id ==")
    s = TaxiiSink(
        api_root_url="https://t.example/api/v1/",
        collection_id="aislopsq",
    )
    assert s._endpoint() == "https://t.example/api/v1/collections/aislopsq/objects/"
    print("  OK")


def test_endpoint_missing_raises():
    print("\n== endpoint missing ==")
    s = TaxiiSink()
    import pytest
    res = s.post_bundle(SAMPLE_BUNDLE)
    assert res["ok"] is False and "requires" in res["error"]
    print(f"  OK error={res['error'][:60]}")


def test_envelope_strips_bundle_metadata():
    print("\n== envelope: bundle 의 type/id 제거 ==")
    env = TaxiiSink.to_envelope(SAMPLE_BUNDLE)
    assert "type" not in env
    assert env["objects"] == SAMPLE_BUNDLE["objects"]
    print(f"  OK env keys={list(env.keys())}")


def test_post_success_with_basic_auth(monkeypatch):
    print("\n== POST 202 success + Basic auth ==")
    _urlopen, captured = _mock_urlopen_factory(status_code=202)
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    s = TaxiiSink(
        collection_objects_url="https://t.example/c/aislopsq/objects/",
        basic_user="u", basic_pass="p",
    )
    res = s.post_bundle(SAMPLE_BUNDLE)
    assert res["ok"] is True
    assert res["status_code"] == 202
    assert res["object_count"] == 2
    assert res["status"]["status"] == "complete"
    # 헤더 검증
    req = captured["req"]
    assert req.method == "POST"
    auth = req.get_header("Authorization") or req.headers.get("Authorization")
    assert auth and auth.startswith("Basic ")
    ct = req.get_header("Content-type") or req.headers.get("Content-type")
    assert ct and "taxii+json" in ct
    # body 가 envelope 형식
    sent = json.loads(req.data.decode("utf-8"))
    assert sent == {"objects": SAMPLE_BUNDLE["objects"]}
    print("  OK headers + envelope correct")


def test_post_with_bearer(monkeypatch):
    print("\n== Bearer token auth ==")
    _urlopen, captured = _mock_urlopen_factory(status_code=200)
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    s = TaxiiSink(
        collection_objects_url="https://t.example/c/x/objects/",
        bearer_token="xyz",
    )
    res = s.post_bundle(SAMPLE_BUNDLE)
    assert res["ok"] is True
    auth = captured["req"].get_header("Authorization")
    assert auth == "Bearer xyz", auth
    print("  OK")


def test_post_http_error(monkeypatch):
    print("\n== HTTP 401 → ok=False ==")
    _urlopen, _ = _mock_urlopen_factory(status_code=401)
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    s = TaxiiSink(collection_objects_url="https://t.example/c/x/objects/")
    res = s.post_bundle(SAMPLE_BUNDLE)
    assert res["ok"] is False
    assert res["status_code"] == 401
    assert "HTTP 401" in res["error"]
    print("  OK")


def test_post_url_error(monkeypatch):
    print("\n== URLError → ok=False ==")
    def _bad(*a, **kw):
        import urllib.error
        raise urllib.error.URLError("DNS failed")
    monkeypatch.setattr("urllib.request.urlopen", _bad)
    s = TaxiiSink(collection_objects_url="https://t.example/c/x/objects/")
    res = s.post_bundle(SAMPLE_BUNDLE)
    assert res["ok"] is False
    assert res["status_code"] is None
    assert "URLError" in res["error"]
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
