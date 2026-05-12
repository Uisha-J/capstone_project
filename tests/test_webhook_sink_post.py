"""WebhookSink.emit() 실 HTTP POST 회귀 — urllib 만 mock.

기존 test_realtime_pipeline.py 는 HMAC sign/verify 단독 함수만 테스트.
본 파일은 emit() 의 전체 흐름 (sig 생성 + 헤더 세팅 + POST + 응답 처리)을 검증.

실 endpoint 호출 옵션: WEBHOOK_LIVE=1 일 때 httpbin.org 로 1회 실 송신.
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.realtime.sinks.webhook_sink import WebhookSink, hmac_sign, hmac_verify


def _mock_urlopen_factory(status_code=200, response_body=b"ok"):
    """urllib.request.urlopen 가로채기. 요청 객체를 capture."""
    captured = {"req": None}

    class _Resp:
        def __init__(self, code):
            self.status = code
        def read(self):
            return response_body
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def _urlopen(req, timeout=None):
        captured["req"] = req
        if status_code >= 400:
            import urllib.error
            raise urllib.error.HTTPError(
                req.full_url, status_code, "fake error",
                req.header_items(), io.BytesIO(response_body),
            )
        return _Resp(status_code)

    return _urlopen, captured


# ─────────────── 헤더 / 본문 검증 ───────────────

def test_emit_sets_required_headers(monkeypatch):
    print("== emit() — 필수 헤더 모두 세팅 ==")
    _urlopen, captured = _mock_urlopen_factory(status_code=200)
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)

    sink = WebhookSink(url="https://siem.example.com/in", secret="s3cr3t")
    payload = {"verdict": "MALICIOUS", "package": "evil-pkg"}
    res = sink.emit(payload)

    assert res["ok"] is True
    assert res["status"] == 200

    req = captured["req"]
    assert req.method == "POST"
    # 헤더는 case-insensitive
    h = {k.lower(): v for k, v in req.header_items()}
    assert h["content-type"] == "application/json"
    assert h["x-aislopsq-event"] == "package.verdict"
    assert h["x-aislopsq-tool"].startswith("ai-slopsquatting/")
    assert h["x-aislopsq-signature"].startswith("sha256=")
    ts = int(h["x-aislopsq-timestamp"])
    # 합리적 시각 (현재 ±10초)
    now_ms = int(time.time() * 1000)
    assert abs(now_ms - ts) < 10_000
    print(f"  OK sig={h['x-aislopsq-signature'][:24]}..")


def test_emit_signature_round_trips_through_verify(monkeypatch):
    """sign → verify 가 통과해야."""
    print("\n== sig 생성 → hmac_verify 통과 ==")
    _urlopen, captured = _mock_urlopen_factory()
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)

    sink = WebhookSink(url="https://x.example.com/in", secret="my-secret")
    payload = {"verdict": "CLEAN", "package": "good-pkg"}
    sink.emit(payload)

    req = captured["req"]
    h = {k.lower(): v for k, v in req.header_items()}
    body = req.data
    ts = int(h["x-aislopsq-timestamp"])
    sig_header = h["x-aislopsq-signature"]

    assert hmac_verify("my-secret", ts, body, sig_header) is True
    # wrong secret
    assert hmac_verify("wrong", ts, body, sig_header) is False
    print("  OK round-trip")


def test_emit_body_is_payload_json(monkeypatch):
    print("\n== body 가 payload JSON ==")
    _urlopen, captured = _mock_urlopen_factory()
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    sink = WebhookSink(url="https://x.example.com/", secret="x")
    payload = {"verdict": "MALICIOUS", "k": [1, 2, 3]}
    sink.emit(payload)
    sent = json.loads(captured["req"].data.decode("utf-8"))
    assert sent == payload
    print(f"  OK body={sent}")


# ─────────────── 오류 처리 ───────────────

def test_emit_http_error_returns_ok_false(monkeypatch):
    print("\n== HTTP 500 → ok=False ==")
    _urlopen, _ = _mock_urlopen_factory(status_code=500)
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    sink = WebhookSink(url="https://broken.example.com/", secret="x")
    res = sink.emit({"v": 1})
    assert res["ok"] is False
    assert res["status"] == 500
    print(f"  OK error={res.get('error', '')[:60]}")


def test_emit_network_error_returns_ok_false(monkeypatch):
    print("\n== URLError → ok=False ==")
    def _bad(*a, **kw):
        import urllib.error
        raise urllib.error.URLError("no DNS")
    monkeypatch.setattr("urllib.request.urlopen", _bad)
    sink = WebhookSink(url="https://nowhere.invalid/", secret="x")
    res = sink.emit({"v": 1})
    assert res["ok"] is False
    assert "no DNS" in res["error"] or "URLError" in res["error"]
    print(f"  OK error={res.get('error', '')[:60]}")


# ─────────────── (선택) 실 endpoint 송신 ───────────────

def test_emit_against_httpbin_live():
    """선택적 — WEBHOOK_LIVE=1 시 httpbin.org/post 로 실 송신."""
    if os.getenv("WEBHOOK_LIVE") != "1":
        print("\n== Live httpbin SKIPPED (set WEBHOOK_LIVE=1) ==")
        return
    print("\n== Live httpbin /post ==")
    sink = WebhookSink(url="https://httpbin.org/post", secret="live-test")
    res = sink.emit({"verdict": "MALICIOUS", "via": "pytest"})
    print(f"  result: {res}")
    assert res["ok"] is True
    assert res["status"] == 200


def main():
    print("(monkeypatch 테스트는 pytest 로 실행)")


if __name__ == "__main__":
    main()
