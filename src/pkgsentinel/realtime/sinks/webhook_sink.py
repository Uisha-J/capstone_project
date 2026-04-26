"""
Webhook sink — HMAC-SHA256 서명된 HTTP POST.

수신자 검증 흐름:
  1. body = raw bytes 읽기
  2. expected = HMAC-SHA256(shared_secret, timestamp + "." + body)
  3. X-AISLOPSQ-Signature 헤더 값과 비교 (constant-time)
  4. 타임스탬프 ±5분 허용 (replay 방지)

heading 형식 (GitHub webhook 과 유사):
  X-AISLOPSQ-Event:     'package.verdict'
  X-AISLOPSQ-Timestamp: '<unix-millis>'
  X-AISLOPSQ-Signature: 'sha256=<hex>'
  X-AISLOPSQ-Tool:      'ai-slopsquatting/2.0'
  Content-Type:         'application/json'
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


def hmac_sign(secret: str, timestamp_ms: int, body: bytes) -> str:
    """HMAC-SHA256(secret, "<ts>.<body>") → hex digest."""
    msg = f"{timestamp_ms}.".encode("utf-8") + body
    sig = hmac.new(
        secret.encode("utf-8"), msg, hashlib.sha256,
    ).hexdigest()
    return sig


def hmac_verify(secret: str, timestamp_ms: int, body: bytes,
                signature_header: str, *, max_age_s: int = 300) -> bool:
    """검증 헬퍼 (수신자 측에서 사용)."""
    if not signature_header:
        return False
    expected_prefix = "sha256="
    if not signature_header.startswith(expected_prefix):
        return False
    expected_sig = signature_header[len(expected_prefix):]
    actual = hmac_sign(secret, timestamp_ms, body)
    if not hmac.compare_digest(actual, expected_sig):
        return False
    # replay 방지: 타임스탬프 너무 오래되면 거부
    now_ms = int(time.time() * 1000)
    if abs(now_ms - timestamp_ms) > max_age_s * 1000:
        return False
    return True


@dataclass
class WebhookSink:
    url: str
    secret: str
    timeout: int = 10
    event_name: str = "package.verdict"

    def emit(self, payload: dict) -> dict:
        """payload (dict) → POST. 결과 dict 반환."""
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        ts = int(time.time() * 1000)
        sig = hmac_sign(self.secret, ts, body)

        req = urllib.request.Request(
            self.url,
            data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ai-slopsq/2.0",
                "X-AISLOPSQ-Event": self.event_name,
                "X-AISLOPSQ-Timestamp": str(ts),
                "X-AISLOPSQ-Signature": f"sha256={sig}",
                "X-AISLOPSQ-Tool": "ai-slopsquatting/2.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return {
                    "ok": True,
                    "status": resp.status,
                    "body_sha256": hashlib.sha256(body).hexdigest()[:16],
                }
        except urllib.error.HTTPError as e:
            return {"ok": False, "status": e.code, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": str(e)}


# ─────────────── CLI 데모 + self-verify ───────────────

if __name__ == "__main__":
    secret = "demo-shared-secret"
    payload = {"verdict": "MALICIOUS", "package": "evil-pkg", "version": "0.0.1"}
    body = json.dumps(payload).encode("utf-8")
    ts = int(time.time() * 1000)
    sig = hmac_sign(secret, ts, body)
    sig_header = f"sha256={sig}"
    print("== sign ==")
    print(f"  signature: {sig}")

    print("\n== verify (correct) ==")
    ok = hmac_verify(secret, ts, body, sig_header)
    print(f"  result: {ok}")
    assert ok

    print("\n== verify (tampered body) ==")
    ok = hmac_verify(secret, ts, body + b"x", sig_header)
    print(f"  result: {ok}")
    assert not ok

    print("\n== verify (wrong secret) ==")
    ok = hmac_verify("WRONG", ts, body, sig_header)
    print(f"  result: {ok}")
    assert not ok

    print("\n== verify (replay - 1 hour old) ==")
    old_ts = ts - 60 * 60 * 1000
    old_sig = hmac_sign(secret, old_ts, body)
    ok = hmac_verify(secret, old_ts, body, f"sha256={old_sig}")
    print(f"  result: {ok}")
    assert not ok

    print("\nALL OK")
