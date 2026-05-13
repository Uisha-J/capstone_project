"""#S4 — api/auth.py 통합 HMAC + replay 차단 테스트."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_dev_mode_no_secret_passes():
    print("== check_hmac: dev 모드 (secret=None) → ok ==")
    from pkgsentinel.api.auth import check_hmac
    ok, err = check_hmac(None, None, None, shared_secret=None)
    assert ok and err is None
    print("  OK")


def test_missing_headers_returns_400():
    print("\n== check_hmac: secret 설정 + 헤더 없음 → 400 ==")
    from pkgsentinel.api.auth import check_hmac
    ok, err = check_hmac(None, None, None, shared_secret="s")
    assert not ok and err is not None
    resp, code = err
    assert code == 400
    print("  OK")


def test_bad_signature_returns_401():
    print("\n== check_hmac: 잘못된 sig → 401 ==")
    from pkgsentinel.api.auth import check_hmac, _reset_nonce_cache
    _reset_nonce_cache()
    ts = int(time.time() * 1000)
    body = b'{"x":1}'
    ok, err = check_hmac("sha256=deadbeef", ts, body, shared_secret="s")
    assert not ok
    resp, code = err
    assert code == 401
    print("  OK")


def test_valid_signature_passes():
    print("\n== check_hmac: 정상 sig → ok ==")
    from pkgsentinel.api.auth import check_hmac, _reset_nonce_cache
    from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign
    _reset_nonce_cache()
    secret = "test-secret-s4"
    body = b'{"hello":"world"}'
    ts = int(time.time() * 1000)
    sig = f"sha256={hmac_sign(secret, ts, body)}"
    ok, err = check_hmac(sig, ts, body, shared_secret=secret)
    assert ok and err is None
    print("  OK")


def test_replay_within_window_blocked():
    """동일 (ts, sig) 두 번째 요청은 401."""
    print("\n== check_hmac: replay 차단 (같은 ts+sig 재전송) ==")
    from pkgsentinel.api.auth import check_hmac, _reset_nonce_cache
    from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign
    _reset_nonce_cache()
    secret = "test-secret-replay"
    body = b'{"a":1}'
    ts = int(time.time() * 1000)
    sig = f"sha256={hmac_sign(secret, ts, body)}"

    # 1st — ok
    ok1, _ = check_hmac(sig, ts, body, shared_secret=secret)
    assert ok1
    # 2nd — 같은 (ts, sig) → 차단
    ok2, err2 = check_hmac(sig, ts, body, shared_secret=secret)
    assert not ok2
    resp, code = err2
    assert code == 401
    assert "replay" in resp["error"].lower()
    print("  OK 2nd request blocked")


def test_replay_disabled_when_nonce_off():
    """enforce_nonce=False 면 재전송 허용."""
    print("\n== check_hmac: enforce_nonce=False → 재전송 허용 ==")
    from pkgsentinel.api.auth import check_hmac, _reset_nonce_cache
    from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign
    _reset_nonce_cache()
    secret = "test-no-nonce"
    body = b'{"x":1}'
    ts = int(time.time() * 1000)
    sig = f"sha256={hmac_sign(secret, ts, body)}"
    ok1, _ = check_hmac(sig, ts, body, shared_secret=secret,
                        enforce_nonce=False)
    ok2, _ = check_hmac(sig, ts, body, shared_secret=secret,
                        enforce_nonce=False)
    assert ok1 and ok2
    print("  OK")


def test_expired_timestamp_rejected():
    """5분 윈도 초과 → 401."""
    print("\n== check_hmac: timestamp 1시간 전 → 401 ==")
    from pkgsentinel.api.auth import check_hmac, _reset_nonce_cache
    from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign
    _reset_nonce_cache()
    secret = "s"
    body = b'{}'
    old_ts = int(time.time() * 1000) - 60 * 60 * 1000
    sig = f"sha256={hmac_sign(secret, old_ts, body)}"
    ok, err = check_hmac(sig, old_ts, body, shared_secret=secret)
    assert not ok
    resp, code = err
    assert code == 401
    print("  OK")


def test_different_signatures_different_nonces():
    """body 다른 → 다른 (ts, sig) → 둘 다 ok."""
    print("\n== check_hmac: 다른 body 두 개 → 둘 다 ok ==")
    from pkgsentinel.api.auth import check_hmac, _reset_nonce_cache
    from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign
    _reset_nonce_cache()
    secret = "s"
    ts = int(time.time() * 1000)
    body1 = b'{"x":1}'
    body2 = b'{"x":2}'
    sig1 = f"sha256={hmac_sign(secret, ts, body1)}"
    sig2 = f"sha256={hmac_sign(secret, ts, body2)}"
    ok1, _ = check_hmac(sig1, ts, body1, shared_secret=secret)
    ok2, _ = check_hmac(sig2, ts, body2, shared_secret=secret)
    assert ok1 and ok2
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
