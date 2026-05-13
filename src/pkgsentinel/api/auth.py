"""#S4 — HMAC auth 통합 헬퍼.

문제 의식:
  api/analyze.py, api/iocs_export.py, api/runtime_alert.py 가 모두
  동일한 4줄짜리 HMAC 검증 boiler-plate 를 가지고 있음:

      if shared_secret is not None:
          if signature_header is None or timestamp_ms is None or raw_body is None:
              return ({"error": "..."}, 400)
          if not hmac_verify(...):
              return ({"error": "..."}, 401)

  + webhook_sink.hmac_verify 는 *timestamp 윈도* 만 검사 — 동일 윈도 안의
    재전송 (replay) 은 막지 못함. 동일 (timestamp, signature) 가 같은
    윈도 내에서 두 번째 도착하면 거부해야 함.

본 모듈:
  - check_hmac(): 위 boiler-plate 를 단 1줄로 압축
  - 5분 윈도 + nonce LRU 캐시 (in-memory) → replay 도 차단
  - dev 모드 (shared_secret=None) 면 즉시 ok=True

엔드포인트는 본 헬퍼 한 줄로 인증:

    ok, err = check_hmac(signature_header, timestamp_ms, raw_body, shared_secret)
    if not ok:
        return err   # (dict, http_code)
    # 인증 통과 — 비즈니스 로직 진행
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict

from ..realtime.sinks.webhook_sink import hmac_verify


# ─────────────── replay nonce 캐시 ───────────────

# (timestamp_ms, signature_hex) → seen_at_epoch_s
# 5분 윈도 + 약간 여유 → 6분 TTL. 메모리 상한 8192 entry (LRU).
_NONCE_CACHE: OrderedDict[tuple[int, str], float] = OrderedDict()
_NONCE_LOCK = threading.Lock()
_NONCE_MAX = 8192
_NONCE_TTL_S = 360


def _nonce_seen(timestamp_ms: int, signature_hex: str) -> bool:
    """이미 본 (timestamp, signature) 면 True. 아니면 기록하고 False."""
    key = (int(timestamp_ms), str(signature_hex))
    now = time.time()
    with _NONCE_LOCK:
        # 만료 청소 — head 부터 TTL 초과 제거
        while _NONCE_CACHE:
            oldest_key = next(iter(_NONCE_CACHE))
            if now - _NONCE_CACHE[oldest_key] > _NONCE_TTL_S:
                _NONCE_CACHE.popitem(last=False)
            else:
                break
        # LRU 상한
        while len(_NONCE_CACHE) >= _NONCE_MAX:
            _NONCE_CACHE.popitem(last=False)
        if key in _NONCE_CACHE:
            # touch (move to end) for accurate LRU — 이미 본 nonce
            _NONCE_CACHE.move_to_end(key)
            return True
        _NONCE_CACHE[key] = now
        return False


def _reset_nonce_cache() -> None:
    """테스트 전용 — 캐시 초기화."""
    with _NONCE_LOCK:
        _NONCE_CACHE.clear()


# ─────────────── 통합 인증 체크 ───────────────

def check_hmac(
    signature_header: str | None,
    timestamp_ms: int | None,
    raw_body: bytes | None,
    shared_secret: str | None,
    *,
    enforce_nonce: bool = True,
) -> tuple[bool, tuple[dict, int] | None]:
    """endpoint 공용 HMAC + replay 검증.

    Args:
      signature_header: "sha256=<hex>" 형식
      timestamp_ms:     X-AISLOPSQ-Timestamp 값
      raw_body:         원본 body bytes
      shared_secret:    None 이면 dev 모드 — 검증 skip
      enforce_nonce:    True (기본) 면 같은 (ts, sig) 재전송 차단

    Returns:
      (ok, err) — ok True 면 err 는 None. ok False 면 err 가 (resp, code).
    """
    if shared_secret is None:
        return True, None
    if signature_header is None or timestamp_ms is None or raw_body is None:
        return False, ({"error": "signature/timestamp/body required for HMAC"}, 400)
    if not hmac_verify(shared_secret, timestamp_ms, raw_body, signature_header):
        return False, ({"error": "invalid signature or replay window expired"}, 401)
    # signature 추출 + nonce 검사
    sig_hex = signature_header.split("=", 1)[-1] if "=" in signature_header \
        else signature_header
    if enforce_nonce and _nonce_seen(timestamp_ms, sig_hex):
        return False, ({"error": "replay detected (nonce already seen)"}, 401)
    return True, None
