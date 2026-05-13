"""학습된 IOC 클라이언트 push endpoint (#S2).

클라이언트 (VSCode extension / 다른 pkgsentinel 서버) 가 *최근 학습한 IOC*
fetch 할 때 사용. 증분 (since 파라미터) 또는 전체.

요청 형식 (GET / POST):
  GET /api/v1/iocs/export?status=approved&since=2026-05-13T00:00:00Z
  POST {"status": "approved", "since": "...", "ioc_type": "ip"}

응답:
  {
    "ok": true,
    "iocs": [
      {
        "id": 42,
        "type": "ip",
        "value": "185.143.223.5",
        "confidence": 0.95,
        "associated_packages": ["evil-stealer@0.0.1"],
        "first_seen": "...",
        "last_seen": "...",
        "status": "approved"
      },
      ...
    ],
    "count": N,
    "high_watermark": "..."   # 가장 최근 last_seen — 다음 호출 시 since 로 사용
  }

OSV-format export 는 #L6 (osv_export.py) — *공개 PR* 용. 본 endpoint 는
*client 실시간 push* 용 (network effect).
"""
from __future__ import annotations

from .auth import check_hmac


def handle_iocs_export(
    query: dict,
    *,
    signature_header: str | None = None,
    timestamp_ms: int | None = None,
    raw_body: bytes | None = None,
    shared_secret: str | None = None,
) -> tuple[dict, int]:
    """학습된 IOC export — 클라이언트 sync 용.

    Args:
      query: {"status", "since", "ioc_type", "min_confidence", "limit"}
        status:      "pending" | "approved" | "retired" — 기본 "approved"
        since:       ISO8601 — last_seen >= since 만 반환 (optional)
        ioc_type:    "ip" | "domain" | "sha256" | "path" | "syscall_chain"
        min_confidence: 0.0~1.0 — 기본 0.7
        limit:       기본 1000, 최대 10000

    Returns:
      (response_dict, http_status_code)
    """
    # HMAC + replay 검증 (#S4)
    ok, err = check_hmac(signature_header, timestamp_ms, raw_body, shared_secret)
    if not ok:
        return err  # type: ignore[return-value]

    status = (query.get("status") or "approved").strip()
    ioc_type = (query.get("ioc_type") or "").strip() or None
    since = (query.get("since") or "").strip() or None
    try:
        min_confidence = float(query.get("min_confidence", 0.7))
    except (TypeError, ValueError):
        min_confidence = 0.7
    try:
        limit = min(int(query.get("limit", 1000)), 10000)
    except (TypeError, ValueError):
        limit = 1000

    if status not in ("pending", "approved", "retired"):
        return ({"error": f"unknown status: {status}"}, 400)

    try:
        from ..db.runtime_intel import RuntimeIntelStore
        store = RuntimeIntelStore()
        iocs = store.list_iocs(
            status=status, ioc_type=ioc_type,
            min_confidence=min_confidence, limit=limit,
        )
    except Exception as e:
        return ({"error": f"store unavailable: {e}"}, 500)

    # since 필터 — Python 측에서 처리 (DB index 가 status/confidence 만)
    if since:
        iocs = [i for i in iocs if (i.last_seen or "") >= since]

    out = [
        {
            "id": i.id,
            "type": i.ioc_type,
            "value": i.value,
            "confidence": i.confidence,
            "observation_count": i.observation_count,
            "first_seen": i.first_seen,
            "last_seen": i.last_seen,
            "associated_packages": i.associated_packages,
            "status": i.status,
        }
        for i in iocs
    ]

    # high_watermark — 다음 호출에서 since 로 사용 가능
    high = max((i.last_seen or "" for i in iocs), default="")

    return ({
        "ok": True,
        "iocs": out,
        "count": len(out),
        "high_watermark": high,
        "filter": {
            "status": status, "ioc_type": ioc_type,
            "min_confidence": min_confidence,
            "since": since, "limit": limit,
        },
    }, 200)
