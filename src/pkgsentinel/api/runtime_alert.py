"""인바운드 webhook — runtime alert (Falco/Tetragon/Wazuh) 수신.

흐름:
  1) HMAC-SHA256 검증 (우리 기존 webhook_sink 의 hmac_sign 과 같은 알고리즘)
  2) source 별 event 파싱 → ParsedEvent
  3) DB 적재 (RuntimeIntelStore.record_observation)
  4) IOC 추출 + upsert + auto_promote
  5) 패턴 추출 — novel 이면 룰 draft 생성
  6) (선택) 패키지 재평가 trigger
  7) 응답 — enriched verdict + IOC 수

본 모듈은 *순수 함수* — Flask/FastAPI 같은 web framework 에 독립. 호출자가
HTTP 어댑터 작성.
"""
from __future__ import annotations

import json
from typing import Any

from ..db.runtime_intel import (
    LearnedIOC,
    LearnedRule,
    RuntimeIntelStore,
    RuntimeObservation,
)
from ..intel.extractor import (
    extract_iocs_from_event,
    extract_pattern_from_event,
    parse_event,
)
from ..realtime.sinks.webhook_sink import hmac_verify


def handle_runtime_alert(
    payload: dict,
    *,
    signature_header: str | None = None,
    timestamp_ms: int | None = None,
    raw_body: bytes | None = None,
    shared_secret: str | None = None,
    store: RuntimeIntelStore | None = None,
    enable_repipeline: bool = False,
) -> tuple[dict, int]:
    """Runtime alert 처리.

    Args:
      payload: source 파싱 후 dict. {"source": "falco", "event": {...}}
               형식이거나 source 가 top-level key 인 형태.
      signature_header: X-AISLOPSQ-Signature 헤더 값 (e.g. "sha256=...")
      timestamp_ms: X-AISLOPSQ-Timestamp 헤더 값 (epoch ms)
      raw_body: 원본 body bytes — HMAC 검증용
      shared_secret: HMAC 검증 secret. None 이면 검증 skip (dev 모드).
      store: RuntimeIntelStore 인스턴스. None 이면 default.
      enable_repipeline: True 면 run_pipeline 으로 재평가 시도.

    Returns:
      (response_dict, http_status_code)
    """
    # ── 1) HMAC 검증 (옵션) ──
    if shared_secret is not None:
        if signature_header is None or timestamp_ms is None \
                or raw_body is None:
            return ({"error": "signature/timestamp/body required for HMAC"},
                    400)
        if not hmac_verify(
            shared_secret, timestamp_ms, raw_body, signature_header,
        ):
            return ({"error": "invalid signature or replay"}, 401)

    # ── 2) source 결정 + event 파싱 ──
    # payload 가 {"source": "...", ...} 형태 또는 payload 안의 known top-level
    # key 로 추정.
    src = (payload.get("source") or "").lower() or _infer_source(payload)
    event_dict = payload.get("event") or payload
    parsed = parse_event(src, event_dict)
    # caller 가 enrichment 정보 첨부 가능
    parsed.package = parsed.package or payload.get("package")
    parsed.version = parsed.version or payload.get("version")
    parsed.ecosystem = parsed.ecosystem or payload.get("ecosystem")

    # ── 3) DB 적재 ──
    store = store or RuntimeIntelStore()
    obs = RuntimeObservation(
        received_at=payload.get("received_at") or _now_iso(),
        source=parsed.source,
        host=parsed.host,
        package=parsed.package,
        ecosystem=parsed.ecosystem,
        version=parsed.version,
        raw_event=event_dict,
        verdict_before=payload.get("verdict_before") or "UNKNOWN",
        mitigation=payload.get("mitigation"),
    )

    # 4) IOC + 패턴 추출
    iocs = extract_iocs_from_event(parsed)
    pattern = extract_pattern_from_event(parsed)
    obs.extracted_iocs = iocs
    obs.extracted_pattern = pattern

    obs_id = store.record_observation(obs)

    # 5) IOC upsert + auto promote
    pkg_at_ver = None
    if parsed.package:
        pkg_at_ver = f"{parsed.package}@{parsed.version or '*'}"
    promoted: list[int] = []
    for ioc in iocs:
        ioc_id = store.upsert_ioc(
            LearnedIOC(
                ioc_type=ioc["type"], value=ioc["value"],
                confidence=ioc.get("confidence", 0.5),
            ),
            observation_id=obs_id,
            package_at_version=pkg_at_ver,
        )
        if store.auto_promote(ioc_id):
            promoted.append(ioc_id)

    # 6) #L5 — 자동 룰 draft 생성 (가능한 모든 종류)
    from ..intel.rule_generator import generate_all_drafts
    rationale = (
        f"Auto-derived from runtime observation #{obs_id} "
        f"(source={parsed.source}, host={parsed.host}, "
        f"pkg={parsed.package}@{parsed.version})"
    )
    drafts = generate_all_drafts([obs_id], iocs, pattern, rationale)
    rule_draft_ids: list[int] = []
    for d in drafts:
        d.created_at = _now_iso()
        rule_draft_ids.append(store.record_rule_draft(d))

    # 6b) #L4 — attack_index live-update
    # learned IOC 와 promoted (high-confidence) IOC 를 in-memory 인덱스에 즉시 등록
    # 다음 분석부터 같은 IOC 발견 시 즉시 매치.
    _live_update_attack_index(iocs, parsed, promoted, obs_id)

    # 7) (선택) 재파이프라인 — 비용 발생 가능. 본 호출자가 명시적으로 켜야.
    verdict_after = obs.verdict_before
    if enable_repipeline and parsed.package and parsed.ecosystem and parsed.version:
        try:
            from ..pipeline import run_pipeline
            from ..schema import Ecosystem
            eco_enum = Ecosystem(parsed.ecosystem)
            rep = run_pipeline(
                parsed.package, eco_enum, parsed.version,
                llm_mode="stub",  # 기본 stub — 비용 0; 호출자 override 가능
            )
            verdict_after = rep.verdict.value
            store.update_verdict_after(obs_id, verdict_after)
        except Exception as e:
            verdict_after = f"REPIPELINE_ERROR: {e}"

    return ({
        "ok": True,
        "observation_id": obs_id,
        "source": parsed.source,
        "package": parsed.package,
        "iocs_recorded": len(iocs),
        "iocs_auto_promoted": len(promoted),
        "rule_draft_ids": rule_draft_ids,
        "verdict_before": obs.verdict_before,
        "verdict_after": verdict_after,
    }, 200)


# ─────────────── 내부 헬퍼 ───────────────

def _live_update_attack_index(
    iocs: list[dict],
    parsed,
    promoted: list[int],
    obs_id: int,
) -> None:
    """학습된 IOC 를 attack_index 의 in-memory 인덱스에 즉시 push.

    재시작 없이 다음 분석부터 같은 IOC 발견 시 매치 가능.
    실패 (인덱스 미로드 등) 는 graceful skip — 본 함수는 사이드 효과만.
    """
    try:
        from ..knowledge.attack_index import get_index
        idx = get_index()
    except Exception:
        return  # OSV/OSSF cache 안 깔린 환경 — graceful

    pkg_at_ver = None
    if parsed.package:
        pkg_at_ver = f"{parsed.package}@{parsed.version or '*'}"

    for ioc in iocs:
        try:
            idx.add_runtime_ioc(
                ioc["type"], ioc["value"],
                confidence=ioc.get("confidence", 0.5),
                associated_packages=[pkg_at_ver] if pkg_at_ver else None,
                source_observation_id=obs_id,
            )
        except Exception:
            continue


def _infer_source(payload: dict) -> str:
    """payload 의 top-level key 로 source 추정."""
    if "output_fields" in payload or "rule" in payload and isinstance(
        payload.get("output_fields"), dict,
    ):
        return "falco"
    if "process_kprobe" in payload or "ProcessKprobe" in payload:
        return "tetragon"
    if "syscheck" in payload and "agent" in payload:
        return "wazuh"
    return "manual"


def _now_iso() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
