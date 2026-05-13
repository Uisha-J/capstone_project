"""인바운드 분석 API endpoint (#S1).

VSCode extension / CLI / CI 가 호출하는 *경량* 분석 요청. 서버 측에서:
  1) AnalysisCache (analyses 테이블) hit 검사 — 같은 (pkg, eco, version) +
     같은 engine_version + rules + kb 면 즉시 응답 (비용 0)
  2) cache miss 면 run_pipeline 실행 후 결과 캐싱 + 응답

요청 형식 (POST JSON):
  {
    "package": "evil-stealer",
    "ecosystem": "npm",
    "version": "0.0.1"            (선택; 없으면 latest 자동 resolve)
    "llm_mode": "stub" | "claude" (선택; 기본 stub — 클라이언트가 비용 통제)
  }

응답:
  {
    "ok": true,
    "verdict": "MALICIOUS" | "HIGH_RISK" | "SUSPICIOUS" | "CLEAN" | ...,
    "confidence": 0.0~1.0,
    "reasoning": "...",            (cache 시 cached_reasoning)
    "evidence_count": N,
    "evidence_summary": [          (상위 3개)
      {"file_path": "...", "ttp_id": "...", "ttp_name": "...", ...}
    ],
    "package_meta": {...},
    "cache": {"hit": bool, "reason": str, "cached_at": "..."},
    "elapsed_s": float,
  }

본 모듈은 *순수 함수* — Flask/FastAPI 같은 framework 독립. 호출자가 HTTP 어댑터.
"""
from __future__ import annotations

import time
from typing import Any

from ..schema import Ecosystem
from .auth import check_hmac


def handle_analyze(
    payload: dict,
    *,
    signature_header: str | None = None,
    timestamp_ms: int | None = None,
    raw_body: bytes | None = None,
    shared_secret: str | None = None,
) -> tuple[dict, int]:
    """경량 분석 endpoint — 캐시 우선.

    Args:
      payload: {"package", "ecosystem", "version", "llm_mode"}
      signature_header: HMAC sha256= 헤더 값 (Optional)
      timestamp_ms: X-AISLOPSQ-Timestamp (Optional)
      raw_body: 원본 body bytes — HMAC 검증용
      shared_secret: HMAC secret. None 이면 검증 skip (dev 모드)

    Returns:
      (response_dict, http_status_code)
    """
    # HMAC + replay 검증 (#S4)
    ok, err = check_hmac(signature_header, timestamp_ms, raw_body, shared_secret)
    if not ok:
        return err  # type: ignore[return-value]

    # 필수 필드
    pkg = (payload.get("package") or "").strip()
    eco_str = (payload.get("ecosystem") or "").strip()
    if not pkg or not eco_str:
        return ({"error": "package + ecosystem required"}, 400)
    try:
        ecosystem = Ecosystem(eco_str)
    except ValueError:
        return (
            {"error": f"unknown ecosystem: {eco_str} "
                      f"(supported: PyPI, npm)"},
            400,
        )

    version = (payload.get("version") or "").strip() or None
    llm_mode = (payload.get("llm_mode") or "stub").strip().lower()
    if llm_mode not in ("stub", "claude"):
        return ({"error": f"unknown llm_mode: {llm_mode}"}, 400)

    t0 = time.time()

    # 캐시 lookup — version 알려진 경우만. 모르면 stage 0 가 latest resolve.
    cache_result = None
    if version:
        try:
            from ..db.analysis_cache import AnalysisCache, CacheKey
            cache = AnalysisCache()
            key = CacheKey(
                package=pkg, ecosystem=ecosystem.value, version=version,
            )
            hit = cache.get(key)
            if hit.hit:
                cache_result = hit
        except Exception:
            # 캐시 사용 불가 — fallthrough to pipeline
            cache_result = None

    if cache_result and cache_result.report:
        rep = cache_result.report
        return ({
            "ok": True,
            "verdict": rep.get("verdict"),
            "confidence": _extract_top_confidence(rep),
            "reasoning": _extract_top_reasoning(rep),
            "evidence_count": len(rep.get("evidence", []) or []),
            "evidence_summary": _evidence_summary(rep),
            "package_meta": rep.get("package_meta") or {},
            "cache": {
                "hit": True,
                "reason": cache_result.reason,
                "cached_at": (cache_result.cache_row or {}).get("analyzed_at"),
            },
            "elapsed_s": round(time.time() - t0, 3),
        }, 200)

    # cache miss → pipeline 실행
    try:
        from ..pipeline import run_pipeline
        rep_obj = run_pipeline(
            package=pkg,
            ecosystem=ecosystem,
            version=version,
            llm_mode=llm_mode,
            use_cache=True,        # AnalysisCache 도 내부에서 put 수행
            force_rescan=False,
        )
        elapsed = round(time.time() - t0, 3)
        return ({
            "ok": True,
            "verdict": rep_obj.verdict.value,
            "confidence": _extract_top_confidence_from_obj(rep_obj),
            "reasoning": _extract_top_reasoning_from_obj(rep_obj),
            "evidence_count": len(rep_obj.evidence or []),
            "evidence_summary": _evidence_summary_from_obj(rep_obj),
            "package_meta": rep_obj.package_meta or {},
            "cache": {"hit": False, "reason": "fresh pipeline run"},
            "elapsed_s": elapsed,
        }, 200)
    except Exception as e:
        return ({
            "ok": False,
            "error": f"{type(e).__name__}: {str(e)[:200]}",
            "elapsed_s": round(time.time() - t0, 3),
        }, 500)


# ─────────────── 헬퍼: dict / Report 양쪽에서 evidence 요약 ───────────────

def _extract_top_confidence(rep: dict) -> float:
    ev = rep.get("evidence") or []
    if not ev:
        return 0.0
    confs = [e.get("confidence", 0.0) for e in ev if isinstance(e, dict)]
    return max(confs) if confs else 0.0


def _extract_top_confidence_from_obj(rep_obj) -> float:
    if not rep_obj.evidence:
        return 0.0
    return max(e.confidence for e in rep_obj.evidence)


def _extract_top_reasoning(rep: dict) -> str:
    ev = rep.get("evidence") or []
    for e in ev:
        r = e.get("llm_reasoning") or e.get("reasoning") or ""
        if r:
            return r[:500]
    summary = (rep.get("package_meta") or {}).get("advisory_summary", "")
    return summary[:500]


def _extract_top_reasoning_from_obj(rep_obj) -> str:
    for e in rep_obj.evidence or []:
        if e.llm_reasoning:
            return e.llm_reasoning[:500]
    return ""


def _evidence_summary(rep: dict) -> list[dict]:
    ev = rep.get("evidence") or []
    out: list[dict] = []
    for e in ev[:3]:
        if not isinstance(e, dict):
            continue
        out.append({
            "file_path": e.get("file_path"),
            "line_start": e.get("line_start"),
            "ttp_id": e.get("ttp_id"),
            "ttp_name": e.get("ttp_name"),
            "ttp_severity": e.get("ttp_severity"),
            "confidence": e.get("confidence"),
            "llm_verdict": e.get("llm_verdict"),
            "code_snippet": (e.get("code_snippet") or "")[:200],
        })
    return out


def _evidence_summary_from_obj(rep_obj) -> list[dict]:
    out: list[dict] = []
    for e in (rep_obj.evidence or [])[:3]:
        out.append({
            "file_path": e.file_path,
            "line_start": e.line_start,
            "ttp_id": e.ttp_id,
            "ttp_name": e.ttp_name,
            "ttp_severity": e.ttp_severity.value if e.ttp_severity else None,
            "confidence": e.confidence,
            "llm_verdict": e.llm_verdict.value if e.llm_verdict else None,
            "code_snippet": (e.code_snippet or "")[:200],
        })
    return out
