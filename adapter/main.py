"""
V1 Chrome / VS Code 확장 ↔ V2 pkgsentinel 엔진 FastAPI 어댑터.

엔드포인트:
  GET  /health             서비스 상태 + 엔진 정보
  POST /analyze            패키지명 리스트 → verdict 결과
  POST /parse-and-analyze  코드 블록 → import 추출 → verdict 결과
  GET  /verdict-legend     V1 프론트엔드용 레벨 정의 (디버깅)

환경변수:
  ANTHROPIC_API_KEY        Claude API 키 (llm_mode=claude 일 때)
  AISLOP_DB_KEY            SQLCipher 마스터 패스프레이즈
  AISLOP_LLM_MODE          stub | claude (기본: stub)
  AISLOP_INTEGRITY_MODE    fast | strict | paranoid (기본: strict)
  AISLOP_USE_CACHE         "true" | "false" (기본: true)
  AISLOP_ALLOWED_ORIGINS   CORS 허용 origin 콤마 구분 (기본: claude.ai/chatgpt/gemini)
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from pkgsentinel.pipeline import run_pipeline
from pkgsentinel.schema import Ecosystem, Verdict
from pkgsentinel.entrypoint.import_parser import parse_code

from adapter.closest_match import find_closest

# ─────────────── 설정 (env-driven) ───────────────

# LLM 모드 자동 결정:
#   - AISLOP_LLM_MODE 명시값 ("stub" / "claude") 있으면 그대로
#   - 명시 없거나 "auto" 면 ANTHROPIC_API_KEY 유효성으로 자동 선택
def _resolve_llm_mode() -> str:
    raw = (os.getenv("AISLOP_LLM_MODE") or "auto").strip().lower()
    if raw in ("stub", "claude"):
        return raw
    # auto / 빈값: API 키 존재 + 형식 유효(placeholder 아님)면 claude
    key = (os.getenv("ANTHROPIC_API_KEY") or "").strip()
    if key.startswith("sk-ant-") and len(key) > 30 and "..." not in key:
        return "claude"
    return "stub"

LLM_MODE = _resolve_llm_mode()
INTEGRITY_MODE = os.getenv("AISLOP_INTEGRITY_MODE", "strict") # fast|strict|paranoid
USE_CACHE = os.getenv("AISLOP_USE_CACHE", "true").lower() != "false"

# HMAC 인증 (선택): 비어 있으면 검증 X (개발 모드)
HMAC_SECRET = (os.getenv("AISLOP_HMAC_SECRET") or "").strip()
HMAC_TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000  # 5분 (replay 방지)

# 시작 로그
import sys
print(f"[Adapter] LLM_MODE={LLM_MODE} (auto-resolved from ANTHROPIC_API_KEY presence)",
      file=sys.stderr, flush=True)
print(f"[Adapter] HMAC auth: {'ENABLED' if HMAC_SECRET else 'disabled (no AISLOP_HMAC_SECRET)'}",
      file=sys.stderr, flush=True)

_DEFAULT_ORIGINS = (
    "https://claude.ai,https://a.claude.ai,"
    "https://chatgpt.com,https://gemini.google.com"
)
ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("AISLOP_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if o.strip()
]

# ─────────────── Verdict → V1 레벨 매핑 ───────────────
# V1 프론트엔드는 CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN 5단계를 인식하고
# 추가로 AGENTIC 을 별도 라벨로 표시 (langchain 등 정상 AI 라이브러리 오인 방지).

VERDICT_TO_LEVEL: dict[Verdict, str] = {
    Verdict.MALICIOUS:      "CRITICAL",
    Verdict.HIGH_RISK:      "HIGH",
    Verdict.SUSPICIOUS:     "MEDIUM",
    Verdict.AGENTIC:        "AGENTIC",     # 별도 라벨 — opt-in 필요
    Verdict.CLEAN:          "LOW",
    Verdict.CANNOT_ANALYZE: "CRITICAL",    # 등록 안 됨도 슬롭스쿼팅 강력 의심
    Verdict.ERROR:          "UNKNOWN",
}

# ─────────────── FastAPI 앱 ───────────────

app = FastAPI(
    title="Slop Detector — V2 Engine Adapter",
    version="2.1.0",
    description="V2 pkgsentinel 엔진을 V1 Chrome/VSCode 확장 호환 HTTP API 로 노출",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ─────────────── HMAC 인증 미들웨어 ───────────────
# 알고리즘: VSCode 익스텐션의 hmac.ts 와 동일 (byte-level)
#   msg = `${timestamp_ms}.` + body_bytes
#   sig = HMAC_SHA256(secret, msg).hex()
#   header: X-AISLOPSQ-Signature: sha256=<hex>
#           X-AISLOPSQ-Timestamp: <ms>
import hmac as _hmac_mod
import hashlib
import time as _time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class HMACAuthMiddleware(BaseHTTPMiddleware):
    """HMAC_SECRET 설정 시 모든 POST 요청에 X-AISLOPSQ-Signature 검증."""
    async def dispatch(self, request, call_next):
        if not HMAC_SECRET or request.method != "POST":
            return await call_next(request)
        # /health 같은 GET 은 통과. POST 만 검증.
        body = await request.body()
        sig_header = request.headers.get("X-AISLOPSQ-Signature", "")
        ts_header = request.headers.get("X-AISLOPSQ-Timestamp", "")
        if not sig_header.startswith("sha256=") or not ts_header:
            return JSONResponse(
                {"detail": "HMAC headers missing (X-AISLOPSQ-Signature/Timestamp)"},
                status_code=401,
            )
        try:
            ts = int(ts_header)
        except ValueError:
            return JSONResponse({"detail": "Invalid timestamp"}, status_code=401)
        now_ms = int(_time.time() * 1000)
        if abs(now_ms - ts) > HMAC_TIMESTAMP_TOLERANCE_MS:
            return JSONResponse(
                {"detail": "Timestamp out of range (>5min, possible replay)"},
                status_code=401,
            )
        expected = sig_header[len("sha256="):]
        msg = f"{ts}.".encode("utf-8") + body
        computed = _hmac_mod.new(
            HMAC_SECRET.encode("utf-8"), msg, hashlib.sha256
        ).hexdigest()
        if not _hmac_mod.compare_digest(expected, computed):
            return JSONResponse({"detail": "Invalid HMAC signature"}, status_code=401)
        # body 를 endpoint 가 다시 읽을 수 있게 receive 재구성
        async def _receive():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = _receive
        return await call_next(request)

app.add_middleware(HMACAuthMiddleware)


# ─────────────── 요청/응답 모델 ───────────────

class AnalyzeRequest(BaseModel):
    packages: List[str] = Field(..., description="분석할 패키지명 리스트")
    ecosystem: str = Field("PyPI", description="PyPI | npm")


class ParseAndAnalyzeRequest(BaseModel):
    filename: str = Field(..., description="언어 식별용 (예: main.py, package.json)")
    code: str = Field(..., description="코드 전체 텍스트")
    ecosystem: Optional[str] = Field(
        None, description="명시 안 하면 파일명/언어로 자동 추정"
    )


class TtpDetail(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    url: Optional[str] = None


class PackageResult(BaseModel):
    # ─── P0 필수 ─────────────────────────────────
    package: str
    ecosystem: str
    level: str                  # V1 호환 레벨
    verdict: str                # V2 raw verdict
    is_agentic: bool = False    # 별도 플래그
    evidence_count: int = 0
    reasons: List[str] = []
    ttp_ids: List[Optional[str]] = []

    # ─── P1 보강 (V2 evidence/report 데이터) ─────
    confidence: float = 0.0     # evidence confidence 평균 (0.0~1.0)
    version: Optional[str] = None
    engine_version: Optional[str] = None
    analyzed_at: Optional[str] = None  # ISO 8601
    ttp_details: List[TtpDetail] = []
    code_snippets: List[str] = []

    # ─── D3 추가: typo-squat 후보 ────────────────
    closest_match: Optional[str] = None  # 환각/오타 의심 시 추정 정상 패키지명

    error: Optional[str] = None


# ─────────────── 헬퍼 ───────────────

def _ecosystem_of(value: Optional[str], language: Optional[str] = None) -> Ecosystem:
    """문자열 → Ecosystem enum. language 힌트로 보정."""
    if value:
        v = value.lower()
        if v in ("npm", "node", "node.js", "nodejs"):
            return Ecosystem.NPM
        if v in ("pypi", "python"):
            return Ecosystem.PYPI
    if language == "javascript":
        return Ecosystem.NPM
    return Ecosystem.PYPI


def _safe_attr(obj: Any, name: str, default: Any = None) -> Any:
    """V2 엔진 데이터 클래스에서 안전하게 속성 추출 (없으면 default)."""
    try:
        value = getattr(obj, name, default)
        return value if value is not None else default
    except Exception:
        return default


def _iso(value: Any) -> Optional[str]:
    """datetime/str → ISO 8601 문자열."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _avg_confidence(evidence_list: list) -> float:
    """evidence 들의 confidence 평균. 비어있으면 0."""
    if not evidence_list:
        return 0.0
    scores = [
        float(_safe_attr(e, "confidence", 0.0) or 0.0)
        for e in evidence_list
    ]
    scores = [s for s in scores if s > 0]
    return round(sum(scores) / len(scores), 3) if scores else 0.0


def _build_ttp_details(evidence_list: list, max_count: int = 5) -> List[TtpDetail]:
    """evidence 에서 TTP 상세 (id/name/severity/url/source) 추출."""
    out: List[TtpDetail] = []
    seen_ids = set()
    for e in evidence_list:
        ttp_id = _safe_attr(e, "ttp_id")
        # 중복 ID 스킵 (단, ID 없는 항목은 통과)
        if ttp_id and ttp_id in seen_ids:
            continue
        if ttp_id:
            seen_ids.add(ttp_id)

        # 의미 있는 항목만 (id 또는 name 중 하나는 있어야)
        ttp_name = _safe_attr(e, "ttp_name")
        if not ttp_id and not ttp_name:
            continue

        out.append(TtpDetail(
            id=ttp_id,
            name=ttp_name,
            severity=_safe_attr(e, "ttp_severity"),
            source=_safe_attr(e, "ttp_source"),
            url=_safe_attr(e, "ttp_url"),
        ))
        if len(out) >= max_count:
            break
    return out


def _build_code_snippets(evidence_list: list, max_count: int = 2) -> List[str]:
    """evidence 에서 의심 코드 스니펫 (상위 N개) 추출."""
    out: List[str] = []
    for e in evidence_list:
        snippet = _safe_attr(e, "code_snippet")
        if snippet and isinstance(snippet, str):
            # 너무 긴 건 자름 (어댑터 응답 크기 제어)
            out.append(snippet[:500])
            if len(out) >= max_count:
                break
    return out


# Verdict 중 closest_match 계산이 의미 있는 것들
# (정상/오류는 후보 제시할 필요 없음)
_RISKY_VERDICTS = {
    Verdict.MALICIOUS,
    Verdict.HIGH_RISK,
    Verdict.SUSPICIOUS,
    Verdict.CANNOT_ANALYZE,
}


def _analyze_single(package: str, ecosystem: Ecosystem) -> PackageResult:
    try:
        report = run_pipeline(
            package=package,
            ecosystem=ecosystem,
            llm_mode=LLM_MODE,
            integrity_mode=INTEGRITY_MODE,
            use_cache=USE_CACHE,
            force_rescan=False,
            use_threat_filter=True,
        )

        evidence_list = list(_safe_attr(report, "evidence", []) or [])

        # closest_match: 위험 verdict 일 때만 계산
        closest: Optional[str] = None
        if report.verdict in _RISKY_VERDICTS:
            try:
                closest = find_closest(package, ecosystem.value)
            except Exception:
                pass  # closest 계산 실패는 분석 결과를 막지 않음

        return PackageResult(
            package=package,
            ecosystem=ecosystem.value,
            level=VERDICT_TO_LEVEL.get(report.verdict, "UNKNOWN"),
            verdict=report.verdict.value,
            is_agentic=(report.verdict == Verdict.AGENTIC),
            evidence_count=len(evidence_list),
            reasons=[
                (_safe_attr(e, "llm_reasoning", "") or "")[:200]
                for e in evidence_list[:3]
                if _safe_attr(e, "llm_reasoning")
            ],
            ttp_ids=[_safe_attr(e, "ttp_id") for e in evidence_list[:5] if _safe_attr(e, "ttp_id")],

            # ─── P1 보강 ─────────────────────────────────
            confidence=_avg_confidence(evidence_list),
            version=_safe_attr(report, "version"),
            engine_version=_safe_attr(report, "engine_version"),
            analyzed_at=_iso(_safe_attr(report, "analyzed_at")),
            ttp_details=_build_ttp_details(evidence_list),
            code_snippets=_build_code_snippets(evidence_list),

            # ─── D3 ──────────────────────────────────────
            closest_match=closest,
        )
    except Exception as e:
        return PackageResult(
            package=package,
            ecosystem=ecosystem.value,
            level="UNKNOWN",
            verdict="ERROR",
            error=f"{type(e).__name__}: {str(e)[:200]}",
        )


# ─────────────── 엔드포인트 ───────────────

@app.get("/health")
def health():
    return {
        "ok": True,
        "engine": "pkgsentinel V2",
        "adapter_version": "2.1.0",
        "llm_mode": LLM_MODE,
        "integrity_mode": INTEGRITY_MODE,
        "cache": USE_CACHE,
    }


@app.get("/verdict-legend")
def verdict_legend():
    """V1 프론트엔드 디버깅용 — verdict ↔ level 매핑 확인."""
    return {
        "mapping": {v.value: lvl for v, lvl in VERDICT_TO_LEVEL.items()},
        "notes": {
            "AGENTIC": "AI 에이전트 패키지 (langchain 등). 악성 아님, opt-in 필요.",
            "CANNOT_ANALYZE": "레지스트리에 없음 — 슬롭스쿼팅 강력 의심.",
        },
    }


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """패키지명 리스트 → verdict 결과."""
    if not req.packages:
        raise HTTPException(400, "packages 가 비었습니다")
    eco = _ecosystem_of(req.ecosystem)
    results = [_analyze_single(name, eco) for name in req.packages]
    return {"results": [r.dict() for r in results]}


# ─────────────── VSCode 익스텐션 호환 endpoint ───────────────
# pkgsentinel-vscode 0.1.0 의 spec (단일 패키지 입출력):
#   POST /api/v1/analyze
#   IN:  {"package": "torch", "ecosystem": "pypi", "llm_mode": "stub", "version"?: "..."}
#   OUT: {"ok": bool, "verdict": MALICIOUS|HIGH_RISK|SUSPICIOUS|CLEAN|UNKNOWN,
#         "confidence": float, "reasoning": str, "evidence_count": int,
#         "evidence_summary": [...], "cache"?: {hit, reason}, "elapsed_s": float}

class VSCodeAnalyzeRequest(BaseModel):
    package: str
    ecosystem: Optional[str] = "pypi"
    llm_mode: Optional[str] = None  # 무시 (서버 측 LLM_MODE 사용)
    version: Optional[str] = None

# Adapter level (CRITICAL/HIGH/MEDIUM/AGENTIC/LOW/UNKNOWN)
# → VSCode verdict (MALICIOUS/HIGH_RISK/SUSPICIOUS/CLEAN/UNKNOWN) 매핑
_LEVEL_TO_VSCODE_VERDICT = {
    "CRITICAL":   "MALICIOUS",
    "HIGH":       "HIGH_RISK",
    "MEDIUM":     "SUSPICIOUS",
    "AGENTIC":    "SUSPICIOUS",   # 안내성 의심 (opt-in 권장)
    "LOW":        "CLEAN",
    "UNKNOWN":    "UNKNOWN",
}

@app.post("/api/v1/analyze")
def analyze_v1(req: VSCodeAnalyzeRequest):
    """VSCode 익스텐션 호환 — 단일 패키지 분석 + spec 변환."""
    import time as _t
    if not req.package or not req.package.strip():
        raise HTTPException(400, "package 가 비었습니다")
    started = _t.time()
    eco = _ecosystem_of(req.ecosystem or "pypi")
    pkg_result = _analyze_single(req.package.strip(), eco)
    d = pkg_result.dict()
    level = d.get("level", "UNKNOWN")
    verdict = _LEVEL_TO_VSCODE_VERDICT.get(level, "UNKNOWN")

    # evidence_summary 구성 (ttp_details + code_snippets 결합)
    evidence_summary = []
    ttp_details = d.get("ttp_details") or []
    snippets = d.get("code_snippets") or []
    for i, ttp in enumerate(ttp_details[:10]):
        evidence_summary.append({
            "ttp_id": ttp.get("id"),
            "ttp_name": ttp.get("name"),
            "ttp_severity": ttp.get("severity"),
            "confidence": d.get("confidence"),
            "code_snippet": snippets[i] if i < len(snippets) else None,
        })

    reasoning_parts = []
    if d.get("verdict") == "CANNOT_ANALYZE":
        reasoning_parts.append("패키지가 PyPI/npm 레지스트리에 등록되지 않음 — 슬롭스쿼팅 강력 의심")
    if d.get("closest_match"):
        reasoning_parts.append(f"추정 정상 패키지: {d['closest_match']}")
    reasoning_parts.extend((d.get("reasons") or [])[:5])

    return {
        "ok": True,
        "verdict": verdict,
        "confidence": d.get("confidence", 0.0),
        "reasoning": " | ".join(reasoning_parts) if reasoning_parts else "",
        "evidence_count": d.get("evidence_count", 0),
        "evidence_summary": evidence_summary,
        "cache": {"hit": False},  # 어댑터는 캐시 X (엔진 측에서 처리)
        "elapsed_s": round(_t.time() - started, 3),
    }


# ─────────────── VSCode 호환 health alias ───────────────
@app.get("/healthz")
def healthz():
    """VSCode 익스텐션용 health alias (/health 와 동일)."""
    return health()


@app.post("/parse-and-analyze")
def parse_and_analyze(req: ParseAndAnalyzeRequest):
    """
    코드 블록 → import 추출 → 각 패키지 verdict 분석.

    Chrome 확장이 AI 응답의 코드 블록을 감지하면 이 엔드포인트를 호출.
    """
    if not req.code.strip():
        raise HTTPException(400, "code 가 비었습니다")

    parsed = parse_code(req.filename, req.code)
    # static + dynamic 합집합 (중복 제거)
    all_pkgs = sorted(set(parsed.packages) | set(parsed.dynamic_packages))

    if not all_pkgs:
        return {
            "filename": req.filename,
            "language": parsed.language,
            "parse_method": parsed.parse_method,
            "results": [],
            "note": "import 가 발견되지 않음",
        }

    eco = _ecosystem_of(req.ecosystem, language=parsed.language)
    results = [_analyze_single(name, eco) for name in all_pkgs]

    return {
        "filename": req.filename,
        "language": parsed.language,
        "parse_method": parsed.parse_method,
        "ecosystem": eco.value,
        "static_packages": parsed.packages,
        "dynamic_packages": parsed.dynamic_packages,
        "results": [r.dict() for r in results],
    }
