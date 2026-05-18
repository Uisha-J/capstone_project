"""
Evidence / Verdict 데이터 모델.

모든 판정은 Evidence 리스트로만 설명되어야 한다.
점수(숫자) 기반 판정 금지. 항상 "어떤 TTP 매칭, 어떤 코드 위치, 어떤 LLM 판단" 형태로만 제공.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

# ───────────────────────── Enums ─────────────────────────

class Ecosystem(str, Enum):
    PYPI = "PyPI"
    NPM = "npm"


class AttackDimension(str, Enum):
    """Cerebro 논문 기준 4가지 공격 차원."""
    INFORMATION_READING = "INFORMATION_READING"
    ENCODING = "ENCODING"
    PAYLOAD_EXECUTION = "PAYLOAD_EXECUTION"
    DATA_TRANSMISSION = "DATA_TRANSMISSION"


class TTPSource(str, Enum):
    """근거로 인용하는 공신력 있는 프레임워크."""
    MITRE_ATTACK = "MITRE ATT&CK"
    MITRE_ATLAS = "MITRE ATLAS"
    OWASP_LLM = "OWASP LLM Top 10"
    OWASP_WEB = "OWASP Top 10"
    CWE = "CWE"
    GHSA = "GitHub Advisory"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class LLMVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    HIGH_RISK = "HIGH_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    AGENTIC = "AGENTIC"               # AISLOPSQ: agentic-by-design, opt-in 필요
    CLEAN = "CLEAN"
    ERROR = "ERROR"                   # Stage 2/4/5 중 하나 이상 실패
    CANNOT_ANALYZE = "CANNOT_ANALYZE"  # 레지스트리 미등록


# ───────────────────── 버전 차이 정보 ─────────────────────

@dataclass
class VersionDiffInfo:
    """Stage 3 결과 — 이전 버전 대비 신규 API 호출 정보."""
    compared_versions: list[str]       # 비교 대상 이전 버전들 (N-1, N-3, N-5)
    new_apis: list[str]                # 새로 등장한 API 호출
    risk_classification: Severity      # 변화의 위험도 (새 Network+Encode+Execute 조합 등)
    details: str                       # 인간이 읽을 설명

    def to_dict(self) -> dict:
        return {
            "compared_versions": self.compared_versions,
            "new_apis": self.new_apis,
            "risk_classification": self.risk_classification.value,
            "details": self.details,
        }


# ───────────────────── TTP 엔트리 (지식 DB) ─────────────────────

@dataclass
class TTPEntry:
    """지식 DB에 저장되는 공식 TTP 엔트리. 판정의 근거가 된다."""
    ttp_id: str                        # "T1059.006"
    ttp_name: str                      # "Python"
    source: TTPSource
    kb_version: str                    # 프레임워크 버전 (예: "MITRE ATT&CK v15.1")
    description: str                   # 공식 설명
    detection_hints: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    url: str = ""
    embedding: list[float] | None = None  # Sentence-Transformer 벡터
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict:
        d = {
            "ttp_id": self.ttp_id,
            "ttp_name": self.ttp_name,
            "source": self.source.value,
            "kb_version": self.kb_version,
            "description": self.description,
            "detection_hints": self.detection_hints,
            "mitigations": self.mitigations,
            "severity": self.severity.value,
            "url": self.url,
            "collected_at": self.collected_at.isoformat(),
        }
        # embedding은 크므로 선택적 직렬화
        if self.embedding is not None:
            d["embedding"] = self.embedding
        return d

    @classmethod
    def from_dict(cls, d: dict) -> TTPEntry:
        collected_raw = d.get("collected_at")
        if isinstance(collected_raw, str) and collected_raw:
            try:
                collected = datetime.fromisoformat(collected_raw)
            except ValueError:
                collected = datetime.now(UTC)
        else:
            collected = datetime.now(UTC)
        return cls(
            ttp_id=d["ttp_id"],
            ttp_name=d["ttp_name"],
            source=TTPSource(d["source"]),
            kb_version=d.get("kb_version", ""),
            description=d.get("description", ""),
            detection_hints=list(d.get("detection_hints", [])),
            mitigations=list(d.get("mitigations", [])),
            severity=Severity(d.get("severity", Severity.MEDIUM.value)),
            url=d.get("url", ""),
            embedding=d.get("embedding"),
            collected_at=collected,
        )


# ───────────────────────── Evidence ─────────────────────────

@dataclass
class Evidence:
    """
    판정 근거 단위.

    하나의 Evidence는 "코드 어느 위치의 어떤 행위 시퀀스가
    어떤 공식 TTP와 매칭되며 LLM이 어떻게 판단했는가"를 완결되게 설명한다.
    """

    # ── 1) 어디서 발견했는가 ─────────────
    file_path: str                          # "setup.py"
    line_start: int
    line_end: int
    code_snippet: str                       # 실제 코드 원문

    # ── 2) 무엇이 의심스러운가 (행위 기반) ─
    behavior_sequence: list[str]            # ["os.environ.get", "base64.b64encode", "requests.post"]
    attack_dimensions: list[AttackDimension]

    # ── 3) 공신력 있는 근거 매핑 (지식 DB) ─
    ttp_id: str                             # "T1048.003"
    ttp_name: str
    ttp_source: TTPSource
    ttp_url: str
    vector_similarity: float                # 0.0~1.0 (코사인 유사도)
    ttp_severity: Severity                  # 매칭된 TTP의 심각도

    # ── 4) LLM 재검토 ─────────────────
    llm_verdict: LLMVerdict
    llm_reasoning: str
    llm_model: str                          # "claude-sonnet-4-5"

    # ── 5) 버전 변화 (해당 시) ─────────
    version_diff: VersionDiffInfo | None = None

    # ── 6) 종합 신뢰도 ────────────────
    confidence: float = 0.0                 # 0.0~1.0

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "behavior_sequence": self.behavior_sequence,
            "attack_dimensions": [d.value for d in self.attack_dimensions],
            "ttp_id": self.ttp_id,
            "ttp_name": self.ttp_name,
            "ttp_source": self.ttp_source.value,
            "ttp_url": self.ttp_url,
            "ttp_severity": self.ttp_severity.value,
            "vector_similarity": self.vector_similarity,
            "llm_verdict": self.llm_verdict.value,
            "llm_reasoning": self.llm_reasoning,
            "llm_model": self.llm_model,
            "version_diff": self.version_diff.to_dict() if self.version_diff else None,
            "confidence": self.confidence,
        }


# ───────────────────── 스테이지별 결과 (내부 전달용) ─────────────────────

@dataclass
class StageResult:
    """각 Stage의 성공/실패와 산출물."""
    stage: str                              # "stage_2_behavior_sequence" 등
    success: bool
    error: str | None = None
    payload: dict = field(default_factory=dict)


# ───────────────────────── AnalysisReport ─────────────────────────

@dataclass
class AnalysisReport:
    """최종 분석 결과. CLI/API 응답, 캐시 저장의 표준 형식."""
    package: str
    ecosystem: Ecosystem
    version: str
    analyzed_at: datetime

    verdict: Verdict
    evidence: list[Evidence] = field(default_factory=list)
    stage_results: list[StageResult] = field(default_factory=list)

    # 메타 정보 (참고용, 판정 근거 아님)
    package_meta: dict = field(default_factory=dict)

    # 실행 환경 정보
    engine_version: str = "2.0.0-alpha"
    kb_versions: dict = field(default_factory=dict)   # {"MITRE ATT&CK": "v15.1", ...}

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "ecosystem": self.ecosystem.value,
            "version": self.version,
            "analyzed_at": self.analyzed_at.isoformat(),
            "verdict": self.verdict.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "stage_results": [
                {"stage": s.stage, "success": s.success, "error": s.error}
                for s in self.stage_results
            ],
            "package_meta": self.package_meta,
            "engine_version": self.engine_version,
            "kb_versions": self.kb_versions,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ───────────────────── 샘플/팩토리 헬퍼 ─────────────────────

def empty_report(
    package: str,
    ecosystem: Ecosystem,
    version: str,
) -> AnalysisReport:
    """초기 리포트 (verdict는 나중에 채움)."""
    return AnalysisReport(
        package=package,
        ecosystem=ecosystem,
        version=version,
        analyzed_at=datetime.now(UTC),
        verdict=Verdict.CLEAN,  # 기본값. 파이프라인 종료 시 결정됨.
    )


__all__ = [
    "Ecosystem",
    "AttackDimension",
    "TTPSource",
    "Severity",
    "LLMVerdict",
    "Verdict",
    "VersionDiffInfo",
    "TTPEntry",
    "Evidence",
    "StageResult",
    "AnalysisReport",
    "empty_report",
]
