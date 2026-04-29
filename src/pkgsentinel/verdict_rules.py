"""
Verdict 결정 규칙.

설계 원칙:
- Evidence 리스트와 스테이지 결과만으로 결정.
- 패키지 나이 / 인기도 / 다운로드 수 일절 참조하지 않음.
- 부분 판정 금지: Stage 2/4/5 중 하나라도 실패하면 ERROR.

LLM 처리 정책:
- **BENIGN LLM verdict 는 weak TTP 신호 (similarity 0.70~0.85, severity LOW)
  를 덮어쓴다.** LLM 이 정상으로 본 약한 매칭은 SUSPICIOUS 로 승격되지 않는다.
- 강한 매칭 (similarity ≥ 0.85, severity ≠ LOW) 은 LLM verdict 와 무관하게
  HIGH_RISK / MALICIOUS 분기로 진입.

판정 규칙 테이블 (설계 문서 3장과 일치)

    MALICIOUS    : high-severity TTP ≥ 1 AND LLM malicious AND avg confidence ≥ 0.85
    HIGH_RISK    : (TTP match ≥ 1 OR version_diff critical)
                       AND LLM in {suspicious, malicious}
    SUSPICIOUS   : weak TTP match (LLM ≠ BENIGN) OR version_diff any
                       OR LLM-only suspicious (confidence ≥ 0.5)
    CLEAN        : all stages passed AND evidence list empty
                       OR weak TTP + LLM=BENIGN (BENIGN overrides)
    ERROR        : Stage 2/4/5 중 하나 이상 실패
    CANNOT_ANALYZE : Stage 0에서 레지스트리 미등록 확정
"""
from __future__ import annotations

from collections.abc import Iterable

from .schema import (
    Evidence,
    LLMVerdict,
    Severity,
    StageResult,
    Verdict,
)

# ─────────────────────── 설정 상수 ───────────────────────

REQUIRED_STAGES_FOR_JUDGMENT = {
    "stage_2_behavior_sequence",
    "stage_4_ttp_matching",
    "stage_5_llm_review",
}

MALICIOUS_CONFIDENCE_THRESHOLD = 0.85

# 강 매칭 임계값 (Stage 4에서도 사용)
STRONG_MATCH_SIMILARITY = 0.85
WEAK_MATCH_SIMILARITY = 0.70


# ─────────────────────── 판정 헬퍼 ───────────────────────

def _all_required_stages_passed(stage_results: Iterable[StageResult]) -> bool:
    """Stage 2, 4, 5가 모두 성공했는지 확인."""
    passed = {s.stage for s in stage_results if s.success}
    return REQUIRED_STAGES_FOR_JUDGMENT.issubset(passed)


def _any_stage_failed(stage_results: Iterable[StageResult]) -> bool:
    """필수 스테이지 중 실패한 게 있는지."""
    for s in stage_results:
        if s.stage in REQUIRED_STAGES_FOR_JUDGMENT and not s.success:
            return True
    return False


def _has_high_severity_ttp(evidence: Iterable[Evidence]) -> bool:
    return any(e.ttp_severity == Severity.HIGH for e in evidence)


def _has_any_strong_ttp_match(evidence: Iterable[Evidence]) -> bool:
    """LLM 이 BENIGN 이 아닌 evidence 만 실제 매칭으로 간주."""
    return any(
        e.vector_similarity >= STRONG_MATCH_SIMILARITY
        and e.llm_verdict != LLMVerdict.BENIGN
        and e.ttp_severity != Severity.LOW
        for e in evidence
    )


def _has_any_ttp_match(evidence: Iterable[Evidence]) -> bool:
    return any(
        e.vector_similarity >= WEAK_MATCH_SIMILARITY
        and e.llm_verdict != LLMVerdict.BENIGN
        for e in evidence
    )


def _any_llm_malicious(evidence: Iterable[Evidence]) -> bool:
    return any(e.llm_verdict == LLMVerdict.MALICIOUS for e in evidence)


def _any_llm_suspicious_or_worse(evidence: Iterable[Evidence]) -> bool:
    """confidence 0.5 이상 의심도 있는 evidence만 고려."""
    return any(
        e.llm_verdict in (LLMVerdict.SUSPICIOUS, LLMVerdict.MALICIOUS)
        and e.confidence >= 0.5
        for e in evidence
    )


def _any_version_diff_critical(evidence: Iterable[Evidence]) -> bool:
    return any(
        e.version_diff is not None
        and e.version_diff.risk_classification == Severity.HIGH
        for e in evidence
    )


def _any_version_diff(evidence: Iterable[Evidence]) -> bool:
    """LOW 이상의 위험이 있는 version diff만 카운트."""
    return any(
        e.version_diff is not None
        and e.version_diff.risk_classification != Severity.LOW
        for e in evidence
    )


def _avg_confidence(evidence: Iterable[Evidence]) -> float:
    items = list(evidence)
    if not items:
        return 0.0
    return sum(e.confidence for e in items) / len(items)


# ─────────────────────── 메인 결정 함수 ───────────────────────

def decide_verdict(
    evidence: list[Evidence],
    stage_results: list[StageResult],
    registry_found: bool = True,
) -> Verdict:
    """
    Evidence + Stage 결과 기반 최종 Verdict 결정.

    순서가 중요:
      1. 레지스트리 미등록이면 즉시 CANNOT_ANALYZE
      2. 필수 스테이지 실패 시 ERROR
      3. Evidence 없고 모두 성공 → CLEAN
      4. 심각도 규칙 순차 평가
    """
    # 1. 레지스트리 미등록
    if not registry_found:
        return Verdict.CANNOT_ANALYZE

    # 2. 필수 스테이지 실패
    if _any_stage_failed(stage_results):
        return Verdict.ERROR

    # 3. 모든 스테이지 통과 후 Evidence 없음 → CLEAN
    if not evidence:
        if _all_required_stages_passed(stage_results):
            return Verdict.CLEAN
        return Verdict.ERROR

    # 4. Evidence 있음 → 규칙 적용

    # MALICIOUS: 가장 엄격
    if (
        _has_high_severity_ttp(evidence)
        and _any_llm_malicious(evidence)
        and _avg_confidence(evidence) >= MALICIOUS_CONFIDENCE_THRESHOLD
    ):
        return Verdict.MALICIOUS

    # HIGH_RISK
    if (
        (_has_any_strong_ttp_match(evidence) or _any_version_diff_critical(evidence))
        and _any_llm_suspicious_or_worse(evidence)
    ):
        return Verdict.HIGH_RISK

    # SUSPICIOUS
    if (
        _has_any_ttp_match(evidence)
        or _any_version_diff(evidence)
        or _any_llm_suspicious_or_worse(evidence)
    ):
        return Verdict.SUSPICIOUS

    # 그 외 → CLEAN (Evidence가 있더라도 약한 근거만 있을 때)
    return Verdict.CLEAN


# 자체 테스트 (sanity check) 는 tests/test_verdict_rules.py 로 이관됨.
