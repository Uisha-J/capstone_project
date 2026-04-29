"""
verdict_rules.decide_verdict() 단위 테스트.

기존 verdict_rules.py 의 __main__ 블록의 sanity check 를 pytest 로 이관 +
정책 docstring 의 6 verdict 상태를 모두 커버:
    MALICIOUS / HIGH_RISK / SUSPICIOUS / CLEAN / ERROR / CANNOT_ANALYZE

특히 직전 __main__ 의 'weak' 케이스가 SUSPICIOUS 를 기대했지만 실제 구현은
CLEAN 을 반환하던 모순(audit T-1) 을 정책에 맞춰 재정의:
    "BENIGN LLM verdict 는 weak TTP 신호를 덮어쓴다."
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import (
    AttackDimension,
    Evidence,
    LLMVerdict,
    Severity,
    StageResult,
    TTPSource,
    Verdict,
)
from pkgsentinel.verdict_rules import (
    REQUIRED_STAGES_FOR_JUDGMENT,
    decide_verdict,
)


# ─────────────── 헬퍼 ───────────────

def _all_passed_stages() -> list[StageResult]:
    return [StageResult(stage=s, success=True) for s in REQUIRED_STAGES_FOR_JUDGMENT]


def _make_evidence(
    *,
    similarity: float,
    severity: Severity,
    llm_verdict: LLMVerdict,
    confidence: float,
    ttp_id: str = "T1027",
    ttp_name: str = "Generic",
    file_path: str = "x.py",
) -> Evidence:
    return Evidence(
        file_path=file_path,
        line_start=1,
        line_end=1,
        code_snippet="",
        behavior_sequence=[],
        attack_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
        ttp_id=ttp_id,
        ttp_name=ttp_name,
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url="https://attack.mitre.org/",
        vector_similarity=similarity,
        ttp_severity=severity,
        llm_verdict=llm_verdict,
        llm_reasoning="test fixture",
        llm_model="test",
        confidence=confidence,
    )


# ─────────────── 1. CANNOT_ANALYZE ───────────────

def test_cannot_analyze_when_registry_not_found():
    assert decide_verdict([], [], registry_found=False) == Verdict.CANNOT_ANALYZE


# ─────────────── 2. ERROR ───────────────

def test_error_when_required_stage_failed():
    partial_fail = [
        StageResult(
            stage="stage_2_behavior_sequence",
            success=False,
            error="AST parse failed",
        ),
        StageResult(stage="stage_4_ttp_matching", success=True),
        StageResult(stage="stage_5_llm_review", success=True),
    ]
    assert decide_verdict([], partial_fail) == Verdict.ERROR


# ─────────────── 3. CLEAN ───────────────

def test_clean_when_all_stages_pass_and_no_evidence():
    assert decide_verdict([], _all_passed_stages()) == Verdict.CLEAN


def test_benign_overrides_weak_ttp_signal():
    """정책 핵심: weak TTP 매칭 + LLM=BENIGN → CLEAN.

    audit T-1 에서 발견된 모순 케이스. similarity 0.72 (weak), severity LOW,
    LLM BENIGN, confidence 0.40 → CLEAN.
    """
    weak = _make_evidence(
        similarity=0.72,
        severity=Severity.LOW,
        llm_verdict=LLMVerdict.BENIGN,
        confidence=0.40,
        ttp_id="T1082",
        ttp_name="System Information Discovery",
    )
    assert decide_verdict([weak], _all_passed_stages()) == Verdict.CLEAN


# ─────────────── 4. SUSPICIOUS ───────────────

def test_suspicious_when_weak_ttp_match_with_non_benign_llm():
    """weak TTP (similarity 0.72) + LLM=SUSPICIOUS confidence 0.6 → SUSPICIOUS.

    BENIGN 이 아니므로 weak TTP 신호가 살아남.
    """
    e = _make_evidence(
        similarity=0.72,
        severity=Severity.MEDIUM,
        llm_verdict=LLMVerdict.SUSPICIOUS,
        confidence=0.60,
    )
    assert decide_verdict([e], _all_passed_stages()) == Verdict.SUSPICIOUS


def test_suspicious_when_llm_only_suspicious():
    """TTP 매칭 약하지만 LLM 이 confidence 0.6 으로 SUSPICIOUS → SUSPICIOUS."""
    e = _make_evidence(
        similarity=0.50,                  # weak (sim 0.70 미만)
        severity=Severity.LOW,
        llm_verdict=LLMVerdict.SUSPICIOUS,
        confidence=0.60,
    )
    assert decide_verdict([e], _all_passed_stages()) == Verdict.SUSPICIOUS


# ─────────────── 5. HIGH_RISK ───────────────

def test_high_risk_when_strong_ttp_match_and_llm_suspicious():
    """strong TTP (sim 0.88, severity MEDIUM) + LLM=SUSPICIOUS → HIGH_RISK."""
    e = _make_evidence(
        similarity=0.88,
        severity=Severity.MEDIUM,
        llm_verdict=LLMVerdict.SUSPICIOUS,
        confidence=0.70,
        ttp_id="T1048",
        ttp_name="Exfiltration Over Alternative Protocol",
    )
    assert decide_verdict([e], _all_passed_stages()) == Verdict.HIGH_RISK


# ─────────────── 6. MALICIOUS ───────────────

def test_malicious_when_high_severity_and_llm_malicious_and_high_confidence():
    """high-severity TTP + LLM=MALICIOUS + confidence 0.90 → MALICIOUS."""
    e = _make_evidence(
        similarity=0.93,
        severity=Severity.HIGH,
        llm_verdict=LLMVerdict.MALICIOUS,
        confidence=0.90,
        ttp_id="T1027",
        ttp_name="Obfuscated Files or Information",
    )
    assert decide_verdict([e], _all_passed_stages()) == Verdict.MALICIOUS


def test_not_malicious_when_confidence_below_threshold():
    """high-severity + LLM MALICIOUS 라도 평균 confidence < 0.85 면 HIGH_RISK 로 강등."""
    e = _make_evidence(
        similarity=0.93,
        severity=Severity.HIGH,
        llm_verdict=LLMVerdict.MALICIOUS,
        confidence=0.70,           # < MALICIOUS_CONFIDENCE_THRESHOLD (0.85)
    )
    v = decide_verdict([e], _all_passed_stages())
    assert v != Verdict.MALICIOUS
    assert v in (Verdict.HIGH_RISK, Verdict.SUSPICIOUS)


# ─────────────── 7. 경계 / 회귀 ───────────────

def test_evidence_with_failed_required_stage_yields_error():
    """Evidence 가 있어도 필수 stage 실패면 ERROR — 부분 판정 금지 정책."""
    e = _make_evidence(
        similarity=0.95, severity=Severity.HIGH,
        llm_verdict=LLMVerdict.MALICIOUS, confidence=0.95,
    )
    partial_fail = [
        StageResult(stage="stage_2_behavior_sequence", success=False, error="x"),
        StageResult(stage="stage_4_ttp_matching", success=True),
        StageResult(stage="stage_5_llm_review", success=True),
    ]
    assert decide_verdict([e], partial_fail) == Verdict.ERROR
