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

from datetime import UTC

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


def test_llm_only_suspicious_with_ttp_match_promotes():
    """TTP 매칭 (sim 0.72) + LLM=SUSPICIOUS confidence 0.6 → SUSPICIOUS.

    LLM-only quorum (T-4) 의 영향을 받지 않는 경로 — TTP 매칭이 있으므로
    _has_any_ttp_match 가 True 로 단독 발화. quorum 은 LLM-only 에만 적용.
    """
    e = _make_evidence(
        similarity=0.72,                  # weak threshold (≥ 0.70)
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


# ─────────────── 8. T-4 quorum 정책 ───────────────

def test_quorum_single_llm_only_suspicious_does_not_promote():
    """LLM-only SUSPICIOUS evidence 1건 + TTP weak (sim 0.50) → CLEAN.

    quorum 미충족 (LLM_SUSPICIOUS_QUORUM=2). TTP 매칭 임계 (0.70) 미만이라
    _has_any_ttp_match 도 False → SUSPICIOUS 분기 모든 조건 미충족.
    """
    e = _make_evidence(
        similarity=0.50,           # weak (< WEAK_MATCH_SIMILARITY 0.70)
        severity=Severity.LOW,
        llm_verdict=LLMVerdict.SUSPICIOUS,
        confidence=0.60,
    )
    assert decide_verdict([e], _all_passed_stages()) == Verdict.CLEAN


def test_quorum_two_llm_only_suspicious_promotes():
    """LLM-only SUSPICIOUS evidence 2건 (sim < 0.70) → SUSPICIOUS (quorum 충족)."""
    e1 = _make_evidence(
        similarity=0.50, severity=Severity.LOW,
        llm_verdict=LLMVerdict.SUSPICIOUS, confidence=0.60,
        file_path="a.py",
    )
    e2 = _make_evidence(
        similarity=0.55, severity=Severity.LOW,
        llm_verdict=LLMVerdict.SUSPICIOUS, confidence=0.65,
        file_path="b.py",
    )
    assert decide_verdict([e1, e2], _all_passed_stages()) == Verdict.SUSPICIOUS


# ─────────────── 9. T-5 CLEAN + evidence visualization ───────────────

def test_clean_with_noise_marked_in_format_report():
    """CLEAN verdict + evidence 1건 → format_report 에 (noisy) 표시 +
    package_meta.clean_with_noise = True 설정.

    weak TTP (sim 0.72, severity LOW, LLM=BENIGN) 1건은 CLEAN 으로 빠지지만
    Evidence list 에는 들어 있음 — 운영자에게 "약신호 N건이 묻혔다" 를 노출.
    """
    from datetime import datetime, timezone

    from pkgsentinel.reporting.formats import format_report
    from pkgsentinel.schema import AnalysisReport, Ecosystem

    weak = _make_evidence(
        similarity=0.72, severity=Severity.LOW,
        llm_verdict=LLMVerdict.BENIGN, confidence=0.40,
    )
    report = AnalysisReport(
        package="x", ecosystem=Ecosystem.PYPI, version="1.0",
        analyzed_at=datetime.now(UTC),
        verdict=Verdict.CLEAN,
        evidence=[weak],
        stage_results=_all_passed_stages(),
    )
    out = format_report(report)
    assert "noisy" in out, "expected '(noisy)' marker in CLEAN+evidence output"
    assert "1 weak evidence" in out
    assert report.package_meta.get("clean_with_noise") is True


# ─────────────── 10. popular×benign 다운그레이드 (apply_popular_downgrade) ───────────────

from pkgsentinel.verdict_rules import apply_popular_downgrade


def _make_indicator_evidence(
    *, file_path: str, severity: Severity, llm_verdict: LLMVerdict = LLMVerdict.SUSPICIOUS
) -> Evidence:
    """47-indicator 매처가 만든 Evidence 모방 (llm_model 식별자로 구분)."""
    e = _make_evidence(
        similarity=1.0,
        severity=severity,
        llm_verdict=llm_verdict,
        confidence=0.7,
        file_path=file_path,
    )
    e.llm_model = "indicator-rule-47"
    return e


def _make_seq_evidence(
    *, file_path: str, severity: Severity, llm_verdict: LLMVerdict = LLMVerdict.SUSPICIOUS
) -> Evidence:
    e = _make_evidence(
        similarity=1.0,
        severity=severity,
        llm_verdict=llm_verdict,
        confidence=0.7,
        file_path=file_path,
    )
    e.llm_model = "sequence-pattern-mine"
    return e


def test_popular_downgrade_unknown_package_passthrough():
    """비-인기 패키지는 다운그레이드 건드리지 않음."""
    out = apply_popular_downgrade(
        Verdict.HIGH_RISK, [], "totally-unknown-pkg-xyz", "PyPI", "claude",
    )
    assert out == Verdict.HIGH_RISK


def test_popular_downgrade_clean_or_malicious_untouched():
    """CLEAN / MALICIOUS 는 어떤 경우에도 다운그레이드 대상 아님."""
    assert apply_popular_downgrade(Verdict.CLEAN, [], "numpy", "PyPI", "claude") == Verdict.CLEAN
    assert apply_popular_downgrade(Verdict.MALICIOUS, [], "numpy", "PyPI", "claude") == Verdict.MALICIOUS


def test_popular_downgrade_rule_a_medium_signals_clean():
    """Rule A: 인기 패키지 + 약~중 신호만 → CLEAN."""
    e = _make_indicator_evidence(file_path="a.py", severity=Severity.MEDIUM)
    out = apply_popular_downgrade(
        Verdict.SUSPICIOUS, [e], "numpy", "PyPI", "stub",
    )
    assert out == Verdict.CLEAN


def test_popular_downgrade_rule_a_blocked_by_high_taint():
    """Rule A: taint 2 이상이면 보호."""
    e = _make_indicator_evidence(file_path="a.py", severity=Severity.MEDIUM)
    out = apply_popular_downgrade(
        Verdict.SUSPICIOUS, [e], "numpy", "PyPI", "stub", taint_total=2,
    )
    assert out == Verdict.SUSPICIOUS


def test_popular_downgrade_rule_a_blocked_by_cooccur():
    """Rule A: 같은 파일에 indicator-HIGH + seq-HIGH co-occur → 보호."""
    e1 = _make_indicator_evidence(file_path="a.py", severity=Severity.HIGH)
    e2 = _make_seq_evidence(file_path="a.py", severity=Severity.HIGH)
    out = apply_popular_downgrade(
        Verdict.HIGH_RISK, [e1, e2], "django", "PyPI", "stub",
    )
    assert out == Verdict.HIGH_RISK


def test_popular_downgrade_blocked_by_llm_malicious():
    """LLM_MALICIOUS evidence 가 하나라도 있으면 다운그레이드 금지."""
    e = _make_indicator_evidence(
        file_path="a.py", severity=Severity.MEDIUM, llm_verdict=LLMVerdict.MALICIOUS,
    )
    out = apply_popular_downgrade(
        Verdict.HIGH_RISK, [e], "numpy", "PyPI", "claude",
    )
    assert out == Verdict.HIGH_RISK


def test_popular_downgrade_rule_b_large_tool_spread_clean():
    """Rule B: 큰 인기 도구 (>50 files) + 분산된 중간 신호 → CLEAN."""
    e = _make_indicator_evidence(file_path="a.py", severity=Severity.HIGH)
    out = apply_popular_downgrade(
        Verdict.SUSPICIOUS, [e], "django", "PyPI", "stub",
        source_file_count=120,
    )
    assert out == Verdict.CLEAN


def test_popular_downgrade_rule_c_llm_benign_claude_only():
    """Rule C: claude 모드 + LLM_BENIGN evidence 있으면 강한 신호도 다운그레이드.

    Rule A 가 ind_high < 5 로 막는 영역 (HIGH 5+) 도 LLM 이 BENIGN 이면 OK.
    """
    high = [_make_indicator_evidence(file_path=f"f{i}.py", severity=Severity.HIGH)
            for i in range(6)]
    benign = _make_indicator_evidence(
        file_path="g.py", severity=Severity.LOW, llm_verdict=LLMVerdict.BENIGN,
    )
    out = apply_popular_downgrade(
        Verdict.HIGH_RISK, [*high, benign], "pandas", "PyPI", "claude",
    )
    assert out == Verdict.CLEAN


def test_popular_downgrade_rule_c_stub_mode_skipped():
    """Rule C 는 stub 모드에선 발화 안 함 (LLM 신뢰 불가)."""
    high = [_make_indicator_evidence(file_path=f"f{i}.py", severity=Severity.HIGH)
            for i in range(6)]
    benign = _make_indicator_evidence(
        file_path="g.py", severity=Severity.LOW, llm_verdict=LLMVerdict.BENIGN,
    )
    out = apply_popular_downgrade(
        Verdict.HIGH_RISK, [*high, benign], "pandas", "PyPI", "stub",
    )
    # Rule A 도 ind_high=6 으로 막힘, Rule B 도 source_file_count 미지정으로 막힘
    assert out == Verdict.HIGH_RISK


def test_popular_downgrade_npm_react_rule_a():
    """npm 인기 패키지도 같은 룰 적용."""
    e = _make_indicator_evidence(file_path="x.js", severity=Severity.MEDIUM)
    out = apply_popular_downgrade(
        Verdict.SUSPICIOUS, [e], "react", "npm", "stub",
    )
    assert out == Verdict.CLEAN
