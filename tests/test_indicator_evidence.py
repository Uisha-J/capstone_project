"""evidence.converters.indicator_hit_to_evidence — file-local risk_combo semantics.

이전 버그: indicator_codes_present 가 패키지 전역이라 한 파일의 DEF-005
가 다른 파일 수십 개의 standalone-weak 지표(EXS-001 등) 를 모두 HIGH 로
escalate → django/numpy 등 합법 대형 프레임워크 FP 폭증.

수정 후: indicator_codes_same_file (파일 로컬) 만 참조.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pkgsentinel.evidence.converters import (
    STANDALONE_WEAK_INDICATORS,
    indicator_hit_to_evidence,
)
from pkgsentinel.schema import LLMVerdict, Severity
from pkgsentinel.stages.indicator_matcher import IndicatorHit
from pkgsentinel.knowledge.malicious_indicators import get as get_indicator


def _hit(code: str, file_path: str, *, confidence: float = 0.85) -> IndicatorHit:
    """Registry 에서 실제 indicator 찾아 IndicatorHit 생성."""
    ind = get_indicator(code)
    assert ind is not None, f"indicator {code} not in registry"
    return IndicatorHit(
        indicator=ind,
        file_path=file_path,
        line=1,
        snippet="<test>",
        reason="test",
        confidence=confidence,
    )


def test_standalone_weak_alone_stays_low():
    """EXS-001 만 단독 → LOW + BENIGN."""
    h = _hit("EXS-001", "pkg/__init__.py")
    ev = indicator_hit_to_evidence(h, {"EXS-001"})
    assert ev.ttp_severity == Severity.LOW
    assert ev.llm_verdict == LLMVerdict.BENIGN


def test_standalone_weak_with_decisive_in_same_file_escalates():
    """EXS-001 + DEF-005 같은 파일 → HIGH 로 escalate."""
    h = _hit("EXS-001", "evil.py")
    ev = indicator_hit_to_evidence(h, {"EXS-001", "DEF-005"})
    assert ev.ttp_severity == Severity.HIGH
    assert ev.llm_verdict in (LLMVerdict.MALICIOUS, LLMVerdict.SUSPICIOUS)


def test_standalone_weak_with_decisive_in_other_file_NOT_escalated():
    """직전 버그 회귀 방지: DEF-005 가 다른 파일에 있어도 EXS-001 은 LOW.

    호출자(pipeline) 가 file-local 집합만 전달한다는 가정. DEF-005 가
    같은 파일에 없으면 indicator_codes_same_file 에 안 들어옴.
    """
    h = _hit("EXS-001", "pkg/__init__.py")
    # 같은 파일엔 EXS-001 만 있음 — DEF-005 는 다른 파일에 있어 여기엔 없음
    ev = indicator_hit_to_evidence(h, {"EXS-001"})
    assert ev.ttp_severity == Severity.LOW, "package-wide escalation 회귀"
    assert ev.llm_verdict == LLMVerdict.BENIGN


def test_decisive_indicator_high_regardless_of_combo():
    """DEF-005 자체는 standalone-weak 가 아니라 항상 HIGH (조합 무관)."""
    if "DEF-005" in STANDALONE_WEAK_INDICATORS:
        return  # 본 테스트는 DEF-005 가 standalone_weak 가 아니어야 의미 있음
    h = _hit("DEF-005", "anything.py", confidence=0.9)
    ev = indicator_hit_to_evidence(h, {"DEF-005"})
    assert ev.ttp_severity != Severity.LOW
