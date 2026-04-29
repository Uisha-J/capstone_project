"""
AISLOPSQ classifier — Step 1~4 결정 트리 통합.

근거: spec/DECISION-TREE.md
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import Verdict
from .capability_detector import (
    extract_capabilities_js,
    extract_capabilities_python,
    map_to_abc,
)
from .manifest import AISLOPSQManifest, parse_manifest
from .rule_of_two import detect_human_in_the_loop
from .rules import (
    DANGEROUS_UNDECLARED,
    RuleReport,
    RuleSeverity,
    run_all_rules,
)
from .signals import (
    SignalReport,
    detect_agentic_js,
    detect_agentic_python,
)

# ─────────────── 결과 ───────────────

@dataclass
class AgenticClassification:
    is_agentic: bool                       # Step 1
    manifest: AISLOPSQManifest | None = None
    signal_report: SignalReport | None = None
    declared: set[str] = field(default_factory=set)
    detected: set[str] = field(default_factory=set)
    undeclared: set[str] = field(default_factory=set)
    abc_actual: set[str] = field(default_factory=set)
    has_human_in_the_loop: bool = False
    rule_report: RuleReport | None = None
    verdict: Verdict = Verdict.CLEAN
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "is_agentic": self.is_agentic,
            "manifest_present": self.manifest is not None,
            "signal": self.signal_report.to_dict() if self.signal_report else None,
            "declared": sorted(self.declared),
            "detected": sorted(self.detected),
            "undeclared": sorted(self.undeclared),
            "abc_actual": sorted(self.abc_actual),
            "has_human_in_the_loop": self.has_human_in_the_loop,
            "rules": self.rule_report.to_dict() if self.rule_report else None,
            "verdict": self.verdict.value,
            "reason": self.reason,
        }


# ─────────────── 메인 ───────────────

def classify(
    *,
    package_name: str,
    description: str = "",
    dependencies: list[str] | None = None,
    sources: dict[str, str] | None = None,
    pyproject_text: str | None = None,
    package_json_text: str | None = None,
    language: str = "python",      # 'python' | 'javascript'
) -> AgenticClassification:
    """전체 결정 트리 실행.

    sources: {file_path: source_code}
    language: capability detector 분기에 사용
    """
    sources = sources or {}
    deps = list(dependencies or [])

    # ─── Step 1A: manifest 기반 ─────
    manifest = parse_manifest(
        pyproject_text=pyproject_text,
        package_json_text=package_json_text,
    )
    is_python = language.startswith("py")

    # Step 1B: 자동 신호
    if is_python:
        signal = detect_agentic_python(
            package_name=package_name,
            description=description,
            dependencies=deps,
            sources=sources,
        )
    else:
        signal = detect_agentic_js(
            package_name=package_name,
            description=description,
            dependencies=deps,
            sources=sources,
        )

    is_agentic = (manifest is not None and manifest.agentic) or signal.is_agentic

    cls = AgenticClassification(
        is_agentic=is_agentic,
        manifest=manifest,
        signal_report=signal,
    )

    if not is_agentic:
        cls.verdict = Verdict.CLEAN  # 호출자가 47-indicator 로 분기
        cls.reason = "not agentic (manifest absent / signals < threshold)"
        return cls

    # ─── Step 2: capability 비교 ───
    if is_python:
        detected = extract_capabilities_python(sources)
    else:
        detected = extract_capabilities_js(sources)

    declared = manifest.declared_set if manifest else set()
    undeclared = detected - declared

    cls.declared = declared
    cls.detected = detected
    cls.undeclared = undeclared

    # 빠른 short-circuit: dangerous undeclared
    if undeclared & DANGEROUS_UNDECLARED:
        cls.verdict = Verdict.MALICIOUS
        cls.reason = (
            f"Step 2: undeclared dangerous capabilities "
            f"{sorted(undeclared & DANGEROUS_UNDECLARED)}"
        )
        # rules 도 기록 (downstream 가시성)
        cls.rule_report = run_all_rules(
            sources,
            declared=declared, detected=detected,
            manifest_present=manifest is not None,
            has_hitl=False,
            declared_session_isolation=manifest.rule_of_two.session_isolation
                if manifest else False,
            design_patterns_applied=manifest.design_patterns.applied
                if manifest else None,
        )
        return cls

    # ─── Step 3: Rule of Two ───
    cls.abc_actual = map_to_abc(detected)
    cls.has_human_in_the_loop = detect_human_in_the_loop(
        sources, language=language,
    )

    declared_session_isolation = (
        manifest.rule_of_two.session_isolation if manifest else False
    )
    design_patterns_applied = (
        manifest.design_patterns.applied if manifest else []
    )

    # ─── Step 4: R1-R4 ───
    rep = run_all_rules(
        sources,
        declared=declared, detected=detected,
        manifest_present=manifest is not None,
        has_hitl=cls.has_human_in_the_loop,
        declared_session_isolation=declared_session_isolation,
        design_patterns_applied=design_patterns_applied,
    )
    cls.rule_report = rep

    # ─── 최종 verdict 결정 ───

    # MALICIOUS triggers
    if rep.has_malicious():
        cls.verdict = Verdict.MALICIOUS
        cls.reason = "R1-R4 MALICIOUS hit: " + ", ".join(
            h.rule_id for h in rep.hits if h.severity == RuleSeverity.MALICIOUS
        )
        return cls

    # HIGH_RISK triggers
    high_risk_rules = [
        h for h in rep.hits if h.severity == RuleSeverity.HIGH_RISK
    ]
    r1_count = sum(1 for h in rep.hits if h.rule_id.startswith("R1-"))

    # R1 ≥ 2 hits + design pattern 부재 → HIGH_RISK
    r1_high_no_dp = (
        r1_count >= 2 and not design_patterns_applied
    )

    if high_risk_rules or r1_high_no_dp:
        cls.verdict = Verdict.HIGH_RISK
        cls.reason = "R1-R4 HIGH_RISK: " + (
            ", ".join(h.rule_id for h in high_risk_rules)
            or "R1 hits without design_patterns"
        )
        return cls

    # SUSPICIOUS triggers
    if rep.hits:
        cls.verdict = Verdict.SUSPICIOUS
        cls.reason = (
            "R1-R4 SUSPICIOUS: "
            + ", ".join(h.rule_id for h in rep.hits)
        )
        return cls

    # 모든 룰 통과 → AGENTIC (opt-in 필요)
    cls.verdict = Verdict.AGENTIC
    if manifest is None:
        cls.reason = ("AGENTIC (manifest absent - explicit opt-in required, "
                      "warning shown)")
    else:
        cls.reason = ("AGENTIC (declared >= detected, all R1-R4 clean - "
                      "explicit opt-in required)")
    return cls
