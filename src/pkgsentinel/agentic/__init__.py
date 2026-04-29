"""
AISLOPSQ — Agentic Package Security 모듈.

근거 사양: docs/aislopsq/
  - spec/AISLOPSQ-MANIFEST-SPEC.md
  - spec/DECISION-TREE.md
  - spec/RULES.md
  - detection/AGENTIC-SIGNALS.md
  - detection/CAPABILITY-DETECTION.md

근거 논문 (papers/):
  - Chhabra et al. 2025 (arXiv:2510.23883) — agentic 4요소 정의
  - Beurer-Kellner et al. 2025 (arXiv:2506.08837) — design patterns
  - Shi et al. 2025 (arXiv:2504.19793) — ToolHijacker
  - Nasr et al. 2025 (arXiv:2510.09023) — filtering 신뢰성 부재
  - Meta AI 2025 — Agents Rule of Two
"""

from .capability_detector import (
    CAPABILITIES,
    Capability,
    extract_capabilities_js,
    extract_capabilities_python,
    map_to_abc,
)
from .classifier import (
    AgenticClassification,
    classify,
)
from .manifest import (
    AISLOPSQManifest,
    parse_manifest,
    parse_npm_package,
    parse_python_pyproject,
)
from .rule_of_two import (
    LethalTrifectaCheck,
    detect_human_in_the_loop,
    has_lethal_trifecta,
)
from .rules import (
    R1_check,
    R2_check,
    R3_check,
    R4_check,
    RuleHit,
    RuleReport,
    RuleSeverity,
    run_all_rules,
)
from .signals import (
    AGENTIC_THRESHOLD,
    SignalReport,
    detect_agentic_js,
    detect_agentic_python,
)

__all__ = [
    # manifest
    "AISLOPSQManifest", "parse_manifest",
    "parse_python_pyproject", "parse_npm_package",
    # capability
    "Capability", "CAPABILITIES",
    "extract_capabilities_python", "extract_capabilities_js",
    "map_to_abc",
    # signals
    "SignalReport", "AGENTIC_THRESHOLD",
    "detect_agentic_python", "detect_agentic_js",
    # rule of two
    "LethalTrifectaCheck", "has_lethal_trifecta", "detect_human_in_the_loop",
    # rules
    "RuleHit", "RuleReport", "RuleSeverity",
    "R1_check", "R2_check", "R3_check", "R4_check", "run_all_rules",
    # classifier
    "AgenticClassification", "classify",
]
