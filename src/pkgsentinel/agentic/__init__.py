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

from .manifest import (
    AISLOPSQManifest, parse_manifest, parse_python_pyproject, parse_npm_package,
)
from .capability_detector import (
    Capability, CAPABILITIES,
    extract_capabilities_python, extract_capabilities_js,
    map_to_abc,
)
from .signals import (
    SignalReport, AGENTIC_THRESHOLD,
    detect_agentic_python, detect_agentic_js,
)
from .rule_of_two import (
    LethalTrifectaCheck, has_lethal_trifecta, detect_human_in_the_loop,
)
from .rules import (
    RuleHit, RuleReport, RuleSeverity,
    R1_check, R2_check, R3_check, R4_check, run_all_rules,
)
from .classifier import (
    AgenticClassification, classify,
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
