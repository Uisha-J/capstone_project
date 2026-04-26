"""
Meta Agents Rule of Two — Lethal Trifecta 검출 + HITL 시그니처.

근거: papers/05-meta-agents-rule-of-two.md, spec/RULES.md (R2-1)

규칙: A(외부 입력) + B(민감 데이터) + C(상태 변경/외부 통신) 동시 보유 시
       prompt injection 최악 시나리오 가능. HITL 또는 session_isolation 으로만 완화.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .capability_detector import Capability, map_to_abc


@dataclass
class LethalTrifectaCheck:
    detected_caps: set[str]
    abc_present: set[str]
    has_trifecta: bool
    has_human_in_the_loop: bool
    declared_satisfies: list[str]
    declared_session_isolation: bool

    @property
    def is_violation(self) -> bool:
        return self.has_trifecta and not self.has_human_in_the_loop \
               and not self.declared_session_isolation

    def to_dict(self) -> dict:
        return {
            "abc_present": sorted(self.abc_present),
            "has_trifecta": self.has_trifecta,
            "has_human_in_the_loop": self.has_human_in_the_loop,
            "declared_satisfies": self.declared_satisfies,
            "declared_session_isolation": self.declared_session_isolation,
            "is_violation": self.is_violation,
        }


def has_lethal_trifecta(
    detected: set[str],
    *,
    has_hitl: bool = False,
    declared_satisfies: list[str] | None = None,
    declared_session_isolation: bool = False,
) -> LethalTrifectaCheck:
    abc = map_to_abc(detected)
    return LethalTrifectaCheck(
        detected_caps=set(detected),
        abc_present=abc,
        has_trifecta=len(abc) == 3,
        has_human_in_the_loop=has_hitl,
        declared_satisfies=list(declared_satisfies or []),
        declared_session_isolation=declared_session_isolation,
    )


# ─────────────── HITL 검출 ───────────────

_HITL_PYTHON_PATTERNS = [
    re.compile(r"\binput\s*\(\s*[\"'][^\"']*\?[^\"']*[\"']\s*\)"),
    re.compile(r"\bconfirm\s*\("),
    re.compile(r"\bapproval_required\s*=\s*True"),
    re.compile(r"\bhuman_in_the_loop\b"),
    re.compile(r"\bHumanInTheLoop\b"),
    re.compile(r"\brequest_approval\b"),
    re.compile(r"@requires_approval\b"),
    re.compile(r"\bask_user_to_continue\b"),
]

_HITL_JS_PATTERNS = [
    re.compile(r"\breadlineSync\b"),
    re.compile(r"\binquirer\b"),
    re.compile(r"\bprompts\s*\("),
    re.compile(r"\brequireApproval\b"),
    re.compile(r"\bhumanInTheLoop\b"),
    re.compile(r"\bHumanInTheLoop\b"),
]


def detect_human_in_the_loop(
    sources: dict[str, str],
    *,
    language: str = "python",
) -> bool:
    """sources 안에 HITL 메커니즘 시그니처가 있는지."""
    pats = (_HITL_PYTHON_PATTERNS if language.startswith("py")
            else _HITL_JS_PATTERNS)
    for src in sources.values():
        if any(p.search(src) for p in pats):
            return True
    return False
