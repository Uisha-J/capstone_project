"""
Stage 4 보강 — 규칙 기반 TTP 매칭.

임베딩 유사도만으로는 짧은 코드 시퀀스와 MITRE 의 일반적 설명 사이의
의미 간극 때문에 강한 매칭이 잘 나오지 않는다.

현직자 조언: "마이터 어택은 정규식 기반으로 할 수밖에 없는 것들이 있다."

이 모듈은 잘 알려진 공격 행위 패턴을 명시적 규칙으로 잡아낸다.
규칙 적중 시 지식 DB 에서 TTP 를 찾아와 Evidence 로 변환.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..schema import AttackDimension, TTPEntry, Severity, TTPSource
from .stage2_behavior import FileSequence


# ─────────────── 행위 패턴 규칙 ───────────────
#
# 각 규칙: "요구 차원 집합 (모두 포함되어야 함)" → (TTP ID, TTP 이름, 심각도)

@dataclass
class BehaviorRule:
    required_dims: set[AttackDimension]
    ttp_id: str
    ttp_name: str
    severity: Severity
    reason: str


RULES: list[BehaviorRule] = [
    # Credential Theft: 환경변수/파일 읽기 + (선택적 인코딩) + 네트워크 송신
    BehaviorRule(
        required_dims={
            AttackDimension.INFORMATION_READING,
            AttackDimension.DATA_TRANSMISSION,
        },
        ttp_id="T1552.001",
        ttp_name="Unsecured Credentials: Credentials In Files",
        severity=Severity.HIGH,
        reason="Sensitive information is read and transmitted externally",
    ),
    # Exfiltration over HTTP with encoding
    BehaviorRule(
        required_dims={
            AttackDimension.INFORMATION_READING,
            AttackDimension.ENCODING,
            AttackDimension.DATA_TRANSMISSION,
        },
        ttp_id="T1048.003",
        ttp_name="Exfiltration Over Unencrypted Non-C2 Protocol",
        severity=Severity.HIGH,
        reason="Information is read, encoded, and transmitted -- classic exfil pattern",
    ),
    # Encoded payload execution
    BehaviorRule(
        required_dims={
            AttackDimension.ENCODING,
            AttackDimension.PAYLOAD_EXECUTION,
        },
        ttp_id="T1027",
        ttp_name="Obfuscated Files or Information",
        severity=Severity.HIGH,
        reason="Decoded/obfuscated content is executed dynamically",
    ),
    # Remote download + execute
    BehaviorRule(
        required_dims={
            AttackDimension.DATA_TRANSMISSION,
            AttackDimension.PAYLOAD_EXECUTION,
        },
        ttp_id="T1105",
        ttp_name="Ingress Tool Transfer",
        severity=Severity.HIGH,
        reason="Content is fetched from a remote endpoint then executed",
    ),
    # Shell command injection pattern (single dimension but explicit)
    BehaviorRule(
        required_dims={AttackDimension.PAYLOAD_EXECUTION},
        ttp_id="T1059",
        ttp_name="Command and Scripting Interpreter",
        severity=Severity.MEDIUM,
        reason="Dynamic code/shell execution detected",
    ),
]


# ─────────────── 적용 ───────────────

@dataclass
class RuleHit:
    rule: BehaviorRule
    file_path: str
    matched_dims: set[AttackDimension]
    matched_calls: list[str]


def apply_rules(fs: FileSequence) -> list[RuleHit]:
    """한 파일의 시퀀스에 규칙 적용. 여러 규칙이 동시에 적중할 수 있음."""
    if not fs.calls:
        return []

    present = set(fs.dimensions)
    hits: list[RuleHit] = []

    for rule in RULES:
        if rule.required_dims.issubset(present):
            hits.append(RuleHit(
                rule=rule,
                file_path=fs.path,
                matched_dims=rule.required_dims,
                matched_calls=[c.name for c in fs.calls],
            ))
    return hits


def rule_hit_to_ttp_entry(hit: RuleHit) -> TTPEntry:
    """RuleHit 을 TTPEntry 스키마로 감싼다 (Evidence 변환용)."""
    return TTPEntry(
        ttp_id=hit.rule.ttp_id,
        ttp_name=hit.rule.ttp_name,
        source=TTPSource.MITRE_ATTACK,
        kb_version="rule-based",
        description=hit.rule.reason,
        severity=hit.rule.severity,
        url=f"https://attack.mitre.org/techniques/{hit.rule.ttp_id.split('.')[0]}/",
    )
