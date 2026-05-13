"""Runtime observation → detection rule auto-generation (#L5).

종류:
  - indicator_47   : 우리 indicator catalog 호환 룰 (regex 기반)
  - falco          : Falco rules.yaml 호환 룰
  - sequence_pattern : sequence_patterns.py 호환 룰
  - aislopsq_r     : AISLOPSQ R-rule 후보 (R3-extension 또는 R4-extension)

본 단계는 *draft* 생성만. 사람 검토 후 promote (LearnedRule.status='approved').
"""
from __future__ import annotations

import json

from ..db.runtime_intel import LearnedRule


def generate_indicator_47_rule(
    observation_ids: list[int],
    pattern: dict,
    rationale: str,
    *,
    confidence: float = 0.5,
) -> LearnedRule:
    """패턴 → 47-indicator catalog 호환 룰 draft.

    rule_body: JSON {
      "code": "RT-NNN",
      "name": "...",
      "dimensions": [...],
      "severity": "HIGH" | "MEDIUM",
      "match_kind": "behavior_combo"  # 우리 indicator_matcher 가 인식
    }
    """
    severity = "HIGH" if len(pattern.get("dimensions") or []) >= 2 else "MEDIUM"
    obs_str = "-".join(str(i) for i in sorted(observation_ids)[:3]) or "x"
    code = f"RT-{obs_str}"
    body = {
        "code": code,
        "name": pattern.get("summary") or "runtime-derived",
        "dimensions": pattern.get("dimensions", []),
        "severity": severity,
        "match_kind": "behavior_combo",
        "indicator_codes_seen": pattern.get("indicator_codes", []),
    }
    return LearnedRule(
        rule_kind="indicator_47",
        rule_body=json.dumps(body, ensure_ascii=False, indent=2),
        source_observation_ids=list(observation_ids),
        confidence=confidence,
        rationale=rationale,
    )


def generate_falco_rule(
    observation_ids: list[int],
    iocs: list[dict],
    pattern: dict,
    rationale: str,
    *,
    confidence: float = 0.7,
) -> LearnedRule | None:
    """IOC 기반 Falco 룰 YAML draft.

    IP / domain / sensitive-path 가 있어야 의미 있는 룰 생성 가능.
    리턴 None: IOC 충분치 않음.
    """
    external_ips = [i["value"] for i in iocs if i["type"] == "ip"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    paths = [i["value"] for i in iocs if i["type"] == "path"]

    if not (external_ips or domains or paths):
        return None

    obs_str = "-".join(str(i) for i in sorted(observation_ids)[:3]) or "x"
    rule_name = f"pkgsentinel-rt-{obs_str}"

    # 조건 조립 — IP / domain / path 합집합
    conditions: list[str] = []
    if external_ips:
        ip_list = ", ".join(f"'{ip.split(':')[0]}'" for ip in external_ips)
        conditions.append(f"evt.type = connect and fd.sip in ({ip_list})")
    if domains:
        dom_list = ", ".join(f"'{d}'" for d in domains)
        conditions.append(f"dns.name in ({dom_list})")
    if paths:
        # 경로는 prefix 매칭
        path_conds = " or ".join(
            f"fd.name pmatch ('{p}')" for p in paths[:5]
        )
        conditions.append(f"(evt.type = openat and ({path_conds}))")

    condition = " or ".join(f"({c})" for c in conditions)

    body_lines = [
        f"- rule: {rule_name}",
        f"  desc: Auto-generated from pkgsentinel runtime observations "
        f"{observation_ids}",
        f"  condition: {condition}",
        f"  output: 'pkgsentinel runtime IOC match (rule={rule_name})'",
        f"  priority: CRITICAL",
        f"  tags: [pkgsentinel, runtime-derived, auto]",
    ]
    body = "\n".join(body_lines) + "\n"

    return LearnedRule(
        rule_kind="falco",
        rule_body=body,
        source_observation_ids=list(observation_ids),
        confidence=confidence,
        rationale=rationale,
    )


def generate_sequence_pattern_rule(
    observation_ids: list[int],
    pattern: dict,
    rationale: str,
    *,
    confidence: float = 0.4,
) -> LearnedRule | None:
    """sequence_patterns.py 호환 패턴 draft.

    dimensions 가 2개 이상일 때만 의미 있음 — 단일 dimension 은 indicator 가 처리.
    """
    dims = pattern.get("dimensions") or []
    if len(set(dims)) < 2:
        return None

    obs_str = "-".join(str(i) for i in sorted(observation_ids)[:3]) or "x"
    body = {
        "code": f"SP-RT-{obs_str}",
        "name": f"Runtime-observed sequence: {pattern.get('summary')}",
        "severity": "HIGH",
        "dimension_sequence": sorted(set(dims)),
        "min_distance": 1,
        "max_distance": 50,
    }
    return LearnedRule(
        rule_kind="sequence_pattern",
        rule_body=json.dumps(body, ensure_ascii=False, indent=2),
        source_observation_ids=list(observation_ids),
        confidence=confidence,
        rationale=rationale,
    )


def generate_aislopsq_r_extension(
    observation_ids: list[int],
    pattern: dict,
    rationale: str,
    *,
    confidence: float = 0.45,
) -> LearnedRule | None:
    """AISLOPSQ R-rule 보강 후보.

    예: 패턴이 'cred read + external network' 인데 패키지가 자신을 agentic 으로
    declare 안 했다 → R3-extension (undeclared capability).
    """
    dims = set(pattern.get("dimensions") or [])
    # 단순 휴리스틱 — 다음 조합은 R3 strengthening 후보
    interesting_combo = (
        "INFORMATION_READING" in dims
        and "DATA_TRANSMISSION" in dims
    )
    if not interesting_combo:
        return None

    obs_str = "-".join(str(i) for i in sorted(observation_ids)[:3]) or "x"
    body = {
        "rule_id": f"R3-RT-{obs_str}",
        "extends": "R3",
        "name": "Runtime-observed undeclared cred-exfil capability",
        "trigger_dimensions": sorted(dims),
        "severity": "MALICIOUS",
        "note": (
            "If package did not declare 'env-secrets' + 'network' capabilities "
            "in AISLOPSQ manifest but runtime shows credential read + "
            "external connect, treat as MALICIOUS regardless of static signals."
        ),
    }
    return LearnedRule(
        rule_kind="aislopsq_r",
        rule_body=json.dumps(body, ensure_ascii=False, indent=2),
        source_observation_ids=list(observation_ids),
        confidence=confidence,
        rationale=rationale,
    )


def generate_all_drafts(
    observation_ids: list[int],
    iocs: list[dict],
    pattern: dict,
    rationale: str,
) -> list[LearnedRule]:
    """가능한 모든 종류의 룰 draft 를 한 observation 으로부터 자동 생성.

    각 generator 는 None 반환 가능 (조건 안 맞으면 skip).
    """
    drafts: list[LearnedRule] = []
    if pattern.get("indicator_codes"):
        drafts.append(generate_indicator_47_rule(
            observation_ids, pattern, rationale,
        ))
    fr = generate_falco_rule(observation_ids, iocs, pattern, rationale)
    if fr:
        drafts.append(fr)
    sr = generate_sequence_pattern_rule(observation_ids, pattern, rationale)
    if sr:
        drafts.append(sr)
    ar = generate_aislopsq_r_extension(observation_ids, pattern, rationale)
    if ar:
        drafts.append(ar)
    return drafts
