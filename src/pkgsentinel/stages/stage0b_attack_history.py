"""
Stage 0B — 공격 이력 조회.

Stage 0 레지스트리 확인 직후 실행.
입력 패키지 이름이 과거 악성으로 보고된 적 있거나,
알려진 악성 이름과 편집거리가 가까우면 Evidence 로 전환.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..knowledge.attack_index import AttackMatch, get_index
from ..schema import (
    Ecosystem,
    Evidence,
    LLMVerdict,
    Severity,
    TTPSource,
)


@dataclass
class AttackHistoryResult:
    # kind="exact" 만 포함 — 현재 조회 버전이 *실제로* 침해된 advisory.
    exact_matches: list[AttackMatch] = field(default_factory=list)
    # kind="historical_name_match" — 이름은 advisory 에 있으나 현재 버전은
    # affected_versions 에 없음 (예: chalk@5.6.2 — chalk@5.6.1 만 침해됨).
    # 정보성으로 보존 — Stage 5/verdict 에서 LOW severity 로 사용 가능.
    historical_name_matches: list[AttackMatch] = field(default_factory=list)
    typosquat_candidates: list[AttackMatch] = field(default_factory=list)
    error: str | None = None

    @property
    def any_hit(self) -> bool:
        return bool(
            self.exact_matches
            or self.historical_name_matches
            or self.typosquat_candidates
        )


def check_attack_history(
    package: str,
    ecosystem: Ecosystem,
    version: str | None = None,
) -> AttackHistoryResult:
    """과거 침해 advisory 조회.

    version 이 주어지면 advisory.affected_versions 에 *그 버전이 포함되는
    경우만* exact_matches 로 분류. 포함되지 않으면 historical_name_matches
    (정보성 — 같은 이름이 과거엔 침해된 적 있으나 현재 버전은 안전).
    """
    result = AttackHistoryResult()
    try:
        idx = get_index()
    except FileNotFoundError as e:
        result.error = str(e)
        return result

    all_name_matches = idx.lookup_exact(package, ecosystem.value, version=version)
    for m in all_name_matches:
        if m.kind == "exact":
            result.exact_matches.append(m)
        else:
            # historical_name_match
            result.historical_name_matches.append(m)
    result.typosquat_candidates = idx.lookup_similar(
        package, ecosystem.value, max_edit_distance=2, max_results=5,
    )
    return result


def to_evidence(
    result: AttackHistoryResult,
    file_path: str = "<registry>",
) -> list[Evidence]:
    """공격 이력 매칭 결과를 Evidence 로 변환."""
    evidence: list[Evidence] = []

    # 정확 일치: 이 이름 자체가 과거 악성 보고됨
    for m in result.exact_matches:
        ap = m.pattern
        evidence.append(Evidence(
            file_path=file_path,
            line_start=0,
            line_end=0,
            code_snippet=f"package name '{ap.affected_packages[0]}' is on the malicious list",
            behavior_sequence=["registry_name_match"],
            attack_dimensions=[],  # 이름 매칭은 차원과 무관
            ttp_id=ap.advisory_id,
            ttp_name=f"Reported malicious package — {ap.summary[:80]}",
            ttp_source=TTPSource.GHSA,
            ttp_url=(ap.references[0] if ap.references else ""),
            ttp_severity=Severity.HIGH,
            vector_similarity=1.0,
            llm_verdict=LLMVerdict.MALICIOUS,
            llm_reasoning=(
                f"Package name matches a previously reported malicious entry "
                f"({ap.advisory_id}, {ap.attack_type}). "
                f"Details: {ap.details[:200]}"
            ),
            llm_model="attack-history-rule",
            confidence=0.99,
        ))

    # 타이포스쿼팅 후보: 유사 이름
    # 주의: 단순 이름 유사성만으로는 판정 근거 약함.
    # 유명 패키지(flask 등)는 악성 패키지에 의해 타깃팅됐을 수 있어 같이 걸림.
    # → 정보성 evidence 로만 기록 (LLM verdict = BENIGN, severity = LOW).
    for m in result.typosquat_candidates[:3]:  # 상위 3개만
        ap = m.pattern
        known_name = ap.affected_packages[0] if ap.affected_packages else "?"
        evidence.append(Evidence(
            file_path=file_path,
            line_start=0,
            line_end=0,
            code_snippet=f"name similar to previously-malicious '{known_name}' (edit distance close)",
            behavior_sequence=["registry_name_similarity"],
            attack_dimensions=[],
            ttp_id="TYPOSQUAT_CANDIDATE",
            ttp_name=f"Name similarity with malicious {known_name} (informational)",
            ttp_source=TTPSource.GHSA,
            ttp_url=(ap.references[0] if ap.references else ""),
            ttp_severity=Severity.LOW,
            vector_similarity=m.similarity,
            llm_verdict=LLMVerdict.BENIGN,
            llm_reasoning=(
                f"Informational: name similarity {m.similarity:.2f} with malicious "
                f"{known_name!r} (advisory {ap.advisory_id}). "
                f"This could indicate either a typosquat attempt or that this package "
                f"shares a name prefix with a popular target. Context required."
            ),
            llm_model="attack-history-rule",
            confidence=0.3,  # 약한 신호
        ))

    return evidence


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    pkg = sys.argv[1] if len(sys.argv) > 1 else "colors"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.NPM

    res = check_attack_history(pkg, eco)
    if res.error:
        print(f"error: {res.error}")
        sys.exit(1)

    print(f"\n=== {eco.value}/{pkg} ===")
    print(f"exact matches       : {len(res.exact_matches)}")
    print(f"typosquat candidates: {len(res.typosquat_candidates)}")

    evs = to_evidence(res)
    print(f"\nevidence generated  : {len(evs)}")
    for e in evs[:3]:
        print(f"\n  [{e.ttp_severity.value}] {e.ttp_name}")
        print(f"    reasoning: {e.llm_reasoning[:150]}")
