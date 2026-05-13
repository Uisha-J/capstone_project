"""
공격 사례 매칭기.

두 가지 경로:
  1. 정확 일치: 입력 패키지 이름이 과거 악성 보고된 이름인가
  2. 근접 일치: 알려진 악성 이름과 편집거리 / 공통 접두사 등

Phase D-2 의 핵심. 지식 DB 의 11만+ 악성 패키지 레퍼런스를 활용.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .osv import AttackPattern, load_patterns

# ─────────────── 인덱스 ───────────────

@dataclass
class AttackMatch:
    # "exact"                  — 이름 + 버전 모두 일치 (또는 버전 미지정 호출)
    # "historical_name_match"  — 이름 일치하지만 *조회 버전이 affected_versions 에 없음*
    # "typosquat_candidate"    — 편집거리 가까운 다른 이름
    kind: str
    pattern: AttackPattern
    similarity: float           # 정확: 1.0, 유사: Jaccard or 편집거리 기반
    reason: str

    @property
    def is_active(self) -> bool:
        """현재 조회 대상이 *실제로* 침해된 상태인가."""
        return self.kind == "exact"


class AttackPatternIndex:
    """메모리 기반 빠른 조회."""

    def __init__(self, patterns: list[AttackPattern]):
        self.patterns = list(patterns)
        # name -> AttackPattern (여러 개일 수 있지만 보통 하나)
        self._by_name: dict[tuple[str, str], list[AttackPattern]] = {}
        for p in self.patterns:
            for name in p.affected_packages:
                key = (p.ecosystem, name.lower())
                self._by_name.setdefault(key, []).append(p)

        # 이름 집합 (유사도 검색용)
        self._all_names = [
            (p.ecosystem, name.lower(), p)
            for p in self.patterns
            for name in p.affected_packages
        ]
        # 학습된 IOC 의 빠른 lookup
        # runtime_iocs[(type, value)] = LearnedIOC dict (subset of fields)
        self._runtime_iocs: dict[tuple[str, str], dict] = {}

        print(f"[AttackIndex] loaded {len(self.patterns)} patterns, "
              f"{len(self._by_name)} unique (ecosystem, name) pairs")

    # ─────────────── live update — runtime intel feedback ───────────────

    def add_runtime_pattern(self, pattern: AttackPattern) -> None:
        """런타임 학습된 AttackPattern 한 건을 인덱스에 즉시 추가.

        호출 후 lookup_exact / lookup_similar 가 새 패턴 반영. 재시작 불필요.
        """
        # 중복 advisory_id 는 무시 (already loaded)
        existing_ids = {p.advisory_id for p in self.patterns}
        if pattern.advisory_id in existing_ids:
            return
        self.patterns.append(pattern)
        for name in pattern.affected_packages:
            key = (pattern.ecosystem, name.lower())
            self._by_name.setdefault(key, []).append(pattern)
            self._all_names.append((pattern.ecosystem, name.lower(), pattern))

    def add_runtime_patterns(self, patterns: list[AttackPattern]) -> int:
        n = 0
        for p in patterns:
            before = len(self.patterns)
            self.add_runtime_pattern(p)
            if len(self.patterns) > before:
                n += 1
        return n

    def add_runtime_ioc(
        self, ioc_type: str, value: str,
        *,
        confidence: float = 0.5,
        associated_packages: list[str] | None = None,
        source_observation_id: int | None = None,
    ) -> None:
        """학습된 IOC 한 건을 즉시 인덱스에 추가.

        associated_packages: ["evil-pkg@0.0.1", ...] 형태. 패키지명 매칭에 활용.
        """
        key = (ioc_type, value.lower() if ioc_type != "sha256" else value)
        self._runtime_iocs[key] = {
            "type": ioc_type,
            "value": value,
            "confidence": confidence,
            "associated_packages": list(associated_packages or []),
            "source_observation_id": source_observation_id,
        }

    def lookup_runtime_ioc(self, ioc_type: str, value: str) -> dict | None:
        key = (ioc_type, value.lower() if ioc_type != "sha256" else value)
        return self._runtime_iocs.get(key)

    def runtime_ioc_count(self) -> int:
        return len(self._runtime_iocs)

    def lookup_exact(
        self,
        package: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[AttackMatch]:
        """이름 매칭 + (선택적) 버전 필터.

        version 이 주어지면 advisory 의 affected_versions 에 *그 버전이 포함*
        될 때만 kind="exact". 포함되지 않으면 kind="historical_name_match"
        (정보성 — 이 이름이 과거에 침해된 적은 있으나 현재 조회 버전은 안전).

        affected_versions 가 비어 있으면 unbounded 로 보고 모두 exact 처리
        (OSV 가 버전 정보를 누락한 경우 — 보수적 매칭).

        version=None 이면 기존 동작 (모두 exact).
        """
        key = (ecosystem, package.lower())
        hits = self._by_name.get(key, [])
        matches: list[AttackMatch] = []
        for p in hits:
            affected = p.affected_versions or []
            if version is None or not affected:
                matches.append(AttackMatch(
                    kind="exact",
                    pattern=p,
                    similarity=1.0,
                    reason=(
                        f"exact match: this package name was reported as "
                        f"malicious ({p.advisory_id})"
                    ),
                ))
                continue
            if version in affected:
                matches.append(AttackMatch(
                    kind="exact",
                    pattern=p,
                    similarity=1.0,
                    reason=(
                        f"exact version match: {package}@{version} is in "
                        f"affected_versions of {p.advisory_id}"
                    ),
                ))
            else:
                matches.append(AttackMatch(
                    kind="historical_name_match",
                    pattern=p,
                    similarity=1.0,
                    reason=(
                        f"name '{package}' was reported as malicious "
                        f"({p.advisory_id}) but version {version} is NOT in "
                        f"affected_versions {affected[:5]}{'...' if len(affected) > 5 else ''} "
                        f"— current version likely safe"
                    ),
                ))
        return matches

    def lookup_similar(
        self,
        package: str,
        ecosystem: str,
        max_edit_distance: int = 2,
        max_results: int = 5,
    ) -> list[AttackMatch]:
        """타이포스쿼팅 후보: 알려진 악성 이름과 편집거리 가까운 것."""
        name_lower = package.lower()
        candidates: list[AttackMatch] = []

        for eco, known, p in self._all_names:
            if eco != ecosystem:
                continue
            if known == name_lower:
                continue  # exact 는 별도 처리
            if abs(len(known) - len(name_lower)) > max_edit_distance:
                continue
            dist = _levenshtein(name_lower, known)
            if dist == 0 or dist > max_edit_distance:
                continue

            sim = 1.0 - dist / max(len(name_lower), len(known))
            candidates.append(AttackMatch(
                kind="typosquat_candidate",
                pattern=p,
                similarity=sim,
                reason=(
                    f"name is within edit distance {dist} of known malicious "
                    f"package {known!r} ({p.advisory_id})"
                ),
            ))

        candidates.sort(key=lambda m: -m.similarity)
        return candidates[:max_results]


def _levenshtein(a: str, b: str) -> int:
    """표준 Levenshtein (제한된 길이용)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + cost,
            ))
        prev = curr
    return prev[-1]


# ─────────────── 싱글톤 인덱스 로드 ───────────────

@lru_cache(maxsize=1)
def get_index() -> AttackPatternIndex:
    cache_dir = Path(__file__).parent / "cache"
    all_patterns: list[AttackPattern] = []
    seen_ids: set[str] = set()

    # 1) OSV (PyPI / npm) — 광범위, 자동수집된 advisory
    # 2) OSSF malicious-packages — 큐레이션된, 라벨 정확도 높음
    # 두 채널 모두 OSV 포맷이라 같은 AttackPattern. advisory_id 로 dedup.
    cache_files = [
        "osv_pypi.json",
        "osv_npm.json",
        "ossf_malicious_pypi.json",
        "ossf_malicious_npm.json",
    ]
    for fn in cache_files:
        path = cache_dir / fn
        if not path.exists():
            continue
        for p in load_patterns(path):
            # advisory_id 충돌 시 OSV 가 먼저 로드 → OSSF dedup. 데이터 손실 X
            # (OSSF 는 OSV 와 거의 같은 advisory 를 재배포; 메타데이터만 다소 풍부)
            if p.advisory_id in seen_ids:
                continue
            seen_ids.add(p.advisory_id)
            all_patterns.append(p)

    if not all_patterns:
        raise FileNotFoundError(
            "위협 feed 캐시가 없습니다. 먼저 수집하세요:\n"
            "  python -m pkgsentinel.knowledge.osv PyPI\n"
            "  python -m pkgsentinel.knowledge.osv npm\n"
            "  python -m pkgsentinel.knowledge.ossf_malicious  (선택)\n"
        )

    return AttackPatternIndex(all_patterns)


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    idx = get_index()
    pkg = sys.argv[1] if len(sys.argv) > 1 else "colors"
    eco = sys.argv[2] if len(sys.argv) > 2 else "npm"

    print(f"\n=== {eco}/{pkg} 조회 ===\n")

    exact = idx.lookup_exact(pkg, eco)
    if exact:
        print(f"[EXACT MATCH] — 이 이름은 {len(exact)}건의 악성 보고가 있음")
        for m in exact[:3]:
            print(f"  {m.pattern.advisory_id}  ({m.pattern.published[:10]})")
            print(f"  summary: {m.pattern.summary[:150]}")
    else:
        print("[exact] 없음")

    similar = idx.lookup_similar(pkg, eco, max_edit_distance=2)
    if similar:
        print(f"\n[TYPOSQUAT CANDIDATES] — 편집거리 <= 2 인 악성 패키지 {len(similar)}건")
        for m in similar[:5]:
            print(f"  sim={m.similarity:.2f}  {m.pattern.affected_packages[0]}  ({m.pattern.advisory_id})")
    else:
        print("\n[typosquat] 없음")
