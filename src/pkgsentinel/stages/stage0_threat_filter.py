"""
Stage 0 Threat Filter — 분석 시작 전 게이트.

3 종류 매칭:
  1. exact malicious     : known_malicious 에 (eco, pkg) 정확 일치
                           → 즉시 MALICIOUS verdict, 이후 stage 스킵 가능
  2. typosquat candidate : 알려진 악성 이름과 편집거리 ≤ 2 → SUSPICIOUS evidence
  3. popular allowlist   : known_popular 에 등재 + rank ≤ 1000 → 신뢰 강화 신호
                           (단, exact malicious 우세 시 무시)
  4. network IoC         : 분석 단계는 stage 5 결과에 의존하므로 본 stage 에서는
                           "패키지 이름 자체가 IoC 도메인" 일 때만 (드물지만 존재)

설계 원칙:
  - 위협 우선: 정상 같은 신호와 위협 신호가 같이 보이면 위협 우선
  - 실패 무해: DB 미초기화 / 키 없음 → SKIPPED 로 fall-through
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import (
    AttackDimension,
    Ecosystem,
    Evidence,
    LLMVerdict,
    Severity,
    TTPSource,
)

# ─────────────── 결과 ───────────────

@dataclass
class ThreatFilterReport:
    exact_match: bool = False
    advisory_id: str | None = None
    advisory_summary: str | None = None
    typosquat_candidates: list[dict] = field(default_factory=list)
    popular_rank: int | None = None
    popular_downloads: int | None = None
    ioc_hits: list[dict] = field(default_factory=list)
    skipped: bool = False
    error: str | None = None

    @property
    def is_known_malicious(self) -> bool:
        return self.exact_match

    @property
    def is_popular(self) -> bool:
        return self.popular_rank is not None and self.popular_rank <= 5000

    @property
    def is_top_popular(self) -> bool:
        """신뢰 강화 임계: top-1000 패키지."""
        return self.popular_rank is not None and self.popular_rank <= 1000

    def to_dict(self) -> dict:
        return {
            "exact_match": self.exact_match,
            "advisory_id": self.advisory_id,
            "advisory_summary": self.advisory_summary,
            "typosquat_candidates": self.typosquat_candidates,
            "popular_rank": self.popular_rank,
            "popular_downloads": self.popular_downloads,
            "ioc_hits": self.ioc_hits,
            "skipped": self.skipped,
            "error": self.error,
        }


# ─────────────── 매칭 ───────────────

def _levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    """짧은 문자열용 표준 Levenshtein. max_dist 초과 시 max_dist+1 반환."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j-1]+1, prev[j]+1, prev[j-1]+cost))
        prev = curr
        if min(prev) > max_dist:
            return max_dist + 1
    return prev[-1]


def _check_exact(db, ecosystem: str, package: str) -> dict | None:
    with db.cursor() as cur:
        cur.execute("""
            SELECT advisory_id, attack_type, summary, modified
            FROM known_malicious
            WHERE ecosystem=? AND lower(package)=lower(?)
            ORDER BY modified DESC LIMIT 1
        """, (ecosystem, package))
        row = cur.fetchone()
        if not row:
            return None
        return {"advisory_id": row[0], "attack_type": row[1],
                "summary": row[2] or "", "modified": row[3]}


def _check_typosquat(
    db, ecosystem: str, package: str, max_dist: int = 2, max_results: int = 5,
) -> list[dict]:
    """known_popular 또는 known_malicious 의 이름과 편집거리 가까운 후보.

    심리적 함정: 우리는 인기 패키지에 대한 typosquat 을 잡고 싶음.
                 → known_popular 와 비교가 더 의미 있음.
    추가로 known_malicious 와도 비교 (이미 알려진 typosquat 패턴 재발견).
    """
    p = package.lower()
    if len(p) < 3:
        return []
    candidates: list[dict] = []

    with db.cursor() as cur:
        # 1) known_popular 와 거리 비교 (rank 낮은 순으로 1000개 정도 제한)
        cur.execute("""
            SELECT package, rank FROM known_popular
            WHERE ecosystem=? AND length(package) BETWEEN ? AND ?
            ORDER BY rank LIMIT 2000
        """, (ecosystem, max(1, len(p) - max_dist), len(p) + max_dist))
        for name, rank in cur.fetchall():
            if name == p:
                continue
            d = _levenshtein(p, name, max_dist=max_dist)
            if 0 < d <= max_dist:
                sim = 1.0 - d / max(len(p), len(name))
                candidates.append({
                    "kind": "typosquat-of-popular",
                    "target": name,
                    "rank": rank,
                    "edit_distance": d,
                    "similarity": round(sim, 3),
                })

        # 2) known_malicious 와 거리 비교 (보통 매우 적음)
        cur.execute("""
            SELECT DISTINCT package FROM known_malicious
            WHERE ecosystem=? AND length(package) BETWEEN ? AND ?
            LIMIT 5000
        """, (ecosystem, max(1, len(p) - max_dist), len(p) + max_dist))
        for (name,) in cur.fetchall():
            if name == p:
                continue
            d = _levenshtein(p, name, max_dist=max_dist)
            if 0 < d <= max_dist:
                sim = 1.0 - d / max(len(p), len(name))
                candidates.append({
                    "kind": "typosquat-of-malicious",
                    "target": name,
                    "edit_distance": d,
                    "similarity": round(sim, 3),
                })

    candidates.sort(key=lambda c: (-c.get("similarity", 0)))
    return candidates[:max_results]


def _check_popular(db, ecosystem: str, package: str) -> dict | None:
    with db.cursor() as cur:
        cur.execute("""
            SELECT rank, downloads_30d, source FROM known_popular
            WHERE ecosystem=? AND lower(package)=lower(?)
        """, (ecosystem, package))
        row = cur.fetchone()
        if not row:
            return None
        return {"rank": row[0], "downloads_30d": row[1], "source": row[2]}


# ─────────────── 공개 API ───────────────

def run(
    package: str,
    ecosystem: Ecosystem,
    *,
    db=None,
) -> ThreatFilterReport:
    rpt = ThreatFilterReport()

    if db is None:
        try:
            from ..db.threat_db import get_default_db
            db = get_default_db()
        except Exception as e:
            rpt.skipped = True
            rpt.error = f"DB unavailable: {e}"
            return rpt

    eco_str = ecosystem.value if isinstance(ecosystem, Ecosystem) else str(ecosystem)

    try:
        # 1. exact
        ex = _check_exact(db, eco_str, package)
        if ex:
            rpt.exact_match = True
            rpt.advisory_id = ex["advisory_id"]
            rpt.advisory_summary = ex["summary"][:300]

        # 2. popular (먼저 체크 - 자기가 popular 면 typosquat 검사 의미 없음)
        pop = _check_popular(db, eco_str, package)
        if pop:
            rpt.popular_rank = pop["rank"]
            rpt.popular_downloads = pop["downloads_30d"]

        # 3. typosquat — 자기가 popular(top 5000) 면 skip
        if not rpt.is_popular:
            rpt.typosquat_candidates = _check_typosquat(db, eco_str, package)
    except Exception as e:
        rpt.error = f"filter error: {e}"
        rpt.skipped = True

    return rpt


# ─────────────── Evidence 변환 ───────────────

def to_evidence(rpt: ThreatFilterReport, package: str, ecosystem: str) -> list[Evidence]:
    evs: list[Evidence] = []

    if rpt.exact_match:
        evs.append(Evidence(
            file_path="<threat-feed>",
            line_start=0, line_end=0,
            code_snippet=(rpt.advisory_summary or "")[:800],
            behavior_sequence=["exact_match:known_malicious"],
            attack_dimensions=[AttackDimension.DATA_TRANSMISSION],
            ttp_id=f"{rpt.advisory_id}/T1195.002",
            ttp_name="Supply Chain Compromise: Compromise Software Supply Chain",
            ttp_source=TTPSource.GHSA,
            ttp_url=f"https://osv.dev/vulnerability/{rpt.advisory_id}",
            ttp_severity=Severity.HIGH,
            vector_similarity=1.0,
            llm_verdict=LLMVerdict.MALICIOUS,
            llm_reasoning=(
                f"This (eco={ecosystem}, pkg={package}) is on the known_malicious "
                f"feed under advisory {rpt.advisory_id}."
            ),
            llm_model="threat-filter-exact",
            confidence=0.99,
        ))

    for cand in rpt.typosquat_candidates[:3]:
        sev = Severity.MEDIUM if cand.get("similarity", 0) >= 0.85 else Severity.LOW
        evs.append(Evidence(
            file_path="<threat-feed>",
            line_start=0, line_end=0,
            code_snippet=(
                f"name {package!r} is within edit distance {cand['edit_distance']} "
                f"of {cand['target']!r} ({cand['kind']})"
            ),
            behavior_sequence=[f"typosquat:{cand['target']}"],
            attack_dimensions=[],
            ttp_id="T1036",       # Masquerading
            ttp_name="Masquerading: Typosquat / Slopsquat",
            ttp_source=TTPSource.MITRE_ATTACK,
            ttp_url="https://attack.mitre.org/techniques/T1036/",
            ttp_severity=sev,
            vector_similarity=cand.get("similarity", 0.0),
            llm_verdict=LLMVerdict.SUSPICIOUS,
            llm_reasoning=f"name suspiciously similar to {cand['target']}",
            llm_model="threat-filter-typosquat",
            confidence=min(0.9, cand.get("similarity", 0)),
        ))

    return evs
