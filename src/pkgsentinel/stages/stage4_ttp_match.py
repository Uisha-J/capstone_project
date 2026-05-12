"""
Stage 4 — Behavior Sequence 를 지식 DB (MITRE 등) 의 TTP 와 매칭.

각 FileSequence 단위로:
  1. 시퀀스를 자연어 설명으로 변환
  2. Sentence-Transformer 임베딩
  3. 로컬 인덱스에서 Top-K TTP 검색
  4. 유사도 임계값 이상이면 후보 TTP 리스트 반환

임계값:
  - 0.70 이상: 후보 매칭
  - 0.85 이상: 강한 매칭 (HIGH_RISK 조건에 사용)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..knowledge.embedder import TTPIndex
from ..knowledge.mitre_attack import load_cached
from ..schema import AttackDimension, TTPEntry
from .stage2_behavior import BehaviorReport, FileSequence
from .stage4_rules import apply_rules, rule_hit_to_ttp_entry

WEAK_THRESHOLD = 0.50     # 이보다 낮으면 무시 (noise)
STRONG_THRESHOLD = 0.70   # 후보로 취함
VERY_STRONG_THRESHOLD = 0.85   # HIGH_RISK 조건


# ─────────────── 결과 구조 ───────────────

@dataclass
class TTPMatch:
    file_path: str
    sequence: list[str]
    dimensions: list[AttackDimension]
    ttp: TTPEntry
    similarity: float
    sequence_text: str   # 자연어 변환된 시퀀스 설명

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "sequence": list(self.sequence),
            "dimensions": [d.value for d in self.dimensions],
            "ttp": self.ttp.to_dict(),
            "similarity": self.similarity,
            "sequence_text": self.sequence_text,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TTPMatch:
        return cls(
            file_path=d["file_path"],
            sequence=list(d.get("sequence", [])),
            dimensions=[AttackDimension(v) for v in d.get("dimensions", [])],
            ttp=TTPEntry.from_dict(d["ttp"]),
            similarity=float(d.get("similarity", 0.0)),
            sequence_text=d.get("sequence_text", ""),
        )


@dataclass
class TTPMatchReport:
    matches: list[TTPMatch] = field(default_factory=list)

    @property
    def has_strong_match(self) -> bool:
        return any(m.similarity >= VERY_STRONG_THRESHOLD for m in self.matches)

    def to_dict(self) -> dict:
        return {"matches": [m.to_dict() for m in self.matches]}

    @classmethod
    def from_dict(cls, d: dict) -> TTPMatchReport:
        return cls(matches=[TTPMatch.from_dict(m) for m in d.get("matches", [])])


# ─────────────── 시퀀스 → 자연어 변환 ───────────────

_DIM_PHRASES = {
    AttackDimension.INFORMATION_READING: "read sensitive data",
    AttackDimension.ENCODING: "obfuscate or encode content",
    AttackDimension.PAYLOAD_EXECUTION: "execute dynamic code",
    AttackDimension.DATA_TRANSMISSION: "transmit data to remote endpoint",
}


def sequence_to_text(fs: FileSequence) -> str:
    """시퀀스를 LLM/임베딩 모델이 이해하기 좋은 문장으로 변환."""
    if not fs.calls:
        return ""

    # 차원 요약 문장
    dims_summary = ", ".join(
        _DIM_PHRASES.get(d, d.value) for d in fs.dimensions
    )

    # API 호출 체인
    chain = " -> ".join(c.name for c in fs.calls)

    return (
        f"The following behavior sequence in {fs.path} ({fs.language}) "
        f"performs: {dims_summary}. "
        f"Call chain: {chain}"
    )


# ─────────────── 인덱스 로드 ───────────────

@lru_cache(maxsize=1)
def _load_index() -> TTPIndex:
    cache_dir = Path(__file__).resolve().parent.parent / "knowledge" / "cache"
    emb_path = cache_dir / "mitre_attack_embedded.json"
    if not emb_path.exists():
        raise FileNotFoundError(
            "임베딩된 TTP 캐시가 없습니다. 먼저 아래 명령으로 생성하세요:\n"
            "  python -m detector.knowledge.embedder"
        )
    entries = load_cached(emb_path)
    return TTPIndex(entries)


# ─────────────── 메인 ───────────────

def match_ttps(behavior: BehaviorReport, top_k: int = 3) -> TTPMatchReport:
    report = TTPMatchReport()

    try:
        index = _load_index()
    except FileNotFoundError:
        # 지식 DB 준비 안 됨 → Stage ERROR 처리 상위에서 결정
        raise

    for fs in behavior.files:
        if not fs.calls:
            continue

        text = sequence_to_text(fs)

        # 1. 임베딩 기반 Top-K
        hits = index.query_text(text, top_k=top_k)
        for ttp, sim in hits:
            if sim < STRONG_THRESHOLD:
                continue
            report.matches.append(TTPMatch(
                file_path=fs.path,
                sequence=fs.sequence,
                dimensions=fs.dimensions,
                ttp=ttp,
                similarity=sim,
                sequence_text=text,
            ))

        # 2. 규칙 기반 매칭 (임베딩이 놓치는 패턴 보강)
        for hit in apply_rules(fs):
            ttp = rule_hit_to_ttp_entry(hit)
            # 규칙 적중은 유사도 1.0 으로 간주 (결정적 매칭)
            report.matches.append(TTPMatch(
                file_path=fs.path,
                sequence=fs.sequence,
                dimensions=fs.dimensions,
                ttp=ttp,
                similarity=1.0,
                sequence_text=f"[rule] {hit.rule.reason}",
            ))

    return report


# ─────────────── CLI 테스트 ───────────────

if __name__ == "__main__":
    import sys

    from ..schema import Ecosystem
    from .stage0_registry import check
    from .stage1_entry_point import extract
    from .stage2_behavior import analyze

    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    v = info.latest_version
    url = info.archive_urls.get(v)
    ext = extract(pkg, eco, v, url)
    behavior = analyze(ext)

    report = match_ttps(behavior)
    print(f"\n=== {pkg} {v} TTP matches (threshold {STRONG_THRESHOLD}) ===")
    if not report.matches:
        print("  (no TTP match above threshold)")
    for m in report.matches:
        strong = " 🔥" if m.similarity >= VERY_STRONG_THRESHOLD else ""
        print(f"\n{m.file_path}")
        print(f"  {m.ttp.ttp_id} — {m.ttp.ttp_name}  (sim {m.similarity:.3f}){strong}")
        print(f"  sequence: {' → '.join(m.sequence[:5])}")
