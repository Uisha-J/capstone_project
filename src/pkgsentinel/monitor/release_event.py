"""
공통 release 이벤트 모델 + 우선순위 점수 계산.

watcher 들은 자신의 RSS/CouchDB 응답을 ReleaseEvent 로 표준화하여
priority_queue 에 넣는다. worker 는 ReleaseEvent 단위로 처리.

우선순위 점수 (낮을수록 먼저 처리, 0 ~ 1000):
  - top-10  popular: 10
  - top-100 popular: 30
  - top-1000 popular: 60
  - top-5000 popular: 90
  - 그 외: 200
  ± 보정:
  - 같은 패키지에 최근 advisory: -50 (즉시 처리)
  - 신규 패키지 (이름이 처음 등장): -20
  - typosquat 후보 (top-1000 과 거리 ≤ 2): -30
  - very small package (~50KB 미만): +20 (대부분 정상 + small lib)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class ReleaseEvent:
    """watcher 가 발견한 단일 게시 이벤트."""
    ecosystem: str                     # 'PyPI' | 'npm'
    package: str
    version: str
    archive_url: str = ""
    source_event: str = "unknown"      # 'pypi_rss','npm_changes','manual',...
    raw_meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────── 우선순위 ───────────────

# 기본 점수 (낮을수록 우선)
_DEFAULT_PRIORITY = 200
_RANK_BUCKETS = [
    (10,    10),
    (100,   30),
    (1000,  60),
    (5000,  90),
]


def compute_priority(
    *,
    rank: int | None = None,
    has_recent_advisory: bool = False,
    is_first_seen: bool = False,
    has_typosquat_signal: bool = False,
    archive_size_bytes: int | None = None,
) -> int:
    """위 표 기반 우선순위 점수. 0 (가장 우선) ~ 1000."""
    score = _DEFAULT_PRIORITY
    if rank is not None:
        for upper, p in _RANK_BUCKETS:
            if rank <= upper:
                score = p
                break

    # 보정
    if has_recent_advisory:
        score -= 50
    if is_first_seen:
        score -= 20
    if has_typosquat_signal:
        score -= 30
    if archive_size_bytes is not None and archive_size_bytes < 50 * 1024:
        score += 20

    return max(0, min(1000, score))
