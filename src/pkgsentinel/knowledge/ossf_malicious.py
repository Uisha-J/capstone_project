"""OSSF malicious-packages feed 통합.

근거: https://github.com/ossf/malicious-packages (Apache 2.0)
- OSSF Securing Software Repositories WG 가 큐레이션
- OSV 포맷 JSON advisory — 우리 OSV 파서 그대로 재사용
- 카테고리 라벨이 OSV 보다 풍부 (특히 slopsquatting / dependency-confusion 명시적)

흐름:
  1. tarball 다운로드 (GitHub: ossf/malicious-packages 의 default branch tar.gz)
  2. osv/malicious/<ecosystem>/<...>/*.json 패턴 파일들 추출
  3. _parse_advisory (osv.py 의 함수) 로 AttackPattern 으로 변환
  4. cache/ossf_malicious_<ecosystem>.json 으로 저장

attack_index.get_index() 에서 OSV cache 와 *함께* 로드 — 패턴 합집합.
"""
from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.request
from collections import Counter
from pathlib import Path

from .osv import AttackPattern, _parse_advisory, save_patterns

# GitHub tarball URL — default branch (main) 전체.
# 작은 repo (수십 MB). 5분 cache TTL 권장 (refresh-feeds.timer 가 일일 갱신).
OSSF_TARBALL_URL = (
    "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz"
)

# 파일 경로 패턴 — repo 내부의 advisory 위치.
# 형식: osv/malicious/<ecosystem-lower>/<package>/<version>/<id>.json
# ecosystem 디렉터리명: npm, pypi, rubygems, crates-io, packagist, ...
_OSV_PATH_RE = re.compile(
    r"^[^/]+/osv/malicious/([^/]+)/.*\.json$",
    re.IGNORECASE,
)


def _ecosystem_dir_to_label(dir_name: str) -> str | None:
    """repo 의 디렉터리명 → 우리 ecosystem 라벨."""
    d = dir_name.lower()
    if d in ("pypi", "py"):
        return "PyPI"
    if d == "npm":
        return "npm"
    # 다른 ecosystem 은 본 프로젝트가 분석 안 함 → skip
    return None


def _download_tarball(url: str = OSSF_TARBALL_URL, timeout: int = 120) -> bytes:
    print(f"[OSSF-mal] downloading {url}")
    req = urllib.request.Request(
        url, headers={"User-Agent": "pkgsentinel/2.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _iter_advisories_from_tarball(
    tar_bytes: bytes,
    ecosystem_filter: str | None = None,
):
    """tarball 에서 OSV-format JSON 파일들을 ecosystem 별로 yield.

    Yields:
      (ecosystem_label, advisory_dict)
    """
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            m = _OSV_PATH_RE.match(member.name.replace("\\", "/"))
            if not m:
                continue
            eco_dir = m.group(1)
            eco_label = _ecosystem_dir_to_label(eco_dir)
            if eco_label is None:
                continue
            if ecosystem_filter and eco_label != ecosystem_filter:
                continue
            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                data = f.read()
                raw = json.loads(data.decode("utf-8"))
            except Exception:
                continue
            yield eco_label, raw


def collect_ossf_malicious(
    ecosystem: str | None = None,
    limit: int | None = None,
) -> dict[str, list[AttackPattern]]:
    """OSSF malicious-packages 전체 또는 단일 ecosystem 수집.

    반환: {ecosystem: [AttackPattern, ...]}.
    """
    tar_bytes = _download_tarball()
    by_eco: dict[str, list[AttackPattern]] = {}
    counts: Counter = Counter()
    for eco_label, raw in _iter_advisories_from_tarball(
        tar_bytes, ecosystem_filter=ecosystem,
    ):
        ap = _parse_advisory(raw, eco_label)
        # AttackPattern 의 source 필드를 "OSV" → "OSSF" 로 표기 변경
        # — 출처 추적용. 분석 로직은 OSV 와 동일.
        if ap is None:
            continue
        ap.source = "OSSF"
        by_eco.setdefault(eco_label, []).append(ap)
        counts[eco_label] += 1
        if limit and counts[eco_label] >= limit:
            # ecosystem 당 limit 적용 — 단일 ecosystem 모드면 즉시 break
            if ecosystem is not None:
                break
    print(f"[OSSF-mal] collected {dict(counts)} advisories")
    return by_eco


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    ecosystem_arg = sys.argv[1] if len(sys.argv) > 1 else None
    limit_arg = int(sys.argv[2]) if len(sys.argv) > 2 else None

    by_eco = collect_ossf_malicious(
        ecosystem=ecosystem_arg, limit=limit_arg,
    )

    cache_dir = Path(__file__).parent / "cache"
    for eco, patterns in by_eco.items():
        out = cache_dir / f"ossf_malicious_{eco.lower()}.json"
        save_patterns(patterns, out)

    # 통계
    for eco, patterns in by_eco.items():
        type_counts = Counter(p.attack_type for p in patterns)
        print(f"\n[{eco}] 공격 유형 분포: {dict(type_counts)}")
