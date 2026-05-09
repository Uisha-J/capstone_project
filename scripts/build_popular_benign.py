"""
build_popular_benign.py — top-N 인기 PyPI/npm 패키지를 benign fixture 로 추출.

목적
----
현 평가 코퍼스의 표본 편향 해결.
- 합성 fixture: malicious 100 / benign 20 (5:1)
- eval_real_data/fixtures.json: malicious 454 / benign 96 (4.7:1)
- 실제 생태계: 99.99%+ 가 benign — FP rate 측정에 benign 코퍼스가 결정적

본 스크립트는 공식 인기 피드에서 top-N 을 가져와 fixture 형식으로 manifest 생성.
이걸 `indicator_fp_table_real.py` 에 입력으로 주면 **현실적 FP 시그널** 산출.

소스 (이미 src/pkgsentinel/feeds/popular.py 에서 사용 중)
----
- PyPI: https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json
        (월간 갱신, BigQuery 30일 다운로드 수)
- npm:  https://anvaka.github.io/npmrank/online/npmrank.json
        (anvaka/npm-top, 정적 1000+ 랭킹)

출력
----
scripts/eval_real_data/popular_benign_manifest.json:
    {
      "generated_at": "...",
      "fixtures": [
        {"name": "boto3", "ecosystem": "PyPI", "version": "1.34.0",
         "label": "benign", "source": "popular_pypi:rank=1"},
        ...
      ],
      "counts": {"benign": N}
    }

Version 결정
----
각 패키지마다 PyPI/npm 레지스트리에서 최신 stable 버전 조회 (pre-release 제외).
이걸 manifest 의 version 필드로 박음.

사용
----
    # 기본: PyPI top 100 + npm top 100
    python scripts/build_popular_benign.py

    # 사이즈 변경
    python scripts/build_popular_benign.py --pypi-top 200 --npm-top 200

    # PyPI 만
    python scripts/build_popular_benign.py --pypi-top 100 --npm-top 0
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

USER_AGENT = "ai-slopsq/2.0 build-popular-benign"
TIMEOUT = 30

PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json"
NPM_TOP_URL = "https://anvaka.github.io/npmrank/online/npmrank.json"


def _http_json(url: str) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


# ─────────────── PyPI ───────────────

def fetch_pypi_top(n: int) -> list[tuple[int, str]]:
    """Returns list of (rank, package_name)."""
    data = _http_json(PYPI_TOP_URL)
    rows = data.get("rows") if isinstance(data, dict) else data
    out = []
    for i, row in enumerate(rows[:n], 1):
        name = row.get("project") or row.get("name") or row
        out.append((i, str(name).strip()))
    return out


def fetch_pypi_latest_version(name: str) -> str | None:
    """PyPI JSON API → info.version (latest stable)."""
    try:
        meta = _http_json(f"https://pypi.org/pypi/{name}/json")
        v = (meta.get("info") or {}).get("version")
        if v and not _is_prerelease(v):
            return v
        # info.version 이 prerelease 면 releases 키에서 stable 최신 검색
        releases = meta.get("releases") or {}
        stable = sorted(
            (k for k in releases if not _is_prerelease(k) and releases[k]),
            key=_sort_key,
            reverse=True,
        )
        return stable[0] if stable else v
    except Exception as e:
        print(f"  pypi/{name}: {e}", file=sys.stderr)
        return None


# ─────────────── npm ───────────────

# 큐레이팅된 npm top-50 fallback (npmrank 파싱 실패 시).
# 일반적으로 다운로드 수 / 의존성 수 기준 상위권. 출처:
# https://www.npmjs.com/browse/depended (관측), 핸드오프 doc 의 9-패키지 smoke 포함.
_NPM_FALLBACK_TOP = [
    "lodash", "react", "react-dom", "vue", "axios", "express", "webpack",
    "typescript", "jquery", "moment", "d3", "chalk", "commander", "debug",
    "dotenv", "yargs", "bluebird", "async", "request", "body-parser",
    "mocha", "chai", "jest", "eslint", "prettier", "@babel/core",
    "@babel/preset-env", "redux", "react-redux", "vue-router", "vuex",
    "next", "gulp", "rollup", "parcel", "ts-node", "nodemon", "pm2",
    "socket.io", "ws", "koa", "fastify", "ramda", "immutable", "rxjs",
    "three", "uuid", "minimist", "glob", "fs-extra",
]


def fetch_npm_top(n: int) -> list[tuple[int, str]]:
    """anvaka/npmrank → top-N by rank score. Fallback to curated list on parse fail."""
    try:
        data = _http_json(NPM_TOP_URL)
    except Exception as e:
        print(f"  npmrank fetch failed: {e}; using fallback list", file=sys.stderr)
        return [(i + 1, name) for i, name in enumerate(_NPM_FALLBACK_TOP[:n])]

    # anvaka/npmrank 실제 형식: {"tags": {tier_idx_str: [pkg_names]}, "rank": {...}}
    # tier_idx 가 클수록 rank 가 높음 → 역순 순회로 top-N 추출
    tags = None
    if isinstance(data, dict):
        if "tags" in data and isinstance(data["tags"], dict):
            tags = data["tags"]
        elif "rank" in data and isinstance(data["rank"], dict):
            # 일부 fork 는 rank 가 dict-of-dict 일 수 있음 — 변환
            tags = data
    if not tags:
        print("  npmrank format unexpected; using fallback", file=sys.stderr)
        return [(i + 1, name) for i, name in enumerate(_NPM_FALLBACK_TOP[:n])]

    # tier 키를 int 로 변환 후 내림차순 정렬
    try:
        tiers_sorted = sorted(
            ((int(k), v) for k, v in tags.items() if isinstance(v, list)),
            key=lambda kv: -kv[0],
        )
    except Exception as e:
        print(f"  npmrank tier sort failed: {e}; fallback", file=sys.stderr)
        return [(i + 1, name) for i, name in enumerate(_NPM_FALLBACK_TOP[:n])]

    out: list[tuple[int, str]] = []
    seen: set[str] = set()
    for _tier, pkgs in tiers_sorted:
        for pkg in pkgs:
            if pkg in seen:
                continue
            seen.add(pkg)
            out.append((len(out) + 1, pkg))
            if len(out) >= n:
                return out
    return out if out else [
        (i + 1, name) for i, name in enumerate(_NPM_FALLBACK_TOP[:n])
    ]


def fetch_npm_latest_version(name: str) -> str | None:
    """npm registry → dist-tags.latest."""
    try:
        # npm 패키지 이름이 @scope/name 형태면 URL escape 필요 (/ 살림)
        # 실제로 "@" 는 URL 안전 문자
        meta = _http_json(f"https://registry.npmjs.org/{name}")
        latest = (meta.get("dist-tags") or {}).get("latest")
        return latest
    except Exception as e:
        print(f"  npm/{name}: {e}", file=sys.stderr)
        return None


# ─────────────── prerelease 판정 ───────────────

_PRERELEASE_TOKENS = ("a", "b", "rc", "alpha", "beta", "dev", "pre")


def _is_prerelease(v: str) -> bool:
    s = v.lower()
    for t in _PRERELEASE_TOKENS:
        if t in s:
            # "1.2.3a1" / "1.2.3.dev0" / "2.0.0rc1" ...
            # 단순 substring 보다 split 으로 정확하게:
            if any(t in part for part in s.replace("-", ".").split(".")):
                return True
    return False


def _sort_key(v: str) -> tuple:
    """단순 PEP440-ish sort key — 정확한 정렬은 packaging 모듈이 정공이지만
       stdlib 만으로 가도록 단순 구현."""
    parts = []
    for chunk in v.replace("-", ".").split("."):
        try:
            parts.append((0, int(chunk)))
        except ValueError:
            parts.append((1, chunk))
    return tuple(parts)


# ─────────────── 메인 ───────────────

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--pypi-top", type=int, default=100,
                   help="PyPI top-N (0=skip)")
    p.add_argument("--npm-top", type=int, default=100,
                   help="npm top-N (0=skip)")
    p.add_argument(
        "--output",
        default=str(ROOT / "scripts" / "eval_real_data" / "popular_benign_manifest.json"),
    )
    p.add_argument("--throttle", type=float, default=0.05,
                   help="레지스트리 호출 간격 (초)")
    args = p.parse_args()

    out_path = Path(args.output).resolve()

    fixtures = []

    # PyPI
    if args.pypi_top > 0:
        print(f"Fetching PyPI top-{args.pypi_top} ranking...")
        pypi_rank = fetch_pypi_top(args.pypi_top)
        print(f"  got {len(pypi_rank)} packages")
        for i, (rank, name) in enumerate(pypi_rank, 1):
            v = fetch_pypi_latest_version(name)
            if v is None:
                continue
            fixtures.append({
                "name": name,
                "ecosystem": "PyPI",
                "version": v,
                "label": "benign",
                "source": f"popular_pypi:rank={rank}",
            })
            if args.throttle:
                time.sleep(args.throttle)
            if i % 25 == 0:
                print(f"  PyPI version-resolve {i}/{len(pypi_rank)}")
        print(f"  → {len(fixtures)} PyPI fixtures")

    # npm
    n_pypi = len(fixtures)
    if args.npm_top > 0:
        print(f"\nFetching npm top-{args.npm_top} ranking...")
        try:
            npm_rank = fetch_npm_top(args.npm_top)
            print(f"  got {len(npm_rank)} packages")
            for i, (rank, name) in enumerate(npm_rank, 1):
                v = fetch_npm_latest_version(name)
                if v is None:
                    continue
                fixtures.append({
                    "name": name,
                    "ecosystem": "npm",
                    "version": v,
                    "label": "benign",
                    "source": f"popular_npm:rank={rank}",
                })
                if args.throttle:
                    time.sleep(args.throttle)
                if i % 25 == 0:
                    print(f"  npm version-resolve {i}/{len(npm_rank)}")
            print(f"  → {len(fixtures) - n_pypi} npm fixtures")
        except Exception as e:
            print(f"  npm ranking fetch failed: {e}", file=sys.stderr)
            print("  (PyPI 부분만으로 manifest 작성)")

    # 출력
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_pypi": PYPI_TOP_URL if args.pypi_top else None,
        "source_npm": NPM_TOP_URL if args.npm_top else None,
        "counts": {
            "benign": len(fixtures),
            "pypi": sum(1 for f in fixtures if f["ecosystem"] == "PyPI"),
            "npm": sum(1 for f in fixtures if f["ecosystem"] == "npm"),
        },
        "fixtures": fixtures,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print(f"=== 완료 ===")
    print(f"  benign 합계 : {len(fixtures)}")
    print(f"    PyPI       : {payload['counts']['pypi']}")
    print(f"    npm        : {payload['counts']['npm']}")
    print(f"  Wrote: {out_path.relative_to(ROOT)}")
    print()
    print("다음 단계:")
    print(f"  python scripts/indicator_fp_table_real.py \\")
    print(f"    --manifest {out_path.relative_to(ROOT)} \\")
    print(f"    --output-md docs/2026-05-06-indicator-fp-popular-benign.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
