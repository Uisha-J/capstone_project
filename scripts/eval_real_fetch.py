"""
Real malicious / benign 패키지 아카이브 다운로더.

소스:
  - 악성 : DataDog/malicious-software-packages-dataset (zip + password "infected")
            * malicious_intent  : 등록 자체가 악성 (slopsquat, typosquat 포함)
            * compromised_lib   : 합법 패키지의 침해 버전 (event-stream / xz / ua-parser 류
                                   "유명 패키지 공격" 카테고리)
  - 정상 : PyPI / npm registry JSON API → 인기 패키지의 최신 sdist
            (top-popular 정렬은 src/pkgsentinel/benchmarks/sample_dataset.csv 의
             benign 라벨 + 추가 인기 패키지로 구성)

이 스크립트는 zip 을 다운로드만 하고 fixtures.json 에 메타데이터만 기록.
실제 소스 추출은 eval_real.py 에서 수행 (재실행 효율).

캐시 위치: scripts/eval_real_data/cache/ (.gitignore 에 추가 권장)
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "scripts" / "eval_real_data"
CACHE_DIR = DATA_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

UA = "pkgsentinel-eval/1.0 (research)"
TIMEOUT = 60


# ─────────────── Fixture 메타 ───────────────

@dataclass
class FixtureMeta:
    name: str                      # 패키지명
    ecosystem: str                 # "PyPI" | "npm"
    version: str
    label: str                     # "malicious" | "benign"
    source: str                    # "datadog/malicious_intent" | "datadog/compromised_lib" | "registry"
    archive_path: str              # 캐시 디렉터리 기준 상대 경로
    archive_format: str            # "zip+password" | "tar.gz" | "tgz"
    archive_inner: Optional[str] = None   # 패스워드 zip 내부의 실제 패키지 아카이브 이름
    archive_size: int = 0
    sha256: str = ""
    note: str = ""


# ─────────────── HTTP 헬퍼 ───────────────

def _http_get(url: str, max_retries: int = 3) -> bytes:
    last_err = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                raise
            last_err = e
        except Exception as e:
            last_err = e
        time.sleep(1 + attempt)
    raise RuntimeError(f"failed to fetch {url}: {last_err}")


def _http_json(url: str) -> dict:
    return json.loads(_http_get(url).decode("utf-8"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ─────────────── DataDog 데이터셋 ───────────────

DATADOG_BASE = (
    "https://raw.githubusercontent.com/"
    "DataDog/malicious-software-packages-dataset/main"
)
DATASET_REPO = DATA_DIR / "dataset_repo"
DATASET_INDEX = DATA_DIR / "dataset_files.txt"


def _ensure_dataset_index() -> Path:
    """sparse clone 으로 zip 경로 목록 인덱스를 만든다.

    - 이미 dataset_files.txt 있으면 그대로 사용
    - dataset_repo 에 .git 만 있으면 ls-tree 로 인덱스 갱신
    - 없으면 git clone --filter=blob:none --depth=1 --no-checkout
    """
    if DATASET_INDEX.exists() and DATASET_INDEX.stat().st_size > 0:
        return DATASET_INDEX

    if not (DATASET_REPO / ".git").exists():
        print(f"  cloning dataset metadata to {DATASET_REPO} (no blobs)...")
        os.system(
            "git clone --filter=blob:none --depth=1 --no-checkout "
            "https://github.com/DataDog/malicious-software-packages-dataset.git "
            f'"{DATASET_REPO}"'
        )

    print(f"  building file index -> {DATASET_INDEX}")
    # ls-tree --name-only 는 blob 사이즈를 읽지 않아 빠름 (수만 파일 < 수초).
    # 사이즈 정보가 필요하면 _download 시점에 HEAD 요청으로 대체.
    import subprocess
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"],
        cwd=DATASET_REPO,
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git ls-tree failed: {result.stderr[:500]}")
    lines = []
    for path in result.stdout.splitlines():
        if not (path.startswith("samples/pypi/") or path.startswith("samples/npm/")):
            continue
        if not path.endswith(".zip"):
            continue
        # size 컬럼은 0 으로 채우고 추후 다운로드 시 결정 — 인덱스 빌드 시간 우선
        lines.append(f"0\t{path}")
    DATASET_INDEX.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return DATASET_INDEX


def _enumerate_datadog(ecosystem: str, kind: str) -> list[dict]:
    """인덱스 파일에서 ecosystem/kind 에 속하는 zip 항목들을 파싱."""
    _ensure_dataset_index()
    eco_short = "pypi" if ecosystem == "pypi" else "npm"
    prefix = f"samples/{eco_short}/{kind}/"
    out = []
    for line in DATASET_INDEX.read_text(encoding="utf-8").splitlines():
        if "\t" not in line:
            continue
        size_s, path = line.split("\t", 1)
        if not path.startswith(prefix):
            continue
        # path: samples/pypi/malicious_intent/<pkg>/<version>/<file>.zip
        rel = path[len(prefix):]
        parts = rel.split("/")
        if len(parts) < 3:
            continue
        pkg_dir, version_dir, fname = parts[0], parts[1], parts[-1]
        try:
            size = int(size_s)
        except ValueError:
            size = 0
        out.append({
            "raw_dir_name": pkg_dir,
            # npm scoped 패키지 복원: '@scope@name' -> '@scope/name'
            "name": (
                "@" + pkg_dir[1:].replace("@", "/", 1)
                if pkg_dir.startswith("@")
                else pkg_dir
            ),
            "version": version_dir,
            "url": f"{DATADOG_BASE}/{path}",
            "size": size,
            "ecosystem": "PyPI" if eco_short == "pypi" else "npm",
            "source": f"datadog/{kind}",
        })
    return out


def _pick_datadog_samples(
    ecosystem: str, kind: str, limit: int, seed: int = 42,
    max_attempts_factor: int = 3,
) -> list[dict]:
    """인덱스에서 limit 개 무작위 zip 선택.

    인덱스에는 size 정보가 없으므로 다운로드 시점에 size 검사를 통해
    너무 큰 (>10MB) 항목은 스킵. limit 채우기 위해 max_attempts_factor 만큼
    여유 후보를 셔플해서 반환.
    """
    candidates = _enumerate_datadog(ecosystem, kind)
    rng = random.Random(seed)
    rng.shuffle(candidates)
    return candidates[: limit * max_attempts_factor]


def fetch_datadog_pypi_malicious(limit: int = 30, seed: int = 42) -> list[dict]:
    return _pick_datadog_samples("pypi", "malicious_intent", limit, seed)


def fetch_datadog_pypi_compromised(limit: int = 6, seed: int = 42) -> list[dict]:
    return _pick_datadog_samples("pypi", "compromised_lib", limit, seed)


def fetch_datadog_npm_malicious(limit: int = 10, seed: int = 42) -> list[dict]:
    return _pick_datadog_samples("npm", "malicious_intent", limit, seed)


def fetch_datadog_npm_compromised(limit: int = 10, seed: int = 42) -> list[dict]:
    return _pick_datadog_samples("npm", "compromised_lib", limit, seed)


# ─────────────── PyPI / npm 정상 패키지 ───────────────

# 학교 capstone 평가용 — 실제 광범위하게 신뢰되는 패키지들.
# 이 명단은 대부분 OpenSSF Critical Project / Tidelift / 다운로드 상위 100 에 포함됨.
PYPI_BENIGN = [
    # 코어 / 표준
    "requests", "urllib3", "setuptools", "pip", "wheel", "build",
    "packaging", "certifi", "idna", "charset-normalizer",
    # 웹 프레임워크
    "flask", "django", "fastapi", "starlette", "uvicorn",
    "werkzeug", "jinja2", "markupsafe", "itsdangerous", "blinker",
    # 데이터 / 과학
    "numpy", "pandas", "scipy", "matplotlib", "seaborn",
    "scikit-learn", "scikit-image",
    # 테스트 / 품질
    "pytest", "pytest-cov", "pytest-xdist", "tox", "coverage",
    "hypothesis", "mock", "freezegun",
    # CLI / TUI
    "click", "rich", "tqdm", "typer", "colorama",
    "tabulate",
    # 직렬화 / 검증
    "pyyaml", "pydantic", "jsonschema", "msgpack", "orjson",
    # DB / ORM
    "sqlalchemy", "alembic", "redis",
    # HTTP 클라이언트
    "httpx", "aiohttp", "websockets",
    # 보안 / 암호
    "cryptography", "bcrypt", "passlib",
    # 클라우드 / AWS
    "boto3", "botocore", "s3transfer",
    # 이미지 / 파일
    "pillow", "lxml", "openpyxl",
    # AI / ML
    "openai", "anthropic", "tiktoken",
    # 기타 인기
    "beautifulsoup4", "selenium", "celery", "kombu", "amqp",
    "structlog", "loguru", "tenacity", "more-itertools",
]

NPM_BENIGN = [
    # 프레임워크 / UI
    "react", "react-dom", "vue", "angular", "svelte",
    # 유틸리티
    "lodash", "underscore", "ramda", "date-fns", "moment",
    # HTTP / 네트워크
    "axios", "node-fetch", "got", "ws",
    # 빌드 / 도구
    "typescript", "webpack", "rollup", "vite", "esbuild",
    # 린팅 / 포맷
    "eslint", "prettier", "stylelint",
    # 서버 / 미들웨어
    "express", "koa", "fastify",
    # 색상 / CLI
    "chalk", "commander", "yargs", "inquirer",
    # 테스트
    "jest", "mocha",
]


def fetch_pypi_benign(limit: int = 30) -> list[dict]:
    out = []
    for name in PYPI_BENIGN[:limit]:
        try:
            meta = _http_json(f"https://pypi.org/pypi/{name}/json")
            info = meta.get("info") or {}
            v = info.get("version") or ""
            urls = meta.get("urls") or []
            sdist = next(
                (u for u in urls if u.get("packagetype") == "sdist"), None
            )
            if not sdist:
                # wheel 만 있으면 wheel
                sdist = next((u for u in urls if u.get("filename")), None)
            if not sdist:
                continue
            out.append({
                "name": name,
                "version": v,
                "url": sdist["url"],
                "size": sdist.get("size", 0),
                "ecosystem": "PyPI",
                "source": "registry",
            })
        except Exception as e:
            print(f"  skip benign pypi {name}: {e}", file=sys.stderr)
    return out


def fetch_npm_benign(limit: int = 10) -> list[dict]:
    out = []
    for name in NPM_BENIGN[:limit]:
        try:
            meta = _http_json(f"https://registry.npmjs.org/{name}")
            latest = (meta.get("dist-tags") or {}).get("latest")
            if not latest:
                continue
            ver_meta = (meta.get("versions") or {}).get(latest) or {}
            tarball = (ver_meta.get("dist") or {}).get("tarball")
            if not tarball:
                continue
            out.append({
                "name": name,
                "version": latest,
                "url": tarball,
                "size": (ver_meta.get("dist") or {}).get("unpackedSize", 0),
                "ecosystem": "npm",
                "source": "registry",
            })
        except Exception as e:
            print(f"  skip benign npm {name}: {e}", file=sys.stderr)
    return out


# ─────────────── 실제 다운로드 ───────────────

MAX_ARCHIVE_SIZE = 10 * 1024 * 1024  # 10MB


def _download(entry: dict, label: str) -> Optional[FixtureMeta]:
    cache_subdir = CACHE_DIR / entry["ecosystem"].lower() / label
    cache_subdir.mkdir(parents=True, exist_ok=True)

    # 캐시 키: name-version.<ext>
    base_name = entry["name"].replace("/", "_").replace("@", "_")
    url_lower = entry["url"].lower()
    if url_lower.endswith(".zip"):
        ext = ".zip"
        archive_format = "zip+password" if entry["source"].startswith("datadog/") else "zip"
    elif url_lower.endswith(".tar.gz") or url_lower.endswith(".tgz"):
        ext = ".tar.gz" if url_lower.endswith(".tar.gz") else ".tgz"
        archive_format = "tar.gz" if ext == ".tar.gz" else "tgz"
    elif url_lower.endswith(".whl"):
        ext = ".whl"
        archive_format = "wheel"
    else:
        # 기본 추정
        ext = ".bin"
        archive_format = "unknown"

    cache_path = cache_subdir / f"{base_name}-{entry['version']}{ext}"
    if cache_path.exists() and cache_path.stat().st_size > 0:
        data = cache_path.read_bytes()
    else:
        try:
            data = _http_get(entry["url"])
        except Exception as e:
            print(f"  fail {entry['name']}: {e}", file=sys.stderr)
            return None
        if len(data) > MAX_ARCHIVE_SIZE:
            print(
                f"  skip {entry['name']} (too large: {len(data)/1024/1024:.1f}MB)",
                file=sys.stderr,
            )
            return None
        cache_path.write_bytes(data)

    return FixtureMeta(
        name=entry["name"],
        ecosystem=entry["ecosystem"],
        version=entry["version"],
        label=label,
        source=entry["source"],
        archive_path=str(cache_path.relative_to(DATA_DIR)).replace("\\", "/"),
        archive_format=archive_format,
        archive_size=len(data),
        sha256=_sha256(data),
        note="",
    )


# ─────────────── 메인 ───────────────

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--mal-pypi", type=int, default=30,
                    help="DataDog PyPI malicious_intent 샘플 수")
    ap.add_argument("--mal-pypi-compromised", type=int, default=6,
                    help="DataDog PyPI compromised_lib 샘플 수 (전부 6개)")
    ap.add_argument("--mal-npm", type=int, default=15,
                    help="DataDog npm malicious_intent 샘플 수")
    ap.add_argument("--mal-npm-compromised", type=int, default=10,
                    help="DataDog npm compromised_lib 샘플 수 — 유명 패키지 침해")
    ap.add_argument("--ben-pypi", type=int, default=30,
                    help="PyPI benign 샘플 수")
    ap.add_argument("--ben-npm", type=int, default=10,
                    help="npm benign 샘플 수")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    print("=== Fetching malicious samples (DataDog) ===")
    mal_entries = []

    if args.mal_pypi > 0:
        print(f"  PyPI / malicious_intent (limit={args.mal_pypi})...")
        mal_entries += fetch_datadog_pypi_malicious(args.mal_pypi, args.seed)

    if args.mal_pypi_compromised > 0:
        print(f"  PyPI / compromised_lib (limit={args.mal_pypi_compromised})...")
        mal_entries += fetch_datadog_pypi_compromised(
            args.mal_pypi_compromised, args.seed,
        )

    if args.mal_npm > 0:
        print(f"  npm / malicious_intent (limit={args.mal_npm})...")
        mal_entries += fetch_datadog_npm_malicious(args.mal_npm, args.seed)

    if args.mal_npm_compromised > 0:
        print(f"  npm / compromised_lib (limit={args.mal_npm_compromised})...")
        mal_entries += fetch_datadog_npm_compromised(
            args.mal_npm_compromised, args.seed,
        )

    print(f"  total malicious entries selected: {len(mal_entries)}")

    print("\n=== Fetching benign samples (registry) ===")
    ben_entries = []
    if args.ben_pypi > 0:
        print(f"  PyPI benign (limit={args.ben_pypi})...")
        ben_entries += fetch_pypi_benign(args.ben_pypi)
    if args.ben_npm > 0:
        print(f"  npm benign (limit={args.ben_npm})...")
        ben_entries += fetch_npm_benign(args.ben_npm)
    print(f"  total benign entries selected: {len(ben_entries)}")

    print("\n=== Downloading archives ===")
    fixtures: list[FixtureMeta] = []

    # 카테고리(source)별로 실제 타겟 개수만 확보 — 큰 zip 으로 스킵돼도 다음 후보 사용
    targets = {
        "datadog/malicious_intent_pypi":     args.mal_pypi,
        "datadog/compromised_lib_pypi":      args.mal_pypi_compromised,
        "datadog/malicious_intent_npm":      args.mal_npm,
        "datadog/compromised_lib_npm":       args.mal_npm_compromised,
    }
    counts: dict[str, int] = {k: 0 for k in targets}
    for entry in mal_entries:
        cat = f"{entry['source']}_{entry['ecosystem'].lower()}"
        cat = cat.replace("PyPI_pypi", "PyPI").replace("npm_npm", "npm")
        # 정규화: source already starts with datadog/<kind>
        eco_suffix = "pypi" if entry["ecosystem"] == "PyPI" else "npm"
        cat = f"{entry['source']}_{eco_suffix}"
        if cat not in targets:
            continue
        if counts[cat] >= targets[cat]:
            continue
        meta = _download(entry, "malicious")
        if meta:
            fixtures.append(meta)
            counts[cat] += 1
    for entry in ben_entries:
        meta = _download(entry, "benign")
        if meta:
            fixtures.append(meta)
    print(f"  malicious downloaded by category: {counts}")

    # 메타 저장
    fixtures_path = DATA_DIR / "fixtures.json"
    payload = {
        "fixtures": [asdict(f) for f in fixtures],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "counts": {
            "malicious": sum(1 for f in fixtures if f.label == "malicious"),
            "benign":    sum(1 for f in fixtures if f.label == "benign"),
        },
    }
    fixtures_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8",
    )

    print(f"\nFixtures saved: {fixtures_path}")
    print(f"  malicious: {payload['counts']['malicious']}")
    print(f"  benign   : {payload['counts']['benign']}")

    total_size = sum(f.archive_size for f in fixtures)
    print(f"  total cache size: {total_size / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
