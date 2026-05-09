"""
패키지 기능 카테고리 분류.

목적
----
잘 알려진 합법 도구 (프레임워크 / 라이브러리 / 빌드 도구 등) 를 식별해 FP cascade
차단. 분류 결과는 다음 곳에서 사용:

  - anomaly_baseline: 분류된 패키지는 좁은 카테고리 이상 탐지 스킵
  - sequence_patterns: SP-002 같은 broad fetch+exec 패턴 차단
  - evidence/converters: 카테고리별 STANDALONE_WEAK 정책 (BROAD_PURPOSE_ONLY_WEAK)

설계 결정 (2026-05-06)
---------------------
초기 디자인은 enum 5개 (web_framework / data_science / dev_tool / bundler /
runtime) 였으나 모든 정책이 binary (broad-purpose vs unknown) 만 사용 →
enum 단순화. 도메인별 차별 정책이 실제로 필요해지면 그때 분리.

  PackageCategory:
    - BROAD_PURPOSE  (잘 알려진 합법 도구)
    - UNKNOWN        (분류 실패 / 신규 / typosquat)

분류 신호 (다중)
---------------
  1. 패키지 이름 (정확 매칭, 80+ entries)
  2. 설명 (description) phrase 매칭 (25+ phrases, word-boundary)
  3. 의존성 시그니처 (boost only)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


# ─────────────── Enum ───────────────

class PackageCategory(str, Enum):
    """패키지 카테고리 — 정책 결정에 사용되는 binary 분류."""
    BROAD_PURPOSE = "broad_purpose"   # 잘 알려진 합법 framework/library/tool
    UNKNOWN = "unknown"               # 분류 실패 / 신규 / typosquat


@dataclass
class CategoryGuess:
    """분류 결과 + 신뢰도 + 근거."""
    category: PackageCategory
    confidence: float       # 0.0 ~ 1.0
    reason: str

    @property
    def is_known(self) -> bool:
        return self.category != PackageCategory.UNKNOWN


# ─────────────── 분류 룰 (정확 매칭) ───────────────
# 잘 알려진 합법 패키지. 도메인 (web/data/dev/...) 정보는 reason 에 메모로만 남김.

_NAME_BROAD_PURPOSE: dict[str, str] = {
    # ─── web framework / API / WSGI / ASGI 서버 ───
    "flask": "web framework",
    "fastapi": "web framework",
    "django": "web framework",
    "starlette": "web framework",
    "tornado": "web framework",
    "bottle": "web framework",
    "pyramid": "web framework",
    "sanic": "web framework",
    "aiohttp": "web framework",
    "quart": "web framework",
    "uvicorn": "web framework",
    "gunicorn": "web framework",
    "werkzeug": "web framework",
    "express": "web framework",
    "koa": "web framework",
    "fastify": "web framework",
    "hapi": "web framework",
    "next": "web framework",
    "nuxt": "web framework",
    "nestjs": "web framework",
    "@nestjs/core": "web framework",

    # ─── data science / ML ───
    "numpy": "data science",
    "pandas": "data science",
    "scipy": "data science",
    "scikit-learn": "data science",
    "sklearn": "data science",
    "matplotlib": "data science",
    "seaborn": "data science",
    "statsmodels": "data science",
    "sympy": "data science",
    "torch": "data science",
    "tensorflow": "data science",
    "keras": "data science",
    "transformers": "data science",
    "datasets": "data science",
    "polars": "data science",
    "xarray": "data science",

    # ─── dev tool / build / package management / test / lint ───
    "pip": "dev tool",
    "setuptools": "dev tool",
    "wheel": "dev tool",
    "build": "dev tool",
    "poetry": "dev tool",
    "hatch": "dev tool",
    "tox": "dev tool",
    "pytest": "dev tool",
    "unittest2": "dev tool",
    "nose": "dev tool",
    "nose2": "dev tool",
    "pre-commit": "dev tool",
    "twine": "dev tool",
    "ruff": "dev tool",
    "mypy": "dev tool",
    "npm": "dev tool",
    "yarn": "dev tool",
    "pnpm": "dev tool",
    "lerna": "dev tool",
    "jest": "dev tool",
    "mocha": "dev tool",
    "eslint": "dev tool",
    "prettier": "dev tool",

    # ─── bundler / transpiler ───
    "webpack": "bundler",
    "vite": "bundler",
    "rollup": "bundler",
    "parcel": "bundler",
    "esbuild": "bundler",
    "swc": "bundler",
    "babel": "bundler",
    "@babel/core": "bundler",
    "typescript": "bundler",
    "ts-node": "bundler",
    "cython": "bundler",
    "pyodide": "bundler",

    # ─── runtime / interpreter / notebook ───
    "ipython": "interactive runtime",
    "jupyter": "interactive runtime",
    "notebook": "interactive runtime",
    "jupyterlab": "interactive runtime",
    "ptpython": "interactive runtime",
    "bpython": "interactive runtime",
}


# ─────────────── 분류 룰 (description phrase) ───────────────
# 약한 신호: 설명 문구. 정확 매칭이 없을 때 fallback.
# (phrase, confidence) — 모두 BROAD_PURPOSE 로 분류. 도메인 정보는 reason 에만.

_DESCRIPTION_PHRASES: list[tuple[str, float, str]] = [
    # web
    ("web framework", 0.9, "web framework"),
    ("application framework", 0.7, "application framework"),
    ("web server", 0.85, "web server"),
    ("http server", 0.85, "http server"),
    ("api framework", 0.8, "api framework"),
    ("rest framework", 0.8, "rest framework"),
    ("wsgi", 0.7, "wsgi"),
    ("asgi", 0.7, "asgi"),
    ("microframework", 0.85, "microframework"),
    # data science
    ("data analysis", 0.8, "data analysis"),
    ("data structures for", 0.7, "data structures library"),
    ("scientific computing", 0.85, "scientific computing"),
    ("numerical computing", 0.85, "numerical computing"),
    ("array computing", 0.85, "array computing"),
    ("machine learning", 0.9, "machine learning"),
    ("deep learning", 0.9, "deep learning"),
    ("neural network", 0.85, "neural network"),
    ("statistical computing", 0.85, "statistical computing"),
    # dev tool
    ("build system", 0.85, "build system"),
    ("build tool", 0.85, "build tool"),
    ("packaging tool", 0.85, "packaging tool"),
    ("package manager", 0.9, "package manager"),
    ("test framework", 0.85, "test framework"),
    ("testing framework", 0.85, "testing framework"),
    ("linter", 0.7, "linter"),
    ("type checker", 0.85, "type checker"),
    # bundler / transpiler
    ("module bundler", 0.95, "module bundler"),
    ("javascript bundler", 0.95, "javascript bundler"),
    ("transpiler", 0.85, "transpiler"),
    ("compiler for", 0.7, "compiler"),
    # runtime
    ("interactive shell", 0.9, "interactive shell"),
    ("interactive computing", 0.85, "interactive computing"),
    ("notebook environment", 0.9, "notebook environment"),
    ("repl", 0.7, "repl"),
]


# ─────────────── 분류 룰 (의존성 시그니처) ───────────────
# 매우 약한 신호: 의존성이 broad-purpose 도구 시사. boost 용.

_DEP_HINTS: set[str] = {
    "asgiref", "starlette", "uvicorn", "gunicorn", "werkzeug",
    "click", "build", "wheel",
    "numpy", "scipy", "pandas",
}


# ─────────────── 메인 분류 함수 ───────────────

def classify(
    package_name: str,
    description: str = "",
    declared_deps: list[str] | None = None,
) -> CategoryGuess:
    """패키지를 BROAD_PURPOSE 또는 UNKNOWN 으로 분류.

    여러 신호 조합:
      1. 정확 패키지명 매칭 (가장 강한 신호, confidence 1.0)
      2. description phrase 매칭 (word-boundary, confidence 0.7~0.9)
      3. 의존성 시그니처 (약한 신호, confidence boost only)

    분류 실패 시 PackageCategory.UNKNOWN.
    """
    declared_deps = declared_deps or []
    name_lower = (package_name or "").strip().lower()
    desc_lower = (description or "").lower()
    dep_lower = {(d or "").strip().lower() for d in declared_deps}

    # 1. 정확 패키지명 매칭
    if name_lower in _NAME_BROAD_PURPOSE:
        domain = _NAME_BROAD_PURPOSE[name_lower]
        return CategoryGuess(
            category=PackageCategory.BROAD_PURPOSE,
            confidence=1.0,
            reason=f"exact name match: {name_lower!r} ({domain})",
        )

    # 2. description phrase 매칭
    desc_matches: list[tuple[float, str]] = []
    for phrase, conf, domain in _DESCRIPTION_PHRASES:
        if re.search(r"\b" + re.escape(phrase) + r"\b", desc_lower):
            desc_matches.append((conf, domain))

    # 3. 의존성 시그니처 (boost 용)
    dep_hit = bool(dep_lower & _DEP_HINTS)

    if desc_matches:
        # 가장 높은 confidence 의 phrase 매칭 선택
        desc_matches.sort(key=lambda x: -x[0])
        conf, domain = desc_matches[0]
        if dep_hit:
            conf = min(1.0, conf + 0.1)
            reason = f"description phrase ({domain}) + dep signal"
        else:
            reason = f"description phrase ({domain})"
        return CategoryGuess(
            category=PackageCategory.BROAD_PURPOSE,
            confidence=conf,
            reason=reason,
        )

    # description 신호 없을 때, 의존성 단독으로는 분류 안 함 (FP 우려).

    return CategoryGuess(
        category=PackageCategory.UNKNOWN,
        confidence=0.0,
        reason="no exact name / description / dep evidence",
    )


# ─────────────── 헬퍼 ───────────────

def is_broad_purpose(guess: CategoryGuess, min_confidence: float = 0.6) -> bool:
    """이 분류가 broad-purpose 이고 신뢰도 임계 이상인가."""
    return (
        guess.category == PackageCategory.BROAD_PURPOSE
        and guess.confidence >= min_confidence
    )


# 호환성 별칭 (이전 코드가 사용했던 set)
BROAD_PURPOSE_CATEGORIES = frozenset({PackageCategory.BROAD_PURPOSE})


# 2026-05-06: BROAD_PURPOSE 패키지에서만 약한 신호로 처리할 indicator 코드.
# popular-benign N=300 측정에서 FP rate ≥ 5% 였지만 unknown 카테고리의 진짜
# 악성 패턴 (ssh-key-theft 등) 에선 핵심 신호.
# → BROAD_PURPOSE 일 때만 STANDALONE_WEAK 처리, UNKNOWN 카테고리엔 full severity.
BROAD_PURPOSE_ONLY_WEAK_INDICATORS: frozenset[str] = frozenset({
    "EXM-002",   # platform conditional check — cross-platform 도구에 빈번
    "SYS-002",   # .bashrc/crontab 키워드 — 합법 shell completion 안내
    "EXM-008",   # subprocess.run — 빌드/테스트/CLI 도구
    "EXM-003",   # ctypes.CDLL — 정상 native binding
    "EXS-002",   # setup.py top-level — 거의 모든 패키지
    "EXM-006",   # dev-mode self-install — pip 등
    "EXF-001",   # info+transmit — telemetry/error reporter
    "SYS-001",   # PATH 조작 — cross-platform 도구
    "NET-009",   # verify=False — 사내 cert 환경
    "NET-010",   # http:// URL — 테스트/예제 코드 빈번
})


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    samples = [
        ("flask", "A simple framework for building complex web applications"),
        ("fastapi", "FastAPI framework, high performance, easy to learn"),
        ("django", "A high-level Python web framework"),
        ("numpy", "Fundamental package for array computing in Python"),
        ("pandas", "Powerful data structures for data analysis, time series, and statistics"),
        ("webpack", "Packs ECMAScript/CommonJs/AMD modules for the browser"),
        ("typescript", "TypeScript is a superset of JavaScript"),
        ("ipython", "Interactive computing in Python"),
        ("requests", "HTTP for humans"),
        ("evil-stealer", "Cute file utility"),
    ]
    for name, desc in samples:
        g = classify(name, desc)
        marker = "OK " if g.is_known else "?? "
        print(f"  {marker} {name:<22s} -> {g.category.value:<14s} conf={g.confidence:.2f}  ({g.reason})")
