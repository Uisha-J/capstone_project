"""
패키지 기능 카테고리 분류.

목적
----
좁은 anomaly_baseline 카테고리 (parser/formatter/date/math) 와 별개로,
**기능 도메인** 단위 분류:
  - web_framework      : HTTP 서빙, 라우팅, 요청 처리 (flask/django/fastapi/express ...)
  - data_science       : 수치/통계/ML 라이브러리 (numpy/pandas/scipy/sklearn/torch ...)
  - dev_tool           : 빌드/패키징/테스트 도구 (pip/setuptools/poetry/pytest ...)
  - bundler_transpiler : 코드 변환/번들링 (webpack/babel/typescript/vite ...)
  - runtime_interpreter: 인터랙티브/REPL/노트북 (ipython/jupyter/cython ...)

이런 카테고리에 속한 패키지는 **자기 도메인의 합법 동작** 으로 위험 차원 호출이 빈번:
  - web_framework: HTTP 송수신 (DATA_TRANSMISSION) + 동적 라우팅 (PAYLOAD_EXECUTION) 정상
  - data_science: 외부 데이터 fetch + ML 모델 로드 정상
  - dev_tool: subprocess + 파일 조작 정상
  - bundler: eval-like 코드 평가 정상

본 모듈은 분류만 함 — 분류 결과를 어떻게 활용할지는 호출자 결정:
  - anomaly_baseline: 분류된 패키지는 좁은 카테고리 이상 탐지 스킵
  - evidence/converters: 카테고리별 STANDALONE_WEAK 확장
  - report.package_meta: 분류 결과 노출 (UI / 디버깅용)

분류 신호 (다중)
---------------
  1. 패키지 이름 (정확 매칭, e.g. 'flask' / 'fastapi')
  2. 설명 (description) 의 phrase 매칭 (e.g. 'web framework')
  3. 의존성 (declared_deps) 의 시그니처 (e.g. 'asgiref' -> web_framework)

설계 원칙
--------
- 분류 실패 (= unknown) 가 default. **추정에 자신 있을 때만 분류**.
- 한 패키지는 1 카테고리만. 충돌 시 우선순위 적용.
- 신뢰도 (confidence) 같이 반환 — 호출자가 임계 정할 수 있게.

본 모듈은 verdict 결정에 직접 영향 X — anomaly_baseline 처럼 evidence 발화 정책에만 영향.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


# ─────────────── Enum ───────────────

class PackageCategory(str, Enum):
    """패키지 기능 카테고리."""
    WEB_FRAMEWORK = "web_framework"
    DATA_SCIENCE = "data_science"
    DEV_TOOL = "dev_tool"
    BUNDLER_TRANSPILER = "bundler_transpiler"
    RUNTIME_INTERPRETER = "runtime_interpreter"
    UNKNOWN = "unknown"


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
# 가장 강한 신호: 잘 알려진 패키지 이름. 이름 자체가 카테고리를 의미.

_NAME_TO_CATEGORY: dict[str, PackageCategory] = {
    # web framework — 풀 스택 / API / WSGI / ASGI 서버
    "flask": PackageCategory.WEB_FRAMEWORK,
    "fastapi": PackageCategory.WEB_FRAMEWORK,
    "django": PackageCategory.WEB_FRAMEWORK,
    "starlette": PackageCategory.WEB_FRAMEWORK,
    "tornado": PackageCategory.WEB_FRAMEWORK,
    "bottle": PackageCategory.WEB_FRAMEWORK,
    "pyramid": PackageCategory.WEB_FRAMEWORK,
    "sanic": PackageCategory.WEB_FRAMEWORK,
    "aiohttp": PackageCategory.WEB_FRAMEWORK,
    "quart": PackageCategory.WEB_FRAMEWORK,
    "uvicorn": PackageCategory.WEB_FRAMEWORK,
    "gunicorn": PackageCategory.WEB_FRAMEWORK,
    "werkzeug": PackageCategory.WEB_FRAMEWORK,
    "express": PackageCategory.WEB_FRAMEWORK,
    "koa": PackageCategory.WEB_FRAMEWORK,
    "fastify": PackageCategory.WEB_FRAMEWORK,
    "hapi": PackageCategory.WEB_FRAMEWORK,
    "next": PackageCategory.WEB_FRAMEWORK,
    "nuxt": PackageCategory.WEB_FRAMEWORK,
    "nestjs": PackageCategory.WEB_FRAMEWORK,
    "@nestjs/core": PackageCategory.WEB_FRAMEWORK,

    # data science / ML
    "numpy": PackageCategory.DATA_SCIENCE,
    "pandas": PackageCategory.DATA_SCIENCE,
    "scipy": PackageCategory.DATA_SCIENCE,
    "scikit-learn": PackageCategory.DATA_SCIENCE,
    "sklearn": PackageCategory.DATA_SCIENCE,
    "matplotlib": PackageCategory.DATA_SCIENCE,
    "seaborn": PackageCategory.DATA_SCIENCE,
    "statsmodels": PackageCategory.DATA_SCIENCE,
    "sympy": PackageCategory.DATA_SCIENCE,
    "torch": PackageCategory.DATA_SCIENCE,
    "tensorflow": PackageCategory.DATA_SCIENCE,
    "keras": PackageCategory.DATA_SCIENCE,
    "transformers": PackageCategory.DATA_SCIENCE,
    "datasets": PackageCategory.DATA_SCIENCE,
    "polars": PackageCategory.DATA_SCIENCE,
    "xarray": PackageCategory.DATA_SCIENCE,

    # dev tool / build / package management
    "pip": PackageCategory.DEV_TOOL,
    "setuptools": PackageCategory.DEV_TOOL,
    "wheel": PackageCategory.DEV_TOOL,
    "build": PackageCategory.DEV_TOOL,
    "poetry": PackageCategory.DEV_TOOL,
    "hatch": PackageCategory.DEV_TOOL,
    "tox": PackageCategory.DEV_TOOL,
    "pytest": PackageCategory.DEV_TOOL,
    "unittest2": PackageCategory.DEV_TOOL,
    "nose": PackageCategory.DEV_TOOL,
    "nose2": PackageCategory.DEV_TOOL,
    "pre-commit": PackageCategory.DEV_TOOL,
    "twine": PackageCategory.DEV_TOOL,
    "ruff": PackageCategory.DEV_TOOL,
    "mypy": PackageCategory.DEV_TOOL,
    "npm": PackageCategory.DEV_TOOL,
    "yarn": PackageCategory.DEV_TOOL,
    "pnpm": PackageCategory.DEV_TOOL,
    "lerna": PackageCategory.DEV_TOOL,
    "jest": PackageCategory.DEV_TOOL,
    "mocha": PackageCategory.DEV_TOOL,
    "eslint": PackageCategory.DEV_TOOL,
    "prettier": PackageCategory.DEV_TOOL,

    # bundler / transpiler
    "webpack": PackageCategory.BUNDLER_TRANSPILER,
    "vite": PackageCategory.BUNDLER_TRANSPILER,
    "rollup": PackageCategory.BUNDLER_TRANSPILER,
    "parcel": PackageCategory.BUNDLER_TRANSPILER,
    "esbuild": PackageCategory.BUNDLER_TRANSPILER,
    "swc": PackageCategory.BUNDLER_TRANSPILER,
    "babel": PackageCategory.BUNDLER_TRANSPILER,
    "@babel/core": PackageCategory.BUNDLER_TRANSPILER,
    "typescript": PackageCategory.BUNDLER_TRANSPILER,
    "ts-node": PackageCategory.BUNDLER_TRANSPILER,
    "cython": PackageCategory.BUNDLER_TRANSPILER,
    "pyodide": PackageCategory.BUNDLER_TRANSPILER,

    # runtime / interpreter / notebook
    "ipython": PackageCategory.RUNTIME_INTERPRETER,
    "jupyter": PackageCategory.RUNTIME_INTERPRETER,
    "notebook": PackageCategory.RUNTIME_INTERPRETER,
    "jupyterlab": PackageCategory.RUNTIME_INTERPRETER,
    "ptpython": PackageCategory.RUNTIME_INTERPRETER,
    "bpython": PackageCategory.RUNTIME_INTERPRETER,
}


# ─────────────── 분류 룰 (description phrase) ───────────────
# 약한 신호: 설명 문구. 정확 매칭이 없을 때 fallback.
# (phrase, category, confidence) 순. word-boundary 매칭 후 우선순위 평가.

_DESCRIPTION_PHRASES: list[tuple[str, PackageCategory, float]] = [
    # Web framework
    ("web framework", PackageCategory.WEB_FRAMEWORK, 0.9),
    ("application framework", PackageCategory.WEB_FRAMEWORK, 0.7),
    ("web server", PackageCategory.WEB_FRAMEWORK, 0.85),
    ("http server", PackageCategory.WEB_FRAMEWORK, 0.85),
    ("api framework", PackageCategory.WEB_FRAMEWORK, 0.8),
    ("rest framework", PackageCategory.WEB_FRAMEWORK, 0.8),
    ("wsgi", PackageCategory.WEB_FRAMEWORK, 0.7),
    ("asgi", PackageCategory.WEB_FRAMEWORK, 0.7),
    ("microframework", PackageCategory.WEB_FRAMEWORK, 0.85),

    # Data science / ML
    ("data analysis", PackageCategory.DATA_SCIENCE, 0.8),
    ("data structures for", PackageCategory.DATA_SCIENCE, 0.7),
    ("scientific computing", PackageCategory.DATA_SCIENCE, 0.85),
    ("numerical computing", PackageCategory.DATA_SCIENCE, 0.85),
    ("array computing", PackageCategory.DATA_SCIENCE, 0.85),
    ("machine learning", PackageCategory.DATA_SCIENCE, 0.9),
    ("deep learning", PackageCategory.DATA_SCIENCE, 0.9),
    ("neural network", PackageCategory.DATA_SCIENCE, 0.85),
    ("statistical computing", PackageCategory.DATA_SCIENCE, 0.85),

    # Dev tool
    ("build system", PackageCategory.DEV_TOOL, 0.85),
    ("build tool", PackageCategory.DEV_TOOL, 0.85),
    ("packaging tool", PackageCategory.DEV_TOOL, 0.85),
    ("package manager", PackageCategory.DEV_TOOL, 0.9),
    ("test framework", PackageCategory.DEV_TOOL, 0.85),
    ("testing framework", PackageCategory.DEV_TOOL, 0.85),
    ("linter", PackageCategory.DEV_TOOL, 0.7),
    ("type checker", PackageCategory.DEV_TOOL, 0.85),

    # Bundler / transpiler
    ("module bundler", PackageCategory.BUNDLER_TRANSPILER, 0.95),
    ("javascript bundler", PackageCategory.BUNDLER_TRANSPILER, 0.95),
    ("transpiler", PackageCategory.BUNDLER_TRANSPILER, 0.85),
    ("compiler for", PackageCategory.BUNDLER_TRANSPILER, 0.7),

    # Runtime / interpreter
    ("interactive shell", PackageCategory.RUNTIME_INTERPRETER, 0.9),
    ("interactive computing", PackageCategory.RUNTIME_INTERPRETER, 0.85),
    ("notebook environment", PackageCategory.RUNTIME_INTERPRETER, 0.9),
    ("repl", PackageCategory.RUNTIME_INTERPRETER, 0.7),
]


# ─────────────── 분류 룰 (의존성 시그니처) ───────────────
# 매우 약한 신호: 의존성 패키지가 카테고리를 시사.
# 단독 신호로는 부족 (다른 신호와 결합 시 confidence boost).

_DEP_HINTS: dict[str, PackageCategory] = {
    "asgiref": PackageCategory.WEB_FRAMEWORK,
    "starlette": PackageCategory.WEB_FRAMEWORK,
    "uvicorn": PackageCategory.WEB_FRAMEWORK,
    "gunicorn": PackageCategory.WEB_FRAMEWORK,
    "werkzeug": PackageCategory.WEB_FRAMEWORK,
    "click": PackageCategory.DEV_TOOL,
    "build": PackageCategory.DEV_TOOL,
    "wheel": PackageCategory.DEV_TOOL,
    "numpy": PackageCategory.DATA_SCIENCE,
    "scipy": PackageCategory.DATA_SCIENCE,
    "pandas": PackageCategory.DATA_SCIENCE,
}


# ─────────────── 메인 분류 함수 ───────────────

def classify(
    package_name: str,
    description: str = "",
    declared_deps: list[str] | None = None,
) -> CategoryGuess:
    """패키지를 기능 카테고리로 분류.

    여러 신호를 조합:
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
    if name_lower in _NAME_TO_CATEGORY:
        cat = _NAME_TO_CATEGORY[name_lower]
        return CategoryGuess(
            category=cat, confidence=1.0,
            reason=f"exact name match: {name_lower!r} -> {cat.value}",
        )

    # 2. description phrase 매칭
    desc_matches: list[tuple[PackageCategory, float, str]] = []
    for phrase, cat, conf in _DESCRIPTION_PHRASES:
        if re.search(r"\b" + re.escape(phrase) + r"\b", desc_lower):
            desc_matches.append((cat, conf, phrase))

    # 3. 의존성 시그니처 (boost 용)
    dep_categories = {_DEP_HINTS[d] for d in dep_lower if d in _DEP_HINTS}

    if desc_matches:
        # 가장 높은 confidence 의 phrase 매칭 선택
        desc_matches.sort(key=lambda x: -x[1])
        cat, conf, phrase = desc_matches[0]
        # 의존성 신호로 confidence 보강
        if cat in dep_categories:
            conf = min(1.0, conf + 0.1)
            reason = f"description phrase {phrase!r} + dep signal -> {cat.value}"
        else:
            reason = f"description phrase {phrase!r} -> {cat.value}"
        return CategoryGuess(category=cat, confidence=conf, reason=reason)

    # description 신호 없을 때, 의존성 단독으로는 분류 안 함 (FP 우려).
    # dep 만 있는 경우 unknown 으로 둠 — 다른 신호 없으면 자신 없는 분류.

    return CategoryGuess(
        category=PackageCategory.UNKNOWN, confidence=0.0,
        reason="no exact name / description / dep evidence",
    )


# ─────────────── 헬퍼 ───────────────

# 카테고리별 'broad' 성격: 좁은 anomaly 카테고리 분류 거부 + 추가 STANDALONE_WEAK 정책 가능.
BROAD_PURPOSE_CATEGORIES = frozenset({
    PackageCategory.WEB_FRAMEWORK,
    PackageCategory.DATA_SCIENCE,
    PackageCategory.DEV_TOOL,
    PackageCategory.BUNDLER_TRANSPILER,
    PackageCategory.RUNTIME_INTERPRETER,
})


def is_broad_purpose(guess: CategoryGuess, min_confidence: float = 0.6) -> bool:
    """이 분류가 broad-purpose 카테고리이고 신뢰도 임계 이상인가."""
    return (
        guess.category in BROAD_PURPOSE_CATEGORIES
        and guess.confidence >= min_confidence
    )


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
        print(f"  {marker} {name:<22s} -> {g.category.value:<22s} conf={g.confidence:.2f}  ({g.reason})")
