"""
어댑터 자체 typo-squat / hallucination 후보 탐지.

V2 엔진과 독립적으로 동작 — 잘 알려진 패키지 이름과의 Levenshtein 거리 기반.
환각 패키지명에 대해 "어쩌면 이걸 쓰려고 했나요?" 답을 익스텐션 CodeAction 으로 제공.

설계:
- Top 패키지 리스트는 메모리에 두고 부팅 시 1회 lower-casing
- Levenshtein 은 max_distance early-exit 으로 빠르게 (대부분 후보가 길이 차이로 컷)
- 결과 캐시 (lru_cache) — 같은 패키지명 반복 조회 시 즉시 응답
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional, Set

# ─── Top 패키지 리스트 (수동 큐레이션) ────────────────────────────
# 시연 핵심 패키지 + 자주 환각되는 패키지 우선.
# 너무 길면 매 요청마다 Levenshtein 비용 증가 → 핵심 ~250개씩 유지.

PYPI_TOP_PACKAGES: Set[str] = {
    # HTTP / 네트워크
    "requests", "urllib3", "idna", "certifi", "charset-normalizer",
    "aiohttp", "httpx", "requests-oauthlib", "websockets", "websocket-client",
    "grpcio", "grpcio-tools",
    # 데이터 분석
    "numpy", "pandas", "scipy", "scikit-learn", "matplotlib",
    "seaborn", "plotly", "bokeh", "altair", "pyarrow", "polars",
    # 머신러닝 / AI
    "tensorflow", "torch", "torchvision", "torchaudio", "keras",
    "transformers", "datasets", "huggingface-hub",
    "sentence-transformers", "tokenizers", "accelerate", "diffusers",
    "openai", "anthropic", "langchain", "langchain-core",
    "langchain-openai", "langchain-community", "langchain-anthropic",
    "llama-index", "tiktoken", "google-generativeai",
    "xgboost", "lightgbm", "catboost", "mlflow", "wandb",
    # 웹 프레임워크
    "flask", "django", "fastapi", "starlette", "uvicorn", "gunicorn",
    "tornado", "bottle", "pyramid", "sanic", "quart",
    # ORM / DB
    "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "pymysql",
    "redis", "pymongo", "motor", "elasticsearch", "asyncpg",
    "peewee", "tortoise-orm", "databases",
    # 클라우드
    "boto3", "botocore", "awscli", "s3transfer",
    "google-cloud-storage", "google-cloud-bigquery", "google-cloud-pubsub",
    "azure-storage-blob", "azure-identity", "azure-keyvault-secrets",
    # 이미지
    "pillow", "opencv-python", "opencv-contrib-python",
    "scikit-image", "imageio", "imageio-ffmpeg",
    # 직렬화 / 설정
    "pyyaml", "jsonschema", "jinja2", "markupsafe", "toml",
    "tomli", "tomlkit", "ruamel.yaml", "orjson", "msgpack",
    "ujson",
    # CLI / 터미널
    "click", "typer", "rich", "colorama", "termcolor", "tqdm",
    "prompt-toolkit", "tabulate", "shellingham",
    # 테스트
    "pytest", "pytest-cov", "pytest-asyncio", "pytest-mock",
    "pytest-xdist", "mock", "hypothesis", "tox", "coverage", "responses",
    "faker", "factory-boy",
    # 비동기 / 작업 큐
    "celery", "rq", "dramatiq", "kombu", "anyio", "trio",
    # 시간 / 날짜
    "python-dateutil", "pytz", "arrow", "pendulum", "tzdata",
    # 빌드 / 패키징
    "setuptools", "wheel", "pip", "poetry", "build", "hatch",
    "twine", "packaging", "setuptools-scm",
    # 유틸리티 / 데이터 클래스
    "six", "attrs", "cattrs", "dataclasses-json", "marshmallow",
    "pydantic", "pydantic-core", "pydantic-settings",
    "typing-extensions", "annotated-types",
    # 보안 / 암호
    "cryptography", "pyjwt", "bcrypt", "passlib", "pyopenssl",
    "argon2-cffi", "python-jose",
    # 파싱 / HTML
    "beautifulsoup4", "lxml", "html5lib", "pyparsing", "soupsieve",
    # 자동화 / 크롤링
    "scrapy", "selenium", "playwright", "pyautogui", "pyppeteer",
    # 시스템 / OS
    "psutil", "watchdog", "filelock", "send2trash", "click-default-group",
    # 노트북 / 데이터과학 환경
    "ipython", "jupyter", "notebook", "jupyterlab",
    "ipykernel", "ipywidgets", "nbconvert", "nbformat",
    # 데이터 앱
    "streamlit", "gradio", "dash", "panel", "voila",
    # 자주 환각되는 / 시연용
    "numpy-stl", "pandas-profiling", "scikit-optimize",
    "tensorflow-probability", "tensorflow-hub", "torch-geometric",
    "scikit-multilearn", "scikit-learn-extra", "imbalanced-learn",
    # 기타
    "python-dotenv", "dotenv", "environs", "dynaconf",
    "loguru", "structlog", "python-json-logger",
    "more-itertools", "toolz", "funcy",
    "requests-cache", "requests-toolbelt",
    "wrapt", "decorator", "deprecated",
    "regex", "ftfy", "unidecode",
    "validators", "email-validator",
    "stripe", "twilio", "sendgrid", "slack-sdk", "discord-py",
    "google-auth", "google-api-python-client", "google-cloud-aiplatform",
    "pre-commit", "black", "isort", "ruff", "flake8", "mypy", "pylint",
    "rapidfuzz", "fuzzywuzzy", "python-levenshtein",
    "sqlcipher3",
}

NPM_TOP_PACKAGES: Set[str] = {
    # 프레임워크 (프론트)
    "react", "react-dom", "react-native", "vue", "@vue/cli",
    "@vue/runtime-core", "@angular/core", "@angular/cli",
    "svelte", "next", "nuxt", "remix", "gatsby", "solid-js",
    # 서버 / API
    "express", "koa", "fastify", "hapi", "@nestjs/core", "@nestjs/common",
    "polka", "restify", "apollo-server",
    # 유틸리티
    "lodash", "lodash-es", "underscore", "ramda", "immer", "immutable",
    "rxjs", "uuid", "nanoid", "shortid", "ulid",
    # HTTP
    "axios", "node-fetch", "got", "ky", "isomorphic-fetch", "undici",
    "cross-fetch",
    # 날짜
    "moment", "moment-timezone", "dayjs", "date-fns", "luxon",
    # CLI
    "chalk", "commander", "yargs", "inquirer", "ora", "cli-progress",
    "minimist", "meow", "kleur", "boxen", "ink", "listr",
    # 빌드 / 번들
    "typescript", "ts-node", "ts-loader", "esbuild", "swc",
    "@swc/core", "webpack", "webpack-cli", "webpack-dev-server",
    "vite", "@vitejs/plugin-react", "parcel", "rollup", "tsup",
    # 린트 / 포맷
    "eslint", "prettier", "stylelint",
    "@typescript-eslint/parser", "@typescript-eslint/eslint-plugin",
    "eslint-plugin-react", "eslint-plugin-import",
    # 테스트
    "jest", "@jest/core", "@jest/globals", "mocha", "chai", "sinon",
    "cypress", "@cypress/react", "playwright", "@playwright/test",
    "vitest", "puppeteer", "supertest", "tap",
    # CSS / 스타일
    "tailwindcss", "postcss", "autoprefixer", "sass", "less",
    "styled-components", "@emotion/react", "@emotion/styled",
    "classnames", "clsx",
    # ORM / DB
    "mongoose", "sequelize", "prisma", "@prisma/client",
    "typeorm", "kysely", "drizzle-orm", "knex",
    "pg", "mysql2", "sqlite3", "better-sqlite3", "redis", "ioredis",
    # 타입
    "@types/node", "@types/react", "@types/react-dom",
    "@types/express", "@types/jest", "@types/lodash",
    "@types/mocha", "@types/chai", "@types/uuid",
    # 상태 관리
    "redux", "@reduxjs/toolkit", "react-redux",
    "mobx", "mobx-react", "zustand", "recoil", "jotai", "valtio",
    # 인증
    "next-auth", "passport", "passport-local", "passport-jwt",
    "jsonwebtoken", "bcrypt", "bcryptjs", "argon2",
    "express-session", "cookie-parser", "cookie", "iron-session",
    # 유틸 / 기타
    "cors", "body-parser", "helmet", "compression", "morgan",
    "dotenv", "cross-env", "concurrently", "nodemon", "pm2",
    "rimraf", "fs-extra", "glob", "minimatch", "chokidar",
    "execa", "shelljs", "fast-glob",
    # GraphQL
    "graphql", "@apollo/server", "@apollo/client", "graphql-tag",
    "apollo-server-express", "type-graphql",
    # 폼 / 검증
    "zod", "yup", "joi", "ajv", "class-validator",
    "react-hook-form", "formik", "@hookform/resolvers",
    # 라우팅
    "react-router", "react-router-dom", "@reach/router",
    "vue-router", "@tanstack/router",
    # Babel
    "babel-loader", "@babel/core", "@babel/preset-env",
    "@babel/preset-react", "@babel/preset-typescript",
    "@babel/plugin-transform-runtime",
    # AI / SDK
    "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core",
    "@langchain/openai", "@langchain/anthropic",
    # 자주 환각되는 / 패키지명 헷갈리는 것
    "react-icons", "@heroicons/react", "lucide-react",
    "react-query", "@tanstack/react-query", "swr",
    "react-table", "@tanstack/react-table",
    "framer-motion", "react-spring", "react-transition-group",
    "socket.io", "socket.io-client", "ws",
    "winston", "pino", "bunyan", "debug",
    "yargs-parser", "args", "cmd-ts",
}


# ─── 부팅 시 lower-case 캐싱 ─────────────────────────────────────
# 매 요청마다 소문자 변환 비용 회피.

_PYPI_LOWER = {p.lower() for p in PYPI_TOP_PACKAGES}
_NPM_LOWER = {p.lower() for p in NPM_TOP_PACKAGES}

# 원본 (응답 시에는 원래 패키지명 그대로 보여주는 게 좋으므로)
_PYPI_LIST = sorted(PYPI_TOP_PACKAGES)
_NPM_LIST = sorted(NPM_TOP_PACKAGES)


def _levenshtein(a: str, b: str, max_d: int = 4) -> int:
    """
    1D DP Levenshtein, max_d 초과면 max_d+1 반환 (early exit).

    a, b 둘 다 lower-case 가정.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_d:
        return max_d + 1

    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la

    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        row_min = i
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                curr[j - 1] + 1,        # insert
                prev[j] + 1,            # delete
                prev[j - 1] + cost,     # substitute
            )
            if curr[j] < row_min:
                row_min = curr[j]
        if row_min > max_d:
            return max_d + 1
        prev = curr
    return prev[lb]


@lru_cache(maxsize=2048)
def find_closest(
    name: str,
    ecosystem: str = "PyPI",
    max_distance: int = 3,
) -> Optional[str]:
    """
    name 과 가장 가까운 top 패키지명 반환.

    규칙:
    - 정확히 일치하면 None (자기 자신 — 추천 불필요)
    - max_distance 초과면 None
    - distance 1 이 우선, 그 다음 알파벳 순
    - 너무 짧은 이름(<=2자) 은 노이즈 가능성 — 일부 케이스 제외

    @lru_cache 로 동일 입력 반복 호출은 즉시 응답.
    """
    if not name or len(name) < 2:
        return None
    name_lower = name.lower()

    if ecosystem.lower() == "npm":
        pool = _NPM_LIST
        pool_lower = _NPM_LOWER
    else:
        pool = _PYPI_LIST
        pool_lower = _PYPI_LOWER

    # 정확히 일치 — 정상 패키지
    if name_lower in pool_lower:
        return None

    best: Optional[tuple[int, str]] = None
    for cand in pool:
        d = _levenshtein(name_lower, cand.lower(), max_distance)
        if d > max_distance:
            continue
        if best is None or d < best[0] or (d == best[0] and cand < best[1]):
            best = (d, cand)
            # distance 1 이면 더 좋은 게 나올 가능성 거의 없음 — 빠르게 끝낼 수도 있지만
            # 알파벳 순 보장을 위해 끝까지 돌림
    return best[1] if best else None
