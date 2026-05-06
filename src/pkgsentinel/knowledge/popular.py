"""인기 패키지 화이트리스트 (popular_rank 에뮬레이션).

프로덕션 파이프라인 stage_0a_threat_filter 의 popular 매칭이 약신호 FP
억제 효과를 갖는데, eval / 로컬 테스트 / DB 미준비 환경에선 그 효과가
없음. 본 정적 명단은 OpenSSF Critical Project / PyPI Top 5000 /
npm anvaka top 1000 에서 항상 등재돼 있는 메이저 패키지.

이 명단은 verdict_rules.apply_popular_downgrade() 에서 인기 패키지의
medium-strength 신호를 CLEAN 으로 다운그레이드하는 데 사용. eval 스크립트
(scripts/eval_real.py) 도 동일 명단을 사용하도록 import.
"""
from __future__ import annotations

POPULAR_PYPI: frozenset[str] = frozenset({
    # 코어 / 표준 라이브러리 wrapper
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
    "click", "rich", "tqdm", "typer", "colorama", "tabulate",
    # 직렬화 / 검증
    "pyyaml", "pydantic", "jsonschema", "msgpack", "orjson",
    # DB / ORM / 캐시
    "sqlalchemy", "alembic", "redis",
    # HTTP 클라이언트 / 네트워크
    "httpx", "aiohttp", "websockets",
    # 보안
    "cryptography", "bcrypt", "passlib",
    # 클라우드
    "boto3", "botocore", "s3transfer",
    # 이미지 / 파일
    "pillow", "lxml", "openpyxl",
    # 자동화 / 브라우저
    "beautifulsoup4", "selenium",
    # 메시징 / 큐
    "celery", "kombu", "amqp",
    # 노트북 / IPython
    "ipython", "jupyter", "notebook",
    # ML / AI
    "torch", "tensorflow", "keras", "transformers",
    "openai", "anthropic", "langchain", "tiktoken",
    # 로깅 / 유틸리티
    "structlog", "loguru", "tenacity", "more-itertools",
})

POPULAR_NPM: frozenset[str] = frozenset({
    # 프레임워크 / UI
    "react", "react-dom", "vue", "angular", "svelte",
    "next", "nuxt",
    # 유틸리티
    "lodash", "underscore", "ramda", "date-fns", "moment",
    # HTTP / 네트워크
    "axios", "node-fetch", "got", "ws",
    # 빌드 / 도구
    "typescript", "webpack", "rollup", "vite", "esbuild",
    "babel-core", "@babel/core", "rxjs",
    # 린팅 / 포맷
    "eslint", "prettier", "stylelint",
    # 서버 / 미들웨어
    "express", "koa", "fastify",
    # 색상 / CLI
    "chalk", "commander", "yargs", "inquirer",
    # 테스트
    "jest", "mocha", "@testing-library/react",
    # 타입
    "tailwindcss", "@types/node", "@types/react",
    # 캐시
    "ioredis",
})


def is_popular(name: str, ecosystem: str) -> bool:
    """이름 정규화 후 popular 명단 매칭."""
    n = name.lower().strip()
    if ecosystem == "PyPI":
        return n in POPULAR_PYPI
    if ecosystem == "npm":
        return n in POPULAR_NPM
    return False
