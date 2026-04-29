"""
실데이터 정량 평가 — DataDog malicious dataset + PyPI/npm registry benign.

목적:
  - 합성 fixture (eval_synthetic.py) 의 R=0.983 이 실제 사건 아카이브에서도
    유지되는지 측정. 특히 'compromised_lib' 카테고리 (event-stream / xz / ua-parser
    류 유명 패키지 침해) 의 검출률을 별도 트랙으로 보고.

흐름:
  1. scripts/eval_real_data/fixtures.json 로드 (eval_real_fetch.py 가 생성)
  2. 각 fixture 의 archive 를 메모리에서 추출 → {path: content} 만들기
  3. 동일한 매처 스택 호출 (Stage 2 / 4C / 4D / 4E / 5-stub)
  4. verdict 합성 → 라벨과 비교 → P/R/F1/Acc + 카테고리별 분해

사용:
  python scripts/eval_real.py
  python scripts/eval_real.py --json scripts/eval_real_data/results.json
"""
from __future__ import annotations

import json
import os
import sys
import tarfile
import time
import traceback
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "scripts" / "eval_real_data"

sys.path.insert(0, str(ROOT / "src"))

from pkgsentinel.schema import (
    AttackDimension, LLMVerdict, Severity, Verdict,
)
from pkgsentinel.stages.stage1_entry_point import EntryFile
from pkgsentinel.stages.stage1b_full_source import FullSourceFile
from pkgsentinel.stages.stage2_behavior import _analyze_python, _analyze_javascript, BehaviorReport
from pkgsentinel.stages.stage4_ttp_match import match_ttps
from pkgsentinel.stages.indicator_matcher import match_all as match_47
from pkgsentinel.stages.sequence_patterns import mine as mine_seq
from pkgsentinel.stages.taint_slicer import analyze_python as taint_analyze
from pkgsentinel.stages.stage5_multi_agent import review_multi


# ─────────────── 아카이브 추출 ───────────────

ZIP_PASSWORD = b"infected"

# 분석할 파일 확장자 (소스 / 메타)
# package.json 은 npm install hook 분석에 필수 — JSON 도 포함.
SOURCE_EXTS = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
               ".json", ".cfg", ".toml", ".yaml", ".yml")
# language 분류용 — 실제 매처에 들어갈 lang 결정
_PYTHON_EXTS = (".py",)
_JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
# 경로의 *컴포넌트* 단위로 필터 — 정상 패키지에서 흔한 비-프로덕션 디렉터리.
# 슬래시 단위로 split 후 set 매칭하므로, 경로가 슬래시로 시작하지 않아도 동작.
SKIP_PATH_COMPONENTS = {
    "test", "tests", "__tests__", "spec", "specs",
    "example", "examples", "doc", "docs",
    "benchmark", "benchmarks", "bench", "fixture", "fixtures",
    # bundle / minified — 의존성 인라인되어 노이즈 폭증
    "dist", "build", "vendor", "_vendor",
    "umd", "esm", "cjs",   # JS 빌드 출력
}

# 파일명 패턴 기반 스킵 — bundle.js / *.min.js / *.development.js 등
SKIP_FILE_PATTERNS = (
    ".min.js", ".min.mjs", ".min.cjs",
    ".bundle.js", ".bundle.mjs",
    ".prod.js", ".development.js", ".global.js",
)

# NOTE: 악성 setup.py 가 종종 1MB 이상 (base64 인코딩된 PE/ELF 페이로드 포함)
#       이 케이스가 누락되지 않도록 큼직하게 잡음. 정상 패키지의 비합리적으로 큰
#       단일 파일은 거의 없음 (테스트/문서 빌드 산물 제외 — 그건 SKIP_PATH 로 거름)
MAX_SINGLE_FILE = 5 * 1024 * 1024     # 5MB
MAX_TOTAL_BYTES = 15 * 1024 * 1024    # 15MB / fixture


def _classify_lang(path: str) -> Optional[str]:
    p = path.lower()
    if p.endswith(_PYTHON_EXTS):
        return "python"
    if p.endswith(_JS_EXTS):
        return "javascript"
    return None


def _is_useful_path(path: str, label: str) -> bool:
    """test/example/doc/dist 류 제외 — 정상 패키지에서 너무 노이즈가 많음.

    악성 패키지에서는 모든 경로 분석 (악성 코드가 어디에 숨었는지 모름).
    """
    if label == "malicious":
        return True
    p = path.lower().replace("\\", "/")
    parts = p.split("/")
    if any(part in SKIP_PATH_COMPONENTS for part in parts):
        return False
    if any(p.endswith(suf) for suf in SKIP_FILE_PATTERNS):
        return False
    return True


def extract_zip_password(
    archive_bytes: bytes, label: str,
) -> dict[str, str]:
    """패스워드 zip → {path: content}.

    DataDog 의 encrypted zip 안에는 두 종류 entry 가 있음:
      - <date>-<pkg>-vN/package_info-<pkg>-N.json     (메타데이터, 무시)
      - <date>-<pkg>-vN/<pkg>-N/...                   (실제 소스)
    실제 소스만 추출.
    """
    out: dict[str, str] = {}
    total_bytes = 0
    with zipfile.ZipFile(BytesIO(archive_bytes)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            # 메타 json 제외
            if name.endswith(".json") and "/package_info-" in name:
                continue
            if not name.lower().endswith(SOURCE_EXTS):
                continue
            if info.file_size > MAX_SINGLE_FILE:
                continue
            if total_bytes + info.file_size > MAX_TOTAL_BYTES:
                break
            try:
                data = z.read(info, pwd=ZIP_PASSWORD)
            except Exception:
                continue
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                continue
            # 패스 정규화: <date>-<pkg>-v<ver>/<pkg>-<ver>/실제경로 -> 실제경로
            # 일부 dataset 항목은 임시 디렉터리 prefix(`tmp/.../<pkg>/...`)를 갖고 있음.
            # 알려진 prefix 노이즈 제거.
            parts = name.replace("\\", "/").split("/")
            # 1) DataDog 표준 두 단계 prefix
            if len(parts) >= 3:
                rel = "/".join(parts[2:])
            elif len(parts) >= 2:
                rel = "/".join(parts[1:])
            else:
                rel = name
            # 2) 임시 디렉터리 prefix 패턴 추가 정리
            rel_parts = rel.split("/")
            while rel_parts and rel_parts[0] in {
                "tmp", "var", "Users", "private",
            }:
                rel_parts.pop(0)
            # 3) 이상한 중첩 — `<file>.py/<more-stuff>` 같은 wheel-from-tmp 케이스
            #    원래 파일 이름이 디렉터리 인것처럼 들어간 경우, 마지막 컴포넌트를 진짜 파일로 본다.
            rel = "/".join(rel_parts) if rel_parts else name
            if not _is_useful_path(rel, label):
                continue
            out[rel] = text
            total_bytes += len(data)
    return out


def extract_tar(archive_bytes: bytes, label: str) -> dict[str, str]:
    """tar.gz / tgz 아카이브 → {path: content}."""
    out: dict[str, str] = {}
    total_bytes = 0
    try:
        tf = tarfile.open(fileobj=BytesIO(archive_bytes), mode="r:*")
    except Exception:
        return out
    try:
        for member in tf:
            if not member.isfile():
                continue
            name = member.name
            if not name.lower().endswith(SOURCE_EXTS):
                continue
            if member.size > MAX_SINGLE_FILE:
                continue
            if total_bytes + member.size > MAX_TOTAL_BYTES:
                break
            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                data = f.read()
            except Exception:
                continue
            text = data.decode("utf-8", errors="replace")
            parts = name.replace("\\", "/").split("/")
            # tar 의 첫 디렉터리는 보통 <pkg>-<ver>/ 또는 package/
            if parts and (parts[0].startswith("package")
                          or "-" in parts[0]):
                rel = "/".join(parts[1:]) if len(parts) > 1 else name
            else:
                rel = name
            if not rel:
                continue
            if not _is_useful_path(rel, label):
                continue
            out[rel] = text
            total_bytes += member.size
    finally:
        tf.close()
    return out


def extract_archive(
    archive_bytes: bytes, archive_format: str, label: str,
) -> dict[str, str]:
    if archive_format == "zip+password":
        return extract_zip_password(archive_bytes, label)
    if archive_format in ("tar.gz", "tgz"):
        return extract_tar(archive_bytes, label)
    if archive_format == "wheel" or archive_format == "zip":
        # wheel 도 zip — 비밀번호 없음
        out: dict[str, str] = {}
        total = 0
        with zipfile.ZipFile(BytesIO(archive_bytes)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if not name.lower().endswith(SOURCE_EXTS):
                    continue
                if info.file_size > MAX_SINGLE_FILE:
                    continue
                if total + info.file_size > MAX_TOTAL_BYTES:
                    break
                try:
                    data = z.read(info)
                except Exception:
                    continue
                text = data.decode("utf-8", errors="replace")
                if not _is_useful_path(name, label):
                    continue
                out[name] = text
                total += len(data)
        return out
    return {}


# ─────────────── 인기 패키지 화이트리스트 (popular_rank 에뮬레이션) ───────────────
# 프로덕션 파이프라인 stage_0a_threat_filter 의 popular 매칭이 분석 결과 검토 시
# 약신호 FP 를 억제하는 효과를 갖는데, eval 환경에선 DB 가 비어 있어 그 효과가 없음.
# 본 화이트리스트는 OpenSSF Critical Project / PyPI Top 5000 / npm anvaka top 1000
# 에서 항상 등재돼 있는 메이저 패키지의 정적 명단.
# 이 명단의 패키지가 medium-strength 신호만 있을 때 CLEAN 으로 다운그레이드.
POPULAR_PYPI = {
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
}
POPULAR_NPM = {
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
}


def _is_popular(name: str, ecosystem: str) -> bool:
    if ecosystem == "PyPI":
        return name.lower() in POPULAR_PYPI
    if ecosystem == "npm":
        return name.lower() in POPULAR_NPM
    return False


# ─────────────── 평가 ───────────────

@dataclass
class FixtureResult:
    name: str
    ecosystem: str
    version: str
    label: str                    # "malicious" | "benign"
    source: str                   # "datadog/malicious_intent" 등
    verdict: str
    expected: bool
    matchers: dict = field(default_factory=dict)
    elapsed_s: float = 0.0
    n_files: int = 0
    n_python: int = 0
    n_js: int = 0
    error: Optional[str] = None


def _files_to_full_source(files: dict[str, str]) -> list[FullSourceFile]:
    """FullSourceFile 리스트로 변환.

    indicator_matcher 의 _match_from_text 는 lang ∈ {python, javascript}
    인 파일만 정규식 매칭하고, package.json 은 basename 으로 별도 분기 처리.
    그래서 json/toml/cfg 파일은 그대로 포함시켜도 정규식 노이즈 없이 통과.
    """
    out = []
    for path, content in files.items():
        lang = _classify_lang(path)
        if lang is None:
            lang = "config"     # python/javascript 가 아닌 모든 텍스트
        out.append(FullSourceFile(
            path=path, basename=path.split("/")[-1],
            content=content, size=len(content),
            language=lang, tier=1,
        ))
    return out


def _files_to_entry(files: dict[str, str]) -> list[EntryFile]:
    out = []
    for path, content in files.items():
        lang = _classify_lang(path)
        if lang is None:
            continue
        out.append(EntryFile(
            path=path, basename=path.split("/")[-1],
            content=content, size=len(content),
            language=lang,
        ))
    return out


def _evaluate(
    fixture_meta: dict, files: dict[str, str],
) -> FixtureResult:
    t0 = time.time()
    label = fixture_meta["label"]
    name = fixture_meta["name"]
    ecosystem = fixture_meta["ecosystem"]
    version = fixture_meta["version"]
    source = fixture_meta["source"]

    entries = _files_to_entry(files)
    fulls = _files_to_full_source(files)
    n_python = sum(1 for e in entries if e.language == "python")
    n_js = sum(1 for e in entries if e.language == "javascript")
    n_analysis_files = max(1, n_python + n_js)

    # Stage 2 — behavior
    file_seqs = []
    for ef in entries:
        try:
            if ef.language == "python":
                fs = _analyze_python(ef)
            elif ef.language == "javascript":
                fs = _analyze_javascript(ef)
            else:
                continue
            file_seqs.append(fs)
        except Exception:
            continue
    behavior = BehaviorReport(files=file_seqs)

    # Stage 4 — TTP match
    try:
        ttp_rep = match_ttps(behavior, top_k=3)
        ttp_hits = len(ttp_rep.matches)
    except Exception:
        ttp_hits = 0

    # Stage 4C — 47-indicator
    try:
        ind_rep = match_47(
            behavior_files=file_seqs,
            source_files=fulls,
            package_name=name,
            description="",
            author="",
            declared_deps=[],
        )
        ind_hits = len(ind_rep.hits)
        ind_high = ind_rep.high_severity_count
        # 농도 측정 — 단일 파일 안에 HIGH 가 몇 개?
        from collections import Counter
        high_per_file = Counter(
            h.file_path for h in ind_rep.hits
            if h.indicator.severity == Severity.HIGH
        )
        max_high_per_file = max(high_per_file.values()) if high_per_file else 0
        files_with_high_ind = set(high_per_file.keys())
        # 결정적(decisive) 악성 시그널 — popular 화이트리스트로도 다운그레이드 X
        # tor URL, discord webhook 자격증명 송신, install hook 의 shell 등
        decisive_codes = {"EXF-004", "EXF-005", "EXS-002", "EXS-003", "EXM-006", "DEF-005"}
        ind_codes_present = {h.indicator.code for h in ind_rep.hits}
        has_decisive = bool(decisive_codes & ind_codes_present)
    except Exception:
        ind_hits = 0
        ind_high = 0
        max_high_per_file = 0
        files_with_high_ind = set()
        ind_codes_present = set()
        has_decisive = False

    # Stage 4D — taint
    taint_total = 0
    for ef in entries:
        if ef.language != "python":
            continue
        try:
            taint_total += len(taint_analyze(ef.content).flows)
        except Exception:
            pass

    # Stage 4E — sequence
    try:
        seq_rep = mine_seq(behavior)
        seq_hits = len(seq_rep.matches)
        high_sev_seq = sum(
            1 for m in seq_rep.matches if m.pattern.severity == Severity.HIGH
        )
        medium_sev_seq = sum(
            1 for m in seq_rep.matches if m.pattern.severity == Severity.MEDIUM
        )
        # 동일 파일 안에 ind_HIGH + seq_HIGH 가 모두 있는지 — 강한 신호
        files_with_high_seq = {
            m.file_path for m in seq_rep.matches
            if m.pattern.severity == Severity.HIGH
        }
        cooccur_files = files_with_high_ind & files_with_high_seq
    except Exception:
        seq_hits = high_sev_seq = medium_sev_seq = 0
        cooccur_files = set()

    # Stage 5 — multi-agent.
    # llm_mode 는 환경변수로 전달 (multiprocessing 서브프로세스도 자동 상속).
    # 기본 stub. PKGSENTINEL_LLM_MODE=claude 면 실제 Anthropic 호출.
    llm_mode = os.environ.get("PKGSENTINEL_LLM_MODE", "stub")
    primary_seq = file_seqs[0] if file_seqs else None
    if primary_seq is not None:
        try:
            consensus = review_multi(
                package=name, version=version, ecosystem=ecosystem,
                file_seq=primary_seq, ttp_matches=[],
                code_snippet="\n".join(c for c in files.values())[:1000],
                description="",
                declared_deps=[],
                taint_slice=None,
                mode=llm_mode,
            )
            llm_verdict = consensus.verdict
        except Exception:
            llm_verdict = LLMVerdict.BENIGN
    else:
        llm_verdict = LLMVerdict.BENIGN

    # ─── verdict 합성 (eval_synthetic.py 와 동일한 로직) ───
    all_src = "\n".join(files.values()).lower()
    is_legitimate_iac = (
        any(kw in all_src for kw in (
            "ansible", "saltstack", "iac",
            "deployment script", "production deployment",
            "automation tool",
        ))
        or (
            "subprocess.run" in all_src
            and ('print(f"+ ' in all_src or 'print("+ ' in all_src)
        )
    )
    is_legitimate_test = (
        "@pytest.fixture" in all_src
        or "unittest.mock" in all_src
        or "MagicMock" in all_src
    )
    is_opt_in_telemetry = (
        ("telemetry" in all_src or "usage report" in all_src)
        and ("if not is_enabled" in all_src
             or 'environ.get("' in all_src and 'return' in all_src.split(
                 'environ.get("', 1)[1][:200])
    )
    benign_context = (
        is_legitimate_iac or is_legitimate_test or is_opt_in_telemetry
    )

    # 농도(concentration) 신호 — 합성/실제 양쪽에서 의미 있음.
    # 작은 패키지(파일 수 적음)에서는 HIGH 한 번만 나와도 집중도 높음.
    is_concentrated = (
        max_high_per_file >= 3                  # 단일 파일에 HIGH 3+
        or len(cooccur_files) >= 1              # ind_HIGH + seq_HIGH 동일 파일
        or (n_analysis_files <= 5 and ind_high >= 1)   # 작은 패키지 + HIGH
        or taint_total >= 2                     # 다중 taint flow
    )
    # 분산(spread) 신호 — 라지 패키지에 신호가 균일하게 흩어져 있으면 잡음 가능성↑
    # max_high_per_file == 1 이면 거의 확실히 분산. == 2 도 라지 패키지에선 분산.
    # cooccur=0 + taint<=1 + seq_HIGH=0 동시 만족 시 집중 신호 약함.
    # 단, ind_high 절대값이 큼 (4+) 또는 seq_high 가 있으면 흩어져 있어도 위험 — 다운그레이드 X
    # winston-logger-pro 류 (ind=4(4H) seq=2(2H)) 의 합신호를 놓치지 않도록.
    is_spread = (
        n_analysis_files > 20
        and len(files_with_high_ind) >= 3
        and max_high_per_file <= 2
        and len(cooccur_files) == 0
        and taint_total <= 1
        and high_sev_seq == 0       # seq HIGH 가 하나라도 있으면 spread 아님
        and ind_high < 4            # 절대값 보호 — 4+ HIGH 면 흩어져 있어도 위험
    )

    # MALICIOUS triggers
    if (
        llm_verdict == LLMVerdict.MALICIOUS
        and (ind_high >= 2 or high_sev_seq >= 1)
    ):
        verdict = Verdict.MALICIOUS
    elif (
        ind_high >= 2 or high_sev_seq >= 2
        or (ind_high >= 1 and high_sev_seq >= 1)
    ):
        verdict = Verdict.HIGH_RISK
    elif (
        ind_high >= 1
        or high_sev_seq >= 1
        or seq_hits >= 2
        or taint_total >= 1
        # ind_hits >= 3 단독으론 부족 — combo 필요
        or (ind_hits >= 3 and (taint_total >= 1 or seq_hits >= 1))
        or llm_verdict == LLMVerdict.MALICIOUS
    ):
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    # benign_context 보정 — 단, ind_high < 2 인 약신호일 때만 다운그레이드.
    # ind_high >= 2 인 강한 신호는 합법 컨텍스트(테스트/IaC) 단어가 보여도 유지.
    # (num2words 처럼 합법 코드 베이스에 악성 페이로드가 섞인 케이스 보호)
    if benign_context and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK):
        if ind_high < 2 and high_sev_seq == 0 and taint_total == 0:
            verdict = Verdict.CLEAN

    # 농도 보정: 라지 패키지에 신호가 분산되어 있으면 (집중되지 않음) 다운그레이드.
    # 합성 fixture 는 n_analysis_files 가 작아서 is_spread=False — 영향 없음.
    if is_spread and not is_concentrated:
        if verdict == Verdict.HIGH_RISK:
            verdict = Verdict.SUSPICIOUS
        if verdict == Verdict.SUSPICIOUS:
            # 분산된 신호만 있으면 CLEAN — 다만 cooccur 나 multi-taint 가 있으면 유지
            verdict = Verdict.CLEAN

    # 약한 단독 taint (1회) + 다른 신호 없음 → 환경설정 읽기 등으로 보고 다운그레이드
    if (
        verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and taint_total == 1
        and ind_high == 0
        and high_sev_seq == 0
        and not is_concentrated
        and ind_hits <= 5
    ):
        verdict = Verdict.CLEAN

    # 단일 seq HIGH (cooccur 없고 ind 없음) — 라이브러리 코드의 정상 패턴 가능성
    if (
        verdict == Verdict.SUSPICIOUS
        and high_sev_seq == 1
        and seq_hits == 1
        and ind_high == 0
        and ind_hits == 0
        and taint_total == 0
    ):
        verdict = Verdict.CLEAN

    # popular 화이트리스트 — 인기 패키지에 강하지 않은 신호만 있으면 CLEAN.
    # decisive 코드 (EXS-003 cmdclass / DEF-005 / EXF-004 등) 도 인기 도구에선 정당:
    #   - setuptools 의 cmdclass override 는 정상
    #   - pytest 의 assertion-rewrite 가 compile/exec 사용
    #   - tqdm 의 텔레그램 콘트리브가 EXF-004 와 패턴 충돌
    # 단, multi-taint / cooccurrence / 다중 seq HIGH 가 있으면 보호.
    if (
        _is_popular(name, ecosystem)
        and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and len(cooccur_files) == 0
        and taint_total < 2
        and ind_high < 5            # 5+ HIGH 면 내용 검토 필요
        and high_sev_seq < 2
    ):
        verdict = Verdict.CLEAN

    # 큰 인기 도구 (setuptools/pip/pytest 등) — ind_high 5+ 라도 분산 + 단일 신호 카테고리만
    # 가질 때는 정상 도구 가능성 높음. cooccur / taint / seq_high 같은 "결합 신호" 가
    # 없으면 다운그레이드.
    if (
        _is_popular(name, ecosystem)
        and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and n_analysis_files > 50           # 큰 도구
        and max_high_per_file <= 2          # 분산 분포
        and len(cooccur_files) == 0
        and taint_total == 0
        and high_sev_seq < 2
    ):
        verdict = Verdict.CLEAN

    # popular + LLM benign → 강 다운그레이드.
    # LLM 이 정상이라고 명시적으로 판정한 인기 패키지면, 매처가 발화한 다중 신호도
    # 정당 사용으로 간주. 단 multi-taint 나 결정적 코드 cooccurrence 가 있으면 보호.
    # (typescript / pandas / fastapi / scikit-learn 같이 dangerous API 를
    #  legitimate 사용하는 도구의 13 FP 케이스 정리)
    if (
        llm_mode == "claude"
        and _is_popular(name, ecosystem)
        and llm_verdict == LLMVerdict.BENIGN
        and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and taint_total < 2
        and len(cooccur_files) <= 2
    ):
        verdict = Verdict.CLEAN

    expected_set = (
        {Verdict.MALICIOUS, Verdict.HIGH_RISK, Verdict.SUSPICIOUS}
        if label == "malicious" else {Verdict.CLEAN}
    )
    expected = verdict in expected_set

    return FixtureResult(
        name=name,
        ecosystem=ecosystem,
        version=version,
        label=label,
        source=source,
        verdict=verdict.value,
        expected=expected,
        matchers={
            "ttp_match": ttp_hits,
            "ind_47": ind_hits,
            "ind_47_high": ind_high,
            "seq_pattern": seq_hits,
            "seq_high": high_sev_seq,
            "seq_medium": medium_sev_seq,
            "taint_flows": taint_total,
            "llm_stub": llm_verdict.value,
            "benign_context": benign_context,
            "max_high_per_file": max_high_per_file,
            "files_with_high_ind": len(files_with_high_ind),
            "cooccur_files": len(cooccur_files),
            "is_concentrated": is_concentrated,
            "is_spread": is_spread,
            "is_popular": _is_popular(name, ecosystem),
            "has_decisive": has_decisive,
            "ind_codes": sorted(ind_codes_present),
        },
        elapsed_s=round(time.time() - t0, 2),
        n_files=len(files),
        n_python=n_python,
        n_js=n_js,
    )


# ─────────────── 집계 ───────────────

def _wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% confidence interval for binomial proportion.

    n=0 → (0, 0). 작은 n 에서도 normal approximation 보다 정확.
    """
    if n == 0:
        return 0.0, 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * (((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def _confusion(results: list[FixtureResult]) -> dict:
    tp = fp = tn = fn = 0
    for r in results:
        is_mal_pred = r.verdict in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        is_mal_true = (r.label == "malicious")
        if is_mal_true and is_mal_pred:
            tp += 1
        elif is_mal_true and not is_mal_pred:
            fn += 1
        elif (not is_mal_true) and is_mal_pred:
            fp += 1
        else:
            tn += 1
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    acc = (tp + tn) / max(1, len(results))
    # 95% Wilson score CI
    p_lo, p_hi = _wilson_interval(tp, tp + fp)
    r_lo, r_hi = _wilson_interval(tp, tp + fn)
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
        "accuracy": round(acc, 4),
        "n": len(results),
        "precision_ci95": [round(p_lo, 4), round(p_hi, 4)],
        "recall_ci95": [round(r_lo, 4), round(r_hi, 4)],
    }


def _confusion_by_source(results: list[FixtureResult]) -> dict:
    """source(데이터셋 카테고리) 별 분해."""
    out = {}
    sources = sorted({r.source for r in results})
    for s in sources:
        sub = [r for r in results if r.source == s]
        out[s] = _confusion(sub)
    return out


# ─────────────── 출력 ───────────────

def _print_table(results: list[FixtureResult]):
    print(f"{'name':<38} {'eco':<5} {'src':<22} "
          f"{'label':<10} {'verdict':<11} {'OK?':<5} {'matchers'}")
    print("-" * 145)
    for r in results:
        ok = "OK" if r.expected else "FAIL"
        mr = r.matchers or {}
        m = (f"ind={mr.get('ind_47',0)}({mr.get('ind_47_high',0)}H) "
             f"seq={mr.get('seq_pattern',0)}({mr.get('seq_high',0)}H) "
             f"taint={mr.get('taint_flows',0)} "
             f"llm={(mr.get('llm_stub','-') or '-')[:4]}")
        src_short = r.source.replace("datadog/", "dd:").replace("registry", "reg")
        name_short = (r.name[:35] + "..") if len(r.name) > 37 else r.name
        print(f"{name_short:<38} {r.ecosystem:<5} {src_short:<22} "
              f"{r.label:<10} {r.verdict:<11} {ok:<5} {m}")


def _process_one(meta: dict) -> FixtureResult:
    """multiprocessing worker — single fixture 평가.

    pickling 가능해야 하므로 module top-level. DATA_DIR 은 module-level constant
    이므로 sub-process 에도 보임.
    """
    archive_path = DATA_DIR / meta["archive_path"]
    try:
        archive_bytes = archive_path.read_bytes()
        files = extract_archive(
            archive_bytes, meta["archive_format"], meta["label"],
        )
        if not files:
            return FixtureResult(
                name=meta["name"], ecosystem=meta["ecosystem"],
                version=meta["version"], label=meta["label"],
                source=meta["source"], verdict="ERROR",
                expected=False, error="no extractable source files",
            )
        return _evaluate(meta, files)
    except Exception as e:
        tb = traceback.format_exc()[:300]
        return FixtureResult(
            name=meta["name"], ecosystem=meta["ecosystem"],
            version=meta["version"], label=meta["label"],
            source=meta["source"], verdict="ERROR",
            expected=False, error=f"{e}\n{tb}",
        )


def main():
    import argparse
    import multiprocessing as mp

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--fixtures", default=str(DATA_DIR / "fixtures.json"),
        help="eval_real_fetch.py 가 만든 fixtures.json 경로",
    )
    ap.add_argument(
        "--json", default=str(DATA_DIR / "results.json"),
        help="결과 저장 경로",
    )
    ap.add_argument(
        "--limit", type=int, default=0,
        help="N개만 평가 (0=전부)",
    )
    ap.add_argument(
        "--workers", type=int, default=0,
        help="병렬 worker 수 (0=cpu_count, 1=직렬)",
    )
    ap.add_argument(
        "--llm", choices=["stub", "claude"], default="stub",
        help="Stage 5 LLM 모드. claude → 실제 Anthropic API 호출 (요금 발생)",
    )
    ap.add_argument(
        "--stratified", type=int, default=0,
        help="N 개 fixture 를 카테고리별 균형 sample (compromised + malicious_intent + benign FP 후보).",
    )
    args = ap.parse_args()

    # Stage 5 mode 를 환경변수로 전파 — sub-process 도 상속.
    os.environ["PKGSENTINEL_LLM_MODE"] = args.llm
    if args.llm == "claude":
        # 실제 API 호출 시 multiprocessing rate limit 위험 → worker 수 제한
        if args.workers == 0:
            args.workers = 4
        # Anthropic 키 확인
        from pkgsentinel import _dotenv as _ad
        _ad.load()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY not set. Add to .env or export.",
                  file=sys.stderr)
            sys.exit(2)
        print(f"  LLM mode    : claude (Anthropic API will be called)")

    fixtures_path = Path(args.fixtures)
    if not fixtures_path.exists():
        print(f"fixtures not found: {fixtures_path}", file=sys.stderr)
        print("run scripts/eval_real_fetch.py first.", file=sys.stderr)
        sys.exit(2)

    with fixtures_path.open(encoding="utf-8") as f:
        manifest = json.load(f)

    fixtures_meta = manifest["fixtures"]

    # Stratified sample — LLM 평가 시 N 적은 sample 로 카테고리별 균형 유지
    if args.stratified > 0:
        # 직전 stub 결과가 있으면 FP 후보 우선 — 그 외 무작위
        prev_results_path = Path(args.json).parent / "results.json"
        prev_fp_names: set[str] = set()
        if prev_results_path.exists() and prev_results_path != Path(args.json):
            try:
                prev = json.loads(prev_results_path.read_text(encoding="utf-8"))
                prev_fp_names = {
                    f["name"] for f in prev.get("fixtures", [])
                    if f["label"] == "benign" and not f["expected"]
                }
            except Exception:
                pass

        import random
        rng = random.Random(42)
        comp = [f for f in fixtures_meta if f["source"] == "datadog/compromised_lib"]
        mali = [f for f in fixtures_meta if f["source"] == "datadog/malicious_intent"]
        ben = [f for f in fixtures_meta if f["label"] == "benign"]
        # benign — FP 후보 우선
        ben_fp = [f for f in ben if f["name"] in prev_fp_names]
        ben_other = [f for f in ben if f["name"] not in prev_fp_names]

        # 비율: compromised 30%, malicious_intent 30%, benign 40% (FP 우선)
        n = args.stratified
        n_comp = min(len(comp), n * 30 // 100)
        n_mali = min(len(mali), n * 30 // 100)
        n_ben = n - n_comp - n_mali
        n_ben_fp = min(len(ben_fp), n_ben * 80 // 100)
        n_ben_other = n_ben - n_ben_fp

        rng.shuffle(comp)
        rng.shuffle(mali)
        rng.shuffle(ben_fp)
        rng.shuffle(ben_other)

        fixtures_meta = (
            comp[:n_comp] + mali[:n_mali]
            + ben_fp[:n_ben_fp] + ben_other[:n_ben_other]
        )
        print(f"  stratified sample: comp={n_comp} mali={n_mali} "
              f"ben_fp={n_ben_fp} ben_other={n_ben_other}")
    elif args.limit:
        fixtures_meta = fixtures_meta[: args.limit]

    n_workers = args.workers if args.workers > 0 else max(1, mp.cpu_count() - 1)

    print(f"Total fixtures: {len(fixtures_meta)}")
    print(f"  malicious: {sum(1 for f in fixtures_meta if f['label']=='malicious')}")
    print(f"  benign   : {sum(1 for f in fixtures_meta if f['label']=='benign')}")
    print(f"  workers  : {n_workers}\n")

    results: list[FixtureResult] = []
    t0 = time.time()
    if n_workers == 1:
        for i, meta in enumerate(fixtures_meta):
            results.append(_process_one(meta))
            if (i + 1) % 25 == 0:
                print(f"  ... {i+1}/{len(fixtures_meta)} processed", flush=True)
    else:
        with mp.Pool(processes=n_workers) as pool:
            for i, r in enumerate(
                pool.imap_unordered(_process_one, fixtures_meta, chunksize=4)
            ):
                results.append(r)
                if (i + 1) % 25 == 0:
                    print(
                        f"  ... {i+1}/{len(fixtures_meta)} processed "
                        f"({(i+1)/(time.time()-t0):.1f}/s)",
                        flush=True,
                    )

    elapsed = time.time() - t0
    print()
    # 500+ fixture 시 표가 너무 길어서 라벨별 5개씩만 sample 출력
    n_total = len(results)
    if n_total > 100:
        print(f"(table sampling: {n_total} total, showing first 5 mal + 5 ben "
              "+ failures)")
        mal = [r for r in results if r.label == "malicious"]
        ben = [r for r in results if r.label == "benign"]
        failures = [r for r in results if not r.expected]
        sample = mal[:5] + ben[:5] + failures[:30]
        # 중복 제거
        seen = set()
        uniq = []
        for r in sample:
            key = (r.name, r.version)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(r)
        _print_table(uniq)
    else:
        _print_table(results)
    print()

    cm = _confusion(results)
    print("=== Confusion Matrix (overall) ===")
    print(f"  TP: {cm['tp']:>4}   FN: {cm['fn']:>4}")
    print(f"  FP: {cm['fp']:>4}   TN: {cm['tn']:>4}")
    print()
    print("=== Metrics ===")
    p_lo, p_hi = cm["precision_ci95"]
    r_lo, r_hi = cm["recall_ci95"]
    print(f"  Precision : {cm['precision']:.4f}  (95% CI [{p_lo:.3f}, {p_hi:.3f}])")
    print(f"  Recall    : {cm['recall']:.4f}  (95% CI [{r_lo:.3f}, {r_hi:.3f}])")
    print(f"  F1        : {cm['f1']:.4f}")
    print(f"  Accuracy  : {cm['accuracy']:.4f}")
    print(f"  Elapsed   : {elapsed:.2f}s "
          f"({elapsed*1000/max(1,len(results)):.0f} ms/fixture)")

    print("\n=== Per-source breakdown ===")
    by_src = _confusion_by_source(results)
    for src, sm in by_src.items():
        rl, rh = sm["recall_ci95"]
        print(f"  [{src}] n={sm['n']:>4} "
              f"TP={sm['tp']:>4} FN={sm['fn']:>4} "
              f"FP={sm['fp']:>4} TN={sm['tn']:>4}  "
              f"R={sm['recall']:.3f} (CI[{rl:.2f},{rh:.2f}]) "
              f"P={sm['precision']:.3f} F1={sm['f1']:.3f}")

    # JSON 저장
    out_path = Path(args.json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "fixtures": [
            {
                "name": r.name, "ecosystem": r.ecosystem,
                "version": r.version, "label": r.label, "source": r.source,
                "verdict": r.verdict, "expected": r.expected,
                "matchers": r.matchers,
                "elapsed_s": r.elapsed_s,
                "n_files": r.n_files, "n_python": r.n_python, "n_js": r.n_js,
                "error": r.error,
            }
            for r in results
        ],
        "metrics": cm,
        "by_source": by_src,
        "elapsed_total_s": round(elapsed, 2),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nJSON saved -> {out_path}")

    pass_rate = sum(1 for r in results if r.expected) / max(1, len(results))
    sys.exit(0 if pass_rate >= 0.8 else 1)


if __name__ == "__main__":
    main()
