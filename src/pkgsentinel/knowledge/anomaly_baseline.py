"""
이상 탐지 베이스라인.

동일 카테고리 패키지들의 "평균적인 행위 프로필" 을 미리 수집하고,
분석 대상이 그 프로필에서 크게 벗어나면 이상 신호로 기록.

예:
  JSON 파서 카테고리 패키지들의 평균 API 호출 집합
    = {json.loads, json.dumps, re, ...}  → 네트워크/실행 API 거의 없음
  → 분석 대상 JSON 파서에서 requests.post 가 보이면 이상.

현재 구현:
  - 카테고리는 간단한 키워드/설명 기반 (ML 분류기 X)
  - 베이스라인은 "이 카테고리에서 나타나면 안 되는 API" 화이트리스트 방식
  - 충분한 데이터가 모이면 나중에 통계 기반으로 승격 가능
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..schema import AttackDimension
from ..stages.stage2_behavior import FileSequence

# ─────────────── 카테고리 정의 ───────────────

@dataclass
class Category:
    name: str
    description: str
    keywords: list[str]             # 패키지명/설명에 이 키워드가 있으면 이 카테고리
    allowed_dimensions: set[AttackDimension]
    disallowed_apis: set[str] = field(default_factory=set)


# 우선순위 순 (앞에 있는 더 구체적인 카테고리가 먼저 매칭).
# 2026-05-06 reorder: date_utility / formatter / math_utility 를 parser 보다
# 앞에 두어 "moment" / "chalk" 가 의도된 카테고리로 분류되도록.
CATEGORIES: list[Category] = [
    Category(
        name="date_utility",
        description="날짜/시간 유틸리티",
        keywords=["date", "moment", "dayjs", "luxon", "timezone"],
        allowed_dimensions=set(),
        disallowed_apis={
            "requests.post", "subprocess.run",
            "http.request", "fetch",
            "eval", "exec",
            "os.environ.get",
        },
    ),
    Category(
        name="formatter",
        description="로그/문자열 포매터, 색상 라이브러리 등",
        keywords=["chalk", "ansi"],  # 매우 좁은 키워드만 (color/log/style 은 너무 광범위)
        allowed_dimensions=set(),  # 네트워크/실행 모두 이상
        disallowed_apis={
            "requests.post", "requests.get",
            "subprocess.run", "subprocess.Popen",
            "http.request", "fetch",
            "eval", "exec",
            "os.environ.get",       # color 라이브러리가 env 읽을 이유 없음
            "process.env",
        },
    ),
    Category(
        name="math_utility",
        description="수학/통계 유틸리티",
        # "stat" / "math" 단독 키워드는 너무 광범위 → 좁은 키워드만.
        # "math" 는 word-boundary 로도 mathjs/math.js 같은 작은 lib 만 매칭.
        keywords=["mathjs", "decimal.js"],
        allowed_dimensions=set(),
        disallowed_apis={
            "requests.post", "subprocess.run", "os.environ.get",
            "http.request", "fetch", "eval", "exec",
        },
    ),
    Category(
        name="parser",
        description="JSON/YAML/CSV/XML 등 데이터 파서",
        # "json"/"yaml" 단독 키워드는 web framework 등에서도 등장 → 좁게.
        keywords=["json parser", "yaml parser", "csv parser", "xml parser",
                  "toml parser", "json5"],
        allowed_dimensions={AttackDimension.INFORMATION_READING},
        disallowed_apis={
            "requests.post", "requests.get",
            "subprocess.run", "subprocess.Popen", "os.system",
            "child_process.exec", "child_process.spawn",
            "http.request", "https.request", "fetch",
            "eval", "exec",
        },
    ),
]


# ─────────────── 카테고리 추정 ───────────────

# 카테고리 추정에 disqualifying 키워드 — 있으면 좁은 카테고리로 분류 안 함.
# 합법 multi-purpose 도구 (numpy / pandas / scipy / jupyter 등) 가 narrow
# category 로 잘못 분류되어 anomaly_baseline FP 폭증하는 것 방지.
# 2026-05-06 추가: pandas 가 "statistics" 의 substring 매칭 "stat" 으로
# math_utility 로 분류되어 13건 anomaly 발생 — 이걸 차단.
#
# "library" 같은 일반 단어는 의도적으로 제외 (거의 모든 패키지 설명에 등장).
_BROAD_PURPOSE_HINTS = {
    "data analysis", "data structures", "dataframe",
    "scientific computing", "numerical computing",
    "machine learning", "deep learning",
    "web framework", "application framework",
    "ide", "notebook", "interactive shell",
    "build system",
}


def guess_category(package_name: str, description: str = "") -> Category | None:
    """패키지 이름/설명에서 카테고리 추정.

    매칭 정책:
      1. **word-boundary** 매칭 사용 (substring 매칭 X)
         "stat" 는 "statistics" 와 매칭하지 않음 — 별도 단어일 때만.
      2. broad-purpose 힌트가 description 에 있으면 narrow category 분류 거부.
         (numpy/pandas/scipy 같은 multi-purpose 도구의 misclassification 방지)
    """
    text = (package_name + " " + description).lower()

    # broad-purpose 힌트 — 있으면 분류 안 함
    if any(hint in text for hint in _BROAD_PURPOSE_HINTS):
        return None

    for cat in CATEGORIES:
        for kw in cat.keywords:
            # word-boundary 매칭. 키워드를 escape 해서 정규식 특수문자 안전.
            if re.search(r"\b" + re.escape(kw) + r"\b", text):
                return cat
    return None


# ─────────────── 이상 탐지 ───────────────

@dataclass
class AnomalyFinding:
    category: str
    file_path: str
    unexpected_apis: list[str]
    unexpected_dimensions: list[AttackDimension]
    reason: str


def check_anomaly(
    file_seq: FileSequence,
    category: Category,
) -> AnomalyFinding | None:
    """파일 하나가 카테고리 베이스라인에서 벗어나는지 확인."""
    unexpected_apis: list[str] = []
    unexpected_dims: list[AttackDimension] = []

    for c in file_seq.calls:
        if c.name in category.disallowed_apis:
            unexpected_apis.append(c.name)
        if (
            c.dimension not in category.allowed_dimensions
            and c.dimension in (
                AttackDimension.DATA_TRANSMISSION,
                AttackDimension.PAYLOAD_EXECUTION,
                AttackDimension.ENCODING,
            )
        ):
            if c.dimension not in unexpected_dims:
                unexpected_dims.append(c.dimension)

    if not unexpected_apis and not unexpected_dims:
        return None

    return AnomalyFinding(
        category=category.name,
        file_path=file_seq.path,
        unexpected_apis=sorted(set(unexpected_apis)),
        unexpected_dimensions=unexpected_dims,
        reason=(
            f"Package classified as {category.name!r} ({category.description}) "
            f"but exhibits APIs/dimensions that are atypical for this category. "
            f"Unexpected APIs: {sorted(set(unexpected_apis))[:5]}, "
            f"Unexpected dimensions: {[d.value for d in unexpected_dims]}"
        ),
    )


# ─────────────── 공개 API ───────────────

def detect_anomalies(
    package_name: str,
    description: str,
    file_sequences: list[FileSequence],
) -> list[AnomalyFinding]:
    category = guess_category(package_name, description)
    if category is None:
        return []  # 카테고리 추정 실패 → 이상 탐지 스킵

    findings: list[AnomalyFinding] = []
    for fs in file_sequences:
        f = check_anomaly(fs, category)
        if f:
            findings.append(f)
    return findings


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    # 합성 예시
    from ..schema import AttackDimension as D
    from ..stages.stage2_behavior import APICall, FileSequence
    from .anomaly_baseline import detect_anomalies  # noqa

    # 예: JSON 파서 카테고리 패키지인데 requests 를 사용
    fake_seq = FileSequence(path="evil-parser/__init__.py", language="python")
    fake_seq.calls = [
        APICall(name="open", line=5, dimension=D.INFORMATION_READING, snippet=""),
        APICall(name="requests.post", line=20, dimension=D.DATA_TRANSMISSION, snippet=""),
    ]
    findings = detect_anomalies("evil-json-parser", "JSON parser library", [fake_seq])
    for f in findings:
        print(f"[ANOMALY] category={f.category}, file={f.file_path}")
        print(f"  reason: {f.reason}")
