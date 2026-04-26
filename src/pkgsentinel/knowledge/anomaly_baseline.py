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


CATEGORIES: list[Category] = [
    Category(
        name="parser",
        description="JSON/YAML/CSV/XML 등 데이터 파서",
        keywords=["json", "yaml", "csv", "xml", "toml", "parser", "parse"],
        allowed_dimensions={AttackDimension.INFORMATION_READING},
        disallowed_apis={
            "requests.post", "requests.get",
            "subprocess.run", "subprocess.Popen", "os.system",
            "child_process.exec", "child_process.spawn",
            "http.request", "https.request", "fetch",
            "eval", "exec",
        },
    ),
    Category(
        name="formatter",
        description="로그/문자열 포매터, 색상 라이브러리 등",
        keywords=["format", "color", "log", "chalk", "ansi", "style"],
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
        name="date_utility",
        description="날짜/시간 유틸리티",
        keywords=["date", "time", "moment", "dayjs", "luxon", "timezone"],
        allowed_dimensions=set(),
        disallowed_apis={
            "requests.post", "subprocess.run",
            "http.request", "fetch",
            "eval", "exec",
            "os.environ.get",
        },
    ),
    Category(
        name="math_utility",
        description="수학/통계 유틸리티",
        keywords=["math", "stat", "random", "number", "calc"],
        allowed_dimensions=set(),
        disallowed_apis={
            "requests.post", "subprocess.run", "os.environ.get",
            "http.request", "fetch", "eval", "exec",
        },
    ),
]


# ─────────────── 카테고리 추정 ───────────────

def guess_category(package_name: str, description: str = "") -> Category | None:
    """패키지 이름/설명에서 카테고리 추정."""
    text = (package_name + " " + description).lower()
    for cat in CATEGORIES:
        for kw in cat.keywords:
            if kw in text:
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
    from .anomaly_baseline import detect_anomalies  # noqa
    from ..stages.stage2_behavior import FileSequence, APICall

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
