"""
Stage 3 — 버전 차이 분석.

이전 버전 N-1, N-3, N-5 를 다운로드해 Entry Point 의 Behavior Sequence 를 비교.
현재 버전에서 "새로 등장한 API 호출"을 식별한다.

axios / event-stream 유형의 '합법 패키지에 악성 주입' 공격을 잡는 핵심 단서.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..schema import Severity, VersionDiffInfo, AttackDimension
from .stage0_registry import RegistryInfo
from .stage1_entry_point import extract, ExtractedPackage
from .stage2_behavior import analyze, BehaviorReport


# ─────────────── 결과 ───────────────

@dataclass
class VersionDiffResult:
    current_version: str
    compared_versions: list[str] = field(default_factory=list)
    new_apis: list[str] = field(default_factory=list)
    new_dimensions: list[AttackDimension] = field(default_factory=list)
    risk_classification: Severity = Severity.LOW
    details: str = ""
    error: Optional[str] = None

    def to_version_diff_info(self) -> Optional[VersionDiffInfo]:
        if not self.compared_versions or self.error:
            return None
        return VersionDiffInfo(
            compared_versions=self.compared_versions,
            new_apis=self.new_apis,
            risk_classification=self.risk_classification,
            details=self.details,
        )


# ─────────────── 이전 버전 선택 규칙 ───────────────

def _pick_previous_versions(
    versions: list[str],
    current: str,
    offsets: list[int] = (1, 3, 5),
) -> list[str]:
    """현재 버전 기준 N-1, N-3, N-5 위치의 버전 문자열 리스트 반환.
    정렬된 리스트를 입력으로 가정 (registry check 에서 정렬됨)."""
    if current not in versions:
        return []
    idx = versions.index(current)
    picks = []
    for off in offsets:
        j = idx - off
        if j >= 0:
            picks.append(versions[j])
    # 중복 제거, 순서 유지
    return list(dict.fromkeys(picks))


# ─────────────── 위험 증가 분류 ───────────────

_HIGH_RISK_COMBOS = [
    # (집합 A, 집합 B) 둘 다 새로 등장 시 HIGH
    ({AttackDimension.DATA_TRANSMISSION}, {AttackDimension.INFORMATION_READING}),
    ({AttackDimension.DATA_TRANSMISSION}, {AttackDimension.ENCODING}),
    ({AttackDimension.PAYLOAD_EXECUTION}, {AttackDimension.ENCODING}),
    ({AttackDimension.PAYLOAD_EXECUTION}, {AttackDimension.DATA_TRANSMISSION}),
]


def _classify_risk(new_dims: set[AttackDimension]) -> tuple[Severity, str]:
    if not new_dims:
        return Severity.LOW, "no new suspicious behavior introduced"

    # HIGH: 위험 조합 등장
    for a, b in _HIGH_RISK_COMBOS:
        if a.issubset(new_dims) and b.issubset(new_dims):
            return (
                Severity.HIGH,
                f"new risky combination: {' + '.join(d.value for d in (a | b))}",
            )

    # MEDIUM: 단일 위험 차원 등장
    if any(
        d in new_dims
        for d in (AttackDimension.PAYLOAD_EXECUTION, AttackDimension.DATA_TRANSMISSION)
    ):
        return (
            Severity.MEDIUM,
            f"new dimension introduced: {', '.join(d.value for d in new_dims)}",
        )

    # LOW: 읽기/인코딩만 추가
    return (
        Severity.LOW,
        f"minor new behavior: {', '.join(d.value for d in new_dims)}",
    )


# ─────────────── 메인 ───────────────

def analyze_version_diff(
    registry_info: RegistryInfo,
    current_ext: ExtractedPackage,
    current_behavior: BehaviorReport,
) -> VersionDiffResult:
    pkg = current_ext.package
    eco = current_ext.ecosystem
    curr_v = current_ext.version

    result = VersionDiffResult(current_version=curr_v)

    if not registry_info.all_versions:
        result.error = "no version list available"
        return result

    prev_versions = _pick_previous_versions(registry_info.all_versions, curr_v)
    if not prev_versions:
        result.error = "no earlier versions to compare (likely first release)"
        return result

    result.compared_versions = prev_versions

    # 현재 버전의 API 집합
    current_apis = set(current_behavior.all_sequence())

    # 이전 버전들에서 나타난 API 합집합
    prev_apis: set[str] = set()
    for pv in prev_versions:
        url = registry_info.archive_urls.get(pv)
        if not url:
            continue
        try:
            prev_ext = extract(pkg, eco, pv, url)
            if prev_ext.error:
                continue
            prev_behavior = analyze(prev_ext)
            prev_apis.update(prev_behavior.all_sequence())
        except Exception:
            # 이전 버전 분석 실패는 치명적 아님 (비교 대상 줄어듦)
            continue

    new_apis = sorted(current_apis - prev_apis)
    result.new_apis = new_apis

    # Dimension 집계
    from .api_catalog import lookup_python, lookup_js
    new_dims: set[AttackDimension] = set()
    for api in new_apis:
        if api.startswith("shell:"):
            # shell 패턴은 이미 dimension 이 따로 붙어있음 — 간이로 분류
            if "curl" in api or "wget" in api:
                new_dims.add(AttackDimension.DATA_TRANSMISSION)
            elif "base64" in api:
                new_dims.add(AttackDimension.ENCODING)
            else:
                new_dims.add(AttackDimension.PAYLOAD_EXECUTION)
            continue

        dim = lookup_python(api) or lookup_js(api)
        if dim:
            new_dims.add(dim)

    result.new_dimensions = sorted(new_dims, key=lambda d: d.value)

    severity, detail = _classify_risk(new_dims)
    result.risk_classification = severity
    result.details = (
        f"{detail}. "
        f"compared with versions: {', '.join(prev_versions)}"
    )

    return result


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys
    from ..schema import Ecosystem
    from .stage0_registry import check
    from .stage1_entry_point import extract
    from .stage2_behavior import analyze as analyze_behavior

    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    if not info.found:
        print("not found")
        sys.exit(1)

    v = info.latest_version
    url = info.archive_urls.get(v)
    ext = extract(pkg, eco, v, url)
    behavior = analyze_behavior(ext)

    diff = analyze_version_diff(info, ext, behavior)
    print(f"current: {diff.current_version}")
    print(f"compared: {diff.compared_versions}")
    print(f"new APIs: {diff.new_apis}")
    print(f"new dimensions: {[d.value for d in diff.new_dimensions]}")
    print(f"risk: {diff.risk_classification.value}")
    print(f"details: {diff.details}")
    if diff.error:
        print(f"error: {diff.error}")
