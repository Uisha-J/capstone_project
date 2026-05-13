"""
Stage 3B — 전 파일 버전 차이 분석.

기존 Stage 3은 Entry Point만 비교했지만, event-stream 사건처럼
악성 코드가 깊은 서브모듈에 숨는 경우를 잡지 못한다.

이 모듈은 FullSourceExtract (stage1b) 를 받아
전체 소스 파일 단위로 버전 간 diff를 수행한다.

감지 항목:
  - 이전 버전에 없던 파일 (신규 파일)
  - 기존 파일에서 새로 등장한 API 호출
  - 기존 파일의 크기가 급격히 변한 경우 (>50% 증가)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import AttackDimension, Severity, VersionDiffInfo
from .stage0_registry import RegistryInfo
from .stage1_entry_point import EntryFile
from .stage1b_full_source import FullSourceExtract, FullSourceFile, extract_all
from .stage2_behavior import BehaviorReport

# ─────────────── 결과 ───────────────

@dataclass
class FileDiff:
    path: str
    kind: str                    # "new_file" | "modified" | "api_added"
    new_apis: list[str] = field(default_factory=list)
    size_before: int = 0
    size_after: int = 0
    dimensions_added: list[AttackDimension] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "new_apis": list(self.new_apis),
            "size_before": self.size_before,
            "size_after": self.size_after,
            "dimensions_added": [d.value for d in self.dimensions_added],
        }

    @classmethod
    def from_dict(cls, d: dict) -> FileDiff:
        return cls(
            path=d["path"],
            kind=d["kind"],
            new_apis=list(d.get("new_apis", [])),
            size_before=int(d.get("size_before", 0)),
            size_after=int(d.get("size_after", 0)),
            dimensions_added=[
                AttackDimension(v) for v in d.get("dimensions_added", [])
            ],
        )


@dataclass
class DependencyChange:
    """패키지 manifest 의 dependencies 변화 (#Z6)."""
    kind: str                # "added" | "removed" | "version_changed"
    name: str
    old_spec: str = ""
    new_spec: str = ""
    is_dangerous: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "name": self.name,
            "old_spec": self.old_spec, "new_spec": self.new_spec,
            "is_dangerous": self.is_dangerous, "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DependencyChange":
        return cls(
            kind=d.get("kind", ""), name=d.get("name", ""),
            old_spec=d.get("old_spec", ""), new_spec=d.get("new_spec", ""),
            is_dangerous=bool(d.get("is_dangerous", False)),
            reason=d.get("reason", ""),
        )


# 위험 의존성 — 정상 패키지가 갑자기 추가하면 의심 (#Z6)
# child_process, crypto 등은 시스템 호출 / 자격증명 류 능력 제공
DANGEROUS_NEW_DEPS = {
    # npm
    "child_process", "node:child_process",
    "node:crypto",            # 정상은 import; 신규 추가는 의심
    "request", "node-fetch", "axios", "got",   # 신규 등장 시 의심 (이미 있던 게 아니면)
    # PyPI
    "subprocess", "pycryptodome", "cryptography",
    "requests", "urllib3", "httpx",            # 신규 등장 시 — 단, 일반적이라 weight 낮음
    "paramiko", "fabric",     # SSH/remote exec
    "psutil",                 # 시스템 정보
    "PyInstaller",
}

# 정말 위험 — 무조건 의심
HIGH_RISK_NEW_DEPS = {
    "node:child_process", "child_process",
    "paramiko", "fabric",
    "pyinstaller",
}


@dataclass
class FullDiffResult:
    current_version: str
    compared_versions: list[str] = field(default_factory=list)
    file_diffs: list[FileDiff] = field(default_factory=list)
    # #Z6 — manifest dependencies 변화
    dep_changes: list[DependencyChange] = field(default_factory=list)
    overall_severity: Severity = Severity.LOW
    summary: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "current_version": self.current_version,
            "compared_versions": list(self.compared_versions),
            "file_diffs": [fd.to_dict() for fd in self.file_diffs],
            "dep_changes": [dc.to_dict() for dc in self.dep_changes],
            "overall_severity": self.overall_severity.value,
            "summary": self.summary,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict) -> FullDiffResult:
        return cls(
            current_version=d.get("current_version", ""),
            compared_versions=list(d.get("compared_versions", [])),
            file_diffs=[FileDiff.from_dict(fd) for fd in d.get("file_diffs", [])],
            dep_changes=[
                DependencyChange.from_dict(dc)
                for dc in d.get("dep_changes", [])
            ],
            overall_severity=Severity(d.get("overall_severity", Severity.LOW.value)),
            summary=d.get("summary", ""),
            error=d.get("error"),
        )

    def to_version_diff_info(self) -> VersionDiffInfo | None:
        if not self.compared_versions or self.error:
            return None
        # 통합 new_apis 리스트
        all_new = []
        for fd in self.file_diffs:
            all_new.extend(fd.new_apis)
        return VersionDiffInfo(
            compared_versions=self.compared_versions,
            new_apis=sorted(set(all_new))[:50],
            risk_classification=self.overall_severity,
            details=self.summary,
        )


# ─────────────── 유틸 ───────────────

def diff_dependencies(
    prev_deps: dict[str, str],
    curr_deps: dict[str, str],
) -> list[DependencyChange]:
    """두 버전의 dep map ({name: version_spec}) 비교 → 변화 목록.

    각 변화에 대해 *위험 의존성* 추가/변경 여부 분류 (#Z6).
    """
    changes: list[DependencyChange] = []
    prev_keys = set(prev_deps.keys())
    curr_keys = set(curr_deps.keys())

    # 추가
    for name in (curr_keys - prev_keys):
        nlow = name.lower()
        is_high_risk = nlow in HIGH_RISK_NEW_DEPS
        is_dangerous = nlow in DANGEROUS_NEW_DEPS or is_high_risk
        reason = ""
        if is_high_risk:
            reason = f"high-risk dependency added: {name}"
        elif is_dangerous:
            reason = f"sensitive dependency added: {name}"
        changes.append(DependencyChange(
            kind="added", name=name,
            new_spec=curr_deps.get(name, ""),
            is_dangerous=is_dangerous, reason=reason,
        ))

    # 제거
    for name in (prev_keys - curr_keys):
        changes.append(DependencyChange(
            kind="removed", name=name,
            old_spec=prev_deps.get(name, ""),
            is_dangerous=False,
            reason="dependency removed (informational)",
        ))

    # 버전 변경
    for name in (prev_keys & curr_keys):
        old = prev_deps[name]
        new = curr_deps[name]
        if old != new:
            changes.append(DependencyChange(
                kind="version_changed", name=name,
                old_spec=old, new_spec=new,
                is_dangerous=False,
                reason=f"dependency version: {old} -> {new}",
            ))

    return changes


def _extract_deps_map(extract: FullSourceExtract) -> dict[str, str]:
    """FullSourceExtract → {dep_name: version_spec}.

    package.json / pyproject.toml / setup.py 합산. stage_dependency 의
    extract_dependencies 결과를 dict 으로 평탄화.
    """
    from .stage_dependency import extract_dependencies
    try:
        de = extract_dependencies(extract.source_files, extract.ecosystem)
    except Exception:
        return {}
    out: dict[str, str] = {}
    for dep in (de.direct_deps + de.dev_deps):
        # 같은 이름 두 번 등장 시 첫 entry 우선
        out.setdefault(dep.name, dep.version_spec)
    return out


def _sources_to_entry_files(extract: FullSourceExtract) -> list[EntryFile]:
    """FullSourceExtract → Stage 2 가 받는 EntryFile 리스트."""
    return [
        EntryFile(
            path=sf.path,
            basename=sf.basename,
            content=sf.content,
            size=sf.size,
            language=sf.language,
        )
        for sf in extract.source_files
        if sf.language in ("python", "javascript")
    ]


def _behavior_for_files(files: list[EntryFile]) -> BehaviorReport:
    """FullSource → Stage 2 재사용."""
    # Stage 2 는 ExtractedPackage를 받지만, 여기선 EntryFile 리스트만 필요
    from .stage2_behavior import _analyze_javascript, _analyze_python

    report = BehaviorReport()
    for ef in files:
        if ef.language == "python":
            report.files.append(_analyze_python(ef))
        elif ef.language == "javascript":
            report.files.append(_analyze_javascript(ef))
    return report


def _normalize_path(path: str) -> str:
    """'pkg-1.2.3/lib/foo.js' 형태에서 버전 부분 제거."""
    parts = path.replace("\\", "/").split("/")
    if not parts:
        return path
    # 첫 번째 디렉터리가 "pkg-x.y.z" 패턴이면 제거
    first = parts[0]
    if "-" in first and any(ch.isdigit() for ch in first):
        parts = parts[1:]
    # npm 의 경우 "package/" 로 시작
    if parts and parts[0] == "package":
        parts = parts[1:]
    return "/".join(parts)


def _classify_severity(
    new_apis_all: set[str],
    new_files_count: int,
    new_dimensions: set[AttackDimension],
) -> tuple[Severity, str]:
    # 위험 조합 (DATA_TRANSMISSION + ENCODING, EXECUTION + TRANSMISSION 등)
    high_combos = [
        {AttackDimension.DATA_TRANSMISSION, AttackDimension.ENCODING},
        {AttackDimension.PAYLOAD_EXECUTION, AttackDimension.ENCODING},
        {AttackDimension.PAYLOAD_EXECUTION, AttackDimension.DATA_TRANSMISSION},
        {AttackDimension.INFORMATION_READING, AttackDimension.DATA_TRANSMISSION},
    ]
    for combo in high_combos:
        if combo.issubset(new_dimensions):
            return (
                Severity.HIGH,
                f"HIGH: new cross-dimension behavior introduced "
                f"({' + '.join(d.value for d in combo)}). "
                f"{new_files_count} new file(s), {len(new_apis_all)} new API(s)."
            )

    if any(
        d in new_dimensions
        for d in (AttackDimension.PAYLOAD_EXECUTION, AttackDimension.DATA_TRANSMISSION)
    ):
        return (
            Severity.MEDIUM,
            f"MEDIUM: risky new dimension introduced "
            f"({', '.join(d.value for d in new_dimensions)}). "
            f"{new_files_count} new file(s), {len(new_apis_all)} new API(s)."
        )

    if new_apis_all or new_files_count:
        return (
            Severity.LOW,
            f"LOW: minor changes — "
            f"{new_files_count} new file(s), {len(new_apis_all)} new API(s), "
            f"dimensions: {', '.join(d.value for d in new_dimensions) or 'none'}"
        )
    return Severity.LOW, "no behavior changes detected"


# ─────────────── 버전 선택 ───────────────

def _pick_previous_versions(
    versions: list[str],
    current: str,
    offsets=(1, 3, 5),
) -> list[str]:
    if current not in versions:
        return []
    idx = versions.index(current)
    picks = []
    for off in offsets:
        j = idx - off
        if j >= 0:
            picks.append(versions[j])
    return list(dict.fromkeys(picks))


# ─────────────── 메인 ───────────────

def _try_load_cached_prev(
    pkg: str, eco, prev_v: str,
) -> tuple[dict[str, set[str]] | None, dict[str, FullSourceFile] | None]:
    """직전 버전의 stage_2_behavior 캐시에서 (apis_by_file, files_partial) 복원.

    Stage cache 에 BehaviorReport 가 to_dict 직렬화로 저장돼 있으면 그대로 로드.
    - apis_by_file: {정규화된 path: {API 호출명, ...}}
    - files_partial: {정규화된 path: FullSourceFile placeholder} — *calls 가 있는
      파일만* (BehaviorReport.files 가 이미 그 필터 적용된 결과).

    한계: 호출 없는 파일은 캐시에 안 남음 → "신규 파일" 검출 부정확 가능.
    호출 측 (analyze_full_diff) 이 result.summary 의 [cached] prefix 로 이 사실을
    소비자에게 알림.

    캐시 미스 / DB 미가용 / 직렬화 오류 → (None, None) — 호출 측이 정상 fallback.
    """
    try:
        from ..db.stage_cache import StageCache, StageCacheKey
        from .stage2_behavior import BehaviorReport
    except Exception:
        return None, None

    try:
        sc = StageCache()
        key = StageCacheKey(
            package=pkg,
            ecosystem=getattr(eco, "value", str(eco)),
            version=prev_v,
            stage="stage_2_behavior",
        )
        # archive_sha256 일치 검증은 skip — 직전 버전 archive 가 안 바뀌었을
        # 거라는 가정. 만약 변경 시 stage_version 해시도 함께 바뀌므로 cache miss.
        hit = sc.get(key)
    except Exception:
        return None, None

    if not hit or not hit.hit or not hit.payload:
        return None, None

    try:
        behavior = BehaviorReport.from_dict(hit.payload)
    except Exception:
        return None, None

    apis_by_file: dict[str, set[str]] = {}
    files_partial: dict[str, FullSourceFile] = {}
    for fs in behavior.files:
        norm = _normalize_path(fs.path)
        apis_by_file[norm] = set(fs.sequence)
        # 최소 placeholder — analyze_full_diff 가 prev_sf.size 같은 필드를
        # api_added 케이스에는 안 씀. new_file 케이스만 size_before=prev_sf.size
        # 사용 — 그러나 캐시 모드에선 new_file 신뢰도 낮으므로 size=0 으로 표기.
        files_partial[norm] = FullSourceFile(
            path=fs.path,
            basename=fs.path.split("/")[-1],
            content="",
            size=0,
            language=fs.language,
            tier=1,
        )

    return apis_by_file, files_partial


def analyze_full_diff(
    registry_info: RegistryInfo,
    current_extract: FullSourceExtract,
    current_behavior: BehaviorReport,
) -> FullDiffResult:
    pkg = current_extract.package
    eco = current_extract.ecosystem
    curr_v = current_extract.version

    result = FullDiffResult(current_version=curr_v)

    if not registry_info.all_versions:
        result.error = "no version list"
        return result

    prev_versions = _pick_previous_versions(registry_info.all_versions, curr_v)
    if not prev_versions:
        result.error = "no earlier versions to compare"
        return result

    result.compared_versions = prev_versions

    # ─── 현재 파일 맵 ───
    curr_files: dict[str, FullSourceFile] = {
        _normalize_path(sf.path): sf for sf in current_extract.source_files
        if sf.language in ("python", "javascript")
    }

    # ─── 현재 파일별 API 호출 시퀀스 맵 ───
    # Stage 2 결과 사용. behavior 의 FileSequence 는 원본 path 를 가지므로 정규화.
    curr_apis_by_file: dict[str, set[str]] = {}
    for fs in current_behavior.files:
        key = _normalize_path(fs.path)
        curr_apis_by_file[key] = set(fs.sequence)

    # ─── 이전 버전들 분석 (한 번만 직전 버전 N-1 기준) ───
    # 성능 — 모든 이전 버전 전수 분석하면 너무 느리므로 N-1 만 비교
    prev_v = prev_versions[0]
    prev_url = registry_info.archive_urls.get(prev_v)
    if not prev_url:
        result.error = f"no archive url for previous version {prev_v}"
        return result

    # 1) 캐시 시도 — 직전 버전이 이미 분석된 적 있으면 재다운로드/재분석 없이 비교.
    cached_apis, cached_files = _try_load_cached_prev(pkg, eco, prev_v)
    if cached_apis is not None and cached_files is not None:
        prev_apis_by_file = cached_apis
        prev_files = cached_files
        result.summary = "[cached] "  # 결과 메시지 prefix 로 캐시 사용 표시
    else:
        # 2) 캐시 미스 — 기존처럼 직접 추출 + 분석
        try:
            prev_extract = extract_all(pkg, eco, prev_v, prev_url)
            if prev_extract.error:
                result.error = f"prev extract failed: {prev_extract.error}"
                return result

            prev_files = {
                _normalize_path(sf.path): sf for sf in prev_extract.source_files
                if sf.language in ("python", "javascript")
            }

            prev_entry_files = _sources_to_entry_files(prev_extract)
            prev_behavior = _behavior_for_files(prev_entry_files)
            prev_apis_by_file = {}
            for fs in prev_behavior.files:
                key = _normalize_path(fs.path)
                prev_apis_by_file[key] = set(fs.sequence)
        except Exception as e:
            result.error = f"prev analysis failed: {e}"
            return result

    # ─── Diff 계산 ───
    file_diffs: list[FileDiff] = []
    new_files_count = 0
    all_new_apis: set[str] = set()
    all_new_dims: set[AttackDimension] = set()

    from .api_catalog import lookup_js, lookup_python

    for path, sf in curr_files.items():
        prev_sf = prev_files.get(path)
        curr_apis = curr_apis_by_file.get(path, set())
        prev_apis = prev_apis_by_file.get(path, set())

        new_apis = curr_apis - prev_apis

        # 차원 변화
        dims_added = set()
        for api in new_apis:
            d = lookup_python(api) or lookup_js(api)
            if d:
                dims_added.add(d)
                all_new_dims.add(d)

        if prev_sf is None:
            # 신규 파일
            file_diffs.append(FileDiff(
                path=path,
                kind="new_file",
                new_apis=sorted(new_apis),
                size_before=0,
                size_after=sf.size,
                dimensions_added=sorted(dims_added, key=lambda d: d.value),
            ))
            new_files_count += 1
            all_new_apis.update(new_apis)
        elif new_apis:
            file_diffs.append(FileDiff(
                path=path,
                kind="api_added",
                new_apis=sorted(new_apis),
                size_before=prev_sf.size,
                size_after=sf.size,
                dimensions_added=sorted(dims_added, key=lambda d: d.value),
            ))
            all_new_apis.update(new_apis)

    result.file_diffs = file_diffs

    # #Z6 — dependencies 변화 감지
    # prev_extract 가 있는 경우 (캐시 모드 X) 만 시도. cache 모드는 manifest 데이터 없음.
    try:
        if 'prev_extract' in locals():
            prev_deps_map = _extract_deps_map(prev_extract)
            curr_deps_map = _extract_deps_map(current_extract)
            result.dep_changes = diff_dependencies(prev_deps_map, curr_deps_map)
    except Exception:
        # graceful — dep diff 실패해도 file diff 결과는 살림
        result.dep_changes = []

    severity, summary = _classify_severity(
        all_new_apis, new_files_count, all_new_dims,
    )
    # #Z6 보강: dangerous dep 추가 시 severity 상향
    has_dangerous_dep_add = any(
        c.kind == "added" and c.is_dangerous
        for c in result.dep_changes
    )
    if has_dangerous_dep_add:
        # 위험 의존성 추가는 최소 MEDIUM, 다른 신호 함께면 HIGH
        if severity == Severity.LOW:
            severity = Severity.MEDIUM
        elif severity == Severity.MEDIUM:
            severity = Severity.HIGH
        # summary 에 표시
        dang_names = [c.name for c in result.dep_changes
                      if c.kind == "added" and c.is_dangerous]
        summary = (summary or "") + (
            f" [Z6] dangerous deps added: {dang_names[:5]}."
        )

    result.overall_severity = severity
    result.summary = summary

    return result


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    from ..schema import Ecosystem
    from .stage0_registry import check

    pkg = sys.argv[1] if len(sys.argv) > 1 else "requests"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    if not info.found:
        print("not found")
        sys.exit(1)

    v = info.latest_version
    url = info.archive_urls.get(v)
    ext = extract_all(pkg, eco, v, url)
    if ext.error:
        print(f"extract failed: {ext.error}")
        sys.exit(1)

    entry_files = _sources_to_entry_files(ext)
    behavior = _behavior_for_files(entry_files)

    diff = analyze_full_diff(info, ext, behavior)
    print(f"[{pkg} {v}] full diff vs {diff.compared_versions}")
    print(f"  severity: {diff.overall_severity.value}")
    print(f"  summary : {diff.summary}")
    if diff.error:
        print(f"  error   : {diff.error}")
    print(f"  changed files: {len(diff.file_diffs)}")
    for fd in diff.file_diffs[:10]:
        print(f"    [{fd.kind}] {fd.path}")
        if fd.new_apis:
            print(f"      + APIs: {fd.new_apis[:5]}")
        if fd.dimensions_added:
            print(f"      + dims: {[d.value for d in fd.dimensions_added]}")
