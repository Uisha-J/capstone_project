"""
의존성 트리 재귀 분석.

event-stream 사건 유형 대응:
  event-stream  (합법)
    └─ flatmap-stream  (악성 주입 대상)

주 패키지가 깨끗해도 의존성이 악성이면 공급망 공격이 성립.

구현:
  - PyPI: setup.py / pyproject.toml / requirements.txt 의 install_requires 파싱
  - npm: package.json > dependencies / devDependencies / peerDependencies
  - 각 의존성에 대해 동일 파이프라인을 재귀 호출 (깊이 제한)
  - 이미 분석한 (pkg, version) 은 캐시로 스킵

주의:
  - 재귀 깊이 기본 2 (직접 의존 + 1 홉)
  - 패키지 수 폭발 방지용 상한 (기본 50)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..schema import Ecosystem
from .stage1b_full_source import FullSourceFile

# ─────────────── 결과 구조 ───────────────

@dataclass
class Dependency:
    name: str
    version_spec: str           # "^1.0.0", ">=2.0", "*"
    source_file: str            # 어디서 선언됐는지

    def __repr__(self):
        return f"{self.name} ({self.version_spec})"


@dataclass
class DependencyExtraction:
    direct_deps: list[Dependency] = field(default_factory=list)
    dev_deps: list[Dependency] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─────────────── Python ───────────────

_PEP_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*([<>=!~][^,;\n]*)?",
)


def _parse_setup_py_deps(content: str) -> list[str]:
    """setup.py 의 install_requires 를 AST 로 파싱.

    지원 형태:
      1. setup(install_requires=["a>=1.0", "b"])                    — 직접
      2. requires = [...]; setup(install_requires=requires)         — 간접 (boto3)
      3. setup(install_requires=[...]+something)                    — BinOp 의 좌측 list

    반환: 의존성 spec 문자열 리스트 (정규화는 _parse_python_requires 가 처리).
    """
    import ast as _ast
    try:
        tree = _ast.parse(content)
    except SyntaxError:
        return []

    # 1차 패스: 모듈 레벨 Assign 으로 정의된 list[str] 수집
    bindings: dict[str, list[str]] = {}
    for node in tree.body:
        if not isinstance(node, _ast.Assign):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], _ast.Name):
            continue
        target = node.targets[0].id
        items = _ast_extract_str_list(node.value)
        if items is not None:
            bindings[target] = items

    # 2차 패스: setup(install_requires=...) 인자에서 값 추출
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        # func 이름이 'setup' 인 경우만
        func_name = (
            node.func.id if isinstance(node.func, _ast.Name)
            else getattr(node.func, "attr", "") if isinstance(node.func, _ast.Attribute)
            else ""
        )
        if func_name != "setup":
            continue
        for kw in node.keywords:
            if kw.arg != "install_requires":
                continue
            items = _ast_extract_str_list(kw.value, bindings=bindings)
            if items is not None:
                return items
    return []


def _ast_extract_str_list(node, bindings: dict | None = None) -> list[str] | None:
    """AST 노드가 list[str] 이거나 list-concat (a+b) 이면 평탄화해 반환.

    Name 노드는 bindings 에 등록된 list[str] 이면 그 값으로 풀어 사용.
    list 가 아니거나 비-문자열 요소가 섞여 있으면 None.
    """
    import ast as _ast
    bindings = bindings or {}
    if isinstance(node, (_ast.List, _ast.Tuple)):
        out: list[str] = []
        for elt in node.elts:
            if isinstance(elt, _ast.Constant) and isinstance(elt.value, str):
                out.append(elt.value)
            else:
                # 비-문자열 요소 — 보수적으로 무시 (typing/PEP 508 spec 외)
                return None
        return out
    if isinstance(node, _ast.Name):
        # 변수 참조 (boto3 류: install_requires=requires)
        return bindings.get(node.id)
    if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Add):
        # left + right 둘 다 list[str] 인 경우만 평탄화
        left = _ast_extract_str_list(node.left, bindings=bindings)
        right = _ast_extract_str_list(node.right, bindings=bindings)
        if left is not None and right is not None:
            return left + right
        return None
    return None


def _parse_python_requires(content: str) -> list[tuple[str, str]]:
    """install_requires 리스트에서 (name, version_spec) 추출."""
    result: list[tuple[str, str]] = []
    for line in content.splitlines():
        line = line.strip().rstrip(",")
        line = line.strip("'\"")
        if not line or line.startswith("#"):
            continue
        # 환경 마커 분리 (";" 이후는 제거)
        if ";" in line:
            line = line.split(";")[0].strip()
        m = _PEP_REQ_RE.match(line)
        if m:
            name = m.group(1)
            spec = (m.group(2) or "").strip()
            result.append((name, spec))
    return result


def extract_python_deps(source_files: list[FullSourceFile]) -> DependencyExtraction:
    result = DependencyExtraction()

    # 1) pyproject.toml
    for sf in source_files:
        if sf.basename != "pyproject.toml":
            continue
        try:
            # Python 3.11+ tomllib, 아래는 간단 파싱
            import tomllib
            data = tomllib.loads(sf.content)
        except ModuleNotFoundError:
            # tomllib 미지원 버전은 생략 (간단히)
            continue
        except Exception as e:
            result.errors.append(f"{sf.path}: toml parse failed: {e}")
            continue

        project = data.get("project", {}) or {}
        deps = project.get("dependencies", []) or []
        for dep in deps:
            if isinstance(dep, str):
                for name, spec in _parse_python_requires(dep):
                    result.direct_deps.append(Dependency(name=name, version_spec=spec, source_file=sf.path))

        # optional-dependencies → dev
        opt = project.get("optional-dependencies", {}) or {}
        for group_deps in opt.values():
            for dep in (group_deps or []):
                if isinstance(dep, str):
                    for name, spec in _parse_python_requires(dep):
                        result.dev_deps.append(Dependency(name=name, version_spec=spec, source_file=sf.path))

    # 2) setup.py — AST 기반 (정규식이 놓치는 indirect 형태 처리).
    #   직접 형태:  setup(..., install_requires=["a>=1.0", "b"], ...)
    #   간접 형태:  requires = [...]; setup(..., install_requires=requires)  ← boto3 류
    for sf in source_files:
        if sf.basename != "setup.py":
            continue
        deps_from_setup = _parse_setup_py_deps(sf.content)
        for item in deps_from_setup:
            for name, spec in _parse_python_requires(item):
                result.direct_deps.append(Dependency(
                    name=name, version_spec=spec, source_file=sf.path,
                ))
        if not deps_from_setup:
            # AST 실패 시 정규식 fallback (구식 setup.py / 비정상 문법)
            m = re.search(
                r"install_requires\s*=\s*\[(.*?)\]", sf.content, re.DOTALL,
            )
            if m:
                body = m.group(1)
                for item in re.findall(r"""['"]([^'"]+)['"]""", body):
                    for name, spec in _parse_python_requires(item):
                        result.direct_deps.append(Dependency(
                            name=name, version_spec=spec, source_file=sf.path,
                        ))

    # 3) requirements.txt
    for sf in source_files:
        if sf.basename.lower() in ("requirements.txt", "requirements-prod.txt"):
            for name, spec in _parse_python_requires(sf.content):
                result.direct_deps.append(Dependency(name=name, version_spec=spec, source_file=sf.path))

    return result


# ─────────────── npm ───────────────

def extract_npm_deps(source_files: list[FullSourceFile]) -> DependencyExtraction:
    result = DependencyExtraction()

    for sf in source_files:
        if sf.basename != "package.json":
            continue
        try:
            data = json.loads(sf.content)
        except Exception as e:
            result.errors.append(f"{sf.path}: json parse failed: {e}")
            continue

        for key, target in (
            ("dependencies", result.direct_deps),
            ("peerDependencies", result.direct_deps),
            ("optionalDependencies", result.direct_deps),
            ("devDependencies", result.dev_deps),
        ):
            block = data.get(key, {}) or {}
            for name, spec in block.items():
                target.append(Dependency(
                    name=name,
                    version_spec=str(spec),
                    source_file=sf.path,
                ))
    return result


# ─────────────── 통합 ───────────────

def extract_dependencies(
    source_files: list[FullSourceFile],
    ecosystem: Ecosystem,
) -> DependencyExtraction:
    if ecosystem == Ecosystem.PYPI:
        return extract_python_deps(source_files)
    if ecosystem == Ecosystem.NPM:
        return extract_npm_deps(source_files)
    return DependencyExtraction()


# ─────────────── 재귀 분석 ───────────────

_PINNED_VERSION_RE = re.compile(r"^\s*(?:==|=)?\s*([0-9][^,;\s]*)\s*$")


def _extract_pinned_version(spec: str | None) -> str | None:
    """version_spec 이 단일 핀 ("1.2.3" 또는 "==1.2.3") 이면 그 버전 반환, 아니면 None.

    range spec (">=1,<2" 등) 은 None — known_malicious 매칭은 그 경우 보수적으로
    이름 매칭만 수행하고 historical 로 분류.
    """
    if not spec:
        return None
    m = _PINNED_VERSION_RE.match(spec)
    if not m:
        return None
    v = m.group(1)
    # 영문 이름 (e.g., 'latest', 'next') 은 제외
    if not v[0].isdigit():
        return None
    return v


# ─────────────── range spec resolution ───────────────

# 캐시: latest 만 ({name, eco} → str|None), all_versions ({name, eco} → list[str]|None)
_REGISTRY_LATEST_CACHE: dict[tuple[str, str], str | None] = {}
_REGISTRY_VERSIONS_CACHE: dict[tuple[str, str], list[str] | None] = {}


def _fetch_registry_versions(
    name: str, ecosystem,
) -> tuple[str | None, list[str]]:
    """레지스트리에서 (latest, all_versions) 한번에 조회.

    npm:   GET /<name>  → dist-tags.latest + list(versions.keys())
    PyPI:  GET /pypi/<name>/json  → info.version + list(releases.keys())
    """
    from ..schema import Ecosystem
    key = (name.lower(), ecosystem.value)

    if key in _REGISTRY_VERSIONS_CACHE:
        return _REGISTRY_LATEST_CACHE.get(key), _REGISTRY_VERSIONS_CACHE[key] or []

    import json as _json
    import urllib.error
    import urllib.request

    if ecosystem == Ecosystem.NPM:
        url = f"https://registry.npmjs.org/{name}"
    elif ecosystem == Ecosystem.PYPI:
        url = f"https://pypi.org/pypi/{name}/json"
    else:
        _REGISTRY_LATEST_CACHE[key] = None
        _REGISTRY_VERSIONS_CACHE[key] = []
        return None, []

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "pkgsentinel-deps/1.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
    except Exception:
        _REGISTRY_LATEST_CACHE[key] = None
        _REGISTRY_VERSIONS_CACHE[key] = []
        return None, []

    if ecosystem == Ecosystem.NPM:
        latest = (data.get("dist-tags") or {}).get("latest")
        versions = list((data.get("versions") or {}).keys())
    else:  # PyPI
        latest = (data.get("info") or {}).get("version")
        versions = list((data.get("releases") or {}).keys())

    _REGISTRY_LATEST_CACHE[key] = latest
    _REGISTRY_VERSIONS_CACHE[key] = versions
    return latest, versions


def _fetch_latest_version(name: str, ecosystem) -> str | None:
    """레지스트리에서 최신 버전 한 개만. 캐시 일관성용 _fetch_registry_versions 호출."""
    latest, _ = _fetch_registry_versions(name, ecosystem)
    return latest


# ── PEP 440 (PyPI) 매칭 ──

def _pypi_max_satisfying(spec: str, versions: list[str]) -> str | None:
    """PyPI 사양 spec 을 만족하는 가장 큰 버전 반환. 불가능 시 None."""
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return None
    spec = spec.strip()
    if not spec:
        return None
    # `2.4.0` (no operator) — 1) 단일 fixed 로 처리. spec 에 operator 없으면 == 추가
    if spec[0] not in "<>=!~":
        spec = "==" + spec
    try:
        sset = SpecifierSet(spec, prereleases=False)
    except Exception:
        return None
    candidates: list[Version] = []
    for v_str in versions:
        try:
            v = Version(v_str)
        except InvalidVersion:
            continue
        if v in sset:
            candidates.append(v)
    if not candidates:
        return None
    return str(max(candidates))


# ── npm semver 매칭 (소규모 in-house 파서) ──

_SEMVER_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$",
)


def _parse_semver(v: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.match(v.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _semver_satisfies(version: str, spec: str) -> bool | None:
    """단순 npm spec 충족 검사. 지원:
      "*", "x", ""        — 모두 통과
      "1.2.3"             — equal
      "^1.2.3"            — >=1.2.3 <2.0.0 (X>0) / >=0.1.2 <0.2.0 (X==0,Y>0)
      "~1.2.3"            — >=1.2.3 <1.3.0
      ">=1.2.3" "<2.0.0"  "<=", ">"
      "1.2.x" / "1.x"     — 마지막 x 는 any
      "A || B"            — 합집합
    실패 시 None.
    """
    v = _parse_semver(version)
    if v is None:
        return None
    spec = (spec or "").strip()
    if spec in ("", "*", "x", "X", "latest"):
        return True
    if "||" in spec:
        for part in spec.split("||"):
            r = _semver_satisfies(version, part.strip())
            if r is True:
                return True
        return False
    # ^X.Y.Z
    if spec.startswith("^"):
        b = _parse_semver(spec[1:])
        if not b:
            return None
        if b[0] > 0:
            return v >= b and v[0] == b[0]
        if b[1] > 0:
            return v >= b and v[0] == 0 and v[1] == b[1]
        return v >= b and v[0] == 0 and v[1] == 0
    # ~X.Y.Z
    if spec.startswith("~"):
        b = _parse_semver(spec[1:])
        if not b:
            return None
        return v >= b and v[0] == b[0] and v[1] == b[1]
    # >= > <= <
    for op in (">=", "<=", ">", "<", "="):
        if spec.startswith(op):
            b = _parse_semver(spec[len(op):])
            if not b:
                return None
            return {
                ">=": v >= b, ">": v > b, "<=": v <= b, "<": v < b, "=": v == b,
            }[op]
    # X.Y.x / X.x
    if ".x" in spec.lower():
        parts = spec.lower().split(".")
        # 마지막 x 의 위치 비교
        try:
            if len(parts) >= 2 and parts[-1] == "x" and parts[-2].isdigit():
                if len(parts) == 3 and parts[0].isdigit():
                    return v[0] == int(parts[0]) and v[1] == int(parts[1])
                if len(parts) == 2 and parts[0].isdigit():
                    return v[0] == int(parts[0])
        except ValueError:
            return None
    # 단일 fixed
    b = _parse_semver(spec)
    if b is not None:
        return v == b
    return None


def _npm_max_satisfying(spec: str, versions: list[str]) -> str | None:
    """semver spec 만족 최대 버전. 충족 불가 시 None."""
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for v_str in versions:
        ok = _semver_satisfies(v_str, spec)
        if ok is True:
            parsed = _parse_semver(v_str)
            if parsed:
                # prerelease (suffix) 가 있는 경우는 후순위 — 단순화
                candidates.append((parsed, v_str))
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    return candidates[-1][1]


def _max_satisfying(spec: str | None, versions: list[str], ecosystem) -> str | None:
    """range spec 의 max-satisfying 을 골라 반환. 실패 시 None."""
    from ..schema import Ecosystem
    if not spec or not versions:
        return None
    if ecosystem == Ecosystem.PYPI:
        return _pypi_max_satisfying(spec, versions)
    if ecosystem == Ecosystem.NPM:
        return _npm_max_satisfying(spec, versions)
    return None


def _resolve_dep_version(
    name: str,
    spec: str | None,
    ecosystem,
    *,
    fetch_registry: bool = True,
) -> str | None:
    """version_spec 을 concrete 버전으로 해석.

    1) pinned spec ("1.2.3" / "==1.2.3") → 그대로
    2) fetch_registry=True 면 registry 의 *전체 versions 중 spec 만족 최대* 선택
       - 만족하는 게 없으면 latest 로 fallback (잘못된 매칭보다는 보수적 정확)
       - registry 호출 실패 → None (caller 가 name-only)
    3) 둘 다 실패 → None

    이전 단순화 (registry latest 무조건) 가 spec 범위 위반을 무시하던 버그 해소.
    """
    pinned = _extract_pinned_version(spec)
    if pinned:
        return pinned
    if not fetch_registry:
        return None

    latest, versions = _fetch_registry_versions(name, ecosystem)
    if not versions:
        return latest  # 버전 목록 조회 실패 시 latest 만이라도

    # 1차: spec 만족 최대
    if spec:
        sat = _max_satisfying(spec, versions, ecosystem)
        if sat:
            return sat
    # 2차: spec 만족 없으면 latest (보수적; latest 가 spec 안의 안전 버전일 수도)
    return latest


@dataclass
class DependencyAnalysisResult:
    """한 의존성의 간단한 분석 요약. 전체 AnalysisReport 를 다 재생성하지는 않음 (성능)."""
    name: str
    version_spec: str
    resolved_version: str | None
    verdict: str                # "MALICIOUS", "HIGH_RISK", "SUSPICIOUS", "CLEAN", "CANNOT_ANALYZE", "SKIPPED"
    reason: str
    evidence_count: int = 0


def analyze_dependencies(
    extraction: DependencyExtraction,
    ecosystem: Ecosystem,
    max_depth: int = 1,
    max_packages: int = 30,
    attack_history_only: bool = True,
    resolve_ranges: bool = True,
) -> list[DependencyAnalysisResult]:
    """
    의존성 재귀 분석.

    attack_history_only=True (기본):
        의존성에 대해서는 지식 DB 공격 이력만 빠르게 조회 (성능).
    attack_history_only=False:
        각 의존성을 완전한 파이프라인으로 분석 (느림, 깊이 1 권장).

    resolve_ranges=True (기본):
        version_spec 이 range (`^5.1.1` 등) 면 registry latest 로 해석해
        version-aware 매칭에 활용. 비활성화 시 pinned 만 추출.
    """
    from .stage0b_attack_history import check_attack_history

    results: list[DependencyAnalysisResult] = []
    all_deps = extraction.direct_deps + extraction.dev_deps

    for dep in all_deps[:max_packages]:
        try:
            if attack_history_only:
                # dep.version_spec 이 pinned 면 직접, range 면 registry latest 로 해석.
                # 둘 다 실패 시 None → name-only 매칭 (보수적).
                resolved_version = _resolve_dep_version(
                    dep.name, dep.version_spec, ecosystem,
                    fetch_registry=resolve_ranges,
                )
                hist = check_attack_history(
                    dep.name, ecosystem, version=resolved_version,
                )
                if hist.error:
                    results.append(DependencyAnalysisResult(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        resolved_version=None,
                        verdict="SKIPPED",
                        reason=f"attack index unavailable: {hist.error}",
                    ))
                    continue

                if hist.exact_matches:
                    pat = hist.exact_matches[0].pattern
                    results.append(DependencyAnalysisResult(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        resolved_version=resolved_version,
                        verdict="MALICIOUS",
                        reason=(
                            f"dependency name is on the malicious list "
                            f"({pat.advisory_id}): {pat.summary[:100]}"
                        ),
                        evidence_count=1,
                    ))
                elif hist.historical_name_matches:
                    # 이름은 advisory 에 있지만 *조회 버전이 affected_versions
                    # 에 없음* — chalk@5.6.2 가 chalk@5.6.1 advisory 에 매칭되는
                    # 류. INFO 로 분류 (CLEAN 과 SUSPICIOUS 사이).
                    top = hist.historical_name_matches[0]
                    results.append(DependencyAnalysisResult(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        resolved_version=resolved_version,
                        verdict="INFO",
                        reason=top.reason,
                        evidence_count=len(hist.historical_name_matches),
                    ))
                elif hist.typosquat_candidates:
                    top = hist.typosquat_candidates[0]
                    results.append(DependencyAnalysisResult(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        resolved_version=resolved_version,
                        verdict="SUSPICIOUS",
                        reason=top.reason,
                        evidence_count=len(hist.typosquat_candidates),
                    ))
                else:
                    results.append(DependencyAnalysisResult(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        resolved_version=resolved_version,
                        verdict="CLEAN",
                        reason="no attack history match",
                    ))
            else:
                # 완전한 파이프라인 재귀 (Phase 후반에 옵션으로)
                from ..pipeline import run_pipeline
                sub_report = run_pipeline(dep.name, ecosystem, llm_mode="stub")
                results.append(DependencyAnalysisResult(
                    name=dep.name,
                    version_spec=dep.version_spec,
                    resolved_version=sub_report.version,
                    verdict=sub_report.verdict.value,
                    reason=f"{len(sub_report.evidence)} evidence item(s)",
                    evidence_count=len(sub_report.evidence),
                ))
        except Exception as e:
            results.append(DependencyAnalysisResult(
                name=dep.name,
                version_spec=dep.version_spec,
                resolved_version=None,
                verdict="SKIPPED",
                reason=f"error: {e}",
            ))

    return results


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    from .stage0_registry import check
    from .stage1b_full_source import extract_all

    pkg = sys.argv[1] if len(sys.argv) > 1 else "requests"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    if not info.found:
        print("not found")
        sys.exit(1)

    url = info.archive_urls.get(info.latest_version)
    ext = extract_all(pkg, eco, info.latest_version, url)
    if ext.error:
        print(f"extract error: {ext.error}")
        sys.exit(1)

    deps = extract_dependencies(ext.source_files, eco)
    print(f"[{pkg}] direct deps: {len(deps.direct_deps)}, dev deps: {len(deps.dev_deps)}")
    for d in deps.direct_deps[:20]:
        print(f"  {d}")

    print("\n=== 의존성 공격 이력 조회 (attack_history_only=True) ===")
    results = analyze_dependencies(deps, eco)
    for r in results:
        marker = "[!]" if r.verdict in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS") else "[ ]"
        print(f"  {marker} {r.name} ({r.version_spec}) -> {r.verdict}")
        if r.verdict != "CLEAN":
            print(f"      reason: {r.reason}")
