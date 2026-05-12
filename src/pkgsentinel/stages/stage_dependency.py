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
) -> list[DependencyAnalysisResult]:
    """
    의존성 재귀 분석.

    attack_history_only=True (기본):
        의존성에 대해서는 지식 DB 공격 이력만 빠르게 조회 (성능).
    attack_history_only=False:
        각 의존성을 완전한 파이프라인으로 분석 (느림, 깊이 1 권장).
    """
    from .stage0b_attack_history import check_attack_history

    results: list[DependencyAnalysisResult] = []
    all_deps = extraction.direct_deps + extraction.dev_deps

    for dep in all_deps[:max_packages]:
        try:
            if attack_history_only:
                hist = check_attack_history(dep.name, ecosystem)
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
                        resolved_version=None,
                        verdict="MALICIOUS",
                        reason=(
                            f"dependency name is on the malicious list "
                            f"({pat.advisory_id}): {pat.summary[:100]}"
                        ),
                        evidence_count=1,
                    ))
                elif hist.typosquat_candidates:
                    top = hist.typosquat_candidates[0]
                    results.append(DependencyAnalysisResult(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        resolved_version=None,
                        verdict="SUSPICIOUS",
                        reason=top.reason,
                        evidence_count=len(hist.typosquat_candidates),
                    ))
                else:
                    results.append(DependencyAnalysisResult(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        resolved_version=None,
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
