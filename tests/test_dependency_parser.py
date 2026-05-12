"""Stage 6 dependency parser 단위 테스트.

특히 setup.py 의 AST 기반 indirect form (`requires = [...]; setup(install_requires=requires)`)
처리를 검증 — boto3 류 패턴.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import Ecosystem  # noqa: E402
from pkgsentinel.stages.stage1b_full_source import FullSourceFile  # noqa: E402
from pkgsentinel.stages.stage_dependency import (  # noqa: E402
    _parse_setup_py_deps,
    extract_python_deps,
)


def _sf(path: str, content: str) -> FullSourceFile:
    return FullSourceFile(
        path=path, basename=path.split("/")[-1],
        content=content, size=len(content),
        language="python", tier=1,
    )


def test_setup_py_direct_list():
    print("== setup.py: direct list ==")
    src = '''
from setuptools import setup
setup(
    name="x",
    install_requires=["foo>=1.0", "bar"],
)
'''
    deps = _parse_setup_py_deps(src)
    assert deps == ["foo>=1.0", "bar"], deps
    print(f"  OK {deps}")


def test_setup_py_indirect_via_variable():
    """boto3-style: requires=[...] 별도 변수 → setup(install_requires=requires)."""
    print("\n== setup.py: indirect via variable (boto3 style) ==")
    src = '''
from setuptools import setup

requires = [
    "botocore>=1.43.6,<1.44.0",
    "jmespath>=0.7.1,<2.0.0",
    "s3transfer>=0.17.0,<0.18.0",
]

setup(
    name="boto3",
    install_requires=requires,
)
'''
    deps = _parse_setup_py_deps(src)
    assert "botocore>=1.43.6,<1.44.0" in deps, deps
    assert "s3transfer>=0.17.0,<0.18.0" in deps, deps
    assert len(deps) == 3, deps
    print(f"  OK {deps}")


def test_setup_py_concat_list():
    print("\n== setup.py: list concat (a + b) ==")
    src = '''
from setuptools import setup
base = ["pkg-a>=1"]
extra = ["pkg-b"]
setup(name="x", install_requires=base + extra)
'''
    deps = _parse_setup_py_deps(src)
    assert deps == ["pkg-a>=1", "pkg-b"], deps
    print(f"  OK {deps}")


def test_setup_py_no_install_requires():
    print("\n== setup.py: no install_requires ==")
    src = "from setuptools import setup\nsetup(name='x')"
    assert _parse_setup_py_deps(src) == []
    print("  OK empty")


def test_setup_py_invalid_syntax():
    print("\n== setup.py: SyntaxError → empty ==")
    src = "def setup(\n  install_requires=[unclosed"
    assert _parse_setup_py_deps(src) == []
    print("  OK fallback empty")


def test_pep_735_dependency_groups():
    """PEP 735 [dependency-groups] 블록 추출 — dev_deps 에 적재."""
    print("\n== PEP 735 [dependency-groups] ==")
    src = '''
[project]
name = "x"
version = "0.1"
dependencies = ["requests"]

[dependency-groups]
dev = ["pytest>=7", "ruff"]
docs = ["sphinx>=5"]
'''
    sources = [_sf("x-0.1/pyproject.toml", src)]
    de = extract_python_deps(sources)
    direct_names = [d.name for d in de.direct_deps]
    dev_names = [d.name for d in de.dev_deps]
    assert "requests" in direct_names
    # PEP 735 group 의 deps → dev_deps
    for n in ("pytest", "ruff", "sphinx"):
        assert n in dev_names, f"missing {n} in dev={dev_names}"
    # source_file 에 group 이름 노출
    for d in de.dev_deps:
        if d.name == "pytest":
            assert "group:dev" in d.source_file
        if d.name == "sphinx":
            assert "group:docs" in d.source_file
    print(f"  OK direct={direct_names} dev={dev_names}")


def test_pep_735_with_optional_dependencies_both():
    """PEP 621 optional-dependencies 와 PEP 735 dependency-groups 동시 존재."""
    print("\n== PEP 621 opt + PEP 735 group 공존 ==")
    src = '''
[project]
name = "x"
version = "0.1"
dependencies = []
optional-dependencies.test = ["pytest"]

[dependency-groups]
lint = ["ruff"]
'''
    sources = [_sf("x-0.1/pyproject.toml", src)]
    de = extract_python_deps(sources)
    dev_names = [d.name for d in de.dev_deps]
    assert "pytest" in dev_names
    assert "ruff" in dev_names
    print(f"  OK dev={dev_names}")


def test_pep_735_include_group_basic():
    """include-group 으로 다른 group 참조 → expand."""
    print("\n== PEP 735 include-group: dev includes test ==")
    src = '''
[project]
name = "x"
version = "0.1"
dependencies = []

[dependency-groups]
test = ["pytest>=7", "hypothesis"]
dev = ["ruff", {include-group = "test"}, "mypy"]
'''
    sources = [_sf("x-0.1/pyproject.toml", src)]
    de = extract_python_deps(sources)
    dev_names = sorted({d.name for d in de.dev_deps
                        if "group:dev" in d.source_file})
    # dev 는 test 포함 → pytest, hypothesis, ruff, mypy
    for n in ("pytest", "hypothesis", "ruff", "mypy"):
        assert n in dev_names, f"missing {n} in {dev_names}"
    print(f"  OK dev expansion: {dev_names}")


def test_pep_735_include_group_chain():
    """test → dev → all 체인 expansion."""
    print("\n== PEP 735 chain: all includes dev which includes test ==")
    src = '''
[project]
name = "x"
version = "0.1"

[dependency-groups]
test = ["pytest"]
dev = [{include-group = "test"}, "ruff"]
all = [{include-group = "dev"}, "tox"]
'''
    sources = [_sf("x-0.1/pyproject.toml", src)]
    de = extract_python_deps(sources)
    all_group_names = sorted({d.name for d in de.dev_deps
                              if "group:all" in d.source_file})
    for n in ("pytest", "ruff", "tox"):
        assert n in all_group_names, f"missing {n} in {all_group_names}"
    print(f"  OK chain expansion: {all_group_names}")


def test_pep_735_cycle_safe():
    """a → b → a 사이클 → 무한 재귀 안 함."""
    print("\n== PEP 735 cycle: a→b→a ==")
    src = '''
[project]
name = "x"
version = "0.1"

[dependency-groups]
a = ["pkg-a", {include-group = "b"}]
b = ["pkg-b", {include-group = "a"}]
'''
    sources = [_sf("x-0.1/pyproject.toml", src)]
    # 무한 재귀 발생 시 RecursionError 또는 hang — 그냥 정상 종료해야
    de = extract_python_deps(sources)
    a_names = {d.name for d in de.dev_deps if "group:a" in d.source_file}
    # 사이클 발생 후 a 는 pkg-a + (b 가 a 참조해서 self-ref → skip) = pkg-a + pkg-b
    # 정확한 결과는 구현 따라 다름 — 핵심은 crash 안 함 + pkg-a 는 포함
    assert "pkg-a" in a_names
    print(f"  OK no crash, a={a_names}")


def test_pep_735_self_reference():
    """{include-group = "<self>"} → 자기 참조 무시."""
    print("\n== PEP 735 self-reference ignored ==")
    src = '''
[project]
name = "x"
version = "0.1"

[dependency-groups]
me = ["pkg-x", {include-group = "me"}, "pkg-y"]
'''
    sources = [_sf("x-0.1/pyproject.toml", src)]
    de = extract_python_deps(sources)
    me_names = sorted({d.name for d in de.dev_deps
                       if "group:me" in d.source_file})
    assert me_names == ["pkg-x", "pkg-y"]
    print(f"  OK {me_names}")


def test_pep_735_missing_reference():
    """존재하지 않는 group 참조 → empty expansion 으로 graceful."""
    print("\n== PEP 735 missing reference ==")
    src = '''
[project]
name = "x"
version = "0.1"

[dependency-groups]
dev = ["ruff", {include-group = "nonexistent"}]
'''
    sources = [_sf("x-0.1/pyproject.toml", src)]
    de = extract_python_deps(sources)
    dev_names = {d.name for d in de.dev_deps}
    assert "ruff" in dev_names
    # nonexistent 는 expand 못 함 → skip
    print(f"  OK dev={dev_names}")


def test_e2e_boto3_pattern():
    """extract_python_deps 의 end-to-end — setup.py 만 있는 boto3-like 패키지."""
    print("\n== E2E: boto3-like setup.py 만 ==")
    src = '''
from setuptools import setup
requires = ["botocore>=1.43.6", "jmespath>=0.7"]
setup(name="boto3", install_requires=requires)
'''
    sources = [_sf("boto3-1.0/setup.py", src)]
    de = extract_python_deps(sources)
    names = [d.name for d in de.direct_deps]
    assert "botocore" in names, names
    assert "jmespath" in names, names
    print(f"  OK direct deps: {names}")


def main():
    tests = [
        test_setup_py_direct_list,
        test_setup_py_indirect_via_variable,
        test_setup_py_concat_list,
        test_setup_py_no_install_requires,
        test_setup_py_invalid_syntax,
        test_pep_735_dependency_groups,
        test_pep_735_with_optional_dependencies_both,
        test_pep_735_include_group_basic,
        test_pep_735_include_group_chain,
        test_pep_735_cycle_safe,
        test_pep_735_self_reference,
        test_pep_735_missing_reference,
        test_e2e_boto3_pattern,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception:
            import traceback
            traceback.print_exc()
            failed += 1
    print("\n" + ("ALL OK" if failed == 0 else f"FAILED: {failed}"))


if __name__ == "__main__":
    main()
