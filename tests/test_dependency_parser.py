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
