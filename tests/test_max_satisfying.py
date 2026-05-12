"""semver / PEP 440 max-satisfying 단위 테스트.

레지스트리 호출 없이 _semver_satisfies / _max_satisfying 의 매칭 로직만 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages.stage_dependency import (
    _max_satisfying,
    _npm_max_satisfying,
    _pypi_max_satisfying,
    _semver_satisfies,
)


# ─────────────── semver 매칭 ───────────────

def test_semver_caret_majorgt0():
    print("== ^1.2.3 ==")
    assert _semver_satisfies("1.2.3", "^1.2.3") is True
    assert _semver_satisfies("1.9.9", "^1.2.3") is True
    assert _semver_satisfies("2.0.0", "^1.2.3") is False
    assert _semver_satisfies("1.2.2", "^1.2.3") is False
    print("  OK")


def test_semver_caret_major0():
    print("\n== ^0.2.3 (X==0,Y>0) ==")
    assert _semver_satisfies("0.2.3", "^0.2.3") is True
    assert _semver_satisfies("0.2.9", "^0.2.3") is True
    assert _semver_satisfies("0.3.0", "^0.2.3") is False
    assert _semver_satisfies("1.0.0", "^0.2.3") is False
    print("  OK")


def test_semver_tilde():
    print("\n== ~1.2.3 ==")
    assert _semver_satisfies("1.2.3", "~1.2.3") is True
    assert _semver_satisfies("1.2.9", "~1.2.3") is True
    assert _semver_satisfies("1.3.0", "~1.2.3") is False
    print("  OK")


def test_semver_comparators():
    print("\n== >= < <= > ==")
    assert _semver_satisfies("1.0.0", ">=1.0.0") is True
    assert _semver_satisfies("0.9.0", ">=1.0.0") is False
    assert _semver_satisfies("1.5.0", "<2.0.0") is True
    assert _semver_satisfies("2.0.0", "<2.0.0") is False
    assert _semver_satisfies("2.0.0", "<=2.0.0") is True
    print("  OK")


def test_semver_wildcards():
    print("\n== '*' / 1.x ==")
    assert _semver_satisfies("9.9.9", "*") is True
    assert _semver_satisfies("1.5.0", "1.x") is True
    assert _semver_satisfies("2.0.0", "1.x") is False
    print("  OK")


def test_semver_or():
    print("\n== A || B ==")
    assert _semver_satisfies("1.5.0", "^1.0.0 || ^2.0.0") is True
    assert _semver_satisfies("2.5.0", "^1.0.0 || ^2.0.0") is True
    assert _semver_satisfies("3.0.0", "^1.0.0 || ^2.0.0") is False
    print("  OK")


def test_npm_max_satisfying_basic():
    print("\n== npm max-satisfying ==")
    versions = ["1.0.0", "1.2.0", "1.5.3", "2.0.0", "2.1.0"]
    assert _npm_max_satisfying("^1.0.0", versions) == "1.5.3"
    assert _npm_max_satisfying("^2.0.0", versions) == "2.1.0"
    assert _npm_max_satisfying(">=3.0.0", versions) is None
    print("  OK")


# ─────────────── PEP 440 매칭 ───────────────

def test_pypi_max_satisfying_range():
    print("\n== PyPI >=1,<2 ==")
    versions = ["0.9.0", "1.0.0", "1.5.0", "1.9.9", "2.0.0", "2.5.0"]
    out = _pypi_max_satisfying(">=1,<2", versions)
    assert out == "1.9.9", out
    print(f"  OK {out}")


def test_pypi_max_satisfying_eq():
    print("\n== PyPI ==1.5.0 ==")
    versions = ["1.0.0", "1.5.0", "2.0.0"]
    assert _pypi_max_satisfying("==1.5.0", versions) == "1.5.0"
    print("  OK")


def test_pypi_max_satisfying_no_match():
    print("\n== PyPI no match ==")
    versions = ["1.0.0", "2.0.0"]
    assert _pypi_max_satisfying(">=3,<4", versions) is None
    print("  OK")


# ─────────────── 통합 ───────────────

def test_max_satisfying_dispatch():
    print("\n== _max_satisfying dispatch ==")
    npm_v = ["1.0.0", "1.5.0", "2.0.0"]
    pypi_v = ["1.0.0", "1.5.0", "2.0.0"]
    assert _max_satisfying("^1.0.0", npm_v, Ecosystem.NPM) == "1.5.0"
    assert _max_satisfying(">=1,<2", pypi_v, Ecosystem.PYPI) == "1.5.0"
    print("  OK")


def main():
    tests = [
        test_semver_caret_majorgt0,
        test_semver_caret_major0,
        test_semver_tilde,
        test_semver_comparators,
        test_semver_wildcards,
        test_semver_or,
        test_npm_max_satisfying_basic,
        test_pypi_max_satisfying_range,
        test_pypi_max_satisfying_eq,
        test_pypi_max_satisfying_no_match,
        test_max_satisfying_dispatch,
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
