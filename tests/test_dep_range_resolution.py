"""_resolve_dep_version 단위 테스트.

실 registry 호출 없이 _fetch_latest_version 만 monkeypatch.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages import stage_dependency as sd


def test_pinned_npm():
    print("== pinned: '5.1.1' ==")
    v = sd._resolve_dep_version(
        "eslint-scope", "5.1.1", Ecosystem.NPM, fetch_registry=False,
    )
    assert v == "5.1.1"
    print(f"  OK {v}")


def test_pinned_pypi_eq():
    print("\n== pinned: '==2.4.0' ==")
    v = sd._resolve_dep_version(
        "x", "==2.4.0", Ecosystem.PYPI, fetch_registry=False,
    )
    assert v == "2.4.0"
    print(f"  OK {v}")


def test_range_no_fetch():
    """fetch_registry=False 면 range 는 None."""
    print("\n== range, fetch off: '^5.1.1' → None ==")
    v = sd._resolve_dep_version(
        "chalk", "^5.1.1", Ecosystem.NPM, fetch_registry=False,
    )
    assert v is None
    print("  OK")


def test_range_with_mocked_fetch(monkeypatch):
    """range + fetch_registry=True + mocked latest → 그 latest 반환."""
    print("\n== range, fetch on (mocked) ==")
    # 캐시 클리어
    sd._REGISTRY_LATEST_CACHE.clear()
    monkeypatch.setattr(
        sd, "_fetch_latest_version",
        lambda name, ecosystem: "5.6.3" if name == "chalk" else None,
    )
    v = sd._resolve_dep_version(
        "chalk", "^5.1.1", Ecosystem.NPM, fetch_registry=True,
    )
    assert v == "5.6.3"
    print(f"  OK {v}")


def test_range_fetch_fail(monkeypatch):
    """range + fetch 실패 → None (보수적 fallback)."""
    print("\n== range, fetch fail → None ==")
    sd._REGISTRY_LATEST_CACHE.clear()
    monkeypatch.setattr(
        sd, "_fetch_latest_version", lambda name, ecosystem: None,
    )
    v = sd._resolve_dep_version(
        "unknown-xyz", "^1.0", Ecosystem.NPM, fetch_registry=True,
    )
    assert v is None
    print("  OK")


def test_fetch_cached(monkeypatch):
    """동일 (name, ecosystem) 두 번째 호출은 캐시 — fetch 1회만."""
    print("\n== _fetch_latest_version 캐시 ==")
    sd._REGISTRY_LATEST_CACHE.clear()
    call_count = [0]

    def _mock_urlopen(*args, **kwargs):
        call_count[0] += 1
        raise OSError("not really called")

    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen)
    # 첫 호출 → 시도해서 실패 → None 캐시
    v1 = sd._fetch_latest_version("chalk", Ecosystem.NPM)
    # 두 번째 → 캐시에서 즉시 None 반환, urlopen 호출 없음
    v2 = sd._fetch_latest_version("chalk", Ecosystem.NPM)
    assert v1 is None and v2 is None
    assert call_count[0] == 1, f"expected 1 fetch, got {call_count[0]}"
    print(f"  OK fetch called {call_count[0]}x (cached after)")


def main():
    # monkeypatch 인자 받는 테스트는 pytest 통해서만. 여기는 일부만.
    test_pinned_npm()
    test_pinned_pypi_eq()
    test_range_no_fetch()
    print("\n(monkeypatch 테스트는 pytest 로 실행)")


if __name__ == "__main__":
    main()
