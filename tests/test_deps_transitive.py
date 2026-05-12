"""Stage 6 transitive (max_depth >= 2) 단위 테스트.

실 registry 호출 없이 _fetch_dep_dependencies + check_attack_history 를
monkeypatch 로 격리 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages import stage_dependency as sd
from pkgsentinel.stages.stage_dependency import (
    Dependency,
    DependencyExtraction,
    analyze_dependencies,
)


def _mk_extraction(direct, dev=None):
    ex = DependencyExtraction()
    ex.direct_deps = [
        Dependency(name=n, version_spec=s, source_file="<test>")
        for n, s in direct
    ]
    ex.dev_deps = [
        Dependency(name=n, version_spec=s, source_file="<test>")
        for n, s in (dev or [])
    ]
    return ex


def _mock_attack_history_factory(malicious_names: set, version_aware: dict = None):
    """이름이 malicious_names 에 있으면 MALICIOUS 반환하는 mock."""
    from pkgsentinel.knowledge.attack_index import AttackMatch
    from pkgsentinel.knowledge.osv import AttackPattern
    from pkgsentinel.stages.stage0b_attack_history import AttackHistoryResult

    def mock_check(name, ecosystem, version=None):
        r = AttackHistoryResult()
        if name.lower() in malicious_names:
            pat = AttackPattern(
                advisory_id="MAL-test-001", aliases=[], source="test",
                ecosystem=ecosystem.value,
                affected_packages=[name],
                affected_versions=list((version_aware or {}).get(name.lower(), [])),
                summary=f"test malicious {name}", details="",
                attack_type="malicious_package", published="2025-01-01",
                modified="2025-01-01",
            )
            r.exact_matches = [AttackMatch(
                kind="exact", pattern=pat, similarity=1.0, reason="mock match",
            )]
        return r
    return mock_check


def test_depth_1_default_behavior(monkeypatch):
    """max_depth=1 (기본) 은 직접 deps 만."""
    print("== depth=1: 직접 deps 만 ==")
    monkeypatch.setattr(
        sd, "_resolve_dep_version",
        lambda name, spec, eco, fetch_registry=True: "1.0.0",
    )
    monkeypatch.setattr(
        "pkgsentinel.stages.stage0b_attack_history.check_attack_history",
        _mock_attack_history_factory(set()),
    )
    monkeypatch.setattr(
        sd, "_fetch_dep_dependencies",
        lambda name, version, eco: [("child-of-" + name, "1.0.0")],
    )
    ex = _mk_extraction([("A", "1.0.0"), ("B", "1.0.0")])
    res = analyze_dependencies(ex, Ecosystem.NPM, max_depth=1)
    names = sorted(r.name for r in res)
    assert names == ["A", "B"], names
    assert all(r.depth == 1 for r in res)
    print(f"  OK names={names}")


def test_depth_2_walks_children(monkeypatch):
    """max_depth=2 면 각 직접 dep 의 자식까지 분석."""
    print("\n== depth=2: dep 의 dep 까지 ==")
    monkeypatch.setattr(
        sd, "_resolve_dep_version",
        lambda name, spec, eco, fetch_registry=True: "1.0.0",
    )
    monkeypatch.setattr(
        "pkgsentinel.stages.stage0b_attack_history.check_attack_history",
        _mock_attack_history_factory(set()),
    )
    # A → A-child, B → B-child
    monkeypatch.setattr(
        sd, "_fetch_dep_dependencies",
        lambda name, version, eco: (
            [("A-child", "1.0.0")] if name == "A"
            else [("B-child", "1.0.0")] if name == "B"
            else []
        ),
    )
    ex = _mk_extraction([("A", "1.0.0"), ("B", "1.0.0")])
    res = analyze_dependencies(ex, Ecosystem.NPM, max_depth=2, max_packages=100)
    by_name = {r.name: r for r in res}
    assert "A" in by_name and "B" in by_name
    assert "A-child" in by_name and "B-child" in by_name
    assert by_name["A-child"].depth == 2
    assert by_name["A-child"].path == ["A"]
    print(f"  OK depths: {sorted((r.name, r.depth) for r in res)}")


def test_cycle_detection(monkeypatch):
    """A → B → A 사이클은 visited 가 끊음."""
    print("\n== cycle detection ==")
    monkeypatch.setattr(
        sd, "_resolve_dep_version",
        lambda name, spec, eco, fetch_registry=True: "1.0.0",
    )
    monkeypatch.setattr(
        "pkgsentinel.stages.stage0b_attack_history.check_attack_history",
        _mock_attack_history_factory(set()),
    )
    monkeypatch.setattr(
        sd, "_fetch_dep_dependencies",
        lambda name, version, eco: (
            [("B", "1.0.0")] if name == "A"
            else [("A", "1.0.0")] if name == "B"
            else []
        ),
    )
    ex = _mk_extraction([("A", "1.0.0")])
    res = analyze_dependencies(ex, Ecosystem.NPM, max_depth=5, max_packages=100)
    names = [r.name for r in res]
    # 각각 정확히 1번씩만
    assert names.count("A") == 1
    assert names.count("B") == 1
    print(f"  OK no duplicates: {names}")


def test_max_packages_cap(monkeypatch):
    """max_packages 가 BFS 전체 dep 수를 cap."""
    print("\n== max_packages cap ==")
    monkeypatch.setattr(
        sd, "_resolve_dep_version",
        lambda name, spec, eco, fetch_registry=True: "1.0.0",
    )
    monkeypatch.setattr(
        "pkgsentinel.stages.stage0b_attack_history.check_attack_history",
        _mock_attack_history_factory(set()),
    )
    # 각 dep 가 자식 5개씩 — 깊이 3 까지 가면 1+5+25+125 = 156 개
    monkeypatch.setattr(
        sd, "_fetch_dep_dependencies",
        lambda name, version, eco: [
            (f"{name}-c{i}", "1.0.0") for i in range(5)
        ],
    )
    ex = _mk_extraction([("root", "1.0.0")])
    res = analyze_dependencies(
        ex, Ecosystem.NPM, max_depth=10, max_packages=15,
    )
    assert len(res) == 15, len(res)
    print(f"  OK len={len(res)} (cap=15)")


def test_transitive_mal_propagates(monkeypatch):
    """깊이 2 의 dep 이 MALICIOUS 면 정확히 그 path 가 잡혀야."""
    print("\n== transitive MALICIOUS at depth 2 ==")
    monkeypatch.setattr(
        sd, "_resolve_dep_version",
        lambda name, spec, eco, fetch_registry=True: "1.0.0",
    )
    monkeypatch.setattr(
        "pkgsentinel.stages.stage0b_attack_history.check_attack_history",
        _mock_attack_history_factory({"evil-child"}),
    )
    monkeypatch.setattr(
        sd, "_fetch_dep_dependencies",
        lambda name, version, eco: (
            [("evil-child", "1.0.0")] if name == "A" else []
        ),
    )
    ex = _mk_extraction([("A", "1.0.0")])
    res = analyze_dependencies(ex, Ecosystem.NPM, max_depth=2)
    evil = next(r for r in res if r.name == "evil-child")
    assert evil.verdict == "MALICIOUS"
    assert evil.depth == 2
    assert evil.path == ["A"]
    print(f"  OK evil-child verdict={evil.verdict} path={evil.path}")


def test_no_registry_resolve_blocks_recursion(monkeypatch):
    """resolved_version=None 이면 자식 확장 안 함."""
    print("\n== resolved_version=None → recursion stop ==")
    monkeypatch.setattr(
        sd, "_resolve_dep_version",
        lambda name, spec, eco, fetch_registry=True: None,
    )
    monkeypatch.setattr(
        "pkgsentinel.stages.stage0b_attack_history.check_attack_history",
        _mock_attack_history_factory(set()),
    )
    monkeypatch.setattr(
        sd, "_fetch_dep_dependencies",
        lambda name, version, eco: [("should-not-appear", "1.0.0")],
    )
    ex = _mk_extraction([("A", "1.0.0")])
    res = analyze_dependencies(ex, Ecosystem.NPM, max_depth=5)
    names = [r.name for r in res]
    assert names == ["A"]
    assert "should-not-appear" not in names
    print(f"  OK only direct: {names}")


def main():
    print("(monkeypatch 테스트는 pytest 로 실행)")


if __name__ == "__main__":
    main()
