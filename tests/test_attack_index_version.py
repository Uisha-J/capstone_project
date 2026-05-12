"""attack_index.AttackPatternIndex.lookup_exact 의 version-aware 매칭 단위 테스트.

OSV cache 파일 의존 없이 메모리 AttackPattern 으로 직접 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.knowledge.attack_index import AttackPatternIndex
from pkgsentinel.knowledge.osv import AttackPattern


def _mk(name, ecosystem, versions, advisory_id="MAL-test-001"):
    return AttackPattern(
        advisory_id=advisory_id,
        aliases=[],
        source="OSV",
        ecosystem=ecosystem,
        affected_packages=[name],
        affected_versions=list(versions),
        summary=f"test advisory for {name}",
        details="details",
        attack_type="malicious_package",
        published="2025-01-01",
        modified="2025-01-01",
    )


def test_exact_with_matching_version():
    print("== version-aware: 매칭 버전 → kind=exact ==")
    idx = AttackPatternIndex([_mk("chalk", "npm", ["5.6.1"])])
    hits = idx.lookup_exact("chalk", "npm", version="5.6.1")
    assert len(hits) == 1
    assert hits[0].kind == "exact"
    assert hits[0].is_active
    print(f"  OK kind={hits[0].kind}")


def test_exact_with_non_matching_version():
    """침해된 버전이 아닌 다른 버전 → historical_name_match."""
    print("\n== version-aware: 다른 버전 → kind=historical_name_match ==")
    idx = AttackPatternIndex([_mk("chalk", "npm", ["5.6.1"])])
    hits = idx.lookup_exact("chalk", "npm", version="5.6.2")
    assert len(hits) == 1
    assert hits[0].kind == "historical_name_match"
    assert not hits[0].is_active
    print(f"  OK kind={hits[0].kind}")
    print(f"  reason: {hits[0].reason[:100]}")


def test_no_version_arg_falls_back_to_name_match():
    print("\n== version 미지정 → 기존 동작 (모두 exact) ==")
    idx = AttackPatternIndex([_mk("chalk", "npm", ["5.6.1"])])
    hits = idx.lookup_exact("chalk", "npm")
    assert hits[0].kind == "exact"
    print("  OK")


def test_empty_affected_versions_treated_as_unbounded():
    """OSV 가 affected_versions 누락 시 모든 버전이 침해된 것으로 본다 (보수적)."""
    print("\n== affected_versions 비어 있으면 모든 버전 → exact ==")
    idx = AttackPatternIndex([_mk("evil-pkg", "npm", [])])
    hits = idx.lookup_exact("evil-pkg", "npm", version="1.0.0")
    assert hits[0].kind == "exact"
    print("  OK (unbounded = 보수적으로 모든 버전)")


def test_multi_advisory_one_matches_other_does_not():
    print("\n== 복수 advisory: 일부만 활성 ==")
    idx = AttackPatternIndex([
        _mk("chalk", "npm", ["5.6.1"], advisory_id="ADV-A"),
        _mk("chalk", "npm", ["5.6.3"], advisory_id="ADV-B"),
    ])
    hits = idx.lookup_exact("chalk", "npm", version="5.6.1")
    by_kind = {h.kind for h in hits}
    assert "exact" in by_kind
    assert "historical_name_match" in by_kind
    print(f"  OK kinds={sorted(by_kind)}")


def test_unknown_package():
    print("\n== 알려지지 않은 이름 → 빈 결과 ==")
    idx = AttackPatternIndex([_mk("chalk", "npm", ["5.6.1"])])
    hits = idx.lookup_exact("nonexistent-xyz", "npm", version="1.0.0")
    assert hits == []
    print("  OK")


def main():
    tests = [
        test_exact_with_matching_version,
        test_exact_with_non_matching_version,
        test_no_version_arg_falls_back_to_name_match,
        test_empty_affected_versions_treated_as_unbounded,
        test_multi_advisory_one_matches_other_does_not,
        test_unknown_package,
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
