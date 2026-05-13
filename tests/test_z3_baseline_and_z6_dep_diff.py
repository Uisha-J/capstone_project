"""#Z3 PackageBaselineStore + #Z6 dependency manifest diff 단위 테스트."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.knowledge.package_baseline import (
    AnomalyVerdict,
    BehaviorProfile,
    PackageBaselineStore,
    build_profile_from_observations,
    check_anomaly,
)
from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages.stage_sandbox import ObservedBehavior
from pkgsentinel.stages.stage3b_full_diff import (
    DANGEROUS_NEW_DEPS,
    DependencyChange,
    HIGH_RISK_NEW_DEPS,
    diff_dependencies,
)


def _setup():
    td = tempfile.mkdtemp(prefix="z3_z6_")
    os.environ["AISLOP_DB_KEY"] = "z3-z6-test"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )
    return td


def _teardown(td):
    import shutil; shutil.rmtree(td, ignore_errors=True)


# ─────────────── #Z3 — BehaviorProfile + Store ───────────────

def test_build_profile_from_observations():
    print("== build_profile_from_observations ==")
    obs1 = ObservedBehavior(
        mode="ossf",
        network_requests=["connect 1.1.1.1:443"],
        process_spawns=[],
        file_writes=[],
    )
    obs2 = ObservedBehavior(
        mode="ossf",
        network_requests=["connect 1.1.1.1:443", "connect 2.2.2.2:443"],
        process_spawns=["/usr/bin/git pull"],
        file_writes=[],
    )
    p = build_profile_from_observations([obs1, obs2])
    assert p.network_count_max == 2
    assert p.exec_count_max == 1
    assert "1.1.1.1" in p.typical_domains
    assert "/usr/bin/git" in p.typical_exec_argv0s
    assert not p.has_sensitive_file_read
    print(f"  OK net_max={p.network_count_max}")


def test_build_profile_detects_sensitive():
    print("\n== profile detects sensitive cred read ==")
    obs = ObservedBehavior(
        file_writes=["/home/runner/.aws/credentials"],
    )
    p = build_profile_from_observations([obs])
    assert p.has_sensitive_file_read is True
    assert any(".aws" in s for s in p.sensitive_paths_seen)
    print("  OK")


def test_baseline_store_roundtrip():
    print("\n== PackageBaselineStore set + get ==")
    td = _setup()
    try:
        store = PackageBaselineStore()
        profile = BehaviorProfile(
            network_count_max=3,
            typical_domains=["api.github.com"],
            has_sensitive_file_read=False,
        )
        store.set("react", "npm", profile,
                  baseline_versions=["18.0.0", "18.1.0", "18.2.0"],
                  sample_count=3)
        got = store.get("react", "npm")
        assert got is not None
        assert got.network_count_max == 3
        assert "api.github.com" in got.typical_domains
        assert store.count() == 1
        print("  OK")
    finally:
        _teardown(td)


def test_baseline_store_get_missing():
    print("\n== get 없는 패키지 → None ==")
    td = _setup()
    try:
        store = PackageBaselineStore()
        assert store.get("nonexistent", "npm") is None
        print("  OK")
    finally:
        _teardown(td)


def test_check_anomaly_cred_first_time_high():
    print("\n== check_anomaly: cred 신규 등장 → high ==")
    baseline = BehaviorProfile(
        has_sensitive_file_read=False,
        typical_domains=["api.github.com"],
        network_count_max=1,
    )
    current = ObservedBehavior(
        file_writes=["/root/.ssh/id_rsa"],
    )
    v = check_anomaly(current, baseline)
    assert v.is_anomalous
    assert v.severity == "high"
    assert any("cred" in r.lower() for r in v.reasons)
    print(f"  OK reasons={v.reasons}")


def test_check_anomaly_network_burst_medium():
    print("\n== check_anomaly: network 폭증 → medium ==")
    baseline = BehaviorProfile(network_count_max=1,
                                typical_domains=["api.github.com"])
    current = ObservedBehavior(
        network_requests=[f"connect 10.0.0.{i}:443" for i in range(10)],
    )
    v = check_anomaly(current, baseline)
    assert v.is_anomalous
    assert v.severity in ("medium", "high")
    print(f"  OK reasons={v.reasons}")


def test_check_anomaly_new_domain_medium():
    print("\n== check_anomaly: 새 domain → medium ==")
    baseline = BehaviorProfile(
        network_count_max=2,
        typical_domains=["api.github.com", "cdn.example.com"],
    )
    current = ObservedBehavior(
        network_requests=["connect attacker.example.com:443"],
    )
    v = check_anomaly(current, baseline)
    assert v.is_anomalous
    assert v.severity in ("medium", "high")
    print("  OK")


def test_check_anomaly_no_deviation_info():
    print("\n== check_anomaly: 일치 → info ==")
    baseline = BehaviorProfile(
        network_count_max=5,
        typical_domains=["api.github.com"],
        has_sensitive_file_read=False,
    )
    current = ObservedBehavior(
        network_requests=["connect api.github.com:443"],
    )
    v = check_anomaly(current, baseline)
    assert not v.is_anomalous
    print("  OK")


# ─────────────── #Z6 — diff_dependencies ───────────────

def test_diff_deps_added():
    print("\n== diff_dependencies: added ==")
    changes = diff_dependencies(
        {"react": "^18.0.0"},
        {"react": "^18.0.0", "axios": "^1.0.0"},
    )
    added = [c for c in changes if c.kind == "added"]
    assert len(added) == 1
    assert added[0].name == "axios"
    print("  OK")


def test_diff_deps_removed():
    print("\n== diff_dependencies: removed ==")
    changes = diff_dependencies(
        {"react": "^18.0.0", "lodash": "^4.0.0"},
        {"react": "^18.0.0"},
    )
    removed = [c for c in changes if c.kind == "removed"]
    assert removed and removed[0].name == "lodash"
    print("  OK")


def test_diff_deps_version_changed():
    print("\n== diff_dependencies: version_changed ==")
    changes = diff_dependencies(
        {"react": "^18.0.0"},
        {"react": "^19.0.0"},
    )
    vc = [c for c in changes if c.kind == "version_changed"]
    assert vc and vc[0].old_spec == "^18.0.0" and vc[0].new_spec == "^19.0.0"
    print("  OK")


def test_diff_deps_dangerous_dep_added():
    """child_process 같은 위험 의존성 신규 추가 → is_dangerous=True."""
    print("\n== dangerous dep 추가 detect ==")
    changes = diff_dependencies(
        {"react": "^18.0.0"},
        {"react": "^18.0.0", "child_process": "*"},
    )
    cp = [c for c in changes if c.name == "child_process"][0]
    assert cp.kind == "added"
    assert cp.is_dangerous is True
    print(f"  OK reason={cp.reason}")


def test_diff_deps_high_risk_dep():
    print("\n== high-risk dep (paramiko) 추가 ==")
    changes = diff_dependencies({}, {"paramiko": "*"})
    p = changes[0]
    assert p.is_dangerous is True
    # high-risk 는 'high-risk' 단어 reason 에 포함
    assert "high-risk" in p.reason.lower()
    print("  OK")


def test_diff_deps_safe_addition():
    """일반 (위험 아닌) 의존성 추가 — flag X."""
    print("\n== 안전한 dep 추가 ==")
    changes = diff_dependencies(
        {"react": "^18.0.0"},
        {"react": "^18.0.0", "lodash": "^4.0.0"},
    )
    lo = [c for c in changes if c.name == "lodash"][0]
    assert lo.is_dangerous is False
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
