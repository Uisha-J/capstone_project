"""RuntimeIntelStore — 격리 DB 단위 테스트."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.db.runtime_intel import (
    LearnedIOC,
    LearnedRule,
    RuntimeIntelStore,
    RuntimeObservation,
    _bump_confidence,
)


def _setup():
    td = tempfile.mkdtemp(prefix="runtime_intel_")
    os.environ["AISLOP_DB_KEY"] = "runtime-intel-test"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )
    return td


def _teardown(td):
    import shutil; shutil.rmtree(td, ignore_errors=True)


# ─────────────── observation ───────────────

def test_record_and_get_observation():
    print("== record + get observation ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        obs = RuntimeObservation(
            received_at="2026-05-13T10:00:00Z", source="falco",
            host="host-1", package="evil-pkg", ecosystem="npm",
            version="0.0.1",
            raw_event={"rule": "Outbound to evil", "output": "..."},
            extracted_iocs=[{"type": "ip", "value": "1.2.3.4"}],
            mitigation="killed",
        )
        oid = s.record_observation(obs)
        assert oid > 0
        got = s.get_observation(oid)
        assert got is not None
        assert got.source == "falco"
        assert got.package == "evil-pkg"
        assert got.mitigation == "killed"
        print(f"  OK id={oid}")
    finally:
        _teardown(td)


def test_update_verdict_after():
    print("\n== update_verdict_after ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        obs = RuntimeObservation(
            received_at="2026-05-13T10:00:00Z", source="falco",
            raw_event={}, verdict_before="CLEAN",
        )
        oid = s.record_observation(obs)
        s.update_verdict_after(oid, "MALICIOUS")
        got = s.get_observation(oid)
        assert got.verdict_after == "MALICIOUS"
        print("  OK")
    finally:
        _teardown(td)


def test_list_observations_by_package():
    print("\n== list_observations(package=...) ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        for v in ("0.0.1", "0.0.2"):
            s.record_observation(RuntimeObservation(
                received_at=f"2026-05-13T10:{v[-1]}0:00Z",
                source="falco", package="evil", ecosystem="npm",
                version=v, raw_event={},
            ))
        s.record_observation(RuntimeObservation(
            received_at="2026-05-13T10:00:00Z", source="falco",
            package="other", ecosystem="npm", version="1.0", raw_event={},
        ))
        evil = s.list_observations(package="evil")
        assert len(evil) == 2
        all_obs = s.list_observations()
        assert len(all_obs) == 3
        print(f"  OK evil={len(evil)} all={len(all_obs)}")
    finally:
        _teardown(td)


# ─────────────── IOC ───────────────

def test_upsert_ioc_creates_new():
    print("\n== upsert_ioc: 신규 → 0.5 confidence ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        ioc = LearnedIOC(ioc_type="ip", value="185.143.223.5")
        iid = s.upsert_ioc(ioc, observation_id=1, package_at_version="evil@0.1")
        assert iid > 0
        got = s.get_ioc(iid)
        assert got.confidence >= 0.5
        assert got.observation_count == 1
        assert "evil@0.1" in got.associated_packages
        print(f"  OK conf={got.confidence}")
    finally:
        _teardown(td)


def test_upsert_ioc_dedups_and_bumps():
    print("\n== upsert_ioc: 동일 IOC 재관측 → count/conf ↑ ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        v = "185.143.223.5"

        # 3 회 다른 observation 으로 재관측
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value=v),
                     observation_id=1, package_at_version="a@1")
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value=v),
                     observation_id=2, package_at_version="a@1")
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value=v),
                     observation_id=3, package_at_version="b@1")

        iocs = s.list_iocs(ioc_type="ip")
        assert len(iocs) == 1
        ioc = iocs[0]
        # 동일 obs_id 는 중복 카운트 안 함 → 1, 2, 3 → count 3
        assert ioc.observation_count == 3
        assert len(ioc.associated_packages) == 2  # a@1, b@1
        # 다중 패키지 등장 → bump 0.9+
        assert ioc.confidence >= 0.9, ioc.confidence
        print(f"  OK count={ioc.observation_count} conf={ioc.confidence} "
              f"pkgs={ioc.associated_packages}")
    finally:
        _teardown(td)


def test_auto_promote_by_multi_package():
    print("\n== auto_promote: 2개 이상 패키지 → approved ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        iid = s.upsert_ioc(
            LearnedIOC(ioc_type="domain", value="evil.example.net"),
            observation_id=1, package_at_version="p1@1",
        )
        # 단일 패키지 — promote 안 함
        assert s.auto_promote(iid) is False
        assert s.get_ioc(iid).status == "pending"

        # 두 번째 패키지 추가
        s.upsert_ioc(
            LearnedIOC(ioc_type="domain", value="evil.example.net"),
            observation_id=2, package_at_version="p2@1",
        )
        assert s.auto_promote(iid) is True
        assert s.get_ioc(iid).status == "approved"
        print("  OK approved")
    finally:
        _teardown(td)


def test_list_iocs_filters():
    print("\n== list_iocs: status / type filter ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="1.1.1.1",
                                confidence=0.6))
        s.upsert_ioc(LearnedIOC(ioc_type="domain", value="x.com",
                                confidence=0.4))
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="2.2.2.2",
                                confidence=0.8))

        ips = s.list_iocs(ioc_type="ip")
        assert len(ips) == 2
        # confidence 내림차순
        assert ips[0].confidence >= ips[1].confidence

        # min_confidence
        high = s.list_iocs(min_confidence=0.7)
        assert all(i.confidence >= 0.7 for i in high)
        print(f"  OK ips={len(ips)} high={len(high)}")
    finally:
        _teardown(td)


# ─────────────── rules ───────────────

def test_record_and_approve_rule():
    print("\n== record_rule_draft + approve_rule ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        rule = LearnedRule(
            rule_kind="indicator_47",
            rule_body='{"code":"EXF-RT-001","regex":"...","severity":"HIGH"}',
            source_observation_ids=[1, 2],
            confidence=0.7,
            rationale="auto-generated from 2 observations",
        )
        rid = s.record_rule_draft(rule)
        assert rid > 0

        # 첫 approve 성공, 두 번째 (이미 approved) 실패
        assert s.approve_rule(rid, "alice") is True
        assert s.approve_rule(rid, "alice") is False

        drafts = s.list_rules(status="draft")
        approved = s.list_rules(status="approved")
        assert len(drafts) == 0
        assert len(approved) == 1
        assert approved[0].approved_by == "alice"
        print("  OK")
    finally:
        _teardown(td)


# ─────────────── 통계 ───────────────

def test_stats():
    print("\n== stats ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.record_observation(RuntimeObservation(
            received_at="t", source="falco", raw_event={}, package="p",
        ))
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="1.1.1.1"),
                     package_at_version="p@1")
        s.record_rule_draft(LearnedRule(
            rule_kind="falco", rule_body="...", created_at="t",
        ))
        st = s.stats()
        assert st["observations"] == 1
        assert st["iocs_total"] == 1
        assert st["rule_drafts_pending_review"] == 1
        print(f"  OK stats={st}")
    finally:
        _teardown(td)


# ─────────────── confidence ───────────────

def test_bump_confidence_monotonic():
    print("\n== _bump_confidence: monotonic ==")
    assert _bump_confidence(0.5, 1, 1) == 0.5
    assert _bump_confidence(0.5, 3, 1) == 0.75
    assert _bump_confidence(0.5, 5, 1) == 0.85
    assert _bump_confidence(0.5, 1, 2) == 0.9
    assert _bump_confidence(0.5, 1, 3) == 0.95
    # 0.95 가 _bump_confidence 의 ceiling (3+ 패키지 등장 시) — 의도된 상한
    assert _bump_confidence(0.5, 100, 100) == 0.95
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
