"""
Stage-level 분석 캐시 테스트.

검증 항목:
- 새 schema (stage_cache 테이블) 가 자동 생성되는가
- get/put/invalidate 가 의도대로 동작하는가
- archive_sha256 불일치 시 캐시 미스
- 동일 stage 의 stage_version 이 의존 모듈 기반으로 결정적 (deterministic)
- 새 advisory 추가 시 트리거가 stage_0a/0b 만 무효화하는가
- 기존 analyses 테이블과 공존
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# 모듈 import 시점에 DB key 확보 — pytest fixture 없이도 동작.
# (다른 tests/test_*.py 와 같은 패턴: 모듈 레벨 sys.path / env 셋업)
if not os.environ.get("AISLOP_DB_KEY"):
    os.environ["AISLOP_DB_KEY"] = "test-stage-cache-passphrase"

from pkgsentinel.db.stage_cache import (
    StageCache,
    StageCacheKey,
    all_supported_stages,
    stage_version_for,
)


def _key(pkg: str, stage: str) -> StageCacheKey:
    return StageCacheKey(pkg, "PyPI", "0.0.1", stage)


def test_supported_stages_nonempty():
    stages = all_supported_stages()
    assert len(stages) >= 5
    assert "stage_4c_ind47" in stages
    assert "stage_2_behavior" in stages


def test_stage_version_deterministic():
    v1 = stage_version_for("stage_4c_ind47")
    v2 = stage_version_for("stage_4c_ind47")
    assert v1 == v2
    assert len(v1) == 16


def test_stage_version_differs_per_stage():
    v_ind = stage_version_for("stage_4c_ind47")
    v_seq = stage_version_for("stage_4e_sequence")
    assert v_ind != v_seq, "different stages must have different version hashes"


def test_threat_filter_version_includes_feed():
    v_no_feed = stage_version_for("stage_0a_threat_filter")
    v_with_feed = stage_version_for("stage_0a_threat_filter", feed_version="abc123")
    v_with_feed2 = stage_version_for("stage_0a_threat_filter", feed_version="xyz789")
    assert v_no_feed != v_with_feed
    assert v_with_feed != v_with_feed2


def test_get_miss_then_put_hit():
    sc = StageCache()
    sc.invalidate(package="t_get_miss_put_hit")
    k = _key("t_get_miss_put_hit", "stage_4c_ind47")

    h = sc.get(k)
    assert not h.hit
    assert "miss" in h.reason

    info = sc.put(k, {"hits": ["EXM-001", "EXF-001"]})
    assert info["stored"]

    h = sc.get(k)
    assert h.hit
    assert h.payload == {"hits": ["EXM-001", "EXF-001"]}
    assert h.cached_at is not None


def test_archive_sha_mismatch_misses():
    sc = StageCache()
    sc.invalidate(package="t_archive_mismatch")
    k = _key("t_archive_mismatch", "stage_2_behavior")
    sc.put(k, {"calls": 3}, archive_sha256="aaa")

    assert sc.get(k, archive_sha256="aaa").hit
    h = sc.get(k, archive_sha256="bbb")
    assert not h.hit
    assert "archive" in h.reason


def test_invalidate_by_stage():
    sc = StageCache()
    sc.invalidate(package="t_inv_stage")
    k1 = _key("t_inv_stage", "stage_2_behavior")
    k2 = _key("t_inv_stage", "stage_4c_ind47")
    sc.put(k1, {"a": 1})
    sc.put(k2, {"a": 2})

    # delete only one stage
    deleted = sc.invalidate(package="t_inv_stage", stage="stage_2_behavior")
    assert deleted == 1

    assert not sc.get(k1).hit
    assert sc.get(k2).hit


def test_invalidate_all_stages_of_package():
    sc = StageCache()
    sc.invalidate(package="t_inv_all")
    for s in ("stage_2_behavior", "stage_4c_ind47", "stage_4e_sequence"):
        sc.put(_key("t_inv_all", s), {"x": 1})

    deleted = sc.invalidate(package="t_inv_all")
    assert deleted == 3


def test_payload_must_be_serializable():
    sc = StageCache()
    sc.invalidate(package="t_payload")
    k = _key("t_payload", "stage_4d_taint")
    # set: not JSON-serializable by default
    info = sc.put(k, {"x": {1, 2, 3}})
    # default=str fallback ensures store succeeds; payload becomes string repr
    assert info["stored"]


def test_cache_survives_multiple_writes():
    sc = StageCache()
    sc.invalidate(package="t_overwrite")
    k = _key("t_overwrite", "stage_2_behavior")
    sc.put(k, {"v": 1})
    sc.put(k, {"v": 2})
    h = sc.get(k)
    assert h.payload == {"v": 2}, "ON CONFLICT DO UPDATE should keep latest"


def test_advisory_trigger_drops_threat_stages_only():
    """known_malicious 에 새 advisory 들어가면 stage_cache 의 threat_filter /
    attack_history 만 무효. 다른 stage 는 유지."""
    sc = StageCache()
    pkg = "t_advisory_trigger"
    sc.invalidate(package=pkg)

    # 4 stage 결과 적재
    for s in (
        "stage_0a_threat_filter",
        "stage_0b_attack_history",
        "stage_2_behavior",
        "stage_4c_ind47",
    ):
        sc.put(_key(pkg, s), {"x": 1})

    # 새 advisory 삽입 → 트리거 발화
    with sc.db.cursor() as cur:
        cur.execute("""
            INSERT INTO known_malicious
                (advisory_id, ecosystem, package, attack_type, source, summary)
            VALUES
                ('GHSA-test-stage-cache', 'PyPI', ?, 'malicious_package',
                 'unit-test', 'unit-test advisory')
        """, (pkg,))

    # threat_filter / attack_history 만 사라져야 함
    assert not sc.get(_key(pkg, "stage_0a_threat_filter")).hit
    assert not sc.get(_key(pkg, "stage_0b_attack_history")).hit
    # 나머지는 그대로
    assert sc.get(_key(pkg, "stage_2_behavior")).hit
    assert sc.get(_key(pkg, "stage_4c_ind47")).hit

    # 정리
    with sc.db.cursor() as cur:
        cur.execute(
            "DELETE FROM known_malicious WHERE advisory_id = 'GHSA-test-stage-cache'"
        )
    sc.invalidate(package=pkg)
