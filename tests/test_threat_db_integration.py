"""
Threat DB + 캐시 + 무결성 + threat_filter 통합 테스트.

전제: AISLOP_DB_KEY 환경변수 또는 master_key 파일이 있어야 함.
이 테스트는 실 OSV 다운로드는 하지 않고, 직접 INSERT 한 데이터로 검증.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# 격리 DB 경로
TEST_DB_DIR = tempfile.mkdtemp(prefix="aislopsq_test_")
TEST_DB_PATH = Path(TEST_DB_DIR) / "test.sqlcipher"
TEST_PASSPHRASE = "test-passphrase-do-not-reuse"

os.environ["AISLOP_DB_KEY"] = TEST_PASSPHRASE

from pkgsentinel.db.threat_db import ThreatDB, reset_default_db
from pkgsentinel.db.integrity import (
    IntegrityChecker, IntegrityMode, RowHMAC, _merkle_root,
)
from pkgsentinel.db.analysis_cache import AnalysisCache, CacheKey
from pkgsentinel.stages.stage0_threat_filter import run as filter_run, ThreatFilterReport
from pkgsentinel.schema import Ecosystem


def _fresh_db() -> ThreatDB:
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    return ThreatDB(TEST_DB_PATH, passphrase=TEST_PASSPHRASE)


# ─────────────── 1. 암호화 검증 ───────────────

def test_db_is_encrypted():
    print("== Test: DB file is actually encrypted ==")
    _ = _fresh_db()
    head = TEST_DB_PATH.read_bytes()[:16]
    assert not head.startswith(b"SQLite format"), "DB header looks like plaintext SQLite"
    print(f"  OK header={head.hex()}, NOT plaintext SQLite")
    return True


def test_wrong_key_rejected():
    print("\n== Test: wrong passphrase is rejected ==")
    db1 = _fresh_db()
    db1.close()
    # 새 ThreatDB 인스턴스 with wrong key
    try:
        ThreatDB(TEST_DB_PATH, passphrase="wrong-key-zzz")
        print("  FAIL: opened with wrong key")
        return False
    except RuntimeError as e:
        print(f"  OK rejected: {str(e)[:80]}")
        return True


# ─────────────── 2. 무결성 검증 ───────────────

def test_merkle_tamper_detection():
    print("\n== Test: Merkle root detects file tamper ==")
    import hashlib
    files = {f"file{i}.txt": f"content {i}".encode() for i in range(8)}
    leaves = [hashlib.sha256(c).hexdigest() for c in files.values()]
    root = _merkle_root(leaves)

    # 한 파일 변조
    leaves2 = leaves.copy()
    leaves2[3] = hashlib.sha256(b"tampered content").hexdigest()
    root2 = _merkle_root(leaves2)

    assert root != root2
    print(f"  OK root1={root[:16]}.., root2={root2[:16]}.. (changed)")
    return True


def test_row_hmac_tamper_detection():
    print("\n== Test: row HMAC detects row tamper ==")
    rh = RowHMAC.from_passphrase(TEST_PASSPHRASE)
    row = {"package": "x", "ecosystem": "PyPI", "version": "1.0",
           "verdict": "CLEAN", "archive_sha256": "a"*64}
    sig = rh.compute(row)
    assert rh.verify(row, sig)

    row["verdict"] = "MALICIOUS"  # 변조
    assert not rh.verify(row, sig)
    print(f"  OK verify rejects modified row")
    return True


def test_integrity_mode_ranking():
    print("\n== Test: integrity mode ranking ==")
    from pkgsentinel.db.integrity import Fingerprint
    chk_strict = IntegrityChecker(IntegrityMode.STRICT)
    cached_fast = Fingerprint(
        mode=IntegrityMode.FAST, archive_url="x",
        archive_sha256="a"*64,
    )
    fresh_strict = Fingerprint(
        mode=IntegrityMode.STRICT, archive_url="x",
        archive_sha256="a"*64,
    )
    ok, why = chk_strict.matches(cached_fast, fresh_strict)
    assert not ok, f"weaker cache should not match stronger fresh: {why}"
    print(f"  OK weaker cache rejected: {why[:60]}")
    return True


# ─────────────── 3. 위협 피드 + 필터 ───────────────

def test_known_malicious_exact_match():
    print("\n== Test: known_malicious exact match -> filter detects ==")
    db = _fresh_db()
    reset_default_db()  # 싱글톤 리셋
    # 직접 INSERT
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO known_malicious
                (advisory_id, ecosystem, package, version_glob, attack_type, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("MAL-2025-test", "PyPI", "evil-test-pkg", "*", "malicious_package", "test"))

    rpt = filter_run("evil-test-pkg", Ecosystem.PYPI, db=db)
    print(f"  exact_match={rpt.exact_match}, advisory={rpt.advisory_id}")
    assert rpt.exact_match
    assert rpt.advisory_id == "MAL-2025-test"
    print(f"  OK")
    return True


def test_typosquat_detection():
    print("\n== Test: typosquat-of-popular detection ==")
    db = _fresh_db()
    reset_default_db()
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO known_popular (ecosystem, package, rank, source)
            VALUES (?, ?, ?, ?)
        """, ("PyPI", "requests", 7, "test"))

    rpt = filter_run("reqests", Ecosystem.PYPI, db=db)
    print(f"  typosquat candidates: {rpt.typosquat_candidates}")
    assert any(c["target"] == "requests" for c in rpt.typosquat_candidates)
    print(f"  OK")
    return True


def test_popular_skips_typosquat():
    print("\n== Test: popular package skips typosquat check ==")
    db = _fresh_db()
    reset_default_db()
    with db.cursor() as cur:
        cur.executemany("""
            INSERT INTO known_popular (ecosystem, package, rank, source)
            VALUES (?, ?, ?, ?)
        """, [
            ("PyPI", "flask", 134, "test"),
            ("PyPI", "flagk", 200, "test"),  # 가까운 다른 인기 패키지
        ])

    rpt = filter_run("flask", Ecosystem.PYPI, db=db)
    print(f"  popular_rank={rpt.popular_rank}, typosquats={rpt.typosquat_candidates}")
    assert rpt.popular_rank == 134
    assert rpt.typosquat_candidates == []  # popular 면 검사 skip
    print(f"  OK")
    return True


# ─────────────── 4. 캐시 ───────────────

def test_cache_basic_hit_miss():
    print("\n== Test: cache get/put basic ==")
    db = _fresh_db()
    reset_default_db()
    cache = AnalysisCache(db, integrity_mode=IntegrityMode.STRICT)

    key = CacheKey(package="test-pkg", ecosystem="PyPI", version="1.0.0")
    h = cache.get(key)
    assert not h.hit
    print(f"  miss before put: {h.reason}")

    cache.put(key, {"verdict": "CLEAN", "evidence": []}, verdict="CLEAN")

    h = cache.get(key)
    assert h.hit
    print(f"  hit after put: {h.reason}")
    return True


def test_cache_invalidation_by_new_advisory():
    print("\n== Test: cache invalidation when new advisory inserted ==")
    db = _fresh_db()
    reset_default_db()
    cache = AnalysisCache(db, integrity_mode=IntegrityMode.STRICT)

    key = CacheKey(package="will-go-bad", ecosystem="PyPI", version="1.0.0")
    cache.put(key, {"verdict": "CLEAN", "evidence": []}, verdict="CLEAN")

    h = cache.get(key)
    assert h.hit, f"should hit before advisory: {h.reason}"

    # 새 advisory 등재 -> trigger 가 cache_invalidation_log 채움
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO known_malicious
                (advisory_id, ecosystem, package, version_glob, attack_type, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("MAL-newly-found", "PyPI", "will-go-bad", "*",
              "malicious_package", "test"))

    h = cache.get(key)
    print(f"  hit after new advisory: hit={h.hit}, reason={h.reason}")
    assert not h.hit
    assert "advisory" in h.reason.lower()
    print(f"  OK invalidated")
    return True


def test_cache_engine_version_invalidation():
    print("\n== Test: cache invalidates on different engine_version ==")
    db = _fresh_db()
    reset_default_db()
    cache = AnalysisCache(db, integrity_mode=IntegrityMode.STRICT)

    key = CacheKey(
        package="test-pkg", ecosystem="PyPI", version="1.0.0",
        engine_version="OLD-VERSION-9.9.9",
    )
    cache.put(key, {"verdict": "CLEAN", "evidence": []}, verdict="CLEAN")
    # put 은 ENGINE_VERSION 으로 강제 — 우리가 미래에 조회할 때 ENGINE_VERSION 매칭

    # Hijack: row 의 engine_version 을 강제로 OLD 로 바꿔 미래 조회 모방
    with db.cursor() as cur:
        cur.execute("""
            UPDATE analyses SET engine_version = ?
            WHERE package = ? AND ecosystem = ? AND version = ?
        """, ("OLD-VERSION-9.9.9", "test-pkg", "PyPI", "1.0.0"))

    # 다른 키 (current ENGINE_VERSION) 로 조회 → miss
    fresh_key = CacheKey(package="test-pkg", ecosystem="PyPI", version="1.0.0")
    h = cache.get(fresh_key)
    print(f"  hit?: {h.hit}, reason={h.reason}")
    assert not h.hit
    return True


def test_paranoid_row_hmac():
    print("\n== Test: paranoid mode row HMAC ==")
    db = _fresh_db()
    reset_default_db()
    cache = AnalysisCache(db, integrity_mode=IntegrityMode.PARANOID)

    key = CacheKey(package="paranoid-pkg", ecosystem="PyPI", version="1.0.0")
    cache.put(key, {"verdict": "CLEAN", "evidence": []}, verdict="CLEAN")

    # 정상 hit
    h = cache.get(key)
    assert h.hit, f"should hit: {h.reason}"
    print(f"  OK normal hit")

    # 메모리 변조 시뮬레이션: row 의 verdict 컬럼만 변조 (HMAC 은 그대로)
    with db.cursor() as cur:
        cur.execute("""
            UPDATE analyses SET verdict = 'BENIGN-FAKE'
            WHERE package = ? AND ecosystem = ? AND version = ?
        """, ("paranoid-pkg", "PyPI", "1.0.0"))

    h = cache.get(key)
    print(f"  after tamper: hit={h.hit}, reason={h.reason}")
    assert not h.hit
    assert "HMAC" in h.reason or "tamper" in h.reason.lower()
    print(f"  OK tamper detected by HMAC")
    return True


# ─────────────── main ───────────────

def main():
    tests = [
        test_db_is_encrypted,
        test_wrong_key_rejected,
        test_merkle_tamper_detection,
        test_row_hmac_tamper_detection,
        test_integrity_mode_ranking,
        test_known_malicious_exact_match,
        test_typosquat_detection,
        test_popular_skips_typosquat,
        test_cache_basic_hit_miss,
        test_cache_invalidation_by_new_advisory,
        test_cache_engine_version_invalidation,
        test_paranoid_row_hmac,
    ]
    failed = 0
    for t in tests:
        try:
            ok = t()
            if not ok:
                failed += 1
        except Exception as e:
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*50}")
    print(f"PASSED: {len(tests) - failed}/{len(tests)}")
    if failed:
        print(f"FAILED: {failed}")
    else:
        print("ALL OK")

    # cleanup
    import shutil
    shutil.rmtree(TEST_DB_DIR, ignore_errors=True)
    sys.exit(failed)


if __name__ == "__main__":
    main()
