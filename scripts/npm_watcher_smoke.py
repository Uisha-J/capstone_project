"""npm changes feed (`poll_once`) 검증 smoke.

격리 DB → npm CouchDB _changes 한 사이클 poll → 큐 enqueue 확인. 분석은 X.
fetch_versions=False 로 빠르게 끝남 (registry 콜 회피).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--fetch-versions", action="store_true",
                    help="활성화 시 registry 콜 추가 → archive_url 채워짐 (느림)")
    args = ap.parse_args()

    td = tempfile.mkdtemp(prefix="npm_smoke_")
    db_path = Path(td) / "smoke.sqlcipher"
    os.environ["AISLOP_DB_KEY"] = "npm-smoke-key"

    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    db = ThreatDB(db_path, passphrase=os.environ["AISLOP_DB_KEY"])
    tdb_mod._default_db = db

    from pkgsentinel.monitor.npm_watcher import poll_once as poll_npm
    from pkgsentinel.monitor.priority_queue import PriorityQueue

    print(f"=== npm watcher smoke ===\nlimit={args.limit}  "
          f"fetch_versions={args.fetch_versions}")

    t0 = time.time()
    try:
        result = poll_npm(
            db=db, limit=args.limit,
            fetch_versions=args.fetch_versions,
            max_versions_per_pkg=1,
        )
    except Exception as e:
        print(f"  poll failed: {type(e).__name__}: {e}")
        sys.exit(1)
    elapsed = time.time() - t0
    print(f"  used: {result.get('used')}")
    print(f"  changes_seen: {result.get('changes_seen', 0)}")
    print(f"  events: {result.get('events', 0)}")
    print(f"  enqueued: {result.get('enqueued', 0)}")
    print(f"  elapsed: {elapsed:.1f}s")

    pq = PriorityQueue(db)
    stats = pq.stats()
    print(f"\nqueue stats: {stats}")

    if stats["pending"] > 0:
        # 1건만 peek (lock + complete X — 큐 보존)
        job = pq.lock_next()
        if job:
            print(f"\nfirst job sample:")
            print(f"  id={job.id} pkg={job.package} eco={job.ecosystem} "
                  f"version={job.version} prio={job.priority}")
            print(f"  archive_url={job.archive_url[:80] if job.archive_url else '-'}")
            pq.abandon(job.id, error="smoke peek only")

    out = ROOT / "scripts" / "eval_real_data" / "results_npm_watcher_smoke.json"
    out.write_text(json.dumps({
        "poll_result": result,
        "queue_stats": stats,
        "elapsed_s": round(elapsed, 2),
        "fetch_versions": args.fetch_versions,
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\nJSON saved -> {out}")

    import shutil
    shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    main()
