"""Phase 4.5 full — 30분 wall-clock 운영 smoke (Haiku 모드).

24h daemon 의 1/48 시간 압축판. 실제 PyPI XMLRPC + npm changes feed 로
신규 release 를 polling 해 큐에 enqueue, worker 가 Haiku 로 분석 + sink.

비용: ~$0.50-1 (Haiku 4.5 × 20-30 packages × 3 agents)

24h 운영용 systemd unit 은 deploy/systemd/ 참고.
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
    ap.add_argument("--minutes", type=int, default=30,
                    help="총 운영 시간 (wall-clock)")
    ap.add_argument("--max-packages", type=int, default=20,
                    help="최대 분석 패키지 수")
    ap.add_argument("--llm-model", default="claude-haiku-4-5",
                    choices=["claude-sonnet-4-5", "claude-haiku-4-5"])
    ap.add_argument("--llm-mode", default="claude",
                    choices=["stub", "claude"])
    ap.add_argument("--enqueue-pypi", type=int, default=50)
    ap.add_argument("--enqueue-npm", type=int, default=0,
                    help="0=skip npm (changes feed 가 RSS 가 느림)")
    ap.add_argument("--out", default=str(
        ROOT / "scripts" / "eval_real_data" / "results_monitor_extended.json"))
    args = ap.parse_args()

    # .env 로드 + 격리 DB
    from pkgsentinel import _dotenv
    _dotenv.load()
    if args.llm_mode == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY missing", file=sys.stderr)
        sys.exit(2)

    td = tempfile.mkdtemp(prefix="monitor_ext_")
    db_path = Path(td) / "smoke.sqlcipher"
    os.environ["AISLOP_DB_KEY"] = "monitor-ext-smoke-key"

    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    db = ThreatDB(db_path, passphrase=os.environ["AISLOP_DB_KEY"])
    tdb_mod._default_db = db

    print(f"=== Monitor extended smoke ===")
    print(f"  budget       : {args.minutes} min wall-clock")
    print(f"  max packages : {args.max_packages}")
    print(f"  LLM          : {args.llm_mode} / {args.llm_model}")
    print(f"  DB (isolated): {db_path}")
    print()

    # ──────────── 1) PyPI polling ────────────
    from pkgsentinel.monitor.pypi_watcher import poll_once as poll_pypi
    print(f"[1] PyPI XMLRPC poll (max={args.enqueue_pypi})")
    t0 = time.time()
    pypi_result = poll_pypi(
        db=db, max_events=args.enqueue_pypi, prefer="auto",
    )
    elapsed_pypi = time.time() - t0
    print(f"    used={pypi_result.get('used')} "
          f"enqueued={pypi_result.get('enqueued', 0)} "
          f"elapsed={elapsed_pypi:.1f}s")

    # ──────────── 2) npm polling (선택) ────────────
    npm_result = None
    if args.enqueue_npm > 0:
        from pkgsentinel.monitor.npm_watcher import poll_once as poll_npm
        print(f"\n[2] npm changes poll (limit={args.enqueue_npm})")
        t0 = time.time()
        try:
            # npm_watcher 는 limit 인자. fetch_versions=False → registry 콜 회피로 빠른 enqueue.
            npm_result = poll_npm(
                db=db, limit=args.enqueue_npm, fetch_versions=False,
            )
            print(f"    used={npm_result.get('used')} "
                  f"changes_seen={npm_result.get('changes_seen', 0)} "
                  f"enqueued={npm_result.get('enqueued', 0)} "
                  f"elapsed={time.time()-t0:.1f}s")
        except Exception as e:
            print(f"    npm poll failed: {e}")

    # ──────────── 3) Worker drain ────────────
    from pkgsentinel.monitor.worker import run_worker
    from pkgsentinel.monitor.priority_queue import PriorityQueue
    pq = PriorityQueue(db)
    pre_stats = pq.stats()
    print(f"\n[3] worker drain (max={args.max_packages})")
    print(f"    queue before: {pre_stats}")

    # wall-clock budget 안에서 worker loop. max_jobs 도착 또는 timeout.
    deadline = time.time() + args.minutes * 60

    # worker 의 run_worker 는 max_jobs 도착하면 exit — loop=False
    t0 = time.time()
    worker_summary = run_worker(
        db=db,
        max_jobs=args.max_packages,
        llm_mode=args.llm_mode,
        llm_model=args.llm_model,
        integrity_mode="strict",
        loop=False,
        verbose=True,
    )
    elapsed_worker = time.time() - t0
    post_stats = pq.stats()
    print(f"\n    elapsed: {elapsed_worker:.1f}s")
    print(f"    processed: {worker_summary['processed']}")
    print(f"    queue after: {post_stats}")

    # ──────────── 4) 결과 요약 ────────────
    by_verdict = {}
    sinks_total = 0
    err_count = 0
    for r in worker_summary["results"]:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
        sinks_total += len(r.get("sinks", []))
        if r.get("error"):
            err_count += 1

    print(f"\n=== Summary ===")
    print(f"  verdicts     : {by_verdict}")
    print(f"  sinks emitted: {sinks_total}")
    print(f"  errors       : {err_count}")
    print(f"  total wall   : {(time.time() - (deadline - args.minutes*60)):.1f}s")

    # ──────────── 5) 저장 ────────────
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "budget_minutes": args.minutes,
        "max_packages": args.max_packages,
        "llm_mode": args.llm_mode,
        "llm_model": args.llm_model,
        "pypi_poll": pypi_result,
        "npm_poll": npm_result,
        "worker_summary": worker_summary,
        "queue_pre": pre_stats,
        "queue_post": post_stats,
        "verdict_distribution": by_verdict,
        "errors": err_count,
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\nJSON saved -> {out_path}")

    # cleanup isolated DB
    import shutil
    shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    main()
