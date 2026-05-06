"""
cron 단일 entrypoint.

서브커맨드:
  watch-pypi    PyPI 신규 release polling → 큐 적재
  watch-npm     npm  신규 release polling → 큐 적재
  worker        큐 pop → 분석 → sink 발송
  refresh-feeds OSV / popular / urlhaus / feodo 피드 갱신
  status        현재 큐 + 피드 상태

권장 cron 설정:
  */10 * * * *  python -m detector.monitor.cron_main watch-pypi
  */5  * * * *  python -m detector.monitor.cron_main watch-npm  --limit 200
  */5  * * * *  python -m detector.monitor.cron_main worker     --max 5
  0 3 * * *     python -m detector.monitor.cron_main refresh-feeds
"""
from __future__ import annotations

import argparse
import json
import sys

from ..db.threat_db import DEFAULT_DB_PATH, ThreatDB


def _make_db(passphrase: str | None) -> ThreatDB:
    if passphrase:
        return ThreatDB(DEFAULT_DB_PATH, passphrase=passphrase)
    return ThreatDB(DEFAULT_DB_PATH)


def _cmd_watch_pypi(args) -> int:
    from . import pypi_watcher
    db = _make_db(args.passphrase)
    r = pypi_watcher.poll_once(db=db, prefer=args.prefer, max_events=args.max)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if not r.get("error") else 1


def _cmd_watch_npm(args) -> int:
    from . import npm_watcher
    db = _make_db(args.passphrase)
    r = npm_watcher.poll_once(
        db=db,
        limit=args.limit,
        fetch_versions=not args.no_fetch_versions,
        max_versions_per_pkg=args.versions_per_pkg,
    )
    print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
    return 0 if not r.get("error") else 1


def _cmd_worker(args) -> int:
    from .worker import run_worker
    db = _make_db(args.passphrase)
    summary = run_worker(
        db=db,
        max_jobs=args.max,
        llm_mode=args.llm_mode,
        integrity_mode=args.integrity_mode,
        loop=args.loop,
        poll_interval_s=args.poll_interval,
        verbose=args.verbose,
    )
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"processed={summary['processed']} "
              f"elapsed={summary['elapsed_s']}s")
        for r in summary["results"]:
            sinks = ",".join(r["sinks"]) if r["sinks"] else "-"
            err = f"  ERR: {r['error'][:80]}" if r.get("error") else ""
            print(f"  id={r['id']:>4} {r['pkg']:<50} "
                  f"verdict={r['verdict']:<11} t={r['elapsed_s']:>5.1f}s "
                  f"sinks={sinks}{err}")
    return 0


def _cmd_refresh_feeds(args) -> int:
    from ..feeds.refresh import run_all
    db = _make_db(args.passphrase)
    summary = run_all(db, skip_if_unchanged=not args.no_skip)
    print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))
    return 0 if summary.get("ok_all") else 1


def _cmd_status(args) -> int:
    from ..feeds.refresh import show_status
    from .priority_queue import PriorityQueue
    db = _make_db(args.passphrase)
    feed_status = show_status(db)
    queue_stats = PriorityQueue(db).stats()
    out = {"feeds": feed_status, "queue": queue_stats}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


# ─────────────── argparse ───────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detector.monitor.cron_main")
    p.add_argument("--passphrase", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("watch-pypi", help="PyPI 신규 release polling")
    s.add_argument("--prefer", choices=["xmlrpc", "rss", "auto"], default="auto")
    s.add_argument("--max", type=int, default=500)
    s.set_defaults(func=_cmd_watch_pypi)

    s = sub.add_parser("watch-npm", help="npm 신규 release polling")
    s.add_argument("--limit", type=int, default=200)
    s.add_argument("--no-fetch-versions", action="store_true")
    s.add_argument("--versions-per-pkg", type=int, default=1)
    s.set_defaults(func=_cmd_watch_npm)

    s = sub.add_parser("worker", help="큐 consumer (분석 + sink)")
    s.add_argument("--max", type=int, default=10)
    s.add_argument("--loop", action="store_true")
    s.add_argument("--poll-interval", type=float, default=30.0)
    s.add_argument("--llm-mode", choices=["stub", "claude"], default="claude")
    s.add_argument("--integrity-mode",
                   choices=["fast", "strict", "paranoid"], default="strict")
    s.add_argument("--verbose", "-v", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_worker)

    s = sub.add_parser("refresh-feeds", help="모든 위협 피드 갱신")
    s.add_argument("--no-skip", action="store_true")
    s.set_defaults(func=_cmd_refresh_feeds)

    s = sub.add_parser("status", help="피드 + 큐 상태")
    s.set_defaults(func=_cmd_status)
    return p


def main():
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
