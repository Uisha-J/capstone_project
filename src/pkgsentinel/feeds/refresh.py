"""
모든 위협 피드 통합 갱신 CLI.

사용 예:
  python -m detector.feeds.refresh --all
  python -m detector.feeds.refresh --osv --popular
  python -m detector.feeds.refresh --osv-pypi --no-skip   # 강제 재적재
  python -m detector.feeds.refresh --status               # 갱신 상태만 확인

cron 예시 (1일 1회):
  0 3 * * * AISLOP_DB_KEY="..." python -m detector.feeds.refresh --all
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from ..db.threat_db import ThreatDB, DEFAULT_DB_PATH, get_default_db
from . import osv as feed_osv
from . import popular as feed_popular
from . import network_ioc as feed_ioc


# ─────────────── 상태 조회 ───────────────

def show_status(db: ThreatDB) -> dict:
    with db.cursor() as cur:
        cur.execute("""
            SELECT source, last_fetched_at, record_count,
                   substr(fetch_sha256, 1, 12), feed_version, error
            FROM feed_meta
            ORDER BY source
        """)
        rows = cur.fetchall()
        cur.execute("SELECT count(*) FROM known_malicious")
        kmc = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM known_popular")
        kpc = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM network_blocklist")
        nbc = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM analyses")
        anc = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM cache_invalidation_log")
        civ = cur.fetchone()[0]

    feeds = []
    for r in rows:
        feeds.append({
            "source": r[0],
            "last_fetched_at": r[1],
            "record_count": r[2],
            "fetch_sha256_prefix": r[3],
            "feed_version": r[4],
            "error": r[5],
        })
    return {
        "feeds": feeds,
        "tables": {
            "known_malicious": kmc,
            "known_popular": kpc,
            "network_blocklist": nbc,
            "analyses": anc,
            "cache_invalidation_log": civ,
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────── 통합 실행 ───────────────

def run_all(
    db: ThreatDB,
    *,
    osv_pypi: bool = True,
    osv_npm: bool = True,
    popular_pypi: bool = True,
    popular_npm: bool = True,
    urlhaus: bool = True,
    feodo: bool = True,
    skip_if_unchanged: bool = True,
    osv_limit: int | None = None,
) -> dict:
    results: list[dict] = []
    t0 = time.time()

    if osv_pypi:
        results.append(feed_osv.ingest_osv(
            "PyPI", db=db, limit=osv_limit,
            skip_if_unchanged=skip_if_unchanged,
        ))
    if osv_npm:
        results.append(feed_osv.ingest_osv(
            "npm", db=db, limit=osv_limit,
            skip_if_unchanged=skip_if_unchanged,
        ))
    if popular_pypi:
        results.append(feed_popular.ingest_pypi_top(
            db=db, skip_if_unchanged=skip_if_unchanged,
        ))
    if popular_npm:
        results.append(feed_popular.ingest_npm_top(
            db=db, skip_if_unchanged=skip_if_unchanged,
        ))
    if urlhaus:
        results.append(feed_ioc.ingest_urlhaus(
            db=db, skip_if_unchanged=skip_if_unchanged,
        ))
    if feodo:
        results.append(feed_ioc.ingest_feodo(
            db=db, skip_if_unchanged=skip_if_unchanged,
        ))

    elapsed = time.time() - t0
    return {
        "elapsed_s": round(elapsed, 1),
        "results": results,
        "ok_all": all(r.get("ok") for r in results),
    }


# ─────────────── CLI ───────────────

def _argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Threat feed refresh")
    p.add_argument("--db", default=str(DEFAULT_DB_PATH))
    p.add_argument("--passphrase", default=None,
                   help="명시 (기본: env AISLOP_DB_KEY)")

    # 선택 플래그
    p.add_argument("--all", action="store_true", help="모든 피드 갱신")
    p.add_argument("--osv", action="store_true", help="OSV (PyPI + npm)")
    p.add_argument("--osv-pypi", action="store_true")
    p.add_argument("--osv-npm", action="store_true")
    p.add_argument("--popular", action="store_true",
                   help="인기 패키지 (PyPI + npm)")
    p.add_argument("--popular-pypi", action="store_true")
    p.add_argument("--popular-npm", action="store_true")
    p.add_argument("--ioc", action="store_true",
                   help="네트워크 IoC (urlhaus + feodo)")
    p.add_argument("--urlhaus", action="store_true")
    p.add_argument("--feodo", action="store_true")

    # 옵션
    p.add_argument("--no-skip", action="store_true",
                   help="동일 sha256 이어도 강제 재적재")
    p.add_argument("--osv-limit", type=int, default=None,
                   help="OSV 적재 행 제한 (개발용)")

    p.add_argument("--status", action="store_true",
                   help="갱신 후 (또는 갱신 없이) 상태만 출력")
    p.add_argument("--json", action="store_true",
                   help="결과 JSON 출력")
    return p


def main():
    args = _argparser().parse_args()

    # DB
    if args.passphrase:
        db = ThreatDB(args.db, passphrase=args.passphrase)
    else:
        db = ThreatDB(args.db)

    # 어떤 피드를 돌릴지 결정
    any_flag = any([
        args.all, args.osv, args.osv_pypi, args.osv_npm,
        args.popular, args.popular_pypi, args.popular_npm,
        args.ioc, args.urlhaus, args.feodo,
    ])

    summary = None
    if any_flag:
        if args.all:
            summary = run_all(
                db, skip_if_unchanged=not args.no_skip, osv_limit=args.osv_limit,
            )
        else:
            summary = run_all(
                db,
                osv_pypi=(args.osv or args.osv_pypi),
                osv_npm=(args.osv or args.osv_npm),
                popular_pypi=(args.popular or args.popular_pypi),
                popular_npm=(args.popular or args.popular_npm),
                urlhaus=(args.ioc or args.urlhaus),
                feodo=(args.ioc or args.feodo),
                skip_if_unchanged=not args.no_skip,
                osv_limit=args.osv_limit,
            )
        if args.json:
            print(json.dumps(summary, indent=2, ensure_ascii=False))
        else:
            print(f"\n[refresh] elapsed {summary['elapsed_s']}s, "
                  f"ok_all={summary['ok_all']}")
            for r in summary["results"]:
                eco = r.get("ecosystem") or r.get("source", "?")
                if r.get("skipped"):
                    print(f"  - {eco}: skipped (unchanged)")
                elif r.get("ok"):
                    print(f"  - {eco}: OK rows={r.get('rows', '?')} "
                          f"feed_version={r.get('feed_version', '?')}")
                else:
                    print(f"  - {eco}: FAIL ({r.get('error')})")

    if args.status or not any_flag:
        st = show_status(db)
        if args.json:
            print(json.dumps(st, indent=2, ensure_ascii=False))
        else:
            print("\n=== Feed status ===")
            for f in st["feeds"]:
                err = f" ERR: {f['error']}" if f["error"] else ""
                print(f"  {f['source']:<18}  rows={f['record_count']:>6}  "
                      f"v={f['feed_version']}  sha={f['fetch_sha256_prefix']}{err}")
            print("\n=== Tables ===")
            for k, v in st["tables"].items():
                print(f"  {k:<25}  {v}")

    db.close()
    sys.exit(0 if not summary or summary["ok_all"] else 1)


if __name__ == "__main__":
    main()
