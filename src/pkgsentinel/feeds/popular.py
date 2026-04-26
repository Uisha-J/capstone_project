"""
인기 패키지 화이트리스트 피드 -> 암호화 DB 적재.

소스:
  - PyPI: https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json
          (월간 갱신, BigQuery 기반 30일 다운로드 수)
  - npm:  https://api.npmjs.org/downloads/range/last-week/<scope>  (개별)
          또는 https://github.com/anvaka/npm-top (top 1000 정적)

목적:
  - false positive 억제: 인기 패키지에서 미세한 의심 신호가 떠도
    verdict 를 자동 강등하지 말고 "리뷰 필요" 로만 표시
  - 단, exact malicious 매칭이 우세하면 무시 (악성 우선)

본 도구는 화이트리스트를 약한 신호로 취급:
  - rank <= 1000 → 신뢰 강화 (false positive 억제)
  - rank <= 5000 → 약한 신뢰
  - 그 외 → 무관
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone

from ..db.threat_db import ThreatDB, get_default_db


# ─────────────── 출처 ───────────────

PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json"
NPM_TOP_URL = "https://anvaka.github.io/npmrank/online/npmrank.json"


# ─────────────── 다운로드 ───────────────

def _http_json(url: str, timeout: int = 60) -> tuple[dict | list, str]:
    if not url.startswith("https://"):
        raise ValueError(f"feed URL must be HTTPS: {url}")
    print(f"[POPULAR] downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ai-slopsq/2.0 popular"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    sha = hashlib.sha256(body).hexdigest()
    return json.loads(body), sha


# ─────────────── 적재 ───────────────

_INSERT_POPULAR_SQL = """
INSERT INTO known_popular (
    ecosystem, package, rank, downloads_30d, stars, source, last_seen_at
) VALUES (
    :ecosystem, :package, :rank, :downloads_30d, :stars, :source, CURRENT_TIMESTAMP
)
ON CONFLICT(ecosystem, package) DO UPDATE SET
    rank          = excluded.rank,
    downloads_30d = excluded.downloads_30d,
    stars         = excluded.stars,
    source        = excluded.source,
    last_seen_at  = CURRENT_TIMESTAMP
"""


def _record_meta(db: ThreatDB, *, source: str, count: int, sha: str,
                 error: str | None = None) -> str:
    feed_version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO feed_meta (source, last_fetched_at, record_count,
                                   fetch_sha256, feed_version, error)
            VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                last_fetched_at = CURRENT_TIMESTAMP,
                record_count    = excluded.record_count,
                fetch_sha256    = excluded.fetch_sha256,
                feed_version    = excluded.feed_version,
                error           = excluded.error
        """, (source, count, sha, feed_version, error))
    return feed_version


# ─────────────── PyPI ───────────────

def ingest_pypi_top(
    *,
    db: ThreatDB | None = None,
    top_n: int = 5000,
    skip_if_unchanged: bool = True,
) -> dict:
    db = db or get_default_db()
    source_key = "popular-pypi"
    t0 = time.time()
    try:
        data, sha = _http_json(PYPI_TOP_URL)
    except Exception as e:
        _record_meta(db, source=source_key, count=0, sha="", error=str(e))
        return {"ok": False, "ecosystem": "PyPI", "error": str(e)}

    if skip_if_unchanged:
        with db.cursor() as cur:
            cur.execute("SELECT fetch_sha256 FROM feed_meta WHERE source=?",
                        (source_key,))
            row = cur.fetchone()
            if row and row[0] == sha:
                print(f"[POPULAR] PyPI unchanged, skip")
                return {"ok": True, "ecosystem": "PyPI", "skipped": True}

    # 데이터 형식: { "last_update": "...", "rows": [{"project": "boto3", "download_count": ...}, ...] }
    rows_in = data.get("rows", []) if isinstance(data, dict) else []
    if not rows_in:
        return {"ok": False, "ecosystem": "PyPI", "error": "empty top-pypi feed"}

    rows = []
    for rank, item in enumerate(rows_in[:top_n], start=1):
        name = item.get("project") or item.get("name")
        if not name:
            continue
        rows.append({
            "ecosystem": "PyPI",
            "package": name.lower(),
            "rank": rank,
            "downloads_30d": int(item.get("download_count") or 0),
            "stars": None,
            "source": "top-pypi-packages",
        })

    with db.cursor() as cur:
        cur.executemany(_INSERT_POPULAR_SQL, rows)

    feed_version = _record_meta(db, source=source_key, count=len(rows), sha=sha)
    print(f"[POPULAR] PyPI: upserted {len(rows)} rows, took {time.time()-t0:.1f}s")
    return {"ok": True, "ecosystem": "PyPI", "rows": len(rows),
            "feed_version": feed_version, "fetch_sha256": sha}


# ─────────────── npm ───────────────

def ingest_npm_top(
    *,
    db: ThreatDB | None = None,
    top_n: int = 5000,
    skip_if_unchanged: bool = True,
) -> dict:
    db = db or get_default_db()
    source_key = "popular-npm"
    t0 = time.time()
    try:
        data, sha = _http_json(NPM_TOP_URL)
    except Exception as e:
        _record_meta(db, source=source_key, count=0, sha="", error=str(e))
        return {"ok": False, "ecosystem": "npm", "error": str(e)}

    if skip_if_unchanged:
        with db.cursor() as cur:
            cur.execute("SELECT fetch_sha256 FROM feed_meta WHERE source=?",
                        (source_key,))
            row = cur.fetchone()
            if row and row[0] == sha:
                print(f"[POPULAR] npm unchanged, skip")
                return {"ok": True, "ecosystem": "npm", "skipped": True}

    # anvaka npmrank 형식: { "rank": { "lodash": <score>, ... } }
    rank_dict = data.get("rank", {}) if isinstance(data, dict) else {}
    if not rank_dict:
        return {"ok": False, "ecosystem": "npm", "error": "empty npmrank feed"}

    items = sorted(rank_dict.items(), key=lambda kv: -float(kv[1] or 0))
    rows = []
    for rank, (name, score) in enumerate(items[:top_n], start=1):
        rows.append({
            "ecosystem": "npm",
            "package": name.lower(),
            "rank": rank,
            "downloads_30d": None,
            "stars": None,
            "source": "anvaka-npmrank",
        })

    with db.cursor() as cur:
        cur.executemany(_INSERT_POPULAR_SQL, rows)

    feed_version = _record_meta(db, source=source_key, count=len(rows), sha=sha)
    print(f"[POPULAR] npm: upserted {len(rows)} rows, took {time.time()-t0:.1f}s")
    return {"ok": True, "ecosystem": "npm", "rows": len(rows),
            "feed_version": feed_version, "fetch_sha256": sha}


# ─────────────── 조회 헬퍼 ───────────────

def lookup_popular(db: ThreatDB, ecosystem: str, package: str) -> dict | None:
    with db.cursor() as cur:
        cur.execute(
            "SELECT rank, downloads_30d, source FROM known_popular "
            "WHERE ecosystem=? AND package=? LIMIT 1",
            (ecosystem, package.lower()),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {"rank": row[0], "downloads_30d": row[1], "source": row[2]}


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse, sys

    p = argparse.ArgumentParser()
    p.add_argument("--ecosystem", choices=["PyPI", "npm", "all"], default="PyPI")
    p.add_argument("--top-n", type=int, default=5000)
    p.add_argument("--passphrase", default=None)
    args = p.parse_args()

    if args.passphrase:
        from ..db.threat_db import ThreatDB, DEFAULT_DB_PATH
        db = ThreatDB(DEFAULT_DB_PATH, passphrase=args.passphrase)
    else:
        db = None

    targets = ["PyPI", "npm"] if args.ecosystem == "all" else [args.ecosystem]
    ok_all = True
    for eco in targets:
        if eco == "PyPI":
            r = ingest_pypi_top(db=db, top_n=args.top_n)
        else:
            r = ingest_npm_top(db=db, top_n=args.top_n)
        if not r.get("ok"):
            ok_all = False
            print(f"FAIL {eco}: {r.get('error')}", file=sys.stderr)
    sys.exit(0 if ok_all else 1)
