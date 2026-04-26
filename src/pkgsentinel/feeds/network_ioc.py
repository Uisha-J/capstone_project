"""
네트워크 IoC (악성 도메인/IP/URL) 피드 -> 암호화 DB 적재.

소스 (모두 무료 + 공개 + HTTPS):
  - URLhaus (abuse.ch) — 활성 악성 URL/도메인. 5분 단위 갱신.
      https://urlhaus.abuse.ch/downloads/csv_recent/
  - Feodo Tracker (abuse.ch) — botnet C2 IP/도메인.
      https://feodotracker.abuse.ch/downloads/ipblocklist.json

사용처:
  - 분석 대상 패키지의 setup.py / postinstall 등에 등장하는
    URL/도메인이 이 블록리스트에 있으면 즉시 강한 악성 신호.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import time
import urllib.request
from datetime import datetime, timezone

from ..db.threat_db import ThreatDB, get_default_db


URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_JSON  = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


# ─────────────── 다운로드 ───────────────

def _http_get(url: str, timeout: int = 60) -> tuple[bytes, str]:
    if not url.startswith("https://"):
        raise ValueError(f"feed URL must be HTTPS: {url}")
    print(f"[IOC] downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ai-slopsq/2.0 ioc"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return body, hashlib.sha256(body).hexdigest()


# ─────────────── DB 헬퍼 ───────────────

_INSERT_IOC_SQL = """
INSERT INTO network_blocklist (
    indicator, indicator_type, source, severity, note, inserted_at
) VALUES (
    :indicator, :indicator_type, :source, :severity, :note, CURRENT_TIMESTAMP
)
ON CONFLICT(indicator, source) DO UPDATE SET
    indicator_type = excluded.indicator_type,
    severity       = excluded.severity,
    note           = excluded.note,
    inserted_at    = CURRENT_TIMESTAMP
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


# ─────────────── URLhaus ───────────────

def ingest_urlhaus(*, db: ThreatDB | None = None,
                   limit: int | None = None,
                   skip_if_unchanged: bool = True) -> dict:
    db = db or get_default_db()
    source_key = "urlhaus"
    t0 = time.time()
    try:
        body, sha = _http_get(URLHAUS_CSV)
    except Exception as e:
        _record_meta(db, source=source_key, count=0, sha="", error=str(e))
        return {"ok": False, "source": source_key, "error": str(e)}

    if skip_if_unchanged:
        with db.cursor() as cur:
            cur.execute("SELECT fetch_sha256 FROM feed_meta WHERE source=?",
                        (source_key,))
            row = cur.fetchone()
            if row and row[0] == sha:
                print(f"[IOC] urlhaus unchanged, skip")
                return {"ok": True, "source": source_key, "skipped": True}

    # CSV 헤더 라인이 # 으로 시작 → skip
    text = body.decode("utf-8", errors="replace")
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # urlhaus CSV: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        parts = next(csv.reader([line]))
        if len(parts) < 7:
            continue
        url = parts[2].strip().strip('"')
        threat = parts[5].strip().strip('"')
        tags = parts[6].strip().strip('"')
        if not url:
            continue

        # 도메인만 따로 추출도 함께
        from urllib.parse import urlparse
        try:
            host = urlparse(url).hostname
        except Exception:
            host = None

        rows.append({
            "indicator": url,
            "indicator_type": "url",
            "source": "urlhaus",
            "severity": "HIGH",
            "note": f"{threat}; tags={tags}",
        })
        if host:
            rows.append({
                "indicator": host,
                "indicator_type": "domain",
                "source": "urlhaus",
                "severity": "HIGH",
                "note": f"{threat}; from-url",
            })

        if limit and len(rows) >= limit:
            break

    # 중복 제거 (indicator+source PK 가 처리하지만, batch 내 중복은 우리가 dedupe)
    seen = set()
    deduped = []
    for r in rows:
        k = (r["indicator"], r["source"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)

    with db.cursor() as cur:
        cur.executemany(_INSERT_IOC_SQL, deduped)

    feed_version = _record_meta(db, source=source_key, count=len(deduped), sha=sha)
    print(f"[IOC] urlhaus: upserted {len(deduped)} rows, took {time.time()-t0:.1f}s")
    return {"ok": True, "source": source_key, "rows": len(deduped),
            "feed_version": feed_version, "fetch_sha256": sha}


# ─────────────── Feodo Tracker ───────────────

def ingest_feodo(*, db: ThreatDB | None = None,
                 skip_if_unchanged: bool = True) -> dict:
    db = db or get_default_db()
    source_key = "feodo"
    t0 = time.time()
    try:
        body, sha = _http_get(FEODO_JSON)
    except Exception as e:
        _record_meta(db, source=source_key, count=0, sha="", error=str(e))
        return {"ok": False, "source": source_key, "error": str(e)}

    if skip_if_unchanged:
        with db.cursor() as cur:
            cur.execute("SELECT fetch_sha256 FROM feed_meta WHERE source=?",
                        (source_key,))
            row = cur.fetchone()
            if row and row[0] == sha:
                print(f"[IOC] feodo unchanged, skip")
                return {"ok": True, "source": source_key, "skipped": True}

    try:
        data = json.loads(body)
    except Exception as e:
        return {"ok": False, "source": source_key, "error": f"json: {e}"}

    rows = []
    for item in data:
        ip = item.get("ip_address")
        if not ip:
            continue
        rows.append({
            "indicator": ip,
            "indicator_type": "ip",
            "source": "feodo",
            "severity": "HIGH",
            "note": f"{item.get('malware', '?')}; "
                    f"first={item.get('first_seen', '?')}; "
                    f"last={item.get('last_online', '?')}",
        })
    with db.cursor() as cur:
        cur.executemany(_INSERT_IOC_SQL, rows)

    feed_version = _record_meta(db, source=source_key, count=len(rows), sha=sha)
    print(f"[IOC] feodo: upserted {len(rows)} rows, took {time.time()-t0:.1f}s")
    return {"ok": True, "source": source_key, "rows": len(rows),
            "feed_version": feed_version, "fetch_sha256": sha}


# ─────────────── 조회 ───────────────

def lookup_indicator(db: ThreatDB, indicator: str) -> list[dict]:
    """주어진 도메인/IP/URL 이 블록리스트에 있는지."""
    with db.cursor() as cur:
        cur.execute(
            "SELECT indicator_type, source, severity, note "
            "FROM network_blocklist WHERE indicator=? "
            "ORDER BY severity",
            (indicator,),
        )
        return [
            {"type": r[0], "source": r[1], "severity": r[2], "note": r[3]}
            for r in cur.fetchall()
        ]


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse, sys

    p = argparse.ArgumentParser()
    p.add_argument("--source", choices=["urlhaus", "feodo", "all"], default="all")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--passphrase", default=None)
    args = p.parse_args()

    if args.passphrase:
        from ..db.threat_db import ThreatDB, DEFAULT_DB_PATH
        db = ThreatDB(DEFAULT_DB_PATH, passphrase=args.passphrase)
    else:
        db = None

    sources = ["urlhaus", "feodo"] if args.source == "all" else [args.source]
    ok_all = True
    for s in sources:
        if s == "urlhaus":
            r = ingest_urlhaus(db=db, limit=args.limit)
        else:
            r = ingest_feodo(db=db)
        if not r.get("ok"):
            ok_all = False
            print(f"FAIL {s}: {r.get('error')}", file=sys.stderr)
    sys.exit(0 if ok_all else 1)
