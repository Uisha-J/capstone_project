"""
PyPI 신규 release watcher.

전략:
  1. XML-RPC `changelog_since_serial(N)` — 가장 정확. since N 이후의
     이벤트 (create, new release, file upload, etc.) 를 반환.
  2. RSS `https://pypi.org/rss/updates.xml` — XML-RPC 가 막힐 때 fallback.

last_serial 은 schema_meta 에 저장 → 다음 polling 시 재사용.
"""
from __future__ import annotations

import time
import urllib.request
import xml.etree.ElementTree as ET
import xmlrpc.client
from typing import Iterable

from ..db.threat_db import ThreatDB, get_default_db
from .priority_queue import PriorityQueue
from .release_event import ReleaseEvent


PYPI_XMLRPC = "https://pypi.org/pypi"
PYPI_RSS    = "https://pypi.org/rss/updates.xml"


# ─────────────── XML-RPC ───────────────

def _fetch_xmlrpc(since_serial: int) -> list[dict]:
    """changelog_since_serial → [{name, version, action, ts, serial}, ...]"""
    proxy = xmlrpc.client.ServerProxy(PYPI_XMLRPC)
    rows = proxy.changelog_since_serial(since_serial)  # type: ignore
    out = []
    for entry in rows:
        # entry = (name, version, timestamp, action, serial)
        if not isinstance(entry, (list, tuple)) or len(entry) < 5:
            continue
        name, version, ts, action, serial = entry
        out.append({
            "name": name, "version": version,
            "timestamp": ts, "action": action, "serial": serial,
        })
    return out


def _to_release_events_xmlrpc(rows: Iterable[dict]) -> list[ReleaseEvent]:
    """create / new release / add * file 만 release 로 인정."""
    events: list[ReleaseEvent] = []
    seen: set[tuple] = set()
    for r in rows:
        action = (r.get("action") or "").lower()
        version = r.get("version")
        # action 종류:
        #   "create"           — 패키지 첫 생성
        #   "new release"      — 새 버전 release
        #   "add source file <fname>"
        #   "add cp311 file <fname>"
        if not version:
            continue
        if not (action == "new release"
                or action == "create"
                or action.startswith("add ")):
            continue
        key = (r["name"], version)
        if key in seen:
            continue
        seen.add(key)
        events.append(ReleaseEvent(
            ecosystem="PyPI",
            package=r["name"],
            version=version,
            source_event="pypi_xmlrpc",
            raw_meta={"action": action, "serial": r.get("serial"),
                      "timestamp": r.get("timestamp")},
        ))
    return events


# ─────────────── RSS fallback ───────────────

def _fetch_rss() -> list[dict]:
    req = urllib.request.Request(
        PYPI_RSS, headers={"User-Agent": "ai-slopsq/2.0 pypi-watcher"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
    root = ET.fromstring(body)
    items = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        # PyPI RSS title 형식: "package_name 1.2.3"
        if not title:
            continue
        parts = title.rsplit(" ", 1)
        if len(parts) != 2:
            continue
        name, version = parts[0], parts[1]
        items.append({
            "name": name, "version": version,
            "link": link, "pubDate": pub,
        })
    return items


def _to_release_events_rss(rows: Iterable[dict]) -> list[ReleaseEvent]:
    events: list[ReleaseEvent] = []
    for r in rows:
        events.append(ReleaseEvent(
            ecosystem="PyPI",
            package=r["name"],
            version=r["version"],
            source_event="pypi_rss",
            raw_meta={"link": r.get("link"), "pubDate": r.get("pubDate")},
        ))
    return events


# ─────────────── DB 상태 ───────────────

_LAST_SERIAL_KEY = "watcher.pypi.last_serial"


def get_last_serial(db: ThreatDB) -> int:
    v = db.get_meta(_LAST_SERIAL_KEY)
    try:
        return int(v) if v else 0
    except ValueError:
        return 0


def set_last_serial(db: ThreatDB, serial: int):
    db.set_meta(_LAST_SERIAL_KEY, str(serial))


# ─────────────── 공개 API ───────────────

def poll_once(*, db: ThreatDB | None = None,
              prefer: str = "auto",
              max_events: int = 500) -> dict:
    """
    한 번의 polling 사이클.

    prefer = 'xmlrpc' | 'rss' | 'auto' (xmlrpc 시도 후 실패 시 rss)
    """
    db = db or get_default_db()
    pq = PriorityQueue(db)

    events: list[ReleaseEvent] = []
    used = None
    error = None

    if prefer in ("auto", "xmlrpc"):
        last_serial = get_last_serial(db)
        try:
            rows = _fetch_xmlrpc(last_serial)
            if rows:
                events = _to_release_events_xmlrpc(rows)
                # 가장 큰 serial 저장
                max_serial = max(r["serial"] for r in rows)
                set_last_serial(db, max_serial)
            used = "xmlrpc"
        except Exception as e:
            error = f"xmlrpc: {e}"
            if prefer == "xmlrpc":
                return {"used": None, "error": error, "enqueued": 0}

    if not events and prefer in ("auto", "rss"):
        try:
            rows = _fetch_rss()
            events = _to_release_events_rss(rows)
            used = "rss"
        except Exception as e:
            error = f"rss: {e}"
            return {"used": None, "error": error, "enqueued": 0}

    if max_events and len(events) > max_events:
        events = events[:max_events]

    enqueued = pq.enqueue_many(events)
    return {
        "used": used,
        "events_seen": len(events),
        "enqueued": enqueued,
        "error": error,
    }


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse, json, sys

    p = argparse.ArgumentParser()
    p.add_argument("--prefer", choices=["xmlrpc", "rss", "auto"], default="auto")
    p.add_argument("--max", type=int, default=500)
    p.add_argument("--passphrase", default=None)
    args = p.parse_args()

    if args.passphrase:
        from ..db.threat_db import ThreatDB, DEFAULT_DB_PATH
        db = ThreatDB(DEFAULT_DB_PATH, passphrase=args.passphrase)
    else:
        db = None

    t0 = time.time()
    r = poll_once(db=db, prefer=args.prefer, max_events=args.max)
    print(f"[pypi-watcher] elapsed {time.time()-t0:.1f}s")
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if not r.get("error") else 1)
