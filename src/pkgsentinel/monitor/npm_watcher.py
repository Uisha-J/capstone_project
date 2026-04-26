"""
npm 신규 release watcher — CouchDB `_changes` feed.

전략:
  - npm registry 자체가 CouchDB. `_changes` 엔드포인트로 변경 이벤트 stream.
  - feed=normal  : 한 번에 since 이후 변경분 받고 종료 (cron 친화)
  - feed=continuous : Server-Sent Events 처럼 line-delimited JSON 무한 stream (데몬 친화)

  본 도구는 cron 모드라서 normal 사용. 한 번 polling 마다 since=N 부터의 변경분을 받아
  큐에 적재하고 종료.

last_seq 는 schema_meta 에 저장.

참고: replicate.npmjs.com 은 정상 작동. 하지만 응답 큰 경우 (since=0) 메모리 폭발 →
       limit 옵션으로 한 번에 받는 변경 수 제한.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from typing import Iterable

from ..db.threat_db import ThreatDB, get_default_db
from .priority_queue import PriorityQueue
from .release_event import ReleaseEvent


NPM_CHANGES = "https://replicate.npmjs.com/_changes"
NPM_REPLICATE_BASE = "https://replicate.npmjs.com"
NPM_REGISTRY = "https://registry.npmjs.org"


# ─────────────── HTTP ───────────────

def _http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "ai-slopsq/2.0 npm-watcher"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _fetch_db_info() -> dict:
    """replicate.npmjs.com 루트 — update_seq 등 DB info."""
    body = _http_get(f"{NPM_REPLICATE_BASE}/", timeout=30)
    return json.loads(body)


def _fetch_changes(since: str | int = 0, limit: int = 200) -> dict:
    """`_changes?since=N&limit=K&include_docs=false`.

    since=0 은 npm 이 4억+ 변경분을 다 보내려 해서 사실상 unusable.
    since=now 는 replicate.npmjs.com 이 400 거부.
    → since 가 0/"0" 이면 db info 의 update_seq 에서 최근 limit 건만.
    """
    if since == 0 or since == "0":
        info = _fetch_db_info()
        cur_seq = int(info.get("update_seq", 0))
        since = max(1, cur_seq - limit)

    # CloudFlare 가 since+limit 외 다른 파라미터 (include_docs/feed) 를 거부.
    qs = urllib.parse.urlencode({"since": since, "limit": limit})
    body = _http_get(f"{NPM_CHANGES}?{qs}", timeout=120)
    return json.loads(body)


def _fetch_package_meta(name: str) -> dict | None:
    """`registry.npmjs.org/<name>` — versions 조회용."""
    try:
        # 점/슬래시 escape (scoped @scope/name)
        encoded = urllib.parse.quote(name, safe="")
        body = _http_get(f"{NPM_REGISTRY}/{encoded}", timeout=30)
        return json.loads(body)
    except Exception:
        return None


# ─────────────── 변환 ───────────────

def _changes_to_events(
    changes: list[dict],
    *,
    fetch_versions: bool = True,
    max_versions_per_pkg: int = 3,
) -> list[ReleaseEvent]:
    """changes row → ReleaseEvent 들.

    각 row 는 {id: '<pkg-name>', seq: N, changes: [{rev: '...'}], deleted?}.
    deleted 면 skip (unpublish — 우리는 "새 게시" 만 처리).

    fetch_versions=True 면 registry 에서 versions 조회 후 최근 N 개를 이벤트로.
    False 면 ReleaseEvent.version="latest" 로만 enqueue (worker 에서 latest 해석).
    """
    events: list[ReleaseEvent] = []
    for row in changes:
        if row.get("deleted"):
            continue
        name = row.get("id")
        if not name or name.startswith("_"):
            continue
        seq = row.get("seq")

        if not fetch_versions:
            events.append(ReleaseEvent(
                ecosystem="npm", package=name, version="latest",
                source_event="npm_changes",
                raw_meta={"seq": seq},
            ))
            continue

        meta = _fetch_package_meta(name)
        if not meta:
            continue
        latest_tag = (meta.get("dist-tags") or {}).get("latest")
        versions = list((meta.get("versions") or {}).keys())
        # 최신 K 개만 (sort 는 publish 순서 정확하지 않음 — keys 그대로 사용)
        recent = versions[-max_versions_per_pkg:] if versions else []
        if latest_tag and latest_tag not in recent:
            recent.append(latest_tag)

        for v in recent:
            ver_meta = (meta.get("versions") or {}).get(v, {})
            tarball = (ver_meta.get("dist") or {}).get("tarball", "")
            events.append(ReleaseEvent(
                ecosystem="npm", package=name, version=v,
                archive_url=tarball,
                source_event="npm_changes",
                raw_meta={
                    "seq": seq,
                    "is_latest": (v == latest_tag),
                    "shasum": (ver_meta.get("dist") or {}).get("shasum"),
                },
            ))
    return events


# ─────────────── DB 상태 ───────────────

_LAST_SEQ_KEY = "watcher.npm.last_seq"


def get_last_seq(db: ThreatDB) -> str | int:
    v = db.get_meta(_LAST_SEQ_KEY)
    if not v:
        return 0
    # CouchDB seq 는 보통 int 지만 future-proof 차원에서 string 도 허용
    try:
        return int(v)
    except ValueError:
        return v


def set_last_seq(db: ThreatDB, seq):
    db.set_meta(_LAST_SEQ_KEY, str(seq))


# ─────────────── 공개 API ───────────────

def poll_once(
    *,
    db: ThreatDB | None = None,
    limit: int = 200,
    fetch_versions: bool = True,
    max_versions_per_pkg: int = 1,
) -> dict:
    """한 번의 polling 사이클.

    fetch_versions=False 로 하면 registry 호출 없이 _changes 만 사용 → 빠름.
                          단 archive_url 이 비어있어 worker 가 별도 fetch 필요.
    """
    db = db or get_default_db()
    pq = PriorityQueue(db)

    last = get_last_seq(db)
    try:
        data = _fetch_changes(since=last, limit=limit)
    except Exception as e:
        return {"used": "couchdb", "error": f"fetch: {e}", "enqueued": 0}

    rows = data.get("results") or []
    new_last = data.get("last_seq") or last

    events = _changes_to_events(
        rows,
        fetch_versions=fetch_versions,
        max_versions_per_pkg=max_versions_per_pkg,
    )
    enqueued = pq.enqueue_many(events)

    set_last_seq(db, new_last)

    return {
        "used": "couchdb",
        "since": last,
        "last_seq": new_last,
        "changes_seen": len(rows),
        "events": len(events),
        "enqueued": enqueued,
    }


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse, sys

    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=200,
                   help="한 번에 받을 changes 최대")
    p.add_argument("--no-fetch-versions", action="store_true",
                   help="registry 메타 호출 없이 changes 만")
    p.add_argument("--versions-per-pkg", type=int, default=1)
    p.add_argument("--passphrase", default=None)
    p.add_argument("--reset-seq", action="store_true",
                   help="last_seq 를 0 으로 리셋 (대량 재처리)")
    args = p.parse_args()

    if args.passphrase:
        from ..db.threat_db import ThreatDB, DEFAULT_DB_PATH
        db = ThreatDB(DEFAULT_DB_PATH, passphrase=args.passphrase)
    else:
        db = None

    if args.reset_seq:
        d = db or get_default_db()
        set_last_seq(d, 0)
        print("OK: last_seq reset to 0")

    t0 = time.time()
    r = poll_once(
        db=db, limit=args.limit,
        fetch_versions=not args.no_fetch_versions,
        max_versions_per_pkg=args.versions_per_pkg,
    )
    print(f"[npm-watcher] elapsed {time.time()-t0:.1f}s")
    print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
    sys.exit(0 if not r.get("error") else 1)
