"""
OSV (osv.dev) 위협 피드 -> 암호화 DB 적재.

근거: https://osv.dev/

기존 detector/knowledge/osv.py 의 파싱 로직을 그대로 활용하되,
이번엔 JSON 파일이 아니라 SQLCipher DB 의 known_malicious 에 직접 INSERT.

다운로드 무결성:
  - HTTPS 만 허용
  - 다운로드한 zip 의 sha256 을 feed_meta.fetch_sha256 에 기록 (감사 추적)
  - 동일 zip 이면 INSERT skip (불필요한 캐시 invalidation 방지)
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import time
import urllib.request
import zipfile
from datetime import UTC, datetime

from ..db.threat_db import ThreatDB, get_default_db

# ─────────────── 출처 ───────────────

OSV_URLS = {
    "PyPI": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "npm":  "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
}


# ─────────────── 분류 휴리스틱 (기존과 동일) ───────────────

_STRONG_MALICIOUS_PHRASES = [
    "malicious package", "malicious code",
    "malware was found", "malware detected",
    "typosquatting", "typo-squat", "slopsquatting",
    "dependency confusion",
    "credential stealer", "info stealer", "infostealer",
    "supply chain attack",
    "backdoored", "contains a backdoor",
    "any version of this package",
    "exfiltrate", "exfiltrates", "harvest credentials",
]

_NETWORK_INDICATOR_RE = re.compile(
    r'(?:https?://[^\s"\'>)]+'
    r'|[a-zA-Z0-9.-]+\.(?:com|net|org|io|xyz|info|top|tk|ml|ga|cf|gq|onion)(?:/[^\s"\'>)]*)?'
    r'|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)'
)

_CODE_INDICATOR_PATTERNS = [
    r"\bbase64\.b64decode\b", r"\bexec\s*\(", r"\beval\s*\(",
    r"\bsubprocess\.(?:Popen|run|call)\b", r"\bos\.system\b",
    r"\bchild_process\.(?:exec|spawn)\b",
    r"\brequests\.(?:get|post)\b", r"\burllib\.request\b",
    r"\bprocess\.env\b", r"\bos\.environ\b", r"\batob\s*\(",
    r"\bcurl\b", r"\bwget\b", r"\bpowershell\b",
]


def _classify(record: dict) -> str:
    advisory_id = (record.get("id") or "").upper()
    if advisory_id.startswith("MAL-"):
        return "malicious_package"
    for alias in record.get("aliases", []) or []:
        if alias.upper().startswith("MAL-"):
            return "malicious_package"

    text = (record.get("summary", "") + " " + record.get("details", "")).lower()
    if any(p in text for p in _STRONG_MALICIOUS_PHRASES):
        if any(k in text for k in ("typosquat", "typo-squat", "typo squat")):
            return "typosquatting"
        if "dependency confusion" in text:
            return "dependency_confusion"
        if "slopsquat" in text:
            return "slopsquatting"
        return "malicious_package"
    return "other"


def _extract_indicators(text: str) -> tuple[list[str], list[str]]:
    code = set()
    for pat in _CODE_INDICATOR_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            code.add(pat.replace(r"\b", "").replace(r"\s*", "")
                     .replace("(?:", "").replace(")", "").strip("\\"))
    net = list(dict.fromkeys(_NETWORK_INDICATOR_RE.findall(text)))[:10]
    return sorted(code), net


# ─────────────── 다운로드 + 무결성 ───────────────

def _download_with_sha256(url: str, timeout: int = 180) -> tuple[bytes, str]:
    """archive 전체 + 자체 계산 sha256."""
    if not url.startswith("https://"):
        raise ValueError(f"feed URL must be HTTPS: {url}")
    print(f"[OSV] downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ai-slopsq/2.0 osv-feed"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    sha = hashlib.sha256(body).hexdigest()
    print(f"[OSV] downloaded {len(body)/1024/1024:.1f} MB, sha256={sha[:16]}..")
    return body, sha


# ─────────────── 파싱 ───────────────

def _parse_one(raw: dict, ecosystem: str) -> list[dict] | None:
    """OSV advisory 1건 -> known_malicious 행들 (영향받는 패키지가 여러 개일 수 있음)."""
    advisory_id = raw.get("id", "")
    if not advisory_id:
        return None
    affected = raw.get("affected") or []
    if not affected:
        return None

    summary = (raw.get("summary") or "")[:500]
    details = (raw.get("details") or "")[:2000]
    text = summary + "\n" + details
    code_ind, net_ind = _extract_indicators(text)
    attack_type = _classify(raw)
    refs = [r.get("url") for r in (raw.get("references") or []) if r.get("url")][:10]

    # 우리는 supply-chain 관련만 적재
    if attack_type not in ("malicious_package", "typosquatting",
                           "dependency_confusion", "slopsquatting"):
        return None

    out = []
    for a in affected:
        p = a.get("package") or {}
        name = p.get("name")
        if not name:
            continue
        # 영향 버전 모음
        versions: set[str] = set()
        for v in (a.get("versions") or []):
            versions.add(v)
        for r in (a.get("ranges") or []):
            for ev in (r.get("events") or []):
                for k, val in ev.items():
                    if k in ("introduced", "fixed", "limit") and val and val != "0":
                        versions.add(val)
        version_glob = ",".join(sorted(versions))[:300] if versions else "*"

        out.append({
            "advisory_id": advisory_id,
            "ecosystem": ecosystem,
            "package": name,
            "version_glob": version_glob,
            "attack_type": attack_type,
            "source": "OSV",
            "summary": summary,
            "code_indicators": json.dumps(code_ind, ensure_ascii=False),
            "network_indicators": json.dumps(net_ind, ensure_ascii=False),
            "references_": json.dumps(refs, ensure_ascii=False),
            "published": raw.get("published", ""),
            "modified": raw.get("modified", ""),
        })
    return out if out else None


# ─────────────── DB 적재 ───────────────

_INSERT_SQL = """
INSERT INTO known_malicious (
    advisory_id, ecosystem, package, version_glob, attack_type, source,
    summary, code_indicators, network_indicators, references_,
    published, modified
) VALUES (
    :advisory_id, :ecosystem, :package, :version_glob, :attack_type, :source,
    :summary, :code_indicators, :network_indicators, :references_,
    :published, :modified
)
ON CONFLICT(advisory_id, ecosystem, package) DO UPDATE SET
    version_glob       = excluded.version_glob,
    attack_type        = excluded.attack_type,
    source             = excluded.source,
    summary            = excluded.summary,
    code_indicators    = excluded.code_indicators,
    network_indicators = excluded.network_indicators,
    references_        = excluded.references_,
    modified           = excluded.modified
"""


def _upsert_rows(db: ThreatDB, rows: list[dict]) -> int:
    if not rows:
        return 0
    with db.cursor() as cur:
        cur.executemany(_INSERT_SQL, rows)
        return cur.rowcount


def _record_feed_meta(
    db: ThreatDB,
    *,
    source: str,
    record_count: int,
    fetch_sha256: str,
    error: str | None = None,
) -> str:
    feed_version = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
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
        """, (source, record_count, fetch_sha256, feed_version, error))
    return feed_version


# ─────────────── 공개 API ───────────────

def ingest_osv(
    ecosystem: str = "PyPI",
    *,
    db: ThreatDB | None = None,
    limit: int | None = None,
    skip_if_unchanged: bool = True,
) -> dict:
    """OSV 덤프 1개를 받아 DB 에 upsert.

    skip_if_unchanged=True 면 직전 회 fetch_sha256 과 동일하면 스킵.
    """
    if ecosystem not in OSV_URLS:
        raise ValueError(f"unsupported ecosystem: {ecosystem}")
    db = db or get_default_db()
    source_key = f"osv-{ecosystem.lower()}"
    t0 = time.time()

    try:
        body, sha = _download_with_sha256(OSV_URLS[ecosystem])
    except Exception as e:
        _record_feed_meta(db, source=source_key, record_count=0,
                          fetch_sha256="", error=f"download failed: {e}")
        return {"ok": False, "ecosystem": ecosystem, "error": str(e)}

    # 변경 없으면 skip
    if skip_if_unchanged:
        with db.cursor() as cur:
            cur.execute(
                "SELECT fetch_sha256, record_count FROM feed_meta WHERE source=?",
                (source_key,),
            )
            row = cur.fetchone()
            if row and row[0] == sha:
                print(f"[OSV] {ecosystem}: unchanged (sha {sha[:12]}..), skip")
                return {
                    "ok": True, "ecosystem": ecosystem, "skipped": True,
                    "record_count": row[1],
                }

    # zip 파싱 -> rows
    rows: list[dict] = []
    parsed_advisories = 0
    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        for n in names:
            try:
                raw = json.loads(zf.read(n))
            except Exception:
                continue
            parsed = _parse_one(raw, ecosystem)
            if not parsed:
                continue
            rows.extend(parsed)
            parsed_advisories += 1
            if limit and len(rows) >= limit:
                break

    print(f"[OSV] {ecosystem}: parsed {parsed_advisories} advisories -> {len(rows)} rows")

    # DB upsert (큰 배치는 분할)
    BATCH = 1000
    total = 0
    for i in range(0, len(rows), BATCH):
        batch = rows[i:i + BATCH]
        total += _upsert_rows(db, batch)

    feed_version = _record_feed_meta(
        db, source=source_key, record_count=len(rows), fetch_sha256=sha,
    )

    print(f"[OSV] {ecosystem}: upserted {total} rows, "
          f"feed_version={feed_version}, took {time.time()-t0:.1f}s")
    return {
        "ok": True, "ecosystem": ecosystem,
        "advisories": parsed_advisories, "rows": len(rows),
        "fetch_sha256": sha, "feed_version": feed_version,
    }


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse
    import sys

    p = argparse.ArgumentParser(description="OSV feed ingester")
    p.add_argument("--ecosystem", choices=["PyPI", "npm", "all"], default="PyPI")
    p.add_argument("--limit", type=int, default=None,
                   help="개발용 — N 행만 적재")
    p.add_argument("--passphrase", default=None)
    p.add_argument("--no-skip", action="store_true",
                   help="동일 sha256 이어도 강제 재적재")
    args = p.parse_args()

    if args.passphrase:
        from ..db.threat_db import DEFAULT_DB_PATH, ThreatDB
        db = ThreatDB(DEFAULT_DB_PATH, passphrase=args.passphrase)
    else:
        db = None  # env/keyfile 사용

    targets = ["PyPI", "npm"] if args.ecosystem == "all" else [args.ecosystem]
    overall_ok = True
    for eco in targets:
        r = ingest_osv(eco, db=db, limit=args.limit,
                       skip_if_unchanged=not args.no_skip)
        if not r.get("ok"):
            overall_ok = False
            print(f"FAIL {eco}: {r.get('error')}", file=sys.stderr)
    sys.exit(0 if overall_ok else 1)
