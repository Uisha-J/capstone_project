"""
분석 결과 캐시 — 6-트리거 무효화.

캐시 hit 조건 (모두 만족):
  1. engine_version 일치
  2. rules_version  일치 (47 indicators / sequence_patterns / api_catalog hash)
  3. kb_version     일치 (MITRE/ATLAS/OWASP 인덱스 hash)
  4. integrity_mode 가 현재 요청 모드와 같거나 더 강함
  5. archive 무결성 검증 (mode 별):
       fast      : ETag/Content-Length 동일
       strict    : archive sha256 동일 (자체 계산)
       paranoid  : archive sha256 + Merkle root + row HMAC 동일
  6. 그 패키지에 cache_invalidation_log 레코드가 캐시 시점 이후 없을 것

이 6번이 트리거 핵심: known_malicious 에 새 advisory 가 들어오는 순간
SQL trigger 가 cache_invalidation_log 에 기록 → 다음 cache.get 시 자동 무효.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from . import master_key as mk
from .integrity import (
    Fingerprint,
    IntegrityChecker,
    IntegrityMode,
    RowHMAC,
)
from .threat_db import ThreatDB, get_default_db

# ─────────────── 버전 해시 헬퍼 ───────────────

# 엔진 자체 버전. detector/__init__.py 에 박을 수도 있지만 여기 단일소스.
ENGINE_VERSION = "2.0.0"


def _hash_module_set(module_names: list[str]) -> str:
    """주어진 모듈들의 source 코드 sha256 합 → 한 hash 로.
    이걸로 rules_version / kb_version 구함.
    """
    h = hashlib.sha256()
    for name in sorted(module_names):
        try:
            mod = __import__(name, fromlist=["*"])
            src = getattr(mod, "__file__", None)
            if src:
                with open(src, "rb") as f:
                    h.update(f.read())
        except Exception:
            h.update(name.encode("utf-8"))
    return h.hexdigest()[:16]


def get_rules_version() -> str:
    """탐지 규칙 모듈들의 hash."""
    return _hash_module_set([
        "pkgsentinel.knowledge.malicious_indicators",
        "pkgsentinel.stages.indicator_matcher",
        "pkgsentinel.stages.sequence_patterns",
        "pkgsentinel.stages.api_catalog",
        "pkgsentinel.stages.taint_slicer",
    ])


def get_kb_version() -> str:
    """지식베이스 (TTP/ATLAS/OWASP) hash."""
    return _hash_module_set([
        "pkgsentinel.knowledge.mitre_attack",
        "pkgsentinel.knowledge.mitre_atlas",
        "pkgsentinel.knowledge.owasp_llm",
    ])


def get_feed_version(db: ThreatDB) -> str:
    """현재 적재된 위협 피드들의 합산 feed_version."""
    with db.cursor() as cur:
        cur.execute("SELECT source, feed_version FROM feed_meta ORDER BY source")
        parts = [f"{r[0]}={r[1] or ''}" for r in cur.fetchall()]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# ─────────────── 캐시 키 ───────────────

@dataclass
class CacheKey:
    package: str
    ecosystem: str
    version: str
    engine_version: str = ENGINE_VERSION


# ─────────────── 캐시 hit 결과 ───────────────

@dataclass
class CacheHit:
    hit: bool
    reason: str
    report: dict | None = None
    cache_row: dict | None = None
    invalidation: list[str] = field(default_factory=list)

    def __bool__(self):
        return self.hit


# ─────────────── 메인 클래스 ───────────────

class AnalysisCache:
    DEFAULT_TTL_DAYS = 7

    def __init__(
        self,
        db: ThreatDB | None = None,
        *,
        integrity_mode: IntegrityMode = IntegrityMode.STRICT,
        ttl_days: int = DEFAULT_TTL_DAYS,
    ):
        self.db = db or get_default_db()
        self.mode = integrity_mode
        self.ttl_days = ttl_days
        self.checker = IntegrityChecker(integrity_mode)
        self._row_hmac: RowHMAC | None = None

    # ─────────────── public ───────────────

    def get(
        self,
        key: CacheKey,
        archive_url: str | None = None,
    ) -> CacheHit:
        """캐시 hit 시 report dict 반환, miss 시 None.

        archive_url 이 있으면 무결성 검증까지 수행.
        없으면 무결성 검증 건너뛰고 다른 트리거로만 hit/miss 판단.
        """
        invalidations: list[str] = []

        row = self._fetch_row(key)
        if row is None:
            return CacheHit(False, "miss: no cache row")

        # 1. engine_version
        if row["engine_version"] != ENGINE_VERSION:
            return CacheHit(False, f"engine version changed "
                            f"({row['engine_version']} -> {ENGINE_VERSION})")

        # 2. rules_version
        cur_rules = get_rules_version()
        if row["rules_version"] != cur_rules:
            return CacheHit(False, f"rules version changed "
                            f"({row['rules_version'][:8]} -> {cur_rules[:8]})")

        # 3. kb_version
        cur_kb = get_kb_version()
        if row["kb_version"] != cur_kb:
            return CacheHit(False, f"kb version changed "
                            f"({row['kb_version'][:8]} -> {cur_kb[:8]})")

        # 4. integrity mode 강도
        cached_mode = IntegrityMode(row["integrity_mode"])
        rank = {IntegrityMode.FAST: 0, IntegrityMode.STRICT: 1,
                IntegrityMode.PARANOID: 2}
        if rank[cached_mode] < rank[self.mode]:
            return CacheHit(False, f"cache mode '{cached_mode.value}' "
                            f"weaker than current '{self.mode.value}'")

        # 5. TTL safeguard
        try:
            cached_at = datetime.fromisoformat(row["analyzed_at"].replace("Z", "+00:00"))
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=UTC)
        except Exception:
            cached_at = datetime.now(UTC) - timedelta(days=self.ttl_days * 2)
        age = datetime.now(UTC) - cached_at
        if age > timedelta(days=self.ttl_days):
            return CacheHit(False, f"TTL exceeded ({age.days}d > {self.ttl_days}d)")

        # 6. cache_invalidation_log: 패키지가 새 advisory 등 무효 신호 받았는가
        with self.db.cursor() as cur:
            cur.execute("""
                SELECT reason, invalidated_at
                FROM cache_invalidation_log
                WHERE ecosystem = ? AND package = ?
                  AND invalidated_at > ?
                ORDER BY invalidated_at DESC LIMIT 5
            """, (key.ecosystem, key.package, row["analyzed_at"]))
            invalidations = [{"reason": r[0], "at": r[1]} for r in cur.fetchall()]
        if invalidations:
            return CacheHit(
                False,
                f"invalidated by feed update: {invalidations[0]['reason']}",
                invalidation=[i["reason"] for i in invalidations],
            )

        # 7. archive 무결성 (URL 주어진 경우)
        if archive_url:
            try:
                fresh_fp = self.checker.fingerprint(archive_url)
            except Exception as e:
                return CacheHit(False, f"integrity check failed: {e}")

            cached_fp = self._row_to_fingerprint(row, archive_url)
            ok, why = self.checker.matches(cached_fp, fresh_fp)
            if not ok:
                return CacheHit(False, f"integrity mismatch: {why}")

        # 8. paranoid: row HMAC 재검증
        if self.mode == IntegrityMode.PARANOID and row.get("row_hmac"):
            rh = self._get_row_hmac()
            # HMAC 계산 시 row_hmac, analyzed_at 모두 제외
            #   analyzed_at 은 DB DEFAULT 로 PUT 시 채워지므로 PUT 시점의
            #   row dict 에는 없었음 → 검증할 때도 빼야 mismatch 안 남
            excluded = {"row_hmac", "analyzed_at"}
            row_for_hmac = {k: v for k, v in row.items() if k not in excluded}
            if not rh.verify(row_for_hmac, row["row_hmac"]):
                # row 변조 의심 — 캐시 invalidate + 로그
                self._log_tamper(key, "row HMAC mismatch")
                return CacheHit(False, "row HMAC mismatch (tamper suspected)")

        # ALL OK
        try:
            report = json.loads(row["report_json"])
        except Exception as e:
            return CacheHit(False, f"corrupt report json: {e}")

        return CacheHit(
            True, "all checks passed", report=report, cache_row=row,
            invalidation=invalidations,
        )

    def put(
        self,
        key: CacheKey,
        report_dict: dict,
        archive_url: str | None = None,
        verdict: str | None = None,
    ) -> dict:
        """분석 결과 + 무결성 지문 저장."""
        if verdict is None:
            verdict = report_dict.get("verdict", "ERROR")

        # 무결성 지문 (archive_url 있는 경우만)
        archive_sha256 = None
        merkle_root = None
        if archive_url:
            try:
                fp = self.checker.fingerprint(archive_url)
                archive_sha256 = fp.archive_sha256
                merkle_root = fp.merkle_root
            except Exception as e:
                # 무결성 계산 실패해도 캐시 저장은 진행 (mode 가 fast 면 정상)
                if self.mode != IntegrityMode.FAST:
                    print(f"[cache.put] integrity fingerprint failed: {e}")

        feed_v = get_feed_version(self.db)
        rules_v = get_rules_version()
        kb_v = get_kb_version()

        # analyzed_at 은 DB 의 strftime DEFAULT 가 채움 (트리거와 형식 일치).
        row = {
            "package": key.package,
            "ecosystem": key.ecosystem,
            "version": key.version,
            "engine_version": ENGINE_VERSION,
            "rules_version": rules_v,
            "kb_version": kb_v,
            "feed_version": feed_v,
            "archive_sha256": archive_sha256,
            "merkle_root": merkle_root,
            "row_hmac": None,
            "integrity_mode": self.mode.value,
            "verdict": verdict,
            "report_json": json.dumps(report_dict, ensure_ascii=False, default=str),
        }

        # paranoid: row HMAC 추가 (analyzed_at 은 빠진 채로 계산)
        if self.mode == IntegrityMode.PARANOID:
            rh = self._get_row_hmac()
            row["row_hmac"] = rh.compute(row)

        with self.db.cursor() as cur:
            cur.execute("""
                INSERT INTO analyses (
                    package, ecosystem, version, engine_version,
                    rules_version, kb_version, feed_version,
                    archive_sha256, merkle_root, row_hmac, integrity_mode,
                    verdict, report_json
                ) VALUES (
                    :package, :ecosystem, :version, :engine_version,
                    :rules_version, :kb_version, :feed_version,
                    :archive_sha256, :merkle_root, :row_hmac, :integrity_mode,
                    :verdict, :report_json
                )
                ON CONFLICT(package, ecosystem, version, engine_version)
                DO UPDATE SET
                    rules_version  = excluded.rules_version,
                    kb_version     = excluded.kb_version,
                    feed_version   = excluded.feed_version,
                    archive_sha256 = excluded.archive_sha256,
                    merkle_root    = excluded.merkle_root,
                    row_hmac       = excluded.row_hmac,
                    integrity_mode = excluded.integrity_mode,
                    verdict        = excluded.verdict,
                    report_json    = excluded.report_json,
                    analyzed_at    = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            """, row)

        return {
            "stored": True,
            "rules_version": rules_v[:8],
            "kb_version": kb_v[:8],
            "feed_version": feed_v[:8],
            "archive_sha256": archive_sha256[:12] if archive_sha256 else None,
            "merkle_root": merkle_root[:12] if merkle_root else None,
        }

    def invalidate(self, key: CacheKey, reason: str = "manual") -> bool:
        with self.db.cursor() as cur:
            cur.execute("""
                DELETE FROM analyses
                WHERE package=? AND ecosystem=? AND version=? AND engine_version=?
            """, (key.package, key.ecosystem, key.version, key.engine_version))
            removed = cur.rowcount
            cur.execute("""
                INSERT INTO cache_invalidation_log
                    (ecosystem, package, invalidated_at, reason)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?)
            """, (key.ecosystem, key.package, f"manual: {reason}"))
        return removed > 0

    def stats(self) -> dict:
        with self.db.cursor() as cur:
            cur.execute("SELECT count(*) FROM analyses")
            total = cur.fetchone()[0]
            cur.execute("""
                SELECT verdict, count(*) FROM analyses GROUP BY verdict
            """)
            by_verdict = {r[0]: r[1] for r in cur.fetchall()}
            cur.execute("""
                SELECT integrity_mode, count(*) FROM analyses GROUP BY integrity_mode
            """)
            by_mode = {r[0]: r[1] for r in cur.fetchall()}
        return {"total": total, "by_verdict": by_verdict, "by_mode": by_mode}

    # ─────────────── internal ───────────────

    def _fetch_row(self, key: CacheKey) -> dict | None:
        with self.db.cursor() as cur:
            cur.execute("""
                SELECT package, ecosystem, version, engine_version,
                       rules_version, kb_version, feed_version,
                       archive_sha256, merkle_root, row_hmac, integrity_mode,
                       verdict, report_json, analyzed_at
                FROM analyses
                WHERE package=? AND ecosystem=? AND version=? AND engine_version=?
            """, (key.package, key.ecosystem, key.version, key.engine_version))
            r = cur.fetchone()
            if not r:
                return None
            return {
                "package": r[0], "ecosystem": r[1], "version": r[2],
                "engine_version": r[3], "rules_version": r[4],
                "kb_version": r[5], "feed_version": r[6],
                "archive_sha256": r[7], "merkle_root": r[8],
                "row_hmac": r[9], "integrity_mode": r[10],
                "verdict": r[11], "report_json": r[12],
                "analyzed_at": r[13],
            }

    def _row_to_fingerprint(self, row: dict, archive_url: str) -> Fingerprint:
        return Fingerprint(
            mode=IntegrityMode(row["integrity_mode"]),
            archive_url=archive_url,
            archive_sha256=row.get("archive_sha256"),
            merkle_root=row.get("merkle_root"),
        )

    def _get_row_hmac(self) -> RowHMAC:
        if self._row_hmac is None:
            passphrase = mk.resolve_passphrase()
            if not passphrase:
                raise RuntimeError("row HMAC requires master passphrase")
            self._row_hmac = RowHMAC.from_passphrase(passphrase)
        return self._row_hmac

    def _log_tamper(self, key: CacheKey, reason: str):
        with self.db.cursor() as cur:
            cur.execute("""
                INSERT INTO cache_invalidation_log
                    (ecosystem, package, invalidated_at, reason)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?)
            """, (key.ecosystem, key.package, f"TAMPER: {reason}"))


# ─────────────── CLI 자체 검증 ───────────────

if __name__ == "__main__":
    # archive_url 없이 동작 확인 (무결성은 별도 테스트로)

    db = get_default_db()
    cache = AnalysisCache(db, integrity_mode=IntegrityMode.STRICT)

    key = CacheKey(package="test-pkg", ecosystem="PyPI", version="0.0.1")
    report = {
        "verdict": "CLEAN",
        "package": "test-pkg",
        "version": "0.0.1",
        "evidence": [],
    }

    # miss
    h = cache.get(key)
    print(f"[miss?]  hit={h.hit}, reason={h.reason}")

    # put
    info = cache.put(key, report, verdict="CLEAN")
    print(f"[put]    {info}")

    # hit (no archive url → 무결성 검증 skip, 다른 트리거만)
    h = cache.get(key)
    print(f"[hit?]   hit={h.hit}, reason={h.reason}")

    # invalidate manually
    removed = cache.invalidate(key, reason="self-test")
    print(f"[inval]  removed={removed}")

    h = cache.get(key)
    print(f"[miss2?] hit={h.hit}, reason={h.reason}")

    print(f"\n[stats]  {cache.stats()}")
