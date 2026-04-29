"""
Stage-level 분석 캐시.

기존 `AnalysisCache` 가 전체 report 한 덩어리를 캐싱했다면, 본 모듈은 단계별
결과를 따로 저장 / 조회 / 무효화한다. 의존 컴포넌트가 변경된 stage 만
선택적으로 재실행하기 위함.

지원 stage 와 의존성 (stage_version 해시 입력):
    stage_2_behavior         pkgsentinel.stages.api_catalog
                             pkgsentinel.stages.stage2_behavior
    stage_2b_string          pkgsentinel.stages.string_analysis
    stage_3b_version_diff    pkgsentinel.stages.stage3b_full_diff
                             pkgsentinel.stages.stage1b_full_source
    stage_4_ttp              pkgsentinel.stages.stage4_ttp_match
                             pkgsentinel.knowledge.mitre_attack
    stage_4c_ind47           pkgsentinel.stages.indicator_matcher
                             pkgsentinel.knowledge.malicious_indicators
    stage_4d_taint           pkgsentinel.stages.taint_slicer
    stage_4e_sequence        pkgsentinel.stages.sequence_patterns
    stage_0a_threat_filter   feed_version (DB)
    stage_0b_attack_history  feed_version (DB)

Stage 5 (LLM review) 는 원리상 캐시하지 않음 — 동일 입력에도 모델이 다른 응답을
줄 수 있고, 재현 불가능한 응답을 캐시하면 디버깅이 어려움.

설계 원칙:
- 기존 `AnalysisCache` 와 공존. report 전체 캐시는 그대로.
- 본 캐시는 Stage 결과를 byte-string 단위로 저장 (json.dumps 직렬화).
- archive_sha256 가 변경되면 모든 stage_cache 행 강제 무효 (자동 트리거 X — Python 측에서 검증).
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .threat_db import ThreatDB, get_default_db


# ─────────────── Stage 별 의존 모듈 매핑 ───────────────
# 각 stage 가 의존하는 모듈 이름 → 해당 모듈들의 source code 합산 sha256.
# 모듈 한 줄만 바뀌어도 stage_version 이 달라져 캐시 미스.

_STAGE_DEPS: dict[str, tuple[str, ...]] = {
    "stage_2_behavior": (
        "pkgsentinel.stages.api_catalog",
        "pkgsentinel.stages.stage2_behavior",
    ),
    "stage_2b_string": (
        "pkgsentinel.stages.string_analysis",
    ),
    "stage_3b_version_diff": (
        "pkgsentinel.stages.stage3b_full_diff",
        "pkgsentinel.stages.stage1b_full_source",
    ),
    "stage_4_ttp": (
        "pkgsentinel.stages.stage4_ttp_match",
        "pkgsentinel.knowledge.mitre_attack",
    ),
    "stage_4c_ind47": (
        "pkgsentinel.stages.indicator_matcher",
        "pkgsentinel.knowledge.malicious_indicators",
    ),
    "stage_4d_taint": (
        "pkgsentinel.stages.taint_slicer",
    ),
    "stage_4e_sequence": (
        "pkgsentinel.stages.sequence_patterns",
    ),
    # threat_filter / attack_history 는 모듈 + DB 의 feed_version 둘 다 의존
    "stage_0a_threat_filter": (
        "pkgsentinel.stages.stage0_threat_filter",
    ),
    "stage_0b_attack_history": (
        "pkgsentinel.stages.stage0b_attack_history",
    ),
}


def _module_files_hash(module_names: tuple[str, ...]) -> str:
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


def stage_version_for(stage: str, feed_version: str | None = None) -> str:
    """주어진 stage 의 현재 의존성 해시.

    threat_filter / attack_history 는 feed_version 도 입력에 포함.
    """
    deps = _STAGE_DEPS.get(stage)
    if not deps:
        # 정의되지 않은 stage 는 stage 이름을 hash 화 (캐시 사실상 disabled)
        return hashlib.sha256(stage.encode()).hexdigest()[:16]
    base = _module_files_hash(deps)
    if stage in ("stage_0a_threat_filter", "stage_0b_attack_history") and feed_version:
        h = hashlib.sha256(f"{base}|{feed_version}".encode()).hexdigest()[:16]
        return h
    return base


def all_supported_stages() -> list[str]:
    return sorted(_STAGE_DEPS.keys())


# ─────────────── 결과 객체 ───────────────

@dataclass
class StageCacheKey:
    package: str
    ecosystem: str
    version: str
    stage: str

    def stage_version(self, feed_version: str | None = None) -> str:
        return stage_version_for(self.stage, feed_version=feed_version)


@dataclass
class StageCacheHit:
    hit: bool
    reason: str
    payload: Any | None = None
    cached_at: str | None = None
    stage_version: str | None = None

    def __bool__(self):
        return self.hit


# ─────────────── 메인 클래스 ───────────────

class StageCache:
    """단계별 분석 결과 캐시 — get / put / invalidate.

    원자성: 본 클래스의 메서드들은 스레드-안전하지만 트랜잭션을 직접 다루지는
    않음. 호출 측에서 ThreadDB 의 cursor() 컨텍스트로 묶고 싶으면
    아래 raw API (`get_raw`, `put_raw`) 를 사용하면 됨.
    """

    def __init__(self, db: ThreatDB | None = None):
        self.db = db or get_default_db()

    # ───── public ─────

    def get(
        self,
        key: StageCacheKey,
        archive_sha256: str | None = None,
        feed_version: str | None = None,
    ) -> StageCacheHit:
        """캐시 hit 시 payload(역직렬화된 객체) 반환, miss 면 hit=False.

        archive_sha256 가 주어지면 캐시된 행의 archive_sha256 와 일치 확인.
        불일치 시 miss (서로 다른 archive 에 대한 stage 결과는 호환 불가).
        """
        sv = key.stage_version(feed_version=feed_version)
        with self.db.cursor() as cur:
            cur.execute("""
                SELECT payload_json, archive_sha256, cached_at
                FROM stage_cache
                WHERE package=? AND ecosystem=? AND version=?
                  AND stage=? AND stage_version=?
            """, (key.package, key.ecosystem, key.version, key.stage, sv))
            row = cur.fetchone()
        if not row:
            return StageCacheHit(False, "miss: no cached row", stage_version=sv)
        payload_json, cached_archive, cached_at = row
        if (
            archive_sha256 is not None
            and cached_archive
            and cached_archive != archive_sha256
        ):
            return StageCacheHit(
                False, "archive sha256 mismatch", stage_version=sv,
                cached_at=cached_at,
            )
        try:
            payload = json.loads(payload_json)
        except Exception as e:
            return StageCacheHit(
                False, f"corrupt payload json: {e}", stage_version=sv,
            )
        return StageCacheHit(
            True, "ok", payload=payload, cached_at=cached_at, stage_version=sv,
        )

    def put(
        self,
        key: StageCacheKey,
        payload: Any,
        archive_sha256: str | None = None,
        feed_version: str | None = None,
    ) -> dict:
        """Stage 결과 저장 (payload 는 JSON-직렬화 가능해야 함)."""
        sv = key.stage_version(feed_version=feed_version)
        try:
            payload_json = json.dumps(payload, ensure_ascii=False, default=str)
        except Exception as e:
            return {"stored": False, "error": f"non-serializable payload: {e}"}
        row = {
            "package": key.package,
            "ecosystem": key.ecosystem,
            "version": key.version,
            "stage": key.stage,
            "stage_version": sv,
            "archive_sha256": archive_sha256,
            "payload_json": payload_json,
        }
        with self.db.cursor() as cur:
            cur.execute("""
                INSERT INTO stage_cache (
                    package, ecosystem, version,
                    stage, stage_version,
                    archive_sha256, payload_json
                )
                VALUES (
                    :package, :ecosystem, :version,
                    :stage, :stage_version,
                    :archive_sha256, :payload_json
                )
                ON CONFLICT(package, ecosystem, version, stage, stage_version)
                DO UPDATE SET
                    archive_sha256 = excluded.archive_sha256,
                    payload_json   = excluded.payload_json,
                    cached_at      = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            """, row)
        return {
            "stored": True,
            "stage": key.stage,
            "stage_version": sv,
        }

    def invalidate(
        self,
        key: StageCacheKey | None = None,
        package: str | None = None,
        ecosystem: str | None = None,
        version: str | None = None,
        stage: str | None = None,
    ) -> int:
        """선택적 무효화. key 또는 (package, ecosystem, version, stage) 조합.

        반환: 삭제된 행 수.
        """
        if key:
            package = key.package
            ecosystem = key.ecosystem
            version = key.version
            stage = key.stage
        clauses = []
        params: list = []
        if package:
            clauses.append("package = ?")
            params.append(package)
        if ecosystem:
            clauses.append("ecosystem = ?")
            params.append(ecosystem)
        if version:
            clauses.append("version = ?")
            params.append(version)
        if stage:
            clauses.append("stage = ?")
            params.append(stage)
        if not clauses:
            raise ValueError(
                "invalidate requires at least one of "
                "(key | package | ecosystem | version | stage)"
            )
        sql = "DELETE FROM stage_cache WHERE " + " AND ".join(clauses)
        with self.db.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount

    def stats(self) -> dict:
        """간이 통계."""
        with self.db.cursor() as cur:
            cur.execute("SELECT count(*) FROM stage_cache")
            total = cur.fetchone()[0]
            cur.execute("""
                SELECT stage, count(*) FROM stage_cache GROUP BY stage
            """)
            by_stage = {r[0]: r[1] for r in cur.fetchall()}
        return {
            "total": total,
            "by_stage": by_stage,
            "supported_stages": all_supported_stages(),
        }


# ─────────────── CLI 자체 검증 ───────────────

if __name__ == "__main__":
    sc = StageCache()
    pkg, eco, ver = "selftest", "PyPI", "0.0.1"
    keys = [
        StageCacheKey(pkg, eco, ver, s) for s in all_supported_stages()
    ]

    # miss
    h = sc.get(keys[0])
    print(f"[miss?]   stage={keys[0].stage} hit={h.hit} reason={h.reason}")

    # put
    info = sc.put(keys[0], {"foo": [1, 2, 3], "n": 42})
    print(f"[put]     {info}")

    # hit
    h = sc.get(keys[0])
    print(f"[hit?]    hit={h.hit} payload={h.payload}")

    # archive mismatch → miss
    info = sc.put(keys[1], {"x": "y"}, archive_sha256="aaa")
    h = sc.get(keys[1], archive_sha256="bbb")
    print(f"[arch x?] hit={h.hit} reason={h.reason}")
    h = sc.get(keys[1], archive_sha256="aaa")
    print(f"[arch ok] hit={h.hit}")

    # invalidate stage 단위
    deleted = sc.invalidate(package=pkg, stage=keys[0].stage)
    print(f"[inv]     stage='{keys[0].stage}' deleted={deleted}")
    h = sc.get(keys[0])
    print(f"[miss2?]  hit={h.hit} reason={h.reason}")

    print(f"\n[stats]   {sc.stats()}")
