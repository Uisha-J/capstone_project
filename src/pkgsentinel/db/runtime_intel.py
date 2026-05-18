"""Runtime threat intel feedback loop — schema + Store.

차단된 공격에서 추출한 IOC + 패턴을 누적 저장 → 다음 분석에 활용.

3 테이블:
  - runtime_observations: 원시 alert + 추출 결과
  - learned_iocs:         정규화된 IOC (ip / domain / sha256 / path / syscall_chain)
  - learned_rules:        auto-generated detection rule draft

row HMAC 패턴은 ThreatDB 의 기존 무결성 모델 (RowHMAC) 과 같은 사상이지만
본 모듈은 *작은 fast-path* 라 HMAC 컬럼은 선택적. INSERT 후 별도 채워도 됨.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from .threat_db import ThreatDB, get_default_db

# ─────────────── 스키마 ───────────────

_SCHEMA = r"""
CREATE TABLE IF NOT EXISTS runtime_observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at     TEXT NOT NULL,
    source          TEXT NOT NULL,                    -- 'falco' | 'tetragon' | 'wazuh' | 'manual'
    host            TEXT,
    package         TEXT,
    ecosystem       TEXT,
    version         TEXT,
    raw_event       TEXT NOT NULL,                    -- 원본 JSON 페이로드
    extracted_iocs  TEXT,                             -- JSON [{type, value, confidence}, ...]
    extracted_pattern TEXT,                           -- JSON {indicators, dims, summary}
    verdict_before  TEXT,
    verdict_after   TEXT,
    mitigation      TEXT,                             -- 'killed' | 'blocked' | 'alerted'
    row_hmac        TEXT
);

CREATE INDEX IF NOT EXISTS idx_obs_pkg ON runtime_observations(package, ecosystem, version);
CREATE INDEX IF NOT EXISTS idx_obs_recv ON runtime_observations(received_at);

CREATE TABLE IF NOT EXISTS learned_iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type        TEXT NOT NULL,                    -- 'ip' | 'domain' | 'sha256' | 'path' | 'syscall_chain'
    value           TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.0,
    observation_count INTEGER NOT NULL DEFAULT 1,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    associated_packages TEXT NOT NULL DEFAULT '[]',   -- JSON ["pkg@ver", ...]
    source_observation_ids TEXT NOT NULL DEFAULT '[]',-- JSON [id, id, ...]
    status          TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'approved' | 'retired'
    notes           TEXT,
    row_hmac        TEXT,
    UNIQUE(ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_ioc_type_val ON learned_iocs(ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_status ON learned_iocs(status, confidence);

CREATE TABLE IF NOT EXISTS learned_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_kind       TEXT NOT NULL,                    -- 'indicator_47' | 'falco' | 'sequence_pattern' | 'aislopsq_r'
    rule_body       TEXT NOT NULL,                    -- YAML / regex / JSON body
    source_observation_ids TEXT NOT NULL DEFAULT '[]',
    confidence      REAL NOT NULL DEFAULT 0.0,
    status          TEXT NOT NULL DEFAULT 'draft',    -- 'draft' | 'approved' | 'deployed' | 'retired'
    created_at      TEXT NOT NULL,
    approved_at     TEXT,
    approved_by     TEXT,
    rationale       TEXT,
    row_hmac        TEXT
);

CREATE INDEX IF NOT EXISTS idx_rule_status ON learned_rules(status, rule_kind);
"""


def _ensure_schema(db: ThreatDB) -> None:
    with db.cursor() as cur:
        cur.executescript(_SCHEMA)


# ─────────────── 데이터 클래스 ───────────────

@dataclass
class RuntimeObservation:
    received_at: str
    source: str                              # 'falco' / 'tetragon' / 'wazuh' / 'manual'
    raw_event: dict
    host: str | None = None
    package: str | None = None
    ecosystem: str | None = None
    version: str | None = None
    extracted_iocs: list[dict] = field(default_factory=list)
    extracted_pattern: dict | None = None
    verdict_before: str | None = None
    verdict_after: str | None = None
    mitigation: str | None = None
    id: int | None = None


@dataclass
class LearnedIOC:
    ioc_type: str            # 'ip' / 'domain' / 'sha256' / 'path' / 'syscall_chain'
    value: str
    confidence: float = 0.0
    observation_count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    associated_packages: list[str] = field(default_factory=list)
    source_observation_ids: list[int] = field(default_factory=list)
    status: str = "pending"
    notes: str | None = None
    id: int | None = None


@dataclass
class LearnedRule:
    rule_kind: str           # 'indicator_47' / 'falco' / 'sequence_pattern' / 'aislopsq_r'
    rule_body: str           # YAML / regex / JSON
    source_observation_ids: list[int] = field(default_factory=list)
    confidence: float = 0.0
    status: str = "draft"
    created_at: str = ""
    approved_at: str | None = None
    approved_by: str | None = None
    rationale: str | None = None
    id: int | None = None


# ─────────────── Store ───────────────

class RuntimeIntelStore:
    """Runtime intel feedback loop 의 영속 저장소.

    스레드 안전 (ThreatDB 의 thread-local 연결 + commit per cursor).
    """

    def __init__(self, db: ThreatDB | None = None):
        self.db = db or get_default_db()
        _ensure_schema(self.db)

    # ───── observation ─────

    def record_observation(self, obs: RuntimeObservation) -> int:
        ts = obs.received_at or _now()
        with self.db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO runtime_observations (
                    received_at, source, host,
                    package, ecosystem, version,
                    raw_event, extracted_iocs, extracted_pattern,
                    verdict_before, verdict_after, mitigation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts, obs.source, obs.host,
                    obs.package, obs.ecosystem, obs.version,
                    json.dumps(obs.raw_event, ensure_ascii=False),
                    json.dumps(obs.extracted_iocs, ensure_ascii=False),
                    json.dumps(obs.extracted_pattern, ensure_ascii=False)
                    if obs.extracted_pattern else None,
                    obs.verdict_before, obs.verdict_after, obs.mitigation,
                ),
            )
            obs_id = cur.lastrowid
        obs.id = obs_id
        return obs_id

    def update_verdict_after(self, observation_id: int, verdict: str) -> None:
        with self.db.cursor() as cur:
            cur.execute(
                "UPDATE runtime_observations SET verdict_after=? WHERE id=?",
                (verdict, observation_id),
            )

    def get_observation(self, observation_id: int) -> RuntimeObservation | None:
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT id, received_at, source, host, package, ecosystem, "
                "version, raw_event, extracted_iocs, extracted_pattern, "
                "verdict_before, verdict_after, mitigation "
                "FROM runtime_observations WHERE id=?",
                (observation_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return _row_to_observation(row)

    def list_observations(
        self, *, package: str | None = None, limit: int = 100,
    ) -> list[RuntimeObservation]:
        q = "SELECT id, received_at, source, host, package, ecosystem, " \
            "version, raw_event, extracted_iocs, extracted_pattern, " \
            "verdict_before, verdict_after, mitigation FROM runtime_observations"
        params: list[Any] = []
        if package:
            q += " WHERE package=?"
            params.append(package)
        q += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        with self.db.cursor() as cur:
            cur.execute(q, params)
            rows = cur.fetchall()
        return [_row_to_observation(r) for r in rows]

    # ───── IOC ─────

    def upsert_ioc(
        self,
        ioc: LearnedIOC,
        *,
        observation_id: int | None = None,
        package_at_version: str | None = None,
    ) -> int:
        """이미 존재하는 IOC 면 observation_count+1, 동일 obs 가 아닌 경우 누적.

        반환: IOC row id.
        """
        ts = _now()
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT id, confidence, observation_count, "
                "associated_packages, source_observation_ids, first_seen "
                "FROM learned_iocs WHERE ioc_type=? AND value=?",
                (ioc.ioc_type, ioc.value),
            )
            row = cur.fetchone()

            if row:
                existing_id = row[0]
                conf = row[1]
                count = row[2]
                packages = json.loads(row[3] or "[]")
                obs_ids = json.loads(row[4] or "[]")
                first_seen = row[5]

                if observation_id is not None and observation_id not in obs_ids:
                    obs_ids.append(observation_id)
                    count += 1
                if package_at_version and package_at_version not in packages:
                    packages.append(package_at_version)

                new_conf = _bump_confidence(conf, count, len(packages))

                cur.execute(
                    "UPDATE learned_iocs SET "
                    "confidence=?, observation_count=?, last_seen=?, "
                    "associated_packages=?, source_observation_ids=? "
                    "WHERE id=?",
                    (
                        new_conf, count, ts,
                        json.dumps(packages, ensure_ascii=False),
                        json.dumps(obs_ids, ensure_ascii=False),
                        existing_id,
                    ),
                )
                ioc.id = existing_id
                ioc.confidence = new_conf
                ioc.observation_count = count
                ioc.associated_packages = packages
                ioc.source_observation_ids = obs_ids
                ioc.first_seen = first_seen
                ioc.last_seen = ts
                return existing_id

            # 신규
            first_seen = ioc.first_seen or ts
            obs_ids = list(ioc.source_observation_ids)
            if observation_id is not None and observation_id not in obs_ids:
                obs_ids.append(observation_id)
            packages = list(ioc.associated_packages)
            if package_at_version and package_at_version not in packages:
                packages.append(package_at_version)
            initial_conf = max(ioc.confidence, 0.5)  # 첫 관측은 0.5 base

            cur.execute(
                "INSERT INTO learned_iocs (ioc_type, value, confidence, "
                "observation_count, first_seen, last_seen, "
                "associated_packages, source_observation_ids, status, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ioc.ioc_type, ioc.value, initial_conf,
                    ioc.observation_count, first_seen, ts,
                    json.dumps(packages, ensure_ascii=False),
                    json.dumps(obs_ids, ensure_ascii=False),
                    ioc.status, ioc.notes,
                ),
            )
            ioc.id = cur.lastrowid
            ioc.confidence = initial_conf
            ioc.first_seen = first_seen
            ioc.last_seen = ts
            ioc.associated_packages = packages
            ioc.source_observation_ids = obs_ids
            return ioc.id

    def auto_promote(self, ioc_id: int) -> bool:
        """confidence 임계 도달 시 status='approved' 로 자동 promotion.

        - confidence >= 0.9 → approved
        - 다중 패키지 (≥2) 등장 IOC → 즉시 approved
        반환: 실제 promote 했으면 True.
        """
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT confidence, status, associated_packages "
                "FROM learned_iocs WHERE id=?", (ioc_id,),
            )
            row = cur.fetchone()
            if not row:
                return False
            conf, status, pkgs_json = row
            if status != "pending":
                return False
            pkgs = json.loads(pkgs_json or "[]")
            should_promote = conf >= 0.9 or len(pkgs) >= 2
            if not should_promote:
                return False
            cur.execute(
                "UPDATE learned_iocs SET status='approved' WHERE id=?",
                (ioc_id,),
            )
        return True

    def list_iocs(
        self, *, status: str | None = None,
        ioc_type: str | None = None,
        min_confidence: float = 0.0,
        limit: int = 1000,
    ) -> list[LearnedIOC]:
        q = "SELECT id, ioc_type, value, confidence, observation_count, " \
            "first_seen, last_seen, associated_packages, " \
            "source_observation_ids, status, notes FROM learned_iocs " \
            "WHERE confidence >= ?"
        params: list[Any] = [min_confidence]
        if status:
            q += " AND status=?"
            params.append(status)
        if ioc_type:
            q += " AND ioc_type=?"
            params.append(ioc_type)
        q += " ORDER BY confidence DESC, observation_count DESC LIMIT ?"
        params.append(limit)
        with self.db.cursor() as cur:
            cur.execute(q, params)
            rows = cur.fetchall()
        return [_row_to_ioc(r) for r in rows]

    def get_ioc(self, ioc_id: int) -> LearnedIOC | None:
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT id, ioc_type, value, confidence, observation_count, "
                "first_seen, last_seen, associated_packages, "
                "source_observation_ids, status, notes FROM learned_iocs "
                "WHERE id=?", (ioc_id,),
            )
            row = cur.fetchone()
        return _row_to_ioc(row) if row else None

    # ───── rule draft ─────

    def record_rule_draft(self, rule: LearnedRule) -> int:
        ts = rule.created_at or _now()
        with self.db.cursor() as cur:
            cur.execute(
                "INSERT INTO learned_rules (rule_kind, rule_body, "
                "source_observation_ids, confidence, status, created_at, "
                "rationale) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    rule.rule_kind, rule.rule_body,
                    json.dumps(rule.source_observation_ids,
                               ensure_ascii=False),
                    rule.confidence, rule.status, ts, rule.rationale,
                ),
            )
            rule.id = cur.lastrowid
        return rule.id

    def approve_rule(self, rule_id: int, approver: str) -> bool:
        ts = _now()
        with self.db.cursor() as cur:
            cur.execute(
                "UPDATE learned_rules SET status='approved', approved_at=?, "
                "approved_by=? WHERE id=? AND status='draft'",
                (ts, approver, rule_id),
            )
            return cur.rowcount > 0

    def list_rules(
        self, *, status: str | None = None,
        rule_kind: str | None = None, limit: int = 100,
    ) -> list[LearnedRule]:
        q = "SELECT id, rule_kind, rule_body, source_observation_ids, " \
            "confidence, status, created_at, approved_at, approved_by, " \
            "rationale FROM learned_rules"
        clauses = []
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(status)
        if rule_kind:
            clauses.append("rule_kind=?")
            params.append(rule_kind)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self.db.cursor() as cur:
            cur.execute(q, params)
            rows = cur.fetchall()
        return [_row_to_rule(r) for r in rows]

    # ───── 통계 ─────

    def stats(self) -> dict:
        with self.db.cursor() as cur:
            cur.execute("SELECT count(*) FROM runtime_observations")
            n_obs = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM learned_iocs")
            n_iocs = cur.fetchone()[0]
            cur.execute(
                "SELECT status, count(*) FROM learned_iocs GROUP BY status",
            )
            by_status = {r[0]: r[1] for r in cur.fetchall()}
            cur.execute(
                "SELECT count(*) FROM learned_rules WHERE status='draft'",
            )
            n_drafts = cur.fetchone()[0]
        return {
            "observations": n_obs,
            "iocs_total": n_iocs,
            "iocs_by_status": by_status,
            "rule_drafts_pending_review": n_drafts,
        }


# ─────────────── 내부 헬퍼 ───────────────

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _bump_confidence(
    current: float, observation_count: int, package_count: int,
) -> float:
    """다중 관측 / 다중 패키지 등장 → confidence 단조 증가, 1.0 상한."""
    bumped = current
    if observation_count >= 3:
        bumped = max(bumped, 0.75)
    if observation_count >= 5:
        bumped = max(bumped, 0.85)
    if package_count >= 2:
        bumped = max(bumped, 0.9)
    if package_count >= 3:
        bumped = max(bumped, 0.95)
    return min(1.0, round(bumped, 4))


def _row_to_observation(row) -> RuntimeObservation:
    return RuntimeObservation(
        id=row[0], received_at=row[1], source=row[2], host=row[3],
        package=row[4], ecosystem=row[5], version=row[6],
        raw_event=json.loads(row[7] or "{}"),
        extracted_iocs=json.loads(row[8] or "[]"),
        extracted_pattern=json.loads(row[9]) if row[9] else None,
        verdict_before=row[10], verdict_after=row[11], mitigation=row[12],
    )


def _row_to_ioc(row) -> LearnedIOC:
    return LearnedIOC(
        id=row[0], ioc_type=row[1], value=row[2],
        confidence=row[3], observation_count=row[4],
        first_seen=row[5], last_seen=row[6],
        associated_packages=json.loads(row[7] or "[]"),
        source_observation_ids=json.loads(row[8] or "[]"),
        status=row[9], notes=row[10],
    )


def _row_to_rule(row) -> LearnedRule:
    return LearnedRule(
        id=row[0], rule_kind=row[1], rule_body=row[2],
        source_observation_ids=json.loads(row[3] or "[]"),
        confidence=row[4], status=row[5], created_at=row[6],
        approved_at=row[7], approved_by=row[8], rationale=row[9],
    )
