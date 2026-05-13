"""Top-N popular 패키지의 정상 동작 baseline 학습 (#Z3).

OSSF Package Analysis 데이터로 인기 패키지의 *전형 행동 프로필* 수집:
  - network: 외부 IP/도메인 connect 시도 여부
  - exec: 자식 프로세스 spawn 여부
  - sensitive_file: 자격증명 류 파일 access 여부
  - import_phase: install / import / runtime 단계별 행동

이후 같은 패키지의 *새 버전* 이 baseline 에서 *크게 벗어나면* anomaly →
supply chain compromise (eslint-scope 2018, event-stream 등) 의 핵심 방어.

Storage: SQLCipher 의 새 테이블 `package_baselines`.
Refresh: 주기적 batch — OSSF Package Analysis 데이터 풀로부터 재학습.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..db.threat_db import ThreatDB, get_default_db
from .ossf_package_analysis import fetch_ossf_analysis, parse_ossf_to_observed
from ..schema import Ecosystem


# ─────────────── 스키마 ───────────────

_BASELINE_SCHEMA = r"""
CREATE TABLE IF NOT EXISTS package_baselines (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    package           TEXT NOT NULL,
    ecosystem         TEXT NOT NULL,
    -- 학습 대상 버전 셋 (JSON list)
    baseline_versions TEXT NOT NULL DEFAULT '[]',
    -- 정상 행동 fingerprint (JSON)
    -- {
    --   "network_count_max": int,
    --   "exec_count_max": int,
    --   "has_sensitive_file_read": bool,
    --   "typical_domains": [..],
    --   "typical_exec_argv0s": [..]
    -- }
    behavior_profile  TEXT NOT NULL DEFAULT '{}',
    sample_count      INTEGER NOT NULL DEFAULT 0,
    last_refreshed    TEXT NOT NULL,
    UNIQUE(package, ecosystem)
);

CREATE INDEX IF NOT EXISTS idx_baseline_pkg ON package_baselines(package, ecosystem);
"""


def _ensure_schema(db: ThreatDB) -> None:
    with db.cursor() as cur:
        cur.executescript(_BASELINE_SCHEMA)


# ─────────────── 데이터 클래스 ───────────────

@dataclass
class BehaviorProfile:
    """패키지의 정상 행동 프로필."""
    network_count_max: int = 0       # 정상 시 최대 외부 connect 수
    exec_count_max: int = 0          # 정상 시 최대 자식 process spawn 수
    file_write_count_max: int = 0
    has_sensitive_file_read: bool = False
    typical_domains: list[str] = field(default_factory=list)
    typical_exec_argv0s: list[str] = field(default_factory=list)
    sensitive_paths_seen: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "network_count_max": self.network_count_max,
            "exec_count_max": self.exec_count_max,
            "file_write_count_max": self.file_write_count_max,
            "has_sensitive_file_read": self.has_sensitive_file_read,
            "typical_domains": list(self.typical_domains),
            "typical_exec_argv0s": list(self.typical_exec_argv0s),
            "sensitive_paths_seen": list(self.sensitive_paths_seen),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BehaviorProfile":
        return cls(
            network_count_max=int(d.get("network_count_max", 0)),
            exec_count_max=int(d.get("exec_count_max", 0)),
            file_write_count_max=int(d.get("file_write_count_max", 0)),
            has_sensitive_file_read=bool(d.get("has_sensitive_file_read", False)),
            typical_domains=list(d.get("typical_domains", [])),
            typical_exec_argv0s=list(d.get("typical_exec_argv0s", [])),
            sensitive_paths_seen=list(d.get("sensitive_paths_seen", [])),
        )


@dataclass
class AnomalyVerdict:
    """현재 버전 행동이 baseline 대비 anomaly 인지."""
    is_anomalous: bool
    reasons: list[str] = field(default_factory=list)
    severity: str = "info"   # "info" | "low" | "medium" | "high"


# ─────────────── Store ───────────────

class PackageBaselineStore:
    """패키지별 행동 baseline 영속 저장."""

    def __init__(self, db: ThreatDB | None = None):
        self.db = db or get_default_db()
        _ensure_schema(self.db)

    def get(self, package: str, ecosystem: str) -> BehaviorProfile | None:
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT behavior_profile FROM package_baselines "
                "WHERE package=? AND ecosystem=?",
                (package.lower(), ecosystem),
            )
            row = cur.fetchone()
        if not row:
            return None
        try:
            return BehaviorProfile.from_dict(json.loads(row[0]))
        except Exception:
            return None

    def set(
        self,
        package: str, ecosystem: str,
        profile: BehaviorProfile,
        baseline_versions: list[str],
        sample_count: int,
    ) -> None:
        import time
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO package_baselines (
                    package, ecosystem, baseline_versions,
                    behavior_profile, sample_count, last_refreshed
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(package, ecosystem) DO UPDATE SET
                    baseline_versions = excluded.baseline_versions,
                    behavior_profile = excluded.behavior_profile,
                    sample_count = excluded.sample_count,
                    last_refreshed = excluded.last_refreshed
                """,
                (
                    package.lower(), ecosystem,
                    json.dumps(baseline_versions),
                    json.dumps(profile.to_dict(), ensure_ascii=False),
                    sample_count, ts,
                ),
            )

    def count(self) -> int:
        with self.db.cursor() as cur:
            cur.execute("SELECT count(*) FROM package_baselines")
            return cur.fetchone()[0]


# ─────────────── 학습기 ───────────────

def build_profile_from_observations(
    observations: list,    # list[ObservedBehavior]
) -> BehaviorProfile:
    """OSSF 관측 결과 N건 → 정상 행동 프로필.

    각 카운트 max → 정상 상한. 같은 패키지의 *어떤* 버전도 이 상한을 넘으면
    anomaly 후보.
    """
    profile = BehaviorProfile()
    seen_domains: set[str] = set()
    seen_execs: set[str] = set()
    seen_sens: set[str] = set()

    for obs in observations:
        if not obs:
            continue
        net = list(getattr(obs, "network_requests", []) or [])
        ex = list(getattr(obs, "process_spawns", []) or [])
        fw = list(getattr(obs, "file_writes", []) or [])

        profile.network_count_max = max(profile.network_count_max, len(net))
        profile.exec_count_max = max(profile.exec_count_max, len(ex))
        profile.file_write_count_max = max(profile.file_write_count_max, len(fw))

        for n in net:
            # "connect IP:port" 또는 "DNS hostname" 류 — 도메인만 추출
            # 간단히 *공백 split 후 마지막 토큰* 사용 (보수적)
            tok = n.split(" ")[-1].split(":")[0]
            if tok:
                seen_domains.add(tok)

        for e in ex:
            argv0 = e.split(" ")[0]
            if argv0:
                seen_execs.add(argv0)

        for f in fw:
            if any(s in f.lower() for s in (
                ".ssh", ".aws", "credentials", "passwd", "shadow",
                ".npmrc", ".pypirc",
            )):
                seen_sens.add(f)
                profile.has_sensitive_file_read = True

    profile.typical_domains = sorted(seen_domains)[:50]
    profile.typical_exec_argv0s = sorted(seen_execs)[:30]
    profile.sensitive_paths_seen = sorted(seen_sens)[:30]
    return profile


def learn_baseline_for_package(
    package: str, ecosystem: Ecosystem,
    versions: list[str], *,
    store: PackageBaselineStore | None = None,
) -> BehaviorProfile:
    """OSSF Package Analysis 데이터로 N 버전의 행동 학습.

    버전 분석 실패한 건은 skip. 학습 성공 시 store 에 영속.
    """
    store = store or PackageBaselineStore()
    observations = []
    for v in versions:
        data = fetch_ossf_analysis(package, ecosystem, v)
        if data:
            observations.append(parse_ossf_to_observed(data))

    profile = build_profile_from_observations(observations)
    if observations:
        store.set(package, ecosystem.value, profile,
                  baseline_versions=versions,
                  sample_count=len(observations))
    return profile


# ─────────────── anomaly 판정 ───────────────

def check_anomaly(
    current_observation,    # ObservedBehavior
    baseline: BehaviorProfile,
) -> AnomalyVerdict:
    """현재 버전의 OSSF 관측 결과를 baseline 과 비교.

    하나 이상 deviation 발견 시 anomaly. severity 은:
      - **high**: cred read 신규 등장 (정상 베이스라인엔 없던 행동)
      - **medium**: network 폭증 (baseline 의 3x 초과) / 새 도메인 등장
      - **low**: exec count 폭증
    """
    reasons: list[str] = []
    severity = "info"

    net_curr = list(getattr(current_observation, "network_requests", []) or [])
    ex_curr = list(getattr(current_observation, "process_spawns", []) or [])
    fw_curr = list(getattr(current_observation, "file_writes", []) or [])

    # 1) sensitive file 신규 등장 — high
    has_cred_now = any(
        any(s in f.lower() for s in (
            ".ssh", ".aws", "credentials", "passwd",
        ))
        for f in fw_curr
    )
    if has_cred_now and not baseline.has_sensitive_file_read:
        reasons.append(
            "cred-file access appeared for the first time vs baseline"
        )
        severity = "high"

    # 2) network 폭증
    if (
        len(net_curr) > baseline.network_count_max * 3
        and len(net_curr) >= 5
    ):
        reasons.append(
            f"network burst: {len(net_curr)} vs baseline max "
            f"{baseline.network_count_max}"
        )
        if severity != "high":
            severity = "medium"

    # 3) 새 도메인 (정상 도메인 set 에 없는 것이 등장)
    typical_set = set(baseline.typical_domains)
    new_domains = []
    for n in net_curr:
        tok = n.split(" ")[-1].split(":")[0]
        if tok and tok not in typical_set:
            new_domains.append(tok)
    if new_domains and baseline.typical_domains:
        reasons.append(
            f"new domain(s) not in baseline: {new_domains[:5]}"
        )
        if severity == "info":
            severity = "medium"

    # 4) exec 폭증
    if (
        len(ex_curr) > baseline.exec_count_max * 3
        and len(ex_curr) >= 3
    ):
        reasons.append(
            f"exec burst: {len(ex_curr)} vs baseline max "
            f"{baseline.exec_count_max}"
        )
        if severity == "info":
            severity = "low"

    return AnomalyVerdict(
        is_anomalous=bool(reasons),
        reasons=reasons,
        severity=severity,
    )
