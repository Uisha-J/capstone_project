"""
SQLCipher 기반 위협 인텔리전스 + 분석 캐시 DB.

근거 / 선택 이유:
  - SQLCipher (https://www.zetetic.net/sqlcipher/) — SQLite + AES-256 페이지 암호화
  - 본 프로젝트의 차별화 포인트:
      * 대부분 supply-chain 도구(Grype, Trivy, OSV-Scanner)는 평문 SQLite 사용
      * 우리는 위협 피드(악성 패키지명, IoC) + 캐시를 모두 암호화 저장
      * 디스크 도난/저장소 압수 시에도 화이트리스트 변조 불가

위협 모델:
  - C: 공개 OSV 데이터 — 기밀성 낮음
  - I: 무결성 핵심. 캐시/피드 변조 시 false negative 발생
  - A: 손상 시 재분석으로 복구

방어 레이어 (DB 엔진과 별개):
  1. AES-256 페이지 암호화 (SQLCipher)
  2. 파일 권한 0600 / 디렉토리 0700
  3. WAL 모드로 트랜잭션 무결성
  4. 피드 다운로드 SHA256 검증 (feeds/* 에서 처리)
  5. analyses 행에 archive_sha256 저장 → 재배포 변조 즉시 감지
"""
from __future__ import annotations

import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

try:
    import sqlcipher3 as _sqlite
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "sqlcipher3 가 설치되지 않았습니다.\n"
        "  pip install sqlcipher3\n"
    ) from e


# ─────────────── 기본 경로 / 키 ───────────────

DEFAULT_DB_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "threat_db.sqlcipher"

# 환경변수 우선순위 (db/master_key.py 와 통합)
ENV_KEY = "AISLOP_DB_KEY"

# 페이지 크기 (4096 = SQLCipher 기본값)
CIPHER_PAGE_SIZE = 4096

# KDF 반복 (SQLCipher 4 기본값 = 256000)
KDF_ITER = 256_000


# ─────────────── 스키마 (마이그레이션은 schema_version 행으로 관리) ───────────────

CURRENT_SCHEMA_VERSION = 1


SCHEMA_V1 = """
-- ────────────────────────────────────────────────────────────────
-- v1 schema. 변경 시 SCHEMA_V<N> 추가하고 _migrate() 에 핸들러 추가.
-- ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS schema_meta (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);


-- ─── 1. 알려진 악성 패키지 (위협 피드) ─────────────────────
CREATE TABLE IF NOT EXISTS known_malicious (
    advisory_id     TEXT NOT NULL,           -- 'GHSA-xxxx', 'MAL-yyyy'
    ecosystem       TEXT NOT NULL CHECK (ecosystem IN ('PyPI', 'npm')),
    package         TEXT NOT NULL,
    version_glob    TEXT,                    -- 영향 받는 버전 (전부면 NULL/'*')
    attack_type     TEXT NOT NULL CHECK (attack_type IN (
                        'malicious_package','typosquatting',
                        'dependency_confusion','slopsquatting','other'
                    )),
    source          TEXT NOT NULL,           -- 'OSV','GHSA','npm-advisory'
    summary         TEXT,
    code_indicators TEXT,                    -- JSON array
    network_indicators TEXT,                 -- JSON array
    references_     TEXT,                    -- JSON array (url 들). 'references' 는 SQL 키워드
    published       TEXT,                    -- ISO date
    modified        TEXT,
    inserted_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (advisory_id, ecosystem, package)
);

CREATE INDEX IF NOT EXISTS idx_km_lookup
    ON known_malicious(ecosystem, package);
CREATE INDEX IF NOT EXISTS idx_km_modified
    ON known_malicious(modified);


-- ─── 2. 인기 패키지 화이트리스트 ───────────────────────────
CREATE TABLE IF NOT EXISTS known_popular (
    ecosystem       TEXT NOT NULL CHECK (ecosystem IN ('PyPI', 'npm')),
    package         TEXT NOT NULL,
    rank            INTEGER,                 -- top-N 순위 (낮을수록 인기)
    downloads_30d   INTEGER,
    stars           INTEGER,
    source          TEXT NOT NULL,           -- 'pypistats','npm-top'
    last_seen_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (ecosystem, package)
);

CREATE INDEX IF NOT EXISTS idx_kp_rank ON known_popular(ecosystem, rank);


-- ─── 3. 네트워크 IoC 블록리스트 ────────────────────────────
CREATE TABLE IF NOT EXISTS network_blocklist (
    indicator       TEXT NOT NULL,           -- domain, IP, URL
    indicator_type  TEXT NOT NULL CHECK (indicator_type IN ('domain','ip','url')),
    source          TEXT NOT NULL,           -- 'urlhaus','spamhaus','manual'
    severity        TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (severity IN ('HIGH','MEDIUM','LOW')),
    note            TEXT,
    inserted_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (indicator, source)
);

CREATE INDEX IF NOT EXISTS idx_nb_indicator ON network_blocklist(indicator);


-- ─── 4. 피드 갱신 메타 ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS feed_meta (
    source          TEXT PRIMARY KEY,        -- 'osv-pypi','osv-npm','ghsa', etc.
    last_fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    record_count    INTEGER NOT NULL DEFAULT 0,
    fetch_sha256    TEXT,                    -- 다운로드 원본 SHA256
    feed_version    TEXT,                    -- 본 도구가 부여한 갱신 ID (timestamp)
    error           TEXT
);


-- ─── 5. 분석 결과 캐시 ─────────────────────────────────────
-- 무결성 컬럼:
--   archive_sha256  → strict/paranoid 모두 기록
--   merkle_root     → paranoid 만 기록 (NULL 가능)
--   row_hmac        → paranoid 만 기록 (NULL 가능). 본 행 무결성 자체 검증
CREATE TABLE IF NOT EXISTS analyses (
    package         TEXT NOT NULL,
    ecosystem       TEXT NOT NULL CHECK (ecosystem IN ('PyPI', 'npm')),
    version         TEXT NOT NULL,
    engine_version  TEXT NOT NULL,
    rules_version   TEXT NOT NULL,
    kb_version      TEXT NOT NULL,
    feed_version    TEXT,
    archive_sha256  TEXT,                    -- 분석 시점의 archive sha256 (자체 계산)
    merkle_root     TEXT,                    -- paranoid 모드: archive 내 파일별 sha256 의 머클 루트
    row_hmac        TEXT,                    -- paranoid 모드: 본 row 자체 HMAC-SHA256
    integrity_mode  TEXT NOT NULL DEFAULT 'strict'
                   CHECK (integrity_mode IN ('fast','strict','paranoid')),
    verdict         TEXT NOT NULL,
    report_json     TEXT NOT NULL,
    analyzed_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    PRIMARY KEY (package, ecosystem, version, engine_version)
);

CREATE INDEX IF NOT EXISTS idx_an_lookup    ON analyses(package, ecosystem, version);
CREATE INDEX IF NOT EXISTS idx_an_verdict   ON analyses(verdict);
CREATE INDEX IF NOT EXISTS idx_an_analyzed  ON analyses(analyzed_at);


-- ─── 6. 캐시 무효화 트리거 (피드 갱신 시 자동) ────────────
-- known_malicious 에 새 행이 들어오면 그 패키지의 캐시는 stale 표시
CREATE TABLE IF NOT EXISTS cache_invalidation_log (
    ecosystem       TEXT NOT NULL,
    package         TEXT NOT NULL,
    invalidated_at  TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    reason          TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package, invalidated_at)
);

CREATE TRIGGER IF NOT EXISTS trg_invalidate_on_new_advisory
AFTER INSERT ON known_malicious
BEGIN
    INSERT OR IGNORE INTO cache_invalidation_log
        (ecosystem, package, invalidated_at, reason)
    VALUES
        (NEW.ecosystem, NEW.package,
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
         'new advisory: ' || NEW.advisory_id);
END;


-- ─── 7. 실시간 분석 큐 ─────────────────────────────────────
-- watcher 가 새 release 감지 → 여기에 적재.
-- worker 가 priority + enqueued_at 순으로 pop.
CREATE TABLE IF NOT EXISTS scan_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    package         TEXT NOT NULL,
    ecosystem       TEXT NOT NULL CHECK (ecosystem IN ('PyPI', 'npm')),
    version         TEXT NOT NULL,
    archive_url     TEXT,
    priority        INTEGER NOT NULL DEFAULT 100,    -- 낮을수록 먼저 처리
    source_event    TEXT NOT NULL,                   -- 'pypi_rss','npm_changes','manual'
    enqueued_at     TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    locked_at       TEXT,                            -- worker 가 잡은 시점
    locked_by       TEXT,                            -- worker id (host:pid)
    completed_at    TEXT,
    result          TEXT,                            -- 'OK', 'ERR:...', NULL=in-flight
    UNIQUE (package, ecosystem, version, enqueued_at)
);

CREATE INDEX IF NOT EXISTS idx_sq_pending
    ON scan_queue (priority, enqueued_at)
    WHERE locked_at IS NULL AND completed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sq_inflight
    ON scan_queue (locked_at)
    WHERE locked_at IS NOT NULL AND completed_at IS NULL;


-- ─── 8. 실시간 알림 발송 로그 ──────────────────────────────
-- sink (STIX/webhook/Falco) 발송 이력.
CREATE TABLE IF NOT EXISTS sink_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    package         TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    version         TEXT NOT NULL,
    sink_kind       TEXT NOT NULL,                   -- 'stix','webhook','falco','syslog'
    sent_at         TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    success         INTEGER NOT NULL DEFAULT 0,
    response_code   INTEGER,
    error           TEXT,
    payload_sha256  TEXT
);

CREATE INDEX IF NOT EXISTS idx_sl_pkg ON sink_log(package, ecosystem, version);
"""


# ─────────────── 연결 헬퍼 ───────────────

class ThreatDB:
    """SQLCipher 연결 래퍼.

    - thread-local 연결 (sqlite3 는 connection 을 thread 간 공유 불가)
    - PRAGMA key 자동 적용
    - WAL 모드 자동 설정
    - 스키마 자동 마이그레이션
    """

    def __init__(
        self,
        db_path: Path | str = DEFAULT_DB_PATH,
        passphrase: str | None = None,
        readonly: bool = False,
    ):
        self.db_path = Path(db_path)
        self._readonly = readonly
        self._passphrase = passphrase or _resolve_passphrase()
        if not self._passphrase:
            raise RuntimeError(
                f"DB passphrase 미설정. 환경변수 {ENV_KEY} 를 설정하거나 "
                "ThreatDB(passphrase=...) 인자 전달."
            )
        self._tls = threading.local()
        self._ensure_dir()
        # 첫 연결 시점에 스키마 + 권한 정렬
        self._init_or_migrate()

    # ─────── public ───────

    def conn(self):
        """thread-local 연결을 반환."""
        if not hasattr(self._tls, "c") or self._tls.c is None:
            self._tls.c = self._open_connection()
        return self._tls.c

    @contextmanager
    def cursor(self):
        c = self.conn()
        cur = c.cursor()
        try:
            yield cur
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            cur.close()

    def close(self):
        c = getattr(self._tls, "c", None)
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
            self._tls.c = None

    def get_meta(self, key: str) -> Optional[str]:
        with self.cursor() as cur:
            cur.execute("SELECT value FROM schema_meta WHERE key=?", (key,))
            row = cur.fetchone()
            return row[0] if row else None

    def set_meta(self, key: str, value: str):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO schema_meta(key, value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def vacuum(self):
        """주기적 호출로 페이지 정리 + 암호화 재패킹."""
        c = self.conn()
        c.execute("VACUUM")

    # ─────── internal ───────

    def _ensure_dir(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # 디렉토리 권한 0700 (POSIX 만 적용)
        if os.name == "posix":
            try:
                os.chmod(self.db_path.parent,
                         stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except OSError:
                pass

    def _open_connection(self):
        c = _sqlite.connect(
            str(self.db_path),
            isolation_level=None,           # autocommit; 트랜잭션은 컨텍스트로
            check_same_thread=False,
        )
        # KEY → 페이지 크기 → KDF 순서로 PRAGMA 적용 (이 순서 중요)
        # SQLCipher 권장 가이드: cipher_page_size 와 kdf_iter 를 key 직후에
        c.execute(f"PRAGMA key = '{_escape_pragma(self._passphrase)}'")
        c.execute(f"PRAGMA cipher_page_size = {CIPHER_PAGE_SIZE}")
        c.execute(f"PRAGMA kdf_iter = {KDF_ITER}")

        # ★ 키 검증 먼저 — 잘못된 키면 여기서 즉시 RuntimeError
        try:
            c.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except _sqlite.DatabaseError as e:
            try:
                c.close()
            except Exception:
                pass
            raise RuntimeError(
                f"DB open failed: passphrase invalid or file corrupt ({e})"
            ) from e

        # 검증 후에 WAL / 기타 PRAGMA 적용
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA synchronous = NORMAL")
        c.execute("PRAGMA foreign_keys = ON")
        c.execute("PRAGMA temp_store = MEMORY")

        return c

    def _init_or_migrate(self):
        # 스키마 파일이 비어있으면 v1 적용
        c = self.conn()
        c.executescript(SCHEMA_V1)
        # 권한 0600
        if os.name == "posix":
            try:
                os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        # 버전 기록
        existing = self.get_meta("schema_version")
        if existing is None:
            self.set_meta("schema_version", str(CURRENT_SCHEMA_VERSION))
        elif int(existing) < CURRENT_SCHEMA_VERSION:
            # 미래 버전을 위한 자리
            self._migrate(int(existing), CURRENT_SCHEMA_VERSION)
            self.set_meta("schema_version", str(CURRENT_SCHEMA_VERSION))

    def _migrate(self, from_v: int, to_v: int):
        # 후속 마이그레이션 핸들러 자리. 현재는 v1 only.
        pass


# ─────────────── 패스프레이즈 해소 ───────────────

def _resolve_passphrase() -> str | None:
    """우선순위:
      1. 환경변수 AISLOP_DB_KEY
      2. ~/.aislopsquatting/db.key (POSIX 0600)
      3. None (호출자 명시 필요)
    """
    env = os.environ.get(ENV_KEY)
    if env:
        return env
    keyfile = Path.home() / ".aislopsquatting" / "db.key"
    if keyfile.exists():
        try:
            data = keyfile.read_text(encoding="utf-8").strip()
            return data or None
        except OSError:
            return None
    return None


def _escape_pragma(s: str) -> str:
    """PRAGMA 문자열 리터럴 이스케이프 (single quote 만 처리)."""
    return s.replace("'", "''")


# ─────────────── 싱글톤 (의존성 주입 가능) ───────────────

_default_db: ThreatDB | None = None
_default_lock = threading.Lock()


def get_default_db() -> ThreatDB:
    global _default_db
    with _default_lock:
        if _default_db is None:
            _default_db = ThreatDB()
        return _default_db


def reset_default_db():
    """테스트용 — 싱글톤 리셋."""
    global _default_db
    with _default_lock:
        if _default_db is not None:
            _default_db.close()
        _default_db = None


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse, json, sys

    p = argparse.ArgumentParser(description="ThreatDB inspector")
    p.add_argument("--db", default=str(DEFAULT_DB_PATH))
    p.add_argument("--init", action="store_true", help="스키마 초기화만")
    p.add_argument("--stats", action="store_true", help="테이블 행 수")
    p.add_argument("--passphrase", default=None,
                   help=f"명시 (기본: env {ENV_KEY})")
    args = p.parse_args()

    try:
        db = ThreatDB(args.db, passphrase=args.passphrase)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    if args.init:
        print(f"OK - DB initialized at {args.db}")
        print(f"     schema_version = {db.get_meta('schema_version')}")

    if args.stats or not args.init:
        with db.cursor() as cur:
            tables = [
                "known_malicious", "known_popular",
                "network_blocklist", "feed_meta",
                "analyses", "cache_invalidation_log",
            ]
            stats = {}
            for t in tables:
                try:
                    cur.execute(f"SELECT count(*) FROM {t}")
                    stats[t] = cur.fetchone()[0]
                except Exception as e:
                    stats[t] = f"ERR: {e}"
        print(json.dumps(stats, indent=2))

    db.close()
