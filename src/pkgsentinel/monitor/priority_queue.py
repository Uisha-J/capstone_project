"""
SQLite (SQLCipher) 기반 우선순위 큐.

DB 테이블: scan_queue (threat_db 내).

worker poll 모델:
  1. 비어있는 작업 중 priority 낮은 + enqueued 오래된 1건 SELECT
  2. UPDATE 로 locked_at, locked_by 채움 (다른 worker 가 못 잡게)
  3. 처리 후 completed_at + result 기록

실패한 작업은 retry 가능하도록 reset() 메서드 제공.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Optional

from ..db.threat_db import ThreatDB, get_default_db
from ..feeds.popular import lookup_popular
from .release_event import ReleaseEvent, compute_priority


def _worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


@dataclass
class QueuedJob:
    id: int
    ecosystem: str
    package: str
    version: str
    archive_url: str
    priority: int
    source_event: str
    enqueued_at: str
    locked_by: Optional[str] = None


class PriorityQueue:
    def __init__(self, db: ThreatDB | None = None):
        self.db = db or get_default_db()

    # ───── enqueue ─────

    def enqueue(self, ev: ReleaseEvent, *, priority: int | None = None) -> bool:
        """이벤트를 큐에 추가. 이미 같은 (pkg, eco, ver, enqueued_at) 있으면 INSERT skip."""
        if priority is None:
            priority = self._auto_priority(ev)

        with self.db.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO scan_queue
                        (package, ecosystem, version, archive_url,
                         priority, source_event)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    ev.package, ev.ecosystem, ev.version, ev.archive_url,
                    priority, ev.source_event,
                ))
                return True
            except Exception:
                # UNIQUE 충돌 (같은 ms 에 다시 들어왔을 때) → skip
                return False

    def enqueue_many(self, events: list[ReleaseEvent]) -> int:
        n = 0
        for ev in events:
            if self.enqueue(ev):
                n += 1
        return n

    # ───── pop (lock) ─────

    def lock_next(self, *, max_inflight: int = 1) -> Optional[QueuedJob]:
        """가장 우선순위 높은 pending 작업 1건을 lock 해서 반환.

        max_inflight 는 하나의 worker 가 동시에 잡고 있을 수 있는 최대.
        직렬 처리 (1건씩) 가 기본.
        """
        wid = _worker_id()
        with self.db.cursor() as cur:
            # 이미 이 worker 가 lock 한 게 있으면 그것부터 처리
            cur.execute("""
                SELECT id, package, ecosystem, version, archive_url,
                       priority, source_event, enqueued_at, locked_by
                FROM scan_queue
                WHERE locked_by = ? AND completed_at IS NULL
                ORDER BY priority, enqueued_at
                LIMIT ?
            """, (wid, max_inflight))
            row = cur.fetchone()
            if row:
                return _row_to_job(row)

            # 새 작업 lock 시도 — atomic UPDATE ... WHERE id = (SELECT ...)
            cur.execute("""
                UPDATE scan_queue
                SET locked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    locked_by = ?
                WHERE id = (
                    SELECT id FROM scan_queue
                    WHERE locked_at IS NULL AND completed_at IS NULL
                    ORDER BY priority, enqueued_at
                    LIMIT 1
                )
                RETURNING id, package, ecosystem, version, archive_url,
                          priority, source_event, enqueued_at, locked_by
            """, (wid,))
            updated = cur.fetchone()
            if updated:
                return _row_to_job(updated)
            return None

    # ───── 처리 완료 / 실패 ─────

    def complete(self, job_id: int, *, result: str = "OK"):
        with self.db.cursor() as cur:
            cur.execute("""
                UPDATE scan_queue
                SET completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    result = ?
                WHERE id = ?
            """, (result, job_id))

    def fail(self, job_id: int, *, error: str):
        # 실패 기록만 남기고 lock 해제 (다른 worker 가 재시도 가능)
        with self.db.cursor() as cur:
            cur.execute("""
                UPDATE scan_queue
                SET locked_at = NULL, locked_by = NULL,
                    result = ?
                WHERE id = ?
            """, (f"RETRY:{error[:200]}", job_id))

    def abandon(self, job_id: int, *, error: str):
        # 영구 실패 (재시도 안 함)
        with self.db.cursor() as cur:
            cur.execute("""
                UPDATE scan_queue
                SET completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    result = ?
                WHERE id = ?
            """, (f"ERR:{error[:200]}", job_id))

    # ───── 통계 + 정리 ─────

    def stats(self) -> dict:
        with self.db.cursor() as cur:
            cur.execute("""
                SELECT
                    SUM(CASE WHEN locked_at IS NULL AND completed_at IS NULL THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN locked_at IS NOT NULL AND completed_at IS NULL THEN 1 ELSE 0 END) AS inflight,
                    SUM(CASE WHEN completed_at IS NOT NULL AND result LIKE 'OK%' THEN 1 ELSE 0 END) AS done,
                    SUM(CASE WHEN completed_at IS NOT NULL AND result LIKE 'ERR%' THEN 1 ELSE 0 END) AS failed,
                    COUNT(*) AS total
                FROM scan_queue
            """)
            r = cur.fetchone()
            return {
                "pending":  r[0] or 0,
                "inflight": r[1] or 0,
                "done":     r[2] or 0,
                "failed":   r[3] or 0,
                "total":    r[4] or 0,
            }

    def reset_stuck(self, *, older_than_minutes: int = 30) -> int:
        """오래 잡혀있는 (worker 죽은 듯한) inflight 작업 unlock."""
        with self.db.cursor() as cur:
            cur.execute("""
                UPDATE scan_queue
                SET locked_at = NULL, locked_by = NULL,
                    result = 'RESET:stuck-worker'
                WHERE locked_at IS NOT NULL
                  AND completed_at IS NULL
                  AND locked_at <
                      strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
            """, (f"-{older_than_minutes} minutes",))
            return cur.rowcount

    def purge_completed(self, *, older_than_days: int = 30) -> int:
        with self.db.cursor() as cur:
            cur.execute("""
                DELETE FROM scan_queue
                WHERE completed_at IS NOT NULL
                  AND completed_at <
                      strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
            """, (f"-{older_than_days} days",))
            return cur.rowcount

    # ───── 우선순위 자동 결정 ─────

    def _auto_priority(self, ev: ReleaseEvent) -> int:
        rank = None
        try:
            row = lookup_popular(self.db, ev.ecosystem, ev.package)
            if row:
                rank = row.get("rank")
        except Exception:
            pass

        # 최근 advisory?
        has_advisory = False
        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM known_malicious
                    WHERE ecosystem = ? AND lower(package) = lower(?)
                    LIMIT 1
                """, (ev.ecosystem, ev.package))
                has_advisory = cur.fetchone() is not None
        except Exception:
            pass

        return compute_priority(
            rank=rank,
            has_recent_advisory=has_advisory,
        )


def _row_to_job(row) -> QueuedJob:
    return QueuedJob(
        id=row[0], package=row[1], ecosystem=row[2], version=row[3],
        archive_url=row[4] or "",
        priority=row[5], source_event=row[6],
        enqueued_at=row[7], locked_by=row[8],
    )


# ─────────────── CLI 테스트 ───────────────

if __name__ == "__main__":
    pq = PriorityQueue()
    print("stats before:", pq.stats())

    # enqueue 3 events
    pq.enqueue(ReleaseEvent("PyPI", "test-popular", "1.0",
                            archive_url="x", source_event="manual"))
    pq.enqueue(ReleaseEvent("PyPI", "test-other", "2.0",
                            archive_url="x", source_event="manual"))
    pq.enqueue(ReleaseEvent("npm", "test-bad", "0.0.1",
                            archive_url="x", source_event="manual"))

    print("stats after enqueue:", pq.stats())

    # pop one
    job = pq.lock_next()
    print(f"locked: id={job.id} {job.ecosystem}/{job.package}@{job.version} "
          f"prio={job.priority}")

    # complete
    pq.complete(job.id, result="OK")
    print("stats after complete:", pq.stats())
