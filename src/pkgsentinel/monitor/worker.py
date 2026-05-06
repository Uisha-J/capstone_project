"""
실시간 분석 worker — 우선순위 큐 consumer.

흐름 (한 사이클):
  1. lock_next() 로 큐에서 1건 잡기
  2. run_pipeline() 호출 (default: llm_mode='stub' — LLM 비용 0)
  3. verdict 가 SUSPICIOUS 이상이면 sinks (STIX/webhook/Falco) 발송
  4. 큐 complete

cron 친화: --max N 으로 N건만 처리 후 종료.
            --loop 옵션은 데몬 모드 (선택).
"""
from __future__ import annotations

import argparse
import json
import os
import time
import traceback
from dataclasses import dataclass

from ..db.threat_db import ThreatDB, get_default_db
from ..pipeline import _report_to_serializable, run_pipeline
from ..realtime.sinks.falco_policy import FalcoPolicySink
from ..realtime.sinks.stix_sink import STIXSink
from ..realtime.sinks.webhook_sink import WebhookSink
from ..schema import Ecosystem, Verdict
from .priority_queue import PriorityQueue, QueuedJob

# ─────────────── Sink 환경변수 설정 ───────────────

@dataclass
class SinkConfig:
    stix_out_dir: str | None = None     # AISLOP_STIX_OUT_DIR
    webhook_url: str | None = None      # AISLOP_WEBHOOK_URL
    webhook_secret: str | None = None   # AISLOP_WEBHOOK_SECRET
    falco_out_dir: str | None = None    # AISLOP_FALCO_OUT_DIR
    taxii_url: str | None = None        # AISLOP_TAXII_URL
    taxii_user: str | None = None       # AISLOP_TAXII_USER
    taxii_pass: str | None = None       # AISLOP_TAXII_PASS

    @classmethod
    def from_env(cls) -> SinkConfig:
        return cls(
            stix_out_dir=os.getenv("AISLOP_STIX_OUT_DIR"),
            webhook_url=os.getenv("AISLOP_WEBHOOK_URL"),
            webhook_secret=os.getenv("AISLOP_WEBHOOK_SECRET"),
            falco_out_dir=os.getenv("AISLOP_FALCO_OUT_DIR"),
            taxii_url=os.getenv("AISLOP_TAXII_URL"),
            taxii_user=os.getenv("AISLOP_TAXII_USER"),
            taxii_pass=os.getenv("AISLOP_TAXII_PASS"),
        )

    def any_configured(self) -> bool:
        return any([
            self.stix_out_dir, self.webhook_url,
            self.falco_out_dir, self.taxii_url,
        ])


# ─────────────── verdict 별 sink 발송 결정 ───────────────

_SINK_VERDICTS = {Verdict.MALICIOUS, Verdict.HIGH_RISK, Verdict.SUSPICIOUS}


def _should_emit(verdict: Verdict) -> bool:
    return verdict in _SINK_VERDICTS


def _log_sink(db: ThreatDB, job: QueuedJob, kind: str,
              success: bool, *, code: int | None = None,
              error: str | None = None, sha: str | None = None):
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO sink_log
                (package, ecosystem, version, sink_kind,
                 success, response_code, error, payload_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job.package, job.ecosystem, job.version, kind,
            1 if success else 0, code, error, sha,
        ))


# ─────────────── sink 발송 ───────────────

def _emit_sinks(
    db: ThreatDB,
    job: QueuedJob,
    report_dict: dict,
    cfg: SinkConfig,
) -> dict:
    out: dict = {}

    if cfg.stix_out_dir or cfg.taxii_url:
        sink = STIXSink(
            out_dir=cfg.stix_out_dir,
            taxii_url=cfg.taxii_url,
            taxii_user=cfg.taxii_user,
            taxii_pass=cfg.taxii_pass,
        )
        try:
            r = sink.emit(report_dict)
            out["stix"] = r
            _log_sink(db, job, "stix", True,
                      code=r.get("taxii_status"),
                      sha=r.get("sha256"))
        except Exception as e:
            out["stix"] = {"error": str(e)}
            _log_sink(db, job, "stix", False, error=str(e))

    if cfg.webhook_url and cfg.webhook_secret:
        sink = WebhookSink(url=cfg.webhook_url, secret=cfg.webhook_secret)
        try:
            r = sink.emit(report_dict)
            out["webhook"] = r
            _log_sink(db, job, "webhook", r.get("ok", False),
                      code=r.get("status"),
                      error=r.get("error"),
                      sha=r.get("body_sha256"))
        except Exception as e:
            out["webhook"] = {"error": str(e)}
            _log_sink(db, job, "webhook", False, error=str(e))

    if cfg.falco_out_dir:
        sink = FalcoPolicySink(out_dir=cfg.falco_out_dir)
        try:
            r = sink.emit(report_dict)
            out["falco"] = r
            _log_sink(db, job, "falco", True)
        except Exception as e:
            out["falco"] = {"error": str(e)}
            _log_sink(db, job, "falco", False, error=str(e))

    return out


# ─────────────── 한 작업 처리 ───────────────

@dataclass
class JobResult:
    job_id: int
    package: str
    ecosystem: str
    version: str
    verdict: str
    elapsed_s: float
    sinks_emitted: dict
    error: str | None = None


def process_one(
    db: ThreatDB,
    queue: PriorityQueue,
    job: QueuedJob,
    *,
    llm_mode: str = "stub",
    integrity_mode: str = "strict",
    sink_cfg: SinkConfig | None = None,
    verbose: bool = False,
) -> JobResult:
    cfg = sink_cfg or SinkConfig.from_env()
    t0 = time.time()
    try:
        rep = run_pipeline(
            package=job.package,
            ecosystem=Ecosystem(job.ecosystem),
            version=job.version,
            llm_mode=llm_mode,
            integrity_mode=integrity_mode,
            use_cache=True,
            force_rescan=False,
            use_threat_filter=True,
            verbose=verbose,
        )
        elapsed = time.time() - t0
        verdict_str = rep.verdict.value

        sinks_out: dict = {}
        if _should_emit(rep.verdict) and cfg.any_configured():
            report_dict = _report_to_serializable(rep)
            sinks_out = _emit_sinks(db, job, report_dict, cfg)

        queue.complete(job.id, result=f"OK:{verdict_str}")
        return JobResult(
            job_id=job.id,
            package=job.package,
            ecosystem=job.ecosystem,
            version=job.version,
            verdict=verdict_str,
            elapsed_s=round(elapsed, 2),
            sinks_emitted=sinks_out,
        )
    except Exception as e:
        elapsed = time.time() - t0
        err = f"{type(e).__name__}: {e}"
        if verbose:
            traceback.print_exc()
        queue.abandon(job.id, error=err[:200])
        return JobResult(
            job_id=job.id,
            package=job.package,
            ecosystem=job.ecosystem,
            version=job.version,
            verdict="ERROR",
            elapsed_s=round(elapsed, 2),
            sinks_emitted={},
            error=err,
        )


# ─────────────── 메인 루프 ───────────────

def run_worker(
    *,
    db: ThreatDB | None = None,
    max_jobs: int = 10,
    llm_mode: str = "stub",
    integrity_mode: str = "strict",
    loop: bool = False,
    poll_interval_s: float = 30.0,
    verbose: bool = False,
) -> dict:
    db = db or get_default_db()
    queue = PriorityQueue(db)
    cfg = SinkConfig.from_env()

    processed: list[dict] = []
    n = 0
    started = time.time()

    while True:
        # stuck job 정리 (10분 이상 lock)
        queue.reset_stuck(older_than_minutes=10)

        job = queue.lock_next()
        if job is None:
            if loop:
                if verbose:
                    print(f"[worker] queue empty, sleep {poll_interval_s}s")
                time.sleep(poll_interval_s)
                continue
            break

        if verbose:
            print(f"[worker] picked id={job.id} prio={job.priority} "
                  f"{job.ecosystem}/{job.package}@{job.version}")

        result = process_one(
            db, queue, job,
            llm_mode=llm_mode,
            integrity_mode=integrity_mode,
            sink_cfg=cfg,
            verbose=verbose,
        )
        processed.append({
            "id": result.job_id,
            "pkg": f"{result.ecosystem}/{result.package}@{result.version}",
            "verdict": result.verdict,
            "elapsed_s": result.elapsed_s,
            "sinks": list(result.sinks_emitted.keys()),
            "error": result.error,
        })
        n += 1
        if n >= max_jobs and not loop:
            break

    return {
        "processed": n,
        "elapsed_s": round(time.time() - started, 1),
        "queue_stats_after": queue.stats(),
        "results": processed,
    }


# ─────────────── CLI ───────────────

def _argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ai-slopsq monitor worker")
    p.add_argument("--max", type=int, default=10,
                   help="처리할 작업 수 (cron 모드)")
    p.add_argument("--loop", action="store_true",
                   help="continuous loop (데몬 모드)")
    p.add_argument("--poll-interval", type=float, default=30.0,
                   help="loop 시 대기 시간 (초)")
    p.add_argument("--llm-mode", choices=["stub", "claude"], default="claude")
    p.add_argument("--integrity-mode",
                   choices=["fast", "strict", "paranoid"], default="strict")
    p.add_argument("--passphrase", default=None)
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--json", action="store_true")
    return p


def main():
    args = _argparser().parse_args()
    if args.passphrase:
        from ..db.threat_db import DEFAULT_DB_PATH, ThreatDB
        db = ThreatDB(DEFAULT_DB_PATH, passphrase=args.passphrase)
    else:
        db = None

    summary = run_worker(
        db=db,
        max_jobs=args.max,
        llm_mode=args.llm_mode,
        integrity_mode=args.integrity_mode,
        loop=args.loop,
        poll_interval_s=args.poll_interval,
        verbose=args.verbose,
    )

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"processed={summary['processed']} "
              f"elapsed={summary['elapsed_s']}s")
        for r in summary["results"]:
            sinks = ",".join(r["sinks"]) if r["sinks"] else "-"
            err = f"  ERR: {r['error']}" if r.get("error") else ""
            print(f"  id={r['id']:>4} {r['pkg']:<50} "
                  f"verdict={r['verdict']:<11} t={r['elapsed_s']:>5.1f}s "
                  f"sinks={sinks}{err}")
        print(f"\nqueue: {summary['queue_stats_after']}")


if __name__ == "__main__":
    main()
