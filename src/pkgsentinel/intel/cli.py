"""Runtime intel CLI dashboard (#L7) — 검토 / 통계 / promote / export.

서브커맨드:
  stats            — 전체 통계 (observations, IOCs by status, rule drafts)
  list-iocs        — 학습된 IOC 목록 (필터: --status / --type / --min-confidence)
  list-rules       — 룰 draft 목록 (필터: --status / --kind)
  list-observations — 최근 observation 목록 (--package)
  approve-rule     — 룰 draft promote (--id N --by alice)
  approve-ioc      — IOC pending → approved 강제 (--id N)
  export-osv       — approved IOC 들을 OSV advisory 디렉터리로 dump

사용:
  python -m pkgsentinel.intel.cli stats
  python -m pkgsentinel.intel.cli list-iocs --status approved --type ip
  python -m pkgsentinel.intel.cli approve-rule --id 7 --by alice
  python -m pkgsentinel.intel.cli export-osv --out-dir /tmp/osv-export
"""
from __future__ import annotations

import argparse
import json
import sys

from ..db.runtime_intel import RuntimeIntelStore
from .osv_export import export_to_directory


def _cmd_stats(args) -> int:
    s = RuntimeIntelStore()
    st = s.stats()
    print(json.dumps(st, indent=2, ensure_ascii=False))
    return 0


def _cmd_list_iocs(args) -> int:
    s = RuntimeIntelStore()
    iocs = s.list_iocs(
        status=args.status, ioc_type=args.type,
        min_confidence=args.min_confidence, limit=args.limit,
    )
    if args.json:
        out = [
            {
                "id": i.id, "type": i.ioc_type, "value": i.value,
                "confidence": i.confidence, "obs_count": i.observation_count,
                "packages": i.associated_packages, "status": i.status,
                "first_seen": i.first_seen, "last_seen": i.last_seen,
            } for i in iocs
        ]
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"{'id':>5} {'type':<12} {'conf':<5} {'obs':<4} "
              f"{'status':<10} {'value':<40} packages")
        print("-" * 100)
        for i in iocs:
            pkgs = ",".join(i.associated_packages[:3])
            print(f"{i.id:>5} {i.ioc_type:<12} {i.confidence:<5.2f} "
                  f"{i.observation_count:<4} {i.status:<10} "
                  f"{i.value[:38]:<40} {pkgs}")
    return 0


def _cmd_list_rules(args) -> int:
    s = RuntimeIntelStore()
    rules = s.list_rules(status=args.status, rule_kind=args.kind,
                         limit=args.limit)
    if args.json:
        out = [
            {
                "id": r.id, "kind": r.rule_kind, "status": r.status,
                "confidence": r.confidence, "created_at": r.created_at,
                "approved_by": r.approved_by, "rationale": r.rationale,
                "body": r.rule_body,
            } for r in rules
        ]
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"{'id':>5} {'kind':<18} {'status':<10} {'conf':<5} "
              f"created       approved_by")
        print("-" * 90)
        for r in rules:
            ts = (r.created_at or "")[:19]
            ab = r.approved_by or "-"
            print(f"{r.id:>5} {r.rule_kind:<18} {r.status:<10} "
                  f"{r.confidence:<5.2f} {ts}  {ab}")
            if args.verbose and r.rationale:
                print(f"        rationale: {r.rationale[:200]}")
    return 0


def _cmd_list_observations(args) -> int:
    s = RuntimeIntelStore()
    obs = s.list_observations(package=args.package, limit=args.limit)
    if args.json:
        out = [
            {
                "id": o.id, "source": o.source, "received_at": o.received_at,
                "package": o.package, "ecosystem": o.ecosystem,
                "version": o.version, "host": o.host,
                "verdict_before": o.verdict_before,
                "verdict_after": o.verdict_after,
                "mitigation": o.mitigation,
                "iocs": o.extracted_iocs,
                "pattern": o.extracted_pattern,
            } for o in obs
        ]
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"{'id':>5} {'src':<10} {'pkg':<25} {'host':<20} "
              f"{'mitig':<10} v_before→v_after")
        print("-" * 100)
        for o in obs:
            pkg = f"{o.package or '?'}@{o.version or '?'}"[:23]
            host = (o.host or "-")[:18]
            v_chg = f"{o.verdict_before or '?'} -> {o.verdict_after or '?'}"
            print(f"{o.id:>5} {o.source:<10} {pkg:<25} {host:<20} "
                  f"{(o.mitigation or '-'):<10} {v_chg}")
    return 0


def _cmd_approve_rule(args) -> int:
    s = RuntimeIntelStore()
    ok = s.approve_rule(args.id, args.by)
    if ok:
        print(f"OK: rule #{args.id} approved by {args.by}")
        return 0
    print(f"FAIL: rule #{args.id} not in draft state (already approved or missing)",
          file=sys.stderr)
    return 1


def _cmd_approve_ioc(args) -> int:
    s = RuntimeIntelStore()
    # 직접 update — auto_promote 는 confidence 임계 기반.
    # 수동 approve 는 status='approved' 강제 set.
    ioc = s.get_ioc(args.id)
    if not ioc:
        print(f"FAIL: IOC #{args.id} not found", file=sys.stderr)
        return 1
    with s.db.cursor() as cur:
        cur.execute(
            "UPDATE learned_iocs SET status='approved' WHERE id=?",
            (args.id,),
        )
    print(f"OK: IOC #{args.id} ({ioc.ioc_type}={ioc.value}) approved")
    return 0


def _cmd_export_osv(args) -> int:
    res = export_to_directory(
        args.out_dir, min_confidence=args.min_confidence,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkgsentinel-intel")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("stats", help="전체 통계")
    s.set_defaults(func=_cmd_stats)

    s = sub.add_parser("list-iocs", help="학습된 IOC 목록")
    s.add_argument("--status", choices=["pending", "approved", "retired"])
    s.add_argument("--type", dest="type",
                   choices=["ip", "domain", "sha256", "path", "syscall_chain"])
    s.add_argument("--min-confidence", type=float, default=0.0)
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_list_iocs)

    s = sub.add_parser("list-rules", help="룰 draft 목록")
    s.add_argument("--status",
                   choices=["draft", "approved", "deployed", "retired"])
    s.add_argument("--kind", choices=[
        "indicator_47", "falco", "sequence_pattern", "aislopsq_r",
    ])
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--verbose", "-v", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_list_rules)

    s = sub.add_parser("list-observations", help="최근 observation")
    s.add_argument("--package")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_list_observations)

    s = sub.add_parser("approve-rule", help="룰 draft → approved")
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--by", required=True)
    s.set_defaults(func=_cmd_approve_rule)

    s = sub.add_parser("approve-ioc", help="IOC pending → approved (수동)")
    s.add_argument("--id", type=int, required=True)
    s.set_defaults(func=_cmd_approve_ioc)

    s = sub.add_parser("export-osv",
                       help="approved IOC → OSV advisory JSON dump")
    s.add_argument("--out-dir", required=True)
    s.add_argument("--min-confidence", type=float, default=0.7)
    s.set_defaults(func=_cmd_export_osv)

    return p


def main():
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
