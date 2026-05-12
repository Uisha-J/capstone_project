"""Phase 4.6 후속 — `attack_history_only=False` 실측 (전체 파이프라인 재귀).

직접 deps 각각을 full run_pipeline (Stage 0-6 전체) 으로 분석.
attack_history_only=True (지식DB 매칭) 와 결과 비교.

비용:
  - dep_llm_mode='stub' (기본): LLM 호출 0, 네트워크 + AST 시간만
  - dep_llm_mode='claude' (옵션): 각 dep 가 multi-agent 3 LLM calls → 비용 발생
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pkgsentinel.schema import Ecosystem  # noqa: E402
from pkgsentinel.stages.stage0_registry import check  # noqa: E402
from pkgsentinel.stages.stage1b_full_source import extract_all  # noqa: E402
from pkgsentinel.stages.stage_dependency import (  # noqa: E402
    analyze_dependencies,
    extract_dependencies,
)

TARGETS = [
    ("requests", Ecosystem.PYPI),
    ("flask",    Ecosystem.PYPI),
    ("boto3",    Ecosystem.PYPI),
    ("django",   Ecosystem.PYPI),
    ("axios",    Ecosystem.NPM),
    ("lodash",   Ecosystem.NPM),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--dep-llm-mode", choices=["stub", "claude"], default="stub",
        help="dep 분석 시 LLM 모드. stub=$0, claude=비용 발생",
    )
    ap.add_argument(
        "--max-packages", type=int, default=10,
        help="패키지 당 분석할 dep 수 상한",
    )
    args = ap.parse_args()

    # 격리 DB + 마스터 키 (run_pipeline 내부의 stage_0a / cache 가 DB 사용)
    import tempfile
    td = tempfile.mkdtemp(prefix="full_recursion_")
    os.environ["AISLOP_DB_KEY"] = "full-recursion-eval-key"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )

    if args.dep_llm_mode == "claude":
        from pkgsentinel import _dotenv as _ad
        _ad.load()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY missing", file=sys.stderr)
            sys.exit(2)

    print(f"=== Full recursion eval (attack_history_only=False) ===")
    print(f"  dep_llm_mode: {args.dep_llm_mode}")
    print(f"  max_packages/target: {args.max_packages}")
    print()

    all_rows = []
    t_all = time.time()
    for name, eco in TARGETS:
        print(f"=== {name} ({eco.value}) ===")
        t0 = time.time()
        try:
            info = check(name, eco)
            if not info.found:
                print(f"  not found")
                continue
            ver = info.latest_version
            url = info.archive_urls.get(ver)
            ext = extract_all(name, eco, ver, url)
            if ext.error:
                print(f"  extract error: {ext.error}")
                continue
            de = extract_dependencies(ext.source_files, eco)

            t_dep = time.time()
            results = analyze_dependencies(
                de, eco,
                attack_history_only=False,
                dep_llm_mode=args.dep_llm_mode,
                max_packages=args.max_packages,
            )
            elapsed_dep = time.time() - t_dep

            by_verdict: dict[str, int] = {}
            for r in results:
                by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
            print(f"  deps analyzed: {len(results)}  "
                  f"time/dep={elapsed_dep/max(1,len(results)):.1f}s  "
                  f"total={elapsed_dep:.1f}s")
            print(f"  verdicts: {by_verdict}")
            for r in results:
                if r.verdict not in ("CLEAN", "SKIPPED"):
                    print(f"    ! {r.name}@{r.resolved_version or '?'}"
                          f"  {r.verdict}  ev={r.evidence_count}")

            all_rows.append({
                "name": name, "ecosystem": eco.value, "version": ver,
                "n_deps": len(results),
                "verdicts": by_verdict,
                "elapsed_s": round(elapsed_dep, 2),
                "results": [
                    {
                        "name": r.name, "version_spec": r.version_spec,
                        "resolved": r.resolved_version,
                        "verdict": r.verdict, "evidence_count": r.evidence_count,
                    } for r in results
                ],
            })
        except Exception as e:
            print(f"  EXCEPTION: {type(e).__name__}: {str(e)[:120]}")

    elapsed = time.time() - t_all
    print(f"\n=== Summary ===")
    print(f"  packages OK: {len(all_rows)}/{len(TARGETS)}")
    print(f"  total elapsed: {elapsed:.1f}s")

    out = ROOT / "scripts" / "eval_real_data" / "results_deps_full_recursion.json"
    out.write_text(json.dumps({
        "mode": args.dep_llm_mode,
        "max_packages": args.max_packages,
        "targets": all_rows,
        "elapsed_total_s": round(elapsed, 2),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nJSON saved -> {out}")

    import shutil
    shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    main()
