"""Phase 4.6 — 의존성 재귀 측정.

대상: 10 패키지 (popular 5 + datadog malicious 5).
각각 stage_1b 로 소스 추출 → stage_dependency 로 직접 의존성 파싱 →
analyze_dependencies (attack_history_only=True) 로 1-hop 분석.

측정값:
  - 패키지당 평균 직접 의존성 수
  - 의존성 중 MALICIOUS / SUSPICIOUS 판정 비율
  - 처리 시간 (캐싱 효과 포함)

비용: API 호출 없음 ($0).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pkgsentinel.schema import Ecosystem  # noqa: E402
from pkgsentinel.stages.stage1b_full_source import extract_all  # noqa: E402
from pkgsentinel.stages.stage_dependency import (  # noqa: E402
    analyze_dependencies,
    extract_dependencies,
)
from pkgsentinel.stages.stage0_registry import check  # noqa: E402

TARGETS = [
    ("requests", Ecosystem.PYPI),
    ("flask",    Ecosystem.PYPI),
    ("pandas",   Ecosystem.PYPI),
    ("boto3",    Ecosystem.PYPI),
    ("react",    Ecosystem.NPM),
    ("lodash",   Ecosystem.NPM),
    ("webpack",  Ecosystem.NPM),
    ("axios",    Ecosystem.NPM),
    ("typescript", Ecosystem.NPM),
    ("django",   Ecosystem.PYPI),
]


def main():
    rows = []
    t_all = time.time()
    for name, eco in TARGETS:
        print(f"\n=== {name} ({eco.value}) ===")
        t0 = time.time()
        try:
            info = check(name, eco)
            if not info.found:
                print(f"  not found")
                rows.append({"name": name, "ecosystem": eco.value,
                             "error": "registry not found"})
                continue
            ver = info.latest_version
            url = info.archive_urls.get(ver)
            ext = extract_all(name, eco, ver, url)
            if ext.error:
                print(f"  extract error: {ext.error}")
                rows.append({"name": name, "ecosystem": eco.value,
                             "version": ver, "error": ext.error})
                continue

            de = extract_dependencies(ext.source_files, eco)
            direct = de.direct_deps
            dev = de.dev_deps
            print(f"  direct={len(direct)} dev={len(dev)} "
                  f"errors={len(de.errors)}")

            t_dep = time.time()
            dep_results = analyze_dependencies(
                de, eco,
                max_depth=1, max_packages=30,
                attack_history_only=True,
            )
            elapsed_dep = time.time() - t_dep
            n_mal = sum(1 for r in dep_results if r.verdict == "MALICIOUS")
            n_sus = sum(1 for r in dep_results if r.verdict == "SUSPICIOUS")
            n_clean = sum(1 for r in dep_results if r.verdict == "CLEAN")
            n_skip = sum(1 for r in dep_results if r.verdict == "SKIPPED")
            print(f"  deps analyzed: {len(dep_results)} in {elapsed_dep:.1f}s")
            print(f"    MAL={n_mal}  SUS={n_sus}  CLEAN={n_clean}  SKIP={n_skip}")
            for r in dep_results:
                if r.verdict in ("MALICIOUS", "SUSPICIOUS"):
                    print(f"      ! {r.name} ({r.verdict}): {r.reason[:80]}")

            rows.append({
                "name": name, "ecosystem": eco.value,
                "version": ver,
                "direct_deps": len(direct),
                "dev_deps": len(dev),
                "deps_analyzed": len(dep_results),
                "mal": n_mal, "sus": n_sus, "clean": n_clean, "skip": n_skip,
                "dep_time_s": round(elapsed_dep, 2),
                "total_time_s": round(time.time() - t0, 2),
            })
        except Exception as e:
            print(f"  EXCEPTION: {type(e).__name__}: {str(e)[:120]}")
            rows.append({"name": name, "ecosystem": eco.value,
                         "error": str(e)[:200]})

    total = time.time() - t_all

    # 집계
    ok_rows = [r for r in rows if "error" not in r]
    if ok_rows:
        avg_direct = sum(r["direct_deps"] for r in ok_rows) / len(ok_rows)
        avg_analyzed = sum(r["deps_analyzed"] for r in ok_rows) / len(ok_rows)
        total_mal = sum(r["mal"] for r in ok_rows)
        total_sus = sum(r["sus"] for r in ok_rows)
        print(f"\n=== Summary ===")
        print(f"  packages OK    : {len(ok_rows)}/{len(rows)}")
        print(f"  avg direct deps: {avg_direct:.1f}")
        print(f"  avg analyzed   : {avg_analyzed:.1f}")
        print(f"  malicious deps : {total_mal} (total)")
        print(f"  suspicious deps: {total_sus} (total)")
        print(f"  total elapsed  : {total:.1f}s")

    out = ROOT / "scripts" / "eval_real_data" / "results_deps_recursion.json"
    out.write_text(json.dumps({
        "targets": rows,
        "summary": {
            "n_ok": len(ok_rows),
            "n_total": len(rows),
            "elapsed_total_s": round(total, 2),
        },
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nJSON saved -> {out}")


if __name__ == "__main__":
    main()
