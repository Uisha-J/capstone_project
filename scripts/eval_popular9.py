"""
인기 9 패키지 재측정 — Phase 1.3.

목적:
  - 9주차 보고서에서 다룬 popular×benign FP 회귀 검증.
  - 대상: django, numpy, pandas, flask, boto3 / lodash, react, webpack, requests
  - LLM 모드(stub / claude) 양쪽에서 verdict 비교.

흐름:
  1. PyPI / npm registry 에서 최신 sdist 또는 tarball 메타 fetch.
  2. 캐시(scripts/eval_real_data/cache/<eco>/benign/) 재사용.
  3. eval_real._evaluate() 로 동일한 매처 스택 실행.
  4. JSON + 콘솔 표 출력.

사용:
  python scripts/eval_popular9.py                      # stub mode
  python scripts/eval_popular9.py --llm claude         # 실 API 호출
  python scripts/eval_popular9.py --json out.json
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from eval_real import _evaluate, extract_archive  # noqa: E402
import eval_real_fetch  # noqa: E402
from eval_real_fetch import _download, _http_json  # noqa: E402

# 인기 패키지 (django/numpy 등) sdist 가 10MB 를 종종 넘김 — 한도 상향.
eval_real_fetch.MAX_ARCHIVE_SIZE = 30 * 1024 * 1024  # 30MB

TARGETS = [
    # (name, ecosystem)
    ("django",   "PyPI"),
    ("numpy",    "PyPI"),
    ("pandas",   "PyPI"),
    ("flask",    "PyPI"),
    ("boto3",    "PyPI"),
    ("lodash",   "npm"),
    ("react",    "npm"),
    ("webpack",  "npm"),
    ("requests", "PyPI"),
]


def _resolve_entry(name: str, ecosystem: str) -> dict | None:
    """레지스트리에서 패키지 메타 → _download 가 받을 entry dict."""
    try:
        if ecosystem == "PyPI":
            meta = _http_json(f"https://pypi.org/pypi/{name}/json")
            info = meta.get("info") or {}
            v = info.get("version") or ""
            urls = meta.get("urls") or []
            sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
            if not sdist:
                sdist = next((u for u in urls if u.get("filename")), None)
            if not sdist:
                return None
            return {
                "name": name, "version": v,
                "url": sdist["url"], "size": sdist.get("size", 0),
                "ecosystem": "PyPI", "source": "registry",
            }
        # npm
        meta = _http_json(f"https://registry.npmjs.org/{name}")
        latest = (meta.get("dist-tags") or {}).get("latest")
        if not latest:
            return None
        ver_meta = (meta.get("versions") or {}).get(latest) or {}
        tarball = (ver_meta.get("dist") or {}).get("tarball")
        if not tarball:
            return None
        return {
            "name": name, "version": latest,
            "url": tarball,
            "size": (ver_meta.get("dist") or {}).get("unpackedSize", 0),
            "ecosystem": "npm", "source": "registry",
        }
    except Exception as e:
        print(f"  resolve fail {name} ({ecosystem}): {e}", file=sys.stderr)
        return None


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--llm", choices=["stub", "claude"], default="stub",
        help="Stage 5 LLM 모드",
    )
    ap.add_argument(
        "--json",
        default=str(ROOT / "scripts" / "eval_real_data" / "results_popular9.json"),
        help="결과 저장 경로",
    )
    args = ap.parse_args()

    os.environ["PKGSENTINEL_LLM_MODE"] = args.llm
    if args.llm == "claude":
        from pkgsentinel import _dotenv as _ad
        _ad.load()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY not set.", file=sys.stderr)
            sys.exit(2)
        print("  LLM mode    : claude")
    else:
        print("  LLM mode    : stub")

    DATA_DIR = ROOT / "scripts" / "eval_real_data"

    results = []
    print(f"\n{'name':<10} {'eco':<5} {'version':<14} "
          f"{'verdict':<12} {'ok':<4} matchers")
    print("-" * 110)

    t0 = time.time()
    for name, ecosystem in TARGETS:
        entry = _resolve_entry(name, ecosystem)
        if entry is None:
            print(f"{name:<10} {ecosystem:<5} {'?':<14} "
                  f"{'RESOLVE_FAIL':<12} {'-':<4}")
            results.append({
                "name": name, "ecosystem": ecosystem,
                "verdict": "RESOLVE_FAIL", "expected": False,
            })
            continue
        meta = _download(entry, "benign")
        if meta is None:
            print(f"{name:<10} {ecosystem:<5} {entry['version']:<14} "
                  f"{'DOWNLOAD_FAIL':<12} {'-':<4}")
            results.append({
                "name": name, "ecosystem": ecosystem,
                "version": entry["version"],
                "verdict": "DOWNLOAD_FAIL", "expected": False,
            })
            continue

        archive_bytes = (DATA_DIR / meta.archive_path).read_bytes()
        files = extract_archive(archive_bytes, meta.archive_format, "benign")
        if not files:
            print(f"{name:<10} {ecosystem:<5} {meta.version:<14} "
                  f"{'NO_FILES':<12} {'-':<4}")
            results.append({
                "name": name, "ecosystem": ecosystem,
                "version": meta.version, "verdict": "NO_FILES",
                "expected": False,
            })
            continue

        fixture_meta = {
            "name": name, "ecosystem": ecosystem,
            "version": meta.version, "label": "benign",
            "source": "registry",
        }
        r = _evaluate(fixture_meta, files)
        mr = r.matchers
        m = (f"ind={mr.get('ind_47',0)}({mr.get('ind_47_high',0)}H) "
             f"seq={mr.get('seq_pattern',0)}({mr.get('seq_high',0)}H) "
             f"taint={mr.get('taint_flows',0)} "
             f"llm={(mr.get('llm_stub','-') or '-')[:4]}")
        ok = "OK" if r.expected else "FAIL"
        print(f"{name:<10} {ecosystem:<5} {r.version:<14} "
              f"{r.verdict:<12} {ok:<4} {m}")
        results.append({
            "name": r.name, "ecosystem": r.ecosystem,
            "version": r.version, "verdict": r.verdict,
            "expected": r.expected, "matchers": r.matchers,
            "elapsed_s": r.elapsed_s, "n_files": r.n_files,
            "n_python": r.n_python, "n_js": r.n_js,
        })

    elapsed = time.time() - t0

    # 집계
    ok_count = sum(1 for r in results if r.get("expected"))
    n = len(results)
    print()
    print(f"=== Summary ({args.llm}) ===")
    print(f"  PASS  : {ok_count}/{n}")
    print(f"  FAIL  : {n - ok_count}/{n}")
    fp = [r["name"] for r in results
          if r.get("verdict") not in ("CLEAN", "RESOLVE_FAIL", "DOWNLOAD_FAIL", "NO_FILES")
          and not r.get("expected", False)]
    if fp:
        print(f"  FP    : {fp}")
    print(f"  Elapsed: {elapsed:.1f}s")

    out_path = Path(args.json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "llm_mode": args.llm,
        "results": results,
        "summary": {
            "n": n, "pass": ok_count, "fail": n - ok_count,
            "fp_names": fp,
            "elapsed_s": round(elapsed, 2),
        },
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nJSON saved -> {out_path}")


if __name__ == "__main__":
    main()
