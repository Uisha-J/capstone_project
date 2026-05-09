"""
indicator_fp_table_real.py — 실 패키지 코퍼스에서 47-indicator FP/TP 통계.

목적
----
`indicator_fp_table.py` (합성 fixture) 의 자연 확장.
실 PyPI/npm 패키지를 레지스트리에서 직접 다운로드 + 매처(Stage 1B/2/4C)만 실행.
풀 파이프라인 / sqlcipher / sentence-transformers / LLM 미사용 — Windows 포터블.

입력
----
manifest JSON. 형식:
    {
      "fixtures": [
        {"name": "django", "ecosystem": "PyPI", "version": "5.0.0",
         "label": "benign", "source": "popular_pypi"},
        ...
      ]
    }
호환: scripts/eval_real_data/fixtures.json 그대로 사용 가능 (label, name,
      ecosystem, version 필드만 읽음).

출력
----
- 사람용: <output_md> (기본 docs/2026-05-06-indicator-fp-real.md)
- 기계용: <output_json> (기본 scripts/eval_real_data/indicator_fp_real_results.json)
  resume 용 — 같은 캐시/출력 경로 재실행 시 이전 hits 캐시 그대로 사용.

캐시
----
- 아카이브: scripts/eval_real_data/cache_lite/<ecosystem>/<name>-<version>.tgz|zip
  (기존 cache/ 와 분리)
- 결과: 위 output_json 에 fixture별 hits set 저장. 다음 실행 시 skip.

사용
----
    # 기본 (eval_real_data/fixtures.json)
    python scripts/indicator_fp_table_real.py

    # 인기 패키지 benign 매니페스트
    python scripts/indicator_fp_table_real.py \\
        --manifest scripts/eval_real_data/popular_benign_manifest.json \\
        --output-md docs/2026-05-06-indicator-fp-popular-benign.md

    # 샘플링
    python scripts/indicator_fp_table_real.py --max 50 --label benign

    # 강제 재분석 (캐시 무시)
    python scripts/indicator_fp_table_real.py --refresh
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pkgsentinel.knowledge.malicious_indicators import INDICATORS  # noqa: E402
from pkgsentinel.schema import Ecosystem  # noqa: E402
from pkgsentinel.stages.indicator_matcher import match_all  # noqa: E402
from pkgsentinel.stages.stage1_entry_point import EntryFile  # noqa: E402
from pkgsentinel.stages.stage1b_full_source import (  # noqa: E402
    FullSourceFile,
    extract_all,
)
from pkgsentinel.stages.stage2_behavior import _analyze_python  # noqa: E402


# ─────────────── 레지스트리 조회 ───────────────

USER_AGENT = "ai-slopsq/2.0 indicator-fp-real"
TIMEOUT = 30


def _http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


def _resolve_archive_url_pypi(name: str, version: str) -> tuple[str, str]:
    """Returns (url, archive_format). Format: 'tar.gz' | 'zip' (wheel)."""
    meta = _http_json(f"https://pypi.org/pypi/{name}/{version}/json")
    urls = meta.get("urls") or []
    # Prefer sdist (.tar.gz) — wheel 은 컴파일된 바이너리 위주라 소스 분석엔 sdist 가 정공
    sdist = next(
        (u for u in urls if u.get("packagetype") == "sdist"), None
    )
    if sdist:
        return sdist["url"], "tar.gz"
    # fallback: wheel 이라도 받음
    wheel = next(
        (u for u in urls if u.get("packagetype") == "bdist_wheel"), None
    )
    if wheel:
        return wheel["url"], "zip"
    raise RuntimeError(f"no archive URL for PyPI {name}=={version}")


def _resolve_archive_url_npm(name: str, version: str) -> tuple[str, str]:
    meta = _http_json(f"https://registry.npmjs.org/{name}/{version}")
    tarball = (meta.get("dist") or {}).get("tarball")
    if not tarball:
        raise RuntimeError(f"no tarball URL for npm {name}@{version}")
    return tarball, "tar.gz"


def _resolve_archive_url(name: str, ecosystem: str, version: str) -> tuple[str, str]:
    if ecosystem.lower() in ("pypi",):
        return _resolve_archive_url_pypi(name, version)
    if ecosystem.lower() in ("npm",):
        return _resolve_archive_url_npm(name, version)
    raise ValueError(f"unsupported ecosystem: {ecosystem}")


# ─────────────── 캐시 ───────────────

def _cache_path(cache_dir: Path, name: str, ecosystem: str,
                version: str, fmt: str) -> Path:
    safe_name = name.replace("/", "_")
    eco = ecosystem.lower()
    return cache_dir / eco / f"{safe_name}-{version}.{fmt}"


def _download_to_cache(url: str, dest: Path) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read()
    dest.write_bytes(data)
    return len(data)


# ─────────────── 단일 fixture 분석 ───────────────

def analyze_fixture(
    name: str,
    ecosystem: str,
    version: str,
    cache_dir: Path,
    refresh: bool = False,
) -> dict[str, Any]:
    """1개 fixture 실행. Returns dict with: hits (set), error, n_files."""
    eco_enum = (
        Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    )
    try:
        url, fmt = _resolve_archive_url(name, ecosystem, version)
    except Exception as e:
        return {"hits": set(), "error": f"resolve_url_fail: {e}", "n_files": 0}

    cache_file = _cache_path(cache_dir, name, ecosystem, version, fmt)
    if refresh or not cache_file.exists():
        try:
            _download_to_cache(url, cache_file)
        except Exception as e:
            return {"hits": set(), "error": f"download_fail: {e}", "n_files": 0}

    # extract_all 은 archive_url 을 받아 다시 다운로드함 → 캐시 재사용을 위해
    # file:// URL 로 우회. urllib 가 file:// 지원함.
    try:
        local_url = cache_file.resolve().as_uri()
        result = extract_all(
            package=name, ecosystem=eco_enum,
            version=version, archive_url=local_url,
        )
    except Exception as e:
        return {"hits": set(), "error": f"extract_fail: {e}", "n_files": 0}

    if result.error:
        return {"hits": set(), "error": f"extract_err: {result.error}",
                "n_files": 0}
    if not result.source_files:
        return {"hits": set(), "error": None, "n_files": 0}

    # Stage 2: behavior — Python 만 (JS 는 indicator_matcher 가 regex 만 사용)
    behavior_files = []
    for sf in result.source_files:
        if sf.language != "python":
            continue
        ef = EntryFile(
            path=sf.path, basename=sf.basename, content=sf.content,
            size=sf.size, language=sf.language,
        )
        try:
            behavior_files.append(_analyze_python(ef))
        except Exception:
            continue

    # Stage 4C: matcher
    rpt = match_all(
        behavior_files=behavior_files,
        source_files=result.source_files,
        package_name=name,
        description="",  # 메타 fixture 에 없음 — MET 카테고리는 거의 안 잡힘
        author="",
        declared_deps=[],
    )
    return {
        "hits": {h.indicator.code for h in rpt.hits},
        "error": None,
        "n_files": len(result.source_files),
    }


# ─────────────── 매니페스트 로드 ───────────────

def load_manifest(path: Path) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    fixtures = raw.get("fixtures") if isinstance(raw, dict) else raw
    out = []
    for fx in fixtures:
        out.append({
            "name": fx["name"],
            "ecosystem": fx["ecosystem"],
            "version": fx.get("version") or fx.get("ver") or "",
            "label": fx.get("label", "unknown"),
            "source": fx.get("source", ""),
        })
    return out


# ─────────────── 결과 캐시 (resume) ───────────────

def load_results_cache(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.get("per_fixture", {}).items()}


def save_results_cache(path: Path, per_fixture: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "per_fixture": per_fixture,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                    encoding="utf-8")


def _fixture_key(fx: dict) -> str:
    return f"{fx['ecosystem']}::{fx['name']}::{fx['version']}"


# ─────────────── 집계 + 보고서 ───────────────

def aggregate(per_fixture: dict[str, dict],
              fixtures: list[dict]) -> dict[str, Any]:
    # 라벨별로 발화 횟수 집계
    label_count = Counter()
    indicator_fires = defaultdict(lambda: Counter())  # code -> {label: count}
    errors_by_label = Counter()

    for fx in fixtures:
        key = _fixture_key(fx)
        rec = per_fixture.get(key)
        if rec is None:
            continue
        label = fx["label"]
        label_count[label] += 1
        if rec.get("error"):
            errors_by_label[label] += 1
            continue
        for code in rec.get("hits", []):
            indicator_fires[code][label] += 1

    return {
        "label_count": dict(label_count),
        "indicator_fires": {k: dict(v) for k, v in indicator_fires.items()},
        "errors_by_label": dict(errors_by_label),
    }


def build_rows(agg: dict) -> list[dict]:
    """indicator code -> 행 (TP/FP/rates/discrim)."""
    n_mal = agg["label_count"].get("malicious", 0)
    n_ben = agg["label_count"].get("benign", 0)
    rows = []
    for code, ind in INDICATORS.items():
        fires = agg["indicator_fires"].get(code, {})
        tp = fires.get("malicious", 0)
        fp = fires.get("benign", 0)
        tp_rate = tp / n_mal if n_mal else 0.0
        fp_rate = fp / n_ben if n_ben else 0.0
        rows.append({
            "code": code,
            "name": ind.name,
            "category": ind.category.value,
            "severity": ind.severity.value,
            "tp": tp,
            "fp": fp,
            "tp_rate": tp_rate,
            "fp_rate": fp_rate,
            "discrimination": tp_rate - fp_rate,
        })
    return rows


def render_markdown(
    rows: list[dict],
    agg: dict,
    manifest_path: Path,
    n_total: int,
    n_processed: int,
) -> str:
    n_mal = agg["label_count"].get("malicious", 0)
    n_ben = agg["label_count"].get("benign", 0)
    err = agg["errors_by_label"]

    high_fp = sorted(
        [r for r in rows if r["fp_rate"] >= 0.30],
        key=lambda x: -x["fp_rate"],
    )
    medium_fp = sorted(
        [r for r in rows if 0.15 <= r["fp_rate"] < 0.30],
        key=lambda x: -x["fp_rate"],
    )
    low_fp = sorted(
        [r for r in rows if 0.05 <= r["fp_rate"] < 0.15],
        key=lambda x: -x["fp_rate"],
    )
    workhorse = sorted(
        [r for r in rows if r["tp_rate"] >= 0.10 and r["fp_rate"] == 0.0],
        key=lambda x: -x["tp_rate"],
    )
    zero_tp = [r for r in rows if r["tp"] == 0]

    md = []
    md.append("# 47-Indicator FP / TP 통계표 — 실 패키지 코퍼스")
    md.append("")
    md.append(f"> 생성일: 2026-05-06  ")
    md.append(f"> 매니페스트: `{manifest_path.relative_to(ROOT) if manifest_path.is_relative_to(ROOT) else manifest_path}`  ")
    md.append(
        f"> 코퍼스: malicious={n_mal}, benign={n_ben} "
        f"(매니페스트 총 {n_total}, 처리 {n_processed})  "
    )
    md.append(
        f"> 적용 범위: `indicator_matcher.match_all` 만 — "
        f"Stage 0/3/4D/4E/5/6, LLM, threat-intel, sentence-transformers 우회"
    )
    if err:
        md.append(f"> 에러: {err}")
    md.append("")

    md.append("## 핵심 요약")
    md.append("")
    md.append(f"- **FP rate ≥ 30%** (STANDALONE_WEAK 강력 후보): {len(high_fp)}개")
    md.append(f"- **FP rate 15~30%** (combo 강화 후보): {len(medium_fp)}개")
    md.append(f"- **FP rate 5~15%** (관찰): {len(low_fp)}개")
    md.append(f"- **고변별 workhorse** (TP≥10% + FP=0): {len(workhorse)}개")
    md.append(f"- **TP=0** (코퍼스에서 미발화): {len(zero_tp)}개")
    md.append("")

    if high_fp:
        md.append("## 1. FP rate ≥ 30% — 즉시 STANDALONE_WEAK 또는 임계 상향")
        md.append("")
        md.append("benign 에서 자주 발화. 단독 발화로는 의심 신호로 채택하지 말 것.")
        md.append("")
        md.append("| Code | Name | Sev | TP | FP | FP rate | TP rate | Discrim |")
        md.append("|---|---|---|---|---|---|---|---|")
        for r in high_fp:
            md.append(
                f"| `{r['code']}` | {r['name']} | {r['severity']} | "
                f"{r['tp']} | {r['fp']} | {r['fp_rate']:.2f} | "
                f"{r['tp_rate']:.2f} | {r['discrimination']:+.2f} |"
            )
        md.append("")

    if medium_fp:
        md.append("## 2. FP rate 15~30% — risk_combo 강화 후보")
        md.append("")
        md.append("단독으로는 약함. 다른 indicator 와 동시 발화일 때만 escalation.")
        md.append("")
        md.append("| Code | Name | Sev | TP | FP | FP rate | TP rate | Discrim |")
        md.append("|---|---|---|---|---|---|---|---|")
        for r in medium_fp:
            md.append(
                f"| `{r['code']}` | {r['name']} | {r['severity']} | "
                f"{r['tp']} | {r['fp']} | {r['fp_rate']:.2f} | "
                f"{r['tp_rate']:.2f} | {r['discrimination']:+.2f} |"
            )
        md.append("")

    if low_fp:
        md.append("## 3. FP rate 5~15% — 관찰")
        md.append("")
        md.append("| Code | Name | Sev | TP | FP | FP rate | TP rate | Discrim |")
        md.append("|---|---|---|---|---|---|---|---|")
        for r in low_fp:
            md.append(
                f"| `{r['code']}` | {r['name']} | {r['severity']} | "
                f"{r['tp']} | {r['fp']} | {r['fp_rate']:.2f} | "
                f"{r['tp_rate']:.2f} | {r['discrimination']:+.2f} |"
            )
        md.append("")

    md.append("## 4. 고변별 Workhorse (TP rate ≥10% + FP=0)")
    md.append("")
    if workhorse:
        md.append("매처 핵심 신호원. 약화/제거 금지.")
        md.append("")
        md.append("| Code | Name | Sev | TP | FP | TP rate | Discrim |")
        md.append("|---|---|---|---|---|---|---|")
        for r in workhorse:
            md.append(
                f"| `{r['code']}` | {r['name']} | {r['severity']} | "
                f"{r['tp']} | {r['fp']} | {r['tp_rate']:.2f} | "
                f"{r['discrimination']:+.2f} |"
            )
    else:
        md.append("(없음 — 코퍼스에 악성이 적거나 매처 회복률 부족)")
    md.append("")

    md.append("## 5. 전체 47-indicator 표 (코드 순)")
    md.append("")
    md.append("| Code | Name | Sev | Cat | TP | FP | TP rate | FP rate | Discrim |")
    md.append("|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda x: x["code"]):
        md.append(
            f"| `{r['code']}` | {r['name']} | {r['severity']} | "
            f"{r['category']} | {r['tp']} | {r['fp']} | "
            f"{r['tp_rate']:.2f} | {r['fp_rate']:.2f} | "
            f"{r['discrimination']:+.2f} |"
        )
    md.append("")

    md.append("## 6. 다음 단계")
    md.append("")
    if high_fp:
        codes = ", ".join(f"`{r['code']}`" for r in high_fp)
        md.append(
            f"1. {codes} 를 `src/pkgsentinel/evidence/converters.py` 의 "
            "`STANDALONE_WEAK_INDICATORS` 에 추가 → 9-패키지 smoke 재측정"
        )
    if medium_fp:
        codes = ", ".join(f"`{r['code']}`" for r in medium_fp)
        md.append(
            f"2. {codes} 를 `pipeline.py` 의 `RISK_COMBO_TRIGGER_CODES` 에서 검토 "
            "(combo 동반 조건이 약하면 강화)"
        )
    if zero_tp:
        md.append(
            f"3. TP=0 indicator {len(zero_tp)}개 — 매처 hint/regex 점검 또는 "
            "코퍼스에 해당 공격 패턴이 부재한지 확인"
        )
    md.append("")

    return "\n".join(md)


# ─────────────── main ───────────────

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--manifest",
        default=str(ROOT / "scripts" / "eval_real_data" / "fixtures.json"),
    )
    p.add_argument("--max", type=int, default=0,
                   help="처리할 fixture 수 상한 (0=무제한)")
    p.add_argument("--label", choices=["all", "benign", "malicious"],
                   default="all")
    p.add_argument(
        "--cache-dir",
        default=str(ROOT / "scripts" / "eval_real_data" / "cache_lite"),
    )
    p.add_argument(
        "--results-json",
        default=str(ROOT / "scripts" / "eval_real_data" / "indicator_fp_real_results.json"),
    )
    p.add_argument(
        "--output-md",
        default=str(ROOT / "docs" / "2026-05-06-indicator-fp-real.md"),
    )
    p.add_argument("--refresh", action="store_true",
                   help="아카이브 + 결과 캐시 무시")
    p.add_argument("--progress-every", type=int, default=10)
    args = p.parse_args()

    manifest_path = Path(args.manifest).resolve()
    cache_dir = Path(args.cache_dir).resolve()
    results_json = Path(args.results_json).resolve()
    output_md = Path(args.output_md).resolve()

    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    fixtures_all = load_manifest(manifest_path)
    if args.label != "all":
        fixtures = [f for f in fixtures_all if f["label"] == args.label]
    else:
        fixtures = fixtures_all
    if args.max:
        fixtures = fixtures[: args.max]

    n_total = len(fixtures_all)
    n_target = len(fixtures)
    print(
        f"[manifest] total={n_total} → label={args.label} → "
        f"max={args.max or 'all'} → 처리 대상={n_target}"
    )

    # resume-cache
    per_fixture = {} if args.refresh else load_results_cache(results_json)

    skipped = 0
    fetched = 0
    failed = 0
    t0 = time.time()

    for i, fx in enumerate(fixtures, 1):
        key = _fixture_key(fx)
        if not args.refresh and key in per_fixture:
            skipped += 1
        else:
            res = analyze_fixture(
                fx["name"], fx["ecosystem"], fx["version"],
                cache_dir=cache_dir, refresh=args.refresh,
            )
            # set 직렬화
            per_fixture[key] = {
                "hits": sorted(res["hits"]),
                "error": res["error"],
                "n_files": res["n_files"],
                "label": fx["label"],
            }
            if res["error"]:
                failed += 1
            else:
                fetched += 1

        if i % args.progress_every == 0 or i == n_target:
            elapsed = time.time() - t0
            rate = (fetched + skipped) / max(elapsed, 0.001)
            eta = (n_target - i) / max(rate, 0.001)
            print(
                f"  [{i}/{n_target}] cache_hit={skipped} fetched={fetched} "
                f"failed={failed} elapsed={elapsed:.0f}s eta={eta:.0f}s"
            )
            # 중간 저장 — 인터럽트 대비
            save_results_cache(results_json, per_fixture)

    save_results_cache(results_json, per_fixture)

    agg = aggregate(per_fixture, fixtures)
    rows = build_rows(agg)
    md = render_markdown(rows, agg, manifest_path, n_total, n_target)

    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(md, encoding="utf-8")

    n_mal = agg["label_count"].get("malicious", 0)
    n_ben = agg["label_count"].get("benign", 0)
    print()
    print(f"=== 결과 ===")
    print(f"  처리: {fetched + skipped}/{n_target}  (실패: {failed})")
    print(f"  benign={n_ben}, malicious={n_mal}")
    high_fp = [r for r in rows if r["fp_rate"] >= 0.30]
    print(f"  FP rate ≥ 30%: {len(high_fp)} 개")
    for r in sorted(high_fp, key=lambda x: -x["fp_rate"])[:10]:
        print(f"    {r['code']:8s} FP={r['fp']}/{n_ben} ({r['fp_rate']:.0%})  "
              f"TP={r['tp']}/{n_mal}  {r['name']}")
    print()
    print(f"  Wrote:")
    print(f"    {output_md.relative_to(ROOT)}")
    print(f"    {results_json.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
