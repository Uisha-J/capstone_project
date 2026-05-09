"""
인디케이터별 FP / TP 통계 표 생성기.

목적
----
Handoff (`docs/2026-05-06-todo.md`) 의 "미해결 의문 1번" 해결:
EXS-001, DEF-005, EXM-005 등이 합법/악성 패키지에서 얼마나 발화하는지 통계.
이 표가 있으면 STANDALONE_WEAK_INDICATORS 명단을 데이터 기반으로 조정 가능.

방법
----
1. `scripts/eval_synthetic.py` 의 인라인 fixture (MAL=100, BEN=20) 를 입력
2. `pkgsentinel.stages.indicator_matcher.match_all` 만 적용
   (Stage 0/3/4D/4E/5/6, LLM, registry, threat-intel, sentence-transformers
    전부 우회 — stdlib + indicator catalog 만 의존)
3. 인디케이터 코드별로 malicious 발화 수(TP) / benign 발화 수(FP) 집계
4. FP rate, TP rate, discrimination(=TP_rate-FP_rate) 계산
5. Markdown 표 + 요약을 `docs/2026-05-06-indicator-fp-table.md` 로 저장

한계
----
- benign N=20 은 통계적으로 작음. 실 패키지 데이터
  (`scripts/eval_real_data/fixtures.json`, N=550) 에서 재측정 시 신뢰도 ↑.
  실 fixture cache 는 macOS 작업 환경에 있고 Windows 클론에서는 미존재.
- expected_indicator 라벨이 fixture 에 없어 "정답 indicator" 검증은 불가.
  단순 발화 빈도만 봄.

실행
----
    python scripts/indicator_fp_table.py
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pkgsentinel.knowledge.malicious_indicators import INDICATORS  # noqa: E402
from pkgsentinel.stages.indicator_matcher import match_all  # noqa: E402
from pkgsentinel.stages.stage1_entry_point import EntryFile  # noqa: E402
from pkgsentinel.stages.stage1b_full_source import FullSourceFile  # noqa: E402
from pkgsentinel.stages.stage2_behavior import _analyze_python  # noqa: E402

import eval_synthetic as es  # noqa: E402


# ─────────────── 언어 감지 (stage1 의 _detect_language 와 동일 정책) ───────────────

_PY_EXT = {".py"}
_JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}


def _detect_lang(path: str) -> str:
    p = Path(path)
    if p.suffix in _PY_EXT:
        return "python"
    if p.suffix in _JS_EXT:
        return "javascript"
    if p.suffix == ".json":
        return "json"
    return "unknown"


# ─────────────── 한 fixture 에 매처 적용 ───────────────

def run_fixture(fx) -> set[str]:
    """fixture 의 file dict 를 stage1B/2 입력으로 빌드 후 match_all 호출.

    Returns: 발화한 indicator 코드 집합.
    """
    behavior_files = []
    source_files = []
    for path, content in fx.files.items():
        lang = _detect_lang(path)
        sf = FullSourceFile(
            path=path,
            basename=Path(path).name,
            content=content,
            size=len(content),
            language=lang,
            tier=1,
        )
        source_files.append(sf)
        if lang == "python":
            ef = EntryFile(
                path=path,
                basename=Path(path).name,
                content=content,
                size=len(content),
                language=lang,
            )
            behavior_files.append(_analyze_python(ef))

    # 메타데이터는 fixture 에 없으므로 비움 — MET 카테고리는 거의 안 잡힘
    rpt = match_all(
        behavior_files=behavior_files,
        source_files=source_files,
        package_name=fx.name,
        description=fx.description if hasattr(fx, "description") else "",
        author="",
        declared_deps=[],
    )
    return {h.indicator.code for h in rpt.hits}


# ─────────────── 메인 ───────────────

def main() -> int:
    n_mal = len(es.MAL_FIXTURES)
    n_ben = len(es.BEN_FIXTURES)

    print(f"Running matcher on {n_mal} malicious + {n_ben} benign fixtures...")
    tp_counter: Counter[str] = Counter()  # 발화 in malicious
    fp_counter: Counter[str] = Counter()  # 발화 in benign

    for i, fx in enumerate(es.MAL_FIXTURES, 1):
        for code in run_fixture(fx):
            tp_counter[code] += 1
        if i % 25 == 0:
            print(f"  malicious {i}/{n_mal}")
    for i, fx in enumerate(es.BEN_FIXTURES, 1):
        for code in run_fixture(fx):
            fp_counter[code] += 1

    # 행 빌드
    rows: list[dict] = []
    for code, ind in INDICATORS.items():
        tp = tp_counter[code]
        fp = fp_counter[code]
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

    rows_by_code = sorted(rows, key=lambda r: r["code"])
    rows_by_discrim = sorted(rows, key=lambda r: (r["discrimination"], -r["fp"]))
    rows_by_fp = sorted(rows, key=lambda r: (-r["fp_rate"], -r["fp"], r["code"]))
    # workhorse: 높은 TP + 0 FP 우선
    rows_by_workhorse = sorted(
        rows, key=lambda r: (-r["discrimination"], -r["tp"])
    )

    high_fp = [r for r in rows if r["fp_rate"] >= 0.30]
    medium_fp = [r for r in rows if 0.15 <= r["fp_rate"] < 0.30]
    zero_tp = [r for r in rows if r["tp"] == 0]
    zero_both = [r for r in rows if r["tp"] == 0 and r["fp"] == 0]
    workhorse = [r for r in rows if r["tp_rate"] >= 0.10 and r["fp_rate"] == 0]

    # Markdown 빌드
    md: list[str] = []
    md.append("# 47-Indicator FP / TP 통계표")
    md.append("")
    md.append("> 생성일: 2026-05-06  ")
    md.append(
        f"> 코퍼스: `scripts/eval_synthetic.py` 인라인 fixture "
        f"(malicious={n_mal}, benign={n_ben})  "
    )
    md.append(
        "> 적용 범위: `indicator_matcher.match_all` 만 — Stage 0/3/4D/4E/5/6, "
        "LLM, registry, threat-intel 전부 우회  "
    )
    md.append(
        "> 한계: benign N=20 은 통계적으로 작음. "
        "실 패키지 데이터(`eval_real_data/fixtures.json`, N=550) 에 동일 분석 적용 시 신뢰도 ↑"
    )
    md.append("")
    md.append("## 핵심 요약")
    md.append("")
    md.append(
        f"- 47 인디케이터 중 **TP=0 (코퍼스에서 한번도 안 잡힘)**: "
        f"{len(zero_tp)}개"
    )
    md.append(f"  - 그 중 **FP=0 까지 포함한 완전 미발화**: {len(zero_both)}개")
    md.append(
        f"- **FP rate ≥ 30%** (STANDALONE_WEAK 후보): {len(high_fp)}개"
    )
    md.append(
        f"- **FP rate 15~30%** (관찰 필요): {len(medium_fp)}개"
    )
    md.append(
        f"- **고변별 workhorse** (TP rate ≥10% + FP=0): {len(workhorse)}개"
    )
    md.append("")

    # 0. 핵심 발견 — 합성 vs 실 코퍼스 갭
    md.append("## 0. 핵심 발견 (합성 코퍼스 vs 실 코퍼스 갭)")
    md.append("")
    md.append(
        "**합성 benign 코퍼스(N=20)에서는 indicator FP 가 거의 0** — "
        "MET-004(설명 짧음, 1/20=5%) 단 1건. "
        "그러나 직전 세션의 9-패키지 smoke test (django/numpy/pandas/flask/boto3 등 "
        "실제 인기 PyPI/npm 패키지) 에서는 8/9 가 HIGH_RISK 이상으로 잡힘."
    )
    md.append("")
    md.append(
        "**해석**: indicator 자체가 FP-prone 한 것이 아니라, "
        "합성 benign fixture 가 *너무 깨끗*해서 실제 인기 패키지의 회색지대 "
        "(테스트용 `requests.post`, 빌드 스크립트 `subprocess`, 설정 파일의 "
        "환경변수 사용 등)을 대표하지 못함. "
        "**즉, 본 표의 FP rate 는 lower bound 이며 실제 운영 FP rate 추정에는 부적합**."
    )
    md.append("")
    md.append(
        "**다음 작업의 정렬 방향**:"
    )
    md.append(
        "1. 실 fixture (`scripts/eval_real_data/fixtures.json`, N=550) 에서 "
        "indicator code list 를 결과 schema 에 추가 → 본 스크립트와 동일 분석 적용 → "
        "**현실적 FP rate 표** 산출."
    )
    md.append(
        "2. 그 표를 근거로 `STANDALONE_WEAK_INDICATORS` / `RISK_COMBO_TRIGGER_CODES` "
        "조정. 합성 코퍼스만으로는 어느 indicator 를 약화/제거할지 결정 불가."
    )
    md.append("")

    # 0.5 Workhorse
    md.append("## 0.5 고변별 Workhorse Indicators (TP rate ≥10%, FP=0)")
    md.append("")
    md.append(
        "현 합성 코퍼스에서 가장 안정적으로 악성 신호를 분리하는 indicator. "
        "약화/제거 절대 금지 — 매처의 핵심 신호원."
    )
    md.append("")
    if workhorse:
        md.append("| Code | Name | Sev | TP | FP | TP rate | Discrim |")
        md.append("|---|---|---|---|---|---|---|")
        for r in sorted(workhorse, key=lambda x: -x["tp_rate"]):
            md.append(
                f"| `{r['code']}` | {r['name']} | {r['severity']} | "
                f"{r['tp']} | {r['fp']} | {r['tp_rate']:.2f} | "
                f"{r['discrimination']:+.2f} |"
            )
    else:
        md.append("(없음 — 매처가 의미 있는 신호를 거의 잡지 못함을 시사. 점검 필요.)")
    md.append("")

    # 1. FP rate 높은 순
    md.append("## 1. FP rate 높은 순 (실제 발화 indicator 만)")
    md.append("")
    md.append("benign 픽스처에서 자주 발화 → 합법 도구의 정상 행위를 의심으로 잡고 있을 가능성.")
    md.append("")
    md.append("| 순위 | Code | Name | Sev | TP | FP | FP rate | TP rate | Discrim |")
    md.append("|---|---|---|---|---|---|---|---|---|")
    rank = 0
    for r in rows_by_fp:
        if r["fp"] == 0:
            break
        rank += 1
        md.append(
            f"| {rank} | `{r['code']}` | {r['name']} | {r['severity']} | "
            f"{r['tp']} | {r['fp']} | {r['fp_rate']:.2f} | "
            f"{r['tp_rate']:.2f} | {r['discrimination']:+.2f} |"
        )
    if rank == 0:
        md.append("| — | (FP=0 인 indicator 만 존재 — 모든 발화 indicator 가 benign 에서 발화 안 함) | | | | | | | |")
    md.append("")

    # 2. Discrimination 낮은 순
    md.append("## 2. Discrimination 낮은 순 (TP=0 제외, 변별력 약한 순)")
    md.append("")
    md.append("Discrimination = TP_rate − FP_rate. 0 에 가까울수록 무작위, 음수면 benign 에서 더 자주 발화.")
    md.append("")
    md.append("| 순위 | Code | Name | Sev | Cat | TP | FP | TP rate | FP rate | Discrim |")
    md.append("|---|---|---|---|---|---|---|---|---|---|")
    shown = 0
    for r in rows_by_discrim:
        if r["tp"] == 0 and r["fp"] == 0:
            continue
        shown += 1
        md.append(
            f"| {shown} | `{r['code']}` | {r['name']} | {r['severity']} | "
            f"{r['category']} | {r['tp']} | {r['fp']} | "
            f"{r['tp_rate']:.2f} | {r['fp_rate']:.2f} | {r['discrimination']:+.2f} |"
        )
        if shown >= 20:
            break
    md.append("")

    # 3. 권장 조치
    md.append("## 3. 권장 조치")
    md.append("")

    md.append("### 3.1 FP rate ≥ 30% — STANDALONE_WEAK_INDICATORS 후보")
    md.append("")
    if high_fp:
        md.append("이 indicator 들은 단독 발화로는 의심 신호 강도가 부족.")
        md.append(
            "`src/pkgsentinel/evidence/converters.py:17` 의 "
            "`STANDALONE_WEAK_INDICATORS` 에 포함되어 있는지 확인하고, "
            "없으면 추가 검토."
        )
        md.append("")
        for r in sorted(high_fp, key=lambda x: -x["fp_rate"]):
            md.append(
                f"- `{r['code']}` ({r['name']}): "
                f"FP={r['fp']}/{n_ben} ({r['fp_rate']:.0%}), "
                f"TP={r['tp']}/{n_mal} ({r['tp_rate']:.0%}), "
                f"discrim={r['discrimination']:+.2f}"
            )
    else:
        md.append("현 코퍼스에서 FP rate ≥ 30% 인 indicator 없음.")
    md.append("")

    md.append("### 3.2 FP rate 15 ~ 30% — risk_combo trigger 검토 대상")
    md.append("")
    if medium_fp:
        md.append(
            "단독으로는 약하지만 risk_combo escalation trigger 에 들어 있다면, "
            "다른 indicator 와의 동시 발화 조건을 강화해야 함. "
            "(`pipeline.py` 의 `RISK_COMBO_TRIGGER_CODES` 참조)"
        )
        md.append("")
        for r in sorted(medium_fp, key=lambda x: -x["fp_rate"]):
            md.append(
                f"- `{r['code']}` ({r['name']}): "
                f"FP={r['fp']}/{n_ben} ({r['fp_rate']:.0%}), "
                f"TP={r['tp']}/{n_mal} ({r['tp_rate']:.0%}), "
                f"discrim={r['discrimination']:+.2f}"
            )
    else:
        md.append("현 코퍼스에서 FP rate 15~30% 구간 indicator 없음.")
    md.append("")

    md.append("### 3.3 TP=0 — 코퍼스 부족 가능성 (실 데이터 재측정 권장)")
    md.append("")
    if zero_tp:
        md.append(
            "현 합성 코퍼스(N=100)에서 한 번도 발화 안 한 indicator. "
            "실제 악성 패키지 코퍼스(`eval_real_data/fixtures.json`)에서 재측정 필요."
        )
        md.append("")
        # 카테고리별로 그룹화
        from collections import defaultdict
        by_cat = defaultdict(list)
        for r in zero_tp:
            by_cat[r["category"]].append(r)
        for cat in sorted(by_cat):
            codes = ", ".join(f"`{r['code']}`" for r in by_cat[cat])
            md.append(f"- **{cat}**: {codes}")
    else:
        md.append("모든 indicator 가 적어도 1번 이상 발화. (좋은 신호)")
    md.append("")

    # 4. 전체 표
    md.append("## 4. 전체 47-indicator 표 (코드 순)")
    md.append("")
    md.append("| Code | Name | Sev | Cat | TP | FP | TP rate | FP rate | Discrim |")
    md.append("|---|---|---|---|---|---|---|---|---|")
    for r in rows_by_code:
        md.append(
            f"| `{r['code']}` | {r['name']} | {r['severity']} | "
            f"{r['category']} | {r['tp']} | {r['fp']} | "
            f"{r['tp_rate']:.2f} | {r['fp_rate']:.2f} | "
            f"{r['discrimination']:+.2f} |"
        )
    md.append("")

    # 5. 다음 단계
    md.append("## 5. 다음 단계")
    md.append("")
    md.append(
        "1. 실 패키지 corpus 에서 재측정 — `eval_real.py` 출력에 indicator code list 를 "
        "추가하도록 schema 확장 후, 본 스크립트와 동등한 분석을 `eval_real_data/fixtures.json` "
        "(N=550) 에 적용."
    )
    md.append(
        "2. 위 §3.1 후보를 `STANDALONE_WEAK_INDICATORS` 에 추가 → 9-패키지 smoke 재측정 → "
        "FP 감소 확인."
    )
    md.append(
        "3. §3.3 TP=0 indicator 들이 실 데이터에서도 0 이면 매처 hint/regex 점검. "
        "여전히 0 이면 indicator 정의 자체를 재검토 또는 제거."
    )
    md.append("")

    md_text = "\n".join(md)

    out_path = ROOT / "docs" / "2026-05-06-indicator-fp-table.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md_text, encoding="utf-8")

    print(f"\nWrote: {out_path.relative_to(ROOT)}")
    print(f"\n=== 요약 ===")
    print(f"  TP=0  (한번도 안 잡힘): {len(zero_tp)} / 47")
    print(f"  FP rate ≥ 30%        : {len(high_fp)} / 47")
    print(f"  FP rate 15~30%       : {len(medium_fp)} / 47")

    print(f"\n=== Top-5 FP rate ===")
    rank = 0
    for r in rows_by_fp:
        if r["fp"] == 0:
            break
        rank += 1
        if rank > 5:
            break
        print(
            f"  {r['code']:8s}  FP={r['fp']:2d}/{n_ben} ({r['fp_rate']:.0%})  "
            f"TP={r['tp']:3d}/{n_mal} ({r['tp_rate']:.0%})  D={r['discrimination']:+.2f}  "
            f"{r['name']}"
        )

    print(f"\n=== Bottom-5 discrimination (TP+FP > 0) ===")
    shown = 0
    for r in rows_by_discrim:
        if r["tp"] == 0 and r["fp"] == 0:
            continue
        shown += 1
        if shown > 5:
            break
        print(
            f"  {r['code']:8s}  D={r['discrimination']:+.2f}  "
            f"TP={r['tp']:3d}/{n_mal}  FP={r['fp']:2d}/{n_ben}  "
            f"{r['name']}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
