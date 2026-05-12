"""
Phase 4.1 + 4.2 — LLM consistency + Haiku/Sonnet A/B.

목적:
  - 동일 입력에 LLM 이 항상 같은 verdict 를 주는가? (re-test reliability)
  - Haiku 4.5 가 Sonnet 4.5 대비 정확도 손실 없이 비용 절감 가능한가?

단일-agent review() 호출로 cost 최소화 (multi-agent 는 3× 비용).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

# fixture 재사용
from eval_synthetic import BEN_FIXTURES, MAL_FIXTURES  # noqa: E402

from pkgsentinel.schema import LLMVerdict  # noqa: E402
from pkgsentinel.stages.stage1_entry_point import EntryFile  # noqa: E402
from pkgsentinel.stages.stage2_behavior import _analyze_python  # noqa: E402
from pkgsentinel.stages.stage5_llm_review import review  # noqa: E402

SONNET = "claude-sonnet-4-5"
HAIKU = "claude-haiku-4-5"


def _fixture_to_inputs(fx) -> tuple:
    """Fixture → (file_seq, code_snippet). 첫 번째 Python 파일 사용."""
    py_files = {p: c for p, c in fx.files.items() if p.endswith(".py")}
    if not py_files:
        return None, ""
    path, content = next(iter(py_files.items()))
    ef = EntryFile(
        path=path, basename=path.split("/")[-1],
        content=content, size=len(content), language="python",
    )
    file_seq = _analyze_python(ef)
    code = "\n".join(fx.files.values())[:1500]
    return file_seq, code


def _expected_verdict(fx) -> str:
    return "malicious" if fx.label == "malicious" else "benign"


def _verdict_matches_label(v: LLMVerdict, label: str) -> bool:
    if label == "malicious":
        return v in (LLMVerdict.MALICIOUS, LLMVerdict.SUSPICIOUS)
    return v == LLMVerdict.BENIGN


def _call_one(fx, model: str) -> dict:
    fs, code = _fixture_to_inputs(fx)
    if fs is None:
        return {"verdict": "ERROR", "reason": "no python file"}
    t0 = time.time()
    try:
        r = review(
            package=fx.name, version="0.0.1", ecosystem="PyPI",
            file_seq=fs, ttp_matches=[],
            code_snippet=code,
            mode="claude", model=model,
        )
        return {
            "verdict": r.verdict.value,
            "reasoning": r.reasoning[:200],
            "elapsed_s": round(time.time() - t0, 2),
        }
    except Exception as e:
        return {
            "verdict": "ERROR",
            "error": str(e)[:200],
            "elapsed_s": round(time.time() - t0, 2),
        }


# ─────────────── 4.1: Consistency ───────────────

def run_consistency(fixtures, n_trials: int, model: str) -> dict:
    """동일 fixture 를 n_trials 회 호출, verdict 분포."""
    print(f"\n=== Consistency: {len(fixtures)} fixtures × {n_trials} trials × {model} ===\n")
    per_fixture: list[dict] = []
    n_consistent = 0
    n_label_correct = 0

    for i, fx in enumerate(fixtures):
        trials = []
        for t in range(n_trials):
            r = _call_one(fx, model)
            trials.append(r["verdict"])
        # 최빈 verdict
        cnt = Counter(trials)
        top, top_n = cnt.most_common(1)[0]
        unique = len(set(trials))
        consistent = unique == 1
        n_consistent += int(consistent)

        # 라벨 일치 여부 (top verdict 기준)
        try:
            top_v = LLMVerdict(top)
        except Exception:
            top_v = LLMVerdict.BENIGN
        correct = _verdict_matches_label(top_v, fx.label)
        n_label_correct += int(correct)

        per_fixture.append({
            "name": fx.name,
            "label": fx.label,
            "trials": trials,
            "unique_count": unique,
            "consistent": consistent,
            "top_verdict": top,
            "top_n": top_n,
            "label_match": correct,
        })
        flag = "OK" if consistent else "VAR"
        lbl_flag = "y" if correct else "n"
        print(f"  [{i+1:>3}/{len(fixtures)}] {fx.name[:30]:<30} "
              f"{fx.label:<10} trials={trials} {flag} {lbl_flag}")

    rate = n_consistent / len(fixtures)
    accuracy = n_label_correct / len(fixtures)
    print(f"\n  Consistency rate : {rate:.3f}  ({n_consistent}/{len(fixtures)})")
    print(f"  Top-verdict acc  : {accuracy:.3f}  ({n_label_correct}/{len(fixtures)})")
    return {
        "model": model,
        "n_fixtures": len(fixtures),
        "n_trials": n_trials,
        "consistency_rate": round(rate, 4),
        "top_verdict_accuracy": round(accuracy, 4),
        "per_fixture": per_fixture,
    }


# ─────────────── 4.2: Haiku vs Sonnet A/B ───────────────

def run_ab(fixtures) -> dict:
    """동일 fixture 를 Sonnet 과 Haiku 둘 다 호출, 비교."""
    print(f"\n=== A/B: {len(fixtures)} fixtures × {{Sonnet, Haiku}} ===\n")
    pairs = []
    n_agree = 0
    n_son_correct = 0
    n_hai_correct = 0
    son_total_s = 0.0
    hai_total_s = 0.0
    for i, fx in enumerate(fixtures):
        s = _call_one(fx, SONNET)
        h = _call_one(fx, HAIKU)
        agree = s["verdict"] == h["verdict"]
        n_agree += int(agree)

        try:
            sv = LLMVerdict(s["verdict"])
            son_correct = _verdict_matches_label(sv, fx.label)
        except Exception:
            son_correct = False
        try:
            hv = LLMVerdict(h["verdict"])
            hai_correct = _verdict_matches_label(hv, fx.label)
        except Exception:
            hai_correct = False
        n_son_correct += int(son_correct)
        n_hai_correct += int(hai_correct)
        son_total_s += s.get("elapsed_s", 0)
        hai_total_s += h.get("elapsed_s", 0)

        pairs.append({
            "name": fx.name,
            "label": fx.label,
            "sonnet": s["verdict"], "sonnet_s": s.get("elapsed_s"),
            "haiku":  h["verdict"], "haiku_s":  h.get("elapsed_s"),
            "agree": agree,
            "sonnet_correct": son_correct,
            "haiku_correct": hai_correct,
        })
        s_flag = "y" if son_correct else "n"
        h_flag = "y" if hai_correct else "n"
        a_flag = "=" if agree else "X"
        print(f"  [{i+1:>2}/{len(fixtures)}] {fx.name[:30]:<30} "
              f"{fx.label:<10} S={s['verdict']:<11} {s_flag}  "
              f"H={h['verdict']:<11} {h_flag}  {a_flag}")

    agree_rate = n_agree / len(fixtures)
    print(f"\n  Agreement rate     : {agree_rate:.3f}  ({n_agree}/{len(fixtures)})")
    print(f"  Sonnet accuracy    : {n_son_correct/len(fixtures):.3f}")
    print(f"  Haiku  accuracy    : {n_hai_correct/len(fixtures):.3f}")
    print(f"  Avg latency Sonnet : {son_total_s/len(fixtures):.2f}s")
    print(f"  Avg latency Haiku  : {hai_total_s/len(fixtures):.2f}s")
    return {
        "n_fixtures": len(fixtures),
        "agreement_rate": round(agree_rate, 4),
        "sonnet_accuracy": round(n_son_correct/len(fixtures), 4),
        "haiku_accuracy":  round(n_hai_correct/len(fixtures), 4),
        "avg_latency_sonnet_s": round(son_total_s/len(fixtures), 2),
        "avg_latency_haiku_s":  round(hai_total_s/len(fixtures), 2),
        "pairs": pairs,
    }


# ─────────────── main ───────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["consistency", "ab", "both"],
                    default="both")
    ap.add_argument("--consistency-n", type=int, default=30,
                    help="consistency: fixture 수 (mal+ben 합)")
    ap.add_argument("--consistency-trials", type=int, default=3)
    ap.add_argument("--ab-n", type=int, default=10,
                    help="A/B: fixture 수 (mal+ben 합)")
    ap.add_argument("--out", default=str(ROOT / "scripts" / "eval_real_data"
                                         / "results_llm_consistency.json"))
    args = ap.parse_args()

    # dotenv
    from pkgsentinel import _dotenv as _ad
    _ad.load()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY missing", file=sys.stderr)
        sys.exit(2)

    # fixture 풀: 합성에서 균등 sampling
    all_mal = MAL_FIXTURES
    all_ben = BEN_FIXTURES

    results: dict = {}
    t0 = time.time()

    if args.mode in ("ab", "both"):
        half = args.ab_n // 2
        ab_fx = list(all_mal[:half]) + list(all_ben[:args.ab_n - half])
        results["ab"] = run_ab(ab_fx)

    if args.mode in ("consistency", "both"):
        half = args.consistency_n // 2
        c_fx = list(all_mal[:half]) + list(all_ben[:args.consistency_n - half])
        results["consistency"] = run_consistency(
            c_fx, n_trials=args.consistency_trials, model=SONNET,
        )

    results["elapsed_total_s"] = round(time.time() - t0, 2)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nJSON saved -> {out_path}")
    print(f"Total elapsed: {results['elapsed_total_s']}s")


if __name__ == "__main__":
    main()
