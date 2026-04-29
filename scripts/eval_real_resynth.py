"""
저장된 results.json 의 matchers 를 가지고 verdict 합성 로직만 재실행.

LLM API 재호출 없이 verdict synthesis 룰 변경의 효과만 측정. 100 fixture
재평가 시 $5 절감.

읽는 정보:
- results 의 각 fixture: name, ecosystem, label, source, matchers
  matchers 안에는 ind_47, ind_47_high, seq_pattern, seq_high, taint_flows,
  llm_stub, max_high_per_file, files_with_high_ind, cooccur_files, ...
- 단, '_evaluate' 의 일부 변수 (ind_codes_present, ind_hits 등) 는 matchers 에
  저장돼 있어야 재현 가능. 누락된 건 보수적으로 0/false.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "scripts" / "eval_real_data"

sys.path.insert(0, str(ROOT / "src"))

from pkgsentinel.schema import LLMVerdict, Verdict

# eval_real.py 의 popular 명단 import (단순 복사 회피)
sys.path.insert(0, str(ROOT / "scripts"))
import eval_real

_is_popular = eval_real._is_popular


def _resynth(fx: dict, llm_mode: str) -> str:
    """fixture 의 matchers 만 가지고 verdict 합성 재실행.

    eval_real._evaluate 의 verdict 결정 부분과 동일한 로직.
    """
    m = fx.get("matchers") or {}
    name = fx["name"]
    ecosystem = fx["ecosystem"]
    fx["label"]

    ind_hits = m.get("ind_47", 0)
    ind_high = m.get("ind_47_high", 0)
    seq_hits = m.get("seq_pattern", 0)
    high_sev_seq = m.get("seq_high", 0)
    taint_total = m.get("taint_flows", 0)
    llm_str = m.get("llm_stub", "benign") or "benign"
    try:
        llm_verdict = LLMVerdict(llm_str)
    except Exception:
        llm_verdict = LLMVerdict.BENIGN

    benign_context = m.get("benign_context", False)
    max_high_per_file = m.get("max_high_per_file", 0)
    m.get("files_with_high_ind", 0)
    cooccur_files = m.get("cooccur_files", 0)
    is_concentrated = m.get("is_concentrated", False)
    is_spread = m.get("is_spread", False)
    n_analysis_files = max(1, fx.get("n_python", 0) + fx.get("n_js", 0))

    # MALICIOUS triggers
    if (
        llm_verdict == LLMVerdict.MALICIOUS
        and (ind_high >= 2 or high_sev_seq >= 1)
    ):
        verdict = Verdict.MALICIOUS
    elif (
        ind_high >= 2 or high_sev_seq >= 2
        or (ind_high >= 1 and high_sev_seq >= 1)
    ):
        verdict = Verdict.HIGH_RISK
    elif (
        ind_high >= 1
        or high_sev_seq >= 1
        or seq_hits >= 2
        or taint_total >= 1
        or (ind_hits >= 3 and (taint_total >= 1 or seq_hits >= 1))
        or llm_verdict == LLMVerdict.MALICIOUS
    ):
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    # benign_context 보정
    if benign_context and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK):
        if ind_high < 2 and high_sev_seq == 0 and taint_total == 0:
            verdict = Verdict.CLEAN

    # 농도 보정
    if is_spread and not is_concentrated:
        if verdict == Verdict.HIGH_RISK:
            verdict = Verdict.SUSPICIOUS
        if verdict == Verdict.SUSPICIOUS:
            verdict = Verdict.CLEAN

    # 약한 단독 taint
    if (
        verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and taint_total == 1
        and ind_high == 0
        and high_sev_seq == 0
        and not is_concentrated
        and ind_hits <= 5
    ):
        verdict = Verdict.CLEAN

    # 단일 seq HIGH only
    if (
        verdict == Verdict.SUSPICIOUS
        and high_sev_seq == 1
        and seq_hits == 1
        and ind_high == 0
        and ind_hits == 0
        and taint_total == 0
    ):
        verdict = Verdict.CLEAN

    # popular 화이트리스트 (기존)
    if (
        _is_popular(name, ecosystem)
        and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and cooccur_files == 0
        and taint_total < 2
        and ind_high < 5
        and high_sev_seq < 2
    ):
        verdict = Verdict.CLEAN

    # 큰 인기 도구
    if (
        _is_popular(name, ecosystem)
        and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and n_analysis_files > 50
        and max_high_per_file <= 2
        and cooccur_files == 0
        and taint_total == 0
        and high_sev_seq < 2
    ):
        verdict = Verdict.CLEAN

    # popular + LLM benign 강 다운그레이드 (NEW)
    if (
        llm_mode == "claude"
        and _is_popular(name, ecosystem)
        and llm_verdict == LLMVerdict.BENIGN
        and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
        and taint_total < 2
        and cooccur_files <= 2
    ):
        verdict = Verdict.CLEAN

    return verdict.value


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="results.json 경로")
    ap.add_argument("--llm", choices=["stub", "claude"], default="claude")
    ap.add_argument("--output", default="", help="재합성 결과 저장 경로")
    args = ap.parse_args()

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    fixtures = data["fixtures"]

    # 재합성
    new_fixtures = []
    flips = []
    for fx in fixtures:
        old_verdict = fx["verdict"]
        new_verdict = _resynth(fx, args.llm)
        fx["expected"]
        # 새 expected 계산
        if fx["label"] == "malicious":
            new_expected = new_verdict in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        else:
            new_expected = new_verdict == "CLEAN"
        new_fx = dict(fx)
        new_fx["verdict"] = new_verdict
        new_fx["expected"] = new_expected
        new_fixtures.append(new_fx)
        if old_verdict != new_verdict:
            flips.append((fx, new_verdict))

    # 새 metrics 계산
    tp = fp = tn = fn = 0
    for fx in new_fixtures:
        is_mal_pred = fx["verdict"] in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        is_mal_true = (fx["label"] == "malicious")
        if is_mal_true and is_mal_pred:
            tp += 1
        elif is_mal_true and not is_mal_pred:
            fn += 1
        elif (not is_mal_true) and is_mal_pred:
            fp += 1
        else:
            tn += 1
    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    acc = (tp + tn) / max(1, len(new_fixtures))

    print(f"=== Re-synth (llm={args.llm}, n={len(new_fixtures)}) ===")
    print(f"  TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  P={p:.4f}  R={r:.4f}  F1={f1:.4f}  Acc={acc:.4f}")
    print(f"  Verdict flips: {len(flips)}")
    print()
    if flips:
        print("Flipped:")
        for fx, new_v in flips:
            old_v = fx["verdict"]
            label = fx["label"]
            print(f"  [{label:<10}] {fx['name']:<35}  {old_v:<11} → {new_v:<11}")

    if args.output:
        out = Path(args.output)
        new_data = dict(data)
        new_data["fixtures"] = new_fixtures
        new_data["metrics"] = {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(f1, 4), "accuracy": round(acc, 4),
            "n": len(new_fixtures),
        }
        out.write_text(json.dumps(new_data, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        print(f"\nSaved → {out}")


if __name__ == "__main__":
    main()
