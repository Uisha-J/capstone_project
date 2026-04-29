"""
Stub LLM vs Claude LLM 결과 비교.

같은 fixture set 두 번 (stub, claude) 평가했을 때 어떤 verdict 가 바뀌었나
정량/정성 분석. 특히:
- LLM 모드에서 새로 잡힌 (FN → TP) 케이스
- LLM 모드에서 새로 정상화된 (FP → TN) 케이스 — 본 사이클의 핵심 기대
- LLM 모드에서 오히려 악화된 (TP → FN, TN → FP) 케이스
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "scripts" / "eval_real_data"


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--stub", default=str(DATA_DIR / "results.json"),
        help="stub 결과 파일 (직전 평가)",
    )
    ap.add_argument(
        "--claude", default=str(DATA_DIR / "results_llm.json"),
        help="claude 결과 파일 (본 사이클)",
    )
    args = ap.parse_args()

    stub = json.loads(Path(args.stub).read_text(encoding="utf-8"))
    claude = json.loads(Path(args.claude).read_text(encoding="utf-8"))

    # name+version 으로 매칭
    stub_by_name = {(f["name"], f["version"]): f for f in stub["fixtures"]}
    claude_by_name = {(f["name"], f["version"]): f for f in claude["fixtures"]}

    common_keys = set(stub_by_name) & set(claude_by_name)
    print(f"Common fixtures: {len(common_keys)}")
    print(f"  stub: {len(stub_by_name)}, claude: {len(claude_by_name)}")
    print()

    # 카테고리별 변화
    flipped_to_correct = []   # FN → TP, FP → TN
    flipped_to_wrong = []     # TP → FN, TN → FP
    same_correct = 0
    same_wrong = 0

    for k in common_keys:
        s = stub_by_name[k]
        c = claude_by_name[k]
        s_ok = s["expected"]
        c_ok = c["expected"]
        if s_ok and c_ok:
            same_correct += 1
        elif (not s_ok) and (not c_ok):
            same_wrong += 1
        elif (not s_ok) and c_ok:
            flipped_to_correct.append((s, c))
        elif s_ok and (not c_ok):
            flipped_to_wrong.append((s, c))

    print("=== Verdict change distribution ===")
    print(f"  Same correct  : {same_correct}")
    print(f"  Same wrong    : {same_wrong}")
    print(f"  → improved (wrong→correct) : {len(flipped_to_correct)}")
    print(f"  → degraded (correct→wrong) : {len(flipped_to_wrong)}")
    print()

    if flipped_to_correct:
        print(f"=== Improved (LLM fixed {len(flipped_to_correct)}) ===")
        for s, c in flipped_to_correct:
            tag_s = "FP" if s["label"] == "benign" else "FN"
            tag_c = "TN" if c["label"] == "benign" else "TP"
            print(f"  [{s['label']:<10}] {s['name']:<35} "
                  f"{tag_s} → {tag_c}  "
                  f"({s['verdict']} → {c['verdict']})")
        print()

    if flipped_to_wrong:
        print(f"=== Degraded (LLM broke {len(flipped_to_wrong)}) ===")
        for s, c in flipped_to_wrong:
            tag_s = "TN" if s["label"] == "benign" else "TP"
            tag_c = "FP" if c["label"] == "benign" else "FN"
            print(f"  [{s['label']:<10}] {s['name']:<35} "
                  f"{tag_s} → {tag_c}  "
                  f"({s['verdict']} → {c['verdict']})")
        print()

    # 두 결과의 metrics 비교
    sm = stub["metrics"]
    cm = claude["metrics"]
    print("=== Metrics on common fixtures ===")
    print("            stub      claude")
    print(f"  Precision {sm['precision']:.3f}     {cm['precision']:.3f}")
    print(f"  Recall    {sm['recall']:.3f}     {cm['recall']:.3f}")
    print(f"  F1        {sm['f1']:.3f}     {cm['f1']:.3f}")
    print(f"  Accuracy  {sm['accuracy']:.3f}     {cm['accuracy']:.3f}")
    print(f"  TP={sm['tp']}/FN={sm['fn']}/FP={sm['fp']}/TN={sm['tn']}  "
          f"vs  TP={cm['tp']}/FN={cm['fn']}/FP={cm['fp']}/TN={cm['tn']}")


if __name__ == "__main__":
    main()
