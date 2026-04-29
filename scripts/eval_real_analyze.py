"""
eval_real_data/results.json 결과 분석 — FN/FP 패턴 분류, 신뢰구간 정리.

`scripts/eval_real.py` 가 만든 결과 파일에서 의미 있는 통계를
요약. 큰 N (500+) 에선 raw 표가 너무 커서 카테고리별 분해 + zero-signal 비율
+ 매처 코드별 분포 등으로 의미 있는 단면만 보여줌.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "scripts" / "eval_real_data"


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--results", default=str(DATA_DIR / "results.json"),
        help="eval_real.py 가 만든 results.json 경로",
    )
    args = ap.parse_args()

    with open(args.results, encoding="utf-8") as f:
        data = json.load(f)

    fixtures = data["fixtures"]
    metrics = data["metrics"]
    by_src = data["by_source"]

    print(f"=== Overall ({metrics['n']} fixtures) ===")
    pl, ph = metrics["precision_ci95"]
    rl, rh = metrics["recall_ci95"]
    print(f"  P={metrics['precision']:.4f} (CI [{pl:.3f}, {ph:.3f}])")
    print(f"  R={metrics['recall']:.4f} (CI [{rl:.3f}, {rh:.3f}])")
    print(f"  F1={metrics['f1']:.4f}  Acc={metrics['accuracy']:.4f}")
    print(f"  TP={metrics['tp']} FN={metrics['fn']} FP={metrics['fp']} TN={metrics['tn']}")
    print()

    print("=== Per-source ===")
    for src, sm in by_src.items():
        if sm["n"] == 0:
            continue
        rl_s, rh_s = sm["recall_ci95"]
        print(f"  {src:<28} n={sm['n']:>4}  "
              f"P={sm['precision']:.3f} R={sm['recall']:.3f} "
              f"(CI [{rl_s:.2f}, {rh_s:.2f}])  F1={sm['f1']:.3f}")
    print()

    # FN 분석
    fns = [f for f in fixtures if f["label"] == "malicious" and not f["expected"]]
    fns_zero = [
        f for f in fns
        if f["matchers"].get("ind_47", 0) == 0
        and f["matchers"].get("seq_pattern", 0) == 0
        and f["matchers"].get("taint_flows", 0) == 0
    ]
    print(f"=== FN ({len(fns)} total) ===")
    print(f"  zero-signal (no ind/seq/taint): {len(fns_zero)} "
          f"({len(fns_zero)/max(1,len(fns))*100:.0f}%)")
    print(f"  has-signal but verdict=CLEAN  : {len(fns) - len(fns_zero)}")
    print()
    if len(fns) - len(fns_zero) > 0:
        print("  Has-signal FNs (likely matcher-fixable):")
        for f in fns:
            m = f.get("matchers") or {}
            if not m:
                continue
            if (m.get("ind_47", 0) == 0 and m.get("seq_pattern", 0) == 0
                    and m.get("taint_flows", 0) == 0):
                continue
            print(f"    {f['name']:<35} {f['ecosystem']:<5} "
                  f"ind={m.get('ind_47',0)}({m.get('ind_47_high',0)}H) "
                  f"seq={m.get('seq_pattern',0)}({m.get('seq_high',0)}H) "
                  f"taint={m.get('taint_flows',0)} verdict={f['verdict']}")
    print()

    # FP 분석
    fps = [f for f in fixtures if f["label"] == "benign" and not f["expected"]]
    print(f"=== FP ({len(fps)} total) ===")
    for f in fps:
        m = f["matchers"]
        codes = m.get("ind_codes") or []
        print(f"  {f['name']:<14} {f['verdict']:<11} files={f['n_files']:<4} "
              f"ind={m['ind_47']}({m['ind_47_high']}H) "
              f"seq={m['seq_pattern']}({m['seq_high']}H) "
              f"taint={m['taint_flows']} cooc={m['cooccur_files']}  "
              f"codes={','.join(codes[:6])}")
    print()

    # 매처 코드별 통계 (TP / FP 별로 어떤 코드가 가장 자주 발화하는가)
    print("=== Indicator code distribution ===")
    tp_codes = Counter()
    fp_codes = Counter()
    for f in fixtures:
        codes = f["matchers"].get("ind_codes") or []
        if f["label"] == "malicious" and f["expected"]:
            for c in codes:
                tp_codes[c] += 1
        elif f["label"] == "benign" and not f["expected"]:
            for c in codes:
                fp_codes[c] += 1
    if tp_codes:
        print("  Top codes in TP (malicious correctly caught):")
        for c, n in tp_codes.most_common(10):
            print(f"    {c:<10} {n}")
    if fp_codes:
        print("  Top codes in FP (benign mislabeled):")
        for c, n in fp_codes.most_common(10):
            print(f"    {c:<10} {n}")

    # ecosystem 별
    print()
    print("=== By ecosystem ===")
    for eco in ("PyPI", "npm"):
        sub = [f for f in fixtures if f["ecosystem"] == eco]
        mal = [f for f in sub if f["label"] == "malicious"]
        ben = [f for f in sub if f["label"] == "benign"]
        tp = sum(1 for f in mal if f["expected"])
        fn = sum(1 for f in mal if not f["expected"])
        fp = sum(1 for f in ben if not f["expected"])
        tn = sum(1 for f in ben if f["expected"])
        if not sub:
            continue
        n_mal = max(1, tp + fn)
        n_ben = max(1, fp + tn)
        print(f"  {eco:<6} n={len(sub):<4}  "
              f"mal R={tp}/{tp+fn} ({tp/n_mal*100:.0f}%)   "
              f"ben TN={tn}/{tn+fp} ({tn/n_ben*100:.0f}%)")


if __name__ == "__main__":
    main()
