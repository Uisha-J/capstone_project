"""Benchmark harness 단위 테스트 (run_pipeline 모킹).

실제 파이프라인은 네트워크/Stage1B 등 무거우므로 여기선 monkey-patch.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.benchmarks import harness
from pkgsentinel.schema import (
    AnalysisReport,
    Ecosystem,
    Verdict,
    empty_report,
)

# ─────────────── run_pipeline 가짜 ───────────────

_FAKE_LABELS = {
    # malicious 라고 우리 엔진이 잡아줘야 하는 (TP 후보)
    "evil-stealer": Verdict.MALICIOUS,
    "shady-pkg": Verdict.HIGH_RISK,
    # 정상이라고 봐야 하는 (TN 후보)
    "flask": Verdict.CLEAN,
    "requests": Verdict.CLEAN,
    # 등록 안 된 (CANNOT_ANALYZE → error)
    "ghost-pkg": Verdict.CANNOT_ANALYZE,
}


def fake_run_pipeline(package, ecosystem, version=None, **kwargs) -> AnalysisReport:
    rep = empty_report(package, ecosystem, version or "0.0.1")
    rep.verdict = _FAKE_LABELS.get(package, Verdict.CLEAN)
    rep.evidence = []
    return rep


# 모듈 패치
harness.run_pipeline = fake_run_pipeline


# ─────────────── 테스트 ───────────────

def test_basic_metrics():
    print("== Basic metrics ==")
    rows = [
        harness.BenchmarkRow("evil-stealer", Ecosystem.NPM, "malicious"),
        harness.BenchmarkRow("shady-pkg", Ecosystem.NPM, "malicious"),
        harness.BenchmarkRow("flask", Ecosystem.PYPI, "benign"),
        harness.BenchmarkRow("requests", Ecosystem.PYPI, "benign"),
    ]
    results, summary = harness.run_benchmark(rows, progress=False)
    print(f"  TP={summary.true_positives} TN={summary.true_negatives} "
          f"FP={summary.false_positives} FN={summary.false_negatives}")
    print(f"  P={summary.precision:.3f} R={summary.recall:.3f} F1={summary.f1:.3f}")
    print(f"  acc={summary.accuracy:.3f}")
    return (
        summary.true_positives == 2
        and summary.true_negatives == 2
        and summary.false_positives == 0
        and summary.false_negatives == 0
    )


def test_false_positive():
    print("\n== False-positive case ==")
    # flask 가 우리 엔진에서 (가짜) MALICIOUS 라고 잘못 판정되도록
    _FAKE_LABELS["flask"] = Verdict.MALICIOUS
    try:
        rows = [
            harness.BenchmarkRow("flask", Ecosystem.PYPI, "benign"),
            harness.BenchmarkRow("evil-stealer", Ecosystem.NPM, "malicious"),
        ]
        results, summary = harness.run_benchmark(rows, progress=False)
        print(f"  FP={summary.false_positives}, P={summary.precision:.3f}")
        return summary.false_positives == 1 and summary.precision == 0.5
    finally:
        _FAKE_LABELS["flask"] = Verdict.CLEAN  # 원복


def test_false_negative():
    print("\n== False-negative case ==")
    # malicious 인데 우리는 CLEAN 으로 잘못 판단
    _FAKE_LABELS["evil-stealer"] = Verdict.CLEAN
    try:
        rows = [
            harness.BenchmarkRow("evil-stealer", Ecosystem.NPM, "malicious"),
            harness.BenchmarkRow("flask", Ecosystem.PYPI, "benign"),
        ]
        results, summary = harness.run_benchmark(rows, progress=False)
        print(f"  FN={summary.false_negatives}, R={summary.recall:.3f}")
        return summary.false_negatives == 1 and summary.recall == 0.0
    finally:
        _FAKE_LABELS["evil-stealer"] = Verdict.MALICIOUS  # 원복


def test_error_packages():
    print("\n== Error / cannot_analyze ==")
    rows = [
        harness.BenchmarkRow("ghost-pkg", Ecosystem.NPM, "malicious"),
        harness.BenchmarkRow("evil-stealer", Ecosystem.NPM, "malicious"),
    ]
    results, summary = harness.run_benchmark(rows, progress=False)
    print(f"  errors={summary.errors}, TP={summary.true_positives}")
    return summary.errors == 1 and summary.true_positives == 1


def test_csv_loader():
    print("\n== CSV loader ==")
    csv_path = (Path(__file__).parent.parent / "src" / "pkgsentinel"
                / "benchmarks" / "sample_dataset.csv")
    rows = list(harness.load_csv(csv_path, Ecosystem.NPM))
    print(f"  rows: {len(rows)}")
    for r in rows:
        print(f"    {r.package:<14} {r.ecosystem.value:<5} {r.expected_label}")
    return len(rows) == 5


def main():
    ok = True
    ok &= test_basic_metrics()
    ok &= test_false_positive()
    ok &= test_false_negative()
    ok &= test_error_packages()
    ok &= test_csv_loader()
    print("\n" + ("ALL OK" if ok else "FAILED"))


if __name__ == "__main__":
    main()
