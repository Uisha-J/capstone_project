"""
Precision/Recall 벤치마크 하니스.

근거 데이터셋:
  - NPM Benchmark (2025): https://arxiv.org/html/2603.27549
    - 6,420 malicious + 7,288 benign npm packages (라벨 포함 CSV)
  - PyPI dataset (논문 별첨)
  - Internal synthetic: detector/tests/test_synthetic_malicious.py

본 모듈은 데이터셋을 메모리에 적재하지 않고
"한 줄 = 한 패키지" CSV/JSONL 스트리밍으로 처리.

사용 예:
  python -m detector.benchmarks.harness data/npm_benchmark.csv \\
      --ecosystem npm --max 100 --output report.json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import traceback
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..pipeline import run_pipeline
from ..schema import Ecosystem, Verdict

# ─────────────── 데이터셋 항목 ───────────────

@dataclass
class BenchmarkRow:
    package: str
    ecosystem: Ecosystem
    expected_label: str          # "malicious" | "benign"
    version: str | None = None
    note: str = ""


# ─────────────── 한 항목 결과 ───────────────

@dataclass
class BenchmarkResult:
    package: str
    ecosystem: str
    expected_label: str
    actual_verdict: str
    is_true_positive: bool = False
    is_true_negative: bool = False
    is_false_positive: bool = False
    is_false_negative: bool = False
    is_error: bool = False
    elapsed_s: float = 0.0
    error: str | None = None
    evidence_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────── 집계 ───────────────

@dataclass
class BenchmarkSummary:
    total: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    errors: int = 0
    avg_elapsed_s: float = 0.0
    by_label: dict = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return (self.true_positives / denom) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return (self.true_positives / denom) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        denom = max(1, self.total - self.errors)
        return (self.true_positives + self.true_negatives) / denom

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "tp": self.true_positives,
            "tn": self.true_negatives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "errors": self.errors,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "avg_elapsed_s": round(self.avg_elapsed_s, 3),
            "by_label": self.by_label,
        }


# ─────────────── 데이터셋 로더 ───────────────

def load_csv(path: Path, ecosystem_default: Ecosystem) -> Iterable[BenchmarkRow]:
    """CSV 헤더: package, ecosystem (옵션), label, version (옵션), note (옵션)."""
    with open(path, encoding="utf-8") as f:
        rd = csv.DictReader(f)
        for row in rd:
            pkg = (row.get("package") or row.get("name") or "").strip()
            if not pkg:
                continue
            eco_raw = (row.get("ecosystem") or "").strip()
            try:
                eco = Ecosystem(eco_raw) if eco_raw else ecosystem_default
            except ValueError:
                eco = ecosystem_default
            label = (row.get("label") or row.get("expected") or "").strip().lower()
            if label not in ("malicious", "benign"):
                # 'positive'/'negative' 호환
                if label in ("positive", "1", "true"):
                    label = "malicious"
                elif label in ("negative", "0", "false"):
                    label = "benign"
                else:
                    label = "benign"
            yield BenchmarkRow(
                package=pkg,
                ecosystem=eco,
                expected_label=label,
                version=row.get("version") or None,
                note=row.get("note") or "",
            )


def load_jsonl(path: Path, ecosystem_default: Ecosystem) -> Iterable[BenchmarkRow]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            j = json.loads(line)
            pkg = j.get("package") or j.get("name", "")
            if not pkg:
                continue
            eco_raw = j.get("ecosystem", "")
            try:
                eco = Ecosystem(eco_raw) if eco_raw else ecosystem_default
            except ValueError:
                eco = ecosystem_default
            label = (j.get("label") or "benign").lower()
            yield BenchmarkRow(
                package=pkg,
                ecosystem=eco,
                expected_label=label,
                version=j.get("version"),
                note=j.get("note", ""),
            )


# ─────────────── verdict 분류 ───────────────

# 우리 verdict 가 "malicious 라고 예측" 하는 셋
_MALICIOUS_VERDICTS = {Verdict.MALICIOUS, Verdict.HIGH_RISK, Verdict.SUSPICIOUS}


def _is_predicted_malicious(verdict: Verdict) -> bool:
    return verdict in _MALICIOUS_VERDICTS


# ─────────────── 한 항목 실행 ───────────────

def run_one(row: BenchmarkRow, **pipeline_kwargs) -> BenchmarkResult:
    t0 = time.time()
    try:
        rep = run_pipeline(
            package=row.package,
            ecosystem=row.ecosystem,
            version=row.version,
            **pipeline_kwargs,
        )
        elapsed = time.time() - t0
        verdict = rep.verdict
        predicted_mal = _is_predicted_malicious(verdict)
        actual_mal = row.expected_label == "malicious"

        is_err = verdict == Verdict.ERROR or verdict == Verdict.CANNOT_ANALYZE

        result = BenchmarkResult(
            package=row.package,
            ecosystem=row.ecosystem.value,
            expected_label=row.expected_label,
            actual_verdict=verdict.value,
            elapsed_s=round(elapsed, 3),
            evidence_count=len(rep.evidence) if rep.evidence else 0,
        )
        if is_err:
            result.is_error = True
        elif predicted_mal and actual_mal:
            result.is_true_positive = True
        elif (not predicted_mal) and (not actual_mal):
            result.is_true_negative = True
        elif predicted_mal and (not actual_mal):
            result.is_false_positive = True
        else:
            result.is_false_negative = True
        return result
    except Exception as e:
        return BenchmarkResult(
            package=row.package,
            ecosystem=row.ecosystem.value,
            expected_label=row.expected_label,
            actual_verdict="ERROR",
            elapsed_s=round(time.time() - t0, 3),
            is_error=True,
            error=f"{type(e).__name__}: {e}\n{traceback.format_exc()[:500]}",
        )


# ─────────────── 전체 실행 ───────────────

def run_benchmark(
    rows: Iterable[BenchmarkRow],
    *,
    max_packages: int | None = None,
    progress: bool = True,
    output_jsonl: Path | None = None,
    pipeline_kwargs: dict | None = None,
) -> tuple[list[BenchmarkResult], BenchmarkSummary]:
    pipeline_kwargs = pipeline_kwargs or {}
    results: list[BenchmarkResult] = []

    out_fh = open(output_jsonl, "w", encoding="utf-8") if output_jsonl else None

    summary = BenchmarkSummary()
    label_counts: dict[str, dict] = {
        "malicious": {"total": 0, "correct": 0, "elapsed": 0.0},
        "benign": {"total": 0, "correct": 0, "elapsed": 0.0},
    }

    try:
        for i, row in enumerate(rows):
            if max_packages is not None and i >= max_packages:
                break
            r = run_one(row, **pipeline_kwargs)
            results.append(r)
            if out_fh is not None:
                out_fh.write(json.dumps(r.to_dict(), ensure_ascii=False))
                out_fh.write("\n")
                out_fh.flush()

            summary.total += 1
            if r.is_true_positive:
                summary.true_positives += 1
            elif r.is_true_negative:
                summary.true_negatives += 1
            elif r.is_false_positive:
                summary.false_positives += 1
            elif r.is_false_negative:
                summary.false_negatives += 1
            if r.is_error:
                summary.errors += 1

            lc = label_counts[row.expected_label]
            lc["total"] += 1
            if (r.is_true_positive or r.is_true_negative):
                lc["correct"] += 1
            lc["elapsed"] += r.elapsed_s

            if progress and (i + 1) % 25 == 0:
                p, rcl = summary.precision, summary.recall
                sys.stderr.write(
                    f"[bench] {i + 1}: P={p:.3f} R={rcl:.3f} "
                    f"TP={summary.true_positives} FP={summary.false_positives} "
                    f"FN={summary.false_negatives} ERR={summary.errors}\n"
                )
                sys.stderr.flush()
    finally:
        if out_fh is not None:
            out_fh.close()

    if summary.total:
        summary.avg_elapsed_s = sum(r.elapsed_s for r in results) / summary.total
    summary.by_label = {
        k: {
            "total": v["total"],
            "correct": v["correct"],
            "accuracy": (v["correct"] / v["total"]) if v["total"] else 0.0,
            "avg_elapsed_s": (v["elapsed"] / v["total"]) if v["total"] else 0.0,
        }
        for k, v in label_counts.items()
    }
    return results, summary


# ─────────────── CLI ───────────────

def _argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AI-Slopsquatting Benchmark Harness")
    p.add_argument("dataset", help="CSV 또는 JSONL 데이터셋 경로")
    p.add_argument("--ecosystem", choices=["PyPI", "npm"], default="npm",
                   help="기본 생태계 (CSV 에 ecosystem 컬럼이 없을 때)")
    p.add_argument("--max", type=int, default=None, help="최대 처리 항목 수")
    p.add_argument("--output", default=None,
                   help="결과 JSONL 출력 (한 줄에 한 결과)")
    p.add_argument("--summary", default=None, help="요약 JSON 출력 경로")
    p.add_argument("--llm-mode", default="claude", choices=["stub", "claude"])
    p.add_argument("--single-agent", action="store_true",
                   help="multi-agent 비활성, legacy single-agent 모드 사용")
    return p


def main():
    args = _argparser().parse_args()
    eco_default = Ecosystem(args.ecosystem)
    path = Path(args.dataset)
    if not path.exists():
        print(f"dataset not found: {path}", file=sys.stderr)
        sys.exit(2)

    if path.suffix.lower() == ".jsonl":
        rows = load_jsonl(path, eco_default)
    else:
        rows = load_csv(path, eco_default)

    out_path = Path(args.output) if args.output else None
    results, summary = run_benchmark(
        rows,
        max_packages=args.max,
        output_jsonl=out_path,
        pipeline_kwargs={
            "llm_mode": args.llm_mode,
            "use_multi_agent": not args.single_agent,
        },
    )

    print("=" * 64)
    print(f"Total       : {summary.total}")
    print(f"TP / TN     : {summary.true_positives} / {summary.true_negatives}")
    print(f"FP / FN     : {summary.false_positives} / {summary.false_negatives}")
    print(f"Errors      : {summary.errors}")
    print(f"Precision   : {summary.precision:.4f}")
    print(f"Recall      : {summary.recall:.4f}")
    print(f"F1          : {summary.f1:.4f}")
    print(f"Accuracy    : {summary.accuracy:.4f}")
    print(f"Avg time    : {summary.avg_elapsed_s:.3f}s / pkg")
    print("By label:")
    for k, v in summary.by_label.items():
        print(f"  {k:<10} total={v['total']:>5}  acc={v['accuracy']:.3f}  avg_t={v['avg_elapsed_s']:.2f}s")

    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"\nSummary saved → {args.summary}")


if __name__ == "__main__":
    main()
