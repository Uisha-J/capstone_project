"""
9-패키지 smoke test — handoff doc 의 직전 측정값 재현 + Fix 효과 측정.

Usage:
    AISLOP_DB_KEY=test-key python scripts/smoke_9pkg.py [--label baseline|fix4|fix1|...]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 핸드오프 doc 9-패키지
PACKAGES = [
    ("requests", "PyPI"),
    ("flask", "PyPI"),
    ("django", "PyPI"),
    ("numpy", "PyPI"),
    ("pandas", "PyPI"),
    ("boto3", "PyPI"),
    ("lodash", "npm"),
    ("react", "npm"),
    ("webpack", "npm"),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--label", default="baseline")
    p.add_argument("--llm", default="stub")
    p.add_argument("--output", default=None)
    args = p.parse_args()

    out_path = Path(args.output or
                    ROOT / "scripts" / "eval_real_data" /
                    f"smoke_9pkg_{args.label}.json")

    env = os.environ.copy()
    env.setdefault("AISLOP_DB_KEY", "test-key")
    env.setdefault("PYTHONIOENCODING", "utf-8")

    rows = []
    t_total = time.time()

    for name, eco in PACKAGES:
        t0 = time.time()
        proc = subprocess.run(
            [sys.executable, "-m", "pkgsentinel.cli",
             name, "-e", eco, "--llm", args.llm],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env, timeout=600,
        )
        dt = time.time() - t0
        out = proc.stdout + "\n" + proc.stderr

        # verdict 추출
        verdict = "?"
        evidence_count = 0
        for line in out.split("\n"):
            if line.startswith("Verdict"):
                verdict = line.split(":", 1)[1].strip() if ":" in line else "?"
            if line.strip().startswith("-- Evidence #"):
                # 마지막 evidence index 보존
                try:
                    n = int(line.split("#")[1].split()[0])
                    evidence_count = max(evidence_count, n)
                except Exception:
                    pass

        # stage 결과 카운트
        stage_ok = sum(1 for L in out.split("\n") if L.strip().startswith("[OK]"))
        stage_fail = sum(1 for L in out.split("\n") if L.strip().startswith("[FAIL]"))

        rows.append({
            "name": name,
            "ecosystem": eco,
            "verdict": verdict,
            "evidence_count": evidence_count,
            "elapsed_s": round(dt, 2),
            "stage_ok": stage_ok,
            "stage_fail": stage_fail,
            "exit_code": proc.returncode,
        })
        print(f"  {name:12s} {eco:5s} {dt:5.1f}s  V={verdict:14s}  "
              f"E={evidence_count:3d}  stages OK={stage_ok}/{stage_ok+stage_fail}")

    elapsed = time.time() - t_total

    payload = {
        "label": args.label,
        "llm_mode": args.llm,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_total_s": round(elapsed, 1),
        "results": rows,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                        encoding="utf-8")

    print()
    print(f"Total: {elapsed:.1f}s")
    print(f"Wrote: {out_path.relative_to(ROOT)}")

    # 요약 표
    print()
    print("=== verdict 분포 ===")
    from collections import Counter
    vc = Counter(r["verdict"] for r in rows)
    for v, n in sorted(vc.items(), key=lambda x: -x[1]):
        print(f"  {v}: {n}")


if __name__ == "__main__":
    sys.exit(main() or 0)
