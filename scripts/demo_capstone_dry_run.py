"""Capstone 시연 sample 5개 사전 검증 (dry-run).

발표 전에 미리 돌려서:
  - 각 샘플의 verdict 확인
  - LLM reasoning 캡처
  - 매처별 신호 dump
  - 비용 측정

샘플:
  1. Synthetic credential-exfil-base64 (cost 0)
  2. DataDog pyqubee@12.1.1 (malicious_intent)
  3. DataDog @operato/board@9.0.40 (compromised_lib)
  4. DataDog react-native-websocket@1.0.4 (compromised_lib)
  5. DataDog num2words@0.5.16 (compromised_lib + IaC 합법 코드)
  6. Legitimate requests@latest (claude → CLEAN 기대)

비용: ~$0.50-1 (Haiku × multi-agent × 6 samples)
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

from pkgsentinel.schema import Ecosystem  # noqa: E402

# .env 로드 + Anthropic 키 확인
from pkgsentinel import _dotenv  # noqa: E402
_dotenv.load()
if not os.environ.get("ANTHROPIC_API_KEY"):
    print("ERROR: ANTHROPIC_API_KEY missing", file=sys.stderr)
    sys.exit(2)
os.environ["PKGSENTINEL_LLM_MODE"] = "claude"


def run_synthetic():
    """1) Synthetic credential-exfil-base64 — deterministic baseline."""
    from eval_synthetic import MAL_FIXTURES
    fx = next(f for f in MAL_FIXTURES if f.name == "credential-exfil-base64")
    print(f"\n[1/6] SYNTHETIC: {fx.name}")
    print(f"  description: {fx.description}")
    print(f"  expected: malicious")

    # 합성 fixture 는 inline 코드 — Stage 2/4c/4d/4e 매처만 호출
    from pkgsentinel.stages.indicator_matcher import match_all
    from pkgsentinel.stages.sequence_patterns import mine as mine_seq
    from pkgsentinel.stages.stage1_entry_point import EntryFile
    from pkgsentinel.stages.stage1b_full_source import FullSourceFile
    from pkgsentinel.stages.stage2_behavior import (BehaviorReport,
                                                    _analyze_python)
    from pkgsentinel.stages.stage5_multi_agent import review_multi
    from pkgsentinel.stages.taint_slicer import analyze_python as taint_analyze

    entry_files = []
    full_files = []
    for path, content in fx.files.items():
        entry_files.append(EntryFile(
            path=path, basename=path.split("/")[-1],
            content=content, size=len(content), language="python",
        ))
        full_files.append(FullSourceFile(
            path=path, basename=path.split("/")[-1],
            content=content, size=len(content), language="python", tier=1,
        ))

    file_seqs = [_analyze_python(ef) for ef in entry_files]
    behavior = BehaviorReport(files=file_seqs)
    ind_rep = match_all(
        behavior_files=file_seqs, source_files=full_files,
        package_name=fx.name, description=fx.description,
        author="", declared_deps=[],
    )
    taint = sum(len(taint_analyze(ef.content).flows) for ef in entry_files)
    seq_rep = mine_seq(behavior)

    t0 = time.time()
    consensus = review_multi(
        package=fx.name, version="0.0.1", ecosystem="PyPI",
        file_seq=file_seqs[0], ttp_matches=[],
        code_snippet="\n".join(fx.files.values())[:1500],
        mode="claude", model="claude-haiku-4-5",
    )
    llm_s = time.time() - t0

    print(f"  Stage 4c indicators: {len(ind_rep.hits)} "
          f"(HIGH={ind_rep.high_severity_count})")
    print(f"  Stage 4d taint flows: {taint}")
    print(f"  Stage 4e sequence patterns: {len(seq_rep.matches)}")
    print(f"  Stage 5 LLM verdict: {consensus.verdict.value} "
          f"(agreement={consensus.agreement_ratio:.2f}, {llm_s:.1f}s)")
    print(f"  → fixture expected: {sorted(v.value for v in fx.expected_verdict_set)}")
    return {
        "id": "synthetic-credential-exfil-base64",
        "label": "malicious",
        "ind_hits": len(ind_rep.hits),
        "ind_high": ind_rep.high_severity_count,
        "taint": taint,
        "seq": len(seq_rep.matches),
        "llm_verdict": consensus.verdict.value,
        "llm_agreement": round(consensus.agreement_ratio, 3),
        "llm_elapsed_s": round(llm_s, 1),
    }


def run_datadog(name: str, ecosystem: str, version: str):
    """DataDog cache 샘플 → eval_real._evaluate 호출."""
    from eval_real import _evaluate, extract_archive
    print(f"\nDataDog {ecosystem}/{name}@{version}")

    # fixture 메타 찾기
    fx_path = ROOT / "scripts" / "eval_real_data" / "fixtures.json"
    fx_meta = None
    for f in json.loads(fx_path.read_text(encoding="utf-8"))["fixtures"]:
        if (f["name"] == name and f["ecosystem"] == ecosystem
                and f["version"] == version):
            fx_meta = f
            break
    if fx_meta is None:
        print(f"  not in fixtures.json — skip")
        return None

    data_dir = ROOT / "scripts" / "eval_real_data"
    archive_bytes = (data_dir / fx_meta["archive_path"]).read_bytes()
    files = extract_archive(
        archive_bytes, fx_meta["archive_format"], "malicious",
    )
    if not files:
        print("  no files extracted")
        return None

    fixture_for_eval = {
        "name": name, "ecosystem": ecosystem, "version": version,
        "label": "malicious", "source": fx_meta["source"],
    }
    t0 = time.time()
    r = _evaluate(fixture_for_eval, files)
    elapsed = time.time() - t0

    print(f"  files extracted: {len(files)}")
    print(f"  verdict: {r.verdict}  (label={r.label}, ok={r.expected})")
    print(f"  ind={r.matchers.get('ind_47')}({r.matchers.get('ind_47_high')}H) "
          f"seq={r.matchers.get('seq_pattern')}({r.matchers.get('seq_high')}H) "
          f"taint={r.matchers.get('taint_flows')}")
    print(f"  LLM: {r.matchers.get('llm_stub')}  elapsed={elapsed:.1f}s")
    return {
        "id": f"{ecosystem}/{name}@{version}",
        "source": fx_meta["source"],
        "label": "malicious",
        "verdict": r.verdict,
        "expected": r.expected,
        "matchers": r.matchers,
        "elapsed_s": round(elapsed, 1),
    }


def run_legitimate():
    """정상 패키지 — requests@latest. CLEAN 기대."""
    print(f"\n[6/6] LEGITIMATE: requests@latest")
    from pkgsentinel.pipeline import run_pipeline
    from pkgsentinel.schema import Ecosystem
    # 격리 DB 셋업
    import tempfile
    td = tempfile.mkdtemp(prefix="demo_legit_")
    os.environ["AISLOP_DB_KEY"] = "demo-dry-run-key"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )

    t0 = time.time()
    rep = run_pipeline(
        "requests", Ecosystem.PYPI,
        llm_mode="claude", llm_model="claude-haiku-4-5",
        use_cache=True, force_rescan=True,
    )
    elapsed = time.time() - t0
    print(f"  verdict: {rep.verdict.value}  elapsed={elapsed:.1f}s")
    if rep.evidence:
        print(f"  top evidence: {rep.evidence[0].ttp_name[:80]}")
    print(f"  → expected: CLEAN")

    import shutil; shutil.rmtree(td, ignore_errors=True)
    return {
        "id": "PyPI/requests@latest",
        "label": "benign",
        "verdict": rep.verdict.value,
        "expected": rep.verdict.value == "CLEAN",
        "elapsed_s": round(elapsed, 1),
    }


def main():
    results = []

    # 1) Synthetic
    try:
        results.append(run_synthetic())
    except Exception as e:
        print(f"  synthetic failed: {type(e).__name__}: {e}")

    # 2-5) DataDog samples
    samples = [
        ("pyqubee", "PyPI", "12.1.1"),
        ("@operato/board", "npm", "9.0.40"),
        ("react-native-websocket", "npm", "1.0.4"),
        ("num2words", "PyPI", "0.5.16"),
    ]
    for i, (name, eco, ver) in enumerate(samples, 2):
        print(f"\n[{i}/6]", end=" ")
        try:
            r = run_datadog(name, eco, ver)
            if r:
                results.append(r)
        except Exception as e:
            print(f"  failed: {type(e).__name__}: {e}")

    # 6) Legitimate
    try:
        results.append(run_legitimate())
    except Exception as e:
        print(f"  legitimate failed: {type(e).__name__}: {e}")

    # 요약
    print("\n" + "=" * 70)
    print(f"{'sample':<45} {'label':<10} {'verdict':<14} ok")
    print("-" * 70)
    for r in results:
        name = r.get("id", "?")[:43]
        label = r.get("label", "?")
        verdict = r.get("verdict") or r.get("llm_verdict") or "?"
        ok = r.get("expected", "?")
        print(f"{name:<45} {label:<10} {verdict:<14} {ok}")

    # JSON 저장
    out = ROOT / "scripts" / "eval_real_data" / "results_demo_dry_run.json"
    out.write_text(
        json.dumps({"results": results,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                   indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(f"\nJSON saved -> {out}")


if __name__ == "__main__":
    main()
