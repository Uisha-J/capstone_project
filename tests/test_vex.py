"""CycloneDX VEX 출력 단위 테스트."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import (
    AttackDimension,
    Ecosystem,
    Evidence,
    LLMVerdict,
    Severity,
    TTPSource,
    Verdict,
    empty_report,
)
from pkgsentinel.stages.stage_vex import _purl, to_cyclonedx, to_json


def make_report(verdict: Verdict, llm_v: LLMVerdict) -> object:
    rep = empty_report("samplepkg", Ecosystem.PYPI, "1.0.0")
    rep.verdict = verdict
    rep.package_meta = {
        "source_files": 3,
        "archive_size": 1234,
        "scorecard": {"overall_score": 7.0, "checks": []},
        "slsa": {"level": "L2"},
        "ssdf": {"pass": 9, "checks": [{}] * 11},
    }
    rep.evidence = [
        Evidence(
            file_path="samplepkg-1.0/setup.py",
            line_start=5, line_end=7,
            code_snippet="os.environ.get('TOKEN')",
            behavior_sequence=["os.environ.get", "requests.post"],
            attack_dimensions=[
                AttackDimension.INFORMATION_READING,
                AttackDimension.DATA_TRANSMISSION,
            ],
            ttp_id="T1041",
            ttp_name="Exfiltration Over C2 Channel",
            ttp_source=TTPSource.MITRE_ATTACK,
            ttp_url="https://attack.mitre.org/techniques/T1041/",
            ttp_severity=Severity.HIGH,
            vector_similarity=0.95,
            llm_verdict=llm_v,
            llm_reasoning="creds out",
            llm_model="multi-agent",
            confidence=0.88,
        ),
    ]
    return rep


def test_basic_structure():
    print("== Basic structure ==")
    rep = make_report(Verdict.MALICIOUS, LLMVerdict.MALICIOUS)
    bom = to_cyclonedx(rep)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"]["purl"] == _purl("samplepkg", Ecosystem.PYPI, "1.0.0")
    assert len(bom["components"]) == 1
    assert len(bom["vulnerabilities"]) == 1
    print(f"  OK - purl={bom['components'][0]['purl']}")


def test_state_mapping():
    print("\n== Verdict -> state mapping ==")
    cases = [
        (Verdict.MALICIOUS, LLMVerdict.MALICIOUS, "exploitable"),
        (Verdict.SUSPICIOUS, LLMVerdict.SUSPICIOUS, "in_triage"),
        (Verdict.CLEAN, LLMVerdict.BENIGN, "not_affected"),
        (Verdict.HIGH_RISK, LLMVerdict.MALICIOUS, "exploitable"),
    ]
    ok = True
    for v, llm_v, expected in cases:
        rep = make_report(v, llm_v)
        bom = to_cyclonedx(rep)
        actual = bom["vulnerabilities"][0]["analysis"]["state"]
        status = "OK  " if actual == expected else "FAIL"
        print(f"  [{status}] {v.value:<14} llm={llm_v.value:<11} -> {actual}")
        if actual != expected:
            ok = False
    assert ok


def test_metadata_properties():
    print("\n== Component metadata properties ==")
    rep = make_report(Verdict.SUSPICIOUS, LLMVerdict.SUSPICIOUS)
    bom = to_cyclonedx(rep)
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    expected = {
        "ai-slopsq:verdict": "SUSPICIOUS",
        "ai-slopsq:source_files": "3",
        "ai-slopsq:scorecard_score": "7.0",
        "ai-slopsq:slsa_level": "L2",
        "ai-slopsq:ssdf_pass": "9/11",
    }
    ok = True
    for k, v in expected.items():
        actual = props.get(k)
        if actual != v:
            print(f"  FAIL: {k} = {actual!r} (expected {v!r})")
            ok = False
        else:
            print(f"  OK  {k} = {v}")
    assert ok


def test_json_serializable():
    print("\n== JSON serialization ==")
    rep = make_report(Verdict.MALICIOUS, LLMVerdict.MALICIOUS)
    s = to_json(rep)
    parsed = json.loads(s)  # round-trip 가능해야 함
    print(f"  json size: {len(s)} chars")
    print(f"  vulnerabilities: {len(parsed['vulnerabilities'])}")
    assert parsed["vulnerabilities"][0]["id"] == "T1041"


def test_purl_npm():
    print("\n== npm purl format ==")
    rep = empty_report("chalk", Ecosystem.NPM, "5.0.0")
    rep.verdict = Verdict.CLEAN
    rep.evidence = []
    bom = to_cyclonedx(rep)
    purl = bom["components"][0]["purl"]
    print(f"  purl: {purl}")
    assert purl == "pkg:npm/chalk@5.0.0"


def main():
    tests = [
        test_basic_structure,
        test_state_mapping,
        test_metadata_properties,
        test_json_serializable,
        test_purl_npm,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception:
            import traceback
            traceback.print_exc()
            failed += 1
    print("\n" + ("ALL OK" if failed == 0 else f"FAILED: {failed}"))


if __name__ == "__main__":
    main()
