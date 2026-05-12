"""CycloneDX 1.5 + STIX 2.1 외부 스키마 호환성 검증.

전체 CycloneDX 스키마는 200+ KB JSON 이라 매번 fetch 하지 않고,
필수 필드/타입만 자체 가드 스키마로 검증. 본 테스트의 목적은:
  - 우리 출력이 호환 도구 (cyclonedx-cli, opencti) 에서 즉시 거부되지 않을
    최소 요구사항을 만족하는지 빠르게 검증.
  - 완전한 conformance 는 별도 CI 단계 (실 검증기 호출) 에서.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jsonschema

from pkgsentinel.realtime.sinks.stix_sink import to_stix_bundle
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
from pkgsentinel.stages.stage_vex import to_cyclonedx

# ─────────────── 가드 스키마 (필수 필드만) ───────────────

CYCLONEDX_GUARD_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["bomFormat", "specVersion", "serialNumber",
                 "version", "metadata", "components", "vulnerabilities"],
    "properties": {
        "bomFormat":    {"const": "CycloneDX"},
        "specVersion":  {"type": "string", "pattern": r"^1\.[345]$"},
        "serialNumber": {"type": "string", "pattern": r"^urn:uuid:"},
        "version":      {"type": "integer", "minimum": 1},
        "metadata": {
            "type": "object",
            "required": ["timestamp", "component"],
            "properties": {
                "timestamp": {"type": "string"},
                "component": {
                    "type": "object",
                    "required": ["type", "name", "purl"],
                    "properties": {
                        "type": {"enum": ["library", "application",
                                          "framework"]},
                        "purl": {"type": "string",
                                 "pattern": r"^pkg:"},
                    },
                },
            },
        },
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "name", "purl"],
                "properties": {
                    "purl": {"type": "string", "pattern": r"^pkg:"},
                },
            },
        },
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "analysis"],
                "properties": {
                    "analysis": {
                        "type": "object",
                        "required": ["state"],
                        "properties": {
                            "state": {"enum": [
                                "exploitable", "not_affected",
                                "in_triage", "false_positive", "resolved",
                            ]},
                        },
                    },
                },
            },
        },
    },
}

STIX_GUARD_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["type", "id", "objects"],
    "properties": {
        "type": {"const": "bundle"},
        "id":   {"type": "string", "pattern": r"^bundle--[0-9a-f-]{36}$"},
        "objects": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["type", "id"],
                "properties": {
                    "type": {"type": "string"},
                    "id":   {"type": "string", "pattern": r"^[a-z-]+--"},
                },
            },
        },
    },
}


def _make_malicious_report():
    rep = empty_report("evil-pkg", Ecosystem.PYPI, "0.0.1")
    rep.verdict = Verdict.MALICIOUS
    rep.package_meta = {
        "source_files": 2,
        "archive_size": 800,
    }
    rep.evidence = [Evidence(
        file_path="setup.py",
        line_start=1, line_end=3,
        code_snippet="os.environ.get('AWS_KEY')",
        behavior_sequence=["os.environ.get", "requests.post"],
        attack_dimensions=[
            AttackDimension.INFORMATION_READING,
            AttackDimension.DATA_TRANSMISSION,
        ],
        ttp_id="T1041",
        ttp_name="Exfiltration Over C2",
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url="https://attack.mitre.org/techniques/T1041/",
        ttp_severity=Severity.HIGH,
        vector_similarity=0.9,
        llm_verdict=LLMVerdict.MALICIOUS,
        llm_reasoning="creds out",
        llm_model="multi-agent",
        confidence=0.92,
    )]
    return rep


# ─────────────── 테스트 ───────────────

def test_cyclonedx_validates_against_guard():
    print("== CycloneDX guard schema ==")
    rep = _make_malicious_report()
    bom = to_cyclonedx(rep)
    jsonschema.validate(bom, CYCLONEDX_GUARD_SCHEMA)
    print(f"  OK bomFormat={bom['bomFormat']} purl={bom['components'][0]['purl']}")


def test_cyclonedx_json_round_trip():
    """JSON dump/load 라운드트립 통과 — UTF-8, ensure_ascii=False 등 OK."""
    print("\n== CycloneDX JSON round-trip ==")
    rep = _make_malicious_report()
    bom = to_cyclonedx(rep)
    s = json.dumps(bom, ensure_ascii=False)
    parsed = json.loads(s)
    jsonschema.validate(parsed, CYCLONEDX_GUARD_SCHEMA)
    print(f"  OK {len(s)} chars")


def test_stix_bundle_validates_against_guard():
    print("\n== STIX 2.1 bundle guard schema ==")
    bundle = to_stix_bundle({
        "verdict": "MALICIOUS",
        "package": "evil-pkg",
        "ecosystem": "PyPI",
        "version": "0.0.1",
        "evidence": [{
            "code_snippet": "requests.post('https://x.com')",
            "ttp_id": "T1041",
            "ttp_url": "https://attack.mitre.org/techniques/T1041/",
            "llm_reasoning": "creds out",
            "confidence": 0.9,
        }],
        "package_meta": {"advisory_summary": "exfil"},
    })
    jsonschema.validate(bundle, STIX_GUARD_SCHEMA)
    # required STIX 2.1 object types in malicious bundle
    types = [o["type"] for o in bundle["objects"]]
    for t in ("identity", "software", "indicator", "malware", "relationship"):
        assert t in types, f"missing {t}"
    print(f"  OK types={types}")


def test_stix_clean_verdict_has_no_malware_object():
    """clean / benign 판정에는 malware SDO 가 없어야."""
    print("\n== STIX clean -> no malware SDO ==")
    bundle = to_stix_bundle({
        "verdict": "CLEAN",
        "package": "good-pkg",
        "ecosystem": "PyPI",
        "version": "1.0.0",
        "evidence": [],
        "package_meta": {},
    })
    jsonschema.validate(bundle, STIX_GUARD_SCHEMA)
    types = [o["type"] for o in bundle["objects"]]
    assert "malware" not in types, f"unexpected malware SDO in clean bundle: {types}"
    print(f"  OK types={types}")


def main():
    tests = [
        test_cyclonedx_validates_against_guard,
        test_cyclonedx_json_round_trip,
        test_stix_bundle_validates_against_guard,
        test_stix_clean_verdict_has_no_malware_object,
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
