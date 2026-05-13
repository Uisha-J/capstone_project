"""Rule generator (#L5) + attack_index live-update (#L4) 단위 테스트."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.intel.rule_generator import (
    generate_aislopsq_r_extension,
    generate_all_drafts,
    generate_falco_rule,
    generate_indicator_47_rule,
    generate_sequence_pattern_rule,
)
from pkgsentinel.knowledge.attack_index import AttackPatternIndex
from pkgsentinel.knowledge.osv import AttackPattern


# ─────────────── #L5 rule generators ───────────────

def test_generate_indicator_47():
    print("== generate indicator_47 rule ==")
    pat = {
        "dimensions": ["INFORMATION_READING", "DATA_TRANSMISSION"],
        "indicator_codes": ["EXF-001", "NET-001"],
        "summary": "cred + network",
    }
    r = generate_indicator_47_rule([1, 2], pat, "auto-derived test")
    assert r.rule_kind == "indicator_47"
    body = json.loads(r.rule_body)
    assert body["code"].startswith("RT-")
    assert body["severity"] == "HIGH"     # 2 dimensions → HIGH
    assert "INFORMATION_READING" in body["dimensions"]
    assert r.source_observation_ids == [1, 2]
    print("  OK")


def test_indicator_47_medium_severity_single_dim():
    print("\n== indicator_47 severity = MEDIUM for single dim ==")
    pat = {"dimensions": ["INFORMATION_READING"],
           "indicator_codes": ["EXF-001"], "summary": "cred"}
    r = generate_indicator_47_rule([5], pat, "test")
    body = json.loads(r.rule_body)
    assert body["severity"] == "MEDIUM"
    print("  OK")


def test_generate_falco_rule_with_iocs():
    print("\n== generate Falco rule with IPs/domains/paths ==")
    iocs = [
        {"type": "ip", "value": "185.143.223.5:443", "confidence": 0.7},
        {"type": "domain", "value": "evil.example.net", "confidence": 0.8},
        {"type": "path", "value": "/root/.ssh/id_rsa", "confidence": 0.65},
    ]
    pat = {"summary": "cred read + external"}
    r = generate_falco_rule([10], iocs, pat, "test")
    assert r is not None
    assert r.rule_kind == "falco"
    assert "185.143.223.5" in r.rule_body
    assert "evil.example.net" in r.rule_body
    assert "id_rsa" in r.rule_body
    assert "priority: CRITICAL" in r.rule_body
    print("  OK")


def test_generate_falco_rule_returns_none_no_iocs():
    print("\n== Falco rule: no IOC → None ==")
    r = generate_falco_rule([1], [], {"summary": "noop"}, "test")
    assert r is None
    print("  OK")


def test_generate_sequence_pattern():
    print("\n== sequence_pattern: 2+ dimensions ==")
    pat = {"dimensions": ["INFORMATION_READING", "DATA_TRANSMISSION"],
           "summary": "exfil chain"}
    r = generate_sequence_pattern_rule([1], pat, "test")
    assert r is not None
    body = json.loads(r.rule_body)
    assert body["code"].startswith("SP-RT-")
    assert len(body["dimension_sequence"]) >= 2
    print("  OK")


def test_sequence_pattern_skips_single_dim():
    print("\n== sequence_pattern: single dim → None ==")
    pat = {"dimensions": ["INFORMATION_READING"], "summary": "only read"}
    r = generate_sequence_pattern_rule([1], pat, "test")
    assert r is None
    print("  OK")


def test_aislopsq_r_extension_for_cred_exfil():
    print("\n== AISLOPSQ R-extension for cred+net combo ==")
    pat = {"dimensions": ["INFORMATION_READING", "DATA_TRANSMISSION"],
           "summary": "cred exfil"}
    r = generate_aislopsq_r_extension([1], pat, "test")
    assert r is not None
    assert r.rule_kind == "aislopsq_r"
    body = json.loads(r.rule_body)
    assert body["extends"] == "R3"
    assert body["severity"] == "MALICIOUS"
    print("  OK")


def test_aislopsq_r_skips_other_combos():
    print("\n== AISLOPSQ R-extension skips non-cred-exfil ==")
    pat = {"dimensions": ["PAYLOAD_EXECUTION"], "summary": "exec only"}
    r = generate_aislopsq_r_extension([1], pat, "test")
    assert r is None
    print("  OK")


def test_generate_all_drafts():
    print("\n== generate_all_drafts: 가능한 모든 종류 ==")
    iocs = [{"type": "ip", "value": "1.2.3.4", "confidence": 0.7}]
    pat = {
        "dimensions": ["INFORMATION_READING", "DATA_TRANSMISSION"],
        "indicator_codes": ["EXF-001"],
        "summary": "cred + net",
    }
    drafts = generate_all_drafts([99], iocs, pat, "test")
    kinds = {d.rule_kind for d in drafts}
    # indicator_47 + falco + sequence + aislopsq_r 모두 생성됨
    assert "indicator_47" in kinds
    assert "falco" in kinds
    assert "sequence_pattern" in kinds
    assert "aislopsq_r" in kinds
    print(f"  OK kinds={kinds}")


# ─────────────── #L4 attack_index live-update ───────────────

def test_attack_index_add_runtime_pattern():
    print("\n== attack_index.add_runtime_pattern ==")
    idx = AttackPatternIndex([])
    p = AttackPattern(
        advisory_id="RT-001", aliases=[], source="runtime", ecosystem="npm",
        affected_packages=["new-evil"], affected_versions=["0.0.1"],
        summary="auto", details="", attack_type="malicious_package",
        published="2026-05-13", modified="2026-05-13",
    )
    idx.add_runtime_pattern(p)
    hits = idx.lookup_exact("new-evil", "npm", version="0.0.1")
    assert hits and hits[0].pattern.advisory_id == "RT-001"
    print("  OK")


def test_attack_index_add_runtime_pattern_dedup():
    """동일 advisory_id 재추가 무시."""
    print("\n== attack_index dedup ==")
    p = AttackPattern(
        advisory_id="RT-DUP", aliases=[], source="runtime", ecosystem="npm",
        affected_packages=["dup"], affected_versions=["1.0"],
        summary="", details="", attack_type="malicious_package",
        published="t", modified="t",
    )
    idx = AttackPatternIndex([p])
    idx.add_runtime_pattern(p)   # 재추가 — 무시되어야
    assert len(idx.patterns) == 1
    print("  OK")


def test_attack_index_add_runtime_ioc():
    print("\n== attack_index.add_runtime_ioc ==")
    idx = AttackPatternIndex([])
    idx.add_runtime_ioc(
        "ip", "185.143.223.5", confidence=0.85,
        associated_packages=["evil@0.1"],
        source_observation_id=42,
    )
    got = idx.lookup_runtime_ioc("ip", "185.143.223.5")
    assert got is not None
    assert got["confidence"] == 0.85
    assert "evil@0.1" in got["associated_packages"]
    assert idx.runtime_ioc_count() == 1
    print("  OK")


def test_attack_index_ioc_case_insensitive_for_domain():
    """domain / ip 매칭은 대소문자 무시."""
    print("\n== attack_index IOC lookup case-insensitive ==")
    idx = AttackPatternIndex([])
    idx.add_runtime_ioc("domain", "Evil.Example.COM", confidence=0.7)
    got = idx.lookup_runtime_ioc("domain", "evil.example.com")
    assert got is not None
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
