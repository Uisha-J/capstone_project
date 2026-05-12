"""MITRE ATLAS / OWASP LLM 카탈로그 단위 테스트."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.knowledge import mitre_atlas, owasp_llm


def test_atlas_basic():
    print("== ATLAS basic ==")
    s = mitre_atlas.stats()
    print(f"  total: {s['total']}, supply_chain_relevant: {s['supply_chain_relevant']}")
    print(f"  by tactic: {s['by_tactic']}")
    assert s["total"] >= 8 and s["supply_chain_relevant"] >= 6


def test_atlas_get():
    print("\n== ATLAS get ==")
    t = mitre_atlas.get("AML.T0010.002")
    print(f"  AML.T0010.002 -> {t.name if t else 'NOT FOUND'}")
    assert t is not None and "ML Software" in t.name


def test_atlas_slopsquatting_techniques():
    print("\n== ATLAS slopsquatting techniques ==")
    techs = mitre_atlas.supply_chain_relevant()
    ids = [t.id for t in techs]
    print(f"  ids: {ids}")
    must_have = {"AML.T0010", "AML.T0010.002", "AML.T0020"}
    missing = must_have - set(ids)
    if missing:
        print(f"  MISSING: {missing}")
    assert not missing
    print(f"  OK: contains {must_have}")


def test_owasp_basic():
    print("\n== OWASP LLM basic ==")
    s = owasp_llm.stats()
    print(f"  total: {s['total']}, slopsquatting_related: {s['slopsquatting_related']}")
    assert s["total"] == 10 and s["slopsquatting_related"] >= 1


def test_owasp_llm05():
    print("\n== OWASP LLM05 (Supply Chain) ==")
    it = owasp_llm.get("LLM05")
    print(f"  name: {it.name if it else 'NOT FOUND'}")
    print(f"  related_to_slopsquatting: {it.related_to_slopsquatting}")
    assert it is not None and it.related_to_slopsquatting


def test_owasp_verdict_mapping():
    print("\n== OWASP verdict mapping ==")
    cases = [
        ("MALICIOUS", ["LLM05", "LLM09"]),
        ("HIGH_RISK", ["LLM05", "LLM09"]),
        ("SUSPICIOUS", ["LLM05"]),
        ("CLEAN", []),
        ("CANNOT_ANALYZE", ["LLM05", "LLM09"]),
    ]
    ok = True
    for v, expected in cases:
        got = owasp_llm.map_verdict_to_owasp(v)
        mark = "OK  " if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"  [{mark}] {v:<14} -> {got}")
    assert ok


def main():
    tests = [
        test_atlas_basic,
        test_atlas_get,
        test_atlas_slopsquatting_techniques,
        test_owasp_basic,
        test_owasp_llm05,
        test_owasp_verdict_mapping,
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
