"""
Stage agentic — AISLOPSQ 분류 단계.

흐름:
  1. ext.source_files 에서 .py / .js 소스 모음
  2. pyproject.toml / package.json 텍스트 추출
  3. detector.agentic.classify() 실행
  4. 결과를 (verdict, evidence, package_meta) 형태로 변환

이 stage 는 Step 1 (agentic 판별) 까지만 게이트로 사용. agentic 인 경우
classify() 의 verdict 가 우선 (final). 일반 패키지 (non-agentic) 는 fall-through
하여 47-indicator 파이프라인이 그대로 실행.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..agentic import classify, AgenticClassification
from ..agentic.rules import RuleSeverity
from ..schema import (
    AttackDimension, Ecosystem, Evidence, LLMVerdict, Severity,
    TTPSource, Verdict,
)


# ─────────────── 결과 ───────────────

@dataclass
class StageAgenticResult:
    triggered: bool                       # agentic 으로 판정되어 본 stage 가 verdict 결정
    classification: Optional[AgenticClassification] = None
    verdict: Optional[Verdict] = None
    evidence: list[Evidence] = None
    package_meta: dict = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.package_meta is None:
            self.package_meta = {}


# ─────────────── 입력 추출 헬퍼 ───────────────

def _collect_sources(source_files, language_filter: str) -> dict[str, str]:
    """ext.source_files 에서 해당 언어 파일들의 {path: content} 추출."""
    out: dict[str, str] = {}
    for sf in source_files or []:
        if getattr(sf, "language", "") != language_filter:
            continue
        out[sf.path] = sf.content or ""
    return out


def _find_manifest_text(source_files, basename: str) -> Optional[str]:
    """basename (pyproject.toml / package.json) 매칭 첫 파일."""
    for sf in source_files or []:
        if sf.basename == basename or sf.path.endswith(f"/{basename}"):
            return sf.content
    return None


def _extract_deps_from_pyproject(text: str | None) -> list[str]:
    if not text:
        return []
    try:
        try:
            import tomllib
            data = tomllib.loads(text)
        except (ImportError, AttributeError):
            import tomli  # type: ignore
            data = tomli.loads(text)
    except Exception:
        return []
    out: list[str] = []
    proj = data.get("project") or {}
    deps = proj.get("dependencies") or []
    for d in deps:
        # d 형식: "pkg>=1.0" 같은 PEP 508 — 단순 split
        name = d.split("[")[0].split(";")[0].split("=")[0].split("<")[0]\
                .split(">")[0].split("~")[0].strip()
        if name:
            out.append(name.lower())
    # tool.poetry / setup.py legacy 무시 (Stage_dependency 가 별도 처리)
    return out


def _extract_deps_from_package_json(text: str | None) -> list[str]:
    if not text:
        return []
    import json
    try:
        data = json.loads(text)
    except Exception:
        return []
    deps: list[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        d = data.get(key) or {}
        if isinstance(d, dict):
            deps.extend(d.keys())
    return [d.lower() for d in deps]


# ─────────────── Verdict / Evidence 변환 ───────────────

def _severity_from_verdict(v: Verdict) -> Severity:
    return {
        Verdict.MALICIOUS: Severity.HIGH,
        Verdict.HIGH_RISK: Severity.HIGH,
        Verdict.SUSPICIOUS: Severity.MEDIUM,
        Verdict.AGENTIC: Severity.LOW,
        Verdict.CLEAN: Severity.LOW,
    }.get(v, Severity.MEDIUM)


def _llm_verdict_from(v: Verdict) -> LLMVerdict:
    return {
        Verdict.MALICIOUS: LLMVerdict.MALICIOUS,
        Verdict.HIGH_RISK: LLMVerdict.MALICIOUS,
        Verdict.SUSPICIOUS: LLMVerdict.SUSPICIOUS,
        Verdict.AGENTIC: LLMVerdict.SUSPICIOUS,
        Verdict.CLEAN: LLMVerdict.BENIGN,
    }.get(v, LLMVerdict.SUSPICIOUS)


def _classification_to_evidence(c: AgenticClassification) -> list[Evidence]:
    """rule hits 각각을 Evidence 로."""
    evs: list[Evidence] = []

    # 큰 그림: capability summary 1건
    sev = _severity_from_verdict(c.verdict)
    evs.append(Evidence(
        file_path="<aislopsq>",
        line_start=0, line_end=0,
        code_snippet=(
            f"declared={sorted(c.declared)}, detected={sorted(c.detected)}, "
            f"undeclared={sorted(c.undeclared)}, ABC={sorted(c.abc_actual)}, "
            f"HITL={c.has_human_in_the_loop}"
        ),
        behavior_sequence=[f"aislopsq:{c.verdict.value}"],
        attack_dimensions=[],
        ttp_id="AISLOPSQ-CLS",
        ttp_name="AISLOPSQ Agentic Classification",
        ttp_source=TTPSource.OWASP_LLM,
        ttp_url="https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/",
        ttp_severity=sev,
        vector_similarity=1.0,
        llm_verdict=_llm_verdict_from(c.verdict),
        llm_reasoning=c.reason,
        llm_model="aislopsq-classifier",
        confidence=0.9 if c.verdict in (Verdict.MALICIOUS, Verdict.HIGH_RISK)
                  else 0.6,
    ))

    # 각 rule hit
    if c.rule_report is not None:
        for h in c.rule_report.hits:
            llm_v = LLMVerdict.MALICIOUS if h.severity == RuleSeverity.MALICIOUS \
                    else LLMVerdict.SUSPICIOUS
            sev_e = (Severity.HIGH if h.severity == RuleSeverity.MALICIOUS
                     else Severity.HIGH if h.severity == RuleSeverity.HIGH_RISK
                     else Severity.MEDIUM)
            evs.append(Evidence(
                file_path=h.file_path or "<aislopsq>",
                line_start=0, line_end=0,
                code_snippet=h.snippet[:1500],
                behavior_sequence=[f"aislopsq:{h.rule_id}"],
                attack_dimensions=[],
                ttp_id=f"AISLOPSQ-{h.rule_id}",
                ttp_name=f"AISLOPSQ {h.rule_id}",
                ttp_source=TTPSource.OWASP_LLM,
                ttp_url=(
                    "https://github.com/anthropics/aislopsq/spec/RULES.md"
                ),
                ttp_severity=sev_e,
                vector_similarity=1.0,
                llm_verdict=llm_v,
                llm_reasoning=h.reason + (
                    f" [excused: {', '.join(h.excused_by)}]" if h.excused_by else ""
                ),
                llm_model="aislopsq-rules",
                confidence=(
                    0.9 if h.severity == RuleSeverity.MALICIOUS
                    else 0.75 if h.severity == RuleSeverity.HIGH_RISK
                    else 0.55
                ),
            ))
    return evs


# ─────────────── 공개 API ───────────────

def run(
    *,
    package_name: str,
    description: str = "",
    declared_deps: list[str] | None = None,
    source_files,                   # list[FullSourceFile]
    ecosystem: Ecosystem,
) -> StageAgenticResult:
    """파이프라인용 entrypoint."""
    is_python = ecosystem == Ecosystem.PYPI

    if is_python:
        sources = _collect_sources(source_files, "python")
        manifest_text = _find_manifest_text(source_files, "pyproject.toml")
        manifest_deps = _extract_deps_from_pyproject(manifest_text)
        cls = classify(
            package_name=package_name, description=description,
            dependencies=list({*manifest_deps, *(declared_deps or [])}),
            sources=sources,
            pyproject_text=manifest_text,
            language="python",
        )
    else:
        sources = _collect_sources(source_files, "javascript")
        manifest_text = _find_manifest_text(source_files, "package.json")
        manifest_deps = _extract_deps_from_package_json(manifest_text)
        cls = classify(
            package_name=package_name, description=description,
            dependencies=list({*manifest_deps, *(declared_deps or [])}),
            sources=sources,
            package_json_text=manifest_text,
            language="javascript",
        )

    if not cls.is_agentic:
        return StageAgenticResult(
            triggered=False,
            classification=cls,
            package_meta={"aislopsq": cls.to_dict()},
        )

    return StageAgenticResult(
        triggered=True,
        classification=cls,
        verdict=cls.verdict,
        evidence=_classification_to_evidence(cls),
        package_meta={"aislopsq": cls.to_dict()},
    )
