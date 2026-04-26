"""
CycloneDX SBOM + VEX 출력기.

근거: CycloneDX v1.5/1.6 — https://cyclonedx.org/
       VEX (Vulnerability Exploitability eXchange) —
       https://cyclonedx.org/capabilities/vex/

목적:
  AnalysisReport 를 표준 CycloneDX JSON 으로 직렬화.
  - components[]    : 분석 대상 패키지 1개
  - vulnerabilities[] : 우리 Evidence 각각을 VEX 항목으로 변환

판정 → CycloneDX analysis.state 매핑:
  MALICIOUS / HIGH_RISK   → exploitable
  SUSPICIOUS              → in_triage
  CLEAN                   → not_affected
  ERROR / CANNOT_ANALYZE  → in_triage
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from ..schema import (
    AnalysisReport,
    Ecosystem,
    Evidence,
    LLMVerdict,
    Severity,
    Verdict,
)


_TOOL_VENDOR = "ai-slopsquatting-detector"
_TOOL_NAME = "secure-capstone"
_TOOL_VERSION = "2.0"
_SCHEMA_VERSION = "1.5"


def _purl(pkg: str, eco: Ecosystem, version: str) -> str:
    if eco == Ecosystem.PYPI:
        return f"pkg:pypi/{pkg}@{version}"
    if eco == Ecosystem.NPM:
        return f"pkg:npm/{pkg}@{version}"
    return f"pkg:generic/{pkg}@{version}"


def _severity_to_cdx(sev: Severity) -> str:
    return {
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
    }.get(sev, "unknown")


def _verdict_to_state(v: Verdict) -> str:
    """전체 verdict → 기본 vuln state."""
    return {
        Verdict.MALICIOUS: "exploitable",
        Verdict.HIGH_RISK: "exploitable",
        Verdict.SUSPICIOUS: "in_triage",
        Verdict.CLEAN: "not_affected",
        Verdict.ERROR: "in_triage",
        Verdict.CANNOT_ANALYZE: "in_triage",
    }.get(v, "in_triage")


def _llm_to_state(verdict: LLMVerdict) -> str:
    return {
        LLMVerdict.MALICIOUS: "exploitable",
        LLMVerdict.SUSPICIOUS: "in_triage",
        LLMVerdict.BENIGN: "not_affected",
    }.get(verdict, "in_triage")


def _evidence_to_vuln(
    e: Evidence,
    pkg_purl: str,
    overall_state: str,
) -> dict:
    """Evidence -> CycloneDX vulnerability 항목."""
    state = _llm_to_state(e.llm_verdict) if e.llm_verdict else overall_state

    # CycloneDX rating 객체
    rating = {
        "method": "other",
        "severity": _severity_to_cdx(e.ttp_severity) if e.ttp_severity else "unknown",
        "score": round(min(1.0, max(0.0, e.confidence)) * 10.0, 2),
    }

    # Source 매핑 — 우리 ttp_source 를 표준 'source.name' 으로
    src_name = e.ttp_source.value if e.ttp_source else "internal"

    return {
        "bom-ref": f"vuln-{e.ttp_id}-{e.file_path}-{e.line_start}",
        "id": e.ttp_id,
        "source": {"name": src_name, "url": e.ttp_url or ""},
        "ratings": [rating],
        "description": e.ttp_name,
        "detail": (e.llm_reasoning or "")[:1500],
        "affects": [{"ref": pkg_purl}],
        "analysis": {
            "state": state,
            "justification": "code_analysis",
            "detail": (
                f"file={e.file_path} L{e.line_start}-{e.line_end}; "
                f"sequence={' -> '.join(e.behavior_sequence[:6])}"
            )[:2000],
            "response": ["update", "rollback"] if state == "exploitable" else [],
        },
        "properties": [
            {"name": "ai-slopsq:vector_similarity", "value": str(round(e.vector_similarity, 3))},
            {"name": "ai-slopsq:confidence", "value": str(round(e.confidence, 3))},
            {"name": "ai-slopsq:llm_model", "value": e.llm_model or ""},
            {"name": "ai-slopsq:llm_verdict",
             "value": e.llm_verdict.value if e.llm_verdict else ""},
        ],
    }


def to_cyclonedx(report: AnalysisReport) -> dict:
    """AnalysisReport -> CycloneDX v1.5 JSON dict."""
    pkg_purl = _purl(report.package, report.ecosystem, report.version)
    overall_state = _verdict_to_state(report.verdict)

    # 메타데이터 생성 시각
    ts = (
        report.analyzed_at.isoformat()
        if hasattr(report, "analyzed_at") and report.analyzed_at
        else datetime.now(timezone.utc).isoformat()
    )

    component = {
        "type": "library",
        "bom-ref": pkg_purl,
        "name": report.package,
        "version": report.version,
        "purl": pkg_purl,
    }

    # Scorecard / SLSA 메타 → component.properties
    pm = report.package_meta or {}
    properties: list[dict] = [
        {"name": "ai-slopsq:verdict", "value": report.verdict.value},
        {"name": "ai-slopsq:source_files", "value": str(pm.get("source_files", 0))},
        {"name": "ai-slopsq:archive_size", "value": str(pm.get("archive_size", 0))},
    ]
    if "scorecard" in pm and pm["scorecard"].get("overall_score") is not None:
        properties.append({
            "name": "ai-slopsq:scorecard_score",
            "value": str(pm["scorecard"]["overall_score"]),
        })
    if "slsa" in pm:
        properties.append({
            "name": "ai-slopsq:slsa_level",
            "value": pm["slsa"].get("level", "UNKNOWN"),
        })
    if "ssdf" in pm:
        ssdf = pm["ssdf"]
        properties.append({
            "name": "ai-slopsq:ssdf_pass",
            "value": f"{ssdf.get('pass', 0)}/{len(ssdf.get('checks', []))}",
        })
    component["properties"] = properties

    vulnerabilities = [
        _evidence_to_vuln(e, pkg_purl, overall_state)
        for e in (report.evidence or [])
    ]

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": _SCHEMA_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [{
                "vendor": _TOOL_VENDOR,
                "name": _TOOL_NAME,
                "version": _TOOL_VERSION,
            }],
            "component": component,
        },
        "components": [component],
        "vulnerabilities": vulnerabilities,
    }
    return bom


def to_json(report: AnalysisReport, indent: int = 2) -> str:
    return json.dumps(
        to_cyclonedx(report),
        indent=indent,
        ensure_ascii=False,
        default=str,
    )


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    # 더미 AnalysisReport 만들기
    from ..schema import (
        AttackDimension,
        TTPSource,
        empty_report,
    )

    rep = empty_report("evil-helpers", Ecosystem.PYPI, "0.0.1")
    rep.verdict = Verdict.MALICIOUS
    rep.package_meta = {
        "source_files": 5,
        "archive_size": 12345,
        "scorecard": {"overall_score": 4.2, "checks": []},
        "slsa": {"level": "L0"},
        "ssdf": {"pass": 3, "checks": [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}]},
    }
    rep.evidence = [
        Evidence(
            file_path="evil-helpers-0.0.1/setup.py",
            line_start=10, line_end=12,
            code_snippet="os.environ.get('AWS_KEY')",
            behavior_sequence=["os.environ.get", "base64.b64encode", "requests.post"],
            attack_dimensions=[
                AttackDimension.INFORMATION_READING,
                AttackDimension.ENCODING,
                AttackDimension.DATA_TRANSMISSION,
            ],
            ttp_id="T1552.001",
            ttp_name="Unsecured Credentials",
            ttp_source=TTPSource.MITRE_ATTACK,
            ttp_url="https://attack.mitre.org/techniques/T1552/001/",
            ttp_severity=Severity.HIGH,
            vector_similarity=1.0,
            llm_verdict=LLMVerdict.MALICIOUS,
            llm_reasoning="credential exfil chain",
            llm_model="multi-agent",
            confidence=0.92,
        ),
    ]

    print(to_json(rep))
