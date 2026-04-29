"""AnalysisReport → JSON-직렬화 가능 dict 변환 (캐시 저장용)."""
from __future__ import annotations

from ..schema import AnalysisReport


def report_to_serializable(report: AnalysisReport) -> dict:
    """AnalysisReport -> JSON-serializable dict (캐시 저장용)."""
    out = {
        "verdict": report.verdict.value,
        "package": report.package,
        "ecosystem": report.ecosystem.value,
        "version": report.version,
        "package_meta": report.package_meta or {},
        "evidence": [],
    }
    for e in report.evidence or []:
        try:
            d = {
                "file_path": e.file_path,
                "line_start": e.line_start,
                "line_end": e.line_end,
                "code_snippet": e.code_snippet,
                "behavior_sequence": list(e.behavior_sequence or []),
                "attack_dimensions": [d.value for d in (e.attack_dimensions or [])],
                "ttp_id": e.ttp_id,
                "ttp_name": e.ttp_name,
                "ttp_source": e.ttp_source.value if e.ttp_source else None,
                "ttp_url": e.ttp_url,
                "ttp_severity": e.ttp_severity.value if e.ttp_severity else None,
                "vector_similarity": e.vector_similarity,
                "llm_verdict": e.llm_verdict.value if e.llm_verdict else None,
                "llm_reasoning": e.llm_reasoning,
                "llm_model": e.llm_model,
                "confidence": e.confidence,
            }
            out["evidence"].append(d)
        except Exception:
            continue
    return out
