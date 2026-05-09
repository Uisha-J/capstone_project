"""사람 읽기 좋은 출력 / 표준 포맷 직렬화."""
from __future__ import annotations

from ..schema import AnalysisReport, Verdict


def format_cyclonedx(report: AnalysisReport) -> str:
    """리포트를 CycloneDX v1.5 SBOM + VEX JSON 으로 직렬화."""
    from ..stages.stage_vex import to_json as _vex_to_json
    return _vex_to_json(report)


def format_report(report: AnalysisReport) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append(f"Package   : {report.package} {report.version} ({report.ecosystem.value})")
    lines.append(f"Analyzed  : {report.analyzed_at.isoformat()}")

    # CLEAN + evidence ≥ 1: "(noisy)" 접미. 사용자가 verdict 만 보고
    # 묻힌 약한 신호를 놓치지 않도록 명시. package_meta.clean_with_noise 도 set.
    verdict_str = report.verdict.value
    if (
        report.verdict == Verdict.CLEAN
        and report.evidence
        and len(report.evidence) > 0
    ):
        verdict_str += f"  (noisy: {len(report.evidence)} weak evidence)"
        if report.package_meta is not None:
            report.package_meta.setdefault("clean_with_noise", True)

    lines.append(f"Verdict   : {verdict_str}")
    # 합법 도구 분류 (web framework / data science / dev tool 등 — 단순 boolean 노출)
    if report.package_meta and report.package_meta.get("legitimate_tool"):
        lines.append("Type      : legitimate tool (broad-purpose framework/library)")
    lines.append("=" * 70)

    lines.append("\n[Stage Results]")
    for s in report.stage_results:
        mark = "OK" if s.success else "FAIL"
        err = f" -- error: {s.error}" if s.error else ""
        payload_str = ""
        if s.payload:
            kvs = [f"{k}={v}" for k, v in list(s.payload.items())[:3]]
            payload_str = "  " + ", ".join(kvs)
        lines.append(f"  [{mark}] {s.stage}{payload_str}{err}")

    if report.evidence:
        lines.append(f"\n[Evidence ({len(report.evidence)})]")
        for i, e in enumerate(report.evidence, 1):
            lines.append(f"\n-- Evidence #{i} --")
            lines.append(f"  File     : {e.file_path} (L{e.line_start}-{e.line_end})")
            lines.append(f"  Sequence : {' -> '.join(e.behavior_sequence[:6])}")
            lines.append(f"  Dims     : {', '.join(d.value for d in e.attack_dimensions)}")
            lines.append(f"  TTP      : {e.ttp_id} -- {e.ttp_name}")
            lines.append(f"             ({e.ttp_source.value}, severity {e.ttp_severity.value}, sim {e.vector_similarity:.2f})")
            if e.ttp_url:
                lines.append(f"             {e.ttp_url}")
            lines.append(f"  LLM      : [{e.llm_verdict.value}] {e.llm_reasoning[:200]}")
            if e.version_diff:
                lines.append(f"  VerDiff  : {e.version_diff.risk_classification.value} -- {e.version_diff.details[:120]}")
            lines.append(f"  Conf     : {e.confidence:.2f}")
    else:
        lines.append("\n[Evidence] (none -- package appears clean)")

    return "\n".join(lines)
