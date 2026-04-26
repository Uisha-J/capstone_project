"""
전체 분석 파이프라인 (통합 버전).

실행 순서:
  Stage 0   레지스트리 확인
  Stage 0B  공격 이력 조회 (OSV DB)
  Stage 1B  전 파일 소스 추출 (Tier 1+2+3)
  Stage 2   Behavior Sequence (Python AST + JS tree-sitter)
  Stage 2B  문자열 상수 풀 분석 (base64/hex/고엔트로피)
  Stage 3B  전 파일 버전 diff (axios/event-stream 대응)
  Stage 4   TTP 매칭 (MITRE 임베딩 + 행위 규칙)
  Stage 4B  카테고리 이상 탐지
  Stage 5   LLM 이중 검증
  Stage 6   의존성 재귀 분석 (--deps 플래그 시)
  Stage 7   바이너리 분석 (.so/.dll/.node/.pyd 존재 시)
  Stage 8   샌드박스 동적 분석 (--sandbox 플래그 시)
  Stage 9   Verdict 결정 + 리포트 구성

필수 스테이지: 2, 4, 5. 그 외는 실패해도 경고로 기록하고 계속.
"""
from __future__ import annotations

import time
import traceback

# .env 자동 로드 (ANTHROPIC_API_KEY, OPENAI_API_KEY 등).
# detector 모듈을 어떻게 진입하든 — pipeline / worker / cron_main —
# 첫 import 시점에 1회 실행. 이미 환경변수에 있으면 덮어쓰지 않음.
from . import _dotenv as _aislopsq_dotenv
_aislopsq_dotenv.load()

from .schema import (
    AnalysisReport,
    AttackDimension,
    Ecosystem,
    Evidence,
    LLMVerdict,
    Severity,
    StageResult,
    TTPSource,
    Verdict,
    empty_report,
)
from .stages.stage0_registry import check
from .stages.stage0b_attack_history import (
    check_attack_history,
    to_evidence as attack_history_to_evidence,
)
from .stages.stage1b_full_source import extract_all, to_entry_files, FullSourceExtract
from .stages.stage2_behavior import analyze as analyze_behavior, BehaviorReport, FileSequence
from .stages.string_analysis import analyze_strings, SuspiciousString
from .stages.stage3b_full_diff import analyze_full_diff
from .stages.stage4_ttp_match import match_ttps, TTPMatch
from .stages.indicator_matcher import match_all as match_47_indicators, IndicatorHit
from .stages.taint_slicer import (
    analyze_python as taint_analyze_python,
    slice_for_llm as taint_slice_for_llm,
    TaintFlow,
)
from .stages.stage5_llm_review import review
from .stages.stage5_multi_agent import (
    review_multi,
    consensus_to_llm_response,
    ConsensusReport,
)
from .stages.stage_scorecard import (
    fetch_for_package as scorecard_fetch_for_package,
    extract_risk_signals as scorecard_risk_signals,
    ScorecardReport,
)
from .stages.stage_ssdf import (
    evaluate as ssdf_evaluate,
    SSDFReport,
)
from .stages.sequence_patterns import (
    mine as mine_sequences,
    SequenceMatch,
)
from .stages.stage_slsa import (
    evaluate as slsa_evaluate,
    SLSAReport,
)
from .stages.stage0_threat_filter import (
    run as threat_filter_run,
    to_evidence as threat_filter_to_evidence,
    ThreatFilterReport,
)
from .stages.stage_agentic import (
    run as agentic_run,
    StageAgenticResult,
)
from .db.integrity import IntegrityMode
from .verdict_rules import decide_verdict


# ─────────────── 헬퍼 ───────────────

def _find_file_seq(behavior: BehaviorReport, file_path: str) -> FileSequence | None:
    for fs in behavior.files:
        if fs.path == file_path:
            return fs
    return None


def _snippet_for(file_seq: FileSequence, max_lines: int = 30) -> str:
    if not file_seq.calls:
        return ""
    return "\n".join(c.snippet for c in file_seq.calls[:max_lines])


def _match_confidence(m: TTPMatch, llm_verdict: LLMVerdict) -> float:
    base = m.similarity
    if llm_verdict == LLMVerdict.MALICIOUS:
        return min(1.0, base + 0.10)
    if llm_verdict == LLMVerdict.SUSPICIOUS:
        return min(1.0, base + 0.05)
    return max(0.0, base - 0.05)


def _sstr_to_evidence(
    file_path: str,
    strs: list[SuspiciousString],
) -> list[Evidence]:
    """SuspiciousString 리스트 → Evidence."""
    out: list[Evidence] = []
    for ss in strs:
        if ss.encoding == "base64":
            ttp_id = "T1140"
            ttp_name = "Deobfuscate/Decode Files or Information"
        elif ss.encoding == "hex":
            ttp_id = "T1027.009"
            ttp_name = "Obfuscated Files: Embedded Payloads"
        else:
            ttp_id = "T1027"
            ttp_name = "Obfuscated Files or Information"

        out.append(Evidence(
            file_path=file_path,
            line_start=ss.line,
            line_end=ss.line,
            code_snippet=f"[{ss.encoding}] {ss.short()}"
                         + (f"\n-> decoded: {ss.decoded[:200]}" if ss.decoded else ""),
            behavior_sequence=[f"string_const:{ss.encoding}"],
            attack_dimensions=[AttackDimension.ENCODING],
            ttp_id=ttp_id,
            ttp_name=ttp_name,
            ttp_source=TTPSource.MITRE_ATTACK,
            ttp_url=f"https://attack.mitre.org/techniques/{ttp_id.split('.')[0]}/",
            ttp_severity=Severity.MEDIUM if ss.decoded else Severity.LOW,
            vector_similarity=1.0,  # 규칙 매칭
            llm_verdict=LLMVerdict.SUSPICIOUS if ss.decoded else LLMVerdict.BENIGN,
            llm_reasoning=f"String constant analysis: {ss.reason}",
            llm_model="string-analysis-rule",
            confidence=0.8 if ss.decoded else 0.4,
        ))
    return out


def _anomaly_to_evidence(
    finding,  # AnomalyFinding
) -> Evidence:
    return Evidence(
        file_path=finding.file_path,
        line_start=0,
        line_end=0,
        code_snippet=f"Category baseline violation ({finding.category})",
        behavior_sequence=[f"anomaly:{finding.category}"],
        attack_dimensions=list(finding.unexpected_dimensions),
        ttp_id="T1059" if AttackDimension.PAYLOAD_EXECUTION in finding.unexpected_dimensions
               else "T1041",
        ttp_name=f"Unexpected behavior for {finding.category} category",
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url="https://attack.mitre.org/",
        ttp_severity=Severity.MEDIUM,
        vector_similarity=1.0,
        llm_verdict=LLMVerdict.SUSPICIOUS,
        llm_reasoning=finding.reason,
        llm_model="anomaly-baseline",
        confidence=0.75,
    )


def _binary_to_evidence(finding) -> Evidence:
    return Evidence(
        file_path=finding.path,
        line_start=0,
        line_end=0,
        code_snippet=(
            f"[{finding.binary_type}] suspicious imports: "
            f"{', '.join(finding.suspicious_imports[:10])}\n"
            + (f"network strings: {', '.join(finding.network_strings[:3])}\n"
               if finding.network_strings else "")
            + (f"interesting strings: {', '.join(finding.strings_of_interest[:3])}"
               if finding.strings_of_interest else "")
        ),
        behavior_sequence=[f"binary:{sym}" for sym in finding.suspicious_imports[:5]],
        attack_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
        ttp_id="T1027.002",
        ttp_name="Software Packing / Native Code",
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url="https://attack.mitre.org/techniques/T1027/002/",
        ttp_severity=Severity.HIGH,
        vector_similarity=1.0,
        llm_verdict=LLMVerdict.SUSPICIOUS,
        llm_reasoning=(
            f"Native binary contains suspicious imports: {finding.suspicious_imports[:5]}. "
            f"Network strings detected: {bool(finding.network_strings)}"
        ),
        llm_model="binary-analysis-rule",
        confidence=0.7,
    )


def _sandbox_to_evidence(obs) -> Evidence:
    return Evidence(
        file_path="<sandbox>",
        line_start=0,
        line_end=0,
        code_snippet=(
            f"mode: {obs.mode}, duration: {obs.duration_s:.2f}s\n"
            f"processes: {obs.process_spawns}\n"
            f"network: {obs.network_requests}\n"
            f"file writes: {obs.file_writes}"
        ),
        behavior_sequence=["sandbox:" + ",".join(obs.network_requests[:3])],
        attack_dimensions=[AttackDimension.DATA_TRANSMISSION] if obs.network_requests else [],
        ttp_id="T1041",
        ttp_name="Exfiltration Over C2 Channel",
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url="https://attack.mitre.org/techniques/T1041/",
        ttp_severity=Severity.HIGH if obs.network_requests else Severity.LOW,
        vector_similarity=1.0,
        llm_verdict=LLMVerdict.SUSPICIOUS if obs.has_findings else LLMVerdict.BENIGN,
        llm_reasoning=(
            f"Sandbox observation ({obs.mode}). "
            f"{'Unexpected runtime activity detected.' if obs.has_findings else 'No unexpected activity.'}"
        ),
        llm_model="sandbox-observer",
        confidence=0.85 if obs.has_findings else 0.3,
    )


# 단독으로는 약한 신호인 지표 코드 (정상 패키지에서도 흔히 사용됨).
# 다른 지표와 조합되어야 의미 있음.
_STANDALONE_WEAK_INDICATORS = {
    "EXM-001",   # exec/eval — Config 파일 로딩 등 정당한 용도 많음
    "EXS-001",   # import-time call — 거의 모든 __init__.py 가 해당
    "SYS-005",   # system info recon — 환경 진단/디버그용 흔함
    "SYS-004",   # directory enumeration — 빌드 도구가 흔히 사용
    "DEF-006",   # error suppression — 정당한 except: pass 도 많음
    "MET-004",   # description anomaly — 정상 패키지에도 짧은 설명 흔함
    "MET-001",   # author identity — author 비어있는 정상 패키지 많음
    "EXM-005",   # dynamic import — 플러그인 시스템 등에 정당
    "DEF-003",   # encoding — base64는 정당한 용도가 많음 (UUID, 토큰 등)
}


def _indicator_hit_to_evidence(h: IndicatorHit, indicator_codes_present: set[str]) -> Evidence:
    """47-Indicator IndicatorHit -> Evidence.

    indicator_codes_present: 같은 패키지 내 매칭된 모든 지표 코드 집합.
    조합 시 escalation 판단에 사용.
    """
    ind = h.indicator

    ttp_id = ind.mitre_ttps[0] if ind.mitre_ttps else "GENERIC"
    ttp_url = (
        f"https://attack.mitre.org/techniques/{ttp_id.split('.')[0]}/"
        if ttp_id != "GENERIC" else ""
    )

    is_standalone_weak = ind.code in _STANDALONE_WEAK_INDICATORS

    # 조합 강도 측정: 위험 카테고리 EXF/NET 가 함께 매칭됐는가
    has_risk_combo = any(
        c.startswith(("EXF-", "NET-002", "NET-007", "NET-008",
                      "EXS-002", "EXS-003", "EXM-006", "EXM-008", "DEF-005"))
        for c in indicator_codes_present
    )

    # LLM verdict 결정
    if is_standalone_weak and not has_risk_combo:
        # 단독 약한 신호 — BENIGN 으로 강등
        llm_v = LLMVerdict.BENIGN
        confidence = min(h.confidence, 0.4)
    elif ind.severity == Severity.HIGH and h.confidence >= 0.8:
        llm_v = LLMVerdict.MALICIOUS
        confidence = h.confidence
    elif ind.severity in (Severity.HIGH, Severity.MEDIUM) and h.confidence >= 0.5:
        llm_v = LLMVerdict.SUSPICIOUS
        confidence = h.confidence
    else:
        llm_v = LLMVerdict.BENIGN
        confidence = h.confidence

    # 단독 약한 신호는 ttp_severity 도 강등
    severity = (
        Severity.LOW if (is_standalone_weak and not has_risk_combo)
        else ind.severity
    )

    return Evidence(
        file_path=h.file_path,
        line_start=h.line,
        line_end=h.line,
        code_snippet=h.snippet[:1500],
        behavior_sequence=[f"indicator:{ind.code}"],
        attack_dimensions=list(ind.related_dimensions),
        ttp_id=f"{ind.code}/{ttp_id}",
        ttp_name=f"{ind.name} -- {ind.category.value}",
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url=ttp_url,
        ttp_severity=severity,
        vector_similarity=1.0,
        llm_verdict=llm_v,
        llm_reasoning=f"[{ind.code}] {h.reason} (description: {ind.description})",
        llm_model="indicator-rule-47",
        confidence=confidence,
    )


def _sequence_match_to_evidence(m: SequenceMatch) -> Evidence:
    """Sequential pattern match -> Evidence."""
    pat = m.pattern
    line_start = m.matched_calls[0].line if m.matched_calls else 0
    line_end = m.matched_calls[-1].line if m.matched_calls else 0
    snippet_lines = []
    for c in m.matched_calls[:8]:
        snippet_lines.append(f"L{c.line:>4}  [{c.dimension.value[:4]}]  {c.name}")
    snippet = "\n".join(snippet_lines)

    ttp_id = pat.related_ttps[0] if pat.related_ttps else "GENERIC"
    ttp_url = (
        f"https://attack.mitre.org/techniques/{ttp_id.split('.')[0]}/"
        if ttp_id != "GENERIC" else ""
    )

    # 패턴 종류별 LLM verdict 기본값
    if pat.severity == Severity.HIGH:
        llm_v = LLMVerdict.MALICIOUS
        confidence = 0.85
    elif pat.severity == Severity.MEDIUM:
        llm_v = LLMVerdict.SUSPICIOUS
        confidence = 0.65
    else:
        llm_v = LLMVerdict.BENIGN
        confidence = 0.4

    return Evidence(
        file_path=m.file_path,
        line_start=line_start,
        line_end=line_end,
        code_snippet=snippet[:1500],
        behavior_sequence=[c.name for c in m.matched_calls],
        attack_dimensions=[c.dimension for c in m.matched_calls],
        ttp_id=f"{pat.code}/{ttp_id}",
        ttp_name=f"{pat.name} -- sequential pattern",
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url=ttp_url,
        ttp_severity=pat.severity,
        vector_similarity=1.0,
        llm_verdict=llm_v,
        llm_reasoning=(
            f"[{pat.code}] {pat.description} | "
            f"matched span={m.span}, calls={len(m.matched_calls)}"
        ),
        llm_model="sequence-pattern-mine",
        confidence=confidence,
    )


def _dependency_to_evidence(dep_result) -> Evidence | None:
    """SUSPICIOUS 이상인 경우만 Evidence 변환."""
    if dep_result.verdict in ("CLEAN", "CANNOT_ANALYZE", "SKIPPED"):
        return None
    sev = Severity.HIGH if dep_result.verdict == "MALICIOUS" else Severity.MEDIUM
    llm_v = LLMVerdict.MALICIOUS if dep_result.verdict == "MALICIOUS" else LLMVerdict.SUSPICIOUS
    return Evidence(
        file_path=f"<dependency: {dep_result.name}>",
        line_start=0,
        line_end=0,
        code_snippet=f"dependency {dep_result.name} ({dep_result.version_spec})",
        behavior_sequence=[f"dep_chain:{dep_result.name}"],
        attack_dimensions=[],
        ttp_id="T1195.001",
        ttp_name="Supply Chain Compromise: Compromise Software Dependencies",
        ttp_source=TTPSource.MITRE_ATTACK,
        ttp_url="https://attack.mitre.org/techniques/T1195/001/",
        ttp_severity=sev,
        vector_similarity=1.0,
        llm_verdict=llm_v,
        llm_reasoning=dep_result.reason,
        llm_model="dependency-analyzer",
        confidence=0.9 if dep_result.verdict == "MALICIOUS" else 0.7,
    )


# ─────────────── 메인 ───────────────

def run_pipeline(
    package: str,
    ecosystem: Ecosystem,
    version: str | None = None,
    llm_mode: str = "stub",
    enable_deps: bool = False,
    enable_sandbox: bool = False,
    verbose: bool = False,
    use_multi_agent: bool = True,
    integrity_mode: str = "strict",       # "fast" | "strict" | "paranoid"
    use_cache: bool = True,
    force_rescan: bool = False,
    use_threat_filter: bool = True,
) -> AnalysisReport:
    stage_results: list[StageResult] = []
    evidence_list: list[Evidence] = []

    # ─── 무결성 모드 정규화 ───
    try:
        _integrity_mode = IntegrityMode(integrity_mode)
    except ValueError:
        _integrity_mode = IntegrityMode.STRICT

    # ========== Stage 0: 레지스트리 ==========
    try:
        reg = check(package, ecosystem)
        stage_results.append(StageResult(
            stage="stage_0_registry",
            success=reg.error is None,
            error=reg.error,
            payload={"found": reg.found},
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_0_registry", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, version or "unknown")
        report.verdict = Verdict.ERROR
        report.stage_results = stage_results
        return report

    if not reg.found:
        report = empty_report(package, ecosystem, version or "unknown")
        report.verdict = Verdict.CANNOT_ANALYZE
        report.stage_results = stage_results
        report.package_meta = {"reason": "registry_not_found"}
        return report

    # ========== Stage 0A: Threat Filter (게이트) ==========
    # 암호화 DB 의 known_malicious / popular / typosquat 매칭.
    # exact match 발견 시 즉시 MALICIOUS verdict 로 단축.
    threat_filter_rpt: ThreatFilterReport | None = None
    if use_threat_filter:
        try:
            threat_filter_rpt = threat_filter_run(package, ecosystem)
            stage_results.append(StageResult(
                stage="stage_0a_threat_filter",
                success=not threat_filter_rpt.skipped,
                error=threat_filter_rpt.error,
                payload={
                    "exact_match": threat_filter_rpt.exact_match,
                    "advisory_id": threat_filter_rpt.advisory_id,
                    "popular_rank": threat_filter_rpt.popular_rank,
                    "typosquat_candidates": len(threat_filter_rpt.typosquat_candidates),
                },
            ))
            if threat_filter_rpt.is_known_malicious:
                # 게이트: 알려진 악성 → 즉시 종료
                evidence_list.extend(threat_filter_to_evidence(
                    threat_filter_rpt, package, ecosystem.value,
                ))
                report = empty_report(package, ecosystem, version or reg.latest_version or "unknown")
                report.verdict = Verdict.MALICIOUS
                report.evidence = evidence_list
                report.stage_results = stage_results
                report.package_meta = {
                    "shortcircuit_reason": "known_malicious_in_threat_feed",
                    "advisory_id": threat_filter_rpt.advisory_id,
                    "advisory_summary": threat_filter_rpt.advisory_summary,
                }
                return report
            # 게이트는 아니지만 typosquat 후보 있으면 evidence 만 추가
            if threat_filter_rpt.typosquat_candidates:
                evidence_list.extend(threat_filter_to_evidence(
                    threat_filter_rpt, package, ecosystem.value,
                ))
        except Exception as e:
            stage_results.append(StageResult(
                stage="stage_0a_threat_filter", success=False, error=str(e),
            ))

    # ========== Stage 0B: 공격 이력 ==========
    try:
        hist = check_attack_history(package, ecosystem)
        stage_results.append(StageResult(
            stage="stage_0b_attack_history",
            success=hist.error is None,
            error=hist.error,
            payload={
                "exact_matches": len(hist.exact_matches),
                "typosquat_candidates": len(hist.typosquat_candidates),
            },
        ))
        if hist.any_hit:
            evidence_list.extend(attack_history_to_evidence(hist))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_0b_attack_history", success=False, error=str(e),
        ))

    # ========== Stage 0C: OpenSSF Scorecard ==========
    # 판정에 직접 영향 X (참고 메타). 실패해도 파이프라인 계속.
    scorecard_report: ScorecardReport | None = None
    try:
        scorecard_report = scorecard_fetch_for_package(reg.raw_metadata, ecosystem)
        stage_results.append(StageResult(
            stage="stage_0c_scorecard",
            success=scorecard_report.available,
            error=scorecard_report.error,
            payload={
                "repo": scorecard_report.repo,
                "score": scorecard_report.overall_score,
                "checks": len(scorecard_report.checks),
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_0c_scorecard", success=False, error=str(e),
        ))

    # ========== Stage 0D: SLSA 프로비넌스 추정 ==========
    slsa_report: SLSAReport | None = None
    try:
        slsa_report = slsa_evaluate(reg.raw_metadata, ecosystem)
        stage_results.append(StageResult(
            stage="stage_0d_slsa",
            success=slsa_report.error is None,
            error=slsa_report.error,
            payload={
                "level": slsa_report.level.value,
                "has_provenance": slsa_report.has_provenance,
                "has_signature": slsa_report.has_signature,
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_0d_slsa", success=False, error=str(e),
        ))

    target_version = version or reg.latest_version or ""
    archive_url = reg.archive_urls.get(target_version, "")
    if not archive_url:
        stage_results.append(StageResult(
            stage="stage_1b_full_source",
            success=False,
            error=f"no archive url for {target_version}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = decide_verdict(evidence_list, stage_results, registry_found=True)
        report.stage_results = stage_results
        report.evidence = evidence_list
        return report

    # ========== Stage 0E: 캐시 조회 (6-트리거 무효화) ==========
    cache_meta: dict = {}
    if use_cache and not force_rescan:
        try:
            from .db.analysis_cache import AnalysisCache, CacheKey
            _cache = AnalysisCache(integrity_mode=_integrity_mode)
            ck = CacheKey(
                package=package,
                ecosystem=ecosystem.value,
                version=target_version,
            )
            hit = _cache.get(ck, archive_url=archive_url)
            cache_meta = {
                "checked": True,
                "hit": hit.hit,
                "reason": hit.reason,
                "integrity_mode": _integrity_mode.value,
            }
            stage_results.append(StageResult(
                stage="stage_0e_cache_lookup",
                success=True,
                payload=cache_meta,
            ))
            if hit.hit and hit.report is not None:
                # 캐시 hit — verdict 만 복원, evidence 는 cached_evidence_count 로
                report = empty_report(package, ecosystem, target_version)
                vstr = hit.report.get("verdict", "ERROR")
                try:
                    report.verdict = Verdict(vstr)
                except Exception:
                    report.verdict = Verdict.ERROR
                report.evidence = []
                report.stage_results = stage_results
                report.package_meta = hit.report.get("package_meta", {}) or {}
                report.package_meta["cache_hit"] = True
                report.package_meta["cached_at"] = (
                    hit.cache_row.get("analyzed_at") if hit.cache_row else None
                )
                report.package_meta["cached_evidence_count"] = len(
                    hit.report.get("evidence", []) or []
                )
                return report
        except Exception as e:
            stage_results.append(StageResult(
                stage="stage_0e_cache_lookup", success=False, error=str(e),
            ))

    # ========== Stage 1B: 전 파일 소스 추출 ==========
    try:
        ext = extract_all(package, ecosystem, target_version, archive_url)
        ok = ext.error is None
        stage_results.append(StageResult(
            stage="stage_1b_full_source",
            success=ok,
            error=ext.error,
            payload={
                "archive_size": ext.archive_size,
                "source_files": len(ext.source_files),
                "binary_files": len(ext.binary_files),
                "total_files": len(ext.all_file_names),
            },
        ))
        if not ok:
            raise RuntimeError(ext.error)
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_1b_full_source", success=False, error=str(e),
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = stage_results
        report.evidence = evidence_list
        return report

    # ========== Stage 1C: AISLOPSQ Agentic Classification ==========
    # 근거: docs/aislopsq/spec/DECISION-TREE.md
    # 흐름:
    #   - 일반 패키지 → 47-indicator 파이프라인으로 fall-through (verdict 영향 X)
    #   - agentic + MALICIOUS / HIGH_RISK / SUSPICIOUS / AGENTIC → 본 stage 결과로 단축
    agentic_result: StageAgenticResult | None = None
    try:
        # 1B 단계의 description / declared deps
        _description = ""
        if reg.raw_metadata:
            info = reg.raw_metadata.get("info", {}) or {}
            _description = info.get("summary", "") or (
                info.get("description") or ""
            )[:300]
        try:
            from .stages.stage_dependency import extract_dependencies
            _dep_ext = extract_dependencies(ext.source_files, ecosystem)
            _declared_deps_for_agt = [d.name for d in _dep_ext.direct_deps]
        except Exception:
            _declared_deps_for_agt = []

        agentic_result = agentic_run(
            package_name=package,
            description=_description,
            declared_deps=_declared_deps_for_agt,
            source_files=ext.source_files,
            ecosystem=ecosystem,
        )
        cls = agentic_result.classification
        stage_results.append(StageResult(
            stage="stage_1c_aislopsq",
            success=True,
            payload={
                "is_agentic": cls.is_agentic if cls else False,
                "manifest_present": cls.manifest is not None if cls else False,
                "signal_score": (cls.signal_report.score
                                 if cls and cls.signal_report else 0),
                "declared": sorted(cls.declared) if cls else [],
                "detected": sorted(cls.detected) if cls else [],
                "undeclared": sorted(cls.undeclared) if cls else [],
                "verdict": cls.verdict.value if cls else None,
            },
        ))
        # agentic 으로 판정되면 본 stage 결과가 verdict 결정.
        # 단, AGENTIC 자체는 후속 stage 도 같이 돌려서 evidence 보강 가능.
        if (agentic_result.triggered
                and agentic_result.verdict in (Verdict.MALICIOUS,
                                               Verdict.HIGH_RISK)):
            evidence_list.extend(agentic_result.evidence)
            report = empty_report(package, ecosystem, target_version)
            report.verdict = agentic_result.verdict
            report.evidence = evidence_list
            report.stage_results = stage_results
            report.package_meta = dict(agentic_result.package_meta)
            return report
        # SUSPICIOUS / AGENTIC: evidence 만 보강하고 후속 stage 도 진행
        if agentic_result.triggered:
            evidence_list.extend(agentic_result.evidence)
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_1c_aislopsq", success=False,
            error=f"{e}\n{traceback.format_exc()[:300]}",
        ))

    # 분석할 EntryFile 리스트 (메타데이터 제외)
    analysis_files = to_entry_files(ext)

    # ExtractedPackage-like 객체 (Stage 2 analyze_behavior 는 entry_files 만 쓴다)
    class _ExtLike:
        pass
    ext_for_behavior = _ExtLike()
    ext_for_behavior.entry_files = analysis_files
    ext_for_behavior.package = package
    ext_for_behavior.ecosystem = ecosystem
    ext_for_behavior.version = target_version

    # ========== Stage 2: Behavior Sequence ==========
    try:
        behavior = analyze_behavior(ext_for_behavior)
        stage_results.append(StageResult(
            stage="stage_2_behavior_sequence",
            success=True,
            payload={
                "files_analyzed": len(behavior.files),
                "files_with_calls": sum(1 for fs in behavior.files if fs.calls),
                "total_calls": len(behavior.all_calls()),
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_2_behavior_sequence", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = stage_results
        report.evidence = evidence_list
        return report

    # ========== Stage 2B: 문자열 상수 풀 ==========
    try:
        total_strs = 0
        for sf in ext.source_files:
            if sf.language not in ("python", "javascript"):
                continue
            strs = analyze_strings(sf.path, sf.content, sf.language)
            if strs:
                total_strs += len(strs)
                evidence_list.extend(_sstr_to_evidence(sf.path, strs))
        stage_results.append(StageResult(
            stage="stage_2b_string_analysis",
            success=True,
            payload={"suspicious_strings": total_strs},
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_2b_string_analysis", success=False, error=str(e),
        ))

    # ========== Stage 3B: 버전 diff ==========
    diff = None
    try:
        diff = analyze_full_diff(reg, ext, behavior)
        stage_results.append(StageResult(
            stage="stage_3b_version_diff",
            success=diff.error is None,
            error=diff.error,
            payload={
                "compared": diff.compared_versions,
                "changed_files": len(diff.file_diffs),
                "severity": diff.overall_severity.value,
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_3b_version_diff", success=False, error=str(e),
        ))

    # ========== Stage 4: TTP 매칭 ==========
    try:
        match_report = match_ttps(behavior, top_k=3)
        stage_results.append(StageResult(
            stage="stage_4_ttp_matching",
            success=True,
            payload={"matches": len(match_report.matches)},
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_4_ttp_matching", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = stage_results
        report.evidence = evidence_list
        return report

    # ========== Stage 4B: 이상 탐지 ==========
    try:
        from .knowledge.anomaly_baseline import detect_anomalies
        description = ""
        author = ""
        if reg.raw_metadata:
            info = reg.raw_metadata.get("info", {}) or {}
            description = info.get("summary", "") or info.get("description", "")[:200]
            author = info.get("author") or info.get("author_email") or ""
        findings = detect_anomalies(package, description, behavior.files)
        for f in findings:
            evidence_list.append(_anomaly_to_evidence(f))
        stage_results.append(StageResult(
            stage="stage_4b_anomaly_detection",
            success=True,
            payload={"anomalies": len(findings)},
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_4b_anomaly_detection", success=False, error=str(e),
        ))
        description = ""
        author = ""

    # ========== Stage 4C: 47-Indicator 매처 (논문 2025) ==========
    try:
        # 의존성 추출 (있으면 메타 매처에 전달)
        declared_deps: list[str] = []
        try:
            from .stages.stage_dependency import extract_dependencies
            dep_ext = extract_dependencies(ext.source_files, ecosystem)
            declared_deps = [d.name for d in dep_ext.direct_deps]
        except Exception:
            pass

        ind_report = match_47_indicators(
            behavior_files=behavior.files,
            source_files=ext.source_files,
            package_name=package,
            description=description,
            author=author,
            declared_deps=declared_deps,
        )
        # 모든 매칭된 지표 코드 집합 (조합 escalation 판단용)
        codes_present = {h.indicator.code for h in ind_report.hits}
        for h in ind_report.hits:
            evidence_list.append(_indicator_hit_to_evidence(h, codes_present))
        stage_results.append(StageResult(
            stage="stage_4c_indicator_matcher",
            success=True,
            payload={
                "total_hits": len(ind_report.hits),
                "high_severity": ind_report.high_severity_count,
                "categories": [c.value for c in ind_report.categories_present],
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_4c_indicator_matcher", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))

    # ========== Stage 4E: Sequential Pattern Mining ==========
    try:
        seq_rpt = mine_sequences(behavior)
        for m in seq_rpt.matches:
            evidence_list.append(_sequence_match_to_evidence(m))
        stage_results.append(StageResult(
            stage="stage_4e_sequence_mining",
            success=seq_rpt.error is None,
            error=seq_rpt.error,
            payload={
                "patterns_matched": len(seq_rpt.matches),
                "patterns": sorted({m.pattern.code for m in seq_rpt.matches}),
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_4e_sequence_mining", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))

    # ========== Stage 4D: Taint Slicing (논문 2025) ==========
    # source(env/file/secret) -> sink(http/exec) 흐름만 추출해
    # Stage 5 LLM 프롬프트 토큰을 줄임.
    taint_slice_by_path: dict[str, str] = {}
    taint_total_flows = 0
    try:
        for sf in ext.source_files:
            if sf.language != "python":
                continue  # JS 는 차후 (tree-sitter 기반)
            rpt = taint_analyze_python(sf.content)
            if rpt.flows:
                taint_total_flows += len(rpt.flows)
                taint_slice_by_path[sf.path] = taint_slice_for_llm(sf.content, rpt.flows)
        stage_results.append(StageResult(
            stage="stage_4d_taint_slicing",
            success=True,
            payload={
                "files_with_flows": len(taint_slice_by_path),
                "total_flows": taint_total_flows,
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_4d_taint_slicing", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))

    # ========== Stage 5: LLM 이중 검증 (단일 또는 다중 에이전트) ==========
    multi_agent_consensus_per_file: dict[str, ConsensusReport] = {}
    try:
        # Stage 5 에서 사용할 의존성 / new_apis 사전 추출
        try:
            from .stages.stage_dependency import extract_dependencies
            _dep_ext = extract_dependencies(ext.source_files, ecosystem)
            stage5_declared_deps = [d.name for d in _dep_ext.direct_deps]
        except Exception:
            stage5_declared_deps = []

        # 새 API 호출(diff 신규 추가) 수집
        new_apis_all: list[str] = []
        if diff and diff.file_diffs:
            for fd in diff.file_diffs:
                # 일부 구현엔 added_calls / new_apis 가 있음 — 안전하게 fallback
                for attr in ("added_calls", "new_apis", "added_apis"):
                    val = getattr(fd, attr, None)
                    if val:
                        for v in val:
                            new_apis_all.append(str(v))

        for m in match_report.matches:
            fs = _find_file_seq(behavior, m.file_path)
            if fs is None:
                continue
            snippet = _snippet_for(fs)
            diff_summary = None
            if diff and diff.file_diffs:
                diff_summary = (
                    f"{len(diff.file_diffs)} file(s) changed, "
                    f"severity {diff.overall_severity.value}"
                )
            taint_slice = taint_slice_by_path.get(fs.path)

            if use_multi_agent:
                consensus_rpt = review_multi(
                    package, target_version, ecosystem.value,
                    fs, match_report.matches,
                    code_snippet=snippet,
                    version_diff_summary=diff_summary,
                    new_apis=new_apis_all,
                    description=description,
                    declared_deps=stage5_declared_deps,
                    taint_slice=taint_slice,
                    mode=llm_mode,
                )
                multi_agent_consensus_per_file[fs.path] = consensus_rpt
                llm = consensus_to_llm_response(consensus_rpt)
            else:
                llm = review(
                    package, target_version, ecosystem.value,
                    fs, match_report.matches, snippet,
                    version_diff_summary=diff_summary,
                    mode=llm_mode,
                    taint_slice=taint_slice,
                )
            line_start = fs.calls[0].line if fs.calls else 0
            line_end = fs.calls[-1].line if fs.calls else 0
            vd_info = diff.to_version_diff_info() if diff else None
            evidence_list.append(Evidence(
                file_path=fs.path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=snippet[:1500],
                behavior_sequence=list(fs.sequence),
                attack_dimensions=list(fs.dimensions),
                ttp_id=m.ttp.ttp_id,
                ttp_name=m.ttp.ttp_name,
                ttp_source=m.ttp.source,
                ttp_url=m.ttp.url,
                ttp_severity=m.ttp.severity,
                vector_similarity=m.similarity,
                llm_verdict=llm.verdict,
                llm_reasoning=llm.reasoning,
                llm_model=llm.model,
                version_diff=vd_info,
                confidence=_match_confidence(m, llm.verdict),
            ))
        # 멀티 에이전트 통계
        ma_payload: dict = {}
        if use_multi_agent and multi_agent_consensus_per_file:
            agreements = [
                c.agreement_ratio for c in multi_agent_consensus_per_file.values()
            ]
            verdicts = [
                c.verdict.value for c in multi_agent_consensus_per_file.values()
            ]
            ma_payload = {
                "multi_agent": True,
                "files_evaluated": len(multi_agent_consensus_per_file),
                "avg_agreement": round(sum(agreements) / len(agreements), 3),
                "verdicts": verdicts,
            }
        stage_results.append(StageResult(
            stage="stage_5_llm_review",
            success=True,
            payload={
                "evidence_generated": len(evidence_list),
                "mode": llm_mode,
                **ma_payload,
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_5_llm_review", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = stage_results
        report.evidence = evidence_list
        return report

    # ========== Stage 6: 의존성 재귀 (옵션) ==========
    if enable_deps:
        try:
            from .stages.stage_dependency import extract_dependencies, analyze_dependencies
            dep_ext = extract_dependencies(ext.source_files, ecosystem)
            dep_results = analyze_dependencies(
                dep_ext, ecosystem, attack_history_only=True, max_packages=30,
            )
            hit_count = 0
            for dr in dep_results:
                ev = _dependency_to_evidence(dr)
                if ev:
                    evidence_list.append(ev)
                    hit_count += 1
            stage_results.append(StageResult(
                stage="stage_6_dependencies",
                success=True,
                payload={
                    "direct": len(dep_ext.direct_deps),
                    "dev": len(dep_ext.dev_deps),
                    "analyzed": len(dep_results),
                    "hits": hit_count,
                },
            ))
        except Exception as e:
            stage_results.append(StageResult(
                stage="stage_6_dependencies", success=False, error=str(e),
            ))

    # ========== Stage 7: 바이너리 ==========
    if ext.binary_files:
        try:
            import urllib.request
            from .stages.stage_binary import extract_and_analyze
            # 아카이브 재다운로드 (전 파일 추출 때와 동일 URL)
            req = urllib.request.Request(
                archive_url, headers={"User-Agent": "slop-detector/2.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                archive_bytes = resp.read()
            bin_findings = extract_and_analyze(
                archive_bytes, ext.binary_files, archive_url,
            )
            hit_count = 0
            for bf in bin_findings:
                if bf.has_findings:
                    evidence_list.append(_binary_to_evidence(bf))
                    hit_count += 1
            stage_results.append(StageResult(
                stage="stage_7_binary",
                success=True,
                payload={
                    "binaries": len(bin_findings),
                    "hits": hit_count,
                },
            ))
        except Exception as e:
            stage_results.append(StageResult(
                stage="stage_7_binary", success=False, error=str(e),
            ))
    else:
        stage_results.append(StageResult(
            stage="stage_7_binary",
            success=True,
            payload={"binaries": 0, "skipped": "no binary files"},
        ))

    # ========== Stage 8: 샌드박스 (옵션) ==========
    if enable_sandbox:
        try:
            from .stages.stage_sandbox import get_default_sandbox
            sb = get_default_sandbox()
            obs = sb.run(package, ecosystem, target_version)
            if obs.has_findings:
                evidence_list.append(_sandbox_to_evidence(obs))
            stage_results.append(StageResult(
                stage="stage_8_sandbox",
                success=True,
                payload={
                    "mode": obs.mode,
                    "duration_s": obs.duration_s,
                    "has_findings": obs.has_findings,
                },
            ))
        except Exception as e:
            stage_results.append(StageResult(
                stage="stage_8_sandbox", success=False, error=str(e),
            ))

    # ========== Stage 9: Verdict + 리포트 ==========
    verdict = decide_verdict(evidence_list, stage_results, registry_found=True)

    report = empty_report(package, ecosystem, target_version)
    report.verdict = verdict
    report.evidence = evidence_list
    report.stage_results = stage_results
    report.package_meta = {
        "latest_version": reg.latest_version,
        "version_count": len(reg.all_versions) if reg.all_versions else 0,
        "archive_size": ext.archive_size,
        "source_files": len(ext.source_files),
        "binary_files": len(ext.binary_files),
    }
    # AISLOPSQ agentic classification (판정 영향 — Step 1C 단계에서 이미 처리됨)
    if agentic_result is not None and agentic_result.classification is not None:
        report.package_meta["aislopsq"] = (
            agentic_result.classification.to_dict()
        )

    # Scorecard 메타 (참고 정보 — 판정에는 직접 영향 없음)
    if scorecard_report is not None:
        report.package_meta["scorecard"] = scorecard_report.to_dict()
        report.package_meta["scorecard_risks"] = scorecard_risk_signals(scorecard_report)

    # SLSA 메타 (참고 정보)
    if slsa_report is not None:
        report.package_meta["slsa"] = slsa_report.to_dict()

    # OWASP LLM Top 10 / MITRE ATLAS 매핑 (참고 정보)
    try:
        from .knowledge.owasp_llm import (
            map_verdict_to_owasp,
            get as get_owasp,
        )
        from .knowledge.mitre_atlas import supply_chain_relevant
        owasp_ids = map_verdict_to_owasp(report.verdict.value)
        report.package_meta["owasp_llm_top10"] = [
            {
                "id": oid,
                "name": get_owasp(oid).name if get_owasp(oid) else "",
                "url": get_owasp(oid).url if get_owasp(oid) else "",
            }
            for oid in owasp_ids
        ]
        # ATLAS — 슬롭스쿼팅 관련 항목 항상 인용 (참고용)
        report.package_meta["mitre_atlas"] = [
            {"id": t.id, "name": t.name, "tactic": t.tactic.value, "url": t.url}
            for t in supply_chain_relevant()[:5]  # 상위 5개만
        ]
    except Exception:
        pass

    # NIST SSDF 준수 체크 (참고 정보)
    try:
        # 파이프라인 전반의 source_paths 모음
        all_source_paths = [sf.path for sf in ext.source_files]
        # binary file 도 포함하면 SBOM 검출 강화
        all_source_paths.extend([bf.path for bf in ext.binary_files])
        ssdf_rpt = ssdf_evaluate(
            ecosystem=ecosystem,
            registry_found=True,
            raw_metadata=reg.raw_metadata,
            source_paths=all_source_paths,
            scorecard=scorecard_report,
        )
        report.package_meta["ssdf"] = ssdf_rpt.to_dict()
        stage_results.append(StageResult(
            stage="stage_ssdf_compliance",
            success=True,
            payload={
                "pass": ssdf_rpt.pass_count,
                "fail": ssdf_rpt.fail_count,
                "unknown": ssdf_rpt.unknown_count,
            },
        ))
    except Exception as e:
        stage_results.append(StageResult(
            stage="stage_ssdf_compliance", success=False, error=str(e),
        ))
    report.kb_versions = {
        "MITRE ATT&CK": "cached-local",
        "OSV": "cached-local",
    }

    # ========== 캐시 저장 (분석 완료 후) ==========
    if use_cache:
        try:
            from .db.analysis_cache import AnalysisCache, CacheKey
            _cache = AnalysisCache(integrity_mode=_integrity_mode)
            ck = CacheKey(
                package=package,
                ecosystem=ecosystem.value,
                version=target_version,
            )
            # report 를 dict 로 직렬화 (Evidence dataclass 직렬화 포함)
            _report_dict = _report_to_serializable(report)
            put_info = _cache.put(
                ck, _report_dict,
                archive_url=archive_url,
                verdict=report.verdict.value,
            )
            report.package_meta["cache_stored"] = True
            report.package_meta["cache_info"] = put_info
        except Exception as e:
            # 캐시 저장 실패는 분석 결과에 영향 없음
            report.package_meta["cache_stored"] = False
            report.package_meta["cache_error"] = str(e)

    return report


def _report_to_serializable(report: AnalysisReport) -> dict:
    """AnalysisReport -> JSON-serializable dict (캐시 저장용)."""
    from dataclasses import asdict
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


# ─────────────── 사람 읽기 좋은 출력 ───────────────

def format_cyclonedx(report: AnalysisReport) -> str:
    """리포트를 CycloneDX v1.5 SBOM + VEX JSON 으로 직렬화."""
    from .stages.stage_vex import to_json as _vex_to_json
    return _vex_to_json(report)


def format_report(report: AnalysisReport) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append(f"Package   : {report.package} {report.version} ({report.ecosystem.value})")
    lines.append(f"Analyzed  : {report.analyzed_at.isoformat()}")
    lines.append(f"Verdict   : {report.verdict.value}")
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


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Package Threat Detection Engine V2")
    parser.add_argument("package")
    parser.add_argument("--ecosystem", "-e", choices=["PyPI", "npm"], default="PyPI")
    parser.add_argument("--version", "-v", default=None)
    parser.add_argument("--llm", choices=["stub", "claude"], default="stub")
    parser.add_argument("--deps", action="store_true", help="의존성 재귀 분석")
    parser.add_argument("--sandbox", action="store_true", help="샌드박스 동적 분석")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = run_pipeline(
        args.package,
        Ecosystem(args.ecosystem),
        version=args.version,
        llm_mode=args.llm,
        enable_deps=args.deps,
        enable_sandbox=args.sandbox,
    )

    if args.json:
        print(report.to_json())
    else:
        print(format_report(report))
