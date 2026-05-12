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

import hashlib
import traceback

# .env 자동 로드 (ANTHROPIC_API_KEY, OPENAI_API_KEY 등).
# detector 모듈을 어떻게 진입하든 — pipeline / worker / cron_main —
# 첫 import 시점에 1회 실행. 이미 환경변수에 있으면 덮어쓰지 않음.
from . import _dotenv as _aislopsq_dotenv

_aislopsq_dotenv.load()

from ._pipeline_state import PipelineContext, PipelineOptions
from .db.integrity import IntegrityMode
from .evidence.converters import (
    anomaly_to_evidence as _anomaly_to_evidence,
)
from .evidence.converters import (
    binary_to_evidence as _binary_to_evidence,
)
from .evidence.converters import (
    dependency_to_evidence as _dependency_to_evidence,
)
from .evidence.converters import (
    indicator_hit_to_evidence as _indicator_hit_to_evidence,
)
from .evidence.converters import (
    sandbox_to_evidence as _sandbox_to_evidence,
)
from .evidence.converters import (
    sequence_match_to_evidence as _sequence_match_to_evidence,
)
from .evidence.converters import (
    sstr_to_evidence as _sstr_to_evidence,
)
from .evidence.snippets import (
    find_file_seq as _find_file_seq,
)
from .evidence.snippets import (
    match_confidence as _match_confidence,
)
from .evidence.snippets import (
    snippet_for as _snippet_for,
)
from .reporting.serialize import report_to_serializable as _report_to_serializable
from .schema import (
    AnalysisReport,
    Ecosystem,
    Evidence,
    LLMVerdict,
    Severity,
    StageResult,
    TTPSource,
    Verdict,
    empty_report,
)
from .stages.indicator_matcher import match_all as match_47_indicators
from .stages.sequence_patterns import (
    mine as mine_sequences,
)
from .stages.stage0_registry import check
from .stages.stage0_threat_filter import (
    ThreatFilterReport,
)
from .stages.stage0_threat_filter import (
    run as threat_filter_run,
)
from .stages.stage0_threat_filter import (
    to_evidence as threat_filter_to_evidence,
)
from .stages.stage0b_attack_history import (
    check_attack_history,
)
from .stages.stage0b_attack_history import (
    to_evidence as attack_history_to_evidence,
)
from .stages.stage1b_full_source import extract_all, to_entry_files
from .stages.stage2_behavior import BehaviorReport
from .stages.stage2_behavior import analyze as analyze_behavior
from .stages.stage3b_full_diff import analyze_full_diff
from .stages.stage4_ttp_match import match_ttps
from .stages.stage5_llm_review import review
from .stages.stage5_multi_agent import (
    ConsensusReport,
    consensus_to_llm_response,
    review_multi,
)
from .stages.stage_agentic import (
    StageAgenticResult,
)
from .stages.stage_agentic import (
    run as agentic_run,
)
from .stages.stage_scorecard import (
    ScorecardReport,
)
from .stages.stage_scorecard import (
    extract_risk_signals as scorecard_risk_signals,
)
from .stages.stage_scorecard import (
    fetch_for_package as scorecard_fetch_for_package,
)
from .stages.stage_slsa import (
    SLSAReport,
)
from .stages.stage_slsa import (
    evaluate as slsa_evaluate,
)
from .stages.stage_ssdf import (
    evaluate as ssdf_evaluate,
)
from .stages.string_analysis import analyze_strings
from .stages.taint_slicer import (
    analyze_python as taint_analyze_python,
)
from .stages.taint_slicer import (
    slice_for_llm as taint_slice_for_llm,
)
from .verdict_rules import decide_verdict

# ─────────────── 메인 ───────────────

def run_pipeline(
    package: str,
    ecosystem: Ecosystem,
    version: str | None = None,
    llm_mode: str = "claude",
    enable_deps: bool = False,
    enable_sandbox: bool = False,
    verbose: bool = False,
    use_multi_agent: bool = True,
    integrity_mode: str = "strict",       # "fast" | "strict" | "paranoid"
    use_cache: bool = True,
    force_rescan: bool = False,
    use_threat_filter: bool = True,
) -> AnalysisReport:
    # 옵션과 컨텍스트 구성. run_pipeline 본문은 ctx 를 통해 누적 결과
    # (stage_results, evidence) 와 단계간 흐르는 산출물 (ext, behavior, diff,
    # description) 을 공유한다.
    options = PipelineOptions(
        llm_mode=llm_mode,
        enable_deps=enable_deps,
        enable_sandbox=enable_sandbox,
        verbose=verbose,
        use_multi_agent=use_multi_agent,
        integrity_mode=integrity_mode,
        use_cache=use_cache,
        force_rescan=force_rescan,
        use_threat_filter=use_threat_filter,
    )
    ctx = PipelineContext(
        package=package,
        ecosystem=ecosystem,
        version=version,
        options=options,
    )

    # ─── LLM 모드 사전 검증 ───
    # claude 모드인데 키가 없으면, 8 단계 정적 분석을 다 돌리고 Stage 5 에서야
    # 실패하는 대신 즉시 ERROR 리포트로 종료. 사용자가 80 초씩 기다리지 않도록.
    if ctx.options.llm_mode == "claude":
        import os as _os
        if not _os.getenv("ANTHROPIC_API_KEY"):
            report = empty_report(package, ecosystem, version or "unknown")
            report.verdict = Verdict.ERROR
            report.stage_results = [StageResult(
                stage="preflight_llm_check",
                success=False,
                error=(
                    "ANTHROPIC_API_KEY 환경변수 미설정. "
                    "키를 설정하거나, 정적 분석만 원하면 --llm stub 으로 실행. "
                    "단, stub 모드는 인기 패키지에서 FP 율이 매우 높음."
                ),
            )]
            return report

    # ─── 무결성 모드 정규화 ───
    try:
        _integrity_mode = IntegrityMode(ctx.options.integrity_mode)
    except ValueError:
        _integrity_mode = IntegrityMode.STRICT

    # ========== Stage 0: 레지스트리 ==========
    try:
        reg = check(package, ecosystem)
        ctx.stage_results.append(StageResult(
            stage="stage_0_registry",
            success=reg.error is None,
            error=reg.error,
            payload={"found": reg.found},
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_0_registry", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, version or "unknown")
        report.verdict = Verdict.ERROR
        report.stage_results = ctx.stage_results
        return report

    if not reg.found:
        report = empty_report(package, ecosystem, version or "unknown")
        report.verdict = Verdict.CANNOT_ANALYZE
        report.stage_results = ctx.stage_results
        report.package_meta = {"reason": "registry_not_found"}
        return report

    # ========== Stage 0A: Threat Filter (게이트) ==========
    # 암호화 DB 의 known_malicious / popular / typosquat 매칭.
    # exact match 발견 시 즉시 MALICIOUS verdict 로 단축.
    threat_filter_rpt: ThreatFilterReport | None = None
    if ctx.options.use_threat_filter:
        try:
            threat_filter_rpt = threat_filter_run(package, ecosystem)
            ctx.stage_results.append(StageResult(
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
                ctx.evidence.extend(threat_filter_to_evidence(
                    threat_filter_rpt, package, ecosystem.value,
                ))
                report = empty_report(package, ecosystem, version or reg.latest_version or "unknown")
                report.verdict = Verdict.MALICIOUS
                report.evidence = ctx.evidence
                report.stage_results = ctx.stage_results
                report.package_meta = {
                    "shortcircuit_reason": "known_malicious_in_threat_feed",
                    "advisory_id": threat_filter_rpt.advisory_id,
                    "advisory_summary": threat_filter_rpt.advisory_summary,
                }
                return report
            # 게이트는 아니지만 typosquat 후보 있으면 evidence 만 추가
            if threat_filter_rpt.typosquat_candidates:
                ctx.evidence.extend(threat_filter_to_evidence(
                    threat_filter_rpt, package, ecosystem.value,
                ))
        except Exception as e:
            ctx.stage_results.append(StageResult(
                stage="stage_0a_threat_filter", success=False, error=str(e),
            ))

    # ========== Stage 0B: 공격 이력 ==========
    try:
        hist = check_attack_history(package, ecosystem)
        ctx.stage_results.append(StageResult(
            stage="stage_0b_attack_history",
            success=hist.error is None,
            error=hist.error,
            payload={
                "exact_matches": len(hist.exact_matches),
                "typosquat_candidates": len(hist.typosquat_candidates),
            },
        ))
        if hist.any_hit:
            ctx.evidence.extend(attack_history_to_evidence(hist))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_0b_attack_history", success=False, error=str(e),
        ))

    # ========== Stage 0C: OpenSSF Scorecard ==========
    # 판정에 직접 영향 X (참고 메타). 실패해도 파이프라인 계속.
    scorecard_report: ScorecardReport | None = None
    try:
        scorecard_report = scorecard_fetch_for_package(reg.raw_metadata, ecosystem)
        ctx.stage_results.append(StageResult(
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
        ctx.stage_results.append(StageResult(
            stage="stage_0c_scorecard", success=False, error=str(e),
        ))

    # ========== Stage 0D: SLSA 프로비넌스 추정 ==========
    slsa_report: SLSAReport | None = None
    try:
        slsa_report = slsa_evaluate(reg.raw_metadata, ecosystem)
        ctx.stage_results.append(StageResult(
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
        ctx.stage_results.append(StageResult(
            stage="stage_0d_slsa", success=False, error=str(e),
        ))

    target_version = version or reg.latest_version or ""
    archive_url = reg.archive_urls.get(target_version, "")
    if not archive_url:
        ctx.stage_results.append(StageResult(
            stage="stage_1b_full_source",
            success=False,
            error=f"no archive url for {target_version}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = decide_verdict(ctx.evidence, ctx.stage_results, registry_found=True)
        report.stage_results = ctx.stage_results
        report.evidence = ctx.evidence
        return report

    # ========== Stage 0E: 캐시 조회 (6-트리거 무효화) ==========
    cache_meta: dict = {}
    if ctx.options.use_cache and not ctx.options.force_rescan:
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
            ctx.stage_results.append(StageResult(
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
                report.stage_results = ctx.stage_results
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
            ctx.stage_results.append(StageResult(
                stage="stage_0e_cache_lookup", success=False, error=str(e),
            ))

    # ========== Stage 1B: 전 파일 소스 추출 ==========
    try:
        ctx.ext = extract_all(package, ecosystem, target_version, archive_url)
        ok = ctx.ext.error is None
        if ok:
            # stage_cache 키용 sha — 정렬된 path+content 기준
            _h = hashlib.sha256()
            for sf in sorted(ctx.ext.source_files, key=lambda f: f.path):
                _h.update(sf.path.encode("utf-8"))
                _h.update(b"\x00")
                _h.update(sf.content.encode("utf-8", errors="replace"))
            ctx.archive_sha256 = _h.hexdigest()[:32]
        ctx.stage_results.append(StageResult(
            stage="stage_1b_full_source",
            success=ok,
            error=ctx.ext.error,
            payload={
                "archive_size": ctx.ext.archive_size,
                "source_files": len(ctx.ext.source_files),
                "binary_files": len(ctx.ext.binary_files),
                "total_files": len(ctx.ext.all_file_names),
                "ext_sha256": ctx.archive_sha256,
            },
        ))
        if not ok:
            raise RuntimeError(ctx.ext.error)
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_1b_full_source", success=False, error=str(e),
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = ctx.stage_results
        report.evidence = ctx.evidence
        return report

    # ========== Stage 1C: AISLOPSQ Agentic Classification ==========
    # 근거: docs/aislopsq/spec/DECISION-TREE.md
    # 흐름:
    #   - 일반 패키지 → 47-indicator 파이프라인으로 fall-through (verdict 영향 X)
    #   - agentic + MALICIOUS / HIGH_RISK / SUSPICIOUS / AGENTIC → 본 stage 결과로 단축
    agentic_result: StageAgenticResult | None = None
    try:
        # 1B 단계의 ctx.description / declared deps
        _description = ""
        if reg.raw_metadata:
            info = reg.raw_metadata.get("info", {}) or {}
            _description = info.get("summary", "") or (
                info.get("ctx.description") or ""
            )[:300]
        try:
            from .stages.stage_dependency import extract_dependencies
            _dep_ext = extract_dependencies(ctx.ext.source_files, ecosystem)
            _declared_deps_for_agt = [d.name for d in _dep_ext.direct_deps]
        except Exception:
            _declared_deps_for_agt = []

        agentic_result = agentic_run(
            package_name=package,
            description=_description,
            declared_deps=_declared_deps_for_agt,
            source_files=ctx.ext.source_files,
            ecosystem=ecosystem,
        )
        cls = agentic_result.classification
        ctx.stage_results.append(StageResult(
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
            ctx.evidence.extend(agentic_result.evidence)
            report = empty_report(package, ecosystem, target_version)
            report.verdict = agentic_result.verdict
            report.evidence = ctx.evidence
            report.stage_results = ctx.stage_results
            report.package_meta = dict(agentic_result.package_meta)
            return report
        # SUSPICIOUS / AGENTIC: evidence 만 보강하고 후속 stage 도 진행
        if agentic_result.triggered:
            ctx.evidence.extend(agentic_result.evidence)
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_1c_aislopsq", success=False,
            error=f"{e}\n{traceback.format_exc()[:300]}",
        ))

    # 분석할 EntryFile 리스트 (메타데이터 제외)
    analysis_files = to_entry_files(ctx.ext)

    # ExtractedPackage-like 객체 (Stage 2 analyze_behavior 는 entry_files 만 쓴다)
    class _ExtLike:
        pass
    ext_for_behavior = _ExtLike()
    ext_for_behavior.entry_files = analysis_files
    ext_for_behavior.package = package
    ext_for_behavior.ecosystem = ecosystem
    ext_for_behavior.version = target_version

    # ========== Stage 2: Behavior Sequence ==========
    # stage_cache 통합 — 같은 (pkg, ver, ext_sha) + 같은 stage_2 코드 hash 면
    # AST 재파싱 없이 캐시된 BehaviorReport 재사용. 패키지 1000개 분석 시
    # 두 번째 분석부터 효과 큼.
    _stage2_cache_status = "skipped"
    try:
        from .db.stage_cache import StageCache, StageCacheKey
        _sc = StageCache() if ctx.options.use_cache else None
        _ck2 = StageCacheKey(
            package=package, ecosystem=ecosystem.value,
            version=target_version, stage="stage_2_behavior",
        )
        _hit = (
            _sc.get(_ck2, archive_sha256=ctx.archive_sha256)
            if _sc and not ctx.options.force_rescan
            else None
        )
        if _hit is not None and _hit.hit:
            ctx.behavior = BehaviorReport.from_dict(_hit.payload)
            _stage2_cache_status = "hit"
        else:
            ctx.behavior = analyze_behavior(ext_for_behavior)
            _stage2_cache_status = "miss" if _hit is not None else "disabled"
            if _sc:
                _sc.put(
                    _ck2, ctx.behavior.to_dict(),
                    archive_sha256=ctx.archive_sha256,
                )

        ctx.stage_results.append(StageResult(
            stage="stage_2_behavior_sequence",
            success=True,
            payload={
                "files_analyzed": len(ctx.behavior.files),
                "files_with_calls": sum(1 for fs in ctx.behavior.files if fs.calls),
                "total_calls": len(ctx.behavior.all_calls()),
                "stage_cache": _stage2_cache_status,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_2_behavior_sequence", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = ctx.stage_results
        report.evidence = ctx.evidence
        return report

    # ========== Stage 2B: 문자열 상수 풀 ==========
    # stage_cache 통합 — 파일별 SuspiciousString 결과를 캐시. 적중 시 재파싱 없이
    # 결과 → evidence 재플레이. evidence 자체는 stage 간 누적이므로 캐시 X.
    _stage2b_cache_status = "skipped"
    try:
        from .db.stage_cache import StageCache, StageCacheKey
        from .stages.string_analysis import SuspiciousString
        _sc = StageCache() if ctx.options.use_cache else None
        _ck2b = StageCacheKey(
            package=package, ecosystem=ecosystem.value,
            version=target_version, stage="stage_2b_string",
        )
        _hit = (
            _sc.get(_ck2b, archive_sha256=ctx.archive_sha256)
            if _sc and not ctx.options.force_rescan
            else None
        )
        total_strs = 0
        if _hit is not None and _hit.hit:
            # 캐시 적중 — payload 는 {path: [SuspiciousString.to_dict(), ...]}
            try:
                per_file = _hit.payload.get("per_file", {})
                for path, items in per_file.items():
                    strs = [SuspiciousString.from_dict(d) for d in items]
                    if strs:
                        total_strs += len(strs)
                        ctx.evidence.extend(_sstr_to_evidence(path, strs))
                _stage2b_cache_status = "hit"
            except Exception:
                # 페이로드 복원 실패 → 재계산 fall-through
                _hit = None

        if _hit is None or not _hit.hit:
            per_file_payload: dict[str, list[dict]] = {}
            for sf in ctx.ext.source_files:
                if sf.language not in ("python", "javascript"):
                    continue
                strs = analyze_strings(sf.path, sf.content, sf.language)
                if strs:
                    total_strs += len(strs)
                    ctx.evidence.extend(_sstr_to_evidence(sf.path, strs))
                    per_file_payload[sf.path] = [s.to_dict() for s in strs]
            _stage2b_cache_status = "miss" if _hit is not None else "disabled"
            if _sc:
                try:
                    _sc.put(
                        _ck2b, {"per_file": per_file_payload},
                        archive_sha256=ctx.archive_sha256,
                    )
                except Exception:
                    pass

        ctx.stage_results.append(StageResult(
            stage="stage_2b_string_analysis",
            success=True,
            payload={
                "suspicious_strings": total_strs,
                "stage_cache": _stage2b_cache_status,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_2b_string_analysis", success=False, error=str(e),
        ))

    # ========== Stage 3B: 버전 ctx.diff ==========
    ctx.diff = None
    _stage3b_cache_status = "skipped"
    try:
        from .db.stage_cache import StageCache, StageCacheKey
        from .stages.stage3b_full_diff import FullDiffResult
        _sc = StageCache() if ctx.options.use_cache else None
        _ck3b = StageCacheKey(
            package=package, ecosystem=ecosystem.value,
            version=target_version, stage="stage_3b_version_diff",
        )
        _hit = (
            _sc.get(_ck3b, archive_sha256=ctx.archive_sha256)
            if _sc and not ctx.options.force_rescan
            else None
        )
        if _hit is not None and _hit.hit:
            try:
                ctx.diff = FullDiffResult.from_dict(_hit.payload)
                _stage3b_cache_status = "hit"
            except Exception:
                _hit = None

        if _hit is None or not _hit.hit:
            ctx.diff = analyze_full_diff(reg, ctx.ext, ctx.behavior)
            _stage3b_cache_status = "miss" if _hit is not None else "disabled"
            if _sc:
                try:
                    _sc.put(
                        _ck3b, ctx.diff.to_dict(),
                        archive_sha256=ctx.archive_sha256,
                    )
                except Exception:
                    pass

        ctx.stage_results.append(StageResult(
            stage="stage_3b_version_diff",
            success=ctx.diff.error is None,
            error=ctx.diff.error,
            payload={
                "compared": ctx.diff.compared_versions,
                "changed_files": len(ctx.diff.file_diffs),
                "severity": ctx.diff.overall_severity.value,
                "stage_cache": _stage3b_cache_status,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_3b_version_diff", success=False, error=str(e),
        ))

    # ========== Stage 4: TTP 매칭 ==========
    _stage4_cache_status = "skipped"
    try:
        from .db.stage_cache import StageCache, StageCacheKey
        from .stages.stage4_ttp_match import TTPMatchReport
        _sc = StageCache() if ctx.options.use_cache else None
        _ck4 = StageCacheKey(
            package=package, ecosystem=ecosystem.value,
            version=target_version, stage="stage_4_ttp",
        )
        _hit = (
            _sc.get(_ck4, archive_sha256=ctx.archive_sha256)
            if _sc and not ctx.options.force_rescan
            else None
        )
        match_report = None
        if _hit is not None and _hit.hit:
            try:
                match_report = TTPMatchReport.from_dict(_hit.payload)
                _stage4_cache_status = "hit"
            except Exception:
                match_report = None

        if match_report is None:
            match_report = match_ttps(ctx.behavior, top_k=3)
            _stage4_cache_status = "miss" if _hit is not None else "disabled"
            if _sc:
                try:
                    _sc.put(
                        _ck4, match_report.to_dict(),
                        archive_sha256=ctx.archive_sha256,
                    )
                except Exception:
                    pass

        ctx.stage_results.append(StageResult(
            stage="stage_4_ttp_matching",
            success=True,
            payload={
                "matches": len(match_report.matches),
                "stage_cache": _stage4_cache_status,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_4_ttp_matching", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = ctx.stage_results
        report.evidence = ctx.evidence
        return report

    # ========== Stage 4B: 이상 탐지 ==========
    try:
        from .knowledge.anomaly_baseline import detect_anomalies
        ctx.description = ""
        author = ""
        if reg.raw_metadata:
            info = reg.raw_metadata.get("info", {}) or {}
            ctx.description = info.get("summary", "") or info.get("ctx.description", "")[:200]
            author = info.get("author") or info.get("author_email") or ""
        findings = detect_anomalies(package, ctx.description, ctx.behavior.files)
        for f in findings:
            ctx.evidence.append(_anomaly_to_evidence(f))
        ctx.stage_results.append(StageResult(
            stage="stage_4b_anomaly_detection",
            success=True,
            payload={"anomalies": len(findings)},
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_4b_anomaly_detection", success=False, error=str(e),
        ))
        ctx.description = ""
        author = ""

    # ========== Stage 4C: 47-Indicator 매처 (논문 2025) ==========
    _stage4c_cache_status = "skipped"
    try:
        from .db.stage_cache import StageCache, StageCacheKey
        from .stages.indicator_matcher import IndicatorMatchReport
        _sc = StageCache() if ctx.options.use_cache else None
        _ck4c = StageCacheKey(
            package=package, ecosystem=ecosystem.value,
            version=target_version, stage="stage_4c_ind47",
        )
        _hit = (
            _sc.get(_ck4c, archive_sha256=ctx.archive_sha256)
            if _sc and not ctx.options.force_rescan
            else None
        )
        ind_report = None
        if _hit is not None and _hit.hit:
            try:
                ind_report = IndicatorMatchReport.from_dict(_hit.payload)
                _stage4c_cache_status = "hit"
            except Exception:
                ind_report = None

        if ind_report is None:
            # 의존성 추출 (있으면 메타 매처에 전달)
            declared_deps: list[str] = []
            try:
                from .stages.stage_dependency import extract_dependencies
                dep_ext = extract_dependencies(ctx.ext.source_files, ecosystem)
                declared_deps = [d.name for d in dep_ext.direct_deps]
            except Exception:
                pass

            ind_report = match_47_indicators(
                behavior_files=ctx.behavior.files,
                source_files=ctx.ext.source_files,
                package_name=package,
                description=ctx.description,
                author=author,
                declared_deps=declared_deps,
            )
            _stage4c_cache_status = "miss" if _hit is not None else "disabled"
            if _sc:
                try:
                    _sc.put(
                        _ck4c, ind_report.to_dict(),
                        archive_sha256=ctx.archive_sha256,
                    )
                except Exception:
                    pass

        # 파일별 지표 코드 집합 — risk_combo escalation 은 file-local 판정.
        # 패키지 전역 집합을 쓰면 한 파일의 결정적 코드가 다른 파일 수십 개의
        # weak 지표를 모두 HIGH 로 부풀려 합법 프레임워크 FP 폭증 (django 케이스).
        codes_per_file: dict[str, set[str]] = {}
        for h in ind_report.hits:
            codes_per_file.setdefault(h.file_path, set()).add(h.indicator.code)
        for h in ind_report.hits:
            ctx.evidence.append(
                _indicator_hit_to_evidence(h, codes_per_file.get(h.file_path, set()))
            )
        ctx.stage_results.append(StageResult(
            stage="stage_4c_indicator_matcher",
            success=True,
            payload={
                "total_hits": len(ind_report.hits),
                "high_severity": ind_report.high_severity_count,
                "categories": [c.value for c in ind_report.categories_present],
                "stage_cache": _stage4c_cache_status,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_4c_indicator_matcher", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))

    # ========== Stage 4E: Sequential Pattern Mining ==========
    _stage4e_cache_status = "skipped"
    try:
        from .db.stage_cache import StageCache, StageCacheKey
        from .stages.sequence_patterns import SequenceMineReport
        _sc = StageCache() if ctx.options.use_cache else None
        _ck4e = StageCacheKey(
            package=package, ecosystem=ecosystem.value,
            version=target_version, stage="stage_4e_sequence",
        )
        _hit = (
            _sc.get(_ck4e, archive_sha256=ctx.archive_sha256)
            if _sc and not ctx.options.force_rescan
            else None
        )
        seq_rpt = None
        if _hit is not None and _hit.hit:
            try:
                seq_rpt = SequenceMineReport.from_dict(_hit.payload)
                _stage4e_cache_status = "hit"
            except Exception:
                seq_rpt = None

        if seq_rpt is None:
            seq_rpt = mine_sequences(ctx.behavior)
            _stage4e_cache_status = "miss" if _hit is not None else "disabled"
            if _sc:
                try:
                    _sc.put(
                        _ck4e, seq_rpt.to_dict(),
                        archive_sha256=ctx.archive_sha256,
                    )
                except Exception:
                    pass

        for m in seq_rpt.matches:
            ctx.evidence.append(_sequence_match_to_evidence(m))
        ctx.stage_results.append(StageResult(
            stage="stage_4e_sequence_mining",
            success=seq_rpt.error is None,
            error=seq_rpt.error,
            payload={
                "patterns_matched": len(seq_rpt.matches),
                "patterns": sorted({m.pattern.code for m in seq_rpt.matches}),
                "stage_cache": _stage4e_cache_status,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_4e_sequence_mining", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))

    # ========== Stage 4D: Taint Slicing (논문 2025) ==========
    # source(env/file/secret) -> sink(http/exec) 흐름만 추출해
    # Stage 5 LLM 프롬프트 토큰을 줄임.
    taint_slice_by_path: dict[str, str] = {}
    taint_total_flows = 0
    _stage4d_cache_status = "skipped"
    try:
        from .db.stage_cache import StageCache, StageCacheKey
        from .stages.taint_slicer import TaintFlow
        _sc = StageCache() if ctx.options.use_cache else None
        _ck4d = StageCacheKey(
            package=package, ecosystem=ecosystem.value,
            version=target_version, stage="stage_4d_taint",
        )
        _hit = (
            _sc.get(_ck4d, archive_sha256=ctx.archive_sha256)
            if _sc and not ctx.options.force_rescan
            else None
        )

        # path → source content (taint_slice_for_llm 재계산용)
        _content_by_path = {
            sf.path: sf.content
            for sf in ctx.ext.source_files
            if sf.language == "python"
        }

        flows_by_path: dict[str, list[TaintFlow]] | None = None
        if _hit is not None and _hit.hit:
            try:
                cached = _hit.payload.get("flows_by_path", {})
                flows_by_path = {
                    p: [TaintFlow.from_dict(f) for f in items]
                    for p, items in cached.items()
                }
                _stage4d_cache_status = "hit"
            except Exception:
                flows_by_path = None

        if flows_by_path is None:
            flows_by_path = {}
            for sf in ctx.ext.source_files:
                if sf.language != "python":
                    continue  # JS 는 차후 (tree-sitter 기반)
                rpt = taint_analyze_python(sf.content)
                if rpt.flows:
                    flows_by_path[sf.path] = rpt.flows
            _stage4d_cache_status = "miss" if _hit is not None else "disabled"
            if _sc:
                try:
                    _sc.put(
                        _ck4d,
                        {
                            "flows_by_path": {
                                p: [f.to_dict() for f in flows]
                                for p, flows in flows_by_path.items()
                            }
                        },
                        archive_sha256=ctx.archive_sha256,
                    )
                except Exception:
                    pass

        for path, flows in flows_by_path.items():
            if not flows:
                continue
            taint_total_flows += len(flows)
            content = _content_by_path.get(path, "")
            if content:
                taint_slice_by_path[path] = taint_slice_for_llm(content, flows)

        ctx.stage_results.append(StageResult(
            stage="stage_4d_taint_slicing",
            success=True,
            payload={
                "files_with_flows": len(taint_slice_by_path),
                "total_flows": taint_total_flows,
                "stage_cache": _stage4d_cache_status,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_4d_taint_slicing", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))

    # ========== Stage 5: LLM 이중 검증 (단일 또는 다중 에이전트) ==========
    multi_agent_consensus_per_file: dict[str, ConsensusReport] = {}
    try:
        # Stage 5 에서 사용할 의존성 / new_apis 사전 추출
        try:
            from .stages.stage_dependency import extract_dependencies
            _dep_ext = extract_dependencies(ctx.ext.source_files, ecosystem)
            stage5_declared_deps = [d.name for d in _dep_ext.direct_deps]
        except Exception:
            stage5_declared_deps = []

        # 새 API 호출(ctx.diff 신규 추가) 수집
        new_apis_all: list[str] = []
        if ctx.diff and ctx.diff.file_diffs:
            for fd in ctx.diff.file_diffs:
                # 일부 구현엔 added_calls / new_apis 가 있음 — 안전하게 fallback
                for attr in ("added_calls", "new_apis", "added_apis"):
                    val = getattr(fd, attr, None)
                    if val:
                        for v in val:
                            new_apis_all.append(str(v))

        for m in match_report.matches:
            fs = _find_file_seq(ctx.behavior, m.file_path)
            if fs is None:
                continue
            snippet = _snippet_for(fs)
            diff_summary = None
            if ctx.diff and ctx.diff.file_diffs:
                diff_summary = (
                    f"{len(ctx.diff.file_diffs)} file(s) changed, "
                    f"severity {ctx.diff.overall_severity.value}"
                )
            taint_slice = taint_slice_by_path.get(fs.path)

            if ctx.options.use_multi_agent:
                consensus_rpt = review_multi(
                    package, target_version, ecosystem.value,
                    fs, match_report.matches,
                    code_snippet=snippet,
                    version_diff_summary=diff_summary,
                    new_apis=new_apis_all,
                    description=ctx.description,
                    declared_deps=stage5_declared_deps,
                    taint_slice=taint_slice,
                    mode=ctx.options.llm_mode,
                )
                multi_agent_consensus_per_file[fs.path] = consensus_rpt
                llm = consensus_to_llm_response(consensus_rpt)
            else:
                llm = review(
                    package, target_version, ecosystem.value,
                    fs, match_report.matches, snippet,
                    version_diff_summary=diff_summary,
                    mode=ctx.options.llm_mode,
                    taint_slice=taint_slice,
                )
            line_start = fs.calls[0].line if fs.calls else 0
            line_end = fs.calls[-1].line if fs.calls else 0
            vd_info = ctx.diff.to_version_diff_info() if ctx.diff else None
            ctx.evidence.append(Evidence(
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
        # version_diff 가 의미 있는 변화를 보고했지만 TTP 매치가 비어 있어
        # diff 결과가 verdict 에 닿지 못하는 경우를 보강.
        # → diff-only Evidence 한 개 추가 (event-stream / xz 류 케이스 대비).
        if (
            ctx.diff is not None
            and ctx.diff.error is None
            and ctx.diff.compared_versions
            and ctx.diff.overall_severity != Severity.LOW
            and not any(e.version_diff for e in ctx.evidence)
        ):
            vd_info = ctx.diff.to_version_diff_info()
            if vd_info is not None:
                # 진단용 — verdict_rules._any_version_diff(_critical) 가 인식
                ctx.evidence.append(Evidence(
                    file_path="<version-diff>",
                    line_start=0,
                    line_end=0,
                    code_snippet=(
                        f"version diff vs {', '.join(vd_info.compared_versions)}: "
                        f"{vd_info.details}"
                    ),
                    behavior_sequence=[f"diff:{api}" for api in vd_info.new_apis[:8]],
                    attack_dimensions=[],
                    ttp_id="DIFF/T1195.002",
                    ttp_name=f"Version-diff risk introduction "
                             f"({vd_info.risk_classification.value})",
                    ttp_source=TTPSource.MITRE_ATTACK,
                    ttp_url="https://attack.mitre.org/techniques/T1195/002/",
                    ttp_severity=vd_info.risk_classification,
                    vector_similarity=1.0,
                    llm_verdict=(
                        LLMVerdict.SUSPICIOUS
                        if vd_info.risk_classification in (Severity.HIGH, Severity.MEDIUM)
                        else LLMVerdict.BENIGN
                    ),
                    llm_reasoning=(
                        f"new APIs introduced in current version vs prior "
                        f"({len(vd_info.new_apis)} added). "
                        f"{vd_info.details}"
                    ),
                    llm_model="version-diff-rule",
                    version_diff=vd_info,
                    confidence=(
                        0.85 if vd_info.risk_classification == Severity.HIGH
                        else 0.6 if vd_info.risk_classification == Severity.MEDIUM
                        else 0.3
                    ),
                ))

        # 멀티 에이전트 통계
        ma_payload: dict = {}
        if ctx.options.use_multi_agent and multi_agent_consensus_per_file:
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
        ctx.stage_results.append(StageResult(
            stage="stage_5_llm_review",
            success=True,
            payload={
                "evidence_generated": len(ctx.evidence),
                "mode": ctx.options.llm_mode,
                **ma_payload,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_5_llm_review", success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        report = empty_report(package, ecosystem, target_version)
        report.verdict = Verdict.ERROR
        report.stage_results = ctx.stage_results
        report.evidence = ctx.evidence
        return report

    # ========== Stage 6: 의존성 재귀 (옵션) ==========
    if ctx.options.enable_deps:
        try:
            from .stages.stage_dependency import analyze_dependencies, extract_dependencies
            dep_ext = extract_dependencies(ctx.ext.source_files, ecosystem)
            dep_results = analyze_dependencies(
                dep_ext, ecosystem, attack_history_only=True, max_packages=30,
            )
            hit_count = 0
            for dr in dep_results:
                ev = _dependency_to_evidence(dr)
                if ev:
                    ctx.evidence.append(ev)
                    hit_count += 1
            ctx.stage_results.append(StageResult(
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
            ctx.stage_results.append(StageResult(
                stage="stage_6_dependencies", success=False, error=str(e),
            ))

    # ========== Stage 7: 바이너리 ==========
    if ctx.ext.binary_files:
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
                archive_bytes, ctx.ext.binary_files, archive_url,
            )
            hit_count = 0
            for bf in bin_findings:
                if bf.has_findings:
                    ctx.evidence.append(_binary_to_evidence(bf))
                    hit_count += 1
            ctx.stage_results.append(StageResult(
                stage="stage_7_binary",
                success=True,
                payload={
                    "binaries": len(bin_findings),
                    "hits": hit_count,
                },
            ))
        except Exception as e:
            ctx.stage_results.append(StageResult(
                stage="stage_7_binary", success=False, error=str(e),
            ))
    else:
        ctx.stage_results.append(StageResult(
            stage="stage_7_binary",
            success=True,
            payload={"binaries": 0, "skipped": "no binary files"},
        ))

    # ========== Stage 8: 샌드박스 (옵션) ==========
    if ctx.options.enable_sandbox:
        try:
            from .stages.stage_sandbox import get_default_sandbox
            sb = get_default_sandbox()
            obs = sb.run(package, ecosystem, target_version)
            if obs.has_findings:
                ctx.evidence.append(_sandbox_to_evidence(obs))
            ctx.stage_results.append(StageResult(
                stage="stage_8_sandbox",
                success=True,
                payload={
                    "mode": obs.mode,
                    "duration_s": obs.duration_s,
                    "has_findings": obs.has_findings,
                },
            ))
        except Exception as e:
            ctx.stage_results.append(StageResult(
                stage="stage_8_sandbox", success=False, error=str(e),
            ))

    # ========== Stage 9: Verdict + 리포트 ==========
    verdict = decide_verdict(ctx.evidence, ctx.stage_results, registry_found=True)

    report = empty_report(package, ecosystem, target_version)
    report.verdict = verdict
    report.evidence = ctx.evidence
    report.stage_results = ctx.stage_results
    report.package_meta = {
        "latest_version": reg.latest_version,
        "version_count": len(reg.all_versions) if reg.all_versions else 0,
        "archive_size": ctx.ext.archive_size,
        "source_files": len(ctx.ext.source_files),
        "binary_files": len(ctx.ext.binary_files),
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
        from .knowledge.mitre_atlas import supply_chain_relevant
        from .knowledge.owasp_llm import (
            get as get_owasp,
        )
        from .knowledge.owasp_llm import (
            map_verdict_to_owasp,
        )
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
        all_source_paths = [sf.path for sf in ctx.ext.source_files]
        # binary file 도 포함하면 SBOM 검출 강화
        all_source_paths.extend([bf.path for bf in ctx.ext.binary_files])
        ssdf_rpt = ssdf_evaluate(
            ecosystem=ecosystem,
            registry_found=True,
            raw_metadata=reg.raw_metadata,
            source_paths=all_source_paths,
            scorecard=scorecard_report,
        )
        report.package_meta["ssdf"] = ssdf_rpt.to_dict()
        ctx.stage_results.append(StageResult(
            stage="stage_ssdf_compliance",
            success=True,
            payload={
                "pass": ssdf_rpt.pass_count,
                "fail": ssdf_rpt.fail_count,
                "unknown": ssdf_rpt.unknown_count,
            },
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_ssdf_compliance", success=False, error=str(e),
        ))
    report.kb_versions = {
        "MITRE ATT&CK": "cached-local",
        "OSV": "cached-local",
    }

    # ========== 캐시 저장 (분석 완료 후) ==========
    if ctx.options.use_cache:
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



if __name__ == "__main__":
    from .cli import main
    main()
