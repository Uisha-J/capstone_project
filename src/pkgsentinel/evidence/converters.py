"""각 탐지 단계 결과를 공통 Evidence 객체로 변환."""
from __future__ import annotations

from ..schema import (
    AttackDimension,
    Evidence,
    LLMVerdict,
    Severity,
    TTPSource,
)
from ..stages.indicator_matcher import IndicatorHit
from ..stages.sequence_patterns import SequenceMatch
from ..stages.string_analysis import SuspiciousString

# 단독으로는 약한 신호인 지표 코드 (정상 패키지에서도 흔히 사용됨).
# 다른 지표와 조합되어야 의미 있음.
STANDALONE_WEAK_INDICATORS = {
    "EXM-001",   # exec/eval — Config 파일 로딩 등 정당한 용도 많음
    "EXS-001",   # import-time call — 거의 모든 __init__.py 가 해당
    "SYS-005",   # system info recon — 환경 진단/디버그용 흔함
    "SYS-004",   # directory enumeration — 빌드 도구가 흔히 사용
    "DEF-006",   # error suppression — 정당한 except: pass 도 많음
    "MET-004",   # description anomaly — 정상 패키지에도 짧은 설명 흔함
    "MET-001",   # author identity — author 비어있는 정상 패키지 많음
    "EXM-005",   # dynamic import — 플러그인 시스템 등에 정당
    "DEF-003",   # encoding — base64는 정당한 용도가 많음 (UUID, 토큰 등)
    # ─── 추가 (2026-05-06, Fix-4+) ───
    # popular-benign N=100 측정 기반 (docs/2026-05-06-fp-root-cause.md):
    "EXM-002",   # 22% FP — `if platform.system() == ...` cross-platform 분기 흔함
    "SYS-002",   # 14% FP — .bashrc/crontab 키워드가 shell completion 안내에 등장
    "EXM-008",   # 13% FP — subprocess.run 빌드/테스트/CLI 도구
    "EXM-003",   # 9% FP — ctypes.CDLL 정상 native binding 다수
    "EXS-002",   # 8% FP — setup.py top-level 호출은 거의 모든 패키지 발화
    "EXM-006",   # 6% FP — dev-mode self-install (pip 등)
    "EXF-001",   # 6% FP — telemetry/error reporter 흔함
    "SYS-001",   # 2% FP — 일부 cross-platform 도구의 PATH 조작
    "NET-009",   # 4% FP — verify=False 가 사내 cert 환경에서 정당
}


def sstr_to_evidence(
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
            vector_similarity=1.0,
            llm_verdict=LLMVerdict.SUSPICIOUS if ss.decoded else LLMVerdict.BENIGN,
            llm_reasoning=f"String constant analysis: {ss.reason}",
            llm_model="string-analysis-rule",
            confidence=0.8 if ss.decoded else 0.4,
        ))
    return out


def anomaly_to_evidence(finding) -> Evidence:
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


def binary_to_evidence(finding) -> Evidence:
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


def sandbox_to_evidence(obs) -> Evidence:
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


def indicator_hit_to_evidence(h: IndicatorHit, indicator_codes_same_file: set[str]) -> Evidence:
    """47-Indicator IndicatorHit -> Evidence.

    indicator_codes_same_file: **같은 파일 안에서** 매칭된 지표 코드 집합.
    여기에 결정적 코드 (EXF-, NET-002/007/008, EXS-002/003, EXM-006/008,
    DEF-005) 가 있으면 standalone-weak 지표를 escalate.

    이전엔 패키지 전역 집합을 사용했는데, 한 파일의 DEF-005 가 다른 파일
    수십 개의 standalone-weak 지표 (EXS-001 import-time 등) 를 모두 HIGH
    로 부풀려서 django/numpy 같은 합법 대형 프레임워크의 FP 가 폭증.
    File-local 로 바꾸면 단일-파일 공격은 그대로 잡히고 (모든 신호가 같은
    파일에 모임), 분산-payload 공격은 결정적 코드 자체가 HIGH 라
    standalone-weak escalation 없이도 발화. 합법 도구의 흩뿌려진 weak
    신호만 BENIGN/LOW 로 정확히 머무름.
    """
    ind = h.indicator

    ttp_id = ind.mitre_ttps[0] if ind.mitre_ttps else "GENERIC"
    ttp_url = (
        f"https://attack.mitre.org/techniques/{ttp_id.split('.')[0]}/"
        if ttp_id != "GENERIC" else ""
    )

    is_standalone_weak = ind.code in STANDALONE_WEAK_INDICATORS

    # Fix-4 (2026-05-06): popular-benign N=100 측정 결과 기반 trigger 명단 축소.
    # 제거: EXM-008 (FP 13%), EXS-002 (FP 8%), EXM-006 (FP 6%), EXF-001 (FP 6%)
    #       — 합법 foundation 도구 (numpy/pip/setuptools/pytest/pandas) 가
    #       정상 기능으로 동시 발화시켜 STANDALONE_WEAK downgrade 무력화.
    # 유지: NET-002/007/008, EXS-003, DEF-005, EXF-002~005
    #       — popular-benign N=100 에서 FP rate ≤ 1% 로 변별력 우수.
    # 근거: docs/2026-05-06-fp-root-cause.md
    _STRONG_TRIGGER_CODES = {
        "EXF-002", "EXF-003", "EXF-004", "EXF-005",  # File/DNS/Webhook/Sus-domain exfil
        "NET-002", "NET-007", "NET-008",             # Mining / curl|bash / reverse shell
        "EXS-003",                                   # cmdclass override
        "DEF-005",                                   # Embedded payload + exec
    }
    has_risk_combo = any(
        c in _STRONG_TRIGGER_CODES
        for c in indicator_codes_same_file
    )

    if is_standalone_weak and not has_risk_combo:
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


def sequence_match_to_evidence(m: SequenceMatch) -> Evidence:
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


def dependency_to_evidence(dep_result) -> Evidence | None:
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
