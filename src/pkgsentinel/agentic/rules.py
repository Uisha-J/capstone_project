"""
R1-R4 룰셋 — agentic 패키지 정밀 검사.

근거: spec/RULES.md
  R1. Prompt Injection 가능성       (Beurer-Kellner 2025, Meta 2025, OWASP LLM01)
  R2. Sandbox Escape 시도           (Meta Rule of Two 2025, OWASP Agentic 2025)
  R3. Undeclared Capability         (OWASP Agentic 2025)
  R4. Hidden Side Channel           (NVIDIA-Lakera 2025, Lin et al. 2025)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .capability_detector import Capability


class RuleSeverity(str, Enum):
    MALICIOUS = "MALICIOUS"
    HIGH_RISK = "HIGH_RISK"
    SUSPICIOUS = "SUSPICIOUS"


@dataclass
class RuleHit:
    rule_id: str            # 'R1-1', 'R2-2', ...
    severity: RuleSeverity
    file_path: str
    snippet: str
    reason: str
    excused_by: list[str] = field(default_factory=list)  # 면책 패턴 목록


@dataclass
class RuleReport:
    hits: list[RuleHit] = field(default_factory=list)

    def add(self, h: RuleHit):
        self.hits.append(h)

    def by_severity(self, sev: RuleSeverity) -> list[RuleHit]:
        return [h for h in self.hits if h.severity == sev]

    def has_malicious(self) -> bool:
        return any(h.severity == RuleSeverity.MALICIOUS for h in self.hits)

    def has_high_risk(self) -> bool:
        return any(h.severity == RuleSeverity.HIGH_RISK for h in self.hits)

    def to_dict(self) -> dict:
        return {
            "total": len(self.hits),
            "by_severity": {
                s.value: len(self.by_severity(s))
                for s in RuleSeverity
            },
            "hits": [
                {
                    "rule": h.rule_id,
                    "severity": h.severity.value,
                    "file": h.file_path,
                    "snippet": h.snippet[:200],
                    "reason": h.reason,
                    "excused_by": h.excused_by,
                }
                for h in self.hits
            ],
        }


# ─────────────── 헬퍼 ───────────────

DANGEROUS_UNDECLARED = {
    Capability.SHELL,
    Capability.CODE_EXEC,
    Capability.CREDENTIAL_PATHS,
}

MEDIUM_UNDECLARED = {
    Capability.NETWORK,
    Capability.FS_WRITE,
    Capability.ENV_SECRETS,
    Capability.DB_ACCESS,
    Capability.MCP_SERVER,
    Capability.DYNAMIC_TOOL_LOAD,
}


def _make_hit(rule_id: str, sev: RuleSeverity, *,
              file_path: str = "", snippet: str = "",
              reason: str = "", excused_by: list[str] | None = None) -> RuleHit:
    return RuleHit(
        rule_id=rule_id, severity=sev,
        file_path=file_path, snippet=snippet[:300],
        reason=reason, excused_by=excused_by or [],
    )


# ─────────────── R1. Prompt Injection 가능성 ───────────────

# R1-1: 신뢰 불가 입력이 system prompt 와 동일 권한
_R1_1_PATTERNS = [
    # f-string으로 외부 콘텐츠를 system prompt 에 직접 삽입
    re.compile(
        r"(?:system|prompt|instruction)\s*=\s*f[\"'][^\"']*\{[^}]*"
        r"(?:html|content|data|text|page|fetched|scraped|web|response|tool_output|"
        r"observation|external|user_input|search_result|retrieved)"
        r"[^}]*\}",
        re.IGNORECASE,
    ),
    # role=system 메시지에 외부값 concat
    re.compile(
        r"\{[\"']role[\"']\s*:\s*[\"']system[\"']\s*,\s*"
        r"[\"']content[\"']\s*:\s*"
        r"[^}]*(?:\+\s*\w+|f[\"'][^\"']*\{)",
        re.IGNORECASE,
    ),
    # tool 결과를 그대로 system 메시지로 push
    re.compile(
        r"messages\s*\.\s*append\s*\(\s*\{\s*[\"']role[\"']\s*:\s*[\"']system[\"']"
        r"[\s\S]{0,80}tool",
        re.IGNORECASE,
    ),
]

# R1-2: tool description 동적 로딩 (ToolHijacker)
_R1_2_PATTERNS = [
    re.compile(r"requests\.get\s*\([^)]*\)\s*\.json\(\)", re.IGNORECASE),
    re.compile(r"agent\s*\.\s*bind_tools\s*\([^)]*remote", re.IGNORECASE),
    re.compile(r"tools?\s*\.\s*append\s*\(\s*request", re.IGNORECASE),
    re.compile(r"client\.listTools\s*\(", re.IGNORECASE),
    re.compile(r"session\.list_tools\s*\(", re.IGNORECASE),
]

# R1-3: 검색/fetch 결과를 sanitization 없이 컨텍스트 주입
_R1_3_PATTERNS = [
    re.compile(
        r"(?:web_search|search|browse|fetch|crawl|scrape)\s*\([^)]*\)"
        r"[\s\S]{0,200}"
        r"(?:llm|model|chain|agent)\s*\.\s*invoke",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<varname>results?|content|response|page|html)\s*=\s*"
        r"(?:requests|httpx|fetch)\s*\."
        r"[\s\S]{0,300}"
        r"messages\s*\.\s*append\s*\([^)]*(?P=varname)",
        re.IGNORECASE,
    ),
]

# R1-4: 자유형 코드/툴 실행 디폴트
_R1_4_PATTERNS = [
    # LLM 출력을 직접 exec (변수명 일치)
    re.compile(
        r"(?P<v>code|cmd|tool_call|llm_output|generated)\s*=\s*"
        r"(?:llm|model|client)\s*\.\s*(?:invoke|complete|chat|generate)"
        r"[\s\S]{0,200}"
        r"(?:exec|eval)\s*\(\s*(?P=v)",
        re.IGNORECASE,
    ),
    # subprocess shell=True 에 LLM 출력
    re.compile(
        r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True[^)]*"
        r"(?:llm_|model_|generated_|cmd|command)",
        re.IGNORECASE,
    ),
    # globals()[tool_name](...) 패턴
    re.compile(r"globals\(\)\s*\[\s*\w+\s*\]\s*\(", re.IGNORECASE),
    # getattr(module, tool_name)(...) 동적 디스패치
    re.compile(r"getattr\s*\([^,]+,\s*\w+\s*\)\s*\(", re.IGNORECASE),
]


def R1_check(
    sources: dict[str, str],
    *,
    design_patterns_applied: list[str] | None = None,
) -> list[RuleHit]:
    hits: list[RuleHit] = []
    dp = set(design_patterns_applied or [])

    for path, src in sources.items():
        # R1-1
        for pat in _R1_1_PATTERNS:
            m = pat.search(src)
            if m:
                excused = []
                if {"dual-llm", "llm-map-reduce"} & dp:
                    excused.append("dual-llm or llm-map-reduce applied")
                hits.append(_make_hit(
                    "R1-1",
                    RuleSeverity.SUSPICIOUS if excused else RuleSeverity.HIGH_RISK,
                    file_path=path, snippet=m.group(0),
                    reason="untrusted input mixed with privileged prompt",
                    excused_by=excused,
                ))
                break

        # R1-2
        for pat in _R1_2_PATTERNS:
            m = pat.search(src)
            if m:
                hits.append(_make_hit(
                    "R1-2", RuleSeverity.HIGH_RISK,
                    file_path=path, snippet=m.group(0),
                    reason="tool description loaded dynamically (ToolHijacker)",
                ))
                break

        # R1-3
        for pat in _R1_3_PATTERNS:
            m = pat.search(src)
            if m:
                excused = []
                if {"plan-then-execute", "context-minimization"} & dp:
                    excused.append("plan-then-execute or context-minimization")
                hits.append(_make_hit(
                    "R1-3",
                    RuleSeverity.SUSPICIOUS,
                    file_path=path, snippet=m.group(0),
                    reason="external fetch result injected to LLM context "
                           "without sanitization",
                    excused_by=excused,
                ))
                break

        # R1-4
        for pat in _R1_4_PATTERNS:
            m = pat.search(src)
            if m:
                excused = []
                if "action-selector" in dp:
                    excused.append("action-selector (whitelisted tools)")
                if "code-then-execute" in dp:
                    excused.append("code-then-execute + sandbox")
                hits.append(_make_hit(
                    "R1-4",
                    RuleSeverity.SUSPICIOUS if excused else RuleSeverity.HIGH_RISK,
                    file_path=path, snippet=m.group(0),
                    reason="free-form code/tool execution as default",
                    excused_by=excused,
                ))
                break

    return hits


# ─────────────── R2. Sandbox Escape ───────────────

# R2-2: 권한 상승
_R2_2_PATTERNS = [
    re.compile(r"\bos\.setuid\s*\(\s*0\s*\)"),
    re.compile(r"\bos\.setgid\s*\(\s*0\s*\)"),
    re.compile(r"subprocess\.\w+\s*\(\s*\[\s*[\"']sudo[\"']"),
    re.compile(r"setresuid\s*\(\s*0\s*,\s*0\s*,\s*0\s*\)"),
    re.compile(r"capset\s*\("),
]

# R2-3: 컨테이너/sandbox 우회
_R2_3_PATTERNS = [
    re.compile(r"[\"']/var/run/docker\.sock[\"']"),
    re.compile(r"[\"']/proc/self/cgroup[\"']"),
    re.compile(r"\bos\.unshare\s*\("),
    re.compile(r"CLONE_NEW(?:NS|UTS|PID|NET|USER)"),
    re.compile(r"\bos\.listdir\s*\(\s*[\"']/proc[\"']\s*\)"),
]

# R2-4: 동적 의존성 설치
_R2_4_PATTERNS_STATIC = [
    re.compile(r"subprocess\.\w+\s*\(\s*\[\s*[\"']pip[\"']\s*,\s*[\"']install[\"']"),
    re.compile(r"os\.system\s*\(\s*f?[\"'][^\"']*pip\s+install"),
    re.compile(r"__import__\s*\(\s*[\"']pip[\"']\s*\)\s*\.\s*main"),
    re.compile(r"child_process\.exec\s*\([^)]*npm\s+install"),
]
_R2_4_DYNAMIC_RE = re.compile(
    r"(?:subprocess\.\w+|os\.system|child_process\.exec)\s*\([^)]*"
    r"(?:llm_|model_|agent_|generated_)",
    re.IGNORECASE,
)


def R2_check(
    sources: dict[str, str],
    *,
    detected_capabilities: set[str],
    has_hitl: bool,
    declared_session_isolation: bool,
) -> list[RuleHit]:
    from .rule_of_two import has_lethal_trifecta
    hits: list[RuleHit] = []

    # R2-1: Lethal Trifecta
    chk = has_lethal_trifecta(
        detected_capabilities,
        has_hitl=has_hitl,
        declared_session_isolation=declared_session_isolation,
    )
    if chk.has_trifecta:
        if chk.is_violation:
            hits.append(_make_hit(
                "R2-1", RuleSeverity.HIGH_RISK,
                file_path="<capability-set>",
                snippet=f"ABC = {sorted(chk.abc_present)}",
                reason="Lethal Trifecta (A+B+C) without HITL or session_isolation",
            ))
        else:
            hits.append(_make_hit(
                "R2-1", RuleSeverity.SUSPICIOUS,
                file_path="<capability-set>",
                snippet=f"ABC = {sorted(chk.abc_present)}",
                reason="Lethal Trifecta present but mitigated (HITL/session_isolation)",
                excused_by=(
                    ["human-in-the-loop"] if has_hitl else []
                ) + (
                    ["session_isolation declared"] if declared_session_isolation else []
                ),
            ))

    for path, src in sources.items():
        # R2-2
        for pat in _R2_2_PATTERNS:
            m = pat.search(src)
            if m:
                hits.append(_make_hit(
                    "R2-2", RuleSeverity.MALICIOUS,
                    file_path=path, snippet=m.group(0),
                    reason="privilege escalation attempt",
                ))
                break

        # R2-3
        for pat in _R2_3_PATTERNS:
            m = pat.search(src)
            if m:
                hits.append(_make_hit(
                    "R2-3", RuleSeverity.MALICIOUS,
                    file_path=path, snippet=m.group(0),
                    reason="container/sandbox escape signal",
                ))
                break

        # R2-4
        is_dynamic = bool(_R2_4_DYNAMIC_RE.search(src))
        for pat in _R2_4_PATTERNS_STATIC:
            m = pat.search(src)
            if m:
                hits.append(_make_hit(
                    "R2-4",
                    RuleSeverity.MALICIOUS if is_dynamic else RuleSeverity.HIGH_RISK,
                    file_path=path, snippet=m.group(0),
                    reason=(
                        "runtime dependency installation "
                        f"({'LLM-driven' if is_dynamic else 'static'})"
                    ),
                ))
                break

    return hits


# ─────────────── R3. Undeclared Capability ───────────────

def R3_check(
    *,
    declared: set[str],
    detected: set[str],
    manifest_present: bool,
) -> list[RuleHit]:
    hits: list[RuleHit] = []
    undeclared = detected - declared

    if undeclared & DANGEROUS_UNDECLARED:
        bad = sorted(undeclared & DANGEROUS_UNDECLARED)
        hits.append(_make_hit(
            "R3-dangerous", RuleSeverity.MALICIOUS,
            file_path="<capability-set>",
            snippet=f"undeclared dangerous: {bad}",
            reason=f"undeclared dangerous capabilities {bad}",
        ))

    medium = (undeclared - DANGEROUS_UNDECLARED) & MEDIUM_UNDECLARED
    if medium:
        hits.append(_make_hit(
            "R3-medium", RuleSeverity.SUSPICIOUS,
            file_path="<capability-set>",
            snippet=f"undeclared medium: {sorted(medium)}",
            reason=(
                "undeclared medium capabilities "
                f"{sorted(medium)}; manifest_present={manifest_present}"
            ),
        ))

    minor = undeclared - DANGEROUS_UNDECLARED - MEDIUM_UNDECLARED
    if minor and not manifest_present:
        hits.append(_make_hit(
            "R3-minor-no-manifest", RuleSeverity.SUSPICIOUS,
            file_path="<capability-set>",
            snippet=f"manifest absent; minor caps: {sorted(minor)}",
            reason="manifest missing; capabilities used implicitly",
        ))

    return hits


# ─────────────── R4. Hidden Side Channel ───────────────

# R4-1: 로깅 툴을 통한 covert exfiltration
# 키워드는 영문 빈도 상위 동의어 + 산업 표준 NIST/CIS 텔레메트리 용어 포함.
# 부분 매칭 (substring) 으로 동작 — `event_logger`, `audit_trail`, `usage_stats` 등 매칭.
_R4_1_LOG_NAMES = [
    "log", "logger", "logging",
    "audit", "trail",
    "track", "tracker", "tracing",
    "metric", "metrics",
    "analytic", "analytics",
    "telemetry", "telemetric",
    "stat", "stats", "statistics",
    "report", "reporter", "reporting",
    "monitor", "monitoring",
    "usage", "event",
    "diagnostic", "diagnostics",
    "heartbeat", "ping",
    "instrument", "instrumentation",
]

# R4-5: tool-name vs behavior mismatch.
# "innocent-sounding" 함수명 안에 dangerous API 가 등장하면 의심.
# 키워드 카탈로그는 일반적인 read-only/validation/format 동사 위주.
_R4_5_BENIGN_VERBS = [
    "validate", "verify", "check", "is_", "has_",
    "format", "parse", "render", "stringify",
    "get", "fetch_config", "read_config", "read_setting",
    "compute", "calculate", "compare", "diff_",
    "convert", "transform", "normalize", "sanitize",
    "hash_", "encode_safe", "escape",
]
_R4_5_DANGEROUS_BODY = re.compile(
    r"(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|"
    r"os\.popen|eval\s*\(|exec\s*\(|compile\s*\(|"
    r"socket\.(?:socket|create_connection)|"
    r"requests\.(?:post|put|patch)\s*\([\"']https?://(?!localhost|127\.|0\.0\.0\.0))",
    re.IGNORECASE,
)


def _r4_1_check(src: str, path: str) -> list[RuleHit]:
    hits = []
    # 함수 정의 / 도구 정의에서 description 이 'log/audit/analytics' 인데
    # 구현부에 외부 endpoint 호출이 있으면 의심
    func_pat = re.compile(
        r"(?:def|async\s+def|@tool[^\n]*\n\s*def)\s+(\w+)\s*\([^)]*\)[^:]*:\s*"
        r"(?:[\"']{3}([^\"']*)[\"']{3})?",
        re.IGNORECASE,
    )
    ext_post_re = re.compile(
        r"requests\.post\s*\([\"']https?://(?!localhost|127\.|0\.0\.0\.0)",
        re.IGNORECASE,
    )
    for m in func_pat.finditer(src):
        fn_name = m.group(1) or ""
        docstring = m.group(2) or ""
        looks_logy = (
            any(k in fn_name.lower() for k in _R4_1_LOG_NAMES)
            or any(k in docstring.lower() for k in _R4_1_LOG_NAMES)
        )
        if not looks_logy:
            continue
        # 함수 본문 (다음 def 까지) 안에 외부 POST 가 있는지
        start = m.end()
        next_def = re.search(r"\n(?:def|async\s+def|@\w)", src[start:])
        body = src[start:start + (next_def.start() if next_def else 800)]
        if ext_post_re.search(body):
            hits.append(_make_hit(
                "R4-1", RuleSeverity.MALICIOUS,
                file_path=path, snippet=m.group(0)[:200],
                reason=f"function '{fn_name}' described as logging "
                       f"but posts to external endpoint",
            ))
    return hits


def _r4_5_check(src: str, path: str) -> list[RuleHit]:
    """benign-name vs dangerous-body mismatch (R4-5).

    함수명이 read-only/validation/format 류로 보이는데 본문에 shell exec/
    network sink 가 등장하면 의심 — Trojan-style 툴 가능성.
    """
    hits = []
    func_pat = re.compile(
        r"(?:def|async\s+def)\s+(\w+)\s*\([^)]*\)\s*(?:->[^:]+)?:\s*"
        r"(?:[\"']{3}([^\"']*)[\"']{3})?",
        re.IGNORECASE,
    )
    for m in func_pat.finditer(src):
        fn_name = (m.group(1) or "").lower()
        if not any(fn_name.startswith(v) or v in fn_name for v in _R4_5_BENIGN_VERBS):
            continue
        # 함수 본문 (다음 def 까지)
        start = m.end()
        next_def = re.search(r"\n(?:def|async\s+def|class\s+|@\w)", src[start:])
        body = src[start:start + (next_def.start() if next_def else 800)]
        bm = _R4_5_DANGEROUS_BODY.search(body)
        if bm:
            hits.append(_make_hit(
                "R4-5", RuleSeverity.HIGH_RISK,
                file_path=path, snippet=m.group(0)[:200],
                reason=(
                    f"function '{fn_name}' has benign-looking name but body "
                    f"contains dangerous primitive: {bm.group(0)[:60]}"
                ),
            ))
    return hits


# R4-2: memory poisoning 경로
_R4_2_PATTERNS = [
    re.compile(
        r"(?:scrape|web_search|fetch|crawl|download|read_url)\s*\([^)]*\)"
        r"[\s\S]{0,300}"
        r"(?:vector_store|chromadb|pinecone|weaviate)\s*\.\s*"
        r"(?:add|upsert|insert|index)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:vector_store|memory)\s*\.\s*add(?:_texts)?\s*\("
        r"\s*(?:external|untrusted|fetched|scraped)",
        re.IGNORECASE,
    ),
]

# R4-4: A2A 미인증
_R4_4_PATTERNS = [
    re.compile(
        r"(?:Crew|GroupChat|GroupChatManager)\s*\([^)]*\)"
        r"[\s\S]{0,300}"
        r"\.\s*(?:kickoff|run|start)\s*\(\s*(?:inputs|messages)\s*=\s*\w+",
        re.IGNORECASE,
    ),
    re.compile(
        r"async\s+def\s+receive_from_peer\s*\([^)]*\)\s*:[\s\S]{0,200}"
        r"(?:process|handle)\s*\(",
        re.IGNORECASE,
    ),
]


def R4_check(
    sources: dict[str, str],
    *,
    detected_capabilities: set[str],
) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for path, src in sources.items():
        # R4-1
        hits.extend(_r4_1_check(src, path))

        # R4-5 (name vs behavior mismatch)
        hits.extend(_r4_5_check(src, path))

        # R4-2
        for pat in _R4_2_PATTERNS:
            m = pat.search(src)
            if m:
                hits.append(_make_hit(
                    "R4-2", RuleSeverity.HIGH_RISK,
                    file_path=path, snippet=m.group(0)[:200],
                    reason="external data ingested to persistent memory "
                           "without provenance",
                ))
                break

        # R4-4
        for pat in _R4_4_PATTERNS:
            m = pat.search(src)
            if m:
                hits.append(_make_hit(
                    "R4-4", RuleSeverity.SUSPICIOUS,
                    file_path=path, snippet=m.group(0)[:200],
                    reason="multi-agent communication without sender authentication",
                ))
                break

    # R4-3: provenance 부재 — 휴리스틱 (memory_persist 사용 + logging 호출 부재)
    has_memory = Capability.MEMORY_PERSIST in detected_capabilities
    if has_memory:
        any_logging = any(
            re.search(r"(?:logger|logging\.|log\.|audit_log)", src)
            for src in sources.values()
        )
        if not any_logging:
            hits.append(_make_hit(
                "R4-3", RuleSeverity.SUSPICIOUS,
                file_path="<provenance-check>",
                snippet="memory_persistent used without logging.* calls",
                reason="persistent memory without provenance / audit log",
            ))

    return hits


# ─────────────── 통합 ───────────────

def run_all_rules(
    sources: dict[str, str],
    *,
    declared: set[str],
    detected: set[str],
    manifest_present: bool,
    has_hitl: bool,
    declared_session_isolation: bool,
    design_patterns_applied: list[str] | None = None,
) -> RuleReport:
    rep = RuleReport()

    for h in R1_check(sources,
                      design_patterns_applied=design_patterns_applied):
        rep.add(h)

    for h in R2_check(
        sources,
        detected_capabilities=detected,
        has_hitl=has_hitl,
        declared_session_isolation=declared_session_isolation,
    ):
        rep.add(h)

    for h in R3_check(
        declared=declared, detected=detected,
        manifest_present=manifest_present,
    ):
        rep.add(h)

    for h in R4_check(sources, detected_capabilities=detected):
        rep.add(h)

    return rep
