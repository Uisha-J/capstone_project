"""Falco / Tetragon / Wazuh alert event → IOC + pattern 추출.

각 source 는 포맷이 다르므로 정규화된 ParsedEvent 로 변환 후 IOC 추출.

IOC 종류:
  - ip        (외부 IP: 사설 RFC1918 제외, registry CDN 제외)
  - domain    (외부 도메인: registry domain 제외)
  - sha256    (file/binary content hash, 알려진 hash)
  - path      (자격증명 / SSH / AWS / browser profile 경로)
  - syscall_chain  (의심 syscall 시퀀스 e.g. openat(.ssh)→read→connect)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# 사설 / 신뢰 도메인 — IOC 로 안 잡음
_INTERNAL_IPS_RE = re.compile(
    r"^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|::1|fe80:)"
)

_TRUSTED_REGISTRY_DOMAINS = {
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "rubygems.org", "crates.io",
    "raw.githubusercontent.com", "github.com",
    "storage.googleapis.com",
    "go.dev", "proxy.golang.org",
}

_CRED_PATH_PATTERNS = [
    re.compile(r"/\.ssh/.+", re.IGNORECASE),
    re.compile(r"/\.aws/credentials", re.IGNORECASE),
    re.compile(r"/\.aws/config", re.IGNORECASE),
    re.compile(r"/\.npmrc", re.IGNORECASE),
    re.compile(r"/\.pypirc", re.IGNORECASE),
    re.compile(r"/\.netrc", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"/etc/shadow", re.IGNORECASE),
    re.compile(r"/proc/\d+/environ", re.IGNORECASE),
    # 브라우저 자격증명 디렉터리
    re.compile(r"Library/Application Support/(Google|Brave|Firefox)/",
               re.IGNORECASE),
    re.compile(r"AppData/Roaming/(Mozilla|Microsoft)/", re.IGNORECASE),
    # 크립토 지갑
    re.compile(r"\.config/(Electrum|Exodus|atomic|metamask)/",
               re.IGNORECASE),
    re.compile(r"Library/Application Support/Exodus", re.IGNORECASE),
]

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+)\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ─────────────── 정규화된 이벤트 ───────────────

@dataclass
class ParsedEvent:
    """Source-independent representation."""
    source: str                                       # 'falco' / 'tetragon' / 'wazuh' / 'manual'
    rule_name: str = ""
    host: str | None = None
    package: str | None = None
    ecosystem: str | None = None
    version: str | None = None
    # 행동
    file_paths_read: list[str] = field(default_factory=list)
    file_paths_written: list[str] = field(default_factory=list)
    connect_targets: list[str] = field(default_factory=list)   # "ip:port" 또는 "host:port"
    dns_queries: list[str] = field(default_factory=list)
    exec_commands: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


# ─────────────── 파서 ───────────────

def parse_event(source: str, payload: dict) -> ParsedEvent:
    """일관된 ParsedEvent 로 정규화."""
    s = (source or "").lower()
    if s == "falco":
        return _parse_falco(payload)
    if s == "tetragon":
        return _parse_tetragon(payload)
    if s == "wazuh":
        return _parse_wazuh(payload)
    return _parse_manual(payload)


def _parse_falco(p: dict) -> ParsedEvent:
    """Falco JSON output schema.

    Reference: https://falco.org/docs/outputs/#json-output
    {
      "rule": "...",
      "priority": "Critical",
      "output_fields": {
        "evt.type": "openat" | "connect" | "execve",
        "fd.name": "...",   # for file events
        "fd.sip": "...",    # connect dst ip
        "fd.sport": 443,
        "proc.cmdline": "...",
        "container.id": "...",
        "k8s.pod.name": "...",
      }
    }
    """
    ev = ParsedEvent(source="falco", raw=p)
    ev.rule_name = p.get("rule") or p.get("Rule") or ""
    ev.host = p.get("hostname") or p.get("host")
    of = p.get("output_fields") or p.get("OutputFields") or {}
    pkg = of.get("pkg.name") or p.get("package")
    if pkg:
        ev.package = pkg
        ev.version = of.get("pkg.version") or p.get("version")
        ev.ecosystem = of.get("pkg.ecosystem") or p.get("ecosystem")

    evt_type = (of.get("evt.type") or "").lower()
    if evt_type in ("openat", "open"):
        path = of.get("fd.name")
        if path:
            ev.file_paths_read.append(path)
    elif evt_type == "connect":
        ip = of.get("fd.sip")
        port = of.get("fd.sport")
        if ip:
            ev.connect_targets.append(f"{ip}:{port}" if port else ip)
    elif evt_type == "execve":
        cmd = of.get("proc.cmdline")
        if cmd:
            ev.exec_commands.append(cmd)

    # DNS 룰
    if of.get("dns.name"):
        ev.dns_queries.append(of["dns.name"])
    return ev


def _parse_tetragon(p: dict) -> ParsedEvent:
    """Tetragon process_kprobe 이벤트.

    {
      "process_kprobe": {
        "process": {"binary": "...", "arguments": "...", "pod": {...}},
        "function_name": "security_file_open" | "tcp_connect" | ...,
        "args": [...]
      }
    }
    """
    ev = ParsedEvent(source="tetragon", raw=p)
    pkb = p.get("process_kprobe") or p.get("ProcessKprobe") or {}
    proc = pkb.get("process") or {}
    ev.host = (proc.get("pod") or {}).get("namespace") or proc.get("binary")
    fn = (pkb.get("function_name") or "").lower()
    args = pkb.get("args") or []

    if "open" in fn or "openat" in fn:
        for a in args:
            v = a.get("file_arg") or a.get("string_arg") or a.get("path_arg")
            if v:
                ev.file_paths_read.append(str(v))
    elif "connect" in fn or "tcp" in fn:
        for a in args:
            v = a.get("sock_arg") or a.get("string_arg")
            if v:
                ev.connect_targets.append(str(v))
    elif "exec" in fn:
        cmd = proc.get("arguments") or proc.get("binary")
        if cmd:
            ev.exec_commands.append(str(cmd))

    # 패키지 추적은 Tetragon 환경에서 외부 enrichment 가 보통 필요
    ev.package = p.get("package")
    ev.version = p.get("version")
    ev.ecosystem = p.get("ecosystem")
    return ev


def _parse_wazuh(p: dict) -> ParsedEvent:
    """Wazuh syscheck alert.

    {
      "rule": {"id": "...", "level": 10, "description": "..."},
      "syscheck": {"path": "...", "sha256_after": "...", ...},
      "agent": {"name": "...", "ip": "..."},
      "data": {...}
    }
    """
    ev = ParsedEvent(source="wazuh", raw=p)
    rule = p.get("rule") or {}
    ev.rule_name = rule.get("description") or rule.get("id") or ""
    agent = p.get("agent") or {}
    ev.host = agent.get("name") or agent.get("ip")

    # syscheck → 파일 경로 (write 이벤트 가정)
    syscheck = p.get("syscheck") or {}
    path = syscheck.get("path")
    if path:
        # write 이벤트 표시
        ev.file_paths_written.append(path)

    # 패키지 정보 (Wazuh 에선 일반적으로 환경 enrich 후 set)
    ev.package = p.get("package")
    ev.version = p.get("version")
    ev.ecosystem = p.get("ecosystem")
    return ev


def _parse_manual(p: dict) -> ParsedEvent:
    """수동 alert / 미지원 source — payload 의 정규 필드 그대로 사용."""
    ev = ParsedEvent(source="manual", raw=p)
    ev.rule_name = p.get("rule") or "manual"
    ev.host = p.get("host")
    ev.package = p.get("package")
    ev.version = p.get("version")
    ev.ecosystem = p.get("ecosystem")
    ev.file_paths_read = list(p.get("file_paths_read") or [])
    ev.file_paths_written = list(p.get("file_paths_written") or [])
    ev.connect_targets = list(p.get("connect_targets") or [])
    ev.dns_queries = list(p.get("dns_queries") or [])
    ev.exec_commands = list(p.get("exec_commands") or [])
    return ev


# ─────────────── IOC 추출 ───────────────

def _is_internal_ip(ip: str) -> bool:
    return bool(_INTERNAL_IPS_RE.match(ip))


def _is_trusted_domain(domain: str) -> bool:
    d = domain.lower().strip()
    for trusted in _TRUSTED_REGISTRY_DOMAINS:
        if d == trusted or d.endswith("." + trusted):
            return True
    return False


def _is_sensitive_path(path: str) -> bool:
    for pat in _CRED_PATH_PATTERNS:
        if pat.search(path):
            return True
    return False


def extract_iocs_from_event(ev: ParsedEvent) -> list[dict]:
    """ParsedEvent → IOC dict 리스트.

    각 dict: {"type": str, "value": str, "confidence": float}
    """
    iocs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add(t: str, v: str, conf: float):
        k = (t, v)
        if k in seen:
            return
        seen.add(k)
        iocs.append({"type": t, "value": v, "confidence": conf})

    # 1) 외부 IP (connect 타깃)
    for target in ev.connect_targets:
        ip_match = _IPV4_RE.search(target)
        if ip_match:
            ip = ip_match.group(0)
            if not _is_internal_ip(ip):
                _add("ip", target, 0.7)

    # 2) DNS 도메인
    for q in ev.dns_queries:
        if q and not _is_trusted_domain(q):
            _add("domain", q.lower(), 0.75)
    # connect 타깃이 도메인 형태인 경우
    for target in ev.connect_targets:
        m = _DOMAIN_RE.search(target)
        if m:
            d = m.group(1).lower()
            if not _IPV4_RE.match(d) and not _is_trusted_domain(d):
                _add("domain", d, 0.75)

    # 3) 자격증명 경로 (read 또는 write)
    for path in ev.file_paths_read + ev.file_paths_written:
        if _is_sensitive_path(path):
            _add("path", path, 0.65)

    # 4) sha256 — 이벤트 raw 에 sha256 필드가 있으면 IOC
    raw_text = str(ev.raw)
    for h in _SHA256_RE.findall(raw_text):
        _add("sha256", h.lower(), 0.85)

    # 5) syscall_chain — 의심 시퀀스 (e.g. openat creds + connect external)
    has_cred_read = any(
        _is_sensitive_path(p) for p in ev.file_paths_read
    )
    has_external_net = any(
        not _is_internal_ip(_IPV4_RE.search(t).group(0))
        for t in ev.connect_targets if _IPV4_RE.search(t)
    )
    if has_cred_read and has_external_net:
        _add(
            "syscall_chain",
            "cred_read_then_external_connect",
            0.85,
        )

    return iocs


# ─────────────── 패턴 추출 ───────────────

def extract_pattern_from_event(ev: ParsedEvent) -> dict:
    """이 alert 가 우리 indicator catalog 의 어느 패턴과 매치하는지 요약.

    반환 (dict — JSON 직렬화 가능):
      {
        "dimensions": ["INFORMATION_READING", "DATA_TRANSMISSION", ...],
        "indicator_codes": ["EXF-001", "EXM-008", ...],
        "summary": "creds + external network — likely EXF-001 류",
        "is_novel": bool   # 우리가 정적으로도 잡았을 패턴인지
      }
    """
    dims: list[str] = []
    codes: list[str] = []

    cred_read = any(
        _is_sensitive_path(p) for p in ev.file_paths_read
    )
    if cred_read:
        dims.append("INFORMATION_READING")
        codes.append("EXF-001")  # cred exfiltration 카테고리

    external_net = False
    for target in ev.connect_targets:
        m = _IPV4_RE.search(target)
        if m and not _is_internal_ip(m.group(0)):
            external_net = True
            break
    for q in ev.dns_queries:
        if not _is_trusted_domain(q):
            external_net = True
            break
    if external_net:
        dims.append("DATA_TRANSMISSION")
        codes.append("NET-001")

    if any(p for p in ev.exec_commands):
        dims.append("PAYLOAD_EXECUTION")
        codes.append("EXM-008")

    has_write_sensitive = any(
        _is_sensitive_path(p) for p in ev.file_paths_written
    )
    if has_write_sensitive:
        dims.append("INFORMATION_READING")  # write 도 자격증명 영역이면 사고
        codes.append("EXF-WRITE")

    # 신규 패턴: 기존 정적 indicator 에 *없는* 조합 — runtime-derived 일 가능성
    # 본 v1 에선 단일 신호 조합 → not novel, 다중 신호 조합 → potentially novel
    is_novel = len(set(dims)) >= 2 and not cred_read  # cred_read+net 같은 흔한 조합은 novel X

    summary_parts = []
    if cred_read:
        summary_parts.append("credential read")
    if external_net:
        summary_parts.append("external network")
    if ev.exec_commands:
        summary_parts.append("process exec")
    if has_write_sensitive:
        summary_parts.append("sensitive write")
    summary = " + ".join(summary_parts) or "(no signals)"

    return {
        "dimensions": sorted(set(dims)),
        "indicator_codes": sorted(set(codes)),
        "summary": summary,
        "is_novel": is_novel,
    }
