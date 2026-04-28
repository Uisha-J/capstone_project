"""
47 Indicator 매처.

Stage 2 의 Behavior Sequence + Stage 1B 의 소스 텍스트를 입력받아
47개 악성 지표 중 어느 것이 매칭되는지 식별.

기존 stage4_rules.py 가 5개 거시 패턴 (T1552, T1048 등) 만 잡았다면,
이 모듈은 더 세밀한 47개 지표 단위로 탐지하고
각각을 Evidence 로 변환할 수 있도록 결과를 제공한다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..schema import AttackDimension, Severity
from ..knowledge.malicious_indicators import (
    INDICATORS,
    IndicatorCategory,
    MaliciousIndicator,
)
from .stage1b_full_source import FullSourceFile
from .stage2_behavior import FileSequence


# ─────────────────── 매칭 결과 ───────────────────

@dataclass
class IndicatorHit:
    indicator: MaliciousIndicator
    file_path: str
    line: int                   # 0 = 파일 단위 (라인 없음)
    snippet: str
    confidence: float           # 0.0~1.0
    reason: str


# ─────────────────── 1) Behavior Sequence 기반 매칭 ───────────────────
# (Stage 2 의 결과를 활용)

def _match_from_sequence(fs: FileSequence) -> list[IndicatorHit]:
    """파일의 API 호출 시퀀스만으로 식별 가능한 지표."""
    if not fs.calls:
        return []
    hits: list[IndicatorHit] = []

    api_names = {c.name for c in fs.calls}
    dims = set(fs.dimensions)
    is_install_hook = any(
        kw in fs.path.lower()
        for kw in ("setup.py", "postinstall", "preinstall")
    )
    is_init_py = fs.path.endswith("__init__.py")

    # EXS-001: import 시 실행
    if is_init_py and len(fs.calls) > 0:
        hits.append(_hit("EXS-001", fs.path, fs.calls[0].line,
                         fs.calls[0].snippet,
                         confidence=0.7,
                         reason="module-level call detected in __init__.py"))

    # EXS-002: 설치 시 실행
    if is_install_hook and len(fs.calls) > 0:
        hits.append(_hit("EXS-002", fs.path, fs.calls[0].line,
                         fs.calls[0].snippet,
                         confidence=0.85,
                         reason="top-level call in install hook file"))

    # EXM-001: dynamic eval/exec
    eval_calls = [c for c in fs.calls if c.name in ("exec", "eval")]
    if eval_calls:
        c = eval_calls[0]
        hits.append(_hit("EXM-001", fs.path, c.line, c.snippet,
                         confidence=0.85,
                         reason=f"{c.name}() detected"))

    # EXM-005: dynamic import
    dyn_imp = [c for c in fs.calls if c.name in ("__import__", "importlib.import_module")]
    if dyn_imp:
        c = dyn_imp[0]
        hits.append(_hit("EXM-005", fs.path, c.line, c.snippet,
                         confidence=0.7,
                         reason="dynamic module import"))

    # EXM-006: pip install at runtime
    if any("pip" in c.snippet and "install" in c.snippet for c in fs.calls):
        c = next(c for c in fs.calls if "pip" in c.snippet and "install" in c.snippet)
        hits.append(_hit("EXM-006", fs.path, c.line, c.snippet,
                         confidence=0.85,
                         reason="runtime pip install detected"))

    # EXM-008: shell command exec
    shell_calls = [
        c for c in fs.calls
        if c.name in ("os.system", "os.popen", "subprocess.run",
                      "subprocess.Popen", "subprocess.call")
    ]
    if shell_calls:
        c = shell_calls[0]
        hits.append(_hit("EXM-008", fs.path, c.line, c.snippet,
                         confidence=0.75,
                         reason="OS shell invocation"))

    # EXF-001: data exfiltration (info read + transmit)
    if (
        AttackDimension.INFORMATION_READING in dims
        and AttackDimension.DATA_TRANSMISSION in dims
    ):
        c = next(c for c in fs.calls
                 if c.dimension == AttackDimension.DATA_TRANSMISSION)
        hits.append(_hit("EXF-001", fs.path, c.line, c.snippet,
                         confidence=0.85,
                         reason="information_reading + data_transmission chain"))

    # SYS-005: system info recon
    recon_apis = {"platform.uname", "platform.system", "socket.gethostname",
                  "getpass.getuser", "os.uname"}
    if api_names & recon_apis:
        c = next(c for c in fs.calls if c.name in recon_apis)
        hits.append(_hit("SYS-005", fs.path, c.line, c.snippet,
                         confidence=0.6,
                         reason="system metadata enumeration"))

    # NET-009: SSL bypass — snippet 단위로 확인
    for c in fs.calls:
        if "verify=False" in c.snippet or "_create_unverified_context" in c.snippet:
            hits.append(_hit("NET-009", fs.path, c.line, c.snippet,
                             confidence=0.8,
                             reason="SSL verification disabled"))
            break

    # NET-010: HTTP unencrypted
    for c in fs.calls:
        if c.dimension == AttackDimension.DATA_TRANSMISSION and "http://" in c.snippet:
            hits.append(_hit("NET-010", fs.path, c.line, c.snippet,
                             confidence=0.6,
                             reason="unencrypted http:// URL"))
            break

    # DEF-003: encoding-based obfuscation
    encoders = {"base64.b64decode", "base64.urlsafe_b64decode",
                "codecs.decode", "bytes.fromhex"}
    if api_names & encoders:
        c = next(c for c in fs.calls if c.name in encoders)
        hits.append(_hit("DEF-003", fs.path, c.line, c.snippet,
                         confidence=0.7,
                         reason="encoding/decoding API used (base64/hex/codecs)"))

    return hits


# ─────────────────── 2) 소스 텍스트 정규식 기반 매칭 ───────────────────

# 카테고리별 정규식 패턴 (보충 매처). 각 매칭마다 IndicatorHit 생성.
_TEXT_PATTERNS: list[tuple[str, str, float, str]] = [
    # (indicator_code, regex, confidence, reason)

    # EXS-003: setuptools cmdclass override
    ("EXS-003",
     r"cmdclass\s*=\s*\{[^}]*['\"](?:install|develop|build_py|egg_info)['\"]",
     0.85,
     "setuptools cmdclass override"),

    # EXM-002: conditional payload trigger by OS / time
    ("EXM-002",
     r"if\s+(?:platform|sys)\.platform\s*[=!]=",
     0.4, "OS conditional check"),
    ("EXM-002",
     r"if\s+platform\.system\s*\(\s*\)\s*[=!]=\s*['\"]",
     0.6, "platform.system() conditional check"),
    ("EXM-002",
     r"if\s+datetime\.(?:datetime\.)?(?:now|today|utcnow)\s*\(\s*\)\s*[<>]",
     0.5, "time-based conditional (datetime trigger)"),

    # EXM-003: ctypes / native dynamic library load
    ("EXM-003",
     r"ctypes\.(?:CDLL|WinDLL|windll)",
     0.7, "native binary loading via ctypes"),
    ("EXM-003",
     r"ctypes\.CFUNCTYPE\s*\([^)]*\)\s*\(\s*ctypes\.addressof",
     0.9,
     "ctypes shellcode execution pattern "
     "(CFUNCTYPE + addressof — direct memory exec)"),
    ("EXM-003",
     r"ctypes\.(?:CFUNCTYPE|cast)\s*\([^)]*\)\s*\([^)]*"
     r"create_string_buffer",
     0.85, "ctypes function pointer over allocated buffer"),

    # EXM-004: hidden execution flags
    ("EXM-004",
     r"creationflags\s*=\s*[A-Z_|0-9]*DETACHED",
     0.8, "subprocess DETACHED_PROCESS flag"),

    # EXM-007: script file execution
    ("EXM-007",
     r"subprocess\.(?:run|Popen|call)\s*\(\s*\[?[\"']?(?:bash|sh|powershell)['\"]?",
     0.8, "explicit shell interpreter invocation"),

    # EXF-003: DNS tunneling
    ("EXF-003",
     r"socket\.gethostbyname\s*\(\s*\w*\+",
     0.7, "DNS query with concatenated payload (string concat)"),
    ("EXF-003",
     r"socket\.gethostbyname\s*\(\s*f[\"'][^\"']*\{[^}]+\}[^\"']*\.[a-z]",
     0.85,
     "DNS query with f-string interpolated payload to external domain"),
    ("EXF-003",
     r"socket\.gethostbyname\s*\(\s*[\"'][^\"']*\{",
     0.6, "DNS query with templated host"),

    # EXF-004: webhook exfil
    ("EXF-004",
     r"discord\.com/api/webhooks/|hooks\.slack\.com/services/|api\.telegram\.org/bot",
     0.95, "chat webhook URL detected"),

    # EXF-005: suspicious domains
    ("EXF-005",
     r"https?://(?:[\w.-]+\.)?(?:pastebin\.com|transfer\.sh|paste\.ee|0x0\.st|file\.io)",
     0.85, "known exfiltration platform"),
    ("EXF-005",
     r"\.onion(?:/|\b)",
     0.95, "tor hidden service URL"),

    # SYS-001: env modification (write)
    ("SYS-001",
     r"os\.environ\s*\[\s*['\"](?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH)['\"]\s*\]\s*=",
     0.85, "environment variable overwrite"),

    # SYS-002: startup persistence
    ("SYS-002",
     r"\.(?:bashrc|zshrc|profile|bash_profile)|HKEY_(?:CURRENT_USER|LOCAL_MACHINE)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|crontab\s+-",
     0.85, "startup/persistence file modification"),

    # SYS-003: crypto wallet harvesting
    ("SYS-003",
     r"\b(?:wallet\.dat|keystore|MetaMask|\.electrum|Exodus|Atomic Wallet)\b",
     0.95, "cryptocurrency wallet path"),

    # SYS-004: directory enumeration
    ("SYS-004",
     r"os\.walk\s*\(\s*['\"]?(?:/|~|\$HOME|C:\\\\)",
     0.6, "filesystem-wide enumeration from root/home"),

    # SYS-007: file deletion (mass)
    ("SYS-007",
     r"shutil\.rmtree\s*\(\s*['\"]?(?:/|~|\$HOME|C:\\\\)",
     0.85, "mass file deletion from root/home"),
    ("SYS-007",
     r"shutil\.rmtree\s*\(\s*os\.path\.expanduser\s*\(\s*['\"]~",
     0.85, "shutil.rmtree on expanded home directory"),
    ("SYS-007",
     r"shutil\.rmtree\s*\(\s*Path\.home\s*\(\s*\)",
     0.85, "shutil.rmtree on Path.home()"),

    # SYS-009: write to sensitive system path
    ("SYS-009",
     r"open\s*\(\s*['\"](?:/etc/|/usr/bin/|/usr/local/bin/|C:\\\\Windows\\\\System32)",
     0.85, "write to sensitive system path"),

    # NET-001: geolocation lookup
    ("NET-001",
     r"\b(?:ipinfo\.io|ip-api\.com|ipify\.org|ifconfig\.me|ipgeolocation)\b",
     0.7, "external IP geolocation API"),

    # NET-002: mining pools
    ("NET-002",
     r"stratum\+tcp://|(?:minexmr|supportxmr|pool\.minexmr)\.com",
     0.95, "cryptocurrency mining pool address"),

    # NET-007: curl|bash style
    ("NET-007",
     r"curl\s+[^|;]*\|\s*(?:bash|sh|python|node)|wget\s+[^|;]*\|\s*(?:bash|sh)",
     0.95, "curl/wget piped to interpreter"),

    # NET-008: reverse shell
    ("NET-008",
     r"(?:/dev/tcp/|os\.dup2\([^)]+,\s*[012]\))",
     0.9, "reverse shell pattern"),

    # DEF-005: embedded string payload + exec
    # exec/eval 인자가 단순 변수 OR base64 디코딩 결과 OR 문자열 연산 결과
    ("DEF-005",
     r"exec\s*\(\s*[a-zA-Z_]\w*\s*\)|Function\s*\(\s*[a-zA-Z_]\w*\s*\)",
     0.7, "exec() called on a variable (likely string payload)"),
    ("DEF-005",
     r"exec\s*\(\s*(?:base64|codecs|bytes|zlib|gzip)\.[a-z_0-9]+\(",
     0.85, "exec() called on decoded payload"),
    ("DEF-005",
     r"eval\s*\(\s*(?:base64|codecs|bytes|zlib|gzip)\.[a-z_0-9]+\(",
     0.85, "eval() called on decoded payload"),

    # NET-009: SSL validation bypass (single-line)
    ("NET-009",
     r"verify\s*=\s*False|_create_unverified_context|rejectUnauthorized\s*[:=]\s*false",
     0.8, "SSL verification disabled"),

    # DEF-006: error suppression
    ("DEF-006",
     r"except\s*(?:[A-Za-z]+\s*)?:\s*pass|2>/dev/null|stderr\s*=\s*subprocess\.DEVNULL",
     0.4, "error suppression pattern"),

    # EXM-005: dynamic import via variable alias (obfuscation)
    # `m = __import__("subprocess")` 형태 — alias 가 위험 모듈 import
    ("EXM-005",
     r"\b\w+\s*=\s*__import__\s*\(\s*[\"'](?:os|subprocess|sys|importlib"
     r"|socket|urllib|ctypes|pty|shutil|pickle|marshal)[\"']\s*\)",
     0.85,
     "dynamic import alias (variable = __import__(<dangerous module>))"),
    ("EXM-005",
     r"\b\w+\s*=\s*importlib\.import_module\s*\(\s*[\"'](?:os|subprocess|"
     r"sys|socket|ctypes|pty)[\"']",
     0.85, "importlib.import_module alias for dangerous module"),

    # EXM-001 보강: file write 안에 exec/subprocess 가 string literal 로
    # 들어가는 self-modifying 패턴
    ("EXM-001",
     r"\.write\s*\(\s*[bf]?[\"'][^\"']*\b(?:exec|eval|subprocess\.run"
     r"|os\.system|importlib\.import_module)\s*\(",
     0.8,
     "exec/subprocess embedded in written-to-file string literal "
     "(self-modifying / dropper pattern)"),
]


def _match_from_text(sf: FullSourceFile) -> list[IndicatorHit]:
    """원본 소스 텍스트에서 정규식 기반 매칭."""
    hits: list[IndicatorHit] = []
    if sf.language not in ("python", "javascript"):
        return hits

    lines = sf.content.splitlines()

    for code, pattern, conf, reason in _TEXT_PATTERNS:
        for i, line in enumerate(lines, start=1):
            try:
                if re.search(pattern, line):
                    hits.append(_hit(
                        code, sf.path, i, line.strip()[:200],
                        confidence=conf, reason=reason,
                    ))
                    break  # 같은 지표 중복 방지 (파일당 1회)
            except re.error:
                continue
    return hits


# ─────────────────── 3) 메타데이터 기반 매칭 ───────────────────

def _match_from_metadata(
    package_name: str,
    description: str,
    author: str,
    declared_deps: list[str],
) -> list[IndicatorHit]:
    """패키지 메타데이터 기반 지표."""
    hits: list[IndicatorHit] = []

    # MET-001: suspicious author
    if author:
        author_lower = author.lower()
        if (
            author_lower in ("test", "anon", "anonymous", "user", "admin", "")
            or "10minutemail" in author_lower
            or "throwaway" in author_lower
        ):
            hits.append(_hit("MET-001", "<metadata>", 0,
                             f"author={author!r}",
                             confidence=0.6,
                             reason=f"placeholder/throwaway author identity"))

    # MET-004: description anomaly
    if description:
        # 설명이 너무 짧음
        if len(description) < 10:
            hits.append(_hit("MET-004", "<metadata>", 0,
                             f"description={description!r}",
                             confidence=0.4,
                             reason="description suspiciously short"))
        # 의미 없는 키워드 스터핑 (단어 길이 평균이 매우 짧거나 길면)
        words = description.split()
        if len(words) > 5:
            avg_len = sum(len(w) for w in words) / len(words)
            if avg_len < 3 or avg_len > 12:
                hits.append(_hit("MET-004", "<metadata>", 0,
                                 description[:120],
                                 confidence=0.3,
                                 reason="description has unusual word-length pattern"))

    # MET-003: suspicious dependencies (description vs deps mismatch)
    # 단순 휴리스틱: parser/format 라이브러리가 subprocess 류 의존하면 의심
    if declared_deps and description:
        desc_lower = description.lower()
        is_parser_like = any(
            kw in desc_lower
            for kw in ("parser", "json", "yaml", "csv", "format", "logger", "color")
        )
        risky_deps = {"subprocess32", "psutil", "pyminizip"}
        if is_parser_like and any(d.lower() in risky_deps for d in declared_deps):
            hits.append(_hit("MET-003", "<metadata>", 0,
                             f"deps={declared_deps}",
                             confidence=0.55,
                             reason="dependencies inconsistent with stated purpose"))

    return hits


# ─────────────────── 헬퍼 ───────────────────

def _hit(code: str, file_path: str, line: int, snippet: str,
         confidence: float, reason: str) -> IndicatorHit:
    ind = INDICATORS[code]
    return IndicatorHit(
        indicator=ind,
        file_path=file_path,
        line=line,
        snippet=snippet,
        confidence=confidence,
        reason=reason,
    )


# ─────────────────── 통합 ───────────────────

@dataclass
class IndicatorMatchReport:
    hits: list[IndicatorHit] = field(default_factory=list)

    @property
    def categories_present(self) -> set[IndicatorCategory]:
        return {h.indicator.category for h in self.hits}

    def by_category(self, cat: IndicatorCategory) -> list[IndicatorHit]:
        return [h for h in self.hits if h.indicator.category == cat]

    @property
    def high_severity_count(self) -> int:
        return sum(1 for h in self.hits if h.indicator.severity == Severity.HIGH)


def match_all(
    behavior_files: list[FileSequence],
    source_files: list[FullSourceFile],
    package_name: str = "",
    description: str = "",
    author: str = "",
    declared_deps: list[str] | None = None,
) -> IndicatorMatchReport:
    report = IndicatorMatchReport()
    declared_deps = declared_deps or []

    # 1. Behavior Sequence 기반
    for fs in behavior_files:
        report.hits.extend(_match_from_sequence(fs))

    # 2. 소스 텍스트 정규식
    for sf in source_files:
        report.hits.extend(_match_from_text(sf))

    # 3. 메타데이터
    report.hits.extend(_match_from_metadata(
        package_name, description, author, declared_deps,
    ))

    # 4. 중복 제거 (같은 indicator + 같은 file 은 confidence 최대만 유지)
    seen: dict[tuple[str, str], IndicatorHit] = {}
    for h in report.hits:
        key = (h.indicator.code, h.file_path)
        if key not in seen or h.confidence > seen[key].confidence:
            seen[key] = h
    report.hits = list(seen.values())

    return report
