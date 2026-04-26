"""
import_parser.py
~~~~~~~~~~~~~~~~
하이브리드 import 파서 — Layer 1: AST (정적), Layer 2: Regex (동적)

지원 언어:
  - Python  (.py)         → AST 우선 + 동적 import 정규식 보완
  - JS / TS (.js .jsx .ts .tsx .mjs .cjs) → 정규식
  - package.json          → JSON 파싱
  - 불명 확장자           → Python AST + JS 정규식 병행
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ── 표준 라이브러리 집합 ───────────────────────────────────────────────────────
# Python 3.10+: sys.stdlib_module_names 사용, 이전 버전은 직접 정의
try:
    STDLIB_MODULES: frozenset[str] = sys.stdlib_module_names  # type: ignore[attr-defined]
except AttributeError:
    STDLIB_MODULES = frozenset({
        "abc", "ast", "asyncio", "base64", "binascii", "builtins", "calendar",
        "cgi", "cgitb", "chunk", "cmd", "code", "codecs", "codeop",
        "collections", "colorsys", "compileall", "concurrent", "configparser",
        "contextlib", "contextvars", "copy", "copyreg", "csv", "ctypes",
        "curses", "dataclasses", "datetime", "dbm", "decimal", "difflib",
        "dis", "doctest", "email", "encodings", "enum", "errno", "faulthandler",
        "fcntl", "filecmp", "fileinput", "fnmatch", "fractions", "ftplib",
        "functools", "gc", "getopt", "getpass", "gettext", "glob", "grp",
        "gzip", "hashlib", "heapq", "hmac", "html", "http", "idlelib",
        "imaplib", "importlib", "inspect", "io", "ipaddress", "itertools",
        "json", "keyword", "lib2to3", "linecache", "locale", "logging",
        "lzma", "mailbox", "math", "mimetypes", "mmap", "modulefinder",
        "multiprocessing", "netrc", "nis", "nntplib", "numbers", "operator",
        "optparse", "os", "ossaudiodev", "pathlib", "pdb", "pickle",
        "pickletools", "pipes", "pkgutil", "platform", "plistlib", "poplib",
        "posix", "posixpath", "pprint", "profile", "pstats", "pty", "pwd",
        "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random", "re",
        "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched",
        "secrets", "select", "selectors", "shelve", "shlex", "shutil",
        "signal", "site", "smtpd", "smtplib", "sndhdr", "socket",
        "socketserver", "spwd", "sqlite3", "sre_compile", "sre_constants",
        "sre_parse", "ssl", "stat", "statistics", "string", "stringprep",
        "struct", "subprocess", "sunau", "symtable", "sys", "sysconfig",
        "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios",
        "test", "textwrap", "threading", "time", "timeit", "tkinter", "token",
        "tokenize", "tomllib", "trace", "traceback", "tracemalloc", "tty",
        "turtle", "turtledemo", "types", "typing", "unicodedata", "unittest",
        "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref",
        "webbrowser", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp",
        "zipfile", "zipimport", "zlib", "zoneinfo",
    })

# ── 결과 모델 ──────────────────────────────────────────────────────────────────
@dataclass
class ParseResult:
    language: str                                               # 탐지된 언어
    parse_method: str                                           # "ast" | "regex" | "hybrid" | "json"
    packages: list[str] = field(default_factory=list)          # 정적 import (AST/JSON)
    dynamic_packages: list[str] = field(default_factory=list)  # 동적 import (Regex)


# ══════════════════════════════════════════════════════════════════════════════
# Layer 1 & 2: Python 파서
# ══════════════════════════════════════════════════════════════════════════════

# 동적 import 패턴 (Layer 2 — Regex)
_PY_DYNAMIC_PATTERNS: list[str] = [
    # importlib.import_module("pkg")
    r"""importlib\.import_module\s*\(\s*['"]([a-zA-Z0-9_\-]+)""",
    # __import__("pkg")
    r"""__import__\s*\(\s*['"]([a-zA-Z0-9_\-]+)""",
    # importlib.util.find_spec("pkg")
    r"""importlib\.util\.find_spec\s*\(\s*['"]([a-zA-Z0-9_\-]+)""",
    # pkg_resources.require("pkg")
    r"""pkg_resources\.require\s*\(\s*['"]([a-zA-Z0-9_\-]+)""",
    # pip.main(["install", "pkg"]) — 런타임 pip 호출
    r"""pip\.main\s*\(\s*\[.*?['"]install['"],\s*['"]([a-zA-Z0-9_\-]+)""",
    # subprocess.run(["pip", "install", "pkg"])
    r"""subprocess\.\w+\s*\(\s*\[.*?['"]install['"],\s*['"]([a-zA-Z0-9_\-]+)""",
]


def parse_python(code: str) -> ParseResult:
    """
    Python 파일 파서.

    Layer 1 (AST): 정적 import / from ... import 완전 탐지
    Layer 2 (Regex): importlib, __import__, subprocess pip 등 동적 패턴 보완
    """
    ast_packages: set[str] = set()
    dynamic_packages: set[str] = set()

    # ── Layer 1: AST ──────────────────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]   # numpy (from numpy.linalg)
                    if top not in STDLIB_MODULES:
                        ast_packages.add(top)

            elif isinstance(node, ast.ImportFrom):
                # level > 0 → 상대 import (from .utils import …) — 스킵
                if node.module and node.level == 0:
                    top = node.module.split(".")[0]  # flask (from flask.ext.sqlalchemy)
                    if top not in STDLIB_MODULES:
                        ast_packages.add(top)

    except SyntaxError:
        # 코드에 문법 오류가 있어도 Layer 2로 최선 탐지
        pass

    # ── Layer 2: Regex (동적 import 보완) ────────────────────────────────────
    for pattern in _PY_DYNAMIC_PATTERNS:
        for match in re.finditer(pattern, code):
            pkg = match.group(1).split(".")[0]
            if pkg not in STDLIB_MODULES and pkg not in ast_packages:
                dynamic_packages.add(pkg)

    method = "hybrid" if dynamic_packages else ("ast" if ast_packages else "regex")
    return ParseResult(
        language="python",
        parse_method=method,
        packages=sorted(ast_packages),
        dynamic_packages=sorted(dynamic_packages),
    )


# ══════════════════════════════════════════════════════════════════════════════
# Layer 2 전용: JavaScript / TypeScript 파서
# ══════════════════════════════════════════════════════════════════════════════

# Node.js 내장 모듈 (필터링 대상)
_NODE_BUILTINS: frozenset[str] = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib",
})

_JS_PATTERNS: list[tuple[str, int]] = [
    # require('package') / require("package")
    (r"""require\s*\(\s*['"]([^./'"@\s][^'"]*?)['"]""",   0),
    # import ... from 'package'
    (r"""from\s+['"]([^./'"@\s][^'"]*?)['"]""",           0),
    # import 'package' (사이드이펙트)
    (r"""^import\s+['"]([^./'"@\s][^'"]*?)['"]""",        re.MULTILINE),
    # dynamic import('package')
    (r"""import\s*\(\s*['"]([^./'"@\s][^'"]*?)['"]""",    0),
    # @scope/pkg 스코프 패키지
    (r"""['"](@[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)""",      0),
]


def _normalise_js_pkg(raw: str) -> str | None:
    """패키지명 정규화: 서브경로 제거, @scope/pkg 유지, 내장 모듈 필터링."""
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("@"):
        parts = raw.split("/")
        return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None
    top = raw.split("/")[0]
    if top in _NODE_BUILTINS or top.startswith("node:"):
        return None
    return top


def parse_javascript(code: str) -> ParseResult:
    """JS / TS 파일 파서 (정규식 기반)."""
    packages: set[str] = set()

    for pattern, flags in _JS_PATTERNS:
        for match in re.finditer(pattern, code, flags):
            pkg = _normalise_js_pkg(match.group(1))
            if pkg:
                packages.add(pkg)

    return ParseResult(
        language="javascript",
        parse_method="regex",
        packages=sorted(packages),
        dynamic_packages=[],
    )


# ══════════════════════════════════════════════════════════════════════════════
# package.json 파서
# ══════════════════════════════════════════════════════════════════════════════

def parse_package_json(code: str) -> ParseResult:
    """package.json 의존성 파서."""
    try:
        data = json.loads(code)
        deps = (
            list(data.get("dependencies", {}).keys())
            + list(data.get("devDependencies", {}).keys())
            + list(data.get("peerDependencies", {}).keys())
        )
        return ParseResult(
            language="package.json",
            parse_method="json",
            packages=sorted(set(deps)),
            dynamic_packages=[],
        )
    except json.JSONDecodeError:
        return ParseResult(language="package.json", parse_method="json")


# ══════════════════════════════════════════════════════════════════════════════
# 진입점 (디스패처)
# ══════════════════════════════════════════════════════════════════════════════

_EXT_TO_LANG: dict[str, str] = {
    ".py":  "python",
    ".js":  "javascript", ".jsx": "javascript",
    ".ts":  "javascript", ".tsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript",
}


def parse_code(filename: str, code: str) -> ParseResult:
    """
    파일명에서 언어를 자동 감지하고 적합한 파서를 호출한다.

    알 수 없는 확장자: Python AST + JS Regex 병행 후 합집합 반환.
    """
    name = Path(filename).name.lower()

    if name == "package.json":
        return parse_package_json(code)

    lang = _EXT_TO_LANG.get(Path(filename).suffix.lower())

    if lang == "python":
        return parse_python(code)
    if lang == "javascript":
        return parse_javascript(code)

    # 확장자 불명 → 두 파서 모두 실행 후 합산
    py_result = parse_python(code)
    js_result = parse_javascript(code)
    merged = sorted(set(py_result.packages + js_result.packages))
    dynamic = sorted(set(py_result.dynamic_packages))

    return ParseResult(
        language="unknown",
        parse_method="hybrid",
        packages=merged,
        dynamic_packages=dynamic,
    )
