"""
Stage 2 — Behavior Sequence 추출.

각 Entry File의 AST 를 파싱해 함수 호출 노드를 순서대로 추출.
4 Attack Dimension 카탈로그에 매칭되는 호출만 시퀀스에 포함.

Python: 표준 `ast` 모듈 사용 (tree-sitter 없이 일단 동작).
JavaScript: 정규식 기반 경량 파서 (AST 대신 우선 패턴 매칭; 향후 tree-sitter 교체).
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from ..schema import AttackDimension
from .api_catalog import lookup_python
from .stage1_entry_point import EntryFile, ExtractedPackage

# ─────────────── 데이터 구조 ───────────────

@dataclass
class APICall:
    """코드 한 지점에서 발견된 API 호출."""
    name: str                           # "os.environ.get"
    line: int
    dimension: AttackDimension
    snippet: str                        # 해당 줄 전체 혹은 발췌

    def __repr__(self):
        return f"{self.name}@L{self.line}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "line": self.line,
            "dimension": self.dimension.value,
            "snippet": self.snippet,
        }

    @classmethod
    def from_dict(cls, d: dict) -> APICall:
        return cls(
            name=d["name"],
            line=d["line"],
            dimension=AttackDimension(d["dimension"]),
            snippet=d.get("snippet", ""),
        )


@dataclass
class FileSequence:
    """파일 하나의 순서 보존된 호출 시퀀스."""
    path: str
    language: str
    calls: list[APICall] = field(default_factory=list)
    parse_error: str | None = None

    @property
    def sequence(self) -> list[str]:
        return [c.name for c in self.calls]

    @property
    def dimensions(self) -> list[AttackDimension]:
        seen = []
        for c in self.calls:
            if c.dimension not in seen:
                seen.append(c.dimension)
        return seen

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "language": self.language,
            "calls": [c.to_dict() for c in self.calls],
            "parse_error": self.parse_error,
        }

    @classmethod
    def from_dict(cls, d: dict) -> FileSequence:
        return cls(
            path=d["path"],
            language=d["language"],
            calls=[APICall.from_dict(c) for c in d.get("calls", [])],
            parse_error=d.get("parse_error"),
        )


@dataclass
class BehaviorReport:
    """ExtractedPackage 전체에 대한 Stage 2 결과."""
    files: list[FileSequence] = field(default_factory=list)

    def all_calls(self) -> list[APICall]:
        return [c for f in self.files for c in f.calls]

    def all_sequence(self) -> list[str]:
        return [c.name for c in self.all_calls()]

    def to_dict(self) -> dict:
        """stage_cache 직렬화용. APICall / FileSequence 도 같이 직렬화."""
        return {"files": [f.to_dict() for f in self.files]}

    @classmethod
    def from_dict(cls, d: dict) -> BehaviorReport:
        return cls(files=[FileSequence.from_dict(f) for f in d.get("files", [])])


# ─────────────── Python AST 방문자 ───────────────

class _PyCallVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.calls: list[APICall] = []

    def visit_Call(self, node: ast.Call):
        name = self._resolve_call_name(node.func)
        if name:
            dim = lookup_python(name)
            if dim is not None:
                line = getattr(node, "lineno", 0)
                snippet = self._get_snippet(line)
                self.calls.append(APICall(
                    name=name,
                    line=line,
                    dimension=dim,
                    snippet=snippet,
                ))
        self.generic_visit(node)

    # attr 체인: a.b.c.func → "a.b.c.func"
    def _resolve_call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = self._resolve_call_name(node.value)
            if left is None:
                return node.attr
            return f"{left}.{node.attr}"
        return None

    def _get_snippet(self, line: int) -> str:
        if 0 < line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()
        return ""


def _analyze_python(f: EntryFile) -> FileSequence:
    seq = FileSequence(path=f.path, language="python")
    try:
        tree = ast.parse(f.content, filename=f.path)
    except SyntaxError as e:
        seq.parse_error = f"SyntaxError: {e}"
        return seq

    visitor = _PyCallVisitor(f.content.splitlines())
    visitor.visit(tree)
    seq.calls = visitor.calls
    return seq


# ─────────────── JavaScript 경량 패턴 ───────────────
#
# 정식 tree-sitter 파서는 Phase 후반에 도입.
# 일단은 카탈로그 이름을 소스 텍스트에서 식별하는 수준.

_JS_IDENT = r"[A-Za-z_$][\w$]*"


def _analyze_javascript(f: EntryFile) -> FileSequence:
    """tree-sitter-javascript 기반 AST 분석."""
    try:
        from .js_ast_parser import analyze_entry_js
        return analyze_entry_js(f)
    except Exception as e:
        # fallback: 정규식 기반 (과거 버전)
        seq = FileSequence(path=f.path, language="javascript")
        seq.parse_error = f"AST parse failed, fallback to regex: {e}"
        lines = f.content.splitlines()
        from .api_catalog import JS_APIS

        for api_name in JS_APIS:
            pattern = re.escape(api_name)
            rx = re.compile(r"(?:(?<=^)|(?<=[^A-Za-z0-9_$]))" + pattern)
            for i, line in enumerate(lines, start=1):
                if rx.search(line):
                    dim = JS_APIS[api_name]
                    seq.calls.append(APICall(
                        name=api_name,
                        line=i,
                        dimension=dim,
                        snippet=line.strip()[:200],
                    ))
        seq.calls.sort(key=lambda c: c.line)
        return seq


# ─────────────── 통합 ───────────────

def _analyze_package_json_scripts(f: EntryFile) -> FileSequence:
    """package.json::scripts 가상 파일의 preinstall/postinstall 내용을 스캔."""
    seq = FileSequence(path=f.path, language="shell")
    lines = f.content.splitlines()
    # 쉘 문자열이라 정확한 AST가 없음 → 위험 키워드 직접 매칭
    shell_patterns = {
        "curl": AttackDimension.DATA_TRANSMISSION,
        "wget": AttackDimension.DATA_TRANSMISSION,
        "nc": AttackDimension.DATA_TRANSMISSION,
        "bash": AttackDimension.PAYLOAD_EXECUTION,
        "sh ": AttackDimension.PAYLOAD_EXECUTION,
        "python ": AttackDimension.PAYLOAD_EXECUTION,
        "node ": AttackDimension.PAYLOAD_EXECUTION,
        "eval": AttackDimension.PAYLOAD_EXECUTION,
        "base64": AttackDimension.ENCODING,
    }
    for i, line in enumerate(lines, start=1):
        lower = line.lower()
        for kw, dim in shell_patterns.items():
            if kw in lower:
                seq.calls.append(APICall(
                    name=f"shell:{kw.strip()}",
                    line=i,
                    dimension=dim,
                    snippet=line.strip()[:200],
                ))
    return seq


def analyze(ext: ExtractedPackage) -> BehaviorReport:
    report = BehaviorReport()
    for ef in ext.entry_files:
        if ef.language == "python":
            report.files.append(_analyze_python(ef))
        elif ef.language == "javascript":
            report.files.append(_analyze_javascript(ef))
        elif ef.language == "shell":
            report.files.append(_analyze_package_json_scripts(ef))
        # toml/json 은 Entry point 자체를 스캔 대상에서 제외 (메타정보)
    return report


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    from ..schema import Ecosystem
    from .stage0_registry import check
    from .stage1_entry_point import extract

    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    if not info.found:
        print(f"[{pkg}] not found")
        sys.exit(1)

    v = info.latest_version
    url = info.archive_urls.get(v)
    ext = extract(pkg, eco, v, url)
    if ext.error:
        print(f"extract failed: {ext.error}")
        sys.exit(1)

    report = analyze(ext)
    print(f"\n=== {pkg} {v} ({eco.value}) Behavior Sequence ===")
    for fs in report.files:
        marker = " [parse ERROR]" if fs.parse_error else ""
        print(f"\n▼ {fs.path}{marker}")
        if fs.parse_error:
            print(f"    {fs.parse_error}")
            continue
        if not fs.calls:
            print("    (no suspicious calls)")
            continue
        print(f"    dimensions: {[d.value for d in fs.dimensions]}")
        for c in fs.calls[:30]:
            print(f"    L{c.line:>3}  [{c.dimension.value[:4]}]  {c.name}")
        if len(fs.calls) > 30:
            print(f"    ... and {len(fs.calls) - 30} more")

    total = len(report.all_calls())
    print(f"\nTotal suspicious calls across entry points: {total}")
    all_seq = report.all_sequence()
    if all_seq:
        print(f"Full sequence sample: {' → '.join(all_seq[:10])}")
