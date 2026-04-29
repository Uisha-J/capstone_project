"""
Capability detector — detection/CAPABILITY-DETECTION.md 매핑 구현.

15개 canonical capability 어휘:
  filesystem-read, filesystem-write, shell, network, env-secrets,
  code-exec, credential-paths, db-access, mcp-client, mcp-server,
  llm-call, tool-loop, memory-persistent, dynamic-tool-load, agent-to-agent

본 모듈은 정적 분석으로 detected capability set 을 추출.
정확도보다 재현율 (recall) 우선 — false positive 가 일부 있어도 OK.
"""
from __future__ import annotations

import ast
import re

# ─────────────── 어휘 ───────────────

class Capability(str):
    FS_READ          = "filesystem-read"
    FS_WRITE         = "filesystem-write"
    SHELL            = "shell"
    NETWORK          = "network"
    ENV_SECRETS      = "env-secrets"
    CODE_EXEC        = "code-exec"
    CREDENTIAL_PATHS = "credential-paths"
    DB_ACCESS        = "db-access"
    MCP_CLIENT       = "mcp-client"
    MCP_SERVER       = "mcp-server"
    LLM_CALL         = "llm-call"
    TOOL_LOOP        = "tool-loop"
    MEMORY_PERSIST   = "memory-persistent"
    DYNAMIC_TOOL_LOAD = "dynamic-tool-load"
    AGENT_TO_AGENT   = "agent-to-agent"


CAPABILITIES = [
    Capability.FS_READ, Capability.FS_WRITE, Capability.SHELL,
    Capability.NETWORK, Capability.ENV_SECRETS, Capability.CODE_EXEC,
    Capability.CREDENTIAL_PATHS, Capability.DB_ACCESS,
    Capability.MCP_CLIENT, Capability.MCP_SERVER, Capability.LLM_CALL,
    Capability.TOOL_LOOP, Capability.MEMORY_PERSIST,
    Capability.DYNAMIC_TOOL_LOAD, Capability.AGENT_TO_AGENT,
]


# ─────────────── credential paths regex ───────────────

CREDENTIAL_PATH_RE = re.compile(
    r"(~/\.ssh/|~/\.aws/|~/\.gnupg/|~/\.config/gcloud/|~/\.kube/|"
    r"~/\.docker/config\.json|~/\.netrc|"
    r"\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|"
    r"\.pem(?:[\"']|$)|\.key(?:[\"']|$)|\.p12(?:[\"']|$)|\.pfx(?:[\"']|$)|"
    r"\.env(?:[.\"']|$)|"
    r"credentials\.json|service[-_]account[-_]?key)"
)


# ─────────────── Python AST 검출 ───────────────

# api dotted name → capability
_PY_CAPABILITY_MAP: list[tuple[str, str]] = [
    # filesystem
    ("os.scandir", Capability.FS_READ),
    ("os.listdir", Capability.FS_READ),
    ("os.walk", Capability.FS_READ),
    ("os.remove", Capability.FS_WRITE),
    ("os.unlink", Capability.FS_WRITE),
    ("os.rmdir", Capability.FS_WRITE),
    ("os.rename", Capability.FS_WRITE),
    ("os.replace", Capability.FS_WRITE),
    ("os.makedirs", Capability.FS_WRITE),
    ("os.mkdir", Capability.FS_WRITE),
    ("os.chmod", Capability.FS_WRITE),
    ("os.chown", Capability.FS_WRITE),
    ("shutil.copy", Capability.FS_WRITE),
    ("shutil.copy2", Capability.FS_WRITE),
    ("shutil.copyfile", Capability.FS_WRITE),
    ("shutil.copytree", Capability.FS_WRITE),
    ("shutil.move", Capability.FS_WRITE),
    ("shutil.rmtree", Capability.FS_WRITE),
    ("glob.glob", Capability.FS_READ),
    ("glob.iglob", Capability.FS_READ),
    # shell
    ("subprocess.run", Capability.SHELL),
    ("subprocess.Popen", Capability.SHELL),
    ("subprocess.call", Capability.SHELL),
    ("subprocess.check_call", Capability.SHELL),
    ("subprocess.check_output", Capability.SHELL),
    ("subprocess.getoutput", Capability.SHELL),
    ("os.system", Capability.SHELL),
    ("os.popen", Capability.SHELL),
    ("pty.spawn", Capability.SHELL),
    ("pty.fork", Capability.SHELL),
    ("asyncio.create_subprocess_exec", Capability.SHELL),
    ("asyncio.create_subprocess_shell", Capability.SHELL),
    # network
    ("requests.get", Capability.NETWORK),
    ("requests.post", Capability.NETWORK),
    ("requests.put", Capability.NETWORK),
    ("requests.patch", Capability.NETWORK),
    ("requests.delete", Capability.NETWORK),
    ("requests.head", Capability.NETWORK),
    ("requests.request", Capability.NETWORK),
    ("httpx.get", Capability.NETWORK),
    ("httpx.post", Capability.NETWORK),
    ("httpx.put", Capability.NETWORK),
    ("httpx.AsyncClient", Capability.NETWORK),
    ("urllib.request.urlopen", Capability.NETWORK),
    ("urllib.request.Request", Capability.NETWORK),
    ("aiohttp.ClientSession", Capability.NETWORK),
    ("socket.socket", Capability.NETWORK),
    ("socket.create_connection", Capability.NETWORK),
    ("http.client.HTTPConnection", Capability.NETWORK),
    ("http.client.HTTPSConnection", Capability.NETWORK),
    ("websockets.connect", Capability.NETWORK),
    ("smtplib.SMTP", Capability.NETWORK),
    ("smtplib.SMTP_SSL", Capability.NETWORK),
    # env
    ("os.environ", Capability.ENV_SECRETS),
    ("os.getenv", Capability.ENV_SECRETS),
    ("dotenv.load_dotenv", Capability.ENV_SECRETS),
    # code exec
    ("exec", Capability.CODE_EXEC),
    ("eval", Capability.CODE_EXEC),
    ("compile", Capability.CODE_EXEC),
    ("__import__", Capability.CODE_EXEC),
    ("importlib.import_module", Capability.CODE_EXEC),
    ("marshal.loads", Capability.CODE_EXEC),
    ("pickle.loads", Capability.CODE_EXEC),
    ("yaml.load", Capability.CODE_EXEC),
    # db
    ("psycopg2.connect", Capability.DB_ACCESS),
    ("psycopg.connect", Capability.DB_ACCESS),
    ("pymysql.connect", Capability.DB_ACCESS),
    ("mysql.connector.connect", Capability.DB_ACCESS),
    ("sqlalchemy.create_engine", Capability.DB_ACCESS),
    ("redis.Redis", Capability.DB_ACCESS),
    ("redis.StrictRedis", Capability.DB_ACCESS),
    ("aioredis.Redis", Capability.DB_ACCESS),
    ("pymongo.MongoClient", Capability.DB_ACCESS),
    ("motor.motor_asyncio.AsyncIOMotorClient", Capability.DB_ACCESS),
    ("cassandra.cluster.Cluster", Capability.DB_ACCESS),
    ("clickhouse_driver.Client", Capability.DB_ACCESS),
    ("duckdb.connect", Capability.DB_ACCESS),
    ("sqlite3.connect", Capability.DB_ACCESS),
    # llm
    ("openai.ChatCompletion.create", Capability.LLM_CALL),
    ("openai.OpenAI", Capability.LLM_CALL),
    ("anthropic.Anthropic", Capability.LLM_CALL),
    ("google.generativeai.GenerativeModel", Capability.LLM_CALL),
    ("cohere.Client", Capability.LLM_CALL),
    ("mistralai.client.MistralClient", Capability.LLM_CALL),
]


# import path 시그니처 (substring 매칭)
_PY_IMPORT_SIGNATURES: list[tuple[str, str]] = [
    ("from mcp.client", Capability.MCP_CLIENT),
    ("import mcp.client", Capability.MCP_CLIENT),
    ("ClientSession", Capability.MCP_CLIENT),  # 보조
    ("from mcp.server", Capability.MCP_SERVER),
    ("import mcp.server", Capability.MCP_SERVER),
    ("FastMCP", Capability.MCP_SERVER),
    ("@server.list_tools", Capability.MCP_SERVER),
    ("@server.call_tool", Capability.MCP_SERVER),
    ("from langchain", Capability.LLM_CALL),
    ("from openai", Capability.LLM_CALL),
    ("from anthropic", Capability.LLM_CALL),
    ("import openai", Capability.LLM_CALL),
    ("import anthropic", Capability.LLM_CALL),
    ("import langchain", Capability.LLM_CALL),
    ("import cohere", Capability.LLM_CALL),
    ("import mistralai", Capability.LLM_CALL),
    ("from langchain.memory", Capability.MEMORY_PERSIST),
    ("from llama_index.core.memory", Capability.MEMORY_PERSIST),
    ("chromadb.Collection", Capability.MEMORY_PERSIST),
    ("pinecone.Index", Capability.MEMORY_PERSIST),
    ("from crewai", Capability.AGENT_TO_AGENT),
    ("from autogen", Capability.AGENT_TO_AGENT),
    ("GroupChat", Capability.AGENT_TO_AGENT),
    ("crew.delegate", Capability.AGENT_TO_AGENT),
]


_PY_IMPORT_REGEX_SIGNATURES: list[tuple[re.Pattern, str]] = [
    # comma-list import 도 매칭: "import os, openai" 같은 형태
    (re.compile(r"^\s*(?:from|import)\s+[\w.,\s]*\bopenai\b", re.MULTILINE),
     Capability.LLM_CALL),
    (re.compile(r"^\s*(?:from|import)\s+[\w.,\s]*\banthropic\b", re.MULTILINE),
     Capability.LLM_CALL),
    (re.compile(r"^\s*(?:from|import)\s+[\w.,\s]*\bcohere\b", re.MULTILINE),
     Capability.LLM_CALL),
    (re.compile(r"^\s*(?:from|import)\s+[\w.,\s]*\bmistralai\b", re.MULTILINE),
     Capability.LLM_CALL),
    (re.compile(r"^\s*(?:from|import)\s+[\w.,\s]*\blangchain", re.MULTILINE),
     Capability.LLM_CALL),
]


def extract_capabilities_python(sources: dict[str, str]) -> set[str]:
    """{file_path: source_code} → detected capability set."""
    found: set[str] = set()

    for path, src in sources.items():
        # AST 기반 호출 매칭
        try:
            tree = ast.parse(src)
            visitor = _PyCapVisitor()
            visitor.visit(tree)
            found.update(visitor.found)
        except SyntaxError:
            pass

        # import / 문자열 패턴 보조 (substring)
        for sig, cap in _PY_IMPORT_SIGNATURES:
            if sig in src:
                found.add(cap)

        # comma-list 등 정규식 보강
        for pat, cap in _PY_IMPORT_REGEX_SIGNATURES:
            if pat.search(src):
                found.add(cap)

        # credential paths
        if CREDENTIAL_PATH_RE.search(src):
            found.add(Capability.CREDENTIAL_PATHS)

        # tool_loop heuristic
        if _is_tool_loop_python(src):
            found.add(Capability.TOOL_LOOP)

        # dynamic-tool-load
        if _is_dynamic_tool_load_python(src):
            found.add(Capability.DYNAMIC_TOOL_LOAD)

    return found


class _PyCapVisitor(ast.NodeVisitor):
    """Python AST 방문자 — 호출 기반 capability 추출."""

    def __init__(self):
        self.found: set[str] = set()

    def visit_Call(self, node: ast.Call):
        name = _resolve_dotted(node.func)
        if name:
            for sig, cap in _PY_CAPABILITY_MAP:
                if name == sig or name.endswith("." + sig.split(".")[-1]) and name.startswith(
                    sig.rsplit(".", 1)[0]
                ):
                    self.found.add(cap)
            # open() 의 mode kwarg 검사
            if name == "open":
                self._check_open_mode(node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # `os.environ`, `process.env` 같은 변수 접근 (호출 아닌)
        name = _resolve_dotted(node)
        if name == "os.environ":
            self.found.add(Capability.ENV_SECRETS)
        self.generic_visit(node)

    def _check_open_mode(self, node: ast.Call):
        mode = None
        # positional 두 번째 인자
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value
        # keyword
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
        if isinstance(mode, str):
            if any(c in mode for c in "wax"):
                self.found.add(Capability.FS_WRITE)
            else:
                self.found.add(Capability.FS_READ)
        else:
            # mode 미지정 = read
            self.found.add(Capability.FS_READ)


def _resolve_dotted(node) -> str | None:
    """ast.Name / ast.Attribute → 'a.b.c'. 그 외 None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_dotted(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


_TOOL_LOOP_HINT_RE = re.compile(
    r"(while\s+True|while\s+\w+|for\s+\w+\s+in)"
    r"[\s\S]{0,500}"
    r"(invoke|chat\.completions|messages\.create|generate_content|complete\(|chat\()"
    r"[\s\S]{0,500}"
    r"(tool|tools\[|callTool|getattr|globals\(\)|dispatch)"
)


def _is_tool_loop_python(src: str) -> bool:
    return bool(_TOOL_LOOP_HINT_RE.search(src))


def _is_dynamic_tool_load_python(src: str) -> bool:
    # tool description 을 외부에서 fetch
    patterns = [
        r"requests\.get\([^)]*\)\s*\.json\(\)",
        r"\.bind_tools\(\s*[^)]*remote",
        r"agent\.tools\s*\.\s*append",
        r"agent\.tools\s*\.\s*extend",
        r"session\.list_tools\(\)",
    ]
    return any(re.search(p, src) for p in patterns)


# ─────────────── JS / TS 검출 (정규식 위주 — 가벼운 처리) ───────────────

_JS_CAPABILITY_PATTERNS: list[tuple[re.Pattern, str]] = [
    # filesystem
    (re.compile(r"\bfs\.readFile(?:Sync)?\b"), Capability.FS_READ),
    (re.compile(r"\bfs\.readdir(?:Sync)?\b"), Capability.FS_READ),
    (re.compile(r"\bfs\.createReadStream\b"), Capability.FS_READ),
    (re.compile(r"\bfsPromises\.readFile\b"), Capability.FS_READ),
    (re.compile(r"\bfs\.writeFile(?:Sync)?\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.appendFile(?:Sync)?\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.createWriteStream\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.unlink(?:Sync)?\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.rm(?:dir)?(?:Sync)?\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.rename(?:Sync)?\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.copyFile(?:Sync)?\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.mkdir(?:Sync)?\b"), Capability.FS_WRITE),
    (re.compile(r"\bfs\.chmod(?:Sync)?\b"), Capability.FS_WRITE),
    # shell
    (re.compile(r"\bchild_process\.exec(?:File)?(?:Sync)?\b"), Capability.SHELL),
    (re.compile(r"\bchild_process\.spawn(?:Sync)?\b"), Capability.SHELL),
    (re.compile(r"\bchild_process\.fork\b"), Capability.SHELL),
    (re.compile(r"\bexeca\("), Capability.SHELL),
    (re.compile(r"\bshelljs\.exec\b"), Capability.SHELL),
    (re.compile(r"\bBun\.spawn\b"), Capability.SHELL),
    # network
    (re.compile(r"\bfetch\("), Capability.NETWORK),
    (re.compile(r"\baxios\.(get|post|put|delete|patch|head)\b"), Capability.NETWORK),
    (re.compile(r"\baxios\("), Capability.NETWORK),
    (re.compile(r"\bhttps?\.request\b"), Capability.NETWORK),
    (re.compile(r"\bgot\("), Capability.NETWORK),
    (re.compile(r"\bnode-fetch\b"), Capability.NETWORK),
    (re.compile(r"\bundici\.(fetch|request)\b"), Capability.NETWORK),
    (re.compile(r"\bnet\.Socket\b"), Capability.NETWORK),
    (re.compile(r"\bnet\.createConnection\b"), Capability.NETWORK),
    (re.compile(r"\bnodemailer\.createTransport\b"), Capability.NETWORK),
    # env
    (re.compile(r"\bprocess\.env\b"), Capability.ENV_SECRETS),
    (re.compile(r"\bdotenv\.config\("), Capability.ENV_SECRETS),
    # code-exec
    (re.compile(r"\beval\("), Capability.CODE_EXEC),
    (re.compile(r"\bnew\s+Function\("), Capability.CODE_EXEC),
    (re.compile(r"\bvm\.runIn(?:NewContext|ThisContext|Context)\b"), Capability.CODE_EXEC),
    (re.compile(r"\bvm2\.NodeVM\b"), Capability.CODE_EXEC),
    # db
    (re.compile(r"['\"]pg['\"]"), Capability.DB_ACCESS),
    (re.compile(r"['\"]mysql2?['\"]"), Capability.DB_ACCESS),
    (re.compile(r"['\"]mongodb['\"]"), Capability.DB_ACCESS),
    (re.compile(r"['\"]ioredis['\"]"), Capability.DB_ACCESS),
    (re.compile(r"['\"]@prisma/client['\"]"), Capability.DB_ACCESS),
    # MCP
    (re.compile(r"@modelcontextprotocol/sdk/client"), Capability.MCP_CLIENT),
    (re.compile(r"@modelcontextprotocol/sdk/server"), Capability.MCP_SERVER),
    (re.compile(r"setRequestHandler\(.*ListToolsRequestSchema"),
     Capability.MCP_SERVER),
    # llm
    (re.compile(r"['\"]openai['\"]"), Capability.LLM_CALL),
    (re.compile(r"@anthropic-ai/sdk"), Capability.LLM_CALL),
    (re.compile(r"@google/generative-ai"), Capability.LLM_CALL),
    (re.compile(r"['\"]cohere-ai['\"]"), Capability.LLM_CALL),
    (re.compile(r"\bgenerateText\("), Capability.LLM_CALL),
    (re.compile(r"\bstreamText\("), Capability.LLM_CALL),
    (re.compile(r"\bgenerateObject\("), Capability.LLM_CALL),
    # memory
    (re.compile(r"@pinecone-database/pinecone"), Capability.MEMORY_PERSIST),
    (re.compile(r"['\"]chromadb['\"]"), Capability.MEMORY_PERSIST),
    (re.compile(r"@qdrant/js-client-rest"), Capability.MEMORY_PERSIST),
]


def extract_capabilities_js(sources: dict[str, str]) -> set[str]:
    found: set[str] = set()
    for path, src in sources.items():
        for pat, cap in _JS_CAPABILITY_PATTERNS:
            if pat.search(src):
                found.add(cap)
        if CREDENTIAL_PATH_RE.search(src):
            found.add(Capability.CREDENTIAL_PATHS)
        # 휴리스틱
        if _is_tool_loop_js(src):
            found.add(Capability.TOOL_LOOP)
        if _is_dynamic_tool_load_js(src):
            found.add(Capability.DYNAMIC_TOOL_LOAD)
        if _is_a2a_js(src):
            found.add(Capability.AGENT_TO_AGENT)
    return found


def _is_tool_loop_js(src: str) -> bool:
    if "while" not in src and "for" not in src:
        return False
    return bool(re.search(
        r"(?:client|llm|model)\.[a-z]*(?:create|invoke|generate)"
        r"[\s\S]{0,600}"
        r"(?:tools?:\s*\[|callTool|toolCalls)",
        src,
    ))


def _is_dynamic_tool_load_js(src: str) -> bool:
    patterns = [
        r"await\s+fetch\s*\([^)]*\)\s*\.then\s*\(\s*r\s*=>\s*r\.json\(\)\s*\)",
        r"agent\.tools\s*=\s*\[",
        r"client\.listTools\s*\(",
    ]
    return any(re.search(p, src) for p in patterns)


def _is_a2a_js(src: str) -> bool:
    patterns = [
        r"['\"]crewai['\"]",
        r"GroupChat",
        r"agent\.send\s*\(",
    ]
    return any(re.search(p, src) for p in patterns)


# ─────────────── ABC 매핑 (Rule of Two) ───────────────

# capability → ABC set
_ABC_MAP: dict[str, set[str]] = {
    Capability.FS_READ:           {"A", "B"},   # 외부 입력 + 홈 디렉터리
    Capability.FS_WRITE:          {"C"},
    Capability.SHELL:             {"C"},
    Capability.NETWORK:           {"A", "C"},   # 양방향
    Capability.ENV_SECRETS:       {"B"},
    Capability.CODE_EXEC:         {"C"},
    Capability.CREDENTIAL_PATHS:  {"B"},
    Capability.DB_ACCESS:         {"A", "B", "C"},
    Capability.MCP_CLIENT:        {"A", "C"},
    Capability.MCP_SERVER:        {"A", "C"},
    Capability.LLM_CALL:          {"A"},
    Capability.TOOL_LOOP:         set(),  # 자체로는 ABC 없음
    Capability.MEMORY_PERSIST:    {"B", "C"},
    Capability.DYNAMIC_TOOL_LOAD: {"A"},
    Capability.AGENT_TO_AGENT:    {"A", "C"},
}


def map_to_abc(detected: set[str]) -> set[str]:
    """detected capability set → {A, B, C} subset."""
    out: set[str] = set()
    for c in detected:
        out |= _ABC_MAP.get(c, set())
    return out
