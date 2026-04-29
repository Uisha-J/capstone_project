"""
Agentic 자동 판별 — manifest 부재 시 가중치 신호 합산.

근거: detection/AGENTIC-SIGNALS.md
임계치: 합 ≥ 5 → agentic.

신호 종류:
  Strong (3): 패키지명 패턴, description 키워드, agent loop, MCP server, ReAct
  Medium (2): LLM SDK dep, agent framework dep, function calling schema, tool decorator,
              Agent/Tool/Executor import
  Weak (1):   vector store, memory module
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

AGENTIC_THRESHOLD = 5


# ─────────────── 정규식 + 키워드 ───────────────

PACKAGE_NAME_PATTERNS_PY = [
    re.compile(
        r"(^|[-_])(agent|autogpt|crewai|langchain|langgraph|"
        r"llama[-_]?index|autogen|haystack)([-_]|$)",
        re.IGNORECASE,
    ),
    re.compile(r"^mcp-server-", re.IGNORECASE),
    re.compile(r"^mcp-", re.IGNORECASE),
]

PACKAGE_NAME_PATTERNS_JS = [
    re.compile(
        r"(^|[-/])(agent|langchain|llamaindex|crewai|autogen)",
        re.IGNORECASE,
    ),
    re.compile(r"^@modelcontextprotocol/", re.IGNORECASE),
    re.compile(r"^mcp-server-", re.IGNORECASE),
    re.compile(r"-agent$", re.IGNORECASE),
]

DESCRIPTION_KEYWORDS = [
    "ai agent", "llm agent", "autonomous agent",
    "tool use", "tool calling", "function calling",
    "mcp", "model context protocol", "agentic",
    "react", "agent loop",
]

LLM_SDK_DEPS_PY = {
    "openai", "anthropic", "google-generativeai",
    "cohere", "mistralai", "boto3",
}

AGENT_FRAMEWORK_DEPS_PY = {
    "langchain", "langchain-core", "langgraph",
    "llama-index", "llama-index-core",
    "crewai", "autogen-agentchat", "autogen",
    "haystack-ai", "mcp", "openai-agents",
}

LLM_SDK_DEPS_JS = {
    "openai", "@anthropic-ai/sdk",
    "@google/generative-ai", "cohere-ai",
    "@aws-sdk/client-bedrock-runtime",
}

AGENT_FRAMEWORK_DEPS_JS = {
    "langchain", "@langchain/core", "@langchain/langgraph",
    "@langchain/openai", "@langchain/anthropic",
    "llamaindex", "@llamaindex/core",
    "crewai", "@modelcontextprotocol/sdk",
    "ai",  # Vercel AI SDK
}

VECTOR_STORE_PY = {
    "chromadb", "pinecone", "weaviate", "faiss",
    "qdrant-client", "qdrant_client",
}
VECTOR_STORE_JS = {
    "chromadb", "pinecone-client", "@pinecone-database/pinecone",
    "weaviate-client", "@qdrant/js-client-rest",
}

MEMORY_MODULE_HINTS_PY = ["langchain.memory", "llama_index.core.memory"]


# ─────────────── 결과 구조 ───────────────

@dataclass
class SignalReport:
    score: int = 0
    is_agentic: bool = False
    matched: list[str] = field(default_factory=list)

    def add(self, weight: int, label: str):
        self.score += weight
        self.matched.append(f"+{weight} {label}")

    def finalize(self):
        self.is_agentic = self.score >= AGENTIC_THRESHOLD
        return self

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "threshold": AGENTIC_THRESHOLD,
            "is_agentic": self.is_agentic,
            "matched": self.matched,
        }


# ─────────────── Python 분석 ───────────────

def detect_agentic_python(
    *,
    package_name: str = "",
    description: str = "",
    dependencies: list[str] | None = None,
    sources: dict[str, str] | None = None,
) -> SignalReport:
    """
    sources: {file_path: source_code}
    dependencies: 패키지명 (lowercased)
    """
    rep = SignalReport()
    deps = {d.lower() for d in (dependencies or [])}
    sources = sources or {}
    desc_l = (description or "").lower()
    name_l = (package_name or "").lower()

    # Strong: 패키지명
    for pat in PACKAGE_NAME_PATTERNS_PY:
        if pat.search(name_l):
            rep.add(3, f"package-name match: {pat.pattern}")
            break

    # Strong: description 키워드
    if any(kw in desc_l for kw in DESCRIPTION_KEYWORDS):
        rep.add(3, "description keyword (AI agent / MCP / tool calling / ...)")

    # Strong: ReAct prompt template
    if any(_has_react_pattern(s) for s in sources.values()):
        rep.add(3, "ReAct pattern (Thought/Action/Observation tokens)")

    # Strong: MCP server 진입점
    if any(_has_mcp_server_python(s) for s in sources.values()):
        rep.add(3, "MCP server entry-point (mcp.server.Server / FastMCP)")

    # Strong: agent loop (휴리스틱 — LLM call + tool dispatch + loop)
    if any(_has_agent_loop_python(s) for s in sources.values()):
        rep.add(3, "agent loop (LLM call + tool dispatch in while/for)")

    # Medium: LLM SDK
    if deps & LLM_SDK_DEPS_PY:
        rep.add(2, f"LLM SDK dependency: {sorted(deps & LLM_SDK_DEPS_PY)}")

    # Medium: agent framework
    if deps & AGENT_FRAMEWORK_DEPS_PY:
        rep.add(2, f"agent framework dependency: {sorted(deps & AGENT_FRAMEWORK_DEPS_PY)}")

    # Medium: tool decorator
    if any(_has_tool_decorator_python(s) for s in sources.values()):
        rep.add(2, "tool decorator (@tool / @function_tool / @server.call_tool)")

    # Medium: Agent/Tool/Executor import
    if any(_has_agent_class_import_python(s) for s in sources.values()):
        rep.add(2, "Agent/Tool/Executor class import")

    # Medium: function-calling schema
    if any(_has_function_calling_schema(s) for s in sources.values()):
        rep.add(2, "OpenAI tools schema usage")

    # Weak: vector store
    if deps & VECTOR_STORE_PY:
        rep.add(1, f"vector store: {sorted(deps & VECTOR_STORE_PY)}")

    # Weak: memory module import (string match)
    for s in sources.values():
        if any(h in s for h in MEMORY_MODULE_HINTS_PY):
            rep.add(1, "memory module import")
            break

    return rep.finalize()


# ─────────────── JS 분석 ───────────────

def detect_agentic_js(
    *,
    package_name: str = "",
    description: str = "",
    dependencies: list[str] | None = None,
    sources: dict[str, str] | None = None,
) -> SignalReport:
    rep = SignalReport()
    deps = {d.lower() for d in (dependencies or [])}
    sources = sources or {}
    desc_l = (description or "").lower()
    name_l = (package_name or "").lower()

    # Strong: 패키지명
    for pat in PACKAGE_NAME_PATTERNS_JS:
        if pat.search(name_l):
            rep.add(3, f"package-name match: {pat.pattern}")
            break

    # Strong: description 키워드
    if any(kw in desc_l for kw in DESCRIPTION_KEYWORDS):
        rep.add(3, "description keyword")

    # Strong: ReAct
    if any(_has_react_pattern(s) for s in sources.values()):
        rep.add(3, "ReAct pattern")

    # Strong: MCP server
    if any(_has_mcp_server_js(s) for s in sources.values()):
        rep.add(3, "MCP server entry-point (Server / setRequestHandler)")

    # Strong: agent loop
    if any(_has_agent_loop_js(s) for s in sources.values()):
        rep.add(3, "agent loop (await LLM + tool dispatch in loop)")

    # Medium: LLM SDK / agent framework
    if deps & LLM_SDK_DEPS_JS:
        rep.add(2, f"LLM SDK dep: {sorted(deps & LLM_SDK_DEPS_JS)}")
    if deps & AGENT_FRAMEWORK_DEPS_JS:
        rep.add(2, f"agent framework dep: {sorted(deps & AGENT_FRAMEWORK_DEPS_JS)}")

    # Medium: tool definition
    if any(_has_tool_definition_js(s) for s in sources.values()):
        rep.add(2, "tool() / DynamicTool / defineFunction")

    # Medium: function calling schema
    if any(_has_function_calling_schema(s) for s in sources.values()):
        rep.add(2, "function calling schema")

    # Medium: Agent/Tool/Executor import
    if any(_has_agent_class_import_js(s) for s in sources.values()):
        rep.add(2, "Agent/Tool/Executor import")

    # Weak: vector store
    if deps & VECTOR_STORE_JS:
        rep.add(1, f"vector store: {sorted(deps & VECTOR_STORE_JS)}")

    return rep.finalize()


# ─────────────── 휴리스틱 ───────────────

_REACT_RE = re.compile(
    r"(\bThought:\s|\bAction:\s|\bObservation:\s)", re.IGNORECASE,
)


def _has_react_pattern(src: str) -> bool:
    # 3토큰 중 2개 이상 등장하면 react 패턴으로 본다
    matches = set(m.group(1).lower().strip()
                  for m in _REACT_RE.finditer(src))
    return len(matches) >= 2


def _has_mcp_server_python(src: str) -> bool:
    if "from mcp.server import" in src or "from mcp.server" in src:
        return True
    if "FastMCP" in src and "@app.tool" in src:
        return True
    if "@server.list_tools" in src or "@server.call_tool" in src:
        return True
    return False


def _has_mcp_server_js(src: str) -> bool:
    if "@modelcontextprotocol/sdk/server" in src:
        return True
    if "ListToolsRequestSchema" in src and "setRequestHandler" in src:
        return True
    return False


_LLM_CALL_RE_PY = re.compile(
    r"(?:openai\.|anthropic\.|llm\.|model\.)"
    r"(?:invoke|chat\s*\.\s*completions|messages\s*\.\s*create"
    r"|generate_content|complete|chat)"
)
_TOOL_DISPATCH_RE_PY = re.compile(
    r"(?:tool\s*\.\s*invoke|tool\s*\.\s*run|tools\[.*?\]"
    r"|globals\(\)\[.*?\]|getattr\(.*?,\s*tool_name\)"
    r"|Tool\.from_function|@tool\b|@function_tool\b)"
)


def _has_agent_loop_python(src: str) -> bool:
    """단순 휴리스틱: while/for 키워드 + 같은 파일에 LLM call + tool dispatch."""
    if "while " not in src and "for " not in src:
        return False
    has_llm = bool(_LLM_CALL_RE_PY.search(src))
    has_disp = bool(_TOOL_DISPATCH_RE_PY.search(src))
    return has_llm and has_disp


_LLM_CALL_RE_JS = re.compile(
    r"(?:client\.|model\.|llm\.|chat\.)"
    r"(?:completions\.create|messages\.create|invoke|generateText"
    r"|streamText|generateContent)"
)
_TOOL_DISPATCH_RE_JS = re.compile(
    r"(?:tools\s*:\s*\[|new\s+DynamicTool|tool\s*\(|callTool"
    r"|invokeTool|toolCalls|maxSteps)"
)


def _has_agent_loop_js(src: str) -> bool:
    if "while" not in src and "for" not in src:
        return False
    has_llm = bool(_LLM_CALL_RE_JS.search(src))
    has_disp = bool(_TOOL_DISPATCH_RE_JS.search(src))
    return has_llm and has_disp


def _has_tool_decorator_python(src: str) -> bool:
    return bool(re.search(
        r"@(?:tool|function_tool|server\.call_tool|server\.list_tools|app\.tool)\b",
        src,
    ))


def _has_tool_definition_js(src: str) -> bool:
    if "new DynamicTool" in src:
        return True
    if re.search(r"\btool\s*\(\s*\{", src):
        return True
    if re.search(r"\bdefineFunction\s*\(", src):
        return True
    return False


def _has_agent_class_import_python(src: str) -> bool:
    patterns = [
        r"from\s+langchain[._\w]*\s+import\s+.*\b(AgentExecutor|Agent|Tool)\b",
        r"from\s+langchain_core\.tools\s+import\s+Tool",
        r"from\s+llama_index[._\w]*\s+import\s+.*\b(ReActAgent|Agent)\b",
        r"from\s+crewai\s+import\s+.*\b(Agent|Crew|Task)\b",
        r"from\s+autogen[._\w]*\s+import",
    ]
    return any(re.search(p, src) for p in patterns)


def _has_agent_class_import_js(src: str) -> bool:
    patterns = [
        r"from\s+['\"]langchain/agents['\"]",
        r"from\s+['\"]@langchain/[\w-]+['\"]",
        r"from\s+['\"]llamaindex['\"]",
        r"from\s+['\"]crewai['\"]",
        r"\bAgentExecutor\b|\bDynamicTool\b",
    ]
    return any(re.search(p, src) for p in patterns)


def _has_function_calling_schema(src: str) -> bool:
    """OpenAI tools=[{type:'function', function:{...}}] 패턴."""
    if re.search(
        r"['\"]type['\"]\s*:\s*['\"]function['\"].*?['\"]function['\"]\s*:",
        src, re.DOTALL,
    ):
        return True
    if re.search(r"tools\s*=\s*\[\s*\{", src):
        return True
    return False
