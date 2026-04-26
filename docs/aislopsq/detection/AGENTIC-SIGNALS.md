# Agentic 자동 판별 신호

manifest가 부재한 패키지에 대해 정적 분석으로 agentic 여부를 판정하는 신호 가중치 표.

근거: Chhabra et al., arXiv:2510.23883 — agentic 시스템의 4요소(planning + tool use + memory + autonomy) 중 **tool use + autonomy** 시그니처가 가장 식별력이 높음.

---

## 판정 기준

신호별 가중치 합계가 **5 이상**이면 agentic으로 분류.

5 임계치는 false positive를 줄이기 위한 권장 값이며, 실제 운영 데이터로 조정 필요.

---

## 신호 표 (Python / PyPI)

| 신호 | 가중치 | 검출 방법 |
|---|---|---|
| **Strong (가중치 3)** | | |
| 패키지명 패턴 | 3 | regex: `(^|[-_])(agent\|autogpt\|crewai\|langchain\|langgraph\|llama-index\|autogen\|haystack)([-_]\|$)`, `^mcp-server-`, `^mcp-` |
| description 키워드 | 3 | description/long_description에 다음 중 1개 이상: `AI agent`, `LLM agent`, `autonomous agent`, `tool use`, `tool calling`, `function calling`, `MCP`, `Model Context Protocol`, `agentic` |
| Agent loop 패턴 | 3 | AST 검출: `while`/`for` 루프 안에서 LLM SDK 호출 + tool dispatch + 결과 피드백 시퀀스 |
| MCP server 진입점 | 3 | `from mcp.server import Server`, `@server.list_tools()`, `@server.call_tool()` |
| ReAct 패턴 | 3 | "Thought:", "Action:", "Observation:" 토큰을 prompt template에 사용 |
| **Medium (가중치 2)** | | |
| LLM SDK 의존성 | 2 | `install_requires` 또는 `dependencies` 에 `openai`, `anthropic`, `google-generativeai`, `cohere`, `mistralai` 중 1개 이상 |
| Agent framework 의존성 | 2 | `langchain`, `langchain-core`, `langgraph`, `llama-index-core`, `crewai`, `autogen-agentchat`, `haystack-ai`, `mcp` |
| Function calling schema | 2 | OpenAI tools schema 사용: `tools=[{"type": "function", "function": {...}}]` 패턴 |
| Tool decorator 사용 | 2 | `@tool`, `@function_tool`, `@server.call_tool` decorator |
| Agent/Tool/Executor 클래스 import | 2 | `from langchain.agents import AgentExecutor`, `from langchain_core.tools import Tool`, `from llama_index.core.agent import ReActAgent` |
| **Weak (가중치 1)** | | |
| Vector store 사용 | 1 | `chromadb`, `pinecone`, `weaviate`, `faiss`, `qdrant-client` |
| 메모리 모듈 import | 1 | `langchain.memory`, `llama_index.core.memory` |

### Python 검출 정규식 모음

```python
PACKAGE_NAME_PATTERNS = [
    r"(^|[-_])(agent|autogpt|crewai|langchain|langgraph|"
    r"llama[-_]?index|autogen|haystack)([-_]|$)",
    r"^mcp-server-",
    r"^mcp-",
]

DESCRIPTION_KEYWORDS = [
    "AI agent", "LLM agent", "autonomous agent",
    "tool use", "tool calling", "function calling",
    "MCP", "Model Context Protocol", "agentic",
    "ReAct", "agent loop"
]

LLM_SDK_DEPS = {
    "openai", "anthropic", "google-generativeai",
    "cohere", "mistralai", "boto3"  # bedrock 사용 시
}

AGENT_FRAMEWORK_DEPS = {
    "langchain", "langchain-core", "langgraph",
    "llama-index", "llama-index-core",
    "crewai", "autogen-agentchat", "autogen",
    "haystack-ai", "mcp", "openai-agents"
}
```

---

## 신호 표 (JavaScript/TypeScript / npm)

| 신호 | 가중치 | 검출 방법 |
|---|---|---|
| **Strong (가중치 3)** | | |
| 패키지명 패턴 | 3 | regex: `(^|[-/])(agent\|langchain\|llamaindex\|crewai\|autogen)`, `^@modelcontextprotocol/`, `^mcp-server-`, `-agent$` |
| description 키워드 | 3 | (Python과 동일) |
| Agent loop 패턴 | 3 | (Python과 동일) |
| MCP server 진입점 | 3 | `import { Server } from "@modelcontextprotocol/sdk/server/index.js"`, `server.setRequestHandler(ListToolsRequestSchema, ...)` |
| ReAct 패턴 | 3 | (Python과 동일) |
| **Medium (가중치 2)** | | |
| LLM SDK 의존성 | 2 | `dependencies` 에 `openai`, `@anthropic-ai/sdk`, `@google/generative-ai`, `cohere-ai` 중 1개 이상 |
| Agent framework 의존성 | 2 | `langchain`, `@langchain/core`, `@langchain/langgraph`, `llamaindex`, `crewai`, `@modelcontextprotocol/sdk` |
| Function calling schema | 2 | `tools: [{ type: "function", function: { ... } }]` 패턴 |
| Tool 정의 패턴 | 2 | `new DynamicTool(...)`, `tool({ ... })`, `defineFunction` 호출 |
| Agent/Tool/Executor import | 2 | `import { AgentExecutor } from "langchain/agents"`, `import { Tool } from "@langchain/core/tools"` |
| **Weak (가중치 1)** | | |
| Vector store 사용 | 1 | `chromadb`, `pinecone-client`, `weaviate-client`, `qdrant-js` |

### JS 검출 정규식 모음

```javascript
const PACKAGE_NAME_PATTERNS = [
    /(^|[-/])(agent|langchain|llamaindex|crewai|autogen)/,
    /^@modelcontextprotocol\//,
    /^mcp-server-/,
    /-agent$/,
];

const LLM_SDK_DEPS = new Set([
    "openai", "@anthropic-ai/sdk",
    "@google/generative-ai", "cohere-ai", "@aws-sdk/client-bedrock-runtime"
]);

const AGENT_FRAMEWORK_DEPS = new Set([
    "langchain", "@langchain/core", "@langchain/langgraph",
    "@langchain/openai", "@langchain/anthropic",
    "llamaindex", "@llamaindex/core",
    "crewai", "@modelcontextprotocol/sdk", "ai" // Vercel AI SDK
]);
```

---

## False positive 케이스 (가중치 조정 시 고려)

다음 케이스는 LLM/agent 관련이지만 agentic 분류에서 제외해야 한다:

1. **단순 chat wrapper** — `openai` 의존성 + chat completion만 호출, tool 사용 없음 → 신호 합 ≤ 2 (LLM SDK + 어쩌면 description). Agentic 아님.
2. **LLM 평가 라이브러리** — `langchain` 의존성이지만 evaluation 용도. AST에서 agent loop 미검출. 신호 합 ≤ 4.
3. **Prompt 라이브러리** — prompt template만 제공. Tool 호출 없음.
4. **벡터 DB 클라이언트** — `chromadb` 같은 패키지. 신호 합 ≤ 1.

따라서 5 이상 임계치는 적절하다. **여러 strong 신호 또는 multiple medium**이 있어야 통과.

---

## 추가 검증 (선택 단계)

Step 1B 통과 후, 다음 보강 검증을 통해 확신도를 높일 수 있다:

```python
def confidence_boost(package) -> float:
    boost = 0.0

    # 실제로 LLM API 호출이 코드에 있는가
    if has_llm_invoke_call(package):
        boost += 0.3

    # tool dispatch 시그니처가 있는가
    if has_tool_dispatch_pattern(package):
        boost += 0.3

    # 외부 입력을 LLM 컨텍스트로 주입하는 경로
    if has_untrusted_to_llm_path(package):
        boost += 0.2

    return boost  # 0.0 ~ 0.8
```

confidence가 0.6 이상이면 Step 2-4 적용. 0.3-0.6 이면 SUSPICIOUS + 인간 검토 큐로.

---

## 임계치 튜닝 가이드

졸업과제 평가 데이터셋을 다음과 같이 구성하여 임계치를 검증할 수 있다:

- **Positive set**: 알려진 agentic 패키지 (langchain, langgraph, crewai, llama-index, AutoGPT 포크 등) 50-100개
- **Negative set**: LLM 관련이지만 non-agentic (openai 클라이언트, prompt template 라이브러리, evaluation 라이브러리 등) 50-100개
- **Edge case**: 단순 chat wrapper, RAG 라이브러리 (tool 사용 안 함) 등 30-50개

이 세 집합에 대해 precision/recall을 측정하고 임계치를 조정.
