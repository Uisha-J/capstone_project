# Capability Detection: npm/PyPI 매핑 테이블

`AISLOPSQ-MANIFEST-SPEC.md` 의 capability vocabulary를 정적 분석으로 추출하기 위한 시그니처 매핑.

---

## 분석 입력

- Python: `.py` 파일 + `pyproject.toml` / `setup.py` / `setup.cfg` (의존성 추출용)
- JavaScript/TypeScript: `.js` / `.ts` / `.mjs` / `.cjs` 파일 + `package.json`

분석은 AST 레벨로 수행 권장. 단순 grep은 false positive가 높음 (주석, 문자열 리터럴).

---

## Python (PyPI) 매핑

### `filesystem-read`

| 시그니처 | 검출 형태 |
|---|---|
| `open(...)` (mode 미지정 또는 `r`/`rb`) | `ast.Call`, func name `open`, no `mode` kwarg or mode in `{"r", "rb", "rt"}` |
| `pathlib.Path(...).read_text()` / `.read_bytes()` | `ast.Attribute` 호출 |
| `pathlib.Path(...).open(...)` (`r` mode) | 동일 |
| `os.scandir`, `os.listdir`, `os.walk` | `ast.Call` to `os.<name>` |
| `glob.glob`, `glob.iglob` | 동일 |
| `aiofiles.open` (async read) | `from aiofiles import open` 사용 |

### `filesystem-write`

| 시그니처 | 검출 형태 |
|---|---|
| `open(..., mode in {"w", "wb", "wt", "a", "ab", "x", "xb"})` | mode kwarg 검사 |
| `pathlib.Path(...).write_text()` / `.write_bytes()` | `ast.Attribute` 호출 |
| `os.remove`, `os.unlink`, `os.rmdir` | 동일 |
| `os.rename`, `os.replace` | 동일 |
| `shutil.copy*`, `shutil.move`, `shutil.rmtree` | 동일 |
| `os.makedirs`, `os.mkdir` | 동일 |
| `os.chmod`, `os.chown` | 권한 변경 |

### `shell`

| 시그니처 | 검출 형태 |
|---|---|
| `subprocess.run`, `subprocess.Popen`, `subprocess.call`, `subprocess.check_output`, `subprocess.check_call` | 모두 `subprocess.<name>` |
| `os.system`, `os.popen` | 동일 |
| `pty.spawn`, `pty.fork` | 동일 |
| `multiprocessing.Process` (target이 외부 명령일 때) | 보조 신호 |
| `asyncio.create_subprocess_exec`, `asyncio.create_subprocess_shell` | 동일 |
| `commands.getoutput` (Python 2 호환) | 동일 |

**위험 가중:** `shell=True` kwarg가 있으면 R2-2 후보. argument가 LLM 출력에서 결정되면 R1-4 + R2-2.

### `network`

| 시그니처 | 검출 형태 |
|---|---|
| `requests.get/post/put/delete/patch/head/options/request` | `ast.Attribute` |
| `httpx.get/post/...`, `httpx.AsyncClient` | 동일 |
| `urllib.request.urlopen`, `urllib.request.Request` | 동일 |
| `aiohttp.ClientSession`, `aiohttp.request` | 동일 |
| `socket.socket`, `socket.create_connection` | 저수준 신호 |
| `http.client.HTTPConnection`, `HTTPSConnection` | 저수준 |
| `websockets.connect`, `websocket.create_connection` | WebSocket |
| `smtplib.SMTP*` | 이메일 outbound (C 카테고리 강) |

**방향 구분:** `network-in` (외부 콘텐츠 fetch — A 카테고리) vs `network-out` (외부 송신 — C 카테고리). 같은 함수가 양쪽 모두 가능하지만, 정적 분석에서는 다음 휴리스틱:
- argument가 패키지 외부에서 결정되는 URL이고, response를 LLM 컨텍스트나 메모리로 전달 → `network-in`
- argument에 사용자 데이터/credentials/메모리 콘텐츠가 포함되어 송신 → `network-out`

대부분의 패키지는 양쪽 다 보유. ABC 매핑에서는 `network` 자체를 A와 C 양쪽에 사상.

### `env-secrets`

| 시그니처 | 검출 형태 |
|---|---|
| `os.environ`, `os.environ.get`, `os.environ[...]` | 동일 |
| `os.getenv` | 동일 |
| `dotenv.load_dotenv`, `from dotenv import` | 동일 |
| `python-decouple` 의 `config(...)` | 동일 |
| AWS/GCP credential 자동 로딩 (`boto3.Session()`, `google.auth.default()`) | 동일 |

### `code-exec`

| 시그니처 | 검출 형태 |
|---|---|
| `exec(...)`, `eval(...)`, `compile(...)` | builtin call |
| `__import__(name_var)` (string 변수) | 동적 import |
| `importlib.import_module(name_var)` | 동일 |
| `importlib.util.spec_from_file_location` | 동일 |
| `types.FunctionType` 으로 새 function 생성 | 동일 |
| `marshal.loads`, `pickle.loads` (untrusted source) | 역직렬화 (RCE 위험) |
| `yaml.load` (without `SafeLoader`) | 동일 |

### `credential-paths`

문자열 리터럴 매칭 (글로벌 정규식):

```python
CREDENTIAL_PATH_PATTERNS = [
    r"~/\.ssh/.*",
    r"~/\.aws/.*",
    r"~/\.gnupg/.*",
    r"~/\.config/gcloud/.*",
    r"~/\.kube/.*",
    r"~/\.docker/config\.json",
    r"~/\.netrc",
    r"id_rsa", r"id_ed25519", r"id_ecdsa",
    r"\.pem$", r"\.key$", r"\.p12$", r"\.pfx$",
    r"\.env(\.|$)",  # .env, .env.local 등
    r"credentials\.json",
    r"service[-_]account[-_]?key",
]
```

`open(...)` 또는 `pathlib.Path(...)` 의 path 인자가 위 패턴과 매칭되면 `credential-paths` 추가.

### `db-access`

| 시그니처 | 검출 형태 |
|---|---|
| `psycopg2.connect`, `psycopg.connect` | PostgreSQL |
| `pymysql.connect`, `mysql.connector.connect` | MySQL |
| `sqlalchemy.create_engine`, `Session()` | ORM |
| `redis.Redis`, `redis.StrictRedis`, `aioredis.Redis` | Redis |
| `pymongo.MongoClient`, `motor.motor_asyncio.AsyncIOMotorClient` | MongoDB |
| `cassandra.cluster.Cluster` | Cassandra |
| `clickhouse_driver.Client` | ClickHouse |
| `duckdb.connect`, `sqlite3.connect` | embedded DB |

### `mcp-client` / `mcp-server`

| Capability | 시그니처 |
|---|---|
| `mcp-client` | `from mcp.client import ...`, `mcp.client.stdio.stdio_client(...)`, `ClientSession(...)`, `await session.call_tool(...)` |
| `mcp-server` | `from mcp.server import Server`, `from mcp.server.fastmcp import FastMCP`, `@server.list_tools()`, `@server.call_tool()`, `@app.tool()` |

### `llm-call`

| 시그니처 | 검출 형태 |
|---|---|
| `openai.ChatCompletion.create`, `openai.OpenAI(...).chat.completions.create` | 동일 |
| `anthropic.Anthropic(...).messages.create` | 동일 |
| `langchain.chat_models.ChatOpenAI(...).invoke` 등 | LangChain LLM 클래스 |
| `langchain_*.ChatModel.invoke` 등 | 동일 |
| `llama_index.core.llms.LLM.complete/.chat` | 동일 |
| `google.generativeai.GenerativeModel.generate_content` | Google |
| `cohere.Client(...).chat` | Cohere |
| `mistralai.client.MistralClient(...).chat` | Mistral |

### `tool-loop`

휴리스틱 검출 — AST에서 다음 시퀀스가 loop body 안에 있는지:

```python
def is_tool_loop(loop_body_ast):
    has_llm_call = any(is_llm_call(node) for node in walk(loop_body_ast))
    has_tool_dispatch = any(is_tool_dispatch(node) for node in walk(loop_body_ast))
    has_result_feedback = any(
        is_message_append(node) or is_state_update(node)
        for node in walk(loop_body_ast)
    )
    return has_llm_call and has_tool_dispatch and has_result_feedback
```

LangGraph/LangChain의 `AgentExecutor.invoke`, `graph.compile().invoke()` 같은 high-level abstraction도 tool-loop로 분류.

### `memory-persistent`

| 시그니처 | 검출 형태 |
|---|---|
| Vector store write | `chromadb.Collection.add`, `pinecone.Index.upsert`, `weaviate.Client.batch.add_data_object` |
| LangChain memory persist | `ConversationBufferMemory.save_context` 호출 + 외부 store 연동 |
| 파일 기반 scratchpad | `open(memory_file, "a")` 패턴 |
| Redis pub/sub 또는 stream | session ID와 함께 사용 시 |

### `dynamic-tool-load`

| 시그니처 | 검출 형태 |
|---|---|
| Tool description을 외부 fetch | `tool_doc = requests.get(url).json(); agent.bind_tools([..., tool_doc])` |
| Tool registry mutation at runtime | `agent.tools.append(...)`, `tools.extend(remote_tools)` |
| MCP `list_tools` 결과를 그대로 binding | `tools = await session.list_tools(); agent.bind_tools(tools)` |

### `agent-to-agent`

| 시그니처 | 검출 형태 |
|---|---|
| CrewAI delegation | `Crew(agents=[...]).kickoff()`, `agent.delegate(...)` |
| AutoGen multi-agent | `GroupChat`, `GroupChatManager` |
| LangGraph subgraph 호출 | `graph.add_node("agent_b", ...)` + 메시지 전달 |
| A2A protocol 라이브러리 | `from a2a import ...` (가설) |

---

## JavaScript / TypeScript (npm) 매핑

### `filesystem-read`

| 시그니처 |
|---|
| `fs.readFile`, `fs.readFileSync`, `fsPromises.readFile` |
| `fs.readdir*`, `fs.opendir*` |
| `fs.createReadStream` |
| `Bun.file(...).text()` (Bun runtime) |
| `Deno.readTextFile`, `Deno.readFile` |

### `filesystem-write`

| 시그니처 |
|---|
| `fs.writeFile*`, `fs.appendFile*`, `fs.createWriteStream` |
| `fs.unlink*`, `fs.rm*`, `fs.rmdir*` |
| `fs.rename*`, `fs.copyFile*` |
| `fs.chmod*`, `fs.chown*` |
| `fs.mkdir*` |

### `shell`

| 시그니처 |
|---|
| `child_process.exec`, `child_process.execFile`, `child_process.execSync`, `child_process.execFileSync` |
| `child_process.spawn`, `child_process.spawnSync` |
| `child_process.fork` |
| `execa(...)` (npm: `execa`) |
| `shelljs.exec` |
| `Bun.spawn`, `Deno.Command(...).spawn()` |

**위험:** `shell: true` 옵션 + LLM 출력이 인자로 들어가는 경우 R1-4 + R2-2.

### `network`

| 시그니처 |
|---|
| `fetch(...)` (global) |
| `axios.get/post/...`, `axios(...)` |
| `http.request`, `https.request` |
| `node-fetch` |
| `got(...)` |
| `undici.fetch`, `undici.request` |
| `net.Socket`, `net.createConnection` |
| `ws.WebSocket(...)`, `socket.io-client` |
| `nodemailer.createTransport(...).sendMail` (이메일 outbound) |

### `env-secrets`

| 시그니처 |
|---|
| `process.env.*`, `process.env[...]` |
| `dotenv.config()`, `import "dotenv/config"` |
| `@aws-sdk/credential-providers` 의 `fromEnv` |
| AWS/GCP SDK의 default credential chain |

### `code-exec`

| 시그니처 |
|---|
| `eval(...)` |
| `Function(...)`, `new Function(...)` |
| `vm.runInNewContext`, `vm.runInThisContext`, `vm.runInContext` |
| `vm2.NodeVM` (외부 라이브러리) |
| 동적 `require(varName)` — variable이 LLM 출력 |
| `await import(varName)` — 동일 |

### `credential-paths`

(Python과 동일 정규식, fs 호출의 path 인자에서 매칭)

### `db-access`

| 시그니처 |
|---|
| `pg`, `pg-pool` |
| `mysql2`, `mysql` |
| `mongodb`, `mongoose` |
| `redis`, `ioredis` |
| `prisma`, `@prisma/client` |
| `drizzle-orm`, `kysely` |
| `better-sqlite3`, `node-sqlite3` |

### `mcp-client` / `mcp-server`

| Capability | 시그니처 |
|---|---|
| `mcp-client` | `import { Client } from "@modelcontextprotocol/sdk/client/index.js"`, `await client.callTool(...)` |
| `mcp-server` | `import { Server } from "@modelcontextprotocol/sdk/server/index.js"`, `server.setRequestHandler(ListToolsRequestSchema, ...)`, `server.setRequestHandler(CallToolRequestSchema, ...)` |

### `llm-call`

| 시그니처 |
|---|
| `openai` SDK: `client.chat.completions.create(...)` |
| `@anthropic-ai/sdk`: `client.messages.create(...)` |
| `@google/generative-ai`: `model.generateContent(...)` |
| `langchain` LLM 클래스의 `.invoke(...)` |
| `ai` (Vercel AI SDK): `generateText`, `streamText`, `generateObject` |
| `cohere-ai`: `cohere.chat(...)` |

### `tool-loop`

휴리스틱은 Python과 동일 — loop body 안에 LLM call + tool dispatch + result feedback.

LangGraph JS, AI SDK의 `tools` + `maxSteps > 1` 등도 포함.

### `memory-persistent`

| 시그니처 |
|---|
| Vector store: `@pinecone-database/pinecone`, `chromadb`, `weaviate-client`, `@qdrant/js-client-rest` |
| 파일 append 패턴 + session ID |
| `redis` pub/sub or stream |

### `dynamic-tool-load`

(Python과 동일 — 외부에서 fetch한 tool description을 binding)

### `agent-to-agent`

| 시그니처 |
|---|
| LangGraph subgraph |
| `crewai` (npm 포팅 시) |
| 커스텀 A2A: 메시지를 다른 LLM agent endpoint로 송신하는 패턴 |

---

## ABC 사상 (Rule of Two 검증용)

`map_to_abc()` 구현용 reference table:

| Capability | A (untrusted) | B (sensitive) | C (state/external) |
|---|---|---|---|
| `filesystem-read` | ✓ (외부 입력 마운트 시) | ✓ (홈 디렉터리 read) | |
| `filesystem-write` | | | ✓ |
| `shell` | | | ✓ |
| `network` | ✓ | | ✓ |
| `env-secrets` | | ✓ | |
| `code-exec` | | | ✓ |
| `credential-paths` | | ✓ | |
| `db-access` | ✓ (외부 데이터 read) | ✓ | ✓ (write) |
| `mcp-client` | ✓ | | ✓ |
| `mcp-server` | ✓ | | ✓ |
| `llm-call` | ✓ (LLM 응답이 외부 콘텐츠) | | |
| `tool-loop` | (자체로는 X, 다른 cap과 결합) | | |
| `memory-persistent` | | ✓ | ✓ |
| `dynamic-tool-load` | ✓ | | |
| `agent-to-agent` | ✓ | | ✓ |

세분화가 필요한 capability (`filesystem-read`, `db-access`, `network`)는 정적 분석으로 추가 컨텍스트를 추출해 정확한 ABC 사상을 시도해야 한다. 모호한 경우 보수적으로 양쪽에 사상.

---

## 구현 권장 도구

- Python: `ast` 모듈 (표준 라이브러리), `astroid` (Pylint 의존), `tree-sitter-python`
- JS/TS: `@babel/parser`, `typescript` compiler API, `tree-sitter-typescript`
- Cross-language: `tree-sitter` 단일 바이너리로 양쪽 처리 가능

의존성 그래프는 PyPI는 `pip-tools` / `johnnydep`, npm은 `npm ls --json`.
