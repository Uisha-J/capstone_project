# AISLOPSQ Manifest Specification (v0.1)

**Status:** Draft
**Scope:** npm (`package.json`), PyPI (`pyproject.toml`)
**Purpose:** agentic 패키지가 자신의 capability 경계와 보안 가정을 정직하게 선언하도록 강제하는 표준.

---

## 1. 동기

LLM 에이전트는 planning, tool use, memory, autonomy 4요소를 갖추고 자율적으로 외부 환경과 상호작용한다 (Chhabra et al., arXiv:2510.23883). 이러한 시스템은 **prompt injection이라는 미해결 위협**에 노출되어 있고, runtime 필터·classifier 기반 방어는 적응적 공격에 신뢰성 있게 작동하지 않는다 (Nasr et al., arXiv:2510.09023 — 12개 방어가 ASR 90%+ 로 우회됨).

따라서 학계 합의는 다음과 같다:

> "현재 시점에서는 prompt injection을 막을 수 없다는 가정 하에, **시스템 설계 단계에서 capability 경계를 명시적으로 좁히는 것**이 가장 신뢰할 수 있는 방어 layer이다."
> — Beurer-Kellner et al. (2025), Meta Agents Rule of Two (2025)

AISLOPSQ Manifest는 이 원칙을 **패키지 supply chain 레벨**에서 강제하는 첫 표준이다. 패키지 작성자가 자신이 사용하는 capability 집합을 사전에 선언함으로써:

1. 패키지 사용자는 의존성 추가 시점에 capability 노출 범위를 알 수 있다
2. 정적 분석 도구는 declared와 detected의 차이로 은닉된 행위를 식별할 수 있다
3. CI/CD는 capability 변화에 대해 정책 기반 게이트를 적용할 수 있다

---

## 2. 위치

### 2.1 Python (`pyproject.toml`)

```toml
[tool.aislopsq]
agentic = true
spec_version = "0.1"
capabilities = [
    "filesystem-read",
    "filesystem-write",
    "shell",
    "network",
    "env-secrets"
]
opt_in_required = true
sandbox_recommended = true

[tool.aislopsq.rule_of_two]
# Meta Agents Rule of Two 적용 선언
# A: untrusted-input, B: sensitive-data, C: state-change-or-external-comm
satisfies = ["A", "C"]    # AB / AC / BC 중 하나
session_isolation = true   # context window 새로 시작 시 reset

[tool.aislopsq.design_patterns]
# Beurer-Kellner et al. 2025 design pattern 적용 여부
applied = ["plan-then-execute", "context-minimization"]

[tool.aislopsq.tool_registry]
# 동적 툴 등록 여부 (ToolHijacker 위협 관련)
dynamic_tools = false
tool_signature_verification = false
```

### 2.2 Node.js (`package.json`)

```json
{
  "name": "my-agent-package",
  "version": "1.0.0",
  "aislopsq": {
    "agentic": true,
    "specVersion": "0.1",
    "capabilities": [
      "filesystem",
      "shell",
      "network"
    ],
    "ruleOfTwo": {
      "satisfies": ["A", "C"],
      "sessionIsolation": true
    },
    "designPatterns": {
      "applied": ["plan-then-execute"]
    },
    "toolRegistry": {
      "dynamicTools": false,
      "toolSignatureVerification": false
    }
  }
}
```

---

## 3. Capability 어휘

다음은 **canonical capability vocabulary**이다. 정확한 매칭을 위해 Python/JavaScript 어휘는 통일했다.

| Capability | 의미 | 검출 신호 (Python) | 검출 신호 (JS/TS) |
|---|---|---|---|
| `filesystem-read` | 파일 읽기 | `open(mode="r")`, `pathlib.Path.read_*`, `os.scandir` | `fs.readFile*`, `fs.readdirSync`, `fsPromises.readFile` |
| `filesystem-write` | 파일 쓰기/삭제 | `open(mode="w/a/x")`, `os.remove`, `shutil.rmtree`, `pathlib.Path.write_*` | `fs.writeFile*`, `fs.unlink*`, `fs.rm*` |
| `shell` | OS 셸/프로세스 | `subprocess.*`, `os.system`, `os.popen`, `pty.spawn` | `child_process.exec*`, `child_process.spawn*`, `execa()` |
| `network` | 외부 HTTP/소켓 | `requests`, `httpx`, `urllib.request`, `socket`, `aiohttp` | `fetch`, `axios`, `http.request`, `net.Socket` |
| `env-secrets` | 환경변수/.env | `os.environ`, `os.getenv`, `dotenv` | `process.env`, `dotenv.config()` |
| `code-exec` | 동적 코드 실행 | `exec`, `eval`, `compile`, `importlib.import_module` (동적), `__import__` | `eval`, `Function()`, `vm.runIn*`, `require()` (동적) |
| `credential-paths` | 알려진 자격증명 경로 | string lit `~/.ssh/*`, `~/.aws/*`, `*.pem`, `id_rsa` 등 | 동일 |
| `db-access` | 데이터베이스 | `psycopg2`, `pymysql`, `sqlalchemy.create_engine`, `redis` | `pg`, `mysql2`, `mongodb`, `redis`, `prisma` |
| `mcp-client` | MCP 서버 호출 | `mcp.client.*`, `from mcp import` | `@modelcontextprotocol/sdk` |
| `mcp-server` | MCP 서버 진입점 | `mcp.server.Server`, `@server.list_tools()` | `@modelcontextprotocol/sdk/server/*` |
| `llm-call` | LLM API 호출 | `openai.*`, `anthropic.*`, `langchain_*` 의 LLM 클래스 | `openai`, `@anthropic-ai/sdk`, `langchain` |
| `tool-loop` | agent loop 패턴 | while/for 안에서 LLM 호출 → tool dispatch → 결과 피드백 | 동일 |
| `memory-persistent` | 영속 메모리 | 벡터 DB write, 파일 기반 scratchpad | 동일 |
| `dynamic-tool-load` | 런타임 툴 로딩 | tool description을 외부 fetch | 동일 |
| `agent-to-agent` | A2A 통신 | `crew.delegate`, `agent.send`, A2A 프로토콜 | 동일 |

이 어휘 외의 capability는 `x-` prefix로 확장 가능 (예: `x-gpu-compute`).

---

## 4. Rule of Two 선언

`rule_of_two.satisfies` 필드는 패키지가 한 세션 내에서 동시에 보유할 수 있는 속성을 명시한다. Meta Agents Rule of Two (2025) 에 따르면 다음 세 가지 중 **2개 이하만** 보유해야 prompt injection 최악 시나리오를 회피할 수 있다.

| 코드 | 속성 | 매핑되는 capability 예시 |
|---|---|---|
| **A** | Untrustworthy input | `network` (외부 fetch), `mcp-client`, `agent-to-agent` |
| **B** | Sensitive data access | `env-secrets`, `credential-paths`, `db-access`, `filesystem-read` (홈 디렉터리) |
| **C** | State change / external comm | `filesystem-write`, `shell`, `code-exec`, outbound `network`, `db-access` (write) |

`satisfies` 필드의 유효 값:
- `["A", "B"]` — 외부 통신/상태 변경 차단됨
- `["A", "C"]` — 민감 데이터 접근 차단됨
- `["B", "C"]` — 신뢰 불가 입력 처리 차단됨
- `["A", "B", "C"]` — **금지**. 자율 작동 불가, human-in-the-loop 필수 (검사 도구는 SUSPICIOUS 또는 HIGH_RISK 처리)

검사 도구는 `detected_capabilities`를 위 매핑으로 ABC 집합에 사상한 뒤 declared `satisfies`와 비교한다. 불일치 시 **SUSPICIOUS** 처리.

---

## 5. Design Pattern 선언

`design_patterns.applied` 는 Beurer-Kellner et al. (arXiv:2506.08837) 의 6개 패턴 중 적용한 것을 선언한다. 검사 도구는 이를 R1 룰셋의 면책 또는 가산점에 사용한다.

| 패턴 키 | 의미 | R1 룰 면책 효과 |
|---|---|---|
| `action-selector` | 사전 승인된 액션 목록에서만 선택, 자유형 툴 호출 차단 | R1-4 (자유형 코드 실행) 면책 |
| `plan-then-execute` | 계획 단계와 실행 단계 분리, 툴 출력이 계획 변경 불가 | R1-3 (검색결과 직접 주입) 부분 면책 |
| `llm-map-reduce` | 외부 데이터를 격리된 LLM에서 map 처리 후 신뢰 layer로 reduce | R1-1 (격리 부재) 면책 |
| `dual-llm` | privileged LLM과 quarantined LLM 분리 | R1-1, R1-3 면책 |
| `code-then-execute` | LLM이 코드 생성, 격리 환경에서 실행, 출력은 sanitize | R1-4 부분 면책 |
| `context-minimization` | 신뢰 불가 컨텍스트가 민감 액션 시점에 컨텍스트에 없음 | R4-3 면책 |

선언만으로는 부족하며, 검사 도구는 implementation 시그니처를 통해 패턴 적용을 검증해야 한다 (구현 가이드는 `RULES.md` 참조).

---

## 6. Tool Registry 선언

`tool_registry.dynamic_tools` 는 ToolHijacker 위협 (Shi et al., arXiv:2504.19793) 의 직접적 대응이다. 동적 툴 로딩을 허용하는 패키지는 악성 툴 문서 주입에 취약하므로 다음 정책을 따라야 한다:

```toml
[tool.aislopsq.tool_registry]
dynamic_tools = true
tool_signature_verification = true   # 동적 툴은 반드시 서명 검증
trusted_tool_sources = ["https://my-org.example/tools/"]
```

`dynamic_tools = true` 이면서 `tool_signature_verification = false` 인 패키지는 검사 도구가 자동으로 **HIGH_RISK** 처리.

---

## 7. 검증 절차 (검사 도구 측)

manifest가 존재하는 패키지는 다음 단계로 검증된다:

1. **Schema 검증** — manifest의 모든 필드가 본 사양에 부합하는지
2. **Detected capabilities 추출** — `CAPABILITY-DETECTION.md` 의 정적 분석 룰로 실제 코드의 capability set 추출
3. **Declared vs Detected 비교**
   ```
   declared ⊇ detected   → AGENTIC (정직한 선언, 사용자 명시 동의 필요)
   declared ⊊ detected   → undeclared = detected − declared
                          if undeclared ∩ {shell, code-exec, credential-paths} ≠ ∅:
                              MALICIOUS
                          else:
                              SUSPICIOUS
   ```
4. **Rule of Two 일관성** — declared capability를 ABC로 사상해 `satisfies` 와 비교
5. **R1-R4 룰셋** 적용 (`RULES.md`)

manifest가 부재한 패키지는 자동 신호 (`AGENTIC-SIGNALS.md`) 로 agentic 여부 판정 후, declared = ∅ 가정 하에 위 절차 적용.

---

## 8. 마이그레이션 가이드

기존 패키지가 본 사양을 채택하기 위한 최소 절차:

1. 정적 분석 도구로 detected capability 목록 추출
2. capability 어휘에서 해당하는 항목을 모두 `capabilities` 에 선언
3. ABC 분류로 `satisfies` 결정
4. 적용된 design pattern 명시 (없다면 빈 리스트 — 검사 도구는 R1 가산점 적용 안 함)

샘플 패키지 (`langchain-style email agent`):

```toml
[tool.aislopsq]
agentic = true
spec_version = "0.1"
capabilities = ["network", "llm-call", "tool-loop"]

[tool.aislopsq.rule_of_two]
satisfies = ["A", "C"]   # 외부 이메일 fetch + 전송, 민감 자격증명 미보유
session_isolation = true

[tool.aislopsq.design_patterns]
applied = ["plan-then-execute"]

[tool.aislopsq.tool_registry]
dynamic_tools = false
```

---

## 9. 보안 고려사항

- manifest 자체는 **정직성 가정에 의존**한다. 악의적 패키지는 거짓 manifest를 작성할 수 있으므로, declared와 detected 비교가 핵심 검증이 된다.
- manifest 부재 ≠ 안전. 자동 신호로 agentic 판정 시 declared = ∅로 처리되어 모든 detected capability가 undeclared로 분류된다.
- 본 사양은 **prompt injection 자체를 막지 못한다**. 학계 합의에 따르면 그것은 현재 불가능하다 (Nasr et al., 2025). 본 사양의 목표는 패키지 설치 시점의 정보 비대칭을 줄이는 것이다.

---

## 10. 향후 작업

- v0.2: A2A 통신 capability의 세분화 (어떤 에이전트와 대화하는지)
- v0.2: memory provenance 선언 필드
- v0.3: SBOM (CycloneDX/SPDX) 통합
- v0.3: signed manifest (Sigstore 통합)

---

## 참조

- arXiv:2510.23883 — Chhabra et al., "Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges" (2025)
- arXiv:2506.08837 — Beurer-Kellner et al., "Design Patterns for Securing LLM Agents against Prompt Injections" (2025)
- arXiv:2504.19793 — Shi et al., "Prompt Injection Attack to Tool Selection in LLM Agents" (2025)
- arXiv:2510.09023 — Nasr et al., "The Attacker Moves Second" (2025)
- Meta AI, "Agents Rule of Two: A Practical Approach to AI Agent Security" (Oct 2025)
- OWASP Top 10 for Agentic Applications (Dec 2025)

각 논문의 핵심 발췌는 `papers/` 디렉터리 참조.
