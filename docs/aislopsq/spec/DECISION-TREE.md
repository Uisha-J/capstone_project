# Decision Tree: AGENTIC verdict 분류 로직

기존 47-indicator 룰셋의 4 verdict (`MALICIOUS / HIGH_RISK / SUSPICIOUS / CLEAN`) 에 `AGENTIC` 을 추가하는 분류 결정 트리.

---

## 전체 흐름

```
입력: package.json 또는 pyproject.toml + 소스 코드
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ Step 1: agentic 패키지인가?                              │
│   - 1A. AISLOPSQ manifest 존재 & agentic=true           │
│   - 1B. 자동 신호 가중치 합계 ≥ 5                        │
│   둘 중 하나라도 만족 → agentic = True                   │
└─────────────────────────────────────────────────────────┘
        │
        ├─── NO  → 기존 47-indicator 파이프라인으로
        │
        └─── YES
              ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: declared vs detected capability 비교             │
│                                                         │
│   manifest 존재:                                         │
│     declared ⊇ detected  → 진행 (정직한 선언)            │
│     declared ⊊ detected  → undeclared 추출               │
│                                                         │
│   manifest 부재:                                         │
│     declared = ∅ 로 처리 → undeclared = detected         │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2-Verdict: undeclared 평가                          │
│                                                         │
│   undeclared ∩ {shell, code-exec, credential-paths}      │
│       ≠ ∅          → return MALICIOUS                    │
│   undeclared ≠ ∅    → continue (with SUSPICIOUS flag)    │
│   undeclared = ∅    → continue (clean declaration)       │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: Rule of Two 일관성 검증                          │
│                                                         │
│   detected capability를 ABC 집합으로 사상                │
│     A: untrusted-input       (network in, MCP, A2A)      │
│     B: sensitive-data        (env, creds, DB read, FS)   │
│     C: state-change/external (FS write, shell, code-exec,│
│                               network out, DB write)     │
│                                                         │
│   satisfies = manifest의 declared 또는 detected 기반 추론│
│                                                         │
│   |actual ABC set| = 3   (모두 보유)                     │
│       AND human-in-the-loop 메커니즘 부재                │
│       → escalate to HIGH_RISK                            │
│   declared satisfies ≠ actual ABC set                    │
│       → SUSPICIOUS                                       │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ Step 4: R1-R4 룰셋 적용 (RULES.md)                       │
│                                                         │
│   R1. Prompt Injection 가능성  (Beurer-Kellner 2025)     │
│   R2. Sandbox Escape 시도      (Meta Rule of Two 2025)   │
│   R3. Undeclared Capability    (OWASP 2025, ToolHijacker)│
│   R4. Hidden Side Channel      (NVIDIA-Lakera 2025,      │
│                                 Log-To-Leak 2025)        │
│                                                         │
│   각 룰의 hit count로 severity 계산                      │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ 최종 Verdict 결정                                        │
│                                                         │
│   if R3 hits MALICIOUS triggers (shell/code-exec/creds   │
│      undeclared)                                         │
│       → return MALICIOUS                                 │
│   if R4-1 (covert exfiltration) OR R4-5 (description-    │
│      behavior mismatch) hit                              │
│       → return MALICIOUS                                 │
│   if R3 minor undeclared OR R2 sandbox escape signs      │
│       → return HIGH_RISK                                 │
│   if R1 hit count ≥ 2 AND no design_patterns applied     │
│       → return HIGH_RISK                                 │
│   if R1 or R4 minor hits                                 │
│       → return SUSPICIOUS                                │
│   if all clean & manifest_present & declared = detected  │
│       → return AGENTIC (사용자 명시 동의 필요)            │
│   if all clean & manifest absent                         │
│       → return AGENTIC + warning("manifest missing")     │
└─────────────────────────────────────────────────────────┘
```

---

## verdict 의미

| Verdict | 의미 | 설치 정책 (권장) |
|---|---|---|
| `MALICIOUS` | undeclared dangerous capability 또는 covert side channel | **block** |
| `HIGH_RISK` | 관리되지 않는 자율성 (Rule of Two 위반, design pattern 부재) | block in production, allow in sandbox |
| `SUSPICIOUS` | manifest 불일치 또는 minor R1/R4 hit | warn, manual review |
| `AGENTIC` | manifest 정직 + R1-R4 clean | **explicit user opt-in 필수**, sandbox 권장 |
| `CLEAN` | non-agentic + 47-indicator clean | allow |

---

## Step 1 상세: agentic 판별

### 1A. Manifest 기반 (우선)

```
if pyproject.toml has [tool.aislopsq] and tool.aislopsq.agentic == true:
    return agentic = True
if package.json has aislopsq.agentic == true:
    return agentic = True
```

### 1B. 자동 신호 (manifest 부재 시 fallback)

`AGENTIC-SIGNALS.md` 의 가중치 표 적용. 합계 ≥ 5 이면 agentic.

핵심 신호 (전체는 `AGENTIC-SIGNALS.md` 참조):

| 신호 | 가중치 |
|---|---|
| 패키지명 패턴 (`agent`, `langchain`, `crewai`, `mcp-server-*` 등) | 3 |
| description 키워드 ("AI agent", "tool use", "MCP" 등) | 3 |
| agent loop 패턴 (LLM call 후 tool dispatch loop) | 3 |
| MCP server 진입점 (`mcp.server.Server`) | 3 |
| LLM SDK 의존성 (`openai`, `anthropic`) + tool calling 사용 | 2 |
| Agent/Tool/Executor 클래스 import | 2 |

---

## Step 2 상세: capability 비교

`CAPABILITY-DETECTION.md` 의 매핑 테이블에 따라 detected_capabilities 추출.

```python
def compare(declared: set, detected: set) -> Tuple[Verdict, set]:
    DANGEROUS = {"shell", "code-exec", "credential-paths"}

    if declared is None:  # manifest 부재
        declared = set()

    undeclared = detected - declared
    over_declared = declared - detected  # informational only

    if undeclared & DANGEROUS:
        return MALICIOUS, undeclared
    if undeclared:
        return SUSPICIOUS, undeclared
    return CLEAN, set()  # declared가 detected 포함
```

---

## Step 3 상세: Rule of Two 검증

```python
def map_to_abc(capabilities: set) -> set:
    A = {"network-in", "mcp-client", "agent-to-agent",
         "filesystem-read"}  # 외부 콘텐츠 fetch
    B = {"env-secrets", "credential-paths", "db-access",
         "filesystem-read"}  # 민감 데이터 (홈디렉터리 read 포함)
    C = {"filesystem-write", "shell", "code-exec",
         "network-out", "db-access"}  # 상태 변경/외부 통신

    result = set()
    if capabilities & A: result.add("A")
    if capabilities & B: result.add("B")
    if capabilities & C: result.add("C")
    return result
```

`actual_abc = map_to_abc(detected)`. 가능 케이스:

- `|actual_abc| ≤ 2` AND declared `satisfies` matches → **OK**
- `|actual_abc| = 3` AND human-in-the-loop 검출됨 → **OK**, 단 `AGENTIC` verdict + warning
- `|actual_abc| = 3` AND HITL 부재 → **HIGH_RISK**
- declared satisfies 와 actual_abc 가 일치하지 않음 → **SUSPICIOUS**

human-in-the-loop 검출 신호:
- `input()` 또는 `confirm()` 호출이 dangerous tool dispatch 직전에 위치
- `approval_required=True` 같은 명시적 플래그
- LangChain `human_in_the_loop` 미들웨어
- MCP server의 `resources/list` 요청 후 사용자 승인 패턴

---

## Step 4 상세: R1-R4

각 룰의 정확한 시그니처와 검출 로직은 `RULES.md` 참조. 여기서는 verdict 가중치만 요약:

| 룰 ID | 카테고리 | 트리거 시 verdict 영향 |
|---|---|---|
| R1-1 | 신뢰 불가 입력이 시스템 프롬프트와 동일 권한 | HIGH_RISK 후보 |
| R1-2 | Tool description 동적 로딩 | HIGH_RISK 후보 |
| R1-3 | 검색 결과 직접 컨텍스트 주입 | SUSPICIOUS |
| R1-4 | 자유형 코드/툴 실행 디폴트 | HIGH_RISK |
| R2-1 | Lethal Trifecta 동시 보유 | HIGH_RISK |
| R2-2 | 권한 상승 시도 | MALICIOUS |
| R2-3 | 컨테이너/sandbox 우회 | MALICIOUS |
| R2-4 | 동적 의존성 설치 | HIGH_RISK |
| R3 | undeclared dangerous capability | MALICIOUS |
| R3 | undeclared minor capability | SUSPICIOUS |
| R4-1 | 로깅 툴을 통한 covert exfiltration | MALICIOUS |
| R4-2 | Memory poisoning 경로 | HIGH_RISK |
| R4-3 | provenance 부재 | SUSPICIOUS |
| R4-4 | A2A 통신 미인증 | SUSPICIOUS |
| R4-5 | description-behavior mismatch | MALICIOUS |

---

## 의사 코드 (참조 구현)

```python
def classify(package) -> Verdict:
    # Step 1
    if not is_agentic(package):
        return existing_47_indicator(package)

    declared = parse_manifest(package)  # None if absent
    detected = extract_capabilities(package)  # CAPABILITY-DETECTION.md

    # Step 2
    verdict, undeclared = compare(declared, detected)
    if verdict == MALICIOUS:
        return MALICIOUS

    # Step 3
    actual_abc = map_to_abc(detected)
    has_hitl = detect_human_in_the_loop(package)

    if len(actual_abc) == 3 and not has_hitl:
        return HIGH_RISK
    if declared and declared.satisfies != actual_abc:
        verdict = SUSPICIOUS  # don't return yet, let R1-R4 escalate

    # Step 4
    rule_hits = run_r1_to_r4(package, declared)

    if rule_hits.has_malicious_trigger():
        return MALICIOUS
    if rule_hits.r1_count >= 2 and not declared.design_patterns_applied:
        return HIGH_RISK
    if rule_hits.r2_or_r4_severe():
        return HIGH_RISK
    if rule_hits.minor():
        return SUSPICIOUS

    return AGENTIC  # opt-in 요구
```

---

## 근거 매핑

각 결정 단계의 근거는 다음 논문에 있다:

| 결정 단계 | 근거 논문 | papers/ 카드 |
|---|---|---|
| Step 1 (agentic 정의) | Chhabra et al. 2025 (4요소 정의) | 01-chhabra-survey.md |
| Step 2 (capability 비교) | OWASP Top 10 Agentic 2025 (Tool Misuse, Privilege Abuse) | INDEX.md 참조 |
| Step 3 (Rule of Two) | Meta Agents Rule of Two 2025 | 05-meta-agents-rule-of-two.md |
| Step 4 R1 (prompt injection) | Beurer-Kellner et al. 2025 | 02-beurer-kellner-design-patterns.md |
| Step 4 R1-2 (tool selection) | Shi et al. 2025 (ToolHijacker) | 03-toolhijacker.md |
| Step 4 R2 (Lethal Trifecta) | Meta Agents Rule of Two 2025 | 05-meta-agents-rule-of-two.md |
| Step 4 R4-1 (covert log) | Lin et al. 2025 (Log-To-Leak) | INDEX.md 참조 |
| 전반 (filtering 신뢰성) | Nasr et al. 2025 | 04-attacker-moves-second.md |
