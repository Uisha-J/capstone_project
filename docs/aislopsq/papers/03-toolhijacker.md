# 03. Shi et al. — ToolHijacker (2025)

## 메타데이터

- **제목**: Prompt Injection Attack to Tool Selection in LLM Agents
- **저자**: Jiawen Shi 외 5인
- **출판**: arXiv preprint
- **arXiv ID**: 2504.19793
- **버전**: v1 (2025-04), v2 (2025-08)
- **URL**:
  - Abstract: https://arxiv.org/abs/2504.19793
  - HTML: https://arxiv.org/html/2504.19793v2
  - PDF: https://arxiv.org/pdf/2504.19793

## Abstract (paraphrase)

LLM 에이전트의 핵심 컴포넌트 중 하나가 tool selection이다. 일반적으로 tool selection은 retrieval과 selection 두 단계로 진행되어 tool library에서 작업에 가장 적합한 툴을 고른다. 본 논문은 **ToolHijacker** 라는 새로운 prompt injection 공격을 제시한다. ToolHijacker는 no-box 시나리오에서 작동하며, tool library에 악성 tool 문서를 주입해서 에이전트가 일관되게 공격자가 의도한 툴을 선택하도록 조작한다. 저자들은 이 악성 문서 생성을 최적화 문제로 정식화하고 두 단계 최적화 전략을 제안한다. 광범위한 실험 평가에 따르면 ToolHijacker는 기존 수동 및 자동 prompt injection 공격을 모두 능가한다.

## 핵심 공격 메커니즘

### Threat Model

- **공격자 능력**: tool library에 새 tool을 추가할 수 있음 (마켓플레이스, MCP server registry, 패키지 의존성 등)
- **공격자 정보**: no-box — target task 설명, retriever, LLM, tool library의 내부 동작을 알지 못함
- **공격자 목표**: 특정 target task에서 에이전트가 자신의 악성 툴을 선택하게 함

### 공격 단계

1. **Shadow framework 구축**: 공격자는 target에 대한 정보가 부족하므로 shadow task descriptions와 shadow LLM을 구축해 target을 모방
2. **악성 tool document 최적화**: 두 단계로 작성
   - **Phase 1 (Retrieval-targeting)**: tool description이 target task의 다양한 표현에서 일관되게 retrieve되도록 최적화
   - **Phase 2 (Selection-targeting)**: retrieve된 후 LLM이 다른 benign 툴들 대신 이것을 선택하도록 최적화
3. **주입**: 최적화된 악성 tool document를 공개 tool registry에 publish

### 결과

ToolHijacker는 기존 prompt injection 공격을 크게 능가하며 (paper §experiments), 본 deliverable의 R1-2 룰의 직접적 동기가 된다. 또한 저자들은 prevention/detection 방어 모두 부분적이라는 점을 발견한다 — PPL-W 같은 방어가 일부 악성 문서를 잡지만 상당 부분을 놓친다.

## 본 논문이 본 deliverable에 미친 영향

이 논문은 **tool registry 자체가 supply chain 공격 벡터**임을 입증한다. 따라서:

1. **Manifest의 `tool_registry` 필드가 필수**가 된다 (`AISLOPSQ-MANIFEST-SPEC.md` §6).
2. `dynamic_tools = true` AND `tool_signature_verification = false` 조합은 자동 HIGH_RISK.
3. 정적 분석은 외부에서 fetch한 tool description을 LLM에 binding하는 코드 패턴을 검출해야 한다 (R1-2).

또한 **R4-5 (description-behavior mismatch)** 룰은 ToolHijacker의 일반화 형태다. 악성 툴은 description을 합리적으로 보이게 작성하지만 구현부가 다른 동작을 한다 — 정적 분석으로 이를 비교 가능.

## AISLOPSQ 매핑

| 본 deliverable 항목 | 본 논문에서의 근거 |
|---|---|
| R1-2 (tool selection 무결성) | 전체 — 핵심 위협 정의 |
| R4-5 (description-behavior mismatch) | 일반화: 악성 툴이 description으로 위장하는 메커니즘 |
| Manifest `tool_registry.dynamic_tools` 필드 | 동적 tool 로딩이 공격 진입점이라는 증명 |
| Manifest `tool_signature_verification` 필드 | 외부 tool source의 신뢰성 보장 필요성 |
| `dynamic-tool-load` capability | CAPABILITY-DETECTION.md 의 시그니처 |

## 검출 시그니처 보강

본 논문의 통찰을 정적 분석으로 옮기기 위한 추가 휴리스틱:

```python
# Anti-pattern 1: 외부 URL에서 tool description fetch
suspicious_patterns = [
    r"requests\.(get|post)\(.*\)\..*\bjson\(\)",  # tool registry endpoint
    r"agent\.(bind_tools|tools)\.(append|extend)",  # 런타임 추가
]

# Anti-pattern 2: MCP list_tools 결과를 검증 없이 binding
async def detect_mcp_unsafe_binding(ast):
    return has_pattern(ast,
        "tools = await session.list_tools()",
        "agent.bind_tools(tools)")  # signature 검증 없음
```

## Claude Code 참조 시 주의사항

본 논문은 공격 논문이므로 구현 시 공격을 그대로 만들지 말 것 (의미 없음). 대신 **방어 측면**에서 다음을 도출:

1. tool description의 내용은 untrusted data로 간주
2. retrieval 단계에서 source verification (signature, allowlist)
3. selection 단계에서 description-implementation 일관성 검증
4. tool 추가/변경에 대한 audit log

또한 본 논문이 다루지 않는 추가 위협이 있다 (저자들도 future work로 언급): **tool selection과 tool calling 동시 공격**, **제3자 packaging** (npm/PyPI 라이브러리에 악성 tool 포함). 본 deliverable은 후자에 직접 대응한다.

## 직접 인용 (15단어 미만 1회)

저자들은 ToolHijacker가 "tool library에 악성 tool 문서를 주입해서 에이전트의 tool selection을 일관되게 조작" (paraphrase) 한다고 정의한다.

## 인용 형식 (BibTeX)

```bibtex
@article{shi2025toolhijacker,
  title={Prompt Injection Attack to Tool Selection in LLM Agents},
  author={Shi, Jiawen and others},
  journal={arXiv preprint arXiv:2504.19793},
  year={2025}
}
```
