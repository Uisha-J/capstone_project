# 02. Beurer-Kellner et al. — Design Patterns for Securing LLM Agents (2025)

## 메타데이터

- **제목**: Design Patterns for Securing LLM Agents against Prompt Injections
- **저자**: Luca Beurer-Kellner (Invariant Labs), Beat Buesser (IBM), Ana-Maria Creţu (EPFL), Edoardo Debenedetti (ETH Zurich), Daniel Dobos (Swisscom), Daniel Fabian (Google), Marc Fischer (Invariant Labs), David Froelicher (Swisscom), Kathrin Grosse (IBM), Daniel Naeff (ETH AI Center), Ezinwanne Ozoani (AppliedAI Institute for Europe), Andrew Paverd (Microsoft), Florian Tramèr (ETH Zurich), Václav Volhejn (Kyutai)
- **출판**: arXiv preprint
- **arXiv ID**: 2506.08837
- **버전**: v1 (2025-06-10)
- **URL**:
  - Abstract: https://arxiv.org/abs/2506.08837
  - HTML: https://arxiv.org/html/2506.08837v1
  - PDF: https://arxiv.org/pdf/2506.08837
- **License**: CC BY 4.0

## Abstract (paraphrase)

LLM 기반 AI 에이전트가 다양한 작업을 처리하는 만능 시스템으로 진화하면서 보안 확보가 핵심 과제로 떠올랐다. 가장 시급한 위협 중 하나가 prompt injection 공격이며, 이는 자연어 입력에 의존하는 에이전트의 본질적 약점을 악용한다 — 특히 도구 접근권이나 민감 정보를 다룰 때 위험하다. 본 논문은 prompt injection에 입증 가능한 저항성을 갖는 AI 에이전트를 만들기 위한 원칙 기반 design pattern들을 제안한다. 저자들은 이 패턴들을 체계적으로 분석하고 utility/security 트레이드오프를 논의하며, 10개 case study를 통해 실제 적용 가능성을 보여준다.

## 핵심 원리

저자들의 design pattern들은 공통된 가이딩 원리를 공유한다 (논문 §3 도입부 paraphrase):

> **에이전트가 신뢰할 수 없는 입력을 처리한 이후에는 결과적 행동을 취하는 능력이 의도적으로 제한되어야 한다 — 특히 도구 사용, 민감 데이터 접근, 시스템 상태 변경을 동반하는 행동의 경우.**

이 원리는 본 AISLOPSQ 표준의 R1 룰 전체와 manifest 의 `design_patterns.applied` 필드의 직접적 근거다.

## §3.1 — 6개 design pattern

### Pattern 1: Action-Selector

LLM이 사전 승인된 액션 목록에서만 선택. 임의의 tool call이나 자유형 명령 생성 불가. injection이 "이 명령을 실행해" 라고 시켜도 enum 밖이면 시스템적으로 거부됨.

→ **AISLOPSQ R1-2, R1-4 면책 근거**

### Pattern 2: Plan-Then-Execute

모델이 한 단계에서 plan을 생성하고, 별도 단계에서 실행. 핵심: tool 출력이 plan을 변경할 수 없음. injection이 tool 출력에 들어와도 이미 결정된 plan을 못 바꿈.

→ **AISLOPSQ R1-3 부분 면책, R2-1 (Lethal Trifecta) 부분 완화 근거**

### Pattern 3: LLM Map-Reduce

신뢰 불가 외부 데이터를 격리된 LLM 인스턴스(들)에서 map 처리. 그 결과를 reduce 단계에서 신뢰 layer로 통합. map 단계 LLM은 권한 없는 sandbox에서 실행됨.

→ **AISLOPSQ R1-1 면책 근거**

### Pattern 4: Dual LLM

privileged LLM과 quarantined LLM 분리. quarantined LLM은 신뢰 불가 입력을 처리하지만 도구 접근 없음. privileged LLM은 도구 접근하지만 신뢰 불가 입력을 직접 받지 않음. 두 LLM 사이는 structured data 형식으로만 통신.

→ **AISLOPSQ R1-1, R1-3 면책 근거**

### Pattern 5: Code-Then-Execute

LLM이 코드를 한 번 생성, 격리된 실행 환경에서 실행, 출력은 sanitize. LLM이 매 step마다 결정하지 않으므로 injection 영향이 격리됨.

→ **AISLOPSQ R1-4 부분 면책 근거 (sandbox와 결합 시)**

### Pattern 6: Context-Minimization

신뢰 불가 콘텐츠가 민감한 결정 시점에 컨텍스트 윈도우에 없음. 즉, 외부 데이터를 본 LLM과 민감 액션을 결정하는 LLM이 다른 시점/세션에 동작.

→ **AISLOPSQ R4-3 (provenance) 면책 근거, Meta Rule of Two의 session_isolation과 연결**

## §4 — Case Studies (10개)

저자들은 10개 실제 시나리오에 패턴을 적용해 실용성을 보여준다:

1. OS Assistant with Fuzzy Search
2. SQL Agent
3. Email & Calendar Assistant
4. Customer Service Chatbot
5. Booking Assistant
6. Product Recommender
7. Resume Screening Assistant
8. Medication Leaflet Chatbot
9. Medical Diagnosis via LLM Intermediary
10. Software Engineering Agent

각 case study는 위협 모델을 정의한 뒤 여러 design 옵션을 비교한다. 본 deliverable의 실제 적용 시나리오 (예: SE Agent 카테고리) 작성 시 §4.10 참조 권장.

## 본 논문의 학계 contribution

이 논문이 본 deliverable의 핵심 근거가 되는 이유:

1. **방어가 미해결 문제임을 인정**한다 — runtime detection/filtering으로는 prompt injection을 막을 수 없으니 시스템 구조로 풀어야 한다는 결론 (※ Nasr et al. 2025 가 이 결론을 강력히 뒷받침).
2. **utility/security 트레이드오프를 명시적으로** 다룬다 — 어떤 패턴은 에이전트의 자유도를 줄임으로써 안전을 얻는다.
3. **case study 기반 검증** — 추상적 원리만이 아니라 실제 패턴이 어디까지 보호하고 어디서 부족한지 실증적으로 보여줌.

## AISLOPSQ 매핑

| 본 deliverable 항목 | 본 논문에서의 근거 |
|---|---|
| `design_patterns.applied` 필드의 6개 값 | §3.1 — 6개 패턴 |
| R1-1 (격리 부재 검출) | §3.1 P3 (Map-Reduce), §3.1 P4 (Dual LLM) |
| R1-2 (tool selection) | §3.1 P1 (Action-Selector) |
| R1-3 (sanitization 부재) | §3.1 P2 (Plan-Then-Execute) |
| R1-4 (자유형 실행) | §3.1 P1 (Action-Selector), §3.1 P5 (Code-Then-Execute) |
| 면책 효과 표 (RULES.md §끝) | §3.1 + §4 case studies 분석 |
| Manifest의 secure-by-design 원리 | §3 도입부의 가이딩 원리 |

## Claude Code 참조 시 주의사항

design pattern 이름을 manifest에서 그대로 사용한다 (`action-selector`, `plan-then-execute`, `llm-map-reduce`, `dual-llm`, `code-then-execute`, `context-minimization`). 이름은 본 논문의 §3.1 표제와 일치시켜 표준화. 새 패턴이 미래에 추가될 경우 본 논문의 명명 규칙 (kebab-case, 동사+명사) 준수.

또한 본 논문은 패턴을 **선언만으로** 인정하지 않는다. case study에서 보듯 패턴 적용은 **구조적**으로 보장되어야 하며 (예: 두 LLM 인스턴스가 실제로 분리됨), 단순히 prompt에 "you are quarantined"라고 쓰는 것으로는 부족하다. 정적 분석 도구는 manifest 선언과 코드 구조 양쪽을 검증해야 한다.

## 직접 인용 (15단어 미만 1회)

저자들의 가이딩 원리는 "신뢰 불가 입력 처리 후 결과적 행동을 의도적으로 제한"으로 요약된다 (paraphrase from §3 introduction).

## 인용 형식 (BibTeX)

```bibtex
@article{beurerkellner2025design,
  title={Design Patterns for Securing LLM Agents against Prompt Injections},
  author={Beurer-Kellner, Luca and Buesser, Beat and Cre{\c{t}}u, Ana-Maria and Debenedetti, Edoardo and Dobos, Daniel and Fabian, Daniel and Fischer, Marc and Froelicher, David and Grosse, Kathrin and Naeff, Daniel and Ozoani, Ezinwanne and Paverd, Andrew and Tram{\`e}r, Florian and Volhejn, V{\'a}clav},
  journal={arXiv preprint arXiv:2506.08837},
  year={2025}
}
```
