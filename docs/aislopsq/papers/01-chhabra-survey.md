# 01. Chhabra et al. — Agentic AI Security Survey (2025)

## 메타데이터

- **제목**: Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges
- **저자**: Shrestha Datta, Shahriar Kabir Nahin, Anshuman Chhabra (corresponding), Prasant Mohapatra
- **출판**: arXiv preprint
- **arXiv ID**: 2510.23883
- **버전**: v1 (2025-10-27), v2 (2026-02-13), v3 (2026-04-03)
- **URL**:
  - Abstract: https://arxiv.org/abs/2510.23883
  - HTML: https://arxiv.org/html/2510.23883v1
  - PDF: https://arxiv.org/pdf/2510.23883

## Abstract (paraphrase)

agentic AI 시스템은 LLM에 planning, tool use, memory, autonomy를 결합한 자율적 자동화 플랫폼이다. 이 시스템은 web/소프트웨어/물리적 환경에서 작업을 자율적으로 실행하므로 전통적 AI safety나 일반 소프트웨어 보안과 구별되는 새로운 보안 위험을 만들어낸다. 본 서베이는 agentic AI에 특화된 위협 분류, 최근 평가 벤치마크/방법론, 기술적·거버넌스 양 측면의 방어 전략을 종합한다. 저자들은 secure-by-design 에이전트 시스템 개발을 지원할 목적으로 현재 연구 상태를 정리하고 미해결 문제를 제시한다.

## 핵심 내용 발췌 (paraphrase)

### §1 — Agentic AI의 정의와 4요소

전통적 LLM은 prompt에 응답하는 수동적 reactive 시스템이다. 반면 agentic AI는 다음 4요소를 결합한다:

1. **Autonomy** — 사람의 지속적 입력 없이 목표 추구
2. **Goal-directed reasoning & planning** — 다단계 계획 수립
3. **Tool/API/embodiment 액세스** — 디지털·물리 환경에 직접 작용
4. **Persistent memory** — 시간에 걸친 deliberation, 적응

이 4요소는 LangChain, AutoGPT, multi-agent orchestration 라이브러리 같은 ecosystem이 개발자에게 보급한 결과 빠르게 확산됐다. (※ 본 deliverable의 Step 1 agentic 판별은 이 4요소 정의에서 도출됨)

### §3 — 위협 분류

저자들은 agentic AI 보안 위협을 5개 카테고리로 분류한다:

- **§3.1 Prompt Injection & Jailbreaks** — 직접/간접, 의도적/비의도적, 텍스트/이미지/비디오/오디오/하이브리드 모달리티, propagating/non-propagating 등 다차원 분류
- **§3.2 Autonomous Cyber-Exploitation & Tool Abuse** — one-day 취약점 자율 익스플로잇, 자율 웹 해킹, 창발적 도구 오용
- **§3.3 Multi-agent & Protocol-level Threats** — MCP-induced 공격, A2A-induced 공격, 사칭/역할 남용, 협업 조작, 책임 회피, 기밀 데이터 변조/유출
- **§3.4 Interface & Environment Risks** — observation/action space 불일치, 실 환경에서의 perception-action 취약성
- **§3.5 Governance & Autonomy Concerns** — 권한 경계, 감사 추적성, 책임 소재

### §4 — 방어 전략

§4에서 저자들은 prompt-injection-resistant design을 agent-focused, user-focused, system-focused로 구분한다. **system-focused**에는 detection, isolation, prompt augmentation, quality-based 방어가 포함된다. 또한 §4.3에서 sandboxing과 capability confinement를 별도 섹션으로 다룬다.

핵심 관찰: 단일 layer 방어로는 충분하지 않으며, **secure-by-design** 접근이 필요하다. 즉 시스템 설계 단계에서 capability 경계와 신뢰 boundary를 명시적으로 정의해야 한다.

### §6 — 미해결 문제

- §6.1 Long-horizon security (지속 메모리·세션 누적 공격)
- §6.2 Multi-agent 보안 (창발적 collusion, 책임 분산)
- §6.3 평가 벤치마크 개선
- §6.4 Adaptive attack에 대한 안전성 (※ Nasr et al. 2025와 연결됨)
- §6.5 Human-agent 보안 인터페이스

## AISLOPSQ 매핑

| 본 deliverable 항목 | 본 논문에서의 근거 위치 |
|---|---|
| Step 1 — agentic 4요소 판별 | §1 (planning + tool use + memory + autonomy 정의) |
| AGENTIC-SIGNALS.md — agent loop, MCP server 등 강한 신호 | §1 (LangChain/AutoGPT 등 ecosystem 패턴) |
| R3 — undeclared capability를 위협으로 분류 | §3.2 (Tool Abuse), §3.3 (Protocol-level) |
| R4-2 — Memory poisoning | §3.4, §6.1 |
| R4-4 — A2A 미인증 | §3.3 (multi-agent collusion, impersonation) |
| 영향도 라벨링 | §3 전반 (저/중/고 영향 위협 구분) |
| Manifest 사양 — secure-by-design 원리 | §4 (시스템 설계 단계 capability 경계) |

## Claude Code 참조 시 주의사항

이 논문은 **분류 체계와 정의의 standard**다. 구현이 아니라 어휘를 정확히 쓰기 위해 참조한다. 예를 들어 본 deliverable의 capability 어휘 (`mcp-client`, `agent-to-agent` 등) 가 학계의 일반적 표현과 일치하는지 확인할 때 §3.3을 참조하면 된다.

## 직접 인용 (15단어 미만 1회)

서베이는 agentic AI를 "web/소프트웨어/물리적 환경에서 자율적으로 작업을 실행할 수 있는 시스템" (paraphrase) 으로 정의하며 이는 본 deliverable의 Step 1 정의의 직접적 출처이다.

## 인용 형식 (BibTeX)

```bibtex
@article{chhabra2025agentic,
  title={Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges},
  author={Datta, Shrestha and Nahin, Shahriar Kabir and Chhabra, Anshuman and Mohapatra, Prasant},
  journal={arXiv preprint arXiv:2510.23883},
  year={2025}
}
```
