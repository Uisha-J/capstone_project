# 05. Meta AI — Agents Rule of Two (2025)

## 메타데이터

- **제목**: Agents Rule of Two: A Practical Approach to AI Agent Security
- **저자/주체**: Meta AI (저자 명시 없음, Mick Ayzenberg 등 Meta AI security researcher 가 sharing)
- **출판**: Meta AI 공식 블로그
- **출판일**: 2025-10-31
- **URL**: https://ai.meta.com/blog/practical-ai-agent-security/

## Abstract (paraphrase)

LLM에서 prompt injection은 근본적인 미해결 약점이다. 신뢰할 수 없는 문자열이 에이전트의 컨텍스트 윈도우에 들어가면 개발자 지침을 무시하거나 권한 없는 작업을 실행하는 것 같은 의도하지 않은 결과가 발생할 수 있다. Meta는 이 위험에 대응하기 위해 **Agents Rule of Two** 라는 framework를 제안한다. 이 framework는 Chromium의 Rule of 2 정책과 Simon Willison의 "lethal trifecta" 개념에서 영감을 받았다.

## 핵심 framework

> **prompt injection을 신뢰성 있게 탐지/거부할 수 있는 robustness 연구 결과가 나오기 전까지, 에이전트는 한 세션 내에서 다음 세 속성 중 두 개 이하만 보유해야 prompt injection의 최악 시나리오를 피할 수 있다.**

세 속성:

- **[A]** An agent can process untrustworthy inputs (신뢰 불가 입력 처리)
- **[B]** An agent can have access to sensitive systems or private data (민감 시스템/사적 데이터 접근)
- **[C]** An agent can change state or communicate externally (상태 변경 또는 외부 통신)

세 속성이 모두 한 세션에서 필요하면 에이전트는 자율 작동 금지, 최소한 human-in-the-loop 승인 또는 다른 신뢰성 있는 검증 수단으로 감독되어야 한다.

## Email-Bot 사례 분석

공격 시나리오: 스팸 이메일 안의 prompt injection 문자열이 사용자의 Email-Bot에게 받은편지함의 사적 콘텐츠를 수집해 Send-New-Email 도구로 공격자에게 전달하라고 지시.

이 공격이 성공하는 조건:
- [A] 에이전트가 untrusted 데이터 (스팸 이메일) 접근
- [B] 에이전트가 사적 데이터 (받은편지함) 접근
- [C] 에이전트가 외부 통신 (이메일 발송)

방어 옵션 (Rule of Two 적용):

- **[BC] 구성**: 신뢰할 수 있는 발신자 (예: 가까운 친구) 의 이메일만 처리 → injection이 컨텍스트 윈도우에 도달 못함
- **[AC] 구성**: 민감 데이터/시스템 접근 없음 (예: 학습용 테스트 환경) → injection이 닿아도 의미 있는 영향 없음
- **[AB] 구성**: 신뢰할 수 있는 수신자에게만 신메일 발송 또는 인간이 초안 검증 → 공격 체인 완성 차단

## 다른 사례

블로그는 세 hypothetical use case에 적용:

- **Travel Agent Assistant [AB]**: 웹 검색 [A] + 사용자 사적 정보 [B], C 차단을 위해 reservation/payment에 인간 confirmation 요구 + 트러스트 외 URL 호출 금지
- **Web Browsing Research Assistant [AC]**: 임의 URL 요청 [C] + 결과 처리 [A], B 차단을 위해 sandbox 브라우저 + preloaded session 없음 + 사적 정보 접근 제한
- **High-Velocity Internal Coder [BC]**: production 시스템 접근 [B] + stateful 변경 [C], A 차단을 위해 author-lineage 기반 데이터 source 필터링

또한 한 세션 내에서 configuration 전환이 안전할 수 있다는 점을 언급 — 예: [AC]로 인터넷 접근 후 외부 통신 차단하고 [B]로 내부 시스템 접근. 단, 이는 attack chain의 [A]→[B]→[C] 완성을 막아야 안전.

## Limitations (블로그 명시)

저자들은 Rule of Two가 만능이 아님을 강조:
- attacker uplift, 스팸 확산, agent mistakes, hallucinations, 과도한 권한 같은 다른 위협 벡터는 별도 방어 필요
- prompt injection의 저영향 결과 (잘못된 정보 응답 등) 도 별도 처리
- Rule of Two 만족이 끝이 아님 — defense-in-depth 필수
- 사용자가 경고 인터스티셜을 무비판적으로 confirm하는 등 패턴은 여전히 위험
- least-privilege 같은 일반 보안 원리의 supplement이지 substitute가 아님

## 본 framework가 본 deliverable에 미친 영향

Rule of Two는 본 deliverable의 **Step 3 검증 로직과 R2-1 룰의 직접적 근거**다:

1. **Manifest의 `rule_of_two.satisfies` 필드** — 패키지가 어느 두 속성을 갖는지 선언
2. **Step 3** — declared satisfies 와 detected capability의 ABC 사상이 일치하는지 검증
3. **R2-1** — 세 속성 모두 보유 + HITL 부재 시 HIGH_RISK
4. **Capability ABC 사상 표** (CAPABILITY-DETECTION.md §끝) — Meta 블로그의 정의를 패키지 capability 어휘로 옮김

Meta는 이 framework를 Anthropic 같은 다른 frontier lab의 결론과 정렬되는 것으로 본다 — Nasr et al. 2025 와 Beurer-Kellner et al. 2025 모두 동일한 "design-time 보안" 결론에 수렴.

## AISLOPSQ 매핑

| 본 deliverable 항목 | 본 블로그에서의 근거 |
|---|---|
| Manifest `rule_of_two.satisfies` 필드 (`["A","B"]` 등) | 핵심 framework 정의 |
| Manifest `rule_of_two.session_isolation` 필드 | "한 세션 내에서" 조건 + configuration 전환 가능성 |
| Step 3 검증 로직 | 세 속성 보유 시 HITL 필수 |
| R2-1 (Lethal Trifecta) | 세 속성 동시 보유의 위험성 |
| ABC 사상 표 | Email-Bot, Travel Agent 등 사례에서 capability를 ABC로 매핑한 방식 |
| HITL 검출 시그니처 (RULES.md R2-1) | "human-in-the-loop approval" 정의 |

## Claude Code 참조 시 주의사항

본 자료는 **블로그 포스트** 이지 peer-reviewed 논문이 아니다. 그러나:

1. Meta가 자사 production 에이전트 설계에 적용하는 framework
2. Simon Willison의 "lethal trifecta" 와 일관된 근거
3. Nasr et al. 2025 와 Beurer-Kellner et al. 2025 와 결론 정합

따라서 학계와 산업계의 합의로 다룰 수 있다. 본 deliverable에서 인용 시 "Meta AI (Oct 2025), Agents Rule of Two" 형식 사용. arXiv 버전이 향후 출판되면 INDEX.md 업데이트 필요.

framework의 ABC를 capability 어휘로 옮길 때 주의: Meta 블로그는 high-level 추상적 정의 ("untrustworthy inputs", "sensitive systems") 만 제공한다. 본 deliverable의 capability 어휘로 사상하는 것은 본 deliverable의 contribution 중 하나이며, 그 사상은 보수적이어야 한다 (모호하면 양쪽 카테고리에 사상해서 false positive를 허용하는 편이 안전).

## 직접 인용 (15단어 미만 1회)

블로그는 Rule of Two를 "한 세션 내 두 속성 이하 보유" 로 정의한다 (paraphrase from "Agents Rule of Two" section).

## 인용 형식 (BibTeX, 비공식)

```bibtex
@misc{meta2025rule,
  title={Agents Rule of Two: A Practical Approach to AI Agent Security},
  author={{Meta AI}},
  year={2025},
  month={October},
  howpublished={\url{https://ai.meta.com/blog/practical-ai-agent-security/}},
  note={Meta AI Blog}
}
```
