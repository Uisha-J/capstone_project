# 04. Nasr et al. — The Attacker Moves Second (2025)

## 메타데이터

- **제목**: The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections
- **저자**: Milad Nasr (OpenAI), Nicholas Carlini (Anthropic), Chawin Sitawarin (Google DeepMind), Sander V. Schulhoff (HackAPrompt/MATS), Jamie Hayes (DeepMind), Michael Ilie (HackAPrompt), Juliette Pluto (DeepMind), Shuang Song (DeepMind), Harsh Chaudhari (Northeastern), Ilia Shumailov (AI Sequrity), Abhradeep Thakurta (DeepMind), Kai Yuanqing Xiao (OpenAI), Andreas Terzis (DeepMind), Florian Tramèr (ETH Zürich)
- **출판**: arXiv preprint, OpenReview
- **arXiv ID**: 2510.09023
- **버전**: v1 (2025-10-10)
- **URL**:
  - Abstract: https://arxiv.org/abs/2510.09023
  - HTML: https://arxiv.org/html/2510.09023v1
  - PDF: https://arxiv.org/pdf/2510.09023
  - OpenReview: https://openreview.net/forum?id=7B9mTg7z25

## Abstract (paraphrase)

LLM 방어의 robustness를 어떻게 평가해야 하는가? 현재 jailbreak/prompt injection 방어의 평가는 정적인 공격 문자열 집합이나 방어를 고려하지 않은 약한 최적화 방법에만 의존한다. 저자들은 이 평가 방식이 결함이 있다고 주장한다. 대신 방어는 **adaptive attacker** — 방어 설계를 명시적으로 겨냥해 공격 전략을 수정하고 상당한 자원을 들여 목적을 최적화하는 공격자 — 에 대해 평가되어야 한다. gradient descent, 강화학습, random search, human-guided exploration 같은 일반 최적화 기법을 체계적으로 튜닝/스케일링해서, 저자들은 12개 최근 방어를 대부분 ASR 90% 이상으로 우회한다 — 원래 논문들이 거의 0%의 공격 성공률을 보고했음에도. 미래의 방어 연구는 본 논문이 제시하는 강한 공격을 고려해야 robustness 주장을 신뢰성 있게 할 수 있다.

## 핵심 결과

저자들은 4 카테고리의 방어 (Prompting, Training, Filtering, Model Secret Knowledge) 에 걸쳐 12개 방어 기법을 평가:

- **Prompting**: Spotlighting, Prompt Sandwich, RPO
- **Training**: Circuit Breaker, StruQ, MetaSecAlign
- **Filtering**: Protect AI Detector, PromptGuard, PIGuard, Model Armor, Data Sentinel
- **Model Secret Knowledge**: MELON

원 논문들이 보고한 결과는 대부분 ASR 0-15% 수준. 본 논문의 adaptive 공격으로는 대부분 90-100% ASR.

특히 강조할 점:
- BERT 기반 detector (Protect AI, PromptGuard, PIGuard, Model Armor)는 모두 search-based adaptive attack에 의해 동시에 우회됨 — vision adversarial example 시대에 알려진 패턴 (classifier + detector 동시 우회) 의 LLM 버전
- **Human red-teaming** 은 모든 시나리오에서 성공 — 자동화 공격이 미흡한 부분도 인간 공격자가 채움
- Adaptive 평가는 어렵지만, 그렇기에 더 중요함

## 본 논문이 본 deliverable에 미친 영향

이 논문은 본 AISLOPSQ 표준의 **존재 이유**를 학술적으로 정당화한다:

> **runtime classifier·filter 기반 prompt injection 방어는 신뢰할 수 없다. 따라서 보안은 시스템 설계 단계에서 capability 경계를 좁히는 방식으로 풀어야 한다.**

이 논리는 다음과 같이 본 deliverable로 이어진다:

1. runtime 방어가 신뢰 불가능 → 사전(install-time) 검증 layer가 필요
2. 사전 검증은 패키지 작성자의 declared capability에 의존
3. declared와 detected의 차이가 곧 보안 신호
4. → AISLOPSQ Manifest

이 논리는 Beurer-Kellner et al. 2025 와도 정합적이다 (둘 다 "system-level isolation이 필요하다" 결론). Meta Agents Rule of Two 도 본 논문을 명시적으로 인용하며 같은 결론에 도달한다.

## AISLOPSQ 매핑

| 본 deliverable 항목 | 본 논문에서의 근거 |
|---|---|
| Manifest 표준의 존재 이유 | Abstract + 결론 — runtime 방어 한계 |
| R1 룰 전체 — design pattern 면책에 의존 | filtering 단독 방어 부족 → 구조적 방어 필수 |
| Step 3 Rule of Two 정당화 | runtime 검출 불가능 → 설계 단계 capability 제한 |
| 졸업과제 contribution narrative | 본 논문의 결론 + Beurer-Kellner 2025 |

## Claude Code 참조 시 주의사항

이 논문은 **defensive 결론**을 강조하기 위해 인용한다 — 즉 "왜 우리가 패키지 레벨 manifest를 만드는가"의 논거. 공격 기법 자체는 본 deliverable과 직접 관련 없음.

또한 본 논문이 미래의 방어가 어떤 평가를 거쳐야 하는지에 대한 가이드라인도 제공한다 (논문 §끝). 본 deliverable은 runtime 방어를 직접 만들지 않으므로 이 가이드라인을 따르지 않지만, AISLOPSQ를 evaluation할 때는 declared/detected 간 mismatch를 일으키는 adversarial 패키지를 구성해서 검사기의 detection rate를 측정하는 방식이 동등한 접근이 된다.

## 직접 인용 (15단어 미만 1회)

저자들은 12개 방어를 "search-based adaptive attack으로 ASR 90% 이상" 으로 우회했다고 보고한다 (paraphrase from §1, Figure 1).

## 인용 형식 (BibTeX)

```bibtex
@article{nasr2025attacker,
  title={The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections},
  author={Nasr, Milad and Carlini, Nicholas and Sitawarin, Chawin and Schulhoff, Sander V. and Hayes, Jamie and Ilie, Michael and Pluto, Juliette and Song, Shuang and Chaudhari, Harsh and Shumailov, Ilia and Thakurta, Abhradeep and Xiao, Kai Yuanqing and Terzis, Andreas and Tram{\`e}r, Florian},
  journal={arXiv preprint arXiv:2510.09023},
  year={2025}
}
```
