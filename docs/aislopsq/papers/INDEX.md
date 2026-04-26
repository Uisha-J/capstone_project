# Papers Index

이 디렉터리는 AISLOPSQ 표준의 모든 룰의 학술적 근거를 제공한다. Claude Code (또는 다른 코딩 에이전트) 가 검사기를 구현할 때, 각 룰의 의도를 정확히 이해하기 위해 해당 논문 카드를 직접 참조해야 한다.

각 카드는 다음을 포함한다:
- 메타데이터 (저자, 출판처, arXiv URL)
- Abstract (paraphrase)
- 핵심 섹션 발췌 (paraphrase, ≤15 단어 직접 인용 시 표시)
- AISLOPSQ deliverable 어느 룰에 매핑되는지

원문 PDF는 직접 참조 (각 카드의 URL).

---

## 카드 목록

| # | 카드 파일 | 저자/출판 | arXiv ID | 매핑되는 룰 |
|---|---|---|---|---|
| 1 | `01-chhabra-survey.md` | Chhabra et al., Survey 2025 | 2510.23883 | Step 1 (agentic 정의), R3 (capability 분류), 영향도 라벨링 |
| 2 | `02-beurer-kellner-design-patterns.md` | Beurer-Kellner et al., 2025 | 2506.08837 | R1 전반, design pattern 면책 |
| 3 | `03-toolhijacker.md` | Shi et al., 2025 | 2504.19793 | R1-2, manifest tool_registry 정책 |
| 4 | `04-attacker-moves-second.md` | Nasr et al., 2025 | 2510.09023 | "filtering 신뢰성 없음" 근거 → manifest 기반 사전 검증 정당화 |
| 5 | `05-meta-agents-rule-of-two.md` | Meta AI, Oct 2025 | (blog) | Step 3 Rule of Two, R2-1 Lethal Trifecta |

---

## 룰별 근거 매핑 (역방향 인덱스)

### Step 1: Agentic 판별

- **agentic의 4요소 정의 (planning + tool use + memory + autonomy)**: Chhabra et al. 2025 §1, §2 → `01-chhabra-survey.md`

### Step 2: Manifest declared vs detected

- **Tool Misuse and Exploitation을 핵심 위협으로 지정**: OWASP Top 10 for Agentic Applications 2025 (genai.owasp.org) — 본 deliverable에서는 INDEX 외부 표준으로 인용
- **Identity and Privilege Abuse**: 동상

### Step 3: Rule of Two

- **A/B/C 3속성 framework**: Meta AI 2025 → `05-meta-agents-rule-of-two.md`
- **Lethal Trifecta 기반**: Simon Willison "lethal trifecta" (2025-06) — Meta가 명시적으로 인용
- **filtering으로는 prompt injection을 막을 수 없다**: Nasr et al. 2025 → `04-attacker-moves-second.md`

### R1: Prompt Injection 가능성

- **R1-1 (격리 부재)**: Beurer-Kellner et al. 2025 §3 (Dual LLM, Map-Reduce, Context-Minimization 패턴) → `02-beurer-kellner-design-patterns.md`
- **R1-2 (tool selection 무결성)**: Shi et al. 2025 → `03-toolhijacker.md`
- **R1-3 (검색 결과 직접 주입)**: Beurer-Kellner et al. 2025 (Plan-Then-Execute) → `02-beurer-kellner-design-patterns.md`
- **R1-4 (자유형 실행)**: Beurer-Kellner et al. 2025 (Action-Selector, Code-Then-Execute) → `02-beurer-kellner-design-patterns.md`

### R2: Sandbox Escape

- **R2-1 (Lethal Trifecta)**: Meta 2025 → `05-meta-agents-rule-of-two.md`; Chhabra et al. 2025 §3 → `01-chhabra-survey.md`
- **R2-2~R2-4**: 일반 보안 룰 + Chhabra et al. 2025 (autonomy로 인한 공격 표면 확장)

### R3: Undeclared Capability

- **OWASP Top 10 Agentic 2025 — Tool Misuse, Privilege Abuse**: 외부 표준
- **declared 범위 초과는 곧 위협**: Chhabra et al. 2025 §3.2

### R4: Hidden Side Channel

- **R4-1 (covert log exfiltration)**: Lin et al. 2025 (Log-To-Leak, OpenReview) — 본 deliverable에서는 INDEX 외부 표준으로 인용 (URL: `https://openreview.net/forum?id=UVgbFuXPaO`)
- **R4-2 (memory poisoning)**: Chhabra et al. 2025 → `01-chhabra-survey.md`
- **R4-3 (provenance/audit log 부재)**: NVIDIA-Lakera 2025 framework (Help Net Security 2025-12-08) — 본 deliverable에서는 외부 인용
- **R4-4 (A2A 미인증)**: Chhabra et al. 2025 (multi-agent collusion)
- **R4-5 (description-behavior mismatch)**: Shi et al. 2025 (ToolHijacker 일반화) → `03-toolhijacker.md`

---

## 외부 인용 (카드 미작성, URL만 제공)

본 deliverable은 다음 자료를 인용하지만 별도 카드를 작성하지 않는다. Claude Code가 직접 참조할 수 있도록 URL만 제공:

- **OWASP Top 10 for Agentic Applications (2025-12-09)**: https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/
- **Log-To-Leak (Lin et al. 2025, OpenReview)**: https://openreview.net/forum?id=UVgbFuXPaO
- **NVIDIA-Lakera Agentic Safety Framework (2025-12)**: https://www.helpnetsecurity.com/2025/12/08/nvidia-agentic-ai-security-framework/
- **From prompt injections to protocol exploits (ScienceDirect 2025)**: https://www.sciencedirect.com/science/article/pii/S2405959525001997
- **From threat to trust (Springer IJIS 2026)**: https://link.springer.com/article/10.1007/s10207-025-01185-y
- **Simon Willison, Lethal Trifecta (2025-06)**: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- **Meta SecAlign (Chen et al. 2025)**: https://arxiv.org/abs/2507.02735

---

## Claude Code 사용 패턴 (예시)

```
[코드 작성 task: "AISLOPSQ Step 1 자동 판별 로직을 Python으로 구현"]

1. spec/DECISION-TREE.md 의 Step 1 정의 확인
2. detection/AGENTIC-SIGNALS.md 의 가중치 표 확인
3. papers/01-chhabra-survey.md 의 §2 (agentic 4요소 정의) 확인 →
   왜 LLM SDK 의존성만으로는 부족한지 이해
4. 구현
```

```
[코드 작성 task: "R1-2 tool selection 무결성 검사 로직"]

1. spec/RULES.md 의 R1-2 시그니처 확인
2. papers/03-toolhijacker.md 확인 → 공격 메커니즘 정확히 이해 →
   왜 retrieval과 selection 단계 모두 검증해야 하는지 파악
3. detection/CAPABILITY-DETECTION.md 의 dynamic-tool-load 시그니처 확인
4. 구현
```
