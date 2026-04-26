# AISLOPSQ — Agentic Package Security Standard

졸업과제 deliverable. npm/PyPI 패키지 중 **agentic** 한 패키지를 식별하고, 그에 맞는 보안 기준을 적용하기 위한 표준·룰셋·근거 논문 묶음.

## 무엇을 다루는가

기존 패키지 정적 분석은 47-indicator 룰셋으로 `MALICIOUS / HIGH_RISK / SUSPICIOUS / CLEAN` 4 verdict를 산출한다. 그러나 LLM 기반 자율 에이전트(planning + tool use + memory + autonomy)를 포함하는 패키지는 기존 룰셋만으로는 위험을 충분히 식별할 수 없다. 이는 학계의 합의이며, 이 deliverable의 모든 룰은 인용된 논문에 근거를 둔다.

이 deliverable은 다음을 정의한다:

1. **`AGENTIC` verdict** — 기존 4 verdict에 추가되는 새 분류
2. **AISLOPSQ Manifest 표준** — 패키지 작성자가 declared capability를 명시하는 메커니즘 (npm/PyPI)
3. **Agentic 자동 판별 신호** — manifest가 없는 경우의 fallback 검출 룰
4. **Capability detection 매핑** — Python/JavaScript 정적 분석으로 detected capability 추출
5. **4 카테고리 룰셋** — Prompt Injection / Sandbox Escape / Undeclared Capability / Hidden Side Channel
6. **결정 트리** — 위 요소들을 결합한 verdict 결정 로직

## 파일 구조

```
aislopsq/
├── README.md                              # (this file)
├── spec/
│   ├── AISLOPSQ-MANIFEST-SPEC.md         # manifest 표준 사양
│   ├── DECISION-TREE.md                  # 분류 결정 트리
│   └── RULES.md                          # 4 카테고리 룰 상세
├── detection/
│   ├── AGENTIC-SIGNALS.md                # agentic 자동 판별 신호
│   └── CAPABILITY-DETECTION.md           # npm/PyPI capability 매핑
└── papers/
    ├── INDEX.md                          # 논문 인덱스 + 룰-논문 매핑
    ├── 01-chhabra-survey.md              # arXiv:2510.23883
    ├── 02-beurer-kellner-design-patterns.md  # arXiv:2506.08837
    ├── 03-toolhijacker.md                # arXiv:2504.19793
    ├── 04-attacker-moves-second.md       # arXiv:2510.09023
    └── 05-meta-agents-rule-of-two.md     # Meta blog (Oct 2025)
```

## Claude Code에서 이 deliverable을 사용하는 법

이 deliverable의 모든 룰은 `papers/`의 핵심 발췌본에 근거를 둔다. Claude Code(또는 다른 에이전트형 코딩 도구)가 이 묶음을 참조해서 검사기를 구현할 때, 다음 순서로 참조하면 된다:

1. **`spec/DECISION-TREE.md`** 를 먼저 읽고 전체 흐름 이해
2. 각 단계에서 인용된 논문 카드 (`papers/0X-*.md`)를 직접 열어 근거 확인
3. 룰 구현 시 `detection/CAPABILITY-DETECTION.md` 의 매핑 테이블을 정적 분석 룰로 변환
4. 모호한 부분은 `papers/INDEX.md` 의 룰-논문 매핑에서 해당 논문을 찾아 원문(arXiv URL 첨부됨) 확인

각 논문 카드는 abstract + 핵심 섹션 + 이 deliverable의 어느 룰에 근거가 되는지를 명시한다.

## 적용 시나리오

```
입력: npm/PyPI 패키지
  │
  ├─ Step 1: Agentic 판별 (manifest 또는 자동 신호)
  │            │
  │            ├─ NO  → 기존 47-indicator 파이프라인
  │            └─ YES → Step 2
  │
  ├─ Step 2: Manifest 정직성 검증
  │            declared ⊇ detected → 진행
  │            declared ⊊ detected → SUSPICIOUS / MALICIOUS
  │
  └─ Step 3: 4 카테고리 룰셋 (R1-R4) 적용
                  │
                  └─ 최종 verdict: AGENTIC / HIGH_RISK / SUSPICIOUS / MALICIOUS
```

상세는 `spec/DECISION-TREE.md` 참조.

## 표준화 contribution

AISLOPSQ Manifest는 npm/PyPI 어디에도 존재하지 않는 새 표준이다. 이 표준의 핵심 아이디어는 학계 합의에서 직접 도출된다:

- Meta Agents Rule of Two (2025): "prompt injection은 미해결 문제이며, 시스템 설계 단계에서 가정하고 만들어야 한다"
- Beurer-Kellner et al. (2025): "에이전트가 신뢰 불가 입력을 처리한 후엔 결과적 행동 능력이 엄격히 제한되어야 한다"
- Nasr et al. (2025): "12개 방어 기법이 적응적 공격에 모두 90%+ ASR로 우회됨 — runtime 필터링은 신뢰할 수 없다"

따라서 **패키지 레벨에서 capability 경계를 사전에 선언·검증**하는 것이 현재 시점의 가장 신뢰할 수 있는 방어 layer다. 이 deliverable의 contribution은 그 정책을 supply chain 분석 도구가 강제할 수 있는 형태로 구체화하는 것이다.
