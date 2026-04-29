# LLM Cost Model

> Stage 5 (LAMPS multi-agent LLM review) 의 운영 비용 추산.
> 본 모델은 [9주차 LLM mode 평가 보고서](../reports/9주차_LLM모드_평가_보고서.md)
> 의 실측치 (100 fixture × 3 agent = 300 calls, ~$5.4) 를 기반으로 함.

## 1. 호출당 토큰 (실측)

| 항목 | 토큰 (평균) | 비고 |
|---|---|---|
| Input — system prompt + 컨텍스트 | ~3,500 | 매 agent 호출 시 동일 system prompt 재전송 (캐시 미적용) |
| Input — package code snippet | ~1,500 | 패키지 첫 30 라인, taint slice |
| Input — version diff summary | ~200 | 있을 때만 |
| **Input total / call** | **~3,500–5,200** | (sequence/diff/dependency 각각 다름) |
| **Output / call** | **~400–600** | JSON 응답 (verdict/reasoning/evidence) |

## 2. 가격표 (2026-04 기준)

| 모델 | Input ($/1M) | Output ($/1M) | Cached input ($/1M) |
|---|---|---|---|
| Claude Sonnet 4.5 | 3.00 | 15.00 | 0.30 |
| Claude Haiku 4.5 | 0.80 | 4.00 | 0.08 |
| OpenAI GPT-4o | 2.50 | 10.00 | 1.25 |
| OpenAI GPT-4o-mini | 0.15 | 0.60 | 0.075 |

LAMPS 는 1 fixture 당 3 agent 호출 (semantic / diff / dependency).

## 3. 호출당 비용 (실측)

| 모델 | 호출 1회 | fixture 1개 (3 agent) |
|---|---|---|
| **Claude Sonnet 4.5** (cache 0%) | $0.018 | **$0.054** |
| Claude Sonnet 4.5 (cache 80% on system prompt) | $0.011 | $0.033 |
| Claude Haiku 4.5 (cache 0%) | $0.005 | $0.015 |
| GPT-4o-mini (cache 0%) | $0.001 | $0.003 |

> 9주차 보고서의 100 fixture 평가 = $5.4 = $0.054/fixture × 100 (Sonnet 4.5,
> cache 0%) — 모델 일치.

## 4. 일일 / 월간 운영 시나리오

가정:
- 신규 PyPI 패키지 ≈ **1,500 / 일**, npm ≈ **500 / 일** (PyPI Stats / npm
  Registry stats 의 2026-04 평균)
- 모든 신규 패키지를 LLM mode 로 분석 (worst case)
- 실제로는 cache hit 으로 *재분석은 무료* — 첫 분석만 비용 발생

### 4.1 일일 비용 (2,000 신규/일, 100% LLM 분석 가정)

| 모델 | cache 0% | cache 50% | cache 80% (prompt cache) |
|---|---|---|---|
| Sonnet 4.5 | $108/일 | $54 | $22 |
| Haiku 4.5 | $30/일 | $15 | $6 |
| GPT-4o-mini | $6/일 | $3 | $1.2 |

### 4.2 월간 비용 (= 일일 × 30)

| 모델 | cache 0% | cache 50% | cache 80% |
|---|---|---|---|
| Sonnet 4.5 | **$3,240** | $1,620 | **$660** |
| Haiku 4.5 | $900 | $450 | $180 |
| GPT-4o-mini | $180 | $90 | $36 |

> 학교 capstone 운영 가정: Sonnet 4.5 + 80% prompt cache = **월 $660**.
> 상용 서비스로는 Haiku 4.5 + cache 가 합리적 ($180/월).

## 5. 캐시 전략

### 5.1 분석 결과 캐시 (`db/analysis_cache.py` + `db/stage_cache.py`)

핵심: **동일 패키지 + 동일 버전 + 동일 archive sha256 → LLM 호출 0**.

6-trigger 무효화:
1. `engine_version` (pkgsentinel 코드 변경)
2. `rules_version` (indicator_matcher 룰 해시)
3. `kb_version` (CVE/OSV 지식베이스)
4. `feed_version` (threat feed 갱신)
5. `archive_sha256` 미스매치 (재배포 / 변조)
6. `cache_invalidation_log` 신규 advisory

Stage-level 캐시 (`stage_cache` 테이블) 는 단계별 결과를 분리 저장해 *부분
무효화* 지원. 예: OSV 갱신 시 `stage_0a_threat_filter` / `stage_0b_attack_history`
만 재계산, Stage 5 (LLM) 는 보존.

> **Stage 5 (LLM) 자체는 캐시하지 않음** — 동일 입력에도 모델이 다른 응답을
> 줄 수 있고, 재현 불가능한 응답을 캐시하면 디버깅이 어려움.
> 대신 LLM 결과를 포함한 *전체 report* 가 `analyses` 테이블에 저장되고
> archive sha256 으로 검증.

### 5.2 Anthropic Prompt Cache (5분 TTL)

- 시스템 프롬프트 + few-shot 부분만 캐싱 → input 토큰의 60-80% 캐싱 가능
- 캐싱된 부분은 90% 할인 ($3 → $0.30/1M)
- 동시 worker 수 ≥ 2 면 5분 내 재사용 확률 높음

본 모델의 `cache 80%` 는 prompt cache 적용 시점.

### 5.3 cache hit rate 가정의 현실성

신규 패키지가 정말 매일 2,000개씩 들어오면 cache hit 거의 0%.
하지만:

- 같은 패키지의 **다른 버전** 이 자주 분석됨 (prompt cache 50%+ 효과)
- 시스템 prompt + few-shot 은 **영구 동일** → cache 항상 hit
- 위 두 요소만으로 80% 시나리오에 가까움

## 6. 비용 절감 옵션 (가성비 순)

| 옵션 | 절감 | 영향 |
|---|---|---|
| Sonnet → Haiku 4.5 | -73% | F1 추정 -0.05 (smoke 측정 필요) |
| Prompt cache (system + few-shot) | -50~70% | 0 (응답 동일) |
| LLM 호출을 SUSPICIOUS 후보만 (게이팅) | -80~90% | Recall 보존 (사전 매처 필터) |
| Stage 5 캐싱 (deterministic 모드) | -100% (재분석 시) | 응답 재현성 trade-off |
| GPT-4o-mini A/B | -94% | F1 미측정 |

가장 안전한 조합: **Sonnet 4.5 + prompt cache + 사전 매처 게이팅** →
500 신규/일 정도만 LLM 호출 → 월 ~$80 (Sonnet 가격에서 cache + gating 으로 -75%).

## 7. 실측 검증

[9주차 LLM 평가 보고서](../reports/9주차_LLM모드_평가_보고서.md) §5 참조.
- 100 fixture / 11분 / $5.4 (Sonnet 4.5, cache 0%)
- F1 stub 0.83 → claude+rule 0.94

## 참고

- Anthropic 가격: <https://www.anthropic.com/pricing>
- OpenAI 가격: <https://openai.com/api/pricing/>
- Anthropic prompt cache: <https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching>
- PyPI 일일 신규 패키지 통계: <https://pypistats.org/>
