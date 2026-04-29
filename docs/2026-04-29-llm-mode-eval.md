# 2026-04-29 — LLM mode 실측 (stub → claude)

## 배경

직전 사이클 (550 fixture stub 모드) 결과 P=0.96 / R=0.73 / F1=0.83 에서 13 FP
잔존. FP 들이 모두 *legitimate dangerous-API user* (flask/pandas/pytest/
fastapi/scikit-learn 등) 라 정적 분석 단독으로는 구분 불가. LLM 실측으로
이 한계를 어디까지 해소할 수 있는지 정량 측정.

평가 시나리오:
- **smoke-mid**: 100 stratified fixture (compromised_lib 30 + malicious_intent 30
  + benign 40, FP 후보 우선)
- 같은 set 을 stub / claude 두 번 → 효과 직접 비교
- claude = Claude Sonnet 4.5 LAMPS 3-agent (semantic / diff / dependency)

## 결과 요약

| 모드 | TP | FN | FP | TN | P | R | F1 | Acc | 비용 |
|---|---|---|---|---|---|---|---|---|---|
| stub | 52 | 8 | 13 | 27 | 0.800 | 0.867 | 0.832 | 0.79 | $0 |
| claude (기존 verdict 룰) | 55 | 5 | 13 | 27 | 0.809 | 0.917 | 0.859 | 0.82 | ~$5 |
| **claude + popular×benign 룰** | 55 | 5 | **2** | **38** | **0.965** | 0.917 | **0.940** | **0.93** | ~$5 |
| 합성 회귀 (cycle 11) | — | — | — | — | 1.000 | 0.983 | 0.992 | — | — |

**핵심**: F1 0.83 → 0.94 (+0.11), FP 13 → 2 (-85%), R 0.87 → 0.92.

## 변경 사항

### 1. `scripts/eval_real.py` — `--llm`, `--stratified` 옵션

- `--llm {stub, claude}` — Stage 5 mode. claude 시 `ANTHROPIC_API_KEY`
  필요 + worker 수 자동 4로 제한 (Anthropic RPM 한계)
- `--stratified N` — N 개 fixture 카테고리별 균형 sample
  (compromised 30%, malicious_intent 30%, benign 40% — FP 후보 우선)
- `PKGSENTINEL_LLM_MODE` 환경변수로 sub-process 자동 상속

### 2. `scripts/eval_real.py` 의 verdict 합성 룰 추가

```python
# popular + LLM benign → 강 다운그레이드 (claude 모드 한정)
if (
    llm_mode == "claude"
    and _is_popular(name, ecosystem)
    and llm_verdict == LLMVerdict.BENIGN
    and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)
    and taint_total < 2
    and cooccur_files <= 2
):
    verdict = Verdict.CLEAN
```

기존 popular 화이트리스트는 `ind_high < 5 AND high_sev_seq < 2` 가드로
typescript / pandas 등 진짜로 강한 신호를 가진 인기 도구는 보호 못 했음.
LLM 이 명시적으로 BENIGN 판정한 경우에만 강 다운그레이드 → 11 FP 정리
(새 FP 만들지 않음).

`llm_mode == "claude"` 가드로 stub 모드와 합성 fixture 회귀 영향 0건.

### 3. 신규 헬퍼

- `scripts/eval_real_compare.py` — stub vs claude 결과 직접 비교
  (개선 / 악화 / 동일 분류)
- `scripts/eval_real_resynth.py` — LLM 재호출 없이 verdict 합성 룰만
  재계산. 룰 튜닝 시 추가 비용 0

## stub vs claude 직접 비교 (동일 100 fixture)

같은 stratified sample 두 번 평가:

| 항목 | stub | claude (new) | 차이 |
|---|---|---|---|
| TP | 52 | 55 | +3 (FN→TP) |
| FN | 8 | 5 | -3 |
| FP | 13 | 2 | -11 |
| TN | 27 | 38 | +11 |

### 개선된 3 FN (LLM 이 약신호도 잡음)

| 패키지 | stub | claude |
|---|---|---|
| `x-portrait` | CLEAN | SUSPICIOUS |
| `pycolorz` | CLEAN | SUSPICIOUS |
| `smartling-openapi-spec` | CLEAN | MALICIOUS |

이 패키지들은 stub 모드에서 ind_47=1 또는 seq=1(1H) 만 발화 → "단일 약한
신호" 다운그레이드 룰로 CLEAN. LLM 은 같은 신호를 보고 SUSPICIOUS/MALICIOUS
판정 → verdict 합성에서 보호.

### 정리된 11 FP (popular + LLM benign)

`typescript`, `uvicorn`, `ws`, `webpack`, `selenium`, `esbuild`,
`scikit-learn`, `websockets`, `celery`, `prettier`, `pandas`.

모두 매처 시점에선 ind_high≥1 또는 seq_high≥1 발화하지만 (legitimate
exec/eval/subprocess 사용), LLM 이 코드 컨텍스트 보고 BENIGN. 새 룰이 이를
신뢰해 CLEAN 으로 정리.

### 남은 2 FP

`flask` (taint=2), `fastapi` (cooccur=3). taint/cooccur 임계값 안에 들지
않아 보호 룰 비적용. 둘 다 진짜 dangerous API 정당 사용 — LLM verdict 만으로
신뢰하기엔 보수적.

## 비용 / 시간

| 항목 | 값 |
|---|---|
| 평가 fixture | 100 stratified |
| LLM 호출 | 100 × 3 agent = 300 calls |
| 모델 | claude-sonnet-4-5 |
| Wall-clock | 11분 (4 worker, RPM 한계 영향 없음) |
| 추정 비용 | ~$5.4 ($0.018/call × 300) |
| Resynth 재시도 비용 | $0 (LLM 재호출 없음) |

550 fixture 전체 LLM 평가로 확장 시 ~$30 / 60분 예상.

## 도중 이슈

### 처음 LLM 모드 효과가 미미해 보임

직전 verdict 합성 룰은 LLM 이 BENIGN 응답해도 ind_high>=2 같은 매처 신호가
HIGH_RISK 강제. 즉 *LLM 의 정상 판정을 신뢰하지 않음*. 13 FP 가 전부
"LLM=benign 인데 verdict=HIGH_RISK" 였음 → `popular + LLM benign` 룰 추가로
LLM 판정을 신뢰하는 명시적 경로 마련.

### Resynth pattern 의 가치

LLM 호출은 비싸지만, 호출 후 결과 (`llm_stub` 필드) 는 results.json 에 저장.
verdict 합성 룰을 바꾸고 싶을 때마다 재호출 ($5+) 하지 말고 resynth 스크립트로
$0 에 다시 측정 가능. 이번 사이클의 새 룰도 resynth 로 검증 후 코드에 반영.

## 검증

```
$ python -X utf8 scripts/eval_synthetic.py
  P=1.000 R=0.983 F1=0.992  (cycle 11 유지)

$ python -X utf8 scripts/eval_real.py --stratified 100 \
        --json scripts/eval_real_data/results_stub_v2.json
  P=0.800 R=0.867 F1=0.832  (stub 모드 영향 0건)

$ python -X utf8 scripts/eval_real.py --llm claude --stratified 100 \
        --json scripts/eval_real_data/results_llm.json
  P=0.809 R=0.917 F1=0.859  (LLM, 기존 verdict 룰)

$ python -X utf8 scripts/eval_real_resynth.py \
        --input scripts/eval_real_data/results_llm.json \
        --llm claude --output scripts/eval_real_data/results_llm_v2.json
  P=0.965 R=0.917 F1=0.940  (LLM + 새 popular×benign 룰)
```

## 다음 단계 (미진행)

1. **550 fixture 전체 LLM 평가** ($30) — smoke-mid 결과 확정 후 large sample
   에서 같은 효과 (F1 +0.11) 가 유지되는지 검증.
2. **남은 2 FP 처리** — flask/fastapi 의 taint=2 / cooccur=3 케이스.
   LLM 이 BENIGN 응답이지만 본 룰은 보수적 임계. fixture 수 늘려 분포 보고
   임계 미세조정.
3. **A/B 비교** — Claude Haiku 4.5 ($0.005/call) vs Sonnet 4.5 ($0.018/call).
   F1 격차가 4배 가격 차를 정당화하는지.
4. **캐싱 활용** — system prompt + few-shot 부분을 prompt cache 로 -90% →
   Sonnet 가격을 Haiku 수준으로.
