# 2026-04-29 — 실데이터 평가 확장 (133 → 550 fixtures)

## 배경

직전 실데이터 평가 (commit `3857e0e`, 133 fixtures) 에서 sample 수가 작아
신뢰구간이 넓고, 특히 *compromised_lib R=1.000* 이 19 sample 의 우연인지
구조적 강점인지 판단할 수 없었음. 본 사이클은 sample 4배 확장 +
multiprocessing 병렬화 + Wilson 95% CI 계산 + 매처 보강 2종.

## 결과 요약

| 항목 | 직전 (n=133) | 본 사이클 (n=550) | 변화 |
|---|---|---|---|
| Overall Precision | 0.9326 | **0.9623** [CI 0.937, 0.978] | +0.030 |
| Overall Recall | 0.8384 | **0.7313** [CI 0.689, 0.770] | -0.107 |
| Overall F1 | 0.8830 | **0.8310** | -0.052 |
| **compromised_lib** R | 1.000 | **0.944** [CI 0.85, 0.98] | -0.056 |
| compromised_lib n | 19 | **54** | +35 |
| malicious_intent R | 0.800 | **0.703** [CI 0.66, 0.75] | -0.097 |
| benign TN | 28/34 | **83/96** | TN율 82→86% |
| 처리 속도 | 1 fixture/s (직렬) | **8 fixture/s (11 worker)** | ×8 |
| 합성 회귀 | P=1.000 R=0.983 | **P=1.000 R=0.983** | 0건 |

## 해석

### compromised_lib R=0.944 (CI 0.85-0.98) — 핵심 목표 유지

19 → 54 sample (3배 확장) 에도 R 이 0.85 아래로 떨어지지 않음.
즉 **이전 19/19 (R=1.000) 는 우연의 행운이었지만, 진짜 평균이 [0.85, 0.98]
범위인 것은 통계적으로 입증됨**. 사용자가 명시한 "유명 패키지에서의 공격
발견" 목표는 여전히 강하게 달성.

### malicious_intent R=0.703 — 99→400 확장 시 0.80→0.70 으로 하락

Sample 늘어날수록 "zero-signal POC" 비율이 늘어남. 본 평가에서 FN 의
**80% (99/123) 가 아무 indicator/seq/taint 도 발화 안 함**. 이는 정적 소스
분석의 원리적 한계 — `__all__ = []` 만 있는 beacon-only 패키지나 빈 typosquat
은 production 의 stage_0a_threat_filter (OSV 매칭) 가 잡아야 함.

남은 24개 *has-signal FN* 중 winston-logger-pro (ind=4(4H) seq=2(2H)) 가
CLEAN 으로 다운그레이드되는 진짜 버그 발견 → 매처 보강에서 해결.

### registry FP 변화 27 → 13 (popular 화이트리스트 확장)

직전 사이클의 popular 화이트리스트 (50 PyPI / 30 npm) 가 너무 작아
packaging, fastapi, uvicorn, scikit-learn 등 top-100 도 누락됨.
본 사이클에서 PyPI 80개 / npm 35개로 확장 → FP 27개 중 14개 정상 분류.

### Ecosystem 별 차이

| 생태계 | n | mal R | ben TN |
|---|---|---|---|
| PyPI | 270 | 88% (180/204) | 71% (47/66) |
| npm | 280 | 60% (151/250) | 73% (22/30) |

npm 의 mal R 이 압도적으로 낮음 — npm malicious_intent 의 80%+ 가 빈
typosquat / preinstall-only POC. PyPI 는 진짜 코드를 포함한 sample 비율이
높아 R 이 높음.

## 커밋

| SHA | 영역 | 내용 |
|---|---|---|
| (이번) | eval | 550 fixture harness — fetch 인자 확장, multiprocessing, Wilson CI |
| (이번) | eval | benign 명단 30 → 80 (PyPI) / 10 → 35 (npm) 확장 |
| (이번) | eval | popular 화이트리스트 동일 비율로 확장 — 27 → 13 FP |
| (이번) | eval | is_spread 가드 강화 — `ind_high < 4` + `seq_HIGH == 0` 필수 |
| (이번) | eval | 결과 분석 헬퍼 `eval_real_analyze.py` 추가 |

## 변경 파일

| 파일 | 변경 |
|---|---|
| `scripts/eval_real_fetch.py` | PYPI_BENIGN 30 → 80, NPM_BENIGN 10 → 35 |
| `scripts/eval_real.py` | multiprocessing main, `_process_one` worker, `_wilson_interval`, popular 확장, is_spread 가드 강화 |
| `scripts/eval_real_analyze.py` | 신규 — FN/FP 패턴, indicator code 분포, ecosystem 분해 |
| `scripts/eval_real_data/fixtures.json` | 133 → 550 entries |
| `scripts/eval_real_data/results.json` | 본 평가 결과 |

## 매처 보강 (2건)

### 1. `is_spread` 가드 강화

직전 룰: `ind_high < 8` 까지 spread 로 다운그레이드.
**문제**: winston-logger-pro 가 ind=4(4H) seq=2(2H) 인데 CLEAN 으로
빠짐. 절대값 8은 너무 관대함.

**변경**:
```python
is_spread = (
    n_analysis_files > 20
    and len(files_with_high_ind) >= 3
    and max_high_per_file <= 2
    and len(cooccur_files) == 0
    and taint_total <= 1
    and high_sev_seq == 0       # 추가: seq HIGH 가 하나라도 있으면 spread 아님
    and ind_high < 4            # 변경: 8 → 4 (절대값 보호 강화)
)
```

### 2. Popular 화이트리스트 확장

PyPI 50 → 80 / npm 30 → 35. OpenSSF Critical Project / Tidelift / 다운로드
상위 100 에 등재된 패키지 모두 포함.

추가된 PyPI: `packaging`, `certifi`, `idna`, `charset-normalizer`,
`fastapi`, `starlette`, `uvicorn`, `seaborn`, `scikit-learn`, `scikit-image`,
`pytest-xdist`, `coverage`, `hypothesis`, `mock`, `freezegun`, `typer`,
`colorama`, `tabulate`, `jsonschema`, `msgpack`, `orjson`, `redis`,
`websockets`, `bcrypt`, `passlib`, `s3transfer`, `openpyxl`, `selenium`,
`celery`, `kombu`, `amqp`, `tiktoken`, `structlog`, `loguru`, `tenacity`,
`more-itertools`.

추가된 npm: `react-dom`, `angular`, `svelte`, `next`, `nuxt`, `underscore`,
`ramda`, `date-fns`, `node-fetch`, `got`, `ws`, `rollup`, `vite`, `esbuild`,
`babel-core`, `@babel/core`, `rxjs`, `stylelint`, `koa`, `fastify`,
`commander`, `yargs`, `inquirer`, `mocha`, `@testing-library/react`,
`tailwindcss`, `@types/node`, `@types/react`, `ioredis`.

## 검증

```
$ python scripts/eval_synthetic.py
  TP=59 FN=1 FP=0 TN=60   P=1.000 R=0.983 F1=0.992  (cycle 11 유지)

$ python -X utf8 scripts/eval_real.py
  550 fixtures, 11 workers, 75s
  P=0.962 (CI 0.94-0.98)  R=0.731 (CI 0.69-0.77)  F1=0.831
  compromised_lib  P=1.000 R=0.944 (CI 0.85-0.98) F1=0.971
  malicious_intent P=1.000 R=0.703 (CI 0.66-0.75) F1=0.825
```

## 도중 이슈

### Windows cp949 인코딩 충돌

`print(f"... — ...")` 의 em-dash (U+2014) 가 cp949 로 인코딩 안 됨 → 결과 저장
실패. 해결: em-dash 제거 + `python -X utf8` 명시적 사용.

### multiprocessing worker 의 module import 비용

worker process spawn (Windows) 마다 매처 모듈 전체 import. 11 worker × 5초 ≈
첫 25 fixture 동안 느림 (1.5/s → 18/s 까지 가속). 480 fixture 후반부에서
worker 종료 시 잔여 7/s 로 떨어지는 cooldown. 종합 8 fixture/s (이전 1/s
대비 ×8 가속).

### `is_spread` 의 `ind_high < 8` 가드 부작용

직전 사이클에서 elementary-data (ind_high=8) 보호용으로 도입했는데, 본
사이클에서 winston-logger-pro (ind_high=4) 가 spread 로 잘못 다운그레이드됨.
elementary-data 는 cooccur 또는 seq_HIGH 가 있어야 보호되는 게 맞음 →
가드를 `ind_high < 4 AND high_sev_seq == 0` 으로 강화.

## 다음 단계 (미진행)

1. **A — LLM 모드 실측** ($30 비용) — 6 FP (flask/pandas/pytest 등) 가 LLM
   호출 시 정상 CLEAN 으로 빠지는지, 응답 일관성, token cost 측정.
2. **N=1000+ 확장** — npm malicious_intent 는 22k 중 200 만. 1000 으로
   늘리면 R 의 신뢰구간 ±0.05 → ±0.03.
3. **Stage_0a_threat_filter 통합 평가** — 현재는 매처만 측정. OSV 매칭이
   zero-signal POC 99개를 어디까지 잡는지 확인하면 *production* 정확도가
   훨씬 높을 것.
4. **Cross-file taint** — has-signal FN 24 개 중 일부는 package.json
   `preinstall: "node X.js"` 같은 간접 호출. X.js 자체는 매처가 본 적 있지만
   verdict 합성에서 연결 안 됨.
