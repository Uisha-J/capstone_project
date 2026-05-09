# 2026-05-06 세션 로그 — autonomous 작업 결과

> 사용자가 자리 비운 동안 진행한 작업 정리. 복귀 시 검토 후 커밋·push 결정.
> 모든 변경은 working tree 에만 있음. **커밋 없음**.

---

## 작업 우선순위 (사용자 지시)

1. (a') matcher-only real eval — 진행 중이던 작업 마무리
2. 편향 표본 해결 — 평가 코퍼스가 too-malicious-heavy 인 문제
3. Pipeline diet — pipeline.py 추가 슬림화

---

## 1. (a') matcher-only real eval ✅

### 신규 파일
- **`scripts/indicator_fp_table_real.py`** (~430 lines)
  - 기능: PyPI/npm 레지스트리에서 아카이브 직접 다운로드 + `indicator_matcher.match_all` 만 적용 → indicator 별 FP/TP 표
  - 의존성: stdlib + indicator catalog 만. **sqlcipher / sentence-transformers / LLM 미사용** (Windows 즉시 실행)
  - 캐시: `scripts/eval_real_data/cache_lite/<eco>/<name>-<ver>.tar.gz` (기존 cache/ 와 분리)
  - resume: 결과 JSON 에 fixture별 hits 저장, 다음 실행 시 skip
  - CLI: `--manifest`, `--max`, `--label`, `--cache-dir`, `--results-json`, `--output-md`, `--refresh`

### 검증
- 100 패키지 처리 157s, 0 failure
- 출력: `docs/2026-05-06-indicator-fp-popular-benign.md` + `scripts/eval_real_data/indicator_fp_real_results.json`

---

## 2. 편향 표본 해결 ✅

### 문제 인식
| 코퍼스 | mal | ben | 비율 |
|---|---:|---:|---|
| 합성 fixture | 100 | 20 | 5:1 (mal-heavy) |
| eval_real_data | 454 | 96 | 4.7:1 (mal-heavy) |
| 실 ecosystem | ~1k 신규/일 | ~300M | ~1:30,000 |

평가 코퍼스가 실 prevalence 와 **5만배 어긋남** → P/R/F1 가 운영 FP 율을 과대평가.

### 신규 파일
- **`scripts/build_popular_benign.py`** (~250 lines)
  - 소스: `hugovk/top-pypi-packages.json` + `anvaka/npmrank.json` (이미 `feeds/popular.py` 가 사용 중인 동일 피드)
  - npmrank fallback: 큐레이팅된 top-50 npm 리스트 (lodash, react, vue, axios, ... — 핸드오프 9-패키지 smoke 포함)
  - 출력: `scripts/eval_real_data/popular_benign_manifest.json` (fixture 형식)
  - CLI: `--pypi-top N`, `--npm-top N`, `--throttle SEC`

### 실행 결과
```
$ python scripts/build_popular_benign.py --pypi-top 50 --npm-top 50
benign 합계 : 100 (PyPI 50 + npm 50)
```

---

## 3. 핵심 발견 — FP root cause 분석

**100 인기 benign 패키지에서 매처 실행 결과 (의외)**:

- FP rate ≥ 30% indicator: **0 개**
- FP rate 15~30%: 3 개 (`EXM-002`, `EXM-005`, `EXM-001`)
- 패키지의 50% 가 0 indicator 발화 (clean), 16% 가 4+ indicator 동시 발화

**top 동시 발화 패키지** (모두 합법 foundation 도구):
- `numpy` 2.4.4: **15 indicators**
- `setuptools` 82.0.1: 13
- `pip` 26.1.1: 12
- `pytest` 9.0.3: 9, `pandas` 9, `cffi` 8

→ 핸드오프 9-패키지 smoke 의 8/9 HIGH_RISK 의 진짜 원인은 **개별 indicator FP 가 아니라 risk_combo escalation**.

### Root Cause 진단

`evidence/converters.py:174-198` 의 escalation 룰:
```python
RISK_COMBO_TRIGGER = {EXF-*, NET-002, NET-007, NET-008,
                      EXS-002, EXS-003, EXM-006, EXM-008, DEF-005}
if STANDALONE_WEAK 이고 같은 파일에 RISK_COMBO_TRIGGER 0 개 → BENIGN downgrade
else → full severity
```

**문제**: trigger 단 **1개만** 같은 파일에 있어도 해당 파일의 모든 weak indicator 가 escalate.
- numpy `setup.py` 같은 파일에 `EXM-008` (subprocess), `EXM-006` (pip install), `EXS-002` (top-level), `EXF-001` (info+transmit) 가 합법적으로 동시 발화 → STANDALONE_WEAK downgrade 무력화.

### 신규 분석 파일
- **`docs/2026-05-06-fp-root-cause.md`** (~200 lines)
  - 합성 vs 인기-benign 코퍼스 FP 비교 표
  - 패키지당 동시 발화 분포 차트
  - 4+ 동시 발화 패키지 상세 (어떤 indicator 가 발화했는지)
  - 권장 수정 4가지 (Fix-1 ~ Fix-4) — 우선순위 + 코드 변경량 평가
  - stratified eval (recall_on_malicious + fp_rate_on_benign 분리) 권장

### 권장 수정 (요약)

| Fix | 내용 | 변경량 | 효과 |
|---|---|---|---|
| Fix-1 | Combo escalation 을 카테고리 다양성 ≥2 로 강화 | small | foundation 도구 FP↓ |
| Fix-2 | scope 를 file → 함수/클래스 로 정밀화 | medium | 가장 정밀, FP↓↓ |
| Fix-3 | trigger 자체에 confidence ≥ 0.85 조건 | small | 약한 trigger 무력화 |
| Fix-4 | trigger 명단에서 EXM-008, EXS-002 등 제거 | smallest | 즉시 효과 |

상세 내용은 `docs/2026-05-06-fp-root-cause.md` 참조.

---

## 4. Pipeline diet ✅ (POC + 부분 적용)

### 변경 전
- `src/pkgsentinel/pipeline.py`: **1058 lines**
- 22개 stage 가 동일한 try/except/StageResult.append 보일러플레이트 반복
- import 블록: `from X import (Y as Z,)` 7번 반복 = 22 lines

### 적용한 다이어트

#### 4.1 Import 블록 통합 (안전, 즉시 적용)
- 모듈별 단일 파라미터 import 7개 → 1개 grouped import
- 영향 모듈: `evidence.converters`, `evidence.snippets`, `stages.stage0_threat_filter`, `stages.stage0b_attack_history`, `stages.stage5_multi_agent`, `stages.stage_agentic`, `stages.stage_scorecard`, `stages.stage_slsa`, `stages.taint_slicer`
- **저장: ~25 lines**

#### 4.2 Stage 컨텍스트 매니저 도입 (POC)
- 신규 파일: **`src/pkgsentinel/_stage_runner.py`** (~110 lines)
- 기능: try/except + StageResult.append 보일러플레이트를 `with stage(ctx, label) as st:` 로 캡슐화
- API:
  - `st.payload = {...}` — 결과 데이터
  - `st.fail(error_str)` — 명시적 실패
  - `st.skip()` — 결과 기록 안 함
  - 예외 자동 catch → success=False 자동 기록 (전체 traceback 포함)

#### 4.3 POC 적용 — Stage 0B/0C/0D 변환
- **0B Attack History**: 18 lines → 11 lines (-7)
- **0C Scorecard**: 16 lines → 9 lines (-7)
- **0D SLSA**: 16 lines → 9 lines (-7)
- **저장: ~21 lines**

### 변경 후
- `src/pkgsentinel/pipeline.py`: **1002 lines** (-56 from 1058)
- 신규 helper: `_stage_runner.py` 110 lines (재사용 가능)

### 회귀 검증
```
$ python -m pytest tests/ --ignore=test_threat_db_integration --ignore=test_realtime_pipeline --ignore=test_stage_cache
78 passed, 61 warnings in 10.83s
```
**0 failure / 0 error.** 무회귀 확인.

### 미적용 (남은 작업)
나머지 19개 stage 도 동일 패턴으로 변환 가능. 각 ~5~7 lines 절감 → **총 100~140 lines 추가 절감 가능**.

POC 가 검증되었으므로 사용자가 OK 판단하면 일괄 변환 (별도 PR 권장 — 변경 폭 큼).

---

## 5. 신규/수정 파일 일람

### Working tree 의 변경

| 파일 | 상태 | 라인 | 역할 |
|---|---|---:|---|
| `scripts/indicator_fp_table_real.py` | new | 430 | 실 패키지 matcher-only FP/TP 분석기 |
| `scripts/build_popular_benign.py` | new | 254 | top-N 인기 패키지 → benign manifest |
| `src/pkgsentinel/_stage_runner.py` | new | 110 | stage 컨텍스트 매니저 |
| `src/pkgsentinel/pipeline.py` | modify | -56 | imports 통합 + 3 stage 변환 |
| `docs/2026-05-06-indicator-fp-popular-benign.md` | new | 95 | 100 인기 패키지 FP/TP 표 |
| `docs/2026-05-06-fp-root-cause.md` | new | 200 | combo escalation root cause 분석 |
| `docs/2026-05-06-session-log.md` | new | (this) | 본 세션 로그 |
| `scripts/eval_real_data/popular_benign_manifest.json` | new | - | 100 패키지 manifest |
| `scripts/eval_real_data/indicator_fp_real_results.json` | new | - | resume 캐시 |
| `scripts/eval_real_data/cache_lite/...` | new | - | 다운로드된 100개 아카이브 (~50MB) |

`scripts/eval_real_data/cache_lite/` 는 `.gitignore` 추가 권장 (대용량 binary).

---

## 6. 복귀 시 결정 사항

### 6.1 즉시 결정
- [ ] 위 변경 검토 → 일괄 커밋 OR 분할 커밋?
  - 분할 권장: (PR1) FP 분석 도구·문서, (PR2) pipeline diet POC
- [ ] `scripts/eval_real_data/cache_lite/` 와 `indicator_fp_real_results.json` 을 .gitignore 에 추가 후 커밋
- [ ] popular_benign_manifest.json 은 커밋? (재현성 ↑) OR 빌드 명령만 README 에 명시?

### 6.2 다음 세션에서 결정
- [ ] **FP root cause 의 Fix 어느 것 적용?** 
  - 권장: Fix-1 (cat 다양성) 빠르게 시도 → 9-패키지 smoke 재측정 → 효과 미흡하면 Fix-2 (scope 정밀화)
- [ ] **Pipeline diet 일괄 변환?**
  - 19 stage × ~5 lines = ~100 lines 추가 절감. 별도 PR 권장
- [ ] **인기 benign 코퍼스 N=500 확장?**
  - `python scripts/build_popular_benign.py --pypi-top 250 --npm-top 250` (~10 분, 150MB)
  - stratified FP rate 신뢰도 ↑ — 의사결정 근거 강화

### 6.3 사용자 본인이 명시한 미해결
- [ ] `eval_real.py` schema 확장 (per-fixture indicator code list) — 풀 파이프라인 환경 필요. macOS-only 라면 그쪽에서. 이번 세션의 `indicator_fp_table_real.py` 가 동등 기능을 라이트 환경으로 제공하므로 우선순위 낮춤 가능.
- [ ] verdict 핵심 docstring 의 "인기도/나이/다운로드 수 미참조" 원칙 유지 — 이번에 어긴 사항 없음.

---

## 7. 빠른 재현 명령

```bash
# 분석 도구 재실행 (FP rate 표 갱신)
python scripts/indicator_fp_table_real.py \
  --manifest scripts/eval_real_data/popular_benign_manifest.json \
  --output-md docs/2026-05-06-indicator-fp-popular-benign.md

# 코퍼스 확장 (N=500)
python scripts/build_popular_benign.py --pypi-top 250 --npm-top 250

# pytest 회귀 (heavy 제외)
python -m pytest tests/ \
  --ignore=tests/test_threat_db_integration.py \
  --ignore=tests/test_realtime_pipeline.py \
  --ignore=tests/test_stage_cache.py
```
