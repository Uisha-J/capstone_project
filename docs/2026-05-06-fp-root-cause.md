# FP Root Cause 분석 — 합성 vs 실 코퍼스 + Combo Escalation 문제

> 생성일: 2026-05-06
> 입력 데이터:
> - `scripts/eval_synthetic.py` 인라인 fixture (MAL=100, BEN=20)
> - `scripts/eval_real_data/popular_benign_manifest.json` (인기 PyPI 50 + npm 50)
> - `src/pkgsentinel/evidence/converters.py` (escalation 규칙)
> - `src/pkgsentinel/pipeline.py` Stage 4C (file-local combo)

---

## 1. 핵심 발견 — 한 문장

**개별 indicator FP rate 는 낮지만 (≥30%: 0개, ≥15%: 3개), foundation 도구 패키지가 RISK_COMBO trigger 를 정상 기능으로 동시에 발화시켜 STANDALONE_WEAK downgrade 가 무력화 → 9-패키지 smoke 의 8/9 HIGH_RISK 가 발생.**

---

## 2. 측정 데이터 비교

### 2.1 두 코퍼스의 FP rate 분포

| Indicator FP rate 구간 | 합성 BEN N=20 | 인기 BEN N=100 |
|---|---:|---:|
| ≥ 30% | 0 | 0 |
| 15 ~ 30% | 0 | **3** (`EXM-002`, `EXM-005`, `EXM-001`) |
| 5 ~ 15% | 0 | **10** (`SYS-002`, `SYS-005`, `EXM-008`, `DEF-003`, `EXS-001`, …) |
| 1 ~ 5% | 1 (MET-004) | 12 |
| 0 % | 46 | 22 |

**관찰**: 합성 코퍼스는 indicator 단독 FP 거의 0. 인기 패키지에선 13개 indicator 가 5%+ FP, 3개가 15%+ FP. 그러나 **30%+ 는 여전히 0개** — 단독 발화로는 임계 미달.

### 2.2 패키지당 indicator 동시 발화 분포 (인기 BEN N=100)

```
indicators 동시 발화 횟수 → 패키지 수
  0 :  50  ##################################################
  1 :  18  ##################
  2 :  10  ##########
  3 :   6  ######
  4 :   5  #####  ←┐
  5 :   4  ####    │
  7 :   1  #       │
  8 :   1  #       │ 16/100 = combo escalation 임계
  9 :   2  ##      │
 12 :   1  #       │
 13 :   1  #       │
 15 :   1  #       │
                   ┘
평균 1.69, 중앙값 1
```

**관찰**: 50% 의 인기 패키지는 0 indicator (clean), 그러나 **16% 가 4+ indicator 동시 발화**.

### 2.3 4+ 동시 발화 패키지 (foundation 도구가 대부분)

| 패키지 | hits | 발화 indicator 코드 |
|---|---:|---|
| `numpy` 2.4.4 | **15** | DEF-003, DEF-006, EXF-001, EXM-001~008(다수), EXS-001/002, NET-009, SYS-001/002/005 |
| `setuptools` 82.0.1 | 13 | DEF-003, DEF-006, EXF-001, EXM-001~008, EXS-001/003, SYS-001/005 |
| `pip` 26.1.1 | 12 | DEF-006, EXF-001, EXM-001~008, EXS-001, NET-009, SYS-002/005 |
| `pytest` 9.0.3 | 9 | DEF-005/006, EXM-001/002/005/006/008, EXS-001, SYS-005 |
| `pandas` 3.0.2 | 9 | EXF-001, EXM-001/002/003/005/008, EXS-001, NET-009, SYS-005 |
| `cffi` 2.0.0 | 8 | EXM-001~008, EXS-002, SYS-005 |
| `botocore` 1.43.4 | 7 | DEF-003, EXF-001, EXM-001/002/005, SYS-002/005 |

---

## 3. Root Cause — RISK_COMBO Trigger 가 너무 헐거움

### 3.1 현재 escalation 룰 (`evidence/converters.py:174-198`)

```python
STANDALONE_WEAK_INDICATORS = {
    "EXM-001", "EXS-001", "SYS-005", "SYS-004", "DEF-006",
    "MET-004", "MET-001", "EXM-005", "DEF-003",
}

# 파일 단위 combo trigger
has_risk_combo = any(
    c.startswith(("EXF-", "NET-002", "NET-007", "NET-008",
                  "EXS-002", "EXS-003", "EXM-006", "EXM-008", "DEF-005"))
    for c in indicator_codes_same_file
)

if is_standalone_weak and not has_risk_combo:
    llm_v = LLMVerdict.BENIGN
    confidence = min(h.confidence, 0.4)
else:
    # full severity 그대로
    ...
```

### 3.2 무엇이 잘못됐나

**numpy `setup.py` 파일 단위로 보면**:
- STANDALONE_WEAK: `EXM-001` (eval, 빌드 코드 생성용), `SYS-005` (platform.uname 으로 OS 분기), `DEF-006` (try/except 빌드 fallback), `EXM-005` (importlib 동적 plugin), `DEF-003` (base64 — 정상 인코딩 사용)
- combo TRIGGER 발화: `EXM-008` (subprocess.run 으로 컴파일러 호출), `EXF-001` (info+transmit 패턴 — 정상 telemetry), `EXM-006` (pip subprocess), `EXS-002` (top-level 호출)

**즉 합법 빌드 도구가 4개의 combo trigger 를 정상 사용** → STANDALONE_WEAK downgrade 가 발동 안 함 → EXM-001/SYS-005/DEF-003/DEF-006/EXM-005 모두 full severity 로 evidence 화 → verdict_rules 가 SUSPICIOUS+ 로 끌어올림.

### 3.3 trigger 가 너무 강력한 indicator 들 (인기 패키지에서 자주 발화)

| Trigger | 인기 BEN FP | 합법 사용 예 |
|---|---:|---|
| `EXM-008` Shell Command Execution | **13%** | 빌드 스크립트, 테스트 러너, CLI tool |
| `EXF-001` Data Exfiltration | 6% | telemetry, error reporter, analytics |
| `EXM-006` Dynamic Package Install | 6% | self-installer, dev-mode tools (pip) |
| `EXS-002` Install-Time Execution | 8% | 거의 모든 패키지의 setup.py top-level |
| `EXS-003` Lifecycle Hook Hijack | 1% | (드물지만 setuptools 가 자체 활용) |
| `DEF-005` Embedded String Payload | 4% | 일부 정상 dynamic codegen |

→ 단 1개의 trigger 만 같은 파일에 있어도 모든 weak 가 escalate. 임계가 너무 헐거움.

---

## 4. 권장 수정 (우선순위)

### 4.1 (Fix-1) Combo trigger 를 "category 다양성" 으로 강화 ⭐

현재: trigger 1개 → escalate
제안: **서로 다른 attack_dimension** 의 trigger 가 ≥2 개일 때만 escalate

```python
# evidence/converters.py 수정안
TRIGGER_BY_CATEGORY = {
    "exfil":   {"EXF-001", "EXF-002", "EXF-003", "EXF-004", "EXF-005",
                "NET-002", "NET-007", "NET-008"},
    "execute": {"EXS-002", "EXS-003", "EXM-006", "EXM-008", "DEF-005"},
}

trigger_cats_present = {
    cat for cat, codes in TRIGGER_BY_CATEGORY.items()
    if any(c in codes for c in indicator_codes_same_file)
}
has_risk_combo = len(trigger_cats_present) >= 2  # 이전: ≥1
```

**효과 예측**:
- numpy: `EXM-008` + `EXM-006` + `EXS-002` (모두 execute 카테고리) + `EXF-001` (exfil) → cat 2 → 여전히 trigger. **하지만 패키지당 평균 cat 다양성이 낮으므로 효과 있을 것** — 전체 측정 필요.
- pip / setuptools: 유사하게 execute 카테고리만 다수 → cat 1 → STANDALONE_WEAK downgrade 발동.
- 진짜 악성 (info-read + base64 + http.post 패턴): exfil 1 + execute 0 또는 + DEF (encoding 별도 카테고리 신설 시) → 영향 시뮬레이션 필요.

검증: 본 스크립트의 `--manifest popular_benign` 재측정 후 combo escalation 발생 패키지 수가 얼마나 줄었는지 확인.

### 4.2 (Fix-2) 파일 단위 → 함수/클래스 단위 scope ⭐⭐

현재: 같은 파일에 있으면 combo 인정
제안: 같은 **함수/클래스 본문** 안에서 발화한 indicator 만 combo 로 인정

근거: 정상 패키지 setup.py 는 여러 헬퍼 함수에 걸쳐 다양한 API 사용. 진짜 악성은 보통 한 install hook 클래스의 run() 메서드에 모든 행위가 집약 (event-stream, pyqubee 등 실 사례).

구현 방향: indicator_matcher 가 hit 에 `enclosing_function/class` 메타데이터 부착 → converters.py 가 같은 enclosing scope 끼리만 combo 판정.

이것이 file-local 보다 한 단계 더 정밀. 단, AST scope 추출 로직 추가 필요 → 중간 정도 작업량.

### 4.3 (Fix-3) Severity-aware combo

현재: trigger 가 발화하면 무조건 escalate
제안: trigger 자체의 confidence 가 ≥0.8 이고, 동일 enclosing scope 내 발화일 때만

근거: 빌드 스크립트의 `subprocess.run(['python', 'setup.py', 'build_ext'])` 같은 합법 호출은 indicator_matcher 에서 이미 confidence 0.7 정도로 채점됨. 진짜 악성 호출은 0.85+.

### 4.4 (Fix-4) trigger 명단 자체 축소

현재 RISK_COMBO trigger 9가지 중, **실 인기 패키지에서 자주 발화하는 것들**:
- `EXM-008` (13% FP) — **명단에서 제거 또는 confidence ≥ 0.85 조건 추가**
- `EXS-002` (8% FP) — setup.py top-level 호출은 거의 모든 정상 패키지에서 발화 → **제거 강력 권장**
- `EXM-006` (6% FP) — dev-mode self-install 흔함 → 조건 추가 (subprocess + 'pip install <변수>')
- `EXF-001` (6% FP) — telemetry/error report 흔함 → confidence ≥ 0.85 조건

남길 것 (실 코퍼스에서 거의 0% FP):
- `NET-002` Mining Pool, `NET-007` Script Dropper (curl|bash), `NET-008` Reverse Shell, `EXS-003` cmdclass override, `DEF-005` Embedded Payload + exec, `EXF-002~005` (Webhook/DNS tunnel/Suspicious Domain)

---

## 5. 검증 방법

본 분석 산출 도구로 회귀 측정 가능:

```bash
# 1. 인기 benign 코퍼스 100개 (이번 측정과 동일)
python scripts/build_popular_benign.py --pypi-top 50 --npm-top 50

# 2. 수정 전 baseline (이미 산출됨)
# scripts/eval_real_data/indicator_fp_real_results.json

# 3. converters.py 또는 pipeline.py 수정 후 풀 파이프라인 재측정
#    → 4+ 동시 발화 패키지 중 verdict 가 CLEAN/CLEAN_WITH_NOISE 로 떨어진 비율 추적
```

---

## 6. 동시에 짚어둘 — 코퍼스 편향

### 6.1 현 코퍼스 비율

| 코퍼스 | malicious | benign | mal:ben |
|---|---:|---:|---|
| 합성 (`eval_synthetic`) | 100 | 20 | **5.0 : 1** |
| 실 (`eval_real_data/fixtures.json`) | 454 | 96 | **4.7 : 1** |
| 실 ecosystem | ~1k 신규 / 일 | ~300M (PyPI+npm) | **~1 : 30,000** |

**문제**: 평가 코퍼스가 실 prevalence 와 5만배 이상 어긋남 → P/R/F1 의 P (precision) 가 **시스템 운영 시 FP rate 를 과대평가**. recall 위주 튜닝의 함정.

### 6.2 권장 — Stratified eval 분리

P/R/F1 단일 metric 대신:
- **Recall on malicious** — 악성 100~500 fixture 중 적정 verdict 비율 (현 형태 그대로 유지)
- **FP rate on benign** — 인기 패키지 N=500+ 에서 verdict ≠ CLEAN 비율 (현재 N=96 → N=500+ 권장)
- 두 metric 을 분리 보고. 단일 F1 으로 합치면 비율 불일치 가려짐.

### 6.3 액션 아이템

1. **인기 benign 코퍼스를 N=500 으로 확장** — `build_popular_benign.py --pypi-top 250 --npm-top 250` 로 한 번 실행 (예상 ~10분)
2. `eval_real.py` 결과 schema 에 `fp_rate_on_benign_only` 필드 추가
3. README / cost_model 의 P/R/F1 수치를 stratified 형태로 재서술

---

## 7. 신규 추가된 도구

| 파일 | 라인 | 역할 |
|---|---:|---|
| `scripts/indicator_fp_table.py` | 219 | 합성 fixture 기반 47-indicator FP/TP 표 |
| `scripts/indicator_fp_table_real.py` | ~430 | 실 패키지 archive 다운로드 + matcher-only 매칭 + 표 |
| `scripts/build_popular_benign.py` | ~220 | 공식 인기 피드 → benign manifest |

세 스크립트 모두 stdlib + 카탈로그 import 만 의존 (sqlcipher / sentence-transformers / LLM 미사용). Windows 즉시 실행.

---

## 8. 다음 단계 (작업 우선순위)

1. **(Fix-2) 함수/클래스 scope combo** 가 가장 정밀한 해결 — 코드 변경량 중간, FP 감소 가장 큼
2. **(Fix-1) category-diversity combo** 는 (Fix-2) 의 보완 또는 단기 패치 — 코드 변경량 작음
3. **인기 benign 코퍼스 N=500 확장** — 의사결정 데이터 신뢰도 ↑
4. **`eval_real.py` schema 확장** — `ind_47_codes: list[str]` 필드 추가 (이전 회의에서 제안된 (a) 작업)
5. 위 변경 후 9-패키지 smoke 재측정 — handoff doc 의 비교 기준값과 대조
