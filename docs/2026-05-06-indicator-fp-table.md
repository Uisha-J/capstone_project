# 47-Indicator FP / TP 통계표

> 생성일: 2026-05-06  
> 코퍼스: `scripts/eval_synthetic.py` 인라인 fixture (malicious=100, benign=20)  
> 적용 범위: `indicator_matcher.match_all` 만 — Stage 0/3/4D/4E/5/6, LLM, registry, threat-intel 전부 우회  
> 한계: benign N=20 은 통계적으로 작음. 실 패키지 데이터(`eval_real_data/fixtures.json`, N=550) 에 동일 분석 적용 시 신뢰도 ↑

## 핵심 요약

- 47 인디케이터 중 **TP=0 (코퍼스에서 한번도 안 잡힘)**: 16개
  - 그 중 **FP=0 까지 포함한 완전 미발화**: 16개
- **FP rate ≥ 30%** (STANDALONE_WEAK 후보): 0개
- **FP rate 15~30%** (관찰 필요): 0개
- **고변별 workhorse** (TP rate ≥10% + FP=0): 3개

## 0. 핵심 발견 (합성 코퍼스 vs 실 코퍼스 갭)

**합성 benign 코퍼스(N=20)에서는 indicator FP 가 거의 0** — MET-004(설명 짧음, 1/20=5%) 단 1건. 그러나 직전 세션의 9-패키지 smoke test (django/numpy/pandas/flask/boto3 등 실제 인기 PyPI/npm 패키지) 에서는 8/9 가 HIGH_RISK 이상으로 잡힘.

**해석**: indicator 자체가 FP-prone 한 것이 아니라, 합성 benign fixture 가 *너무 깨끗*해서 실제 인기 패키지의 회색지대 (테스트용 `requests.post`, 빌드 스크립트 `subprocess`, 설정 파일의 환경변수 사용 등)을 대표하지 못함. **즉, 본 표의 FP rate 는 lower bound 이며 실제 운영 FP rate 추정에는 부적합**.

**다음 작업의 정렬 방향**:
1. 실 fixture (`scripts/eval_real_data/fixtures.json`, N=550) 에서 indicator code list 를 결과 schema 에 추가 → 본 스크립트와 동일 분석 적용 → **현실적 FP rate 표** 산출.
2. 그 표를 근거로 `STANDALONE_WEAK_INDICATORS` / `RISK_COMBO_TRIGGER_CODES` 조정. 합성 코퍼스만으로는 어느 indicator 를 약화/제거할지 결정 불가.

## 0.5 고변별 Workhorse Indicators (TP rate ≥10%, FP=0)

현 합성 코퍼스에서 가장 안정적으로 악성 신호를 분리하는 indicator. 약화/제거 절대 금지 — 매처의 핵심 신호원.

| Code | Name | Sev | TP | FP | TP rate | Discrim |
|---|---|---|---|---|---|---|
| `EXF-001` | Data Exfiltration | HIGH | 21 | 0 | 0.21 | +0.21 |
| `EXM-008` | Shell Command Execution | HIGH | 17 | 0 | 0.17 | +0.17 |
| `EXS-002` | Install-Time Execution | HIGH | 11 | 0 | 0.11 | +0.11 |

## 1. FP rate 높은 순 (실제 발화 indicator 만)

benign 픽스처에서 자주 발화 → 합법 도구의 정상 행위를 의심으로 잡고 있을 가능성.

| 순위 | Code | Name | Sev | TP | FP | FP rate | TP rate | Discrim |
|---|---|---|---|---|---|---|---|---|
| 1 | `MET-004` | Description Anomaly | LOW | 8 | 1 | 0.05 | 0.08 | +0.03 |

## 2. Discrimination 낮은 순 (TP=0 제외, 변별력 약한 순)

Discrimination = TP_rate − FP_rate. 0 에 가까울수록 무작위, 음수면 benign 에서 더 자주 발화.

| 순위 | Code | Name | Sev | Cat | TP | FP | TP rate | FP rate | Discrim |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `EXS-001` | Import-Time Execution | HIGH | Execution Stage | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 2 | `EXM-004` | Hidden Code Execution | HIGH | Execution Mechanism | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 3 | `EXF-003` | DNS Tunneling | HIGH | Exfiltration | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 4 | `SYS-001` | Environment Modification | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 5 | `SYS-002` | Startup File Persistence | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 6 | `SYS-003` | Crypto Wallet Harvesting | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 7 | `SYS-007` | File Deletion | MEDIUM | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 8 | `SYS-009` | Sensitive Path Write | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 9 | `NET-008` | Reverse Shell | HIGH | Network Operations | 1 | 0 | 0.01 | 0.00 | +0.01 |
| 10 | `EXM-006` | Dynamic Package Install | HIGH | Execution Mechanism | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 11 | `EXM-007` | Script File Execution | HIGH | Execution Mechanism | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 12 | `EXF-004` | Webhook Exfiltration | HIGH | Exfiltration | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 13 | `EXF-005` | Suspicious Domain Exfiltration | HIGH | Exfiltration | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 14 | `NET-001` | Geolocation Lookup | MEDIUM | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 15 | `NET-002` | Mining Pool Connection | HIGH | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 16 | `NET-009` | SSL Validation Bypass | MEDIUM | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 17 | `NET-010` | Unencrypted Communication | MEDIUM | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 18 | `DEF-005` | Embedded String Payload | HIGH | Defense Evasion | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 19 | `DEF-006` | Error Suppression | LOW | Defense Evasion | 2 | 0 | 0.02 | 0.00 | +0.02 |
| 20 | `MET-004` | Description Anomaly | LOW | Metadata Manipulation | 8 | 1 | 0.08 | 0.05 | +0.03 |

## 3. 권장 조치

### 3.1 FP rate ≥ 30% — STANDALONE_WEAK_INDICATORS 후보

현 코퍼스에서 FP rate ≥ 30% 인 indicator 없음.

### 3.2 FP rate 15 ~ 30% — risk_combo trigger 검토 대상

현 코퍼스에서 FP rate 15~30% 구간 indicator 없음.

### 3.3 TP=0 — 코퍼스 부족 가능성 (실 데이터 재측정 권장)

현 합성 코퍼스(N=100)에서 한 번도 발화 안 한 indicator. 실제 악성 패키지 코퍼스(`eval_real_data/fixtures.json`)에서 재측정 필요.

- **Defense Evasion**: `DEF-001`, `DEF-002`, `DEF-004`
- **Exfiltration**: `EXF-002`
- **Metadata Manipulation**: `MET-001`, `MET-002`, `MET-003`, `MET-005`, `MET-006`
- **Network Operations**: `NET-003`, `NET-004`, `NET-005`, `NET-006`
- **System Impact**: `SYS-004`, `SYS-006`, `SYS-008`

## 4. 전체 47-indicator 표 (코드 순)

| Code | Name | Sev | Cat | TP | FP | TP rate | FP rate | Discrim |
|---|---|---|---|---|---|---|---|---|
| `DEF-001` | ASCII Art Deception | MEDIUM | Defense Evasion | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `DEF-002` | Computational Obfuscation | MEDIUM | Defense Evasion | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `DEF-003` | Encoding-Based Obfuscation | HIGH | Defense Evasion | 5 | 0 | 0.05 | 0.00 | +0.05 |
| `DEF-004` | Encryption-Based Obfuscation | HIGH | Defense Evasion | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `DEF-005` | Embedded String Payload | HIGH | Defense Evasion | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `DEF-006` | Error Suppression | LOW | Defense Evasion | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `EXF-001` | Data Exfiltration | HIGH | Exfiltration | 21 | 0 | 0.21 | 0.00 | +0.21 |
| `EXF-002` | File Exfiltration | HIGH | Exfiltration | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `EXF-003` | DNS Tunneling | HIGH | Exfiltration | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `EXF-004` | Webhook Exfiltration | HIGH | Exfiltration | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `EXF-005` | Suspicious Domain Exfiltration | HIGH | Exfiltration | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `EXM-001` | Dynamic Evaluation | HIGH | Execution Mechanism | 6 | 0 | 0.06 | 0.00 | +0.06 |
| `EXM-002` | Conditional Payload Trigger | MEDIUM | Execution Mechanism | 3 | 0 | 0.03 | 0.00 | +0.03 |
| `EXM-003` | Binary Execution | HIGH | Execution Mechanism | 3 | 0 | 0.03 | 0.00 | +0.03 |
| `EXM-004` | Hidden Code Execution | HIGH | Execution Mechanism | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `EXM-005` | Dynamic Module Import | MEDIUM | Execution Mechanism | 4 | 0 | 0.04 | 0.00 | +0.04 |
| `EXM-006` | Dynamic Package Install | HIGH | Execution Mechanism | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `EXM-007` | Script File Execution | HIGH | Execution Mechanism | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `EXM-008` | Shell Command Execution | HIGH | Execution Mechanism | 17 | 0 | 0.17 | 0.00 | +0.17 |
| `EXS-001` | Import-Time Execution | HIGH | Execution Stage | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `EXS-002` | Install-Time Execution | HIGH | Execution Stage | 11 | 0 | 0.11 | 0.00 | +0.11 |
| `EXS-003` | Lifecycle Hook Hijack | HIGH | Execution Stage | 8 | 0 | 0.08 | 0.00 | +0.08 |
| `MET-001` | Suspicious Author Identity | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-002` | Combosquatting | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-003` | Suspicious Dependency | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-004` | Description Anomaly | LOW | Metadata Manipulation | 8 | 1 | 0.08 | 0.05 | +0.03 |
| `MET-005` | Decoy Functionality | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-006` | Metadata Typosquatting | HIGH | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-001` | Geolocation Lookup | MEDIUM | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `NET-002` | Mining Pool Connection | HIGH | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `NET-003` | Suspicious Connection | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-004` | Archive Dropper | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-005` | Binary Dropper | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-006` | Payload Dropper | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-007` | Script Dropper | HIGH | Network Operations | 3 | 0 | 0.03 | 0.00 | +0.03 |
| `NET-008` | Reverse Shell | HIGH | Network Operations | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `NET-009` | SSL Validation Bypass | MEDIUM | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `NET-010` | Unencrypted Communication | MEDIUM | Network Operations | 2 | 0 | 0.02 | 0.00 | +0.02 |
| `SYS-001` | Environment Modification | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `SYS-002` | Startup File Persistence | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `SYS-003` | Crypto Wallet Harvesting | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `SYS-004` | Directory Enumeration | MEDIUM | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-005` | System Info Reconnaissance | MEDIUM | System Impact | 8 | 0 | 0.08 | 0.00 | +0.08 |
| `SYS-006` | File Relocation | MEDIUM | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-007` | File Deletion | MEDIUM | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |
| `SYS-008` | Arbitrary File Write | MEDIUM | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-009` | Sensitive Path Write | HIGH | System Impact | 1 | 0 | 0.01 | 0.00 | +0.01 |

## 5. 다음 단계

1. 실 패키지 corpus 에서 재측정 — `eval_real.py` 출력에 indicator code list 를 추가하도록 schema 확장 후, 본 스크립트와 동등한 분석을 `eval_real_data/fixtures.json` (N=550) 에 적용.
2. 위 §3.1 후보를 `STANDALONE_WEAK_INDICATORS` 에 추가 → 9-패키지 smoke 재측정 → FP 감소 확인.
3. §3.3 TP=0 indicator 들이 실 데이터에서도 0 이면 매처 hint/regex 점검. 여전히 0 이면 indicator 정의 자체를 재검토 또는 제거.
