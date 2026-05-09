# 47-Indicator FP / TP 통계표 — 실 패키지 코퍼스

> 생성일: 2026-05-06  
> 매니페스트: `scripts\eval_real_data\popular_benign_manifest.json`  
> 코퍼스: malicious=0, benign=100 (매니페스트 총 100, 처리 100)  
> 적용 범위: `indicator_matcher.match_all` 만 — Stage 0/3/4D/4E/5/6, LLM, threat-intel, sentence-transformers 우회

## 핵심 요약

- **FP rate ≥ 30%** (STANDALONE_WEAK 강력 후보): 0개
- **FP rate 15~30%** (combo 강화 후보): 3개
- **FP rate 5~15%** (관찰): 10개
- **고변별 workhorse** (TP≥10% + FP=0): 0개
- **TP=0** (코퍼스에서 미발화): 47개

## 2. FP rate 15~30% — risk_combo 강화 후보

단독으로는 약함. 다른 indicator 와 동시 발화일 때만 escalation.

| Code | Name | Sev | TP | FP | FP rate | TP rate | Discrim |
|---|---|---|---|---|---|---|---|
| `EXM-002` | Conditional Payload Trigger | MEDIUM | 0 | 22 | 0.22 | 0.00 | -0.22 |
| `EXM-005` | Dynamic Module Import | MEDIUM | 0 | 21 | 0.21 | 0.00 | -0.21 |
| `EXM-001` | Dynamic Evaluation | HIGH | 0 | 18 | 0.18 | 0.00 | -0.18 |

## 3. FP rate 5~15% — 관찰

| Code | Name | Sev | TP | FP | FP rate | TP rate | Discrim |
|---|---|---|---|---|---|---|---|
| `SYS-002` | Startup File Persistence | HIGH | 0 | 14 | 0.14 | 0.00 | -0.14 |
| `SYS-005` | System Info Reconnaissance | MEDIUM | 0 | 14 | 0.14 | 0.00 | -0.14 |
| `EXM-008` | Shell Command Execution | HIGH | 0 | 13 | 0.13 | 0.00 | -0.13 |
| `DEF-003` | Encoding-Based Obfuscation | HIGH | 0 | 11 | 0.11 | 0.00 | -0.11 |
| `EXS-001` | Import-Time Execution | HIGH | 0 | 9 | 0.09 | 0.00 | -0.09 |
| `EXM-003` | Binary Execution | HIGH | 0 | 9 | 0.09 | 0.00 | -0.09 |
| `EXS-002` | Install-Time Execution | HIGH | 0 | 8 | 0.08 | 0.00 | -0.08 |
| `EXM-006` | Dynamic Package Install | HIGH | 0 | 6 | 0.06 | 0.00 | -0.06 |
| `EXF-001` | Data Exfiltration | HIGH | 0 | 6 | 0.06 | 0.00 | -0.06 |
| `DEF-006` | Error Suppression | LOW | 0 | 5 | 0.05 | 0.00 | -0.05 |

## 4. 고변별 Workhorse (TP rate ≥10% + FP=0)

(없음 — 코퍼스에 악성이 적거나 매처 회복률 부족)

## 5. 전체 47-indicator 표 (코드 순)

| Code | Name | Sev | Cat | TP | FP | TP rate | FP rate | Discrim |
|---|---|---|---|---|---|---|---|---|
| `DEF-001` | ASCII Art Deception | MEDIUM | Defense Evasion | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `DEF-002` | Computational Obfuscation | MEDIUM | Defense Evasion | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `DEF-003` | Encoding-Based Obfuscation | HIGH | Defense Evasion | 0 | 11 | 0.00 | 0.11 | -0.11 |
| `DEF-004` | Encryption-Based Obfuscation | HIGH | Defense Evasion | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `DEF-005` | Embedded String Payload | HIGH | Defense Evasion | 0 | 4 | 0.00 | 0.04 | -0.04 |
| `DEF-006` | Error Suppression | LOW | Defense Evasion | 0 | 5 | 0.00 | 0.05 | -0.05 |
| `EXF-001` | Data Exfiltration | HIGH | Exfiltration | 0 | 6 | 0.00 | 0.06 | -0.06 |
| `EXF-002` | File Exfiltration | HIGH | Exfiltration | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `EXF-003` | DNS Tunneling | HIGH | Exfiltration | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `EXF-004` | Webhook Exfiltration | HIGH | Exfiltration | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `EXF-005` | Suspicious Domain Exfiltration | HIGH | Exfiltration | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `EXM-001` | Dynamic Evaluation | HIGH | Execution Mechanism | 0 | 18 | 0.00 | 0.18 | -0.18 |
| `EXM-002` | Conditional Payload Trigger | MEDIUM | Execution Mechanism | 0 | 22 | 0.00 | 0.22 | -0.22 |
| `EXM-003` | Binary Execution | HIGH | Execution Mechanism | 0 | 9 | 0.00 | 0.09 | -0.09 |
| `EXM-004` | Hidden Code Execution | HIGH | Execution Mechanism | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `EXM-005` | Dynamic Module Import | MEDIUM | Execution Mechanism | 0 | 21 | 0.00 | 0.21 | -0.21 |
| `EXM-006` | Dynamic Package Install | HIGH | Execution Mechanism | 0 | 6 | 0.00 | 0.06 | -0.06 |
| `EXM-007` | Script File Execution | HIGH | Execution Mechanism | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `EXM-008` | Shell Command Execution | HIGH | Execution Mechanism | 0 | 13 | 0.00 | 0.13 | -0.13 |
| `EXS-001` | Import-Time Execution | HIGH | Execution Stage | 0 | 9 | 0.00 | 0.09 | -0.09 |
| `EXS-002` | Install-Time Execution | HIGH | Execution Stage | 0 | 8 | 0.00 | 0.08 | -0.08 |
| `EXS-003` | Lifecycle Hook Hijack | HIGH | Execution Stage | 0 | 1 | 0.00 | 0.01 | -0.01 |
| `MET-001` | Suspicious Author Identity | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-002` | Combosquatting | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-003` | Suspicious Dependency | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-004` | Description Anomaly | LOW | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-005` | Decoy Functionality | MEDIUM | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `MET-006` | Metadata Typosquatting | HIGH | Metadata Manipulation | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-001` | Geolocation Lookup | MEDIUM | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-002` | Mining Pool Connection | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-003` | Suspicious Connection | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-004` | Archive Dropper | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-005` | Binary Dropper | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-006` | Payload Dropper | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-007` | Script Dropper | HIGH | Network Operations | 0 | 1 | 0.00 | 0.01 | -0.01 |
| `NET-008` | Reverse Shell | HIGH | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `NET-009` | SSL Validation Bypass | MEDIUM | Network Operations | 0 | 4 | 0.00 | 0.04 | -0.04 |
| `NET-010` | Unencrypted Communication | MEDIUM | Network Operations | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-001` | Environment Modification | HIGH | System Impact | 0 | 2 | 0.00 | 0.02 | -0.02 |
| `SYS-002` | Startup File Persistence | HIGH | System Impact | 0 | 14 | 0.00 | 0.14 | -0.14 |
| `SYS-003` | Crypto Wallet Harvesting | HIGH | System Impact | 0 | 1 | 0.00 | 0.01 | -0.01 |
| `SYS-004` | Directory Enumeration | MEDIUM | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-005` | System Info Reconnaissance | MEDIUM | System Impact | 0 | 14 | 0.00 | 0.14 | -0.14 |
| `SYS-006` | File Relocation | MEDIUM | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-007` | File Deletion | MEDIUM | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-008` | Arbitrary File Write | MEDIUM | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |
| `SYS-009` | Sensitive Path Write | HIGH | System Impact | 0 | 0 | 0.00 | 0.00 | +0.00 |

## 6. 다음 단계

2. `EXM-002`, `EXM-005`, `EXM-001` 를 `pipeline.py` 의 `RISK_COMBO_TRIGGER_CODES` 에서 검토 (combo 동반 조건이 약하면 강화)
3. TP=0 indicator 47개 — 매처 hint/regex 점검 또는 코퍼스에 해당 공격 패턴이 부재한지 확인
