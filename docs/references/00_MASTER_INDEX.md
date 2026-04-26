# 참고 자료 마스터 인덱스

> 본 프로젝트 (AI 슬롭스쿼팅 탐지 → 패키지 위협 탐지 엔진 V2) 에서 참조한 **모든 자료의 공식 원본 경로**.
>
> 최종 정리: 2026-04-25
> 위치: `secure_capstone/reports/references/`

---

## 폴더 구조

```
references/
├── 00_MASTER_INDEX.md            ← (본 문서)
├── 01_papers_academic.md         ← 학술 논문 (9편)
├── 02_frameworks_standards.md    ← 공식 표준/프레임워크 (11건)
├── 03_industry_reports.md        ← 산업 보고서/블로그 (11건)
├── 04_tools_libraries.md         ← 사용 도구/라이브러리 (10건)
├── 05_data_sources.md            ← 데이터 출처 (OSV, MITRE JSON 등)
└── 06_related_projects.md        ← 경쟁/유사 프로젝트
```

---

## 빠른 조회 (우선순위 높은 5건)

| # | 자료 | 경로 |
|---|---|---|
| 1 | **Unveiling Malicious Logic — 47개 지표 택소노미 (2025)** | [01_papers_academic.md#1-1](#) / https://arxiv.org/html/2512.12559v1 |
| 2 | **Cerebro — Behavior Sequence 기반 탐지 (ACM TOSEM 2025)** | [01_papers_academic.md#1-2](#) / https://arxiv.org/abs/2309.02637 |
| 3 | **DONAPI — 132 API 카탈로그 (USENIX Security 2024)** | [01_papers_academic.md#1-3](#) / https://www.usenix.org/system/files/sec24fall-prepub-171-huang-cheng.pdf |
| 4 | **NIST SP 800-218 — SSDF v1.1** | [02_frameworks_standards.md#2-1](#) / https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf |
| 5 | **MITRE ATT&CK Enterprise** | [05_data_sources.md#5-1](#) / https://attack.mitre.org/ |

---

## 카테고리별 건수 요약

| 카테고리 | 건수 |
|---|:---:|
| 학술 논문 | 9 |
| 공식 표준/프레임워크 | 11 |
| 산업 보고서 | 11 |
| 기술 도구/라이브러리 | 10 |
| 데이터 소스 | 8 |
| 유사/경쟁 프로젝트 | 5 |
| **총계** | **54** |

---

## 인용 통계

- 학술 논문 중 **2024~2026 발표**: 6편 (전체 67%)
- 가장 많이 인용: MITRE ATT&CK, Cerebro, Unveiling Malicious Logic
- 공공 프레임워크 다수 (NIST, SLSA, OpenSSF, MITRE, OWASP, CISA)

---

## 사용 원칙 (법적/학술적)

1. **판정 근거 인용**: 모든 Evidence 의 TTP 매핑은 공식 자료 원문을 인용
2. **코드 라이선스**: 모든 참조 도구의 라이선스 확인 (MIT, Apache 2.0 위주)
3. **BibTeX**: 학술 인용을 위한 BibTeX 는 `01_papers_academic.md` 말미에 정리
4. **연구 윤리**: OSV, GHSA 등 공개 DB 만 사용. 유료/비공개 자료 없음.
