# 학술 논문 (9편)

> 모든 URL 은 공식 원본. arXiv 는 HTML + PDF 링크 모두 표기.
> 연도는 공식 게재/업로드 기준.

---

## 1.1 Unveiling Malicious Logic (2025) ★

> **Unveiling Malicious Logic: Towards a Statement-Level Taxonomy and Dataset for Securing Python Packages**

| 항목 | 값 |
|---|---|
| 연도 | 2025 |
| arXiv ID | 2512.12559 |
| HTML | https://arxiv.org/html/2512.12559v1 |
| PDF | https://www.arxiv.org/pdf/2512.12559 |

**핵심 기여:**
- 47개 악성 지표 × 7개 유형 세밀 택소노미
- Statement-level 라벨링 데이터셋
- Sequential pattern mining 으로 공격 시퀀스 추출

**V2 직접 반영 예정:**
- `detector/knowledge/malicious_indicators.py` 신규 모듈 (47개 지표)
- 현재 4 Dimension → 7 Category 확장

---

## 1.2 Cerebro (2025, ACM TOSEM) ★

> **Killing Two Birds with One Stone: Malicious Package Detection in NPM and PyPI using a Single Model of Malicious Behavior Sequence**

| 항목 | 값 |
|---|---|
| 저자 | Junan Zhang, Kaifeng Huang, Yiheng Huang, Bihuan Chen, Ruisi Wang, Chong Wang, Xin Peng |
| 게재 | ACM Transactions on Software Engineering and Methodology (TOSEM), 2025 |
| DOI | 10.1145/3705304 |
| arXiv | 2309.02637 |
| HTML | https://arxiv.org/html/2309.02637v2 |
| PDF | https://arxiv.org/pdf/2309.02637 |
| ACM | https://dl.acm.org/doi/10.1145/3705304 |
| ResearchGate | https://www.researchgate.net/publication/373715331 |

**핵심 기여:**
- 16 features 를 Behavior Sequence 로 모델링
- PyPI 683개 + npm 799개 신규 악성 패키지 탐지
- 운영팀으로부터 385+ 감사 메일
- Tree-sitter 기반 AST 쿼리

**V2 반영됨:**
- `stages/api_catalog.py` 의 4 Attack Dimension 개념
- Tree-sitter 접근 방식

---

## 1.3 DONAPI (USENIX Security 2024)

> **Donapi: Malicious NPM Packages Detector using Behavior Sequence Knowledge Mapping**

| 항목 | 값 |
|---|---|
| 게재 | USENIX Security Symposium 2024 |
| arXiv | 2403.08334 |
| HTML | https://arxiv.org/html/2403.08334v1 |
| USENIX PDF | https://www.usenix.org/system/files/sec24fall-prepub-171-huang-cheng.pdf |
| USENIX Final | https://www.usenix.org/system/files/usenixsecurity24-huang-cheng.pdf |

**핵심 기여:**
- 132개 native API 모니터링
- 12 behavior types + 40 subtypes
- Behavior Sequence Knowledge Mapping

**V2 반영됨:**
- `stages/api_catalog.py` 의 API 카탈로그 구조

---

## 1.4 Taint-Based Code Slicing for LLMs (2025)

> **Taint-Based Code Slicing for LLMs-based Malicious NPM Package Detection**

| 항목 | 값 |
|---|---|
| 연도 | 2025 |
| arXiv ID | 2512.12313 |
| HTML | https://arxiv.org/html/2512.12313 |

**핵심 기여:**
- LLM 에 전체 코드 대신 taint slice 만 전달
- JavaScript 특화 taint 분석
- LLM 비용/오탐 동시 감소

**V2 활용 예정:**
- Stage 2 에 간이 taint 추적 추가
- Stage 5 LLM 프롬프트에 slice 만 첨부

---

## 1.5 Mind the Gap (2025)

> **Mind the Gap: Evaluating LLMs for High-Level Malicious Package Detection vs. Fine-Grained Indicator Identification**

| 항목 | 값 |
|---|---|
| 연도 | 2025 |
| arXiv ID | 2602.16304 |
| HTML | https://arxiv.org/html/2602.16304 |

**핵심 기여:**
- 13개 LLM 비교 평가
- "고수준 판정" vs "세부 지표 식별" 분리 벤치마크
- PyPI 전용 벤치마크 데이터

**V2 활용:**
- Stage 5 LLM 프롬프트 이분화 (고수준 확정 / fine-grained 추출)

---

## 1.6 LAMPS: LLM 다중 에이전트 (2025)

> **Many Hands Make Light Work: An LLM-based Multi-Agent System for Detecting Malicious PyPI Packages**

| 항목 | 값 |
|---|---|
| 연도 | 2025 |
| arXiv ID | 2601.12148 |
| HTML | https://arxiv.org/html/2601.12148v1 |

**핵심 기여:**
- 다중 에이전트로 해석 가능한 판정
- 각 에이전트가 다른 관점 담당
- 감사 가능한 의사결정

**V2 활용:**
- Stage 5 를 여러 전문 에이전트로 분리

---

## 1.7 NPM Benchmark (2025)

> **Understanding NPM Malicious Package Detection: A Benchmark-Driven Empirical Analysis**

| 항목 | 값 |
|---|---|
| 연도 | 2025 |
| arXiv ID | 2603.27549 |
| HTML | https://arxiv.org/html/2603.27549 |

**핵심 기여:**
- 6,420 악성 + 7,288 양성 벤치마크
- 11개 행위 카테고리 + 8개 회피 기법
- 2020~2025 패키지, 8 도구 / 13 변형 평가

**V2 활용:**
- 우리 엔진 Precision/Recall 측정 데이터셋

---

## 1.8 Robust Industry Detection (2024)

> **Towards Robust Detection of Open Source Software Supply Chain Poisoning Attacks in Industry Environments**

| 항목 | 값 |
|---|---|
| 연도 | 2024 |
| arXiv ID | 2409.09356 |
| Abstract | https://arxiv.org/abs/2409.09356 |
| HTML | https://arxiv.org/html/2409.09356 |
| PDF | https://arxiv.org/pdf/2409.09356 |

**핵심 기여:**
- 산업 환경 낮은 FP 율 튜닝 방법론
- PyPI 2022 FP 폭주 사례 분석

---

## 1.9 기타 관련 논문

### 1.9.1 We Have a Package for You (USENIX)

> **We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs**

| 항목 | 값 |
|---|---|
| 게재 | USENIX Security 2024 |
| URL | https://www.usenix.org/publications/loginonline/we-have-package-you-comprehensive-analysis-package-hallucinations-code |
| 저자 | University of Texas at San Antonio, Virginia Tech, University of Oklahoma |

**핵심 수치:**
- 19.7% 환각률 (전체 LLM 평균)
- 21.7% vs 5.2% (오픈소스 vs 독점)
- 58% 환각이 10회 중 2회 이상 재등장
- 38% 환각 이름이 실제 패키지와 매우 유사

### 1.9.2 Library Hallucinations

> **Library Hallucinations in LLMs: Risk Analysis Grounded in Real-World Incidents** (2025)

| 항목 | 값 |
|---|---|
| URL | https://arxiv.org/pdf/2509.22202 |

### 1.9.3 PyPI 메타데이터 기반 탐지

> **Malicious Package Detection using Metadata Information**

| 항목 | 값 |
|---|---|
| arXiv | 2402.07444 |
| Abstract | https://arxiv.org/abs/2402.07444 |
| HTML | https://arxiv.org/html/2402.07444v1 |
| PDF | https://arxiv.org/pdf/2402.07444 |

### 1.9.4 SCORE (2024)

> **SCORE: Syntactic Code Representations for Static Script Malware Detection**

| 항목 | 값 |
|---|---|
| arXiv | 2411.08182 |
| HTML | https://arxiv.org/html/2411.08182v1 |

### 1.9.5 Knowledge-Mining PyPI 탐지

> **Cutting the Gordian Knot: Detecting Malicious PyPI Packages via a Knowledge-Mining Framework**

| 항목 | 값 |
|---|---|
| arXiv | 2601.16463 |
| HTML | https://arxiv.org/html/2601.16463v1 |
| PDF | https://arxiv.org/pdf/2601.16463 |

### 1.9.6 PyPI 악성 실증

> **An Empirical Study of Malicious Code In PyPI Ecosystem**

| 항목 | 값 |
|---|---|
| PDF | https://lcwj3.github.io/img_cs/pdf/An%20Empirical%20Study%20of%20Malicious%20Code%20In%20PyPI%20Ecosystem.pdf |

### 1.9.7 ML 기반 PyPI 탐지

> **A Machine Learning-Based Approach For Detecting Malicious PyPI Packages**

| 항목 | 값 |
|---|---|
| ResearchGate | https://www.researchgate.net/publication/386555242 |

### 1.9.8 LLM 공급망 중간자 공격

> **Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain**

| 항목 | 값 |
|---|---|
| arXiv | 2604.08407 |
| Abstract | https://arxiv.org/abs/2604.08407v1 |
| HTML | https://arxiv.org/html/2604.08407v1 |

### 1.9.9 LLM 코딩 에이전트 스킬 공급망 공격

> **Supply-Chain Poisoning Attacks Against LLM Coding Agent Skill Ecosystems**

| 항목 | 값 |
|---|---|
| arXiv | 2604.03081 |
| Abstract | https://arxiv.org/abs/2604.03081 |
| HTML | https://arxiv.org/html/2604.03081 |

### 1.9.10 LLM 환각 취약성 측정

> **Importing Phantoms: Measuring LLM Package Hallucination Vulnerabilities**

| 항목 | 값 |
|---|---|
| arXiv | 2501.19012 |
| HTML | https://arxiv.org/html/2501.19012v1 |

### 1.9.11 Robust/Adaptive Detection (2025)

> **Robust and Adaptive Detection of Malicious Packages from ...**

| 항목 | 값 |
|---|---|
| arXiv | 2512.04338 |
| PDF | https://arxiv.org/pdf/2512.04338 |

---

## BibTeX 통합

```bibtex
@article{unveiling2025taxonomy,
  title={Unveiling Malicious Logic: Towards a Statement-Level Taxonomy and Dataset for Securing Python Packages},
  year={2025},
  eprint={2512.12559},
  archivePrefix={arXiv}
}

@article{cerebro2025,
  title={Killing Two Birds with One Stone: Malicious Package Detection in NPM and PyPI using a Single Model of Malicious Behavior Sequence},
  author={Zhang, Junan and Huang, Kaifeng and Huang, Yiheng and Chen, Bihuan and Wang, Ruisi and Wang, Chong and Peng, Xin},
  journal={ACM Transactions on Software Engineering and Methodology},
  year={2025},
  publisher={ACM},
  doi={10.1145/3705304}
}

@inproceedings{donapi2024,
  title={Donapi: Malicious NPM Packages Detector using Behavior Sequence Knowledge Mapping},
  booktitle={USENIX Security Symposium},
  year={2024}
}

@article{taint2025slicing,
  title={Taint-Based Code Slicing for LLMs-based Malicious NPM Package Detection},
  year={2025},
  eprint={2512.12313},
  archivePrefix={arXiv}
}

@article{mindgap2025,
  title={Mind the Gap: Evaluating LLMs for High-Level Malicious Package Detection vs. Fine-Grained Indicator Identification},
  year={2025},
  eprint={2602.16304},
  archivePrefix={arXiv}
}

@article{lamps2025,
  title={Many Hands Make Light Work: An LLM-based Multi-Agent System for Detecting Malicious PyPI Packages},
  year={2025},
  eprint={2601.12148},
  archivePrefix={arXiv}
}

@article{npmbench2025,
  title={Understanding NPM Malicious Package Detection: A Benchmark-Driven Empirical Analysis},
  year={2025},
  eprint={2603.27549},
  archivePrefix={arXiv}
}

@article{robust2024industry,
  title={Towards Robust Detection of Open Source Software Supply Chain Poisoning Attacks in Industry Environments},
  year={2024},
  eprint={2409.09356},
  archivePrefix={arXiv}
}

@inproceedings{usenix2024hallucination,
  title={We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs},
  booktitle={USENIX Security Symposium},
  year={2024}
}
```
