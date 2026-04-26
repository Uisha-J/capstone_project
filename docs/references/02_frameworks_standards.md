# 공식 표준 및 프레임워크 (11건)

> 정부기관 / 국제 표준기구 / 산업 컨소시엄 공식 문서.
> 모든 URL 은 원본 공식 사이트.

---

## 2.1 NIST SP 800-218 (SSDF v1.1) ★

> **Secure Software Development Framework (SSDF) Version 1.1**

| 항목 | 값 |
|---|---|
| 발행 | NIST (National Institute of Standards and Technology) |
| 버전 | v1.1 (2022), v1.2 Draft (2025) |
| 공식 PDF | https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf |
| CSRC 인덱스 | https://csrc.nist.gov/projects/ssdf |
| v1.1 Final | https://csrc.nist.gov/pubs/sp/800/218/final |
| v1.2 Draft | https://csrc.nist.gov/pubs/sp/800/218/r1/ipd |
| CISA 게시 | https://www.cisa.gov/resources-tools/resources/nist-sp-800-218-secure-software-development-framework-v11-recommendations-mitigating-risk-software |
| 해설 | https://www.aikido.dev/learn/compliance/compliance-frameworks/nist-ssdf |
| Chainguard 매핑 | https://edu.chainguard.dev/software-security/secure-software-development/ssdf/ |
| 구현 가이드 | https://www.blackduck.com/blog/nist-ssdf-secure-software-development.html |

**V2 관련 핵심 항목:**
- **PW.4**: Reuse existing secure software (외부 소프트웨어 검증)
- **PW.4.1**: Provenance, SBOM 이해
- **PW.4.4**: 지속적 취약점 모니터링

---

## 2.2 NIST SP 800-218A (AI 모델 SSDF)

> **Secure Software Development Practices for Generative AI and Dual-Use Foundation Models**

| 항목 | 값 |
|---|---|
| 발행 | NIST |
| 공식 PDF | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.ipd.pdf |

**V2 연관:**
- LLM 환각 기반 공급망 공격에 대한 정부 공식 인식

---

## 2.3 MITRE ATT&CK ★

> **Adversarial Tactics, Techniques, and Common Knowledge**

| 항목 | 값 |
|---|---|
| 운영 | The MITRE Corporation |
| 공식 사이트 | https://attack.mitre.org/ |
| STIX 데이터 저장소 | https://github.com/mitre/cti |
| Enterprise Matrix JSON (raw) | https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json |

**V2 반영됨:**
- `knowledge/mitre_attack.py` 에서 568 techniques 자동 수집 중
- 주요 매핑: T1027, T1048, T1059, T1105, T1552

---

## 2.4 MITRE ATLAS

> **Adversarial Threat Landscape for AI Systems**

| 항목 | 값 |
|---|---|
| 운영 | MITRE |
| 공식 사이트 | https://atlas.mitre.org/ |

**V2 활용 예정:**
- AI/LLM 특화 TTP (현재 미수집, 향후 추가)

---

## 2.5 OWASP Top 10 for LLM Applications

> **OWASP Foundation 공식 리스트 — LLM 특화 취약점 Top 10**

| 항목 | 값 |
|---|---|
| 공식 프로젝트 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |

**V2 연관:**
- LLM05 (Supply Chain) 카테고리와 슬롭스쿼팅 직접 연결

---

## 2.6 SLSA v1.0 ★

> **Supply-chain Levels for Software Artifacts**

| 항목 | 값 |
|---|---|
| 운영 | OpenSSF (Google 주도) |
| 공식 사이트 | https://slsa.dev/ |
| OpenSSF 프로젝트 페이지 | https://openssf.org/projects/slsa/ |
| Wiz 해설 | https://www.wiz.io/academy/application-security/slsa-framework |
| Harness 해설 | https://www.harness.io/blog/slsa-supply-chain-levels-for-software-artifacts |
| Checkmarx 해설 | https://checkmarx.com/glossary/what-is-the-slsa-framework/ |
| Chainguard 소개 | https://edu.chainguard.dev/compliance/slsa/what-is-slsa/ |
| Sonar 리소스 | https://www.sonarsource.com/resources/library/slsa/ |
| CyberArk 개발자 블로그 | https://developer.cyberark.com/blog/what-is-slsa-supply-chain-levels-for-software-artifacts/ |

**4단계 레벨:**
- L1: 프로비넌스 문서화
- L2: 빌드 플랫폼 디지털 서명
- L3: 빌드 환경 격리
- L4: 최고 수준

---

## 2.7 CISA — Securing the Software Supply Chain (2024)

> **Enduring Security Framework: Securing the Software Supply Chain**

| 항목 | 값 |
|---|---|
| 발행 | CISA (Cybersecurity and Infrastructure Security Agency, 미국) |
| 공식 PDF | https://www.cisa.gov/sites/default/files/2024-08/SECURING_THE_SOFTWARE_SUPPLY_CHAIN_SUPPLIERS_508.pdf |

**V2 연관:**
- 부록 C: SLSA 적용 권고
- 미 연방 공식 지침으로 인용 시 권위 확보

---

## 2.8 OpenSSF Scorecard ★

> **오픈소스 프로젝트 보안 자동 평가 도구**

| 항목 | 값 |
|---|---|
| 운영 | OpenSSF (Linux Foundation) |
| 공식 사이트 | https://scorecard.dev/ |
| GitHub | https://github.com/ossf/scorecard |
| 해설 | https://www.deployhub.com/openssf-scorecard/ |
| Sbomify 설명 | https://sbomify.com/2024/04/25/openssf-and-openssf-scorecards-bolstering-open-source-security/ |

**18+ 체크:**
Binary-Artifacts, Branch-Protection, CII-Best-Practices, Code-Review, Dangerous-Workflow, Dependency-Update-Tool, Fuzzing, Maintained, Packaging, Pinned-Dependencies, SAST, Security-Policy, Signed-Releases, Token-Permissions, Vulnerabilities, Webhooks 등

---

## 2.9 OpenSSF OSPS Baseline (2024)

> **Open Source Project Security Baseline**

| 항목 | 값 |
|---|---|
| 공식 | https://baseline.openssf.org/ |
| Kusari 소개 | https://www.kusari.dev/blog/introducing-osps-baseline |
| OpenSSF Tech Talk | https://www.kusari.dev/blog/openssf-tech-talk-recap-using-the-osps-baseline-to-navigate-standards-and-regulations |

**8개 카테고리 통제 + YAML 스펙**
SSDF, Scorecard, OCRE, CRA 와 교차 매핑

---

## 2.10 GUAC (Graph for Understanding Artifact Composition)

> **OpenSSF 공급망 그래프 DB**

| 항목 | 값 |
|---|---|
| OpenSSF | https://openssf.org/tag/guac/ |

**기능:**
- SBOM + SLSA + 취약점 + Scorecard 를 그래프로 통합

---

## 2.11 SBOM 표준

### CycloneDX

| 항목 | 값 |
|---|---|
| 공식 | https://cyclonedx.org/ |

### SPDX

| 항목 | 값 |
|---|---|
| 공식 | https://spdx.dev/ |

**V2 활용 예정:**
- CycloneDX VEX 포맷으로 분석 결과 출력

---

## 2.12 OWASP Top 10 (웹 일반)

| 항목 | 값 |
|---|---|
| 공식 | https://owasp.org/www-project-top-ten/ |

---

## 2.13 Common Vulnerability Scoring System (CVSS)

| 항목 | 값 |
|---|---|
| 공식 (FIRST) | https://www.first.org/cvss/ |
