# 데이터 소스 (8건)

> 본 엔진이 실제로 DB 에 적재하거나 조회하는 데이터 원천.

---

## 5.1 MITRE ATT&CK Enterprise ★ (현재 V2 사용)

> **STIX 2.x 포맷의 공개 TTP 데이터**

| 항목 | 값 |
|---|---|
| 공식 사이트 | https://attack.mitre.org/ |
| GitHub 저장소 | https://github.com/mitre/cti |
| Raw JSON (Enterprise) | https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json |

**V2 사용 현황:**
- 568 techniques 자동 수집 (`detector/knowledge/mitre_attack.py`)
- 로컬 캐시: `detector/knowledge/cache/mitre_attack.json`
- 임베딩 캐시: `detector/knowledge/cache/mitre_attack_embedded.json`

---

## 5.2 MITRE ATLAS

> **AI 시스템 대상 공격 TTP**

| 항목 | 값 |
|---|---|
| 공식 사이트 | https://atlas.mitre.org/ |

**V2 계획:** 추가 수집기 개발 예정

---

## 5.3 OSV — Open Source Vulnerabilities ★ (현재 V2 사용)

> **Google 운영, PyPI/npm 악성 패키지 공식 DB**

| 항목 | 값 |
|---|---|
| 공식 사이트 | https://osv.dev/ |
| PyPI 전체 덤프 (zip) | https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip |
| npm 전체 덤프 (zip) | https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip |

**V2 사용 현황:**
- PyPI 11,164 악성 advisory 수집 완료 (`detector/knowledge/cache/osv_pypi.json`)
- npm 212,465 악성 advisory 수집 완료 (`detector/knowledge/cache/osv_npm.json`)
- 정확 일치 + 타이포스쿼팅 유사도 매칭 운영

---

## 5.4 GitHub Advisory Database (GHSA)

> **오픈소스 보안 권고 공개 DB**

| 항목 | 값 |
|---|---|
| 공식 | https://github.com/advisories |
| GHSA API | GitHub GraphQL API 를 통해 조회 가능 |

**V2 간접 사용:**
- OSV 덤프에 GHSA advisory 도 포함되므로 간접적으로 사용 중

---

## 5.5 PyPI Safety DB

> **Python 패키지 취약점 공개 DB**

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/pyupio/safety-db |

---

## 5.6 PyPI / npm 공식 레지스트리 API (현재 V2 사용)

### 5.6.1 PyPI JSON API

| 항목 | 값 |
|---|---|
| 엔드포인트 | `https://pypi.org/pypi/{package}/json` |

### 5.6.2 npm Registry

| 항목 | 값 |
|---|---|
| 엔드포인트 | `https://registry.npmjs.org/{package}` |

**V2 내 사용:** `detector/stages/stage0_registry.py`

---

## 5.7 NVD (National Vulnerability Database)

> **미 정부 운영 취약점 DB**

| 항목 | 값 |
|---|---|
| 공식 | https://nvd.nist.gov/ |
| API | https://nvd.nist.gov/developers/vulnerabilities |

---

## 5.8 CWE (Common Weakness Enumeration)

> **MITRE 운영 약점 분류 체계**

| 항목 | 값 |
|---|---|
| 공식 | https://cwe.mitre.org/ |

---

## 5.9 npm Security Advisories

> **npm 공식 권고**

| 항목 | 값 |
|---|---|
| 공식 | https://www.npmjs.com/advisories |

---

## 5.10 OWASP Top 10 for LLM Applications

> **LLM 특화 취약점 카테고리**

| 항목 | 값 |
|---|---|
| 공식 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |

---

## 5.11 데이터 수집 자동화 명령어 (참고용)

본 프로젝트 재현을 위해 실행한 명령:

```bash
# MITRE ATT&CK 568 techniques
python -m detector.knowledge.mitre_attack

# 임베딩 생성 (Sentence-Transformers)
python -m detector.knowledge.embedder

# OSV PyPI (11,164 건)
python -m detector.knowledge.osv PyPI

# OSV npm (212,465 건)
python -m detector.knowledge.osv npm
```

---

## 5.12 캐시 파일 위치 (현 V2 로컬)

| 파일 | 경로 | 크기 (대략) |
|---|---|---|
| MITRE ATT&CK raw | `detector/knowledge/cache/mitre_attack.json` | ~1MB |
| MITRE ATT&CK embedded | `detector/knowledge/cache/mitre_attack_embedded.json` | ~3MB |
| OSV PyPI | `detector/knowledge/cache/osv_pypi.json` | ~30MB |
| OSV npm | `detector/knowledge/cache/osv_npm.json` | ~500MB |

**주의:** 캐시 파일 크기 큰 편. `.gitignore` 필요. (현재 이미 제외됨)
