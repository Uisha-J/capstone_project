# 관련/경쟁 프로젝트 (5건)

> 유사한 목적을 가진 기존 오픈소스 및 상용 도구.

---

## 6.1 Phantom Guard (오픈소스, 비교 완료)

> **의존성 파일 기반 공급망 공격 탐지**

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/matte1782/phantom_guard |

**특징:**
- Python, 비동기 우선 설계
- PyPI / npm / Cargo 지원
- 15개 위험 신호 기반 가중치 분석
- VS Code / GitHub Action / pre-commit 통합

**본 프로젝트 대비:**
- Phantom Guard: 설치 전 `requirements.txt` 검사
- 본 프로젝트: **AI 응답 시점 + 소스코드 분석**

---

## 6.2 SlopGuard (오픈소스)

> **AI 환각 패키지 의존성 탐지**

| 항목 | 값 |
|---|---|
| URL | https://aditya01933.github.io/aditya.github.io/slopguard |

**특징:**
- 3단계 지연 로딩 trust scoring
- 메타데이터 중심 탐지
- 다운로드 수 가중치, 연령, 유지관리자 신뢰도

**본 프로젝트 대비:**
- SlopGuard: 메타데이터 + 배포 지표 중심
- 본 프로젝트: **실제 코드 행위 분석 + MITRE 매핑**

---

## 6.3 Socket (상용)

> **공급망 보안 플랫폼**

| 항목 | 값 |
|---|---|
| 공식 | https://socket.dev/ |
| 블로그 | https://socket.dev/blog |

**참고:**
- 메타데이터 + 소스 분석 결합
- Chrome Extension 제공 (패키지 레지스트리 페이지 대상)
- 본 프로젝트와 차별점: Socket 은 레지스트리 페이지 기반, 우리는 **AI 사이트 실시간**

---

## 6.4 Snyk (상용)

> **취약점 / 공급망 보안**

| 항목 | 값 |
|---|---|
| 공식 | https://snyk.io/ |

---

## 6.5 Aikido Security (상용)

> **공급망 / AI 보안**

| 항목 | 값 |
|---|---|
| 공식 | https://www.aikido.dev/ |

---

## 6.6 Dependabot (GitHub 내장)

> **GitHub 의 의존성 자동 업데이트**

| 항목 | 값 |
|---|---|
| 공식 | https://github.com/dependabot |

**한계:**
- 취약점 알림은 하지만, **악성 패키지 존재 여부는 검증 안 함**

---

## 6.7 AI Slop Detection Chrome Extensions (비교)

### 6.7.1 Slop Evader

| 항목 | 값 |
|---|---|
| Chrome Web Store | https://chromewebstore.google.com/detail/slop-evader/mlofdhcgaaimlpbjlhpfnpjfpebjpdpp |

### 6.7.2 AI Slop Meter

| 항목 | 값 |
|---|---|
| Chrome Web Store | https://chromewebstore.google.com/detail/ai-slop-meter/mhjlleifaocopeongciebnkjpidaocai |

### 6.7.3 AI Slop Detector (오픈소스)

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/voidcommit-afk/ai-slop-detector |

**참고:** AI 생성 이미지/텍스트 탐지 (본 프로젝트와는 범위 다름)

### 6.7.4 AI Slop Detector (텍스트, Gemma 기반)

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/Priyansurout/ai-slop-detector-extension |

---

## 6.8 LLM 환각 탐지 연구 도구 (참고)

### 6.8.1 SelfCheckGPT

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/potsawee/selfcheckgpt |

### 6.8.2 LLM_Check

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/GaurangSriramanan/LLM_Check_Hallucination_Detection |
| 게재 | NeurIPS 2024 |

### 6.8.3 HalluciNot (aimonlabs)

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/aimonlabs/hallucination-detection-model |

### 6.8.4 MIND (ACL 2024)

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/oneal2000/MIND |

### 6.8.5 EasyDetect

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/OpenKG-ORG/EasyDetect |

### 6.8.6 Awesome Hallucination Detection (큐레이션)

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/EdinburghNLP/awesome-hallucination-detection |

### 6.8.7 Idiap Hallucination Detection

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/idiap/hallucination-detection |

### 6.8.8 MLLM Hallucination (큐레이션)

| 항목 | 값 |
|---|---|
| GitHub | https://github.com/showlab/Awesome-MLLM-Hallucination |

### 6.8.9 GitHub Topic: hallucination-detection

| 항목 | 값 |
|---|---|
| URL | https://github.com/topics/hallucination-detection |

---

## 6.9 본 프로젝트 포지셔닝 요약

| 측면 | Phantom Guard | SlopGuard | Socket | Snyk | **본 프로젝트** |
|---|:---:|:---:|:---:|:---:|:---:|
| AI 응답 실시간 감지 | ✗ | ✗ | ✗ | ✗ | **✓** |
| 소스코드 정적 분석 | ✗ | ✗ | ✓ | ✓ | **✓** |
| 의존성 재귀 분석 | ✓ | ✓ | ✓ | ✓ | **✓** |
| 바이너리 분석 | ✗ | ✗ | ✗ | ✗ | **✓** |
| 샌드박스 동적 분석 | ✗ | ✗ | 일부 | ✓ | **✓** |
| MITRE TTP 공식 매핑 | ✗ | ✗ | ✗ | ✗ | **✓** |
| LLM 이중 검증 | ✗ | ✗ | ✗ | ✗ | **✓** |
| 오픈소스 | ✓ | ✓ | ✗ | ✗ | **✓** |
| 비용 | 무료 | 무료 | 상용 | 상용 | **무료** |

**차별점:** AI 사이트 실시간 + 공식 TTP + 범용 분석 + 완전 오픈소스 조합은 본 프로젝트가 유일.
