# Slop Detector — Chrome 익스텐션

AI 챗봇 응답의 패키지 추천을 **실시간으로 슬롭스쿼팅(악성 패키지) 분석**.

## 지원 사이트
| 사이트 | 호스트 |
|---|---|
| Claude | `claude.ai`, `*.claudeusercontent.com` (아티팩트 iframe) |
| ChatGPT | `chatgpt.com` |
| Gemini | `gemini.google.com` |
| Perplexity | `*.perplexity.ai` |
| Microsoft Copilot | `copilot.microsoft.com` |
| DeepSeek | `chat.deepseek.com` |
| xAI Grok | `grok.com` |
| Phind | `www.phind.com` |
| Mistral Le Chat | `chat.mistral.ai` |

## 설치
1. `chrome://extensions/` 열기
2. 우상단 **개발자 모드** 활성화
3. **"압축해제된 확장 프로그램을 로드합니다"** → 이 폴더 선택 (`clients/chrome/`)
4. 익스텐션 활성화

## 사용 흐름
1. 어댑터가 `localhost:8001`에서 실행 중인지 확인 (`docker compose up -d`)
2. 지원 사이트에서 LLM에게 코드 또는 패키지 설치 명령 질문
3. 응답 안에 import / `pip install` / `npm install` 발견되면 **자동 스캔**
4. 결과 패널이 채팅 아래(또는 아티팩트 옆)에 표시됨

## 패널 표시
- **위험 카운터**: `⚠ 위험 N · ❓ 미지 M · ✓ 안전 K`
- **칩 색상**: 빨강(CRITICAL/HIGH) / 주황(MEDIUM) / 보라(AGENTIC) / 점선회색(UNKNOWN) / 서브틀(LOW)
- **다크/라이트 자동 감지**: 페이지 배경 휘도 측정
- **상세 토글**: 클릭하면 패키지별 verdict, TTP, LLM 분석, 코드 스니펫 표시

## 설정 (팝업)

익스텐션 아이콘 클릭 → 팝업 하단:

- **HMAC Secret** *(선택)* — 어댑터 `AISLOP_HMAC_SECRET`와 같은 값 입력 시 인증 활성화. 비우면 인증 안 함 (개발 모드)

## 보안
- **권한**: `storage` 1개만 + 명시된 호스트 (와일드카드 남용 없음)
- **외부 통신**: `http://localhost:8001` (어댑터)로만, 외부 서비스 직접 호출 없음
- **XSS 방어**: LLM 응답의 모든 텍스트 `_esc()`로 HTML escape
- **CSP 우회 없음** — `eval`, `document.write`, 원격 스크립트 로드 X
- **HMAC 인증** *(옵션)* — `AISLOP_HMAC_SECRET` 설정 시 WebCrypto로 SHA-256 서명, replay 방지(±5분), timing-safe 비교

## 아키텍처
```
content/common.js        — 공통 (패키지 추출, 패널 빌더, 다크모드 감지)
content/claude.js        — claude.ai (채팅 + 인라인 아티팩트)
content/artifact.js      — claudeusercontent.com iframe (CF 프레임 자동 스킵)
content/chatgpt.js       — chatgpt.com
content/gemini.js        — gemini.google.com
content/generic.js       — Perplexity/Copilot/DeepSeek/Grok/Phind/Mistral
background.js            — Service Worker (어댑터 호출 + HMAC 서명)
popup.html / popup.js    — 상태 표시 + HMAC secret 설정
```

## import → PyPI 패키지명 매핑
import 이름과 PyPI 패키지명이 다른 흔한 경우 자동 보정:
- `cv2` → `opencv-python`
- `sklearn` → `scikit-learn`
- `PIL` → `Pillow`
- `bs4` → `beautifulsoup4`
- `yaml` → `PyYAML`
- `pytorch` → `torch`
- `dotenv` → `python-dotenv`
- 등 (전체 목록은 `content/common.js`의 `IMPORT_TO_PYPI` 참고)

이 매핑 없으면 `cv2` 같은 합법 import가 "PyPI 미등록"으로 잘못 판정됨.

## 트러블슈팅

| 증상 | 해결 |
|---|---|
| "분석 엔진 오프라인" | `docker compose ps` 로 `slop_api` 컨테이너 확인 |
| 패널 안 나옴 | `chrome://extensions/` 새로고침 + 페이지 Ctrl+R |
| Claude 아티팩트 안 나옴 | 매니페스트에 `*.claudeusercontent.com` 권한 확인 |
| 같은 응답에 패널 2개 | 익스텐션 새로고침 (옛 코드 캐시) |
