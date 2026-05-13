# pkgsentinel — VSCode Extension

Real-time supply-chain attack / slopsquatting detection for package manifests.

매니페스트 파일을 열거나 저장하면 모든 의존성을 pkgsentinel 서버로 보내
분석한다. 각 줄에 verdict squiggle 이 표시되고, hover 하면 LLM reasoning
+ TTP evidence 가 보인다.

## 지원 매니페스트

- `package.json` (npm) — dependencies / devDependencies / optional / peer
- `pyproject.toml` (PEP 621 + Poetry)
- `requirements*.txt` (pip)

## 동작 흐름

```
파일 열기/저장
   │
   ▼
manifest 파서 → DependencyMention[]   (name, ecosystem, version, line)
   │
   ▼
verdict 캐시 hit? ── yes ──┐
   │ no                    │
   ▼                       │
POST /api/v1/analyze       │   (HMAC-SHA256 서명)
   │                       │
   └────── 결과 머지 ──────┘
                  │
                  ▼
   Diagnostic (squiggle) + Hover (verdict + evidence) + 상태바 요약
```

## 설치 (개발자 빌드)

```bash
cd clients/vscode
npm install
npm run compile
npm run package        # → pkgsentinel-vscode.vsix
code --install-extension pkgsentinel-vscode.vsix
```

## 설정

| 키 | 기본 | 설명 |
|----|------|------|
| `pkgsentinel.serverUrl` | `http://localhost:8787` | pkgsentinel HTTP 서버 base URL |
| `pkgsentinel.hmacSecret` | `""` | HMAC secret. 빈 문자열이면 unsigned (dev only) |
| `pkgsentinel.llmMode` | `stub` | `stub` (무료) / `claude` (Anthropic Haiku) |
| `pkgsentinel.autoScanOnSave` | `true` | 매니페스트 저장 시 자동 재스캔 |
| `pkgsentinel.maxConcurrent` | `4` | 동시 분석 요청 수 |
| `pkgsentinel.cacheTtlMinutes` | `60` | 클라이언트 verdict 캐시 TTL |
| `pkgsentinel.requestTimeoutSeconds` | `60` | 요청 타임아웃 |

## 명령

- `pkgsentinel: Scan workspace manifests` — 워크스페이스 모든 매니페스트 스캔
- `pkgsentinel: Scan current manifest` — 현재 파일만 스캔
- `pkgsentinel: Clear verdict cache` — 클라이언트 globalState 캐시 비움
- `pkgsentinel: Show output log` — 출력 채널 표시

## 비용

- 캐시 hit 99%/95% 환경에서 LLM 호출 → 사실상 무료
- cache miss + claude 모드 → 패키지당 ~$0.005 (Haiku, multi-agent 3 calls)
- `stub` 모드 → LLM 호출 0, 100% 결정적 (CI/CD 용)

서버 측 캐시가 (package, ecosystem, version, engine_version, rules_hash,
kb_hash) 키로 동일 패키지를 공유 → 100명 사용자가 같은 react@18.2.0 을
분석해도 서버는 한 번만 분석.

## 보안

- `hmacSecret` 은 VSCode settings 에 저장 (Settings Sync 사용 시 동기화됨)
- 매니페스트 *내용* 은 서버로 전송 ✕. **이름 + 버전만** 전송.
- HTTPS 권장 (`serverUrl` 을 https://...)
- 클라이언트 캐시는 `globalState` (사용자 별) — 워크스페이스 간 공유

## 트러블슈팅

| 증상 | 원인 / 조치 |
|------|-------------|
| `🔌 server down` | `serverUrl` 잘못 또는 서버 미기동. `curl <url>/healthz` 로 확인 |
| 401 invalid signature | `hmacSecret` 가 서버측 `PKGSENTINEL_HMAC_SECRET` 와 불일치 |
| Squiggle 안 보임 | 매니페스트 파일명 확인 (`package.json`, `pyproject.toml`, `requirements*.txt`) |
| Timeout | cold pipeline 은 30s+ — `requestTimeoutSeconds` 늘리기 또는 캐시 우선 |

## 라이선스

Apache-2.0. pkgsentinel server 와 동일.
