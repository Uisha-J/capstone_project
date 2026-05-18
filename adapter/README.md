# Slop Detector Adapter

Chrome / VSCode 익스텐션과 `pkgsentinel` V2 엔진을 연결하는 **FastAPI 어댑터**.

## 역할
- 익스텐션의 단순 HTTP 호출 → 엔진 파이프라인 호출
- 엔진의 풍부한 결과 → 익스텐션 친화적인 단순 구조로 변환
- 두 익스텐션(`Chrome` + `VSCode`)이 같은 API 사용

## 빠른 시작

```bash
# 1. 환경변수 설정
cp ../.env.example ../.env
# .env 열어서 AISLOP_DB_KEY 와 (선택) ANTHROPIC_API_KEY 입력

# 2. Docker 실행 (프로젝트 루트에서)
cd ..
docker compose up -d --build

# 3. 동작 확인
curl http://localhost:8001/health
```

## API 엔드포인트

| Method | Path | 용도 | 사용처 |
|---|---|---|---|
| GET | `/health` | 어댑터 상태 + 현재 LLM 모드 | Chrome |
| GET | `/healthz` | 동일 (VSCode 호환 alias) | VSCode |
| POST | `/analyze` | 패키지 리스트 → 다중 분석 결과 | Chrome |
| POST | `/parse-and-analyze` | 코드 → import 추출 → 분석 | Chrome |
| POST | `/api/v1/analyze` | 단일 패키지 → VSCode 스펙 응답 | VSCode |
| GET | `/verdict-legend` | level 매핑 표 (디버깅) | — |

## 환경변수

`.env.example` 참고. 핵심:

- **`AISLOP_DB_KEY`** *(필수)* — SQLCipher 패스프레이즈
- **`ANTHROPIC_API_KEY`** *(선택)* — Claude API 키. 있으면 진짜 LLM 분석, 없으면 stub
- **`AISLOP_LLM_MODE`** — `auto` / `stub` / `claude`. 기본 `auto` (키 유무로 자동 결정)
- **`AISLOP_HMAC_SECRET`** *(선택)* — 설정 시 모든 POST 요청에 HMAC-SHA256 서명 검증

## 보안

### HMAC 인증 (옵션)
`AISLOP_HMAC_SECRET` 설정 시:
- 모든 POST 요청에 `X-AISLOPSQ-Signature: sha256=<hex>` 헤더 필요
- `X-AISLOPSQ-Timestamp: <ms>` 헤더 — ±5분 허용 (replay 방지)
- 알고리즘: `HMAC_SHA256(secret, f"{ts}.{body_bytes}")`
- `hmac.compare_digest` 사용 (timing attack 방지)

### LLM 모드 자동 결정
`AISLOP_LLM_MODE=auto` (기본):
- `ANTHROPIC_API_KEY`가 `sk-ant-` 로 시작 + 30자 초과 + `...` 미포함 → `claude`
- 그 외 → `stub`

placeholder 값(`sk-ant-api-...`)은 자동으로 stub 처리되어 안전.

## 응답 구조 (PackageResult)

```json
{
  "package": "torch",
  "ecosystem": "PyPI",
  "level": "LOW",
  "verdict": "CLEAN",
  "is_agentic": false,
  "evidence_count": 0,
  "reasons": [],
  "ttp_ids": [],
  "confidence": 0.95,
  "version": "2.12.0",
  "closest_match": null
}
```

`level`: `CRITICAL` / `HIGH` / `MEDIUM` / `AGENTIC` / `LOW` / `UNKNOWN`
`verdict`: `MALICIOUS` / `HIGH_RISK` / `SUSPICIOUS` / `AGENTIC` / `CLEAN` / `CANNOT_ANALYZE` / `ERROR`

## 트러블슈팅

| 증상 | 원인 | 해결 |
|---|---|---|
| `llm_mode: stub` 만 나옴 | API 키 미설정 또는 placeholder | `.env`에 실제 키 입력 후 `docker compose up -d --build` |
| 401 Unauthorized | HMAC 활성인데 익스텐션 시크릿 불일치 | 양쪽 시크릿 같게 설정 |
| 분석 매우 느림 | 첫 호출 시 모델 로딩 | 정상. 두 번째 호출부터 캐시로 빠름 |
