# pkgsentinel — Docker 배포

본 디렉터리는 **#S3** — Flask HTTP 서버를 Docker 로 배포하기 위한 자산.

## 파일

- `Dockerfile.server` — multi-stage build, non-root, healthcheck 포함
- `docker-compose.yml` — 단일 호스트용 스택 (server only)
- `.env.example` — 필요한 환경변수 예시
- `.dockerignore` — 빌드 컨텍스트 축소

## 1. 빠른 시작 (단일 컨테이너)

```bash
# 1) DB 키 + HMAC secret 생성
export AISLOP_DB_KEY=$(openssl rand -hex 32)
export PKGSENTINEL_HMAC_SECRET=$(openssl rand -hex 32)

# 2) 이미지 빌드
docker build -t pkgsentinel-server:latest \
    -f deploy/docker/Dockerfile.server .

# 3) 실행
docker run -d --name pkgsentinel \
    -p 8787:8787 \
    -e AISLOP_DB_KEY=$AISLOP_DB_KEY \
    -e PKGSENTINEL_HMAC_SECRET=$PKGSENTINEL_HMAC_SECRET \
    -e ANTHROPIC_API_KEY=sk-ant-... \
    -v pkgsentinel-data:/var/lib/pkgsentinel \
    -v pkgsentinel-logs:/var/log/pkgsentinel \
    --read-only --tmpfs /tmp \
    --security-opt no-new-privileges:true \
    pkgsentinel-server:latest

# 4) 헬스체크
curl http://localhost:8787/healthz
curl http://localhost:8787/readyz
curl http://localhost:8787/metrics
```

## 2. compose 사용

```bash
cp deploy/docker/.env.example deploy/docker/.env
# .env 편집 — secret/key 값 채우기
vim deploy/docker/.env

docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml logs -f
```

## 3. 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| POST   | /api/v1/analyze       | 패키지 분석 (S1) — 캐시 우선 |
| POST   | /api/v1/runtime-alert | Falco/Wazuh/Tetragon webhook (#R5/#L1) |
| GET/POST | /api/v1/iocs/export | 학습 IOC sync (S2) |
| GET    | /healthz              | liveness probe |
| GET    | /readyz               | readiness probe (DB 연결 검증) |
| GET    | /metrics              | Prometheus 카운터 |

## 4. HMAC 인증

`PKGSENTINEL_HMAC_SECRET` 가 설정되면 모든 POST endpoint 가 HMAC-SHA256
검증을 수행. 클라이언트는 다음 헤더 동봉:

- `X-AISLOPSQ-Signature: sha256=<hex>`
- `X-AISLOPSQ-Timestamp: <epoch_ms>`

서명 알고리즘: `pkgsentinel.realtime.sinks.webhook_sink.hmac_sign` 참고.

```python
from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign
import time, json, requests

body_dict = {"package": "evil", "ecosystem": "npm"}
body = json.dumps(body_dict).encode("utf-8")
ts = int(time.time() * 1000)
sig = hmac_sign(SECRET, ts, body)

r = requests.post(
    "http://server:8787/api/v1/analyze",
    data=body,
    headers={
        "Content-Type": "application/json",
        "X-AISLOPSQ-Signature": f"sha256={sig}",
        "X-AISLOPSQ-Timestamp": str(ts),
    },
)
```

GET `/api/v1/iocs/export` 는 query string 기반 — HMAC 검증 skip (read endpoint).

## 5. systemd 대안 (bare-metal)

Docker 대신 systemd 단독 운영 시: `deploy/systemd/pkgsentinel-server.service`
참고. `gunicorn` 명령으로 동일한 WSGI app 노출.

## 6. 운영 권장

- **이미지 보안**: `--read-only` + `tmpfs /tmp` + non-root (uid 10001) — 본
  Dockerfile 기본값.
- **Reverse proxy**: TLS termination 은 nginx / traefik 에서.
  HSTS / rate-limit / CORS 도 reverse proxy 측 처리 권장.
- **백업**: `pkgsentinel-data` volume (`/var/lib/pkgsentinel/*.sqlcipher`) —
  SQLCipher 암호화 상태로 그대로 백업 가능.
- **로그 회전**: `--log-opt max-size=100m --log-opt max-file=5` 권장.
- **모니터링**: `/metrics` 를 Prometheus 가 scrape. Grafana 대시보드는 추후.

## 7. 부하 예측 (참고)

| 시나리오 | RPS | LLM 호출 | 월 비용 (Haiku) |
|----------|-----|----------|-----------------|
| 캐시 hit 99% | 100 | 1 | ~$0.5 |
| 캐시 hit 95% | 100 | 5 | ~$3 |
| 캐시 hit 50% | 10  | 5 | ~$3 |

cache hit ratio 가 LLM 비용을 결정. 동일 패키지/버전 분석은 무료.
