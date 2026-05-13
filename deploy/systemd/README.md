# pkgsentinel — systemd 운영 자산

24시간 daemon 운영을 위한 5개 service / 3개 timer 묶음.

## 토폴로지

```
   refresh-feeds.timer (daily 03:30 UTC)
       └─→ refresh-feeds.service       # OSV / GHSA / 위협 피드 캐시 갱신

   watch-pypi.timer (5min)
       └─→ watch-pypi.service          # PyPI XMLRPC → priority queue enqueue

   watch-npm.timer (5min)
       └─→ watch-npm.service           # npm changes → priority queue enqueue

   pkgsentinel-worker.service          # queue 상시 consume → 분석 → STIX/Falco/webhook sink
       (Type=simple, --loop, --llm-model haiku, MemoryMax=4G)

   pkgsentinel-server.service          # HTTP API — analyze / runtime-alert / iocs-export
       (Type=simple, gunicorn -w 4 --threads 2, port 8787, #S3)
```

## 설치 (Ubuntu / RHEL 가족)

```bash
# 1. 시스템 유저
sudo useradd --system --home /opt/pkgsentinel --shell /usr/sbin/nologin pkgsentinel
sudo mkdir -p /opt/pkgsentinel /var/lib/pkgsentinel /var/log/pkgsentinel \
              /etc/pkgsentinel /var/lib/pkgsentinel/sinks

# 2. 코드 + venv
sudo -u pkgsentinel git clone <repo> /opt/pkgsentinel
sudo -u pkgsentinel python3 -m venv /opt/pkgsentinel/.venv
sudo -u pkgsentinel /opt/pkgsentinel/.venv/bin/pip install -e /opt/pkgsentinel

# 3. 환경 파일 (DB 키 + 옵션 sink 설정)
sudo install -m 0640 -o root -g pkgsentinel /dev/stdin /etc/pkgsentinel/env <<'EOF'
# 필수 — DB 마스터 패스프레이즈 (또는 AISLOP_KMS=aws 로 외부 KMS)
AISLOP_DB_KEY=__GENERATE_AND_REPLACE__

# 필수 — Stage 5 LLM
ANTHROPIC_API_KEY=__YOUR_KEY__

# HTTP API server (#S3) HMAC secret — 클라이언트(VSCode extension 등)와 공유.
# 미설정 시 server 가 HMAC 검증을 skip (dev 모드 — prod 비권장).
PKGSENTINEL_HMAC_SECRET=__GENERATE_AND_REPLACE__

# 선택 — sink. 비어 두면 sink 비활성, verdict 만 DB 에 적재.
AISLOP_STIX_OUT_DIR=/var/lib/pkgsentinel/sinks/stix
AISLOP_FALCO_OUT_DIR=/var/lib/pkgsentinel/sinks/falco
# AISLOP_WEBHOOK_URL=https://siem.example.com/in
# AISLOP_WEBHOOK_SECRET=<hmac secret>
# AISLOP_PMG_OUT_DIR=/var/lib/pkgsentinel/sinks/pmg
# TAXII 2.1 (collection objects endpoint) — Basic 또는 Bearer 중 택1
# AISLOP_TAXII_URL=https://taxii.example.com/api/v1/collections/aislopsq/objects/
# AISLOP_TAXII_USER=<basic-user>     # Basic auth
# AISLOP_TAXII_PASS=<basic-pass>     # Basic auth
# AISLOP_TAXII_BEARER=<jwt>          # OpenCTI/MISP 류 (우선)
EOF

# 4. 캐시 빌드 (한 번만; refresh-feeds.timer 가 이후 갱신)
sudo -u pkgsentinel /opt/pkgsentinel/.venv/bin/python -m pkgsentinel.knowledge.osv PyPI
sudo -u pkgsentinel /opt/pkgsentinel/.venv/bin/python -m pkgsentinel.knowledge.osv npm
sudo -u pkgsentinel /opt/pkgsentinel/.venv/bin/python -m pkgsentinel.knowledge.mitre_attack
sudo -u pkgsentinel /opt/pkgsentinel/.venv/bin/python -m pkgsentinel.knowledge.embedder

# 5. systemd unit 설치
sudo install -m 0644 deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload

# 6. 활성화
sudo systemctl enable --now \
    pkgsentinel-refresh-feeds.timer \
    pkgsentinel-watch-pypi.timer \
    pkgsentinel-watch-npm.timer \
    pkgsentinel-worker.service \
    pkgsentinel-server.service     # HTTP API (#S3)

# 7. 동작 확인
systemctl status pkgsentinel-worker
journalctl -u pkgsentinel-worker -f --since "10 min ago"
```

## 24h 운영 비용 예상 (Haiku 모드)

- watch-pypi: 5분 × 24h = 288 호출 (XMLRPC만, $0)
- watch-npm:  5분 × 24h = 288 호출 (changes feed, $0)
- worker:     queue 의존. 대략 신규 release **수천 건/일** 중 *enqueue 우선순위*
              에 따라 worker 가 처리 — Haiku 4.5 × multi-agent (3 calls/pkg).
              예상 800-1500 pkg/day × 3 × $0.01 = **$24-45/day**.
- refresh-feeds: 1회/day × ~5분 × 네트워크만 ($0)

Sonnet 모드면 위 비용의 ~5배 → $120-225/day.

## 운영 점검

```bash
# 큐 상태
sudo -u pkgsentinel /opt/pkgsentinel/.venv/bin/python -m pkgsentinel.monitor.cron_main status

# 최근 분석 결과
sudo -u pkgsentinel sqlite3 \
    /var/lib/pkgsentinel/threat_db.sqlcipher \
    "SELECT package, ecosystem, version, verdict, analyzed_at \
     FROM analyses ORDER BY analyzed_at DESC LIMIT 20"
# (실제로는 SQLCipher pragma key 필요 — pysqlcipher 권장)

# 디스크 — OSV cache 약 250MB, 분석 DB 약 50MB/일 가정
df -h /var/lib/pkgsentinel
```

## 정지 / 비활성

```bash
sudo systemctl disable --now \
    pkgsentinel-refresh-feeds.timer \
    pkgsentinel-watch-pypi.timer \
    pkgsentinel-watch-npm.timer \
    pkgsentinel-worker.service \
    pkgsentinel-server.service
```

## 보안 모델

- `User=pkgsentinel` — 비특권 service account
- `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`
- `MemoryMax=4G` — TTP embedder + AttackIndex (총 ~2GB 사용; 여유 4GB)
- 비밀은 `/etc/pkgsentinel/env` (mode 0640, owner root:pkgsentinel) 또는 외부 KMS
- 악성 패키지 **소스코드 자체는 실행하지 않음** (static 분석만). sandbox 동적
  분석은 별도 Docker 컨테이너 (`stage_sandbox.StraceDockerSandbox`) 에서만.
