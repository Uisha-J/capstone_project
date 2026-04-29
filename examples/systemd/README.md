# systemd 배포 예제

`pkgsentinel-worker` / `pkgsentinel-cron` console script 의 systemd unit 예시.

## 파일

| 파일 | 역할 |
|---|---|
| `pkgsentinel-worker.service` | 큐 consumer (long-running 또는 cron `--max N` 모드) |
| `pkgsentinel-cron.service` | 주기 트리거 oneshot (timer 와 짝) |

> 운영 환경에서는 `pkgsentinel-cron@watch-pypi.service`, `@watch-npm.service`,
> `@refresh-feeds.service` 처럼 instance unit 으로 분리 권장.
> 본 예시는 단일 unit 형태로 단순화.

## 설치 절차

### 1. 사용자 / 디렉터리

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pkgsentinel
sudo mkdir -p /var/lib/pkgsentinel /var/log/pkgsentinel /etc/pkgsentinel
sudo chown -R pkgsentinel:pkgsentinel /var/lib/pkgsentinel /var/log/pkgsentinel
sudo chmod 0700 /etc/pkgsentinel
```

### 2. 패키지 설치 (가상환경 권장)

```bash
sudo -u pkgsentinel python3 -m venv /var/lib/pkgsentinel/venv
sudo -u pkgsentinel /var/lib/pkgsentinel/venv/bin/pip install -e \
    git+https://github.com/Uisha-J/capstone_project#egg=pkgsentinel

# 콘솔 스크립트 심볼릭 링크
sudo ln -sf /var/lib/pkgsentinel/venv/bin/pkgsentinel-worker /usr/local/bin/
sudo ln -sf /var/lib/pkgsentinel/venv/bin/pkgsentinel-cron /usr/local/bin/
sudo ln -sf /var/lib/pkgsentinel/venv/bin/pkgsentinel-feeds /usr/local/bin/
```

### 3. DB 패스워드 등록

```bash
sudo install -m 0600 -o pkgsentinel -g pkgsentinel /dev/null /etc/pkgsentinel/env
# /etc/pkgsentinel/env 내용 (예시 — 실제 비밀번호로 교체):
#   AISLOP_DB_KEY=replace-with-strong-random-passphrase
#   ANTHROPIC_API_KEY=sk-ant-...   # LLM 모드 사용 시
```

### 4. unit 설치

```bash
sudo install -m 0644 pkgsentinel-worker.service /etc/systemd/system/
sudo install -m 0644 pkgsentinel-cron.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 5. timer 설정 (cron 모드)

`/etc/systemd/system/pkgsentinel-cron.timer`:

```ini
[Unit]
Description=pkgsentinel cron timer

[Timer]
# 매 5분마다 trigger
OnCalendar=*:0/5
Persistent=true
Unit=pkgsentinel-cron.service

[Install]
WantedBy=timers.target
```

활성화:

```bash
sudo systemctl enable --now pkgsentinel-cron.timer
sudo systemctl enable --now pkgsentinel-worker.service
```

## 검증

```bash
# 서비스 상태
sudo systemctl status pkgsentinel-worker
sudo systemctl status pkgsentinel-cron.timer

# 큐 상태 확인
sudo -u pkgsentinel pkgsentinel-cron status

# 로그
sudo journalctl -u pkgsentinel-worker -f
sudo journalctl -u pkgsentinel-cron --since "1 hour ago"
```

## 보안 노트

- 본 unit 들은 `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`
  등 systemd hardening 적용. `ReadWritePaths` 만 쓰기 허용.
- DB 키는 `EnvironmentFile=/etc/pkgsentinel/env` (퍼미션 0600). 더 강한
  보호가 필요하면 `LoadCredential=` + systemd-creds (encrypted at rest)
  사용.
- 외부 LLM API 호출 시 `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` 도 같은 env
  파일에 두고 절대 git 에 커밋 금지.

## Docker / Compose 대안

systemd 외에 컨테이너 환경을 선호하면 `Dockerfile` (옵션) 작성 후
docker-compose 로 워커 N개 + cron 스케줄러 구성도 가능.
본 저장소엔 Docker 예제 미포함 (capstone 범위 외).
