# pkgsentinel × FIM 통합 가이드 (#R5)

본 디렉터리는 **Wazuh / OSSEC / osquery** 같은 FIM (File Integrity Monitoring)
도구가 *수상한 패키지 활동* 을 감지했을 때, pkgsentinel 의 **인바운드 webhook
API** (`POST /api/v1/runtime-alert`) 로 자동 트리거되도록 하는 구성 예시.

## 토폴로지

```
   [Wazuh agent]                    [pkgsentinel API server]
   ─── syscheck                     ─── handle_runtime_alert()
       FIM event                          │
   ─── active-response                    │
       │                                  │
       └─→ POST runtime-alert ────────────┘
                                          │
                                          ▼
                                  IOC 추출 → DB 적재
                                  attack_index live-update
                                  자동 룰 draft 생성
                                          │
                                          ▼
                                  enriched verdict + STIX/Falco/Tetragon/pmg 알림
                                  → fleet-wide 차단 정책 전파
```

## 1. Wazuh 통합

### 1-A. syscheck 모니터링 — npm / pip / 시스템 자격증명 경로

`/var/ossec/etc/ossec.conf` 에 추가:

```xml
<!-- pkgsentinel: 패키지 설치 경로 + 자격증명 변경 감지 -->
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /opt/app/node_modules
  </directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /opt/app/.venv/lib/python3.11/site-packages
  </directories>

  <!-- 자격증명 read 감지 — 어느 process 든 -->
  <directories check_all="yes" realtime="yes">
    /root/.ssh
  </directories>
  <directories check_all="yes" realtime="yes">
    /home/*/.aws
  </directories>
  <directories check_all="yes" realtime="yes">
    /home/*/.ssh
  </directories>

  <!-- crontab / systemd / launchd — persistence 시도 감지 -->
  <directories check_all="yes" realtime="yes">
    /etc/cron.d
  </directories>
  <directories check_all="yes" realtime="yes">
    /etc/systemd/system
  </directories>

  <!-- 무시 — 자체 로그 -->
  <ignore>/var/log</ignore>
  <ignore>/var/lib/pkgsentinel</ignore>
</syscheck>
```

### 1-B. active-response — pkgsentinel API 트리거

`/var/ossec/etc/ossec.conf` 의 `<active-response>` 섹션:

```xml
<command>
  <name>pkgsentinel-trigger</name>
  <executable>pkgsentinel-trigger.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>pkgsentinel-trigger</command>
  <location>local</location>
  <!-- 트리거 조건: 위 syscheck 디렉터리에서 변경 감지 시 -->
  <rules_id>550,551,552,553,554</rules_id>
</active-response>
```

스크립트 `/var/ossec/active-response/bin/pkgsentinel-trigger.sh`:

```bash
#!/usr/bin/env bash
# Wazuh active-response → pkgsentinel webhook
# /var/ossec/active-response/bin/pkgsentinel-trigger.sh
set -euo pipefail

ACTION="$1"   # add | delete
USER="$2"
IP="$3"
ALERT_ID="$4"
RULE_ID="$5"
AGENT_NAME="$6"
EVENT="$7"    # 원본 alert JSON (Wazuh 가 전달)

# pkgsentinel API endpoint + HMAC secret (사전 공유)
PKGSENTINEL_URL="${PKGSENTINEL_URL:-https://pkgsentinel.internal/api/v1/runtime-alert}"
PKGSENTINEL_SECRET="${PKGSENTINEL_SECRET}"

# 본 alert 를 pkgsentinel 의 ParsedEvent 형식으로 wrap
BODY=$(cat <<EOF
{
  "source": "wazuh",
  "rule": {"id": "$RULE_ID"},
  "agent": {"name": "$AGENT_NAME", "ip": "$IP"},
  "syscheck": $EVENT
}
EOF
)

# HMAC-SHA256 timestamp(ms) + body
TS=$(date +%s%3N)
SIG=$(printf '%s.' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$PKGSENTINEL_SECRET" | awk '{print $2}')

# POST
curl -fsSL "$PKGSENTINEL_URL" \
  -H "Content-Type: application/json" \
  -H "X-AISLOPSQ-Event: runtime-alert" \
  -H "X-AISLOPSQ-Timestamp: $TS" \
  -H "X-AISLOPSQ-Signature: sha256=$SIG" \
  --data-binary "$BODY" \
  2>/dev/null || true

exit 0
```

권한 설정:
```bash
chmod 750 /var/ossec/active-response/bin/pkgsentinel-trigger.sh
chown root:ossec /var/ossec/active-response/bin/pkgsentinel-trigger.sh
```

### 1-C. 사용자 정의 룰 — package install path 변경

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="pkgsentinel,syscheck,">
  <rule id="100501" level="7">
    <if_sid>550</if_sid>
    <field name="file">/opt/app/node_modules</field>
    <description>pkgsentinel: node_modules content changed</description>
  </rule>
  <rule id="100502" level="9">
    <if_sid>550</if_sid>
    <field name="file">.ssh|.aws/credentials|.npmrc|.pypirc</field>
    <description>pkgsentinel: credential file modified</description>
  </rule>
  <rule id="100503" level="10">
    <if_sid>550</if_sid>
    <field name="file">/etc/cron|/etc/systemd</field>
    <description>pkgsentinel: persistence path modified</description>
  </rule>
</group>
```

## 2. osquery 통합 (대안)

osquery scheduled query:

```sql
-- /etc/osquery/osquery.conf snippet
{
  "schedule": {
    "pkgsentinel_new_packages": {
      "query": "SELECT name, version, path FROM npm_packages WHERE path LIKE '/opt/%';",
      "interval": 300
    },
    "pkgsentinel_python_packages": {
      "query": "SELECT name, version, path FROM python_packages WHERE path LIKE '/opt/%';",
      "interval": 300
    },
    "pkgsentinel_suspicious_processes": {
      "query": "SELECT pid, name, cmdline, parent FROM processes WHERE name IN ('curl', 'wget', 'nc') AND cmdline LIKE '%http%';",
      "interval": 60
    }
  }
}
```

osquery → Fleet/Zeek → pkgsentinel webhook 으로 동일 흐름.

## 3. pkgsentinel API server 띄우기

서버 측 (간단 Flask 어댑터 예시):

```python
# pkgsentinel_api_server.py
import os
import json
from flask import Flask, request, jsonify

from pkgsentinel.api.runtime_alert import handle_runtime_alert

app = Flask(__name__)
SHARED_SECRET = os.environ["PKGSENTINEL_SHARED_SECRET"]

@app.post("/api/v1/runtime-alert")
def runtime_alert():
    raw = request.get_data()
    payload = json.loads(raw)
    sig = request.headers.get("X-AISLOPSQ-Signature")
    ts = int(request.headers.get("X-AISLOPSQ-Timestamp", "0"))

    resp, code = handle_runtime_alert(
        payload,
        signature_header=sig,
        timestamp_ms=ts,
        raw_body=raw,
        shared_secret=SHARED_SECRET,
        enable_repipeline=False,    # True 시 LLM 비용 발생
    )
    return jsonify(resp), code


if __name__ == "__main__":
    # 프로덕션은 gunicorn + nginx 권장
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"))
```

systemd unit `/etc/systemd/system/pkgsentinel-api.service`:

```ini
[Unit]
Description=pkgsentinel runtime-alert webhook API
After=network-online.target

[Service]
Type=simple
User=pkgsentinel
Group=pkgsentinel
WorkingDirectory=/opt/pkgsentinel
EnvironmentFile=/etc/pkgsentinel/env
ExecStart=/opt/pkgsentinel/.venv/bin/gunicorn \
    --bind 0.0.0.0:8443 \
    --workers 2 --timeout 60 \
    --certfile=/etc/pkgsentinel/server.pem \
    --keyfile=/etc/pkgsentinel/server.key \
    pkgsentinel_api_server:app

Restart=on-failure
RestartSec=10s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/pkgsentinel
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```

## 4. 운영 흐름 검증

1. Wazuh agent 가 `~/.aws/credentials` 변경 감지
2. active-response 가 webhook POST
3. pkgsentinel `handle_runtime_alert` 가:
   - HMAC 검증
   - Wazuh syscheck 이벤트 파싱
   - IOC 추출 (`path: ~/.aws/credentials` 등)
   - DB 적재 (`runtime_observations`)
   - 학습된 IOC 누적 → 다중 패키지 등장 시 자동 promote
   - 룰 draft 자동 생성 (indicator_47 / falco / aislopsq_r)
   - attack_index live-update — 즉시 적용
4. SIEM (STIX/TAXII) 알림 + (옵션) PmgPolicy install 차단

## 5. 검토 / 운영 CLI

```bash
# IOC 누적 상태
pkgsentinel-intel stats

# 최근 24시간 alert
pkgsentinel-intel list-observations --limit 50

# pending IOC 검토
pkgsentinel-intel list-iocs --status pending

# 룰 draft 검토 + 승인
pkgsentinel-intel list-rules --status draft --verbose
pkgsentinel-intel approve-rule --id 7 --by alice

# OSSF 기여를 위해 approved IOC → OSV advisory
pkgsentinel-intel export-osv --out-dir /tmp/osv-pr-batch-2026-05
```

## 6. 보안 고려사항

- **HMAC 공유 secret** — pkgsentinel `AISLOP_WEBHOOK_SECRET` 환경변수와 Wazuh
  `PKGSENTINEL_SECRET` 환경변수가 *동일* 해야. KMS (#3.4 KMS backends) 사용 권장.
- **replay 방지** — timestamp ±5분 외 alert 자동 거부 (hmac_verify 가 처리).
- **TLS 강제** — pkgsentinel API 는 HTTPS 만. self-signed 또는 Let's Encrypt.
- **rate limit** — nginx / WAF 단에서 IP 당 분당 100 req 권장.

## 7. 통합 검증 체크리스트

- [ ] Wazuh active-response 가 webhook POST 성공 (curl + HMAC 헤더 확인)
- [ ] pkgsentinel API 가 401 (잘못된 sig) / 200 (정상) 정확히 구분
- [ ] `runtime_observations` 테이블에 row 적재 확인
- [ ] `learned_iocs` 에 IP/path/domain 추출 결과 누적 확인
- [ ] `attack_index` 가 재시작 없이 새 IOC 인식 (다음 분석 시 즉시 매치)
- [ ] STIX sink (또는 webhook sink) 가 enriched verdict 전송 확인

## 8. 관련 우리 구현 부분

- 인바운드 webhook 핸들러: `src/pkgsentinel/api/runtime_alert.py`
- IOC 추출기: `src/pkgsentinel/intel/extractor.py`
- DB 저장소: `src/pkgsentinel/db/runtime_intel.py`
- 룰 자동 생성: `src/pkgsentinel/intel/rule_generator.py`
- attack_index live-update: `src/pkgsentinel/knowledge/attack_index.py`
  (`add_runtime_pattern`, `add_runtime_ioc`)
- 운영 CLI: `python -m pkgsentinel.intel.cli`
- OSV export: `src/pkgsentinel/intel/osv_export.py`
- Generic strict-mode Falco/Tetragon: `src/pkgsentinel/realtime/sinks/falco_policy.py`
  (`generate_strict_mode_falco`, `generate_strict_mode_tetragon`)
