#!/usr/bin/env bash
# pkgsentinel × Wazuh active-response 어댑터.
# 설치: /var/ossec/active-response/bin/pkgsentinel-trigger.sh
# 권한: chmod 750; chown root:ossec
#
# 환경변수 (/etc/pkgsentinel/env 또는 wazuh-manager systemd unit):
#   PKGSENTINEL_URL=https://pkgsentinel.internal/api/v1/runtime-alert
#   PKGSENTINEL_SECRET=<HMAC shared secret — pkgsentinel 의 AISLOP_WEBHOOK_SECRET 과 동일>
set -euo pipefail

# Wazuh 가 전달하는 위치 인자
ACTION="${1:-}"        # add | delete
USER="${2:-}"
IP="${3:-}"
ALERT_ID="${4:-}"
RULE_ID="${5:-}"
AGENT_NAME="${6:-$(hostname)}"
EVENT_JSON="${7:-{}}"  # 원본 alert JSON (Wazuh 가 escape 해서 전달)

PKGSENTINEL_URL="${PKGSENTINEL_URL:-https://pkgsentinel.internal/api/v1/runtime-alert}"
PKGSENTINEL_SECRET="${PKGSENTINEL_SECRET:-}"

# 환경변수 없으면 silent exit — Wazuh 알림 전반 영향 없음
if [[ -z "$PKGSENTINEL_SECRET" ]]; then
    echo "[pkgsentinel-trigger] PKGSENTINEL_SECRET unset, skipping" >&2
    exit 0
fi

# Wazuh ParsedEvent 호환 body
BODY=$(cat <<EOF
{
  "source": "wazuh",
  "rule": {"id": "$RULE_ID"},
  "agent": {"name": "$AGENT_NAME", "ip": "$IP"},
  "syscheck": $EVENT_JSON
}
EOF
)

TS=$(date +%s%3N)
# HMAC-SHA256("<ts>.<body>")
SIG=$(printf '%s.' "$TS" | { cat; printf '%s' "$BODY"; } \
        | openssl dgst -sha256 -hmac "$PKGSENTINEL_SECRET" -hex \
        | awk '{print $NF}')

# 타임아웃 짧게 — active-response 가 Wazuh 큐를 블록 안 하게.
# 실패는 silent — pkgsentinel 가용성 문제 시 Wazuh syscheck 알림은 유지.
curl --max-time 8 -fsSL "$PKGSENTINEL_URL" \
    -H "Content-Type: application/json" \
    -H "X-AISLOPSQ-Event: runtime-alert" \
    -H "X-AISLOPSQ-Timestamp: $TS" \
    -H "X-AISLOPSQ-Signature: sha256=$SIG" \
    --data-binary "$BODY" \
    >/dev/null 2>&1 || true

exit 0
