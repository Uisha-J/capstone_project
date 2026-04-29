"""
pip-audit JSON 결과를 받아 severity 임계로 CI gate.

근거:
- pip-audit 는 모든 vuln 을 동일 가중치로 출력. low/medium 도 fail 하면
  새 의존성 추가 시마다 CI red — 작업 흐름이 끊김.
- 대신 high/critical 만 차단하고 low/medium 은 알람 형태로 보고.
- severity 정보는 OSV / GHSA 의 CVSS 또는 published severity 필드를 사용.

Exit codes:
  0 : 통과 (vuln 없음 또는 모두 low/medium)
  1 : high/critical 발견 — CI 차단
  2 : 입력 파싱 실패
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# 차단 대상 severity. CVSS 환산 또는 OSV 표기.
BLOCK_SEVERITIES = {"HIGH", "CRITICAL", "high", "critical"}


def _vuln_severity(v: dict) -> str:
    """vulnerability dict 에서 severity 추출.

    pip-audit 의 JSON 포맷은 버전에 따라 다양:
      - 최신: vuln["severity"] = "HIGH" | ...
      - 일부: vuln["aliases"] 안의 GHSA 응답에서 score
      - 옛날: severity 필드 없음 → "UNKNOWN"
    """
    s = v.get("severity")
    if s and isinstance(s, str):
        return s
    # 일부 source 는 vector_string + score 만 줄 수 있음 — score 로 추정
    score = v.get("score") or v.get("cvss_score")
    if isinstance(score, (int, float)):
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    return "UNKNOWN"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: audit_gate.py <pip-audit-output.json>", file=sys.stderr)
        return 2

    path = Path(argv[1])
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 2

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"json parse failed: {e}", file=sys.stderr)
        return 2

    # pip-audit 의 JSON 구조: { "dependencies": [ { "vulns": [...] } ] }
    blocking: list[dict] = []
    info: list[dict] = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []) or []:
            sev = _vuln_severity(v)
            entry = {
                "package": dep.get("name", "?"),
                "version": dep.get("version", "?"),
                "id": v.get("id", "?"),
                "severity": sev,
                "fix_versions": v.get("fix_versions", []),
            }
            if sev in BLOCK_SEVERITIES:
                blocking.append(entry)
            else:
                info.append(entry)

    if info:
        print(f"--- {len(info)} info-level vulnerabilities (low/medium/unknown) ---")
        for e in info:
            print(f"  [{e['severity']:<8}] {e['package']}=={e['version']}  {e['id']}")
    if blocking:
        print(f"\n!!! {len(blocking)} HIGH/CRITICAL vulnerabilities detected !!!",
              file=sys.stderr)
        for e in blocking:
            fixv = ", ".join(e["fix_versions"]) or "no fix available"
            print(f"  [{e['severity']}] {e['package']}=={e['version']}  "
                  f"{e['id']}  → fix: {fixv}", file=sys.stderr)
        return 1

    print("\nOK: no high/critical vulnerabilities.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
