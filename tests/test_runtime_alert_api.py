"""runtime_alert API + IOC extractor 단위 테스트."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.api.runtime_alert import handle_runtime_alert
from pkgsentinel.intel.extractor import (
    ParsedEvent,
    extract_iocs_from_event,
    extract_pattern_from_event,
    parse_event,
)
from pkgsentinel.realtime.sinks.webhook_sink import hmac_sign


def _setup():
    td = tempfile.mkdtemp(prefix="rt_alert_")
    os.environ["AISLOP_DB_KEY"] = "rt-alert-test"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )
    return td


def _teardown(td):
    import shutil; shutil.rmtree(td, ignore_errors=True)


# ─────────────── 파서 — Falco ───────────────

def test_parse_falco_openat():
    print("== parse Falco openat ==")
    p = {
        "source": "falco",
        "rule": "Sensitive file read",
        "output_fields": {
            "evt.type": "openat",
            "fd.name": "/root/.ssh/id_rsa",
            "proc.cmdline": "node /opt/foo",
        },
    }
    ev = parse_event("falco", p)
    assert ev.source == "falco"
    assert "/root/.ssh/id_rsa" in ev.file_paths_read
    print("  OK")


def test_parse_falco_connect():
    print("\n== parse Falco connect ==")
    p = {
        "source": "falco",
        "rule": "External outbound",
        "output_fields": {
            "evt.type": "connect",
            "fd.sip": "185.143.223.5",
            "fd.sport": 443,
        },
    }
    ev = parse_event("falco", p)
    assert ev.connect_targets and "185.143.223.5" in ev.connect_targets[0]
    print(f"  OK {ev.connect_targets}")


def test_parse_tetragon_open():
    print("\n== parse Tetragon ==")
    p = {
        "process_kprobe": {
            "process": {"binary": "/usr/bin/node", "pod": {"namespace": "ci"}},
            "function_name": "security_file_open",
            "args": [{"file_arg": "/home/runner/.aws/credentials"}],
        },
    }
    ev = parse_event("tetragon", p)
    assert any(".aws/credentials" in p_ for p_ in ev.file_paths_read)
    print("  OK")


def test_parse_wazuh_syscheck():
    print("\n== parse Wazuh syscheck ==")
    p = {
        "rule": {"id": "550", "level": 7, "description": "Integrity"},
        "agent": {"name": "ci-host-1"},
        "syscheck": {
            "path": "/opt/app/node_modules/.bin/payload",
            "sha256_after": "a" * 64,
        },
    }
    ev = parse_event("wazuh", p)
    assert "/opt/app/node_modules/.bin/payload" in ev.file_paths_written
    assert ev.host == "ci-host-1"
    print("  OK")


def test_parse_manual_passthrough():
    print("\n== parse manual ==")
    p = {
        "source": "manual",
        "package": "evil-x", "ecosystem": "npm", "version": "1.0",
        "connect_targets": ["evil.example.com:443"],
        "file_paths_read": ["/etc/passwd"],
    }
    ev = parse_event("manual", p)
    assert ev.package == "evil-x"
    assert "evil.example.com:443" in ev.connect_targets
    print("  OK")


# ─────────────── IOC extractor ───────────────

def test_extract_external_ip():
    print("\n== IOC: 외부 IP ==")
    ev = ParsedEvent(source="falco", connect_targets=["185.143.223.5:443"])
    iocs = extract_iocs_from_event(ev)
    assert any(i["type"] == "ip" and "185.143.223.5" in i["value"]
               for i in iocs)
    print(f"  OK {iocs}")


def test_extract_skips_internal_ip():
    print("\n== IOC: 사설 IP 제외 ==")
    ev = ParsedEvent(source="falco",
                     connect_targets=["127.0.0.1:80", "10.0.0.5:443"])
    iocs = extract_iocs_from_event(ev)
    assert not any(i["type"] == "ip" for i in iocs)
    print("  OK")


def test_extract_external_domain():
    print("\n== IOC: 외부 domain ==")
    ev = ParsedEvent(source="falco",
                     dns_queries=["attacker.example.com",
                                  "registry.npmjs.org"])
    iocs = extract_iocs_from_event(ev)
    domains = {i["value"] for i in iocs if i["type"] == "domain"}
    assert "attacker.example.com" in domains
    # trusted registry 는 IOC 아님
    assert "registry.npmjs.org" not in domains
    print(f"  OK {domains}")


def test_extract_sensitive_path():
    print("\n== IOC: 자격증명 경로 ==")
    ev = ParsedEvent(
        source="falco",
        file_paths_read=["/root/.ssh/id_rsa", "/etc/shadow",
                         "/tmp/normal.txt"],
    )
    iocs = extract_iocs_from_event(ev)
    paths = {i["value"] for i in iocs if i["type"] == "path"}
    assert any(".ssh/id_rsa" in p for p in paths)
    assert any("/etc/shadow" in p for p in paths)
    # 일반 임시 파일은 IOC 아님
    assert not any("/tmp/normal.txt" in p for p in paths)
    print(f"  OK {paths}")


def test_extract_syscall_chain():
    print("\n== IOC: syscall chain (creds + external) ==")
    ev = ParsedEvent(
        source="falco",
        file_paths_read=["/root/.ssh/id_rsa"],
        connect_targets=["185.143.223.5:443"],
    )
    iocs = extract_iocs_from_event(ev)
    chains = [i for i in iocs if i["type"] == "syscall_chain"]
    assert chains
    assert chains[0]["confidence"] >= 0.8
    print(f"  OK chain={chains}")


def test_extract_sha256():
    print("\n== IOC: sha256 ==")
    h = "a" * 64
    ev = ParsedEvent(source="wazuh", raw={"sha256_after": h})
    iocs = extract_iocs_from_event(ev)
    assert any(i["type"] == "sha256" and i["value"] == h for i in iocs)
    print("  OK")


# ─────────────── 패턴 추출 ───────────────

def test_pattern_cred_exfil():
    print("\n== pattern: cred + network → EXF-001/NET-001 ==")
    ev = ParsedEvent(
        source="falco",
        file_paths_read=["/root/.aws/credentials"],
        connect_targets=["185.143.223.5:443"],
    )
    pat = extract_pattern_from_event(ev)
    assert "INFORMATION_READING" in pat["dimensions"]
    assert "DATA_TRANSMISSION" in pat["dimensions"]
    assert "EXF-001" in pat["indicator_codes"]
    print(f"  OK {pat['summary']}")


def test_pattern_exec_dimension():
    print("\n== pattern: exec command ==")
    ev = ParsedEvent(source="falco", exec_commands=["/bin/sh -c 'curl evil'"])
    pat = extract_pattern_from_event(ev)
    assert "PAYLOAD_EXECUTION" in pat["dimensions"]
    print("  OK")


# ─────────────── handle_runtime_alert end-to-end ───────────────

def test_handle_alert_no_hmac():
    """HMAC secret None 이면 검증 skip."""
    print("\n== handle: HMAC skip mode ==")
    td = _setup()
    try:
        payload = {
            "source": "falco",
            "package": "evil-pkg", "ecosystem": "npm", "version": "0.0.1",
            "event": {
                "rule": "cred exfil",
                "output_fields": {
                    "evt.type": "openat",
                    "fd.name": "/root/.ssh/id_rsa",
                },
            },
        }
        resp, code = handle_runtime_alert(payload)
        assert code == 200
        assert resp["ok"] is True
        assert resp["observation_id"] > 0
        assert resp["iocs_recorded"] >= 1
        print(f"  OK iocs={resp['iocs_recorded']}")
    finally:
        _teardown(td)


def test_handle_alert_with_hmac_invalid():
    print("\n== handle: HMAC 잘못된 sig → 401 ==")
    td = _setup()
    try:
        body = b'{"source":"falco","event":{}}'
        resp, code = handle_runtime_alert(
            json.loads(body),
            signature_header="sha256=deadbeef",
            timestamp_ms=int(time.time() * 1000),
            raw_body=body,
            shared_secret="my-secret",
        )
        assert code == 401
        print(f"  OK rejected: {resp}")
    finally:
        _teardown(td)


def test_handle_alert_with_hmac_valid():
    print("\n== handle: HMAC 정상 sig → 200 ==")
    td = _setup()
    try:
        body_dict = {
            "source": "falco",
            "event": {
                "rule": "external connect",
                "output_fields": {
                    "evt.type": "connect",
                    "fd.sip": "185.143.223.5",
                    "fd.sport": 443,
                },
            },
        }
        body = json.dumps(body_dict).encode("utf-8")
        ts = int(time.time() * 1000)
        sig = hmac_sign("my-secret", ts, body)
        resp, code = handle_runtime_alert(
            body_dict,
            signature_header=f"sha256={sig}",
            timestamp_ms=ts,
            raw_body=body,
            shared_secret="my-secret",
        )
        assert code == 200
        assert resp["iocs_recorded"] >= 1
        print("  OK")
    finally:
        _teardown(td)


def test_handle_alert_auto_promotes_multi_package():
    """동일 IP IOC 가 두 다른 패키지에서 등장 → 자동 promote."""
    print("\n== handle: multi-package IOC → auto promote ==")
    td = _setup()
    try:
        for pkg in ("pkg-a", "pkg-b"):
            handle_runtime_alert({
                "source": "falco",
                "package": pkg, "ecosystem": "npm", "version": "1.0",
                "event": {
                    "rule": "external",
                    "output_fields": {
                        "evt.type": "connect",
                        "fd.sip": "185.143.223.5",
                        "fd.sport": 443,
                    },
                },
            })
        from pkgsentinel.db.runtime_intel import RuntimeIntelStore
        s = RuntimeIntelStore()
        ips = s.list_iocs(ioc_type="ip", status="approved")
        assert any("185.143.223.5" in i.value for i in ips), \
            f"expected approved IP IOC, got {ips}"
        print(f"  OK {len(ips)} promoted")
    finally:
        _teardown(td)


def test_handle_alert_infers_source():
    """source key 누락 시 payload 구조로 추정."""
    print("\n== handle: source 추정 ==")
    td = _setup()
    try:
        # Tetragon-like payload (no explicit source)
        resp, _ = handle_runtime_alert({
            "process_kprobe": {
                "process": {"binary": "/usr/bin/npm"},
                "function_name": "tcp_connect",
                "args": [{"sock_arg": "8.8.8.8:443"}],
            },
        })
        assert resp["source"] == "tetragon"
        print("  OK")
    finally:
        _teardown(td)


def main():
    pass


if __name__ == "__main__":
    main()
