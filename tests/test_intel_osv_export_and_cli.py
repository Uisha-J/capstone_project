"""OSV export (#L6) + CLI dashboard (#L7) 단위 테스트."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.db.runtime_intel import (
    LearnedIOC,
    LearnedRule,
    RuntimeIntelStore,
    RuntimeObservation,
)
from pkgsentinel.intel.osv_export import (
    _ecosystem_to_osv,
    _split_pkg_at_version,
    export_approved_iocs,
    export_to_directory,
    ioc_to_osv_advisory,
)


def _setup():
    td = tempfile.mkdtemp(prefix="osv_export_")
    os.environ["AISLOP_DB_KEY"] = "osv-export-test"
    from pkgsentinel.db.threat_db import ThreatDB
    import pkgsentinel.db.threat_db as tdb_mod
    tdb_mod._default_db = ThreatDB(
        Path(td) / "t.sqlcipher",
        passphrase=os.environ["AISLOP_DB_KEY"],
    )
    return td


def _teardown(td):
    import shutil; shutil.rmtree(td, ignore_errors=True)


# ─────────────── OSV export 헬퍼 ───────────────

def test_split_pkg_at_version():
    print("== _split_pkg_at_version ==")
    assert _split_pkg_at_version("lodash@4.17.21") == ("lodash", "4.17.21")
    # npm scoped
    assert _split_pkg_at_version("@scope/foo@1.0") == ("@scope/foo", "1.0")
    # no version
    assert _split_pkg_at_version("evil-pkg") == ("evil-pkg", "*")
    assert _split_pkg_at_version("evil@*") == ("evil", "*")
    print("  OK")


def test_ecosystem_normalization():
    print("\n== _ecosystem_to_osv ==")
    assert _ecosystem_to_osv("pypi") == "PyPI"
    assert _ecosystem_to_osv("PyPI") == "PyPI"
    assert _ecosystem_to_osv("npm") == "npm"
    print("  OK")


def test_ioc_to_osv_advisory_basic():
    print("\n== ioc_to_osv_advisory basic shape ==")
    ioc = LearnedIOC(
        id=42, ioc_type="ip", value="185.143.223.5",
        confidence=0.9, observation_count=5,
        first_seen="2026-05-13T00:00:00Z",
        last_seen="2026-05-13T01:00:00Z",
        associated_packages=["evil-stealer@0.0.1", "react-html-table@1.2"],
        source_observation_ids=[10, 11, 12],
        status="approved",
    )
    adv = ioc_to_osv_advisory(ioc)
    assert adv["schema_version"].startswith("1.")
    assert adv["id"] == "PKGSENTINEL-IOC-42"
    assert "Runtime-observed" in adv["summary"]
    assert "185.143.223.5" in adv["summary"]
    # affected — 2 패키지 모두 포함
    affected_names = {a["package"]["name"] for a in adv["affected"]}
    assert "evil-stealer" in affected_names
    assert "react-html-table" in affected_names
    # database_specific 메타데이터 포함
    ds = adv["database_specific"]["pkgsentinel"]
    assert ds["ioc_type"] == "ip"
    assert ds["confidence"] == 0.9
    print("  OK")


def test_export_approved_iocs_filters():
    """approved 만 export, pending 무시."""
    print("\n== export_approved_iocs: status=approved 만 ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="1.1.1.1",
                                confidence=0.95, status="approved"),
                     package_at_version="pkg@1.0")
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="2.2.2.2",
                                confidence=0.6, status="pending"),
                     package_at_version="pkg@1.0")

        # status='approved' 로 강제 update
        with s.db.cursor() as cur:
            cur.execute("UPDATE learned_iocs SET status='approved' "
                        "WHERE value='1.1.1.1'")

        out = export_approved_iocs(store=s, min_confidence=0.7)
        ids = [a["database_specific"]["pkgsentinel"]["ioc_value"] for a in out]
        assert "1.1.1.1" in ids
        assert "2.2.2.2" not in ids
        print(f"  OK exported {len(out)} approved IOCs")
    finally:
        _teardown(td)


def test_export_to_directory_writes_files():
    print("\n== export_to_directory ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.upsert_ioc(LearnedIOC(ioc_type="domain", value="evil.example.net",
                                confidence=0.9, status="approved"),
                     package_at_version="evil-stealer@0.0.1")
        with s.db.cursor() as cur:
            cur.execute("UPDATE learned_iocs SET status='approved'")

        out_dir = Path(td) / "osv_dump"
        res = export_to_directory(out_dir, store=s, min_confidence=0.7)
        assert res["count"] >= 1
        files = list(out_dir.glob("*.json"))
        assert files
        # JSON 유효성
        with open(files[0]) as f:
            data = json.load(f)
        assert data["id"].startswith("PKGSENTINEL-IOC-")
        print(f"  OK {res['count']} files in {out_dir}")
    finally:
        _teardown(td)


# ─────────────── CLI ───────────────

def _run_cli(argv, monkeypatch=None) -> tuple[int, str, str]:
    """sys.argv 와 stdout/stderr 캡처. 반환 (exit_code, stdout, stderr)."""
    from pkgsentinel.intel import cli
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    code = 0
    try:
        try:
            parser = cli._build_parser()
            args = parser.parse_args(argv)
            code = args.func(args)
        except SystemExit as e:
            code = e.code
    finally:
        out = sys.stdout.getvalue()
        err = sys.stderr.getvalue()
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    return code or 0, out, err


def test_cli_stats():
    print("\n== CLI: stats ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.record_observation(RuntimeObservation(
            received_at="t", source="falco", raw_event={},
        ))
        code, out, _ = _run_cli(["stats"])
        assert code == 0
        data = json.loads(out)
        assert "observations" in data
        assert data["observations"] == 1
        print("  OK")
    finally:
        _teardown(td)


def test_cli_list_iocs_table_format():
    print("\n== CLI: list-iocs (table format) ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.upsert_ioc(LearnedIOC(ioc_type="ip", value="1.2.3.4",
                                confidence=0.8),
                     package_at_version="evil@0.1")
        code, out, _ = _run_cli(["list-iocs", "--type", "ip"])
        assert code == 0
        assert "1.2.3.4" in out
        assert "evil@0.1" in out
        print("  OK")
    finally:
        _teardown(td)


def test_cli_list_iocs_json_format():
    print("\n== CLI: list-iocs --json ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.upsert_ioc(LearnedIOC(ioc_type="domain", value="evil.com",
                                confidence=0.7))
        code, out, _ = _run_cli(["list-iocs", "--json"])
        data = json.loads(out)
        assert isinstance(data, list)
        assert any(i["value"] == "evil.com" for i in data)
        print("  OK")
    finally:
        _teardown(td)


def test_cli_approve_rule():
    print("\n== CLI: approve-rule ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        rule = LearnedRule(
            rule_kind="indicator_47", rule_body='{"x":1}',
            created_at="t", confidence=0.7,
        )
        rid = s.record_rule_draft(rule)
        code, out, _ = _run_cli(["approve-rule", "--id", str(rid),
                                 "--by", "alice"])
        assert code == 0
        assert "approved by alice" in out
        # 다시 approve 시도 → 1 (fail)
        code2, _, err2 = _run_cli(["approve-rule", "--id", str(rid),
                                   "--by", "bob"])
        assert code2 == 1
        assert "not in draft" in err2
        print("  OK")
    finally:
        _teardown(td)


def test_cli_approve_ioc_manual():
    print("\n== CLI: approve-ioc (수동) ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        iid = s.upsert_ioc(LearnedIOC(ioc_type="path", value="/etc/shadow",
                                      confidence=0.5))
        code, out, _ = _run_cli(["approve-ioc", "--id", str(iid)])
        assert code == 0
        ioc = s.get_ioc(iid)
        assert ioc.status == "approved"
        print("  OK")
    finally:
        _teardown(td)


def test_cli_export_osv():
    print("\n== CLI: export-osv ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        iid = s.upsert_ioc(LearnedIOC(
            ioc_type="ip", value="9.9.9.9",
            confidence=0.95, status="approved",
        ), package_at_version="evil-x@1.0")
        with s.db.cursor() as cur:
            cur.execute("UPDATE learned_iocs SET status='approved'")

        out_dir = Path(td) / "export"
        code, out, _ = _run_cli([
            "export-osv", "--out-dir", str(out_dir),
            "--min-confidence", "0.7",
        ])
        assert code == 0
        data = json.loads(out)
        assert data["count"] >= 1
        # 실 파일 확인
        files = list(out_dir.glob("*.json"))
        assert files
        print(f"  OK {data['count']} files")
    finally:
        _teardown(td)


def test_cli_list_observations():
    print("\n== CLI: list-observations ==")
    td = _setup()
    try:
        s = RuntimeIntelStore()
        s.record_observation(RuntimeObservation(
            received_at="2026-05-13T10:00:00Z", source="falco",
            host="h1", package="evil", ecosystem="npm", version="1.0",
            raw_event={}, verdict_before="CLEAN", mitigation="killed",
        ))
        code, out, _ = _run_cli(["list-observations", "--package", "evil"])
        assert code == 0
        assert "evil" in out
        assert "killed" in out
        print("  OK")
    finally:
        _teardown(td)


def main():
    pass


if __name__ == "__main__":
    main()
