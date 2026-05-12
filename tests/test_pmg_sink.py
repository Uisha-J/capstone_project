"""PmgPolicySink + to_pmg_policy 단위 테스트."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.realtime.sinks.pmg_policy import (
    PmgPolicySink,
    to_pmg_policy,
)


def _r(verdict, pkg="evil-pkg", eco="PyPI", ver="0.0.1", **kw):
    base = {
        "verdict": verdict, "package": pkg, "ecosystem": eco, "version": ver,
        "evidence": [], "package_meta": {},
    }
    base.update(kw)
    return base


# ─────────────── verdict → action 매핑 ───────────────

def test_malicious_creates_deny_policy():
    print("== MALICIOUS → deny ==")
    yaml = to_pmg_policy(_r("MALICIOUS"))
    assert yaml is not None
    assert "action: deny" in yaml
    assert 'p.name == "evil-pkg"' in yaml
    assert 'p.version == "0.0.1"' in yaml
    assert 'p.ecosystem == "pypi"' in yaml
    print("  OK deny policy generated")


def test_high_risk_creates_deny_policy():
    print("\n== HIGH_RISK → deny ==")
    yaml = to_pmg_policy(_r("HIGH_RISK"))
    assert yaml is not None
    assert "action: deny" in yaml
    print("  OK")


def test_suspicious_creates_warn_policy():
    print("\n== SUSPICIOUS → warn ==")
    yaml = to_pmg_policy(_r("SUSPICIOUS"))
    assert yaml is not None
    assert "action: warn" in yaml
    print("  OK")


def test_clean_skipped():
    print("\n== CLEAN → no policy (None) ==")
    assert to_pmg_policy(_r("CLEAN")) is None
    print("  OK skip")


def test_unknown_verdict_skipped():
    print("\n== ERROR / unknown → None ==")
    assert to_pmg_policy(_r("ERROR")) is None
    assert to_pmg_policy(_r("CANNOT_ANALYZE")) is None
    print("  OK")


# ─────────────── 포맷 검증 ───────────────

def test_yaml_structure():
    print("\n== YAML 구조 (required fields) ==")
    yaml = to_pmg_policy(_r("MALICIOUS"))
    # 필수 키들
    for key in (
        "name: pkgsentinel-auto",
        "description:",
        "tags:",
        "rules:",
        "- name:",
        "summary:",
        "check:",
        "- cel: |",
        "action:",
    ):
        assert key in yaml, f"missing {key!r} in:\n{yaml}"
    print("  OK structure complete")


def test_summary_includes_ttp_and_reasoning():
    print("\n== summary 에 TTP + LLM reasoning ==")
    r = _r("MALICIOUS", evidence=[{
        "ttp_id": "T1041",
        "llm_reasoning": "credential exfil via env→base64→requests.post",
    }])
    yaml = to_pmg_policy(r)
    assert "T1041" in yaml
    assert "credential exfil" in yaml
    print("  OK")


def test_wildcard_version():
    """version=* 면 CEL 에서 버전 비교 생략."""
    print("\n== version=* → all versions ==")
    yaml = to_pmg_policy(_r("MALICIOUS", ver="*"))
    assert "p.version" not in yaml
    assert 'p.name == "evil-pkg"' in yaml
    print("  OK no version constraint")


def test_npm_ecosystem_label():
    print("\n== npm 라벨 정규화 ==")
    yaml = to_pmg_policy(_r("MALICIOUS", eco="npm"))
    assert 'p.ecosystem == "npm"' in yaml
    print("  OK")


def test_rule_name_slug():
    """패키지명에 특수문자 있어도 yaml 안전한 rule name."""
    print("\n== rule name slug ==")
    yaml = to_pmg_policy(_r("MALICIOUS", pkg="@scope/evil-pkg", eco="npm"))
    # @scope/evil-pkg → scope-evil-pkg 같이 정규화
    # rule name 줄에 슬래시나 @ 없어야
    rule_line = [
        ln for ln in yaml.splitlines() if ln.strip().startswith("- name:")
    ][0]
    assert "/" not in rule_line
    assert "@" not in rule_line
    print(f"  OK rule line: {rule_line.strip()}")


# ─────────────── PmgPolicySink ───────────────

def test_sink_writes_file():
    print("\n== sink writes yaml file ==")
    td = tempfile.mkdtemp(prefix="pmg_test_")
    try:
        sink = PmgPolicySink(out_dir=td)
        res = sink.emit(_r("MALICIOUS"))
        assert res["ok"] is True
        assert not res.get("skipped")
        assert os.path.exists(res["file"])
        content = open(res["file"]).read()
        assert "action: deny" in content
        print(f"  OK file={Path(res['file']).name}")
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)


def test_sink_skips_clean():
    print("\n== sink skips CLEAN ==")
    td = tempfile.mkdtemp(prefix="pmg_test_")
    try:
        sink = PmgPolicySink(out_dir=td)
        res = sink.emit(_r("CLEAN"))
        assert res["ok"] is True
        assert res["skipped"] is True
        # 파일 안 만들어짐
        assert not os.listdir(td)
        print("  OK no file")
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)


def main():
    pass


if __name__ == "__main__":
    main()
