"""#R5 FIM 통합 자산 — 구성 파일 sanity 테스트.

deploy/fim/ 의 파일들이:
  - 정상적으로 존재
  - XML / shell syntax 유효
  - README 가 필요한 섹션 포함
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
FIM_DIR = ROOT / "deploy" / "fim"


def test_fim_directory_exists():
    print("== deploy/fim/ 존재 ==")
    assert FIM_DIR.exists()
    assert FIM_DIR.is_dir()
    print("  OK")


def test_readme_present_and_substantial():
    print("\n== README.md 충실 ==")
    readme = FIM_DIR / "README.md"
    assert readme.exists()
    content = readme.read_text(encoding="utf-8")
    # 핵심 섹션
    for section in (
        "Wazuh", "osquery",
        "active-response",
        "runtime-alert",
        "HMAC",
        "syscheck",
    ):
        assert section in content, f"missing section: {section}"
    # 길이 sanity
    assert len(content) > 3000, f"README too short ({len(content)} chars)"
    print(f"  OK {len(content)} chars")


def test_wazuh_ossec_snippet_valid_xml():
    """ossec.conf snippet — XML 파편 (외부 root 없음) 이라 그냥 element root 둘러싸 parse."""
    print("\n== wazuh-ossec.conf.snippet.xml 유효 XML ==")
    f = FIM_DIR / "wazuh-ossec.conf.snippet.xml"
    assert f.exists()
    body = f.read_text(encoding="utf-8")
    # snippet 은 multiple top-level — <root> 로 감싸 parse 시도
    wrapped = f"<root>{body}</root>"
    try:
        ET.fromstring(wrapped)
    except ET.ParseError as e:
        raise AssertionError(f"snippet XML invalid: {e}") from e
    # 필수 element 포함
    assert "<syscheck>" in body
    assert "active-response" in body
    assert "pkgsentinel-trigger" in body
    print("  OK")


def test_local_rules_snippet_valid_xml():
    print("\n== local_rules.xml.snippet 유효 XML ==")
    f = FIM_DIR / "local_rules.xml.snippet"
    assert f.exists()
    body = f.read_text(encoding="utf-8")
    # 본 파일은 root group 하나라 직접 parse 가능
    try:
        ET.fromstring(body)
    except ET.ParseError as e:
        raise AssertionError(f"rules XML invalid: {e}") from e
    # 우리 정의 룰 ID
    assert "100501" in body
    assert "100502" in body
    assert "100503" in body
    print("  OK")


def test_trigger_script_syntax():
    """bash -n 으로 syntax 만 검증 (실 실행 안 함)."""
    print("\n== pkgsentinel-trigger.sh syntax ==")
    f = FIM_DIR / "pkgsentinel-trigger.sh"
    assert f.exists()
    # shebang 첫 줄
    text = f.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash") or text.startswith("#!/bin/bash")
    # 핵심 변수 / 명령어 등장
    for tok in (
        "PKGSENTINEL_URL", "PKGSENTINEL_SECRET",
        "X-AISLOPSQ-Signature", "openssl dgst",
        "curl",
    ):
        assert tok in text, f"trigger script missing {tok}"
    # bash -n 으로 syntax 검증 (gitbash 환경에서도 동작)
    import shutil
    bash = shutil.which("bash")
    if bash:
        import subprocess
        res = subprocess.run(
            [bash, "-n", str(f)],
            capture_output=True, text=True, timeout=10,
        )
        assert res.returncode == 0, f"bash syntax err: {res.stderr}"
        print("  OK bash -n passed")
    else:
        print("  OK (bash not available — skipped syntax check)")


def test_trigger_script_executable_bit():
    """본 git 환경은 Windows 라 +x 자동 안 됨 — 내용 기반 검증만.
    배포 시 README 가 chmod 750 지시."""
    print("\n== trigger script 권한 안내 README 확인 ==")
    readme = (FIM_DIR / "README.md").read_text(encoding="utf-8")
    assert "chmod 750" in readme or "chmod +x" in readme
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
