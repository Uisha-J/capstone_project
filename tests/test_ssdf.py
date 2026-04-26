"""NIST SSDF 준수 체크 단위 테스트."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages.stage_ssdf import evaluate, SSDFStatus
from pkgsentinel.stages.stage_scorecard import ScorecardReport, ScorecardCheck


def _make_scorecard(pairs: dict[str, float]) -> ScorecardReport:
    return ScorecardReport(
        available=True,
        repo="x/y",
        date="2026-04-26",
        overall_score=sum(pairs.values()) / max(1, len(pairs)),
        checks=[ScorecardCheck(k, v, f"{k} reason") for k, v in pairs.items()],
    )


def test_well_maintained_package():
    print("== Well-maintained package ==")
    sc = _make_scorecard({
        "Maintained": 10.0, "Code-Review": 9.0, "Signed-Releases": 8.0,
        "Security-Policy": 9.0, "Vulnerabilities": 10.0,
        "SAST": 8.0, "Fuzzing": 10.0,
    })
    rpt = evaluate(
        ecosystem=Ecosystem.PYPI,
        registry_found=True,
        raw_metadata={"urls": [{"digests": {"sha256": "x" * 64}}]},
        source_paths=[
            "pkg-1.0/SECURITY.md", "pkg-1.0/CHANGES.rst",
            "pkg-1.0/src/__init__.py",
        ],
        scorecard=sc,
    )
    print(f"  PASS={rpt.pass_count} FAIL={rpt.fail_count} UNK={rpt.unknown_count}")
    for c in rpt.checks:
        print(f"    {c.code:<8} {c.status.value:<7} {c.title}")
    # 7/11 이상 통과 기대
    return rpt.pass_count >= 7


def test_unmaintained_package():
    print("\n== Unmaintained / no-policy package ==")
    sc = _make_scorecard({
        "Maintained": 0.0, "Code-Review": 0.0, "Signed-Releases": 0.0,
        "Security-Policy": 0.0, "Vulnerabilities": 3.0,
        "SAST": 0.0, "Fuzzing": 0.0,
    })
    rpt = evaluate(
        ecosystem=Ecosystem.PYPI,
        registry_found=True,
        raw_metadata={},
        source_paths=["pkg-0.0.1/setup.py"],
        scorecard=sc,
    )
    print(f"  PASS={rpt.pass_count} FAIL={rpt.fail_count} UNK={rpt.unknown_count}")
    for c in rpt.checks:
        print(f"    {c.code:<8} {c.status.value:<7} {c.title}")
    # FAIL 항목이 4 개 이상 기대 (방치 + SBOM 없음 + 코드리뷰 없음 등)
    return rpt.fail_count >= 4


def test_no_scorecard():
    print("\n== No scorecard (all unknown) ==")
    rpt = evaluate(
        ecosystem=Ecosystem.PYPI,
        registry_found=True,
        raw_metadata={"urls": [{"digests": {"sha256": "x" * 64}}]},
        source_paths=["pkg/setup.py", "pkg/SECURITY.md"],
        scorecard=None,
    )
    print(f"  PASS={rpt.pass_count} FAIL={rpt.fail_count} UNK={rpt.unknown_count}")
    # SECURITY.md, registry, integrity 는 스코어카드 없이도 PASS
    pass_codes = {c.code for c in rpt.checks if c.status == SSDFStatus.PASS}
    print(f"  PASS codes: {sorted(pass_codes)}")
    return "PW.4.4" in pass_codes and "PW.4.5" in pass_codes and "PO.4.1" in pass_codes


def test_npm_integrity():
    print("\n== npm integrity check ==")
    rpt = evaluate(
        ecosystem=Ecosystem.NPM,
        registry_found=True,
        raw_metadata={
            "dist-tags": {"latest": "1.2.3"},
            "versions": {
                "1.2.3": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/x/-/x-1.2.3.tgz",
                        "integrity": "sha512-abcdef==",
                    },
                },
            },
        },
        source_paths=["package/package.json"],
        scorecard=None,
    )
    pw45 = next(c for c in rpt.checks if c.code == "PW.4.5")
    print(f"  PW.4.5 status={pw45.status.value}, evidence={pw45.evidence[:80]}")
    return pw45.status == SSDFStatus.PASS


def main():
    ok = True
    ok &= test_well_maintained_package()
    ok &= test_unmaintained_package()
    ok &= test_no_scorecard()
    ok &= test_npm_integrity()
    print("\n" + ("ALL OK" if ok else "FAILED"))


if __name__ == "__main__":
    main()
