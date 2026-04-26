"""
Stage SSDF — NIST SP 800-218 (Secure Software Development Framework) 준수 체크.

근거: NIST SP 800-218 (SSDF v1.1) — https://csrc.nist.gov/pubs/sp/800/218/final

이 스테이지는 패키지를 "공급자 측" 관점에서가 아니라
"소비자 측" 관점에서 SSDF 의 어떤 항목이 충족되는지를
정적으로 평가한다 (한정된 신호로만).

체크 항목 (subset):
  PO.4.1   보안 정책 / 보고 채널 존재
  PS.1.1   파일 무결성 보호 (signed releases)
  PS.2.1   소프트웨어 변경 이력 공개 (changelog/git tag)
  PS.3.1   SBOM 제공
  PW.4.1   유지보수 활성도
  PW.4.4   권위있는 출처 (PyPI/npm 공식 등록)
  PW.4.5   컴포넌트 무결성 확인 가능 (해시/서명)
  PW.7.1   코드 리뷰 정책 (PR 기반)
  PW.8.1   테스트 존재 (CI/Fuzzing)
  RV.1.1   알려진 취약점 패치 (Scorecard Vulnerabilities)
  RV.2.1   취약점 신고 채널 (Security Policy)

각 항목 결과:
  - PASS    : 충족 신호 발견
  - FAIL    : 명확히 충족되지 않음
  - UNKNOWN : 판단 불가 (기본)

판정에 직접 영향 X — 리포트 메타에만 기록.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..schema import Ecosystem
from .stage_scorecard import ScorecardReport


class SSDFStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass
class SSDFCheck:
    code: str          # 예: "PW.4.4"
    title: str
    status: SSDFStatus
    evidence: str = ""
    reference: str = "https://csrc.nist.gov/pubs/sp/800/218/final"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "status": self.status.value,
            "evidence": self.evidence[:200],
            "reference": self.reference,
        }


@dataclass
class SSDFReport:
    checks: list[SSDFCheck] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    unknown_count: int = 0

    def to_dict(self) -> dict:
        return {
            "pass": self.pass_count,
            "fail": self.fail_count,
            "unknown": self.unknown_count,
            "checks": [c.to_dict() for c in self.checks],
            "compliance_ratio": round(
                self.pass_count / max(1, len(self.checks)), 3
            ),
        }


# ─────────────── Scorecard 항목 → SSDF 매핑 ───────────────

# Scorecard check 이름 → 통과 임계값 (PASS 기준)
_SCORECARD_PASS = {
    "Security-Policy": 7.0,
    "Signed-Releases": 5.0,
    "Maintained": 5.0,
    "Code-Review": 5.0,
    "SAST": 5.0,
    "Fuzzing": 5.0,
    "Vulnerabilities": 7.0,
}


def _scorecard_status(
    scorecard: ScorecardReport | None,
    name: str,
) -> tuple[SSDFStatus, str]:
    if scorecard is None or not scorecard.available:
        return SSDFStatus.UNKNOWN, "no scorecard data"
    for c in scorecard.checks:
        if c.name == name:
            threshold = _SCORECARD_PASS.get(name, 5.0)
            if c.score < 0:
                return SSDFStatus.UNKNOWN, f"{name}=N/A"
            if c.score >= threshold:
                return SSDFStatus.PASS, f"{name}={c.score:.1f}/10 (>= {threshold})"
            return SSDFStatus.FAIL, f"{name}={c.score:.1f}/10 (< {threshold}). {c.reason[:120]}"
    return SSDFStatus.UNKNOWN, f"{name} check not present"


# ─────────────── 패키지 메타 → SSDF ───────────────

def _has_sbom_in_files(source_paths: list[str]) -> bool:
    """sbom.json / cyclonedx*.json / spdx*.json 등이 있는지."""
    keys = ("sbom", "cyclonedx", "spdx")
    for p in source_paths:
        low = p.lower()
        if any(k in low for k in keys):
            return True
    return False


def _has_changelog(source_paths: list[str]) -> bool:
    keys = (
        "changelog", "history.md", "history.rst",
        "release_notes", "release-notes",
    )
    bare_basenames = ("changes.md", "changes.rst", "changes.txt", "changes")
    for p in source_paths:
        low = p.lower()
        # 경로 어디든 키워드 포함
        if any(k in low for k in keys):
            return True
        # 또는 basename 이 CHANGES.* 류
        base = low.rsplit("/", 1)[-1]
        if base in bare_basenames or base.startswith("changes."):
            return True
    return False


def _has_security_md(source_paths: list[str]) -> bool:
    for p in source_paths:
        low = p.lower()
        if low.endswith("security.md") or low.endswith("security.rst"):
            return True
    return False


# ─────────────── 메인 평가 ───────────────

def evaluate(
    ecosystem: Ecosystem,
    registry_found: bool,
    raw_metadata: dict | None,
    source_paths: list[str],
    scorecard: ScorecardReport | None = None,
    declared_deps_count: int = 0,
) -> SSDFReport:
    checks: list[SSDFCheck] = []

    # PO.4.1 — 보안 정책 / 보고 채널
    has_secmd = _has_security_md(source_paths)
    sc_status, sc_evidence = _scorecard_status(scorecard, "Security-Policy")
    if has_secmd:
        checks.append(SSDFCheck(
            "PO.4.1",
            "Security policy / report channel exists",
            SSDFStatus.PASS,
            evidence=f"SECURITY.md found ({sc_evidence})",
        ))
    else:
        checks.append(SSDFCheck(
            "PO.4.1",
            "Security policy / report channel exists",
            sc_status,
            evidence=sc_evidence or "no SECURITY.md, no scorecard",
        ))

    # PS.1.1 — 파일 무결성 보호 (signed releases)
    sc_status, sc_evidence = _scorecard_status(scorecard, "Signed-Releases")
    checks.append(SSDFCheck(
        "PS.1.1",
        "File integrity protection (signed releases)",
        sc_status,
        evidence=sc_evidence,
    ))

    # PS.2.1 — 변경 이력 공개
    has_chl = _has_changelog(source_paths)
    checks.append(SSDFCheck(
        "PS.2.1",
        "Software change history disclosed",
        SSDFStatus.PASS if has_chl else SSDFStatus.UNKNOWN,
        evidence=("CHANGELOG/HISTORY found" if has_chl
                  else "no CHANGELOG file in archive"),
    ))

    # PS.3.1 — SBOM 제공
    has_sbom = _has_sbom_in_files(source_paths)
    checks.append(SSDFCheck(
        "PS.3.1",
        "Software Bill of Materials (SBOM) provided",
        SSDFStatus.PASS if has_sbom else SSDFStatus.FAIL,
        evidence=("SBOM file found in archive" if has_sbom
                  else "no SBOM (sbom.json / cyclonedx / spdx) in archive"),
    ))

    # PW.4.1 — 유지보수 활성도
    sc_status, sc_evidence = _scorecard_status(scorecard, "Maintained")
    checks.append(SSDFCheck(
        "PW.4.1",
        "Component is actively maintained",
        sc_status,
        evidence=sc_evidence,
    ))

    # PW.4.4 — 권위있는 출처
    if registry_found:
        checks.append(SSDFCheck(
            "PW.4.4",
            "Component obtained from authoritative source",
            SSDFStatus.PASS,
            evidence=f"published on {ecosystem.value}",
        ))
    else:
        checks.append(SSDFCheck(
            "PW.4.4",
            "Component obtained from authoritative source",
            SSDFStatus.FAIL,
            evidence=f"not found on {ecosystem.value}",
        ))

    # PW.4.5 — 무결성 확인 가능 (PyPI 는 SHA256, npm 은 integrity 포함)
    integrity_evidence = "registry guarantees archive checksum"
    if raw_metadata:
        if ecosystem == Ecosystem.PYPI:
            # urls 또는 releases[v][i].digests.sha256
            urls = raw_metadata.get("urls") or []
            has_hash = any((u.get("digests") or {}).get("sha256") for u in urls)
            integrity_status = SSDFStatus.PASS if has_hash else SSDFStatus.UNKNOWN
            integrity_evidence = (
                "PyPI provides sha256 digests" if has_hash
                else "no sha256 found in current version metadata"
            )
        elif ecosystem == Ecosystem.NPM:
            latest = (raw_metadata.get("dist-tags") or {}).get("latest")
            ver = (raw_metadata.get("versions") or {}).get(latest, {}) if latest else {}
            integrity = (ver.get("dist") or {}).get("integrity")
            integrity_status = SSDFStatus.PASS if integrity else SSDFStatus.UNKNOWN
            integrity_evidence = (
                f"npm dist.integrity = {integrity}" if integrity
                else "no dist.integrity in versions[latest]"
            )
        else:
            integrity_status = SSDFStatus.UNKNOWN
    else:
        integrity_status = SSDFStatus.UNKNOWN
        integrity_evidence = "no registry metadata"
    checks.append(SSDFCheck(
        "PW.4.5",
        "Component integrity is verifiable",
        integrity_status,
        evidence=integrity_evidence,
    ))

    # PW.7.1 — 코드 리뷰 정책
    sc_status, sc_evidence = _scorecard_status(scorecard, "Code-Review")
    checks.append(SSDFCheck(
        "PW.7.1",
        "Code review policy enforced (PR-based)",
        sc_status,
        evidence=sc_evidence,
    ))

    # PW.8.1 — SAST / Fuzzing 존재
    sc_sast_status, sc_sast_ev = _scorecard_status(scorecard, "SAST")
    sc_fuzz_status, sc_fuzz_ev = _scorecard_status(scorecard, "Fuzzing")
    if sc_sast_status == SSDFStatus.PASS or sc_fuzz_status == SSDFStatus.PASS:
        final = SSDFStatus.PASS
        ev = f"SAST: {sc_sast_ev}; Fuzzing: {sc_fuzz_ev}"
    elif sc_sast_status == SSDFStatus.FAIL and sc_fuzz_status == SSDFStatus.FAIL:
        final = SSDFStatus.FAIL
        ev = f"SAST: {sc_sast_ev}; Fuzzing: {sc_fuzz_ev}"
    else:
        final = SSDFStatus.UNKNOWN
        ev = f"SAST: {sc_sast_ev}; Fuzzing: {sc_fuzz_ev}"
    checks.append(SSDFCheck(
        "PW.8.1",
        "Test/scan automation exists",
        final,
        evidence=ev,
    ))

    # RV.1.1 — 알려진 취약점 패치 (Scorecard Vulnerabilities)
    sc_status, sc_evidence = _scorecard_status(scorecard, "Vulnerabilities")
    checks.append(SSDFCheck(
        "RV.1.1",
        "No known unpatched vulnerabilities",
        sc_status,
        evidence=sc_evidence,
    ))

    # RV.2.1 — 신고 채널 (= PO.4.1 의 동치 — 통과되면 통과)
    rv_status = (
        SSDFStatus.PASS if has_secmd else
        (SSDFStatus.PASS if scorecard and any(
            c.name == "Security-Policy" and c.score >= 7.0 for c in scorecard.checks
        ) else SSDFStatus.UNKNOWN)
    )
    checks.append(SSDFCheck(
        "RV.2.1",
        "Vulnerability reporting channel exists",
        rv_status,
        evidence="SECURITY.md or Scorecard Security-Policy",
    ))

    # 카운트 집계
    pass_n = sum(1 for c in checks if c.status == SSDFStatus.PASS)
    fail_n = sum(1 for c in checks if c.status == SSDFStatus.FAIL)
    unk_n = sum(1 for c in checks if c.status == SSDFStatus.UNKNOWN)

    return SSDFReport(
        checks=checks,
        pass_count=pass_n,
        fail_count=fail_n,
        unknown_count=unk_n,
    )


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    # 가짜 데이터로 자체 테스트
    from .stage_scorecard import (
        ScorecardReport, ScorecardCheck,
    )

    sc = ScorecardReport(
        available=True,
        repo="pallets/flask",
        date="2026-04-20",
        overall_score=7.1,
        checks=[
            ScorecardCheck("Maintained", 10.0, "active"),
            ScorecardCheck("Code-Review", 0.0, "0 approved changesets"),
            ScorecardCheck("Signed-Releases", 6.0, "3/5 signed"),
            ScorecardCheck("Security-Policy", 9.0, "policy present"),
            ScorecardCheck("Vulnerabilities", 10.0, "no known CVE"),
            ScorecardCheck("Fuzzing", 10.0, "OSS-Fuzz integrated"),
            ScorecardCheck("SAST", 0.0, "no SAST"),
        ],
    )

    rpt = evaluate(
        ecosystem=Ecosystem.PYPI,
        registry_found=True,
        raw_metadata={
            "urls": [
                {"digests": {"sha256": "abcdef..." * 8}},
            ],
        },
        source_paths=[
            "flask-3.0.0/src/flask/__init__.py",
            "flask-3.0.0/CHANGES.rst",
            "flask-3.0.0/SECURITY.md",
        ],
        scorecard=sc,
    )

    print(f"=== SSDF Compliance ===")
    print(f"PASS: {rpt.pass_count}, FAIL: {rpt.fail_count}, UNKNOWN: {rpt.unknown_count}")
    print(f"compliance ratio: {rpt.pass_count / max(1, len(rpt.checks)):.2f}")
    print()
    for c in rpt.checks:
        mark = {"PASS": "+", "FAIL": "-", "UNKNOWN": "?"}[c.status.value]
        print(f"  [{mark}] {c.code:<8} {c.title}")
        print(f"        {c.evidence[:100]}")
