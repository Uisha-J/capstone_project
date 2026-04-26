"""
Stage SLSA — 빌드 프로비넌스 / SLSA 레벨 추정.

근거: SLSA v1.0 — https://slsa.dev/
        npm provenance — https://docs.npmjs.com/generating-provenance-statements
        PyPI PEP 740 (attestations) — https://peps.python.org/pep-0740/

목표:
  외부 저장소(공급자) 가 제공한 attestation/provenance 메타데이터를 보고
  SLSA Build Track Level 을 보수적으로 추정한다.
  (실제 검증은 외부 도구 — slsa-verifier — 가 필요. 여기서는 메타 신호만.)

추정 매핑 (보수적):
  - L0  : provenance 정보 없음
  - L1  : 빌드 정보(스크립트/CI) 가 있지만 검증 불가
  - L2  : 호스티드 빌드의 attestation 메타가 존재 (= npm provenance, PyPI PEP-740)
  - L3+ : 본 도구로는 단정 불가 (별도 사이트 검증 필요)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..schema import Ecosystem


class SLSALevel(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3_OR_HIGHER = "L3+"
    UNKNOWN = "UNKNOWN"


@dataclass
class SLSAReport:
    level: SLSALevel
    has_provenance: bool
    has_signature: bool
    builder_url: Optional[str] = None
    source_uri: Optional[str] = None
    raw_provenance: Optional[dict] = None
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "has_provenance": self.has_provenance,
            "has_signature": self.has_signature,
            "builder_url": self.builder_url,
            "source_uri": self.source_uri,
            "notes": self.notes[:5],
            "error": self.error,
        }

    def summary_line(self) -> str:
        if self.error:
            return f"SLSA: error ({self.error})"
        return (
            f"SLSA estimated {self.level.value} "
            f"(provenance={self.has_provenance}, signed={self.has_signature})"
        )


# ─────────────── npm provenance ───────────────

def _evaluate_npm(raw: dict) -> SLSAReport:
    """npm 메타데이터에서 provenance 단서 검색."""
    notes: list[str] = []
    has_provenance = False
    has_signature = False
    builder_url: Optional[str] = None
    source_uri: Optional[str] = None
    raw_prov: Optional[dict] = None

    latest = (raw.get("dist-tags") or {}).get("latest")
    ver = (raw.get("versions") or {}).get(latest, {}) if latest else {}
    dist = ver.get("dist") or {}

    # 1) dist.attestations 가 있으면 provenance 발급 가능 (npm 공식)
    attestations = dist.get("attestations") or {}
    if attestations:
        has_provenance = True
        prov_url = attestations.get("url")
        if prov_url:
            notes.append(f"attestations.url={prov_url}")
        prov_count = attestations.get("count")
        if prov_count:
            notes.append(f"attestations.count={prov_count}")
        raw_prov = attestations

    # 2) dist.signatures
    sigs = dist.get("signatures") or []
    if sigs:
        has_signature = True
        notes.append(f"signatures={len(sigs)} entry(s)")

    # 3) repository / homepage 에서 source_uri 추정
    repo = ver.get("repository")
    if isinstance(repo, dict):
        source_uri = repo.get("url")
    elif isinstance(repo, str):
        source_uri = repo

    # 빌더 — npm provenance 는 GitHub Actions runner 가 보통
    if has_provenance:
        # npm/pacote 가 공개하는 attestation 의 builder 는 보통 https://github.com/actions
        builder_url = "https://github.com/actions"

    # SLSA 레벨 추정
    if has_provenance and has_signature:
        level = SLSALevel.L2
    elif has_provenance or has_signature:
        level = SLSALevel.L1
    else:
        level = SLSALevel.L0

    return SLSAReport(
        level=level,
        has_provenance=has_provenance,
        has_signature=has_signature,
        builder_url=builder_url,
        source_uri=source_uri,
        raw_provenance=raw_prov,
        notes=notes,
    )


# ─────────────── PyPI PEP-740 attestations ───────────────

def _evaluate_pypi(raw: dict) -> SLSAReport:
    """PyPI 메타데이터에서 PEP-740 attestation 단서 검색."""
    notes: list[str] = []
    has_provenance = False
    has_signature = False
    builder_url: Optional[str] = None
    source_uri: Optional[str] = None
    raw_prov: Optional[dict] = None

    info = raw.get("info") or {}
    # source 추정
    project_urls = info.get("project_urls") or {}
    source_uri = (
        project_urls.get("Source") or
        project_urls.get("Homepage") or
        info.get("home_page")
    )

    # 1) urls[*].provenance / attestations / has_attestations
    urls = raw.get("urls") or []
    for u in urls:
        # PEP-740 표준에선 url 옆 별도 attestation 엔드포인트 + has_attestations 플래그
        if u.get("provenance") or u.get("has_attestations") or u.get("attestations"):
            has_provenance = True
            raw_prov = {
                "url": u.get("url"),
                "filename": u.get("filename"),
                "provenance": u.get("provenance") or u.get("attestations"),
                "has_attestations": u.get("has_attestations"),
            }
            notes.append(f"PEP-740 attestation on {u.get('filename')}")
            break

    # 2) digest 가 sha256 이면 무결성 검증 가능 (= 약한 증명)
    if not has_provenance:
        for u in urls:
            d = u.get("digests") or {}
            if d.get("sha256"):
                notes.append("PyPI provides sha256 digest (integrity only)")
                break

    # PyPI 는 직접 GPG 서명 잘 안 씀 — has_signature 는 보수적으로 False
    if has_provenance:
        # PEP-740 은 GitHub Actions 등 OIDC 기반 — 빌더 URL 은 attestation 안에
        builder_url = "https://github.com/actions"

    if has_provenance and has_signature:
        level = SLSALevel.L2
    elif has_provenance:
        level = SLSALevel.L2  # PEP-740 attestation 단독으로도 L2 로 봄
    else:
        level = SLSALevel.L0

    return SLSAReport(
        level=level,
        has_provenance=has_provenance,
        has_signature=has_signature,
        builder_url=builder_url,
        source_uri=source_uri if isinstance(source_uri, str) else None,
        raw_provenance=raw_prov,
        notes=notes,
    )


# ─────────────── 통합 ───────────────

def evaluate(raw_metadata: dict | None, ecosystem: Ecosystem) -> SLSAReport:
    if not raw_metadata:
        return SLSAReport(
            level=SLSALevel.UNKNOWN,
            has_provenance=False,
            has_signature=False,
            error="no metadata",
        )
    try:
        if ecosystem == Ecosystem.NPM:
            return _evaluate_npm(raw_metadata)
        if ecosystem == Ecosystem.PYPI:
            return _evaluate_pypi(raw_metadata)
        return SLSAReport(
            level=SLSALevel.UNKNOWN,
            has_provenance=False,
            has_signature=False,
            error=f"unsupported ecosystem: {ecosystem}",
        )
    except Exception as e:
        return SLSAReport(
            level=SLSALevel.UNKNOWN,
            has_provenance=False,
            has_signature=False,
            error=f"{type(e).__name__}: {e}",
        )


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys
    from .stage0_registry import check

    pkg = sys.argv[1] if len(sys.argv) > 1 else "sigstore"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    if not info.found:
        print(f"package not found: {pkg}")
        sys.exit(1)

    rpt = evaluate(info.raw_metadata, eco)
    print(rpt.summary_line())
    print(f"  builder_url : {rpt.builder_url}")
    print(f"  source_uri  : {rpt.source_uri}")
    print(f"  notes       :")
    for n in rpt.notes:
        print(f"    - {n}")
