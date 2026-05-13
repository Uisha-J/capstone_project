"""학습한 IOC + advisory → OSV advisory 포맷 export (#L6).

OSSF / OSV community 에 기여 가능한 표준 포맷.

OSV schema: https://ossf.github.io/osv-schema/

학습한 IOC 중 status='approved' 만 export (사람 검토 통과한 것).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..db.runtime_intel import LearnedIOC, RuntimeIntelStore


def _split_pkg_at_version(s: str) -> tuple[str, str]:
    """'pkg@ver' → ('pkg', 'ver'). 양식 안 맞으면 (s, '*')."""
    if "@" not in s:
        return s, "*"
    name, _, ver = s.rpartition("@")
    # scoped npm (`@scope/foo@1.0`) 의 경우 첫 @ 제외하고 마지막 @ 가 separator
    if name.startswith("@") and "/" in name:
        return name, ver
    if not name:
        return s, "*"
    return name, ver or "*"


def _ecosystem_to_osv(eco: str) -> str:
    """우리 ecosystem 라벨 → OSV ecosystem 라벨.

    OSV 는 case-sensitive 라벨 사용 — PyPI / npm 등.
    """
    e = eco.lower()
    if e == "pypi":
        return "PyPI"
    if e == "npm":
        return "npm"
    return eco


def ioc_to_osv_advisory(ioc: LearnedIOC) -> dict:
    """학습한 IOC 한 건 → OSV advisory JSON.

    associated_packages 에 등장한 모든 (pkg, eco, version) 를 affected 에 묶음.
    """
    affected_by_eco_pkg: dict[tuple[str, str], list[str]] = {}
    for pv in ioc.associated_packages:
        name, ver = _split_pkg_at_version(pv)
        # ecosystem 는 IOC 자체엔 없음 — caller 가 따로 알려줘야 하지만
        # 본 단순 export 는 npm 기본 (대부분의 학습 IOC source) 가정.
        # 더 정확하게는 RuntimeObservation 에서 추적해야 — 다음 사이클 보강.
        key = ("npm", name)
        affected_by_eco_pkg.setdefault(key, []).append(ver)

    affected = []
    for (eco, name), versions in affected_by_eco_pkg.items():
        affected.append({
            "package": {
                "name": name,
                "ecosystem": _ecosystem_to_osv(eco),
            },
            "versions": sorted(set(versions)),
        })

    return {
        "schema_version": "1.6.0",
        "id": f"PKGSENTINEL-IOC-{ioc.id or 'x'}",
        "summary": _ioc_summary(ioc),
        "details": _ioc_details(ioc),
        "modified": ioc.last_seen or ioc.first_seen,
        "published": ioc.first_seen,
        "affected": affected,
        "database_specific": {
            "pkgsentinel": {
                "ioc_type": ioc.ioc_type,
                "ioc_value": ioc.value,
                "confidence": ioc.confidence,
                "observation_count": ioc.observation_count,
                "source_observation_ids": ioc.source_observation_ids,
                "status": ioc.status,
            },
        },
    }


def _ioc_summary(ioc: LearnedIOC) -> str:
    label = {
        "ip": "IP address",
        "domain": "Domain",
        "sha256": "File hash",
        "path": "Sensitive path access",
        "syscall_chain": "Syscall sequence",
    }.get(ioc.ioc_type, "Indicator")
    return f"Runtime-observed {label}: {ioc.value}"


def _ioc_details(ioc: LearnedIOC) -> str:
    pkgs = ", ".join(ioc.associated_packages[:10])
    return (
        f"This indicator ({ioc.ioc_type}={ioc.value}) was runtime-observed "
        f"in association with the following package versions: {pkgs}. "
        f"Confidence: {ioc.confidence}. "
        f"Total observations across hosts: {ioc.observation_count}. "
        f"Source: pkgsentinel runtime intel feedback loop. "
        f"This advisory is auto-generated and approved by review."
    )


# ─────────────── public API ───────────────

def export_approved_iocs(
    store: RuntimeIntelStore | None = None,
    *,
    min_confidence: float = 0.7,
) -> list[dict]:
    """approved status + 최소 confidence 충족 IOC → OSV advisory list."""
    store = store or RuntimeIntelStore()
    iocs = store.list_iocs(status="approved", min_confidence=min_confidence)
    return [ioc_to_osv_advisory(i) for i in iocs]


def export_to_directory(
    out_dir: str | Path,
    *,
    store: RuntimeIntelStore | None = None,
    min_confidence: float = 0.7,
) -> dict:
    """OSV advisory 들을 디렉터리에 개별 JSON 파일로 dump.

    파일명: <ADVISORY_ID>.json
    OSSF malicious-packages repo PR 형식 호환.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    advisories = export_approved_iocs(
        store=store, min_confidence=min_confidence,
    )
    written = []
    for adv in advisories:
        fname = f"{adv['id']}.json"
        path = out / fname
        path.write_text(
            json.dumps(adv, indent=2, ensure_ascii=False), encoding="utf-8",
        )
        written.append(str(path))
    return {
        "count": len(advisories),
        "files": written,
        "out_dir": str(out),
    }
