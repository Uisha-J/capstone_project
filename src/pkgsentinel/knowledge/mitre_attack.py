"""
MITRE ATT&CK Enterprise 자동 수집기.

소스: https://github.com/mitre/cti (STIX 2.x JSON)
수집 대상: Enterprise Matrix Techniques (attack-pattern 타입)

정적 코드 분석 관점에서 탐지 가능한 TTP만 선별하여 TTPEntry 리스트로 반환.
"""
from __future__ import annotations

import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from ..schema import Severity, TTPEntry, TTPSource

# MITRE cti 리포지토리 — Enterprise Matrix STIX Bundle 원본 URL
ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


# ─────────────── 코드 레벨 탐지 가능 여부 필터 ───────────────
#
# 네트워크/프로세스/파일 등 정적 분석 가능한 전술만 선별.
# 물리적 접근, UI 조작, 정찰(외부) 같은 것은 제외한다.

CODE_DETECTABLE_TACTICS = {
    "execution",              # T1059 시리즈 등
    "persistence",            # T1547 등
    "privilege-escalation",
    "defense-evasion",        # T1027 Obfuscation 등
    "credential-access",      # T1552 등
    "discovery",              # T1082 등
    "collection",             # T1114 등
    "command-and-control",    # T1071 등
    "exfiltration",           # T1048 등
    "impact",                 # T1486 Data Encrypted 등
}

EXCLUDED_TACTICS = {
    "initial-access",   # 주로 사회공학/피싱이라 코드 기반 탐지 어려움
    "lateral-movement", # 네트워크 환경 필요 (정적 분석 불가)
    "reconnaissance",   # 대부분 외부 활동
    "resource-development",
}


# ─────────────── 심각도 매핑 규칙 ───────────────

HIGH_SEVERITY_KEYWORDS = {
    "exec", "eval", "command", "script", "exfil", "credential",
    "harvest", "steal", "encrypt", "wipe", "destroy", "obfusc",
    "backdoor", "implant", "shell",
}

MEDIUM_SEVERITY_KEYWORDS = {
    "read", "collect", "stage", "encode", "archive", "discover",
}


def _infer_severity(name: str, description: str) -> Severity:
    """TTP 이름/설명에서 심각도 추정."""
    text = (name + " " + description).lower()
    if any(kw in text for kw in HIGH_SEVERITY_KEYWORDS):
        return Severity.HIGH
    if any(kw in text for kw in MEDIUM_SEVERITY_KEYWORDS):
        return Severity.MEDIUM
    return Severity.LOW


def _get_attack_id(obj: dict) -> str | None:
    """STIX external_references 에서 T-code 추출."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _get_attack_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _get_tactics(obj: dict) -> list[str]:
    """kill_chain_phases 에서 ATT&CK 전술 추출."""
    phases = obj.get("kill_chain_phases", [])
    return [
        p.get("phase_name", "")
        for p in phases
        if p.get("kill_chain_name") == "mitre-attack"
    ]


# ─────────────── 공개 API ───────────────

def download_raw(url: str = ENTERPRISE_ATTACK_URL) -> dict:
    """MITRE ATT&CK 원본 JSON 다운로드."""
    print(f"[MITRE] downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "slop-detector/2.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_techniques(stix_bundle: dict) -> list[TTPEntry]:
    """
    STIX Bundle에서 attack-pattern 타입을 필터링하여 TTPEntry 로 변환.
    코드 탐지 가능한 전술만 선별.
    """
    entries: list[TTPEntry] = []
    now = datetime.now(UTC)

    # 버전 추출
    kb_version = "unknown"
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            kb_version = obj.get("x_mitre_version", "unknown")
            break

    skipped_deprecated = 0
    skipped_tactic = 0

    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        # 폐기된 것 제외
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            skipped_deprecated += 1
            continue

        ttp_id = _get_attack_id(obj)
        if not ttp_id:
            continue

        tactics = _get_tactics(obj)
        if not any(t in CODE_DETECTABLE_TACTICS for t in tactics):
            skipped_tactic += 1
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")

        entries.append(TTPEntry(
            ttp_id=ttp_id,
            ttp_name=name,
            source=TTPSource.MITRE_ATTACK,
            kb_version=f"MITRE ATT&CK v{kb_version}",
            description=description,
            detection_hints=[obj.get("x_mitre_detection", "")] if obj.get("x_mitre_detection") else [],
            mitigations=[],  # 관계 객체에서 별도 수집 가능 (생략)
            severity=_infer_severity(name, description),
            url=_get_attack_url(obj),
            collected_at=now,
        ))

    print(f"[MITRE] collected: {len(entries)} techniques "
          f"(skipped {skipped_deprecated} deprecated, {skipped_tactic} non-code-detectable)")
    return entries


def save_cached(entries: list[TTPEntry], path: Path) -> None:
    """수집 결과를 JSON 파일로 로컬 캐시 (임베딩 제외)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(
            [e.to_dict() for e in entries],
            f,
            ensure_ascii=False,
            indent=2,
        )
    print(f"[MITRE] saved {len(entries)} entries → {path}")


def load_cached(path: Path) -> list[TTPEntry]:
    """로컬 캐시에서 읽기."""
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    result = []
    for d in data:
        result.append(TTPEntry(
            ttp_id=d["ttp_id"],
            ttp_name=d["ttp_name"],
            source=TTPSource(d["source"]),
            kb_version=d["kb_version"],
            description=d["description"],
            detection_hints=d.get("detection_hints", []),
            mitigations=d.get("mitigations", []),
            severity=Severity(d["severity"]),
            url=d.get("url", ""),
            embedding=d.get("embedding"),
            collected_at=datetime.fromisoformat(d["collected_at"]),
        ))
    return result


def collect() -> list[TTPEntry]:
    """원샷 수집 — 다운로드 → 파싱."""
    bundle = download_raw()
    return parse_techniques(bundle)


# ─────────────── CLI 진입점 ───────────────

if __name__ == "__main__":
    out_path = Path(__file__).parent / "cache" / "mitre_attack.json"
    entries = collect()

    # 통계
    from collections import Counter
    sev_counts = Counter(e.severity.value for e in entries)
    print(f"\n심각도 분포: {dict(sev_counts)}")
    print("예시 5개:")
    for e in entries[:5]:
        print(f"  {e.ttp_id} ({e.severity.value}): {e.ttp_name}")

    save_cached(entries, out_path)
