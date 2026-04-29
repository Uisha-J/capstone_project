"""
OSV (osv.dev) 기반 최근 공급망 공격 사례 수집기.

OSV 는 Google 이 운영하는 오픈소스 취약점 공개 DB.
PyPI / npm 에서 실제 발견된 악성 패키지 리포트가 집약되어 있음.

수집 파이프라인:
  1. OSV API 에서 PyPI / npm 전체 advisory 덤프 (GCS zip 공개)
  2. 악성 패키지 관련 advisory 만 필터 (MAL-* / GHSA-* 등)
  3. 각 advisory 에서 패키지명, 버전, 설명, 코드 지표 추출
  4. 저장 (JSON 파일, 나중에 DB로)
"""
from __future__ import annotations

import io
import json
import re
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

# OSV 공개 덤프 (GCS)
OSV_PYPI_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
OSV_NPM_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"


# ─────────────── 데이터 구조 ───────────────

@dataclass
class AttackPattern:
    """수집된 실제 공격 사례 한 건."""
    advisory_id: str               # "GHSA-xxxx" / "MAL-xxxx"
    aliases: list[str]             # 다른 ID (CVE 등)
    source: str                    # "OSV"
    ecosystem: str                 # "PyPI" / "npm"

    # 대상 패키지
    affected_packages: list[str]   # 공격자가 올린 패키지명 리스트
    affected_versions: list[str]   # 악성 버전들

    # 설명
    summary: str
    details: str

    # 분류
    attack_type: str               # "malicious_package" | "dependency_confusion" | "typosquatting" | "other"
    published: str                 # ISO date
    modified: str                  # ISO date

    # 자동 추출된 인디케이터 (Phase D-2에서 채움)
    code_indicators: list[str] = field(default_factory=list)
    network_indicators: list[str] = field(default_factory=list)

    # 참고 URL
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────── 다운로드 + 파싱 ───────────────

def _download_zip(url: str, timeout: int = 120) -> bytes:
    print(f"[OSV] downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "slop-detector/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


_NETWORK_INDICATOR_RE = re.compile(
    r'(?:https?://[^\s"\'>)]+'
    r'|[a-zA-Z0-9.-]+\.(?:com|net|org|io|xyz|info|top|tk|ml|ga|cf|gq|onion)(?:/[^\s"\'>)]*)?'
    r'|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)'
)

# 코드에서 자주 보이는 악성 API / 체인 지표
_CODE_INDICATOR_PATTERNS = [
    r"\bbase64\.b64decode\b",
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\bsubprocess\.(?:Popen|run|call)\b",
    r"\bos\.system\b",
    r"\bchild_process\.(?:exec|spawn)\b",
    r"\brequests\.(?:get|post)\b",
    r"\burllib\.request\b",
    r"\bprocess\.env\b",
    r"\bos\.environ\b",
    r"\batob\s*\(",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bpowershell\b",
]


def _extract_indicators(text: str) -> tuple[list[str], list[str]]:
    """advisory 본문에서 코드 지표 / 네트워크 지표 추출."""
    code_set = set()
    for pat in _CODE_INDICATOR_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            code_set.add(pat.replace(r"\b", "").replace(r"\s*", "").replace("(?:", "").replace(")", "").strip("\\"))
    network_matches = _NETWORK_INDICATOR_RE.findall(text)
    # 중복 제거 + 소문자화 + 길이 제한
    network_list = list(dict.fromkeys(network_matches))[:10]
    return sorted(code_set), network_list


_STRONG_MALICIOUS_PHRASES = [
    "malicious package",
    "malicious code",
    "malware was found",
    "malware detected",
    "typosquatting",
    "typo-squat",
    "slopsquatting",
    "dependency confusion",
    "credential stealer",
    "info stealer",
    "infostealer",
    "supply chain attack",
    "backdoored",
    "contains a backdoor",
    "any version of this package",
    "exfiltrate",
    "exfiltrates",
    "harvest credentials",
]


def _classify_attack(record: dict) -> str:
    """
    엄격한 분류:
      - advisory_id 가 "MAL-" 로 시작 → 확실한 악성 패키지
      - aliases 중 "MAL-*" 존재 → 동일
      - summary/details 에 "강한 악성 구문" 포함 → 악성 패키지
      - 그 외 CVE/GHSA 취약점은 모두 "other" (공격 패턴 DB 에 넣지 않음)
    """
    advisory_id = record.get("id", "").upper()
    if advisory_id.startswith("MAL-"):
        return "malicious_package"
    for alias in record.get("aliases", []) or []:
        if alias.upper().startswith("MAL-"):
            return "malicious_package"

    text = (record.get("summary", "") + " " + record.get("details", "")).lower()

    if any(phrase in text for phrase in _STRONG_MALICIOUS_PHRASES):
        # 타이포스쿼팅 별도 분류
        if any(kw in text for kw in ["typosquat", "typo-squat", "typo squat"]):
            return "typosquatting"
        if "dependency confusion" in text:
            return "dependency_confusion"
        if "slopsquat" in text:
            return "slopsquatting"
        return "malicious_package"

    return "other"


def _parse_advisory(raw: dict, ecosystem: str) -> AttackPattern | None:
    """OSV JSON 한 건을 AttackPattern 으로 변환."""
    advisory_id = raw.get("id", "")
    if not advisory_id:
        return None

    affected = raw.get("affected", []) or []
    if not affected:
        return None

    pkg_names = []
    versions = []
    for a in affected:
        p = a.get("package", {}) or {}
        name = p.get("name", "")
        if name:
            pkg_names.append(name)
        for v in (a.get("versions") or []):
            versions.append(v)
        for r in (a.get("ranges") or []):
            for ev in r.get("events", []) or []:
                # introduced / fixed / limit 에 있는 version 추출
                for k, v in ev.items():
                    if k in ("introduced", "fixed", "limit") and v != "0":
                        versions.append(v)

    pkg_names = sorted(set(pkg_names))
    versions = sorted(set(versions))
    if not pkg_names:
        return None

    summary = raw.get("summary", "") or ""
    details = raw.get("details", "") or ""
    refs = [r.get("url") for r in (raw.get("references") or []) if r.get("url")]

    code_ind, net_ind = _extract_indicators(summary + "\n" + details)

    return AttackPattern(
        advisory_id=advisory_id,
        aliases=raw.get("aliases", []) or [],
        source="OSV",
        ecosystem=ecosystem,
        affected_packages=pkg_names,
        affected_versions=versions[:20],   # 너무 많으면 잘림
        summary=summary[:500],
        details=details[:2000],
        attack_type=_classify_attack(raw),
        published=raw.get("published", ""),
        modified=raw.get("modified", ""),
        code_indicators=code_ind,
        network_indicators=net_ind,
        references=refs[:10],
    )


# ─────────────── 수집 ───────────────

def collect_osv(
    ecosystem: str = "PyPI",
    limit: int | None = None,
) -> list[AttackPattern]:
    url = OSV_PYPI_ZIP if ecosystem == "PyPI" else OSV_NPM_ZIP
    zip_bytes = _download_zip(url)

    patterns: list[AttackPattern] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for i, name in enumerate(zf.namelist()):
            if not name.endswith(".json"):
                continue
            try:
                raw = json.loads(zf.read(name))
            except Exception:
                continue
            ap = _parse_advisory(raw, ecosystem)
            if ap and ap.attack_type in (
                "malicious_package", "typosquatting",
                "dependency_confusion", "slopsquatting",
            ):
                patterns.append(ap)
            if limit and len(patterns) >= limit:
                break
    print(f"[OSV] {ecosystem}: collected {len(patterns)} supply-chain relevant advisories")
    return patterns


def save_patterns(patterns: list[AttackPattern], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([p.to_dict() for p in patterns], f, ensure_ascii=False, indent=2)
    print(f"[OSV] saved {len(patterns)} patterns -> {path}")


def load_patterns(path: Path) -> list[AttackPattern]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return [AttackPattern(**d) for d in data]


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys
    from collections import Counter

    ecosystem = sys.argv[1] if len(sys.argv) > 1 else "PyPI"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else None

    patterns = collect_osv(ecosystem, limit=limit)

    type_counts = Counter(p.attack_type for p in patterns)
    print(f"\n공격 유형 분포: {dict(type_counts)}")

    # 최근 5건 요약
    print("\n최근 5건 샘플:")
    for p in sorted(patterns, key=lambda x: x.published, reverse=True)[:5]:
        print(f"\n  [{p.advisory_id}] {p.attack_type}  ({p.published[:10]})")
        print(f"    packages: {p.affected_packages[:3]}")
        print(f"    summary : {p.summary[:100]}")
        if p.code_indicators:
            print(f"    code    : {p.code_indicators[:5]}")
        if p.network_indicators:
            print(f"    network : {p.network_indicators[:3]}")

    out_dir = Path(__file__).parent / "cache"
    save_patterns(patterns, out_dir / f"osv_{ecosystem.lower()}.json")
