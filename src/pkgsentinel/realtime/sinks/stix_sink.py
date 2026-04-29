"""
STIX 2.1 indicator/bundle 생성기.

근거: OASIS STIX 2.1 — https://docs.oasis-open.org/cti/stix/v2.1/

본 도구의 분석 결과를 STIX 2.1 표준 포맷으로 직렬화.
다음 객체 타입 사용:
  - indicator       : 우리 verdict 와 detection rule
  - malware         : verdict=MALICIOUS 인 패키지 자체
  - software        : 분석 대상 패키지 (SCO)
  - relationship    : indicator <-> malware/software
  - identity        : 본 도구 (creator)
  - x-aislopsq-*    : custom 확장 (verdict, evidence 등)

수신자 (TAXII server, MISP, OpenCTI 등) 가 그대로 import 가능.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

_TOOL_ID = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'ai-slopsq-detector')}"
_TOOL_NAME = "ai-slopsquatting-detector"
_TOOL_VERSION = "2.0"


def _now_ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _new_id(prefix: str, *parts: str) -> str:
    """결정적 UUIDv5 (같은 입력 → 같은 ID — STIX dedup 유리)."""
    seed = "|".join(parts)
    return f"{prefix}--{uuid.uuid5(uuid.NAMESPACE_DNS, seed)}"


def _purl(eco: str, name: str, version: str) -> str:
    if eco == "PyPI":
        return f"pkg:pypi/{name}@{version}"
    if eco == "npm":
        return f"pkg:npm/{name}@{version}"
    return f"pkg:generic/{name}@{version}"


# ─────────────── STIX pattern 빌더 ───────────────

def _build_pattern(report: dict) -> str:
    """우리 evidence 들을 STIX pattern (CSL) 로 결합.

    예: [software:name = 'evil-pkg' AND software:version = '1.0.0']
    """
    pkg = report.get("package", "?")
    ver = report.get("version", "?")
    eco = report.get("ecosystem", "?")
    return (
        f"[software:name = '{pkg}' AND "
        f"software:version = '{ver}' AND "
        f"software:vendor = '{eco}']"
    )


def _verdict_to_label(verdict: str) -> list[str]:
    return {
        "MALICIOUS":  ["malicious-activity", "supply-chain-compromise"],
        "HIGH_RISK":  ["malicious-activity"],
        "SUSPICIOUS": ["anomalous-activity"],
        "CLEAN":      ["benign"],
    }.get(verdict, ["anomalous-activity"])


# ─────────────── 객체 빌더 ───────────────

def _identity_object() -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _TOOL_ID,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": _now_ts(),
        "name": _TOOL_NAME,
        "identity_class": "system",
        "sectors": ["technology"],
        "description": "AI-slopsquatting supply-chain detector",
    }


def _software_object(pkg: str, ver: str, eco: str) -> dict:
    return {
        "type": "software",
        "spec_version": "2.1",
        "id": _new_id("software", eco, pkg, ver),
        "name": pkg,
        "version": ver,
        "vendor": eco,
        "extensions": {
            "extension-definition--aislopsq-purl": {
                "extension_type": "property-extension",
                "purl": _purl(eco, pkg, ver),
            },
        },
    }


def _malware_object(pkg: str, ver: str, eco: str, verdict: str) -> dict | None:
    if verdict not in ("MALICIOUS", "HIGH_RISK"):
        return None
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": _new_id("malware", eco, pkg, ver),
        "created_by_ref": _TOOL_ID,
        "created": _now_ts(),
        "modified": _now_ts(),
        "name": f"{eco}/{pkg}@{ver}",
        "malware_types": ["trojan", "backdoor"],
        "is_family": False,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack",
             "phase_name": "initial-access"},
            {"kill_chain_name": "mitre-attack",
             "phase_name": "execution"},
        ],
    }


def _indicator_object(report: dict) -> dict:
    pkg = report.get("package", "?")
    ver = report.get("version", "?")
    eco = report.get("ecosystem", "?")
    verdict = report.get("verdict", "ERROR")

    # 가장 신뢰도 높은 evidence 의 ttp_id 인용
    evs = report.get("evidence", []) or []
    top_ev = (
        max(evs, key=lambda e: e.get("confidence", 0))
        if evs else {}
    )
    ttp = top_ev.get("ttp_id", "T1195.002")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _new_id("indicator", eco, pkg, ver, verdict),
        "created_by_ref": _TOOL_ID,
        "created": _now_ts(),
        "modified": _now_ts(),
        "name": f"{verdict}: {eco}/{pkg}@{ver}",
        "description": top_ev.get("llm_reasoning", "") or
                       report.get("package_meta", {}).get("advisory_summary", ""),
        "indicator_types": _verdict_to_label(verdict),
        "pattern": _build_pattern(report),
        "pattern_type": "stix",
        "valid_from": _now_ts(),
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack",
             "phase_name": "initial-access"},
        ],
        "labels": _verdict_to_label(verdict),
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": ttp.split("/")[-1] if "/" in ttp else ttp,
                "url": top_ev.get("ttp_url", ""),
            },
            {
                "source_name": "purl",
                "external_id": _purl(eco, pkg, ver),
            },
        ],
        "x_aislopsq_verdict": verdict,
        "x_aislopsq_confidence": top_ev.get("confidence", 0.0),
        "x_aislopsq_evidence_count": len(evs),
    }


def _relationship(source: str, target: str, rtype: str) -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _new_id("relationship", source, target, rtype),
        "created_by_ref": _TOOL_ID,
        "created": _now_ts(),
        "modified": _now_ts(),
        "relationship_type": rtype,
        "source_ref": source,
        "target_ref": target,
    }


# ─────────────── 번들 생성 ───────────────

def to_stix_bundle(report: dict) -> dict:
    """AnalysisReport-dict → STIX 2.1 bundle."""
    pkg = report.get("package", "?")
    ver = report.get("version", "?")
    eco = report.get("ecosystem", "?")
    verdict = report.get("verdict", "ERROR")

    objects: list[dict] = []
    objects.append(_identity_object())
    sw = _software_object(pkg, ver, eco)
    objects.append(sw)

    indic = _indicator_object(report)
    objects.append(indic)
    objects.append(_relationship(indic["id"], sw["id"], "indicates"))

    mal = _malware_object(pkg, ver, eco, verdict)
    if mal:
        objects.append(mal)
        objects.append(_relationship(indic["id"], mal["id"], "indicates"))
        objects.append(_relationship(mal["id"], sw["id"], "uses"))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return bundle


def to_stix_json(report: dict) -> str:
    return json.dumps(to_stix_bundle(report), indent=2, ensure_ascii=False)


# ─────────────── TAXII 2.1 push (옵션) ───────────────

@dataclass
class STIXSink:
    """파일 / TAXII 2.1 collection 으로 발송."""
    out_dir: str | None = None        # 파일 저장 루트
    taxii_url: str | None = None      # TAXII collection POST URL
    taxii_user: str | None = None
    taxii_pass: str | None = None
    timeout: int = 15

    def emit(self, report: dict) -> dict:
        bundle = to_stix_bundle(report)
        body = json.dumps(bundle, ensure_ascii=False).encode("utf-8")
        sha = hashlib.sha256(body).hexdigest()
        result: dict = {"sha256": sha}

        # 1) 파일 저장
        if self.out_dir:
            import os
            os.makedirs(self.out_dir, exist_ok=True)
            pkg = report.get("package", "x")
            eco = report.get("ecosystem", "x")
            ver = report.get("version", "x")
            fname = f"{eco}_{pkg}_{ver}_{sha[:12]}.json".replace("/", "_")
            path = os.path.join(self.out_dir, fname)
            with open(path, "wb") as f:
                f.write(body)
            result["file"] = path

        # 2) TAXII 2.1 push
        if self.taxii_url:
            try:
                req = urllib.request.Request(
                    self.taxii_url,
                    data=body, method="POST",
                    headers={
                        "Content-Type": "application/taxii+json;version=2.1",
                        "Accept": "application/taxii+json;version=2.1",
                        "User-Agent": "ai-slopsq/2.0",
                    },
                )
                if self.taxii_user and self.taxii_pass:
                    import base64
                    cred = base64.b64encode(
                        f"{self.taxii_user}:{self.taxii_pass}".encode()
                    ).decode()
                    req.add_header("Authorization", f"Basic {cred}")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    result["taxii_status"] = resp.status
            except urllib.error.HTTPError as e:
                result["taxii_status"] = e.code
                result["taxii_error"] = e.read()[:200].decode("utf-8", "replace")
            except Exception as e:
                result["taxii_error"] = str(e)

        return result


# ─────────────── CLI 데모 ───────────────

if __name__ == "__main__":
    # sample report
    rep = {
        "verdict": "MALICIOUS",
        "package": "evil-helpers",
        "ecosystem": "PyPI",
        "version": "0.0.1",
        "evidence": [{
            "ttp_id": "T1195.002",
            "ttp_url": "https://attack.mitre.org/techniques/T1195/002/",
            "llm_reasoning": "credential exfil chain in install hook",
            "confidence": 0.92,
        }],
        "package_meta": {"advisory_summary": "auto-detected"},
    }
    print(to_stix_json(rep))
