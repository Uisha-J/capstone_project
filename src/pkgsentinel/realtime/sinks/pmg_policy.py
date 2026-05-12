"""SafeDep pmg (Package Manager Guard) sink.

pmg 는 npm install / pip install 명령을 wrap 해 정책에 따라 차단/허용.
근거: https://github.com/safedep/pmg + https://docs.safedep.io/cloud/vet

우리 verdict (MALICIOUS / HIGH_RISK / SUSPICIOUS / CLEAN) → pmg 가 소비하는
정책 YAML 로 변환. pmg 가 정책을 평가해 install 차단.

정책 포맷 (vet 호환 CEL — pmg 가 vet 정책 소비):

  name: pkgsentinel-deny
  description: Auto-generated from pkgsentinel verdicts
  tags: [auto, pkgsentinel]
  rules:
    - name: block-evil-stealer
      summary: "pkgsentinel verdict=MALICIOUS for evil-stealer@0.0.1"
      check:
        - cel: |
            packages.exists(p,
              p.name == "evil-stealer" &&
              p.version == "0.0.1" &&
              p.ecosystem == "pypi"
            )
      action: deny

본 sink 는 단일 verdict report 1건당 하나의 정책 yaml 을 생성. 누적 emit 시
caller 가 외부 도구(yamllint / 자체 merger)로 한 정책으로 묶을 수도 있음.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


# verdict → action 매핑.
# MALICIOUS / HIGH_RISK → deny (install 차단)
# SUSPICIOUS           → warn (install 허용하지만 사용자에게 경고)
# CLEAN                → 정책 생성 안 함 (no-op)
_VERDICT_ACTION = {
    "MALICIOUS": "deny",
    "HIGH_RISK": "deny",
    "SUSPICIOUS": "warn",
    "AGENTIC": "warn",
}


def _ecosystem_to_pmg(eco: str) -> str:
    """우리 ecosystem 라벨 → pmg/vet 의 ecosystem ID."""
    e = eco.lower()
    if e == "pypi":
        return "pypi"
    if e == "npm":
        return "npm"
    return e


def _slug(s: str) -> str:
    """yaml-안전한 짧은 id. 영문/숫자/하이픈/언더스코어만."""
    out = []
    for ch in s.lower():
        if ch.isalnum() or ch in "-_":
            out.append(ch)
        else:
            out.append("-")
    s2 = "".join(out).strip("-")
    return s2 or "x"


def to_pmg_policy(report: dict) -> str | None:
    """단일 verdict report → pmg 정책 YAML.

    verdict 가 CLEAN / ERROR / CANNOT_ANALYZE 등이면 None (정책 생성 안 함).
    """
    verdict = (report.get("verdict") or "").upper()
    action = _VERDICT_ACTION.get(verdict)
    if action is None:
        return None

    pkg = report.get("package") or "unknown"
    ver = report.get("version") or "*"
    eco = _ecosystem_to_pmg(report.get("ecosystem") or "pypi")

    # rule name = "<action>-<eco>-<pkg-slug>-<ver-slug>"
    rule_name = f"{action}-{_slug(eco)}-{_slug(pkg)}-{_slug(ver)}"[:64]

    # 요약 — 첫 evidence 의 ttp + LLM reasoning 활용
    summary_parts = [
        f"pkgsentinel verdict={verdict}",
        f"{pkg}@{ver} ({eco})",
    ]
    evidence = report.get("evidence") or []
    if evidence:
        first = evidence[0]
        ttp = first.get("ttp_id")
        if ttp:
            summary_parts.append(f"TTP: {ttp}")
        reasoning = (first.get("llm_reasoning") or "")[:120]
        if reasoning:
            summary_parts.append(f"Reason: {reasoning}")
    summary = " | ".join(summary_parts).replace("\n", " ").replace('"', "'")

    # CEL — vet 호환. 정확한 (name, version, ecosystem) 매칭
    # version=* 면 모든 버전 차단
    if ver == "*" or not ver:
        cel = (
            f'packages.exists(p, '
            f'p.name == "{pkg}" && '
            f'p.ecosystem == "{eco}"'
            f')'
        )
    else:
        cel = (
            f'packages.exists(p, '
            f'p.name == "{pkg}" && '
            f'p.version == "{ver}" && '
            f'p.ecosystem == "{eco}"'
            f')'
        )

    # YAML 직접 build — 의존성 없이 (PyYAML 옵션, 단순 case)
    yaml_lines = [
        "name: pkgsentinel-auto",
        f'description: "Auto-generated from pkgsentinel verdict={verdict}"',
        "tags:",
        "  - auto",
        "  - pkgsentinel",
        f'  - {verdict.lower()}',
        "rules:",
        f"  - name: {rule_name}",
        f'    summary: "{summary}"',
        "    check:",
        "      - cel: |",
        f"          {cel}",
        f"    action: {action}",
    ]
    return "\n".join(yaml_lines) + "\n"


@dataclass
class PmgPolicySink:
    """verdict report → pmg/vet 정책 YAML 파일 저장.

    out_dir: 정책 yaml 저장 디렉터리. 비어 있으면 to_pmg_policy 만 사용 가능.
    """
    out_dir: str | None = None

    def emit(self, report: dict) -> dict:
        policy = to_pmg_policy(report)
        if policy is None:
            return {
                "ok": True,
                "skipped": True,
                "reason": f"verdict={report.get('verdict')} → no policy",
            }

        body = policy.encode("utf-8")
        sha = hashlib.sha256(body).hexdigest()
        result: dict = {"ok": True, "sha256": sha, "size": len(body)}

        if self.out_dir:
            os.makedirs(self.out_dir, exist_ok=True)
            pkg = report.get("package", "x")
            eco = report.get("ecosystem", "x")
            ver = report.get("version", "x")
            fname = (
                f"pmg-{_slug(eco)}-{_slug(pkg)}-{_slug(ver)}-{sha[:8]}.yaml"
            )
            path = os.path.join(self.out_dir, fname)
            with open(path, "wb") as f:
                f.write(body)
            result["file"] = path

        return result
