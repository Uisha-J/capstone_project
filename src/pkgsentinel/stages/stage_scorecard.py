"""
Stage Scorecard — OpenSSF Scorecard 점수 조회.

근거: OpenSSF Scorecard — https://scorecard.dev/
API : https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}

목적:
  - 패키지의 GitHub repo 가 안전한 개발 관행을 따르는지 외부 평가 인용
  - 우리 판정에 직접 영향 X (참고 메타 정보)
  - Scorecard 가 측정하는 항목 (예시): Maintained, Code-Review,
    Branch-Protection, Token-Permissions, Vulnerabilities, …

설계 원칙:
  - 절대 외부 호출 실패가 파이프라인 전체를 망가뜨리지 않게 한다.
  - 타임아웃 짧게 (8s).
  - 캐시 없음 (외부 의존성 추가 회피). 필요 시 CLI 단에서 메모이즈 권장.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from ..schema import Ecosystem

# ─────────────── 결과 ───────────────

@dataclass
class ScorecardCheck:
    name: str
    score: float           # 0.0 ~ 10.0 (-1 = N/A)
    reason: str = ""
    documentation: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": self.score,
            "reason": self.reason[:200],
        }


@dataclass
class ScorecardReport:
    available: bool
    repo: str | None = None       # github.com/owner/repo
    date: str | None = None
    overall_score: float | None = None
    checks: list[ScorecardCheck] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "repo": self.repo,
            "date": self.date,
            "overall_score": self.overall_score,
            "checks": [c.to_dict() for c in self.checks],
            "error": self.error,
        }

    def summary_line(self) -> str:
        if not self.available:
            return f"Scorecard: unavailable ({self.error or 'no repo'})"
        return f"Scorecard {self.overall_score:.1f}/10 for {self.repo} ({len(self.checks)} checks)"


# ─────────────── GitHub URL 추출 ───────────────

_GH_URL_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?(?:#.*)?$",
    re.IGNORECASE,
)
_GH_GIT_PLUS = re.compile(
    r"git\+https?://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_GH_SSH = re.compile(
    r"git@github\.com:([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def extract_github_repo(url: str) -> str | None:
    """다양한 형식의 URL 에서 'owner/repo' 추출."""
    if not url:
        return None
    url = url.strip()
    for rgx in (_GH_URL_RE, _GH_GIT_PLUS, _GH_SSH):
        m = rgx.match(url)
        if m:
            owner, repo = m.group(1), m.group(2)
            return f"{owner}/{repo}"
    return None


def find_github_repo_in_metadata(
    raw_metadata: dict | None,
    ecosystem: Ecosystem,
) -> str | None:
    """PyPI/npm 메타데이터에서 GitHub owner/repo 추출."""
    if not raw_metadata:
        return None

    candidates: list[str] = []
    if ecosystem == Ecosystem.PYPI:
        info = raw_metadata.get("info", {}) or {}
        for key in ("home_page", "project_url", "package_url", "docs_url"):
            v = info.get(key)
            if isinstance(v, str):
                candidates.append(v)
        project_urls = info.get("project_urls") or {}
        if isinstance(project_urls, dict):
            for v in project_urls.values():
                if isinstance(v, str):
                    candidates.append(v)
    elif ecosystem == Ecosystem.NPM:
        # npm metadata 는 dist-tags 가 있는 풀 패키지 메타
        # 또는 versions[latest] 메타 둘 다 가능.
        for v in (raw_metadata.get("homepage"), raw_metadata.get("bugs", {}) or {}):
            if isinstance(v, str):
                candidates.append(v)
            elif isinstance(v, dict):
                for vv in v.values():
                    if isinstance(vv, str):
                        candidates.append(vv)
        repo = raw_metadata.get("repository")
        if isinstance(repo, dict) and "url" in repo:
            candidates.append(repo["url"])
        elif isinstance(repo, str):
            candidates.append(repo)
        # versions[latest].repository
        latest = (raw_metadata.get("dist-tags") or {}).get("latest")
        if latest:
            ver_meta = (raw_metadata.get("versions") or {}).get(latest, {})
            ver_repo = ver_meta.get("repository")
            if isinstance(ver_repo, dict) and "url" in ver_repo:
                candidates.append(ver_repo["url"])
            elif isinstance(ver_repo, str):
                candidates.append(ver_repo)
            ver_home = ver_meta.get("homepage")
            if isinstance(ver_home, str):
                candidates.append(ver_home)

    for url in candidates:
        slug = extract_github_repo(url)
        if slug:
            return slug
    return None


# ─────────────── Scorecard API 호출 ───────────────

_SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com/{slug}"


def fetch_scorecard(repo_slug: str, timeout: int = 8) -> ScorecardReport:
    """Scorecard API 호출. 실패해도 예외 던지지 않음."""
    if not repo_slug:
        return ScorecardReport(available=False, error="empty repo slug")

    url = _SCORECARD_API.format(slug=repo_slug)
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "slop-detector/2.0 scorecard"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ScorecardReport(
                available=False, repo=repo_slug,
                error="not in scorecard cache (404)",
            )
        return ScorecardReport(
            available=False, repo=repo_slug, error=f"HTTP {e.code}",
        )
    except Exception as e:
        return ScorecardReport(
            available=False, repo=repo_slug, error=f"network error: {e}",
        )

    score = data.get("score")
    date = data.get("date")
    checks_raw = data.get("checks") or []

    checks: list[ScorecardCheck] = []
    for c in checks_raw:
        checks.append(ScorecardCheck(
            name=c.get("name", "?"),
            score=float(c.get("score", -1)),
            reason=c.get("reason", "") or "",
            documentation=(c.get("documentation") or {}).get("short", "")
            if isinstance(c.get("documentation"), dict) else "",
        ))

    return ScorecardReport(
        available=True,
        repo=repo_slug,
        date=date,
        overall_score=float(score) if score is not None else None,
        checks=checks,
    )


# ─────────────── 통합 헬퍼 ───────────────

def fetch_for_package(
    raw_metadata: dict | None,
    ecosystem: Ecosystem,
    timeout: int = 8,
) -> ScorecardReport:
    """레지스트리 메타로부터 자동 GitHub repo 찾고 Scorecard 조회."""
    repo = find_github_repo_in_metadata(raw_metadata, ecosystem)
    if not repo:
        return ScorecardReport(
            available=False, error="no github repo found in metadata",
        )
    return fetch_scorecard(repo, timeout=timeout)


# ─────────────── 위험 신호 추출 ───────────────

# Scorecard 의 어떤 항목이 LOW 면 보안상 우려 신호인지
_RISK_THRESHOLDS = {
    "Maintained": 3.0,           # 6개월 이상 미유지
    "Code-Review": 5.0,          # 코드 리뷰 부재
    "Branch-Protection": 3.0,    # 보호되지 않은 main
    "Token-Permissions": 5.0,    # 과도한 GITHUB_TOKEN 권한
    "Vulnerabilities": 7.0,      # 알려진 CVE 보유
    "Pinned-Dependencies": 3.0,  # 의존성 미고정
    "Dangerous-Workflow": 7.0,   # 위험한 GitHub Actions
}


def extract_risk_signals(report: ScorecardReport) -> list[str]:
    """Scorecard 결과에서 사람-읽기 쉬운 위험 신호 문장 추출."""
    if not report.available or not report.checks:
        return []
    signals: list[str] = []
    for c in report.checks:
        threshold = _RISK_THRESHOLDS.get(c.name)
        if threshold is None:
            continue
        if 0 <= c.score < threshold:
            signals.append(
                f"Scorecard: {c.name}={c.score:.1f}/10 (threshold {threshold}). "
                f"{c.reason[:120]}"
            )
    return signals


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    # 사용법: python -m detector.stages.stage_scorecard <slug-or-url>
    arg = sys.argv[1] if len(sys.argv) > 1 else "anthropics/anthropic-sdk-python"
    if arg.startswith(("http", "git")):
        slug = extract_github_repo(arg)
        print(f"extracted slug: {slug}")
        if not slug:
            print("could not parse")
            sys.exit(1)
    else:
        slug = arg

    print(f"fetching scorecard for {slug} ...")
    rpt = fetch_scorecard(slug)
    print(rpt.summary_line())
    if rpt.available:
        print(f"  date         : {rpt.date}")
        print(f"  overall_score: {rpt.overall_score:.2f}/10")
        print("  checks       :")
        for c in rpt.checks:
            print(f"    - {c.name:<25}  {c.score:>5.1f}  {c.reason[:80]}")
        print()
        print("Risk signals:")
        for s in extract_risk_signals(rpt):
            print(f"  ! {s}")
    else:
        print(f"  error: {rpt.error}")
