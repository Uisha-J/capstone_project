"""OpenSSF Scorecard 단위 테스트 (URL 추출 + 옵션: 실제 API 호출)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.schema import Ecosystem
from pkgsentinel.stages.stage_scorecard import (
    extract_github_repo,
    find_github_repo_in_metadata,
    fetch_scorecard,
    extract_risk_signals,
)


def test_url_extraction():
    print("== URL extraction ==")
    cases = [
        ("https://github.com/pallets/flask", "pallets/flask"),
        ("https://github.com/pallets/flask.git", "pallets/flask"),
        ("https://github.com/pallets/flask/", "pallets/flask"),
        ("https://github.com/pallets/flask#readme", "pallets/flask"),
        ("git+https://github.com/owner/repo.git", "owner/repo"),
        ("git@github.com:owner/repo.git", "owner/repo"),
        ("https://gitlab.com/x/y", None),
        ("not a url", None),
        ("", None),
    ]
    ok = True
    for url, expected in cases:
        got = extract_github_repo(url)
        mark = "OK  " if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"  [{mark}] {url!r:<60} -> {got}")
    return ok


def test_metadata_extraction():
    print("\n== Metadata extraction (mock) ==")
    pypi_meta = {
        "info": {
            "home_page": "https://pallets.com",
            "project_urls": {
                "Source": "https://github.com/pallets/flask",
                "Docs": "https://flask.palletsprojects.com/",
            },
        },
    }
    npm_meta = {
        "homepage": "https://chalk.example.com",
        "repository": {"type": "git", "url": "git+https://github.com/chalk/chalk.git"},
        "dist-tags": {"latest": "5.0.0"},
        "versions": {"5.0.0": {}},
    }
    s_pypi = find_github_repo_in_metadata(pypi_meta, Ecosystem.PYPI)
    s_npm = find_github_repo_in_metadata(npm_meta, Ecosystem.NPM)
    print(f"  PyPI: {s_pypi}  (expected pallets/flask)")
    print(f"  npm : {s_npm}   (expected chalk/chalk)")
    return s_pypi == "pallets/flask" and s_npm == "chalk/chalk"


def test_unknown_repo():
    print("\n== Unknown repo (404 expected) ==")
    rpt = fetch_scorecard("nonexistent-org-xyz/nonexistent-repo-abc", timeout=8)
    print(f"  available: {rpt.available}")
    print(f"  error    : {rpt.error}")
    return not rpt.available


def test_real_fetch():
    """선택적: 실제 API 호출 — SCORECARD_LIVE=1 일 때만."""
    if os.getenv("SCORECARD_LIVE") != "1":
        print("\n== Live fetch SKIPPED (set SCORECARD_LIVE=1 to enable) ==")
        return True
    print("\n== Live fetch (pallets/flask) ==")
    rpt = fetch_scorecard("pallets/flask")
    print(f"  available    : {rpt.available}")
    print(f"  overall_score: {rpt.overall_score}")
    print(f"  checks       : {len(rpt.checks)}")
    sig = extract_risk_signals(rpt)
    print(f"  risk signals : {len(sig)}")
    for s in sig[:3]:
        print(f"    - {s[:120]}")
    return rpt.available and rpt.overall_score is not None


def main():
    ok = True
    ok &= test_url_extraction()
    ok &= test_metadata_extraction()
    ok &= test_unknown_repo()
    ok &= test_real_fetch()
    print("\n" + ("ALL OK" if ok else "FAILED"))


if __name__ == "__main__":
    main()
