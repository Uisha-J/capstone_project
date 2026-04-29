"""
Stage 0 — 레지스트리 존재 확인.

PyPI / npm 에서 패키지의 등록 여부만 확인. 판정에는 쓰지 않음 (CANNOT_ANALYZE 여부만 결정).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..schema import Ecosystem


@dataclass
class RegistryInfo:
    found: bool
    latest_version: str | None = None
    all_versions: list[str] = None
    archive_urls: dict[str, str] = None       # {version: tarball_url}
    raw_metadata: dict = None
    error: str | None = None


def _http_get_json(url: str, timeout: int = 15) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": "slop-detector/2.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_pypi(package: str) -> RegistryInfo:
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        data = _http_get_json(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return RegistryInfo(found=False)
        return RegistryInfo(found=False, error=f"HTTP {e.code}")
    except Exception as e:
        return RegistryInfo(found=False, error=str(e))

    releases = data.get("releases", {}) or {}
    versions = [v for v, files in releases.items() if files]

    # 각 버전의 sdist/wheel URL
    archive_urls: dict[str, str] = {}
    for v, files in releases.items():
        if not files:
            continue
        # sdist 우선, 없으면 wheel
        sdist = next((f for f in files if f.get("packagetype") == "sdist"), None)
        wheel = next((f for f in files if f.get("packagetype") == "bdist_wheel"), None)
        chosen = sdist or wheel or files[0]
        archive_urls[v] = chosen.get("url", "")

    return RegistryInfo(
        found=True,
        latest_version=data.get("info", {}).get("version"),
        all_versions=sorted(versions, key=lambda v: list(map(_try_int, v.split(".")))),
        archive_urls=archive_urls,
        raw_metadata=data,
    )


def check_npm(package: str) -> RegistryInfo:
    url = f"https://registry.npmjs.org/{package}"
    try:
        data = _http_get_json(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return RegistryInfo(found=False)
        return RegistryInfo(found=False, error=f"HTTP {e.code}")
    except Exception as e:
        return RegistryInfo(found=False, error=str(e))

    versions = list((data.get("versions") or {}).keys())
    archive_urls: dict[str, str] = {}
    for v, meta in (data.get("versions") or {}).items():
        archive_urls[v] = meta.get("dist", {}).get("tarball", "")

    latest = data.get("dist-tags", {}).get("latest")

    return RegistryInfo(
        found=True,
        latest_version=latest,
        all_versions=sorted(versions, key=lambda v: list(map(_try_int, v.split(".")))),
        archive_urls=archive_urls,
        raw_metadata=data,
    )


def check(package: str, ecosystem: Ecosystem) -> RegistryInfo:
    if ecosystem == Ecosystem.PYPI:
        return check_pypi(package)
    if ecosystem == Ecosystem.NPM:
        return check_npm(package)
    raise ValueError(f"unsupported ecosystem: {ecosystem}")


def _try_int(x: str):
    try:
        return int(x)
    except ValueError:
        return 9999  # alpha/beta 등은 뒤로


# CLI 테스트
if __name__ == "__main__":
    import sys
    eco = Ecosystem.PYPI if len(sys.argv) < 3 else Ecosystem(sys.argv[2])
    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    info = check(pkg, eco)
    if not info.found:
        print(f"[{pkg}] NOT FOUND on {eco.value} (error: {info.error})")
    else:
        print(f"[{pkg}] found on {eco.value}")
        print(f"  latest: {info.latest_version}")
        print(f"  versions: {len(info.all_versions)}")
        print(f"  sample archive url: {list(info.archive_urls.values())[0] if info.archive_urls else '-'}")
