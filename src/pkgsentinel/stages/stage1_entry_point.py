"""
Stage 1 — 아카이브 스트리밍 다운로드 + Entry Point 추출.

메모리에서 처리, 디스크에 풀지 않음.
Tier 1 Entry Point 만 추출: 설치/import 자동 실행되는 파일.
"""
from __future__ import annotations

import io
import json
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field

from ..schema import Ecosystem

# ─────────────── Tier 1 파일 패턴 ───────────────

PYPI_TIER1_BASENAMES = {
    "setup.py",
    "pyproject.toml",
    "setup.cfg",
    "__init__.py",
    "__main__.py",
}

NPM_TIER1_BASENAMES = {
    "package.json",
    "index.js",
    "index.mjs",
    "index.cjs",
    "postinstall.js",
    "preinstall.js",
}

# npm tarball 최상위 폴더는 "package/" 이므로 무시하고 basename/상대경로로 판단
# PyPI sdist 는 최상위가 "{name}-{version}/" 이므로 마찬가지


# ─────────────── 데이터 구조 ───────────────

@dataclass
class EntryFile:
    path: str                  # 아카이브 내부 상대 경로
    basename: str
    content: str               # UTF-8 디코딩된 텍스트
    size: int

    # 파일 내용 탐지된 언어 (아직 기본값만)
    language: str = "unknown"


@dataclass
class ExtractedPackage:
    package: str
    ecosystem: Ecosystem
    version: str
    archive_url: str
    archive_size: int

    entry_files: list[EntryFile] = field(default_factory=list)
    all_file_names: list[str] = field(default_factory=list)   # 전체 파일 목록 (참고)
    error: str | None = None


# ─────────────── 다운로드 + 추출 ───────────────

MAX_ARCHIVE_SIZE = 50 * 1024 * 1024   # 50MB 상한
MAX_TEXT_FILE_SIZE = 500 * 1024       # 개별 텍스트 파일 500KB 제한
TIMEOUT = 60


def _download(url: str) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "slop-detector/2.0"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read(MAX_ARCHIVE_SIZE + 1)
    if len(data) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"archive too large (>{MAX_ARCHIVE_SIZE} bytes)")
    return data


# 배제할 경로 (예시/테스트/문서 코드는 제품 코드가 아니므로 분석 대상에서 제외)
EXCLUDE_DIR_SEGMENTS = {
    "examples", "example", "tests", "test", "__tests__", "docs",
    "doc", "sample", "samples", "fixtures", "fixture", "demo", "demos",
    "node_modules", ".git", ".github",
    # 2026-05-06 추가: 벤더된 3rd party 코드 — 분석 대상 아님
    # (django/.../static/admin/js/vendor/xregexp 같은 케이스에서 DEF-005 FP 발생)
    "vendor", "vendored", "third_party", "thirdparty", "_vendor",
    # 2026-05-06 추가 (fastapi LLM 모드 v2 잔존 FP 분석):
    # fastapi/docs_src/ + fastapi/scripts/playwright/ 가 분석 대상 들어가
    # 7건 NET-010 + 1건 T1140 FP 발생.
    "docs_src", "documentation",                  # docs 변형
    "playwright", "cypress", "e2e",               # E2E 테스트 도구
}

# 정확 매칭 외에, segment 가 이 prefix 들 중 하나로 시작하면 제외.
# numpy 의 `vendored-meson/`, `vendored-numpy/` 같은 하이픈 결합 디렉토리 대응.
EXCLUDE_DIR_PREFIXES = (
    "vendored-",   # vendored-meson, vendored-numpy 등
    "_vendor_",    # 일부 빌드 도구의 vendoring 패턴
    # 2026-05-06 추가: docs/example/test 의 변형
    "docs_",       # docs_src, docs_internal 등
    "doc-",        # doc-build, doc-examples 등
    "example_",    # example_app, example_data 등
)


def _has_excluded_segment(parts: list[str]) -> bool:
    for seg in parts:
        if seg in EXCLUDE_DIR_SEGMENTS:
            return True
        for pfx in EXCLUDE_DIR_PREFIXES:
            if seg.startswith(pfx):
                return True
    return False


def _is_tier1_pypi(name: str) -> bool:
    """상대 경로 name이 PyPI Tier 1인가."""
    parts = name.replace("\\", "/").split("/")
    basename = parts[-1]

    if basename not in PYPI_TIER1_BASENAMES:
        return False

    # 예시/테스트 폴더 제외
    if _has_excluded_segment(parts):
        return False

    # setup.py, pyproject.toml, setup.cfg 는 최상위 (pkg-x.y.z/ 바로 아래)만
    if basename in {"setup.py", "pyproject.toml", "setup.cfg"}:
        if len(parts) != 2:
            return False
        return True

    # __init__.py / __main__.py 는 "최상위 패키지 혹은 src 레이아웃의 최상위 패키지"만
    # 허용 구조:
    #   pkg-1.0.0/<package>/__init__.py        (flat)
    #   pkg-1.0.0/src/<package>/__init__.py    (src layout)
    if basename in {"__init__.py", "__main__.py"}:
        if len(parts) == 3:
            return True
        if len(parts) == 4 and parts[1] == "src":
            return True
        return False

    return True


def _is_tier1_npm(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    basename = parts[-1]

    if basename not in NPM_TIER1_BASENAMES:
        return False

    if _has_excluded_segment(parts):
        return False

    # package.json 은 최상위 것만
    if basename == "package.json" and len(parts) > 2:
        return False

    # index.js 는 npm tarball 최상위 디렉터리 ("package/") 기준 1레벨
    if basename.startswith("index"):
        # 최상위 'package/index.js' 만 허용
        if len(parts) > 2:
            return False

    return True


def _safe_decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _detect_language(basename: str) -> str:
    if basename.endswith(".py"):
        return "python"
    if basename.endswith((".js", ".mjs", ".cjs")):
        return "javascript"
    if basename == "package.json" or basename.endswith(".json"):
        return "json"
    if basename == "pyproject.toml" or basename.endswith(".toml"):
        return "toml"
    if basename == "setup.cfg" or basename.endswith(".cfg"):
        return "cfg"
    return "unknown"


def _extract_from_tar(data: bytes, is_tier1) -> tuple[list[EntryFile], list[str]]:
    entries: list[EntryFile] = []
    all_names: list[str] = []

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name = member.name
            all_names.append(name)

            if not is_tier1(name):
                continue
            if member.size > MAX_TEXT_FILE_SIZE:
                continue

            try:
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                raw = fobj.read()
            except Exception:
                continue

            basename = name.replace("\\", "/").split("/")[-1]
            entries.append(EntryFile(
                path=name,
                basename=basename,
                content=_safe_decode(raw),
                size=len(raw),
                language=_detect_language(basename),
            ))
    return entries, all_names


def _extract_from_zip(data: bytes, is_tier1) -> tuple[list[EntryFile], list[str]]:
    entries: list[EntryFile] = []
    all_names: list[str] = []

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            all_names.append(info.filename)

            if not is_tier1(info.filename):
                continue
            if info.file_size > MAX_TEXT_FILE_SIZE:
                continue

            try:
                raw = zf.read(info.filename)
            except Exception:
                continue

            basename = info.filename.replace("\\", "/").split("/")[-1]
            entries.append(EntryFile(
                path=info.filename,
                basename=basename,
                content=_safe_decode(raw),
                size=len(raw),
                language=_detect_language(basename),
            ))
    return entries, all_names


def extract(
    package: str,
    ecosystem: Ecosystem,
    version: str,
    archive_url: str,
) -> ExtractedPackage:
    """원샷: URL 다운로드 → 압축 해제 → Tier 1 파일 리스트 반환."""
    result = ExtractedPackage(
        package=package,
        ecosystem=ecosystem,
        version=version,
        archive_url=archive_url,
        archive_size=0,
    )
    try:
        data = _download(archive_url)
        result.archive_size = len(data)
    except Exception as e:
        result.error = f"download failed: {e}"
        return result

    is_tier1 = _is_tier1_pypi if ecosystem == Ecosystem.PYPI else _is_tier1_npm

    try:
        # PyPI sdist는 .tar.gz, wheel은 .zip (확장자 .whl)
        # npm 은 .tgz (tar.gz)
        if archive_url.endswith((".tar.gz", ".tgz")):
            entries, names = _extract_from_tar(data, is_tier1)
        elif archive_url.endswith((".zip", ".whl")):
            entries, names = _extract_from_zip(data, is_tier1)
        else:
            # 시도 순서: tar → zip
            try:
                entries, names = _extract_from_tar(data, is_tier1)
            except Exception:
                entries, names = _extract_from_zip(data, is_tier1)
    except Exception as e:
        result.error = f"extract failed: {e}"
        return result

    # package.json 을 파싱해서 postinstall 스크립트는 별도 추출 (npm)
    if ecosystem == Ecosystem.NPM:
        for ef in entries:
            if ef.basename == "package.json":
                try:
                    pkg = json.loads(ef.content)
                    scripts = pkg.get("scripts", {}) or {}
                    extra = []
                    for hook in ("preinstall", "install", "postinstall"):
                        if hook in scripts:
                            extra.append(f"# {hook}: {scripts[hook]}")
                    if extra:
                        # 가상 "scripts__virtual" 파일로 추가
                        entries.append(EntryFile(
                            path="package.json::scripts",
                            basename="package.json::scripts",
                            content="\n".join(extra),
                            size=sum(len(x) for x in extra),
                            language="shell",
                        ))
                except Exception:
                    pass
                break

    result.entry_files = entries
    result.all_file_names = names
    return result


# ─────────────── CLI 테스트 ───────────────

if __name__ == "__main__":
    import sys

    from .stage0_registry import check

    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    if not info.found:
        print(f"[{pkg}] not found")
        sys.exit(1)

    v = info.latest_version
    url = info.archive_urls.get(v)
    print(f"[{pkg}] latest={v}, url={url[:80]}...")

    ext = extract(pkg, eco, v, url)
    if ext.error:
        print(f"error: {ext.error}")
        sys.exit(1)

    print(f"archive size: {ext.archive_size} bytes")
    print(f"total files in archive: {len(ext.all_file_names)}")
    print(f"tier 1 files extracted: {len(ext.entry_files)}")
    for ef in ext.entry_files:
        print(f"  [{ef.language}] {ef.path} ({ef.size} bytes)")
        preview = ef.content.splitlines()[:3]
        for line in preview:
            print(f"      {line[:100]}")
        print("      ...")
