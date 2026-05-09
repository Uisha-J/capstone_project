"""
Stage 1B — 전 파일 소스 확보 (Tier 2/3 커버).

Tier 1 (stage1_entry_point) 만으로는 sub-module 에 숨긴 악성 코드를 못 잡는다.
event-stream 사건처럼 깊은 파일에 악성 코드가 있는 경우를 대비.

전략:
  - 텍스트 소스 파일(.py/.js/.mjs/.cjs/.ts) 전체 추출
  - 파일 크기 제한 (500KB 넘으면 스킵)
  - 테스트/문서/예시 경로는 제외
  - 바이너리 파일은 별도 목록으로 분리 (Phase C 바이너리 분석용)
"""
from __future__ import annotations

import io
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field

from ..schema import Ecosystem
from .stage1_entry_point import (
    EXCLUDE_DIR_PREFIXES,
    EXCLUDE_DIR_SEGMENTS,
    MAX_ARCHIVE_SIZE,
    MAX_TEXT_FILE_SIZE,
    EntryFile,
    _detect_language,
    _safe_decode,
)

# ─────────────── 바이너리 / 분석 대상 분류 ───────────────

SOURCE_EXTENSIONS_PY = {".py"}
SOURCE_EXTENSIONS_JS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
METADATA_EXTENSIONS = {".json", ".toml", ".cfg", ".yaml", ".yml", ".ini"}

BINARY_EXTENSIONS = {
    ".so", ".dylib", ".dll", ".pyd", ".node",     # 컴파일된 네이티브
    ".exe", ".bin",
}

DOC_EXTENSIONS = {".md", ".rst", ".txt", ".html"}  # 분석 제외 (DOS prevent)


# ─────────────── 데이터 구조 ───────────────

@dataclass
class FullSourceFile:
    path: str
    basename: str
    content: str
    size: int
    language: str
    tier: int           # 1 = entry point, 2 = 1-hop imports, 3 = 그 외 소스


@dataclass
class FullSourceExtract:
    package: str
    ecosystem: Ecosystem
    version: str
    archive_url: str
    archive_size: int

    source_files: list[FullSourceFile] = field(default_factory=list)
    binary_files: list[str] = field(default_factory=list)     # 경로만 기록 (Phase C 용)
    all_file_names: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    error: str | None = None


# ─────────────── 파일 분류 ───────────────

def _is_excluded_path(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    for seg in parts:
        if seg in EXCLUDE_DIR_SEGMENTS:
            return True
        for pfx in EXCLUDE_DIR_PREFIXES:
            if seg.startswith(pfx):
                return True
    return False


def _classify_file(name: str) -> str:
    """'source_py' | 'source_js' | 'metadata' | 'binary' | 'doc' | 'other'"""
    lower = name.lower()
    for ext in SOURCE_EXTENSIONS_PY:
        if lower.endswith(ext):
            return "source_py"
    for ext in SOURCE_EXTENSIONS_JS:
        if lower.endswith(ext):
            return "source_js"
    for ext in METADATA_EXTENSIONS:
        if lower.endswith(ext):
            return "metadata"
    for ext in BINARY_EXTENSIONS:
        if lower.endswith(ext):
            return "binary"
    for ext in DOC_EXTENSIONS:
        if lower.endswith(ext):
            return "doc"
    return "other"


def _assign_tier(name: str, ecosystem: Ecosystem) -> int:
    """Tier 1 / 2 / 3 분류 — 실행 자동성 기준."""
    parts = name.replace("\\", "/").split("/")
    basename = parts[-1]

    # Tier 1: 설치/import 시 자동 실행
    if ecosystem == Ecosystem.PYPI:
        if basename in {"setup.py", "__init__.py", "__main__.py"} and len(parts) <= 4:
            return 1
    else:  # npm
        if basename in {"index.js", "index.mjs", "index.cjs", "postinstall.js", "preinstall.js"}:
            if len(parts) <= 2:
                return 1

    # Tier 2: scripts/, bin/, cli 관련
    if any(p in parts for p in ("bin", "scripts", "cli")):
        return 2

    # Tier 3: 그 외 소스
    return 3


# ─────────────── 다운로드 ───────────────

def _download(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "slop-detector/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_ARCHIVE_SIZE + 1)
    if len(data) > MAX_ARCHIVE_SIZE:
        raise ValueError(f"archive too large (>{MAX_ARCHIVE_SIZE} bytes)")
    return data


# ─────────────── 추출 ───────────────

def _process_member(
    name: str,
    size: int,
    read_bytes,                          # 지연 읽기 함수
    ecosystem: Ecosystem,
) -> tuple[FullSourceFile | None, str | None, str | None]:
    """
    returns: (source_file, binary_path, skipped_reason)
    셋 중 하나만 non-None.
    """
    if _is_excluded_path(name):
        return None, None, "excluded_path"

    kind = _classify_file(name)

    if kind == "binary":
        return None, name, None
    if kind == "doc":
        return None, None, "doc_skipped"
    if kind == "other":
        return None, None, "unknown_type"
    if size > MAX_TEXT_FILE_SIZE:
        return None, None, f"too_large({size}B)"

    try:
        raw = read_bytes()
    except Exception as e:
        return None, None, f"read_fail:{e}"

    basename = name.replace("\\", "/").split("/")[-1]
    lang = _detect_language(basename)
    tier = _assign_tier(name, ecosystem)

    sf = FullSourceFile(
        path=name,
        basename=basename,
        content=_safe_decode(raw),
        size=size,
        language=lang if kind != "metadata" else lang,
        tier=tier,
    )
    return sf, None, None


def _extract_from_tar(data: bytes, ecosystem: Ecosystem):
    sources, binaries, all_names, skipped = [], [], [], []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name = member.name
            all_names.append(name)

            def _reader(_m=member):
                # default arg `_m=member` 으로 loop 변수 바인딩 (ruff B023)
                f = tf.extractfile(_m)
                return f.read() if f else b""

            src, bin_path, reason = _process_member(
                name, member.size, _reader, ecosystem
            )
            if src:
                sources.append(src)
            if bin_path:
                binaries.append(bin_path)
            if reason:
                skipped.append((name, reason))
    return sources, binaries, all_names, skipped


def _extract_from_zip(data: bytes, ecosystem: Ecosystem):
    sources, binaries, all_names, skipped = [], [], [], []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            all_names.append(name)

            def _reader(_i=info):
                return zf.read(_i.filename)

            src, bin_path, reason = _process_member(
                name, info.file_size, _reader, ecosystem
            )
            if src:
                sources.append(src)
            if bin_path:
                binaries.append(bin_path)
            if reason:
                skipped.append((name, reason))
    return sources, binaries, all_names, skipped


# ─────────────── 공개 API ───────────────

def extract_all(
    package: str,
    ecosystem: Ecosystem,
    version: str,
    archive_url: str,
) -> FullSourceExtract:
    result = FullSourceExtract(
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

    try:
        if archive_url.endswith((".tar.gz", ".tgz")):
            src, bins, names, skipped = _extract_from_tar(data, ecosystem)
        elif archive_url.endswith((".zip", ".whl")):
            src, bins, names, skipped = _extract_from_zip(data, ecosystem)
        else:
            try:
                src, bins, names, skipped = _extract_from_tar(data, ecosystem)
            except Exception:
                src, bins, names, skipped = _extract_from_zip(data, ecosystem)
    except Exception as e:
        result.error = f"extract failed: {e}"
        return result

    result.source_files = src
    result.binary_files = bins
    result.all_file_names = names
    result.skipped = skipped
    return result


def to_entry_files(full: FullSourceExtract) -> list[EntryFile]:
    """FullSourceExtract 를 기존 Stage 2 가 받을 수 있는 EntryFile 리스트로 변환."""
    result: list[EntryFile] = []
    for sf in full.source_files:
        # 메타데이터 파일은 분석 제외
        if sf.language in ("json", "toml", "cfg"):
            # 단, package.json 은 scripts 추출을 위해 EntryFile 로 유지 (Stage 2에서 처리)
            if sf.basename != "package.json":
                continue
        result.append(EntryFile(
            path=sf.path,
            basename=sf.basename,
            content=sf.content,
            size=sf.size,
            language=sf.language,
        ))
    return result


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys
    from collections import Counter

    from .stage0_registry import check

    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    info = check(pkg, eco)
    if not info.found:
        print("not found")
        sys.exit(1)

    v = info.latest_version
    url = info.archive_urls.get(v)
    ext = extract_all(pkg, eco, v, url)
    if ext.error:
        print(f"error: {ext.error}")
        sys.exit(1)

    print(f"[{pkg} {v}] archive {ext.archive_size} bytes, total {len(ext.all_file_names)} files")
    print(f"  source files  : {len(ext.source_files)}")
    print(f"  binary files  : {len(ext.binary_files)}")
    print(f"  skipped       : {len(ext.skipped)}")

    tier_counts = Counter(sf.tier for sf in ext.source_files)
    lang_counts = Counter(sf.language for sf in ext.source_files)
    print(f"  tier dist     : {dict(tier_counts)}")
    print(f"  lang dist     : {dict(lang_counts)}")

    if ext.binary_files:
        print("\nBinary files (Phase C 분석 대상):")
        for b in ext.binary_files[:5]:
            print(f"  {b}")
