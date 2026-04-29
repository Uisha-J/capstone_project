"""
바이너리 파일 분석 (.so / .dll / .node / .pyd 등).

완전한 역공학은 불가능하지만, 다음은 정적으로 확인 가능:
  - PE (Windows .dll/.pyd): import table → 의심 API (CreateProcess, InternetOpen, WriteFile 등)
  - ELF (Linux .so): dynamic symbols → libc 의심 호출 (execve, system, popen)
  - 바이너리 내 문자열 추출 → 네트워크 인디케이터 (URL, IP)

본 Phase 는 의심 심볼만 식별하고 Evidence 로 변환.
완전 분석은 IDA/Ghidra 수준이라 졸업작품 범위 초과.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass, field

# ─────────────── 의심 심볼 사전 ───────────────

# Windows PE 의심 API
SUSPICIOUS_PE_IMPORTS = {
    # 프로세스/실행
    "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "CreateRemoteThread", "NtCreateThreadEx",
    # 네트워크
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpSendRequestA",
    "socket", "connect", "send", "recv", "WSAStartup",
    # 자격증명
    "GetUserNameA", "GetComputerNameA", "RegOpenKeyExA", "CredReadA",
    # 파일/메모리
    "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "SetWindowsHookExA", "SetWindowsHookExW",
}

# Linux ELF 의심 libc 호출
SUSPICIOUS_ELF_SYMBOLS = {
    "system", "execve", "execv", "execvp", "execl", "popen",
    "fork", "vfork", "clone",
    "socket", "connect", "send", "recv",
    "mmap", "mprotect",
    "ptrace",
    "getenv",
}


# ─────────────── 결과 ───────────────

@dataclass
class BinaryFinding:
    path: str
    binary_type: str              # "pe" | "elf" | "unknown"
    suspicious_imports: list[str] = field(default_factory=list)
    network_strings: list[str] = field(default_factory=list)
    strings_of_interest: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def has_findings(self) -> bool:
        return bool(self.suspicious_imports or self.network_strings)


# ─────────────── PE 분석 ───────────────

def _analyze_pe(data: bytes, path: str) -> BinaryFinding:
    find = BinaryFinding(path=path, binary_type="pe")
    try:
        import pefile
    except ImportError:
        find.error = "pefile not installed"
        return find
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    name = imp.name.decode("utf-8", errors="replace")
                    if name in SUSPICIOUS_PE_IMPORTS:
                        find.suspicious_imports.append(name)
    except Exception as e:
        find.error = f"pe parse: {e}"
    return find


# ─────────────── ELF 분석 ───────────────

def _analyze_elf(data: bytes, path: str) -> BinaryFinding:
    find = BinaryFinding(path=path, binary_type="elf")
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        find.error = "pyelftools not installed"
        return find
    try:
        elf = ELFFile(io.BytesIO(data))
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    name = sym.name
                    if name and name in SUSPICIOUS_ELF_SYMBOLS:
                        find.suspicious_imports.append(name)
    except Exception as e:
        find.error = f"elf parse: {e}"
    return find


# ─────────────── 문자열 추출 ───────────────

_NETWORK_STR_RE = re.compile(
    rb"(?:https?://[^\x00-\x1f\x7f-\xff\s\"']{4,200}"
    rb"|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)"
)

_INTERESTING_STR_RE = re.compile(
    rb"(?:/etc/passwd|/\.ssh/|\.aws/credentials|powershell|cmd\.exe|curl\s|wget\s)"
)


def extract_strings(data: bytes, min_len: int = 6) -> tuple[list[str], list[str]]:
    """바이너리에서 printable string 추출."""
    network = set()
    interesting = set()

    for m in _NETWORK_STR_RE.finditer(data):
        try:
            network.add(m.group(0).decode("ascii"))
        except Exception:
            pass

    for m in _INTERESTING_STR_RE.finditer(data):
        try:
            interesting.add(m.group(0).decode("ascii", errors="replace"))
        except Exception:
            pass

    return sorted(network)[:10], sorted(interesting)[:10]


# ─────────────── 메인 ───────────────

def detect_binary_type(data: bytes) -> str:
    if len(data) < 4:
        return "unknown"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"\xfe\xed\xfa\xcf" or data[:4] == b"\xcf\xfa\xed\xfe":
        return "macho"
    return "unknown"


def analyze_binary(data: bytes, path: str) -> BinaryFinding:
    btype = detect_binary_type(data)

    if btype == "pe":
        find = _analyze_pe(data, path)
    elif btype == "elf":
        find = _analyze_elf(data, path)
    else:
        find = BinaryFinding(path=path, binary_type=btype)

    # 공통: 문자열 추출 (PE/ELF 모두 적용)
    network, interesting = extract_strings(data)
    find.network_strings = network
    find.strings_of_interest = interesting

    # 중복 제거
    find.suspicious_imports = sorted(set(find.suspicious_imports))
    return find


# ─────────────── 아카이브에서 바이너리 추출 ───────────────

def extract_and_analyze(
    archive_bytes: bytes,
    binary_file_paths: list[str],
    archive_url: str,
) -> list[BinaryFinding]:
    """
    FullSourceExtract.binary_files 의 경로 리스트를 받아
    원본 아카이브에서 바이너리를 읽어 분석.
    """
    import tarfile
    import zipfile

    results: list[BinaryFinding] = []
    if not binary_file_paths:
        return results

    paths_set = set(binary_file_paths)

    try:
        if archive_url.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
                for member in tf.getmembers():
                    if member.name in paths_set and member.isfile():
                        f = tf.extractfile(member)
                        if f is None:
                            continue
                        data = f.read()
                        if len(data) > 10 * 1024 * 1024:  # 10MB 상한
                            continue
                        results.append(analyze_binary(data, member.name))
        else:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                for info in zf.infolist():
                    if info.filename in paths_set and not info.is_dir():
                        if info.file_size > 10 * 1024 * 1024:
                            continue
                        data = zf.read(info.filename)
                        results.append(analyze_binary(data, info.filename))
    except Exception as e:
        results.append(BinaryFinding(
            path="<archive>", binary_type="unknown",
            error=f"archive read failed: {e}",
        ))

    return results


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python -m detector.stages.stage_binary <path-to-binary>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    find = analyze_binary(data, sys.argv[1])
    print(f"type: {find.binary_type}")
    print(f"error: {find.error}")
    print(f"suspicious imports: {find.suspicious_imports}")
    print(f"network strings: {find.network_strings}")
    print(f"interesting strings: {find.strings_of_interest}")
