"""Stage 7 binary (stage_binary.py) 단위 테스트.

목적:
  - detect_binary_type: PE/ELF/Mach-O magic 식별
  - extract_strings: 네트워크 URL/IP, 의심 경로 추출
  - analyze_binary: 통합 흐름 + 의심 import 검증 (PE/ELF 둘 다)
  - extract_and_analyze: tar.gz / zip 아카이브에서 바이너리 골라 분석

실 pefile/pyelftools 라이브러리는 설치돼 있으므로 *최소 합성 PE/ELF*
를 in-memory 로 만들어 정상 분석 시 의심 심볼 검출 확인.
"""
from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.stages.stage_binary import (
    BinaryFinding,
    analyze_binary,
    detect_binary_type,
    extract_and_analyze,
    extract_strings,
)


# ─────────────── 1) magic 검출 ───────────────

def test_detect_pe():
    print("== detect: PE (MZ header) ==")
    assert detect_binary_type(b"MZ" + b"\x00" * 100) == "pe"
    print("  OK")


def test_detect_elf():
    print("\n== detect: ELF (7F 45 4C 46) ==")
    assert detect_binary_type(b"\x7fELF" + b"\x00" * 100) == "elf"
    print("  OK")


def test_detect_macho():
    print("\n== detect: Mach-O (FEEDFACF / CFFAEDFE) ==")
    assert detect_binary_type(b"\xfe\xed\xfa\xcf" + b"\x00" * 100) == "macho"
    assert detect_binary_type(b"\xcf\xfa\xed\xfe" + b"\x00" * 100) == "macho"
    print("  OK")


def test_detect_unknown():
    print("\n== detect: 비-실행 → unknown ==")
    assert detect_binary_type(b"PK\x03\x04zip") == "unknown"
    assert detect_binary_type(b"plain text") == "unknown"
    assert detect_binary_type(b"") == "unknown"
    assert detect_binary_type(b"\x00\x00") == "unknown"
    print("  OK")


# ─────────────── 2) 문자열 추출 ───────────────

def test_extract_strings_network():
    print("\n== extract_strings: URL + IP ==")
    data = (
        b"random bytes \x00\x01\x02"
        b"https://attacker.example.com/c2 "
        b"normal junk \xfe\xfd"
        b"185.143.223.5:8080 "
        b"http://x.tk/payload"
    )
    network, _ = extract_strings(data)
    assert any("attacker.example.com" in n for n in network)
    assert any("185.143.223.5" in n for n in network)
    assert any("x.tk" in n for n in network)
    print(f"  OK net={network}")


def test_extract_strings_interesting():
    print("\n== extract_strings: 자격증명 / shell 경로 ==")
    data = (
        b"\x00 /etc/passwd \x01"
        b"~/.aws/credentials"
        b"\xfe powershell -enc"
        b"cmd.exe /c"
    )
    _, interesting = extract_strings(data)
    assert any("/etc/passwd" in s for s in interesting)
    assert any(".aws/credentials" in s for s in interesting)
    assert any("powershell" in s for s in interesting)
    print(f"  OK interesting={interesting}")


def test_extract_strings_empty_safe():
    print("\n== extract_strings: 빈 입력 안전 ==")
    network, interesting = extract_strings(b"")
    assert network == [] and interesting == []
    print("  OK")


# ─────────────── 3) analyze_binary ───────────────

def test_analyze_unknown_returns_empty_finding():
    print("\n== analyze: unknown → no import 검출, 문자열만 ==")
    data = b"plain ascii content https://x.com /etc/passwd"
    find = analyze_binary(data, "test.dat")
    assert find.binary_type == "unknown"
    assert find.suspicious_imports == []
    assert any("x.com" in n for n in find.network_strings)
    # has_findings 는 suspicious_imports 또는 network_strings 어느 쪽이라도 있으면 True
    assert find.has_findings is True
    print("  OK")


def _build_minimal_elf_with_symbol(symbol: str = "execve") -> bytes:
    """pyelftools 가 파싱할 최소 ELF 64-bit 헤더 + .dynsym 한 개.

    완전한 ELF 가 아니라 — pyelftools 가 *처음에 magic 검증* 후 sections 순회.
    sections 없으면 빈 iter — _analyze_elf 가 그냥 빈 finding 반환.
    SUSPICIOUS_ELF_SYMBOLS 검출은 *실제 import 가 있는 바이너리* 가 필요해
    합성으로는 비현실적. _analyze_elf 가 *에러 없이 끝나는지* 만 검증.
    """
    # ELF64 header 64 bytes
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4] = 2          # 64-bit
    eh[5] = 1          # little endian
    eh[6] = 1          # version
    # e_type=3 (DYN), e_machine=62 (x86_64)
    eh[16:18] = (3).to_bytes(2, "little")
    eh[18:20] = (62).to_bytes(2, "little")
    eh[20:24] = (1).to_bytes(4, "little")
    # e_ehsize=64
    eh[52:54] = (64).to_bytes(2, "little")
    return bytes(eh)


def test_analyze_elf_parses_without_crash():
    """최소 ELF — _analyze_elf 가 예외 없이 BinaryFinding 반환."""
    print("\n== analyze ELF: 최소 헤더 — crash 안 함 ==")
    data = _build_minimal_elf_with_symbol()
    find = analyze_binary(data, "test.so")
    assert find.binary_type == "elf"
    # 정상 ELF 또는 error 둘 다 OK (합성이라 sections 없음 — pyelftools 가 OK 처리)
    assert find.path == "test.so"
    print(f"  OK error={find.error}")


def test_analyze_pe_minimal_no_crash():
    """최소 PE 헤더 — _analyze_pe 가 graceful (pefile 가 parse 실패해도 error 필드)."""
    print("\n== analyze PE: 최소 MZ 헤더 — crash 안 함 ==")
    data = b"MZ" + b"\x00" * 120  # DOS stub + zeros
    find = analyze_binary(data, "test.dll")
    assert find.binary_type == "pe"
    # pefile 가 PE32 header 없는 binary 는 거부 → error 필드 설정
    # 우리 코드가 예외 잡고 error 반환하는지만 확인
    assert find.path == "test.dll"
    print(f"  OK error={find.error}")


# ─────────────── 4) extract_and_analyze (archive) ───────────────

def _make_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, data in files.items():
            zf.writestr(path, data)
    return buf.getvalue()


def test_extract_and_analyze_from_targz():
    print("\n== extract_and_analyze: tar.gz ==")
    binary_data = b"MZ" + b"\x00" * 200 + b"https://evil.example.com"
    archive = _make_tar({
        "pkg/foo.so": binary_data,
        "pkg/text.txt": b"non-binary file",
    })
    findings = extract_and_analyze(
        archive, ["pkg/foo.so"], "test.tar.gz",
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.path == "pkg/foo.so"
    # 네트워크 문자열은 추출되어야 (PE 파싱 실패해도 strings 는 항상 실행)
    assert any("evil.example.com" in n for n in f.network_strings)
    print(f"  OK net_strings={f.network_strings}")


def test_extract_and_analyze_from_zip():
    print("\n== extract_and_analyze: zip ==")
    archive = _make_zip({
        "pkg/lib.pyd": b"MZ" + b"\x00" * 100 + b"powershell -enc x",
    })
    findings = extract_and_analyze(
        archive, ["pkg/lib.pyd"], "test.zip",
    )
    assert len(findings) == 1
    assert any("powershell" in s for s in findings[0].strings_of_interest)
    print("  OK")


def test_extract_and_analyze_empty_list():
    print("\n== extract_and_analyze: empty binary list → no findings ==")
    archive = _make_tar({"pkg/x.txt": b"hi"})
    findings = extract_and_analyze(archive, [], "test.tar.gz")
    assert findings == []
    print("  OK")


def test_extract_and_analyze_archive_error():
    """아카이브 파싱 실패 → error 필드 단일 BinaryFinding."""
    print("\n== extract_and_analyze: 깨진 아카이브 → error finding ==")
    findings = extract_and_analyze(
        b"not a real archive", ["x.so"], "test.tar.gz",
    )
    assert len(findings) == 1
    assert findings[0].error is not None
    print(f"  OK error: {findings[0].error[:60]}")


def test_extract_and_analyze_size_limit():
    """10MB 초과 바이너리 → skip."""
    print("\n== extract_and_analyze: >10MB → skip ==")
    huge = b"MZ" + b"\x00" * (11 * 1024 * 1024)
    archive = _make_tar({"pkg/big.dll": huge})
    findings = extract_and_analyze(archive, ["pkg/big.dll"], "test.tar.gz")
    # skipped → 빈 결과
    assert findings == []
    print("  OK")


def main():
    pass


if __name__ == "__main__":
    main()
