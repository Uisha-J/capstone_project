"""
샌드박스 동적 분석.

Docker 격리 컨테이너에서 `pip install --dry-run` 혹은 실제 install 을 실행하고:
  - 생성된 프로세스
  - 발생한 네트워크 요청 (iptables / tcpdump 또는 로그)
  - 생성/변경된 파일

을 관찰해 동적 행위 프로필을 수집.

현재 제약:
  - 실제 동작은 Docker 데몬 필요
  - 프로토타입에서는 "mock 모드" 로 개념 증명
  - 진짜 구현은 다음 요소 필요:
      * Docker SDK (docker-py)
      * 네트워크 캡처 (strace / sysdig / bpftrace)
      * 파일시스템 diff

이 모듈의 현재 역할:
  1. 인터페이스 정의 (ObservedBehavior 데이터 모델)
  2. Mock 모드 동작 (실행하지 않고 정적 분석 결과를 동적인 것처럼 포맷)
  3. 실제 Docker 통합은 별도 docker-compose 서비스로 Phase C-2b 에서 완성

설계상 향후 교체 가능하도록 BaseSandbox 추상화.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..schema import Ecosystem

# ─────────────── 관찰된 동적 행위 ───────────────

@dataclass
class ObservedBehavior:
    """샌드박스 내부에서 관찰된 실제 행위."""
    process_spawns: list[str] = field(default_factory=list)         # "curl http://..."
    network_requests: list[str] = field(default_factory=list)       # "GET http://..."
    file_writes: list[str] = field(default_factory=list)            # "/tmp/x"
    env_reads: list[str] = field(default_factory=list)              # "AWS_*"

    mode: str = "mock"                                               # "mock" | "docker"
    duration_s: float = 0.0
    error: str | None = None

    @property
    def has_findings(self) -> bool:
        return bool(
            self.process_spawns
            or self.network_requests
            or self.file_writes
        )


# ─────────────── 베이스 ───────────────

class BaseSandbox(ABC):
    @abstractmethod
    def run(
        self,
        package: str,
        ecosystem: Ecosystem,
        version: str,
    ) -> ObservedBehavior:
        raise NotImplementedError


# ─────────────── Mock 샌드박스 ───────────────

class MockSandbox(BaseSandbox):
    """실행 없이 정적 힌트만 반환. Docker 미사용 환경용."""

    def run(self, package, ecosystem, version) -> ObservedBehavior:
        return ObservedBehavior(
            mode="mock",
            duration_s=0.0,
            error="sandbox not executed (mock mode)",
        )


# ─────────────── Docker 샌드박스 ───────────────

DOCKER_IMAGE_PY = "python:3.11-slim"
DOCKER_IMAGE_NODE = "node:20-alpine"


class DockerSandbox(BaseSandbox):
    """
    격리 컨테이너에서 install 실행 후 관찰.

    접근 방식:
      1. --network none 으로 우선 install --dry-run (네트워크 차단 상태에서 시도)
         → 네트워크 접근 시도 시 실패 로그 확인
      2. 실제 install 은 --network bridge + DNS/트래픽 로깅
      3. 파일 생성은 /sandbox 마운트 diff 로 확인

    현재는 개념 증명 — 실제 운영 전에 보안 검토 필요 (악성 코드가 실행됨).
    """

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def _available(self) -> bool:
        return shutil.which("docker") is not None

    def run(self, package, ecosystem, version) -> ObservedBehavior:
        if not self._available():
            return ObservedBehavior(
                mode="docker",
                error="docker not available on this host",
            )

        if ecosystem == Ecosystem.PYPI:
            return self._run_pypi(package, version)
        if ecosystem == Ecosystem.NPM:
            return self._run_npm(package, version)

        return ObservedBehavior(
            mode="docker",
            error=f"unsupported ecosystem: {ecosystem}",
        )

    def _run_pypi(self, package: str, version: str) -> ObservedBehavior:
        import time

        target = f"{package}=={version}" if version and version != "unknown" else package
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",       # 일단 네트워크 차단 — 설치 스크립트가 네트워크 시도하는지 관찰
            "--read-only",
            "--tmpfs", "/tmp",
            DOCKER_IMAGE_PY,
            "pip", "install", "--dry-run", "--no-cache-dir", "--disable-pip-version-check",
            target,
        ]
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout, text=True,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            combined = stdout + "\n" + stderr
        except subprocess.TimeoutExpired:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error="timeout (possibly hanging install script)",
            )
        except Exception as e:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error=f"docker failed: {e}",
            )

        # 간이 로그 파싱
        obs = ObservedBehavior(mode="docker", duration_s=time.time() - t0)

        import re
        # 네트워크 실패 로그 = 설치 과정에서 네트워크를 시도한 증거
        if re.search(r"(Temporary failure|Network is unreachable|Could not fetch)", combined):
            obs.network_requests.append("pip install attempted network (blocked by --network none)")

        if "Executing" in combined or "Running setup.py" in combined:
            obs.process_spawns.append("setup.py executed during pip install")

        return obs

    def _run_npm(self, package: str, version: str) -> ObservedBehavior:
        import time

        target = f"{package}@{version}" if version and version != "unknown" else package
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--tmpfs", "/workdir:rw",
            "-w", "/workdir",
            DOCKER_IMAGE_NODE,
            "sh", "-c",
            f"npm init -y >/dev/null 2>&1 && "
            f"npm install --ignore-scripts=false --no-audit --no-fund --dry-run {target} 2>&1 | head -200",
        ]
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout, text=True,
            )
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error="timeout",
            )
        except Exception as e:
            return ObservedBehavior(
                mode="docker",
                duration_s=time.time() - t0,
                error=f"docker failed: {e}",
            )

        obs = ObservedBehavior(mode="docker", duration_s=time.time() - t0)

        import re
        if re.search(r"(ENOTFOUND|ECONNREFUSED|getaddrinfo)", combined):
            obs.network_requests.append("npm install attempted network (blocked)")
        if "postinstall" in combined.lower() or "preinstall" in combined.lower():
            obs.process_spawns.append("install hook script executed")

        return obs


# ─────────────── strace Sandbox ───────────────

# strace 베이스 이미지 — 컨테이너 진입 시 apt-get 으로 strace 설치 후 실행.
# 평가용 베이스 이미지를 미리 만들어 두면 (Dockerfile) overhead 가 감소.
STRACE_IMAGE_PY = "python:3.11-slim"

# 캡처 syscall 셋:
#  - network : connect / sendto / sendmsg / recvfrom / accept
#  - execve  : 자식 프로세스 실행 (악성 install 훅)
#  - file    : openat / open / unlink (자격증명 파일 열람 추적)
_STRACE_SYSCALLS = "network,execve,openat,unlink"


_STRACE_NETWORK_RE = re.compile(
    r"^[0-9]+\s+connect\([0-9]+,\s*\{sa_family=AF_INET\d?,\s*"
    r"(?:sin_port=htons\(\d+\),\s*)?(?:sin_addr=)?inet_addr\([\"']([^)]+)[\"']\)",
    re.MULTILINE,
)
_STRACE_EXEC_RE = re.compile(
    r"^[0-9]+\s+execve\([\"']([^\"']+)[\"'],\s*\[([^\]]+)\]",
    re.MULTILINE,
)
_STRACE_OPEN_RE = re.compile(
    r"^[0-9]+\s+openat\([^,]+,\s*[\"']([^\"']+)[\"']",
    re.MULTILINE,
)


class StraceDockerSandbox(DockerSandbox):
    """strace 로 syscall 캡처 + 파싱.

    DockerSandbox 가 stdout 키워드 매칭으로만 행위를 추측했다면,
    여기는 커널 syscall 레벨에서 실측한다.

    동작:
      1. 컨테이너 진입 후 strace 가 없으면 `apt-get -y install strace` (이미지가
         strace 포함된 derived image 라면 skip — 30초 절감).
      2. `strace -f -e trace=<syscalls> -o /tmp/s.log pip install ...` 실행.
      3. /tmp/s.log 파싱 → connect 의 inet_addr / execve 의 argv[0] /
         openat 의 path 를 ObservedBehavior 의 각 필드에 추가.

    제약:
      - Linux 호스트 + Docker 만 동작 (Windows 호스트의 Docker Desktop 도 가능).
      - --network none 일 때도 connect 시도는 syscall 로 남으므로 차단됐어도 잡힘.
      - 큰 install 의 경우 strace 로그가 수 MB — head 로 100k 라인까지만 파싱.

    근거: strace -e network 트래픽 캡처는 supply chain 동적 분석의 표준 기법.
    """

    def __init__(self, timeout: int = 90, has_strace_image: bool = False):
        super().__init__(timeout=timeout)
        # has_strace_image=True 면 이미지가 이미 strace 포함 — apt 설치 skip
        self.has_strace_image = has_strace_image

    def _strace_install_cmd(self) -> str:
        if self.has_strace_image:
            return ""
        # apt-get 출력 억제 + lock 회피
        return (
            "apt-get update -qq 2>/dev/null >/dev/null && "
            "apt-get install -y -qq strace 2>/dev/null >/dev/null && "
        )

    def _run_pypi(self, package: str, version: str) -> ObservedBehavior:
        import time
        target = (
            f"{package}=={version}"
            if version and version != "unknown" else package
        )
        # /tmp tmpfs 에 strace 로그 — read-only fs 와 충돌 회피 위해 rw 마운트.
        # network=bridge 로 두어 실제 connect syscall 이 발생할 수 있게 함
        # (악성 패턴 식별이 목적이라면 차단 + 시도 로그가 더 안전).
        install_block = (
            f"{self._strace_install_cmd()}"
            f"strace -f -qq -e trace={_STRACE_SYSCALLS} "
            f"-o /tmp/s.log -- "
            f"pip install --dry-run --no-cache-dir "
            f"--disable-pip-version-check {target} 2>/dev/null; "
            f"head -c 500000 /tmp/s.log || true"
        )
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--tmpfs", "/tmp:rw,size=64m",
            STRACE_IMAGE_PY,
            "sh", "-c", install_block,
        ]
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout, text=True,
            )
            log = proc.stdout or ""
        except subprocess.TimeoutExpired:
            return ObservedBehavior(
                mode="docker+strace",
                duration_s=time.time() - t0,
                error="timeout",
            )
        except Exception as e:
            return ObservedBehavior(
                mode="docker+strace",
                duration_s=time.time() - t0,
                error=f"docker failed: {e}",
            )

        return self._parse_strace_log(log, time.time() - t0)

    @staticmethod
    def _parse_strace_log(log: str, duration_s: float) -> ObservedBehavior:
        obs = ObservedBehavior(mode="docker+strace", duration_s=duration_s)
        # network connect
        seen_net: set[str] = set()
        for m in _STRACE_NETWORK_RE.finditer(log):
            addr = m.group(1)
            if addr in seen_net:
                continue
            seen_net.add(addr)
            obs.network_requests.append(f"connect -> {addr}")

        # execve
        seen_exec: set[str] = set()
        for m in _STRACE_EXEC_RE.finditer(log):
            exe = m.group(1)
            if exe in seen_exec:
                continue
            seen_exec.add(exe)
            # argv[0] 만 발췌 (작은 따옴표 정리)
            argv0 = m.group(2).split(",")[0].strip().strip("\"'")
            obs.process_spawns.append(f"execve {exe} (argv0={argv0})")

        # file opens — 자격증명 디렉터리 / SSH 키 / AWS 캐시 / .npmrc 만 기록
        # 일반 .py / .so 는 너무 많아 제외
        sensitive_paths = re.compile(
            r"(?:\.ssh/|\.aws/|\.npmrc|\.pypirc|/etc/passwd|/etc/shadow|"
            r"credentials|keychain|/proc/\d+/environ)",
            re.IGNORECASE,
        )
        seen_open: set[str] = set()
        for m in _STRACE_OPEN_RE.finditer(log):
            path = m.group(1)
            if path in seen_open:
                continue
            if not sensitive_paths.search(path):
                continue
            seen_open.add(path)
            obs.file_writes.append(f"open {path}")  # 실제로는 read 도 포함 — 필드 재사용

        return obs


# ─────────────── 선택 헬퍼 ───────────────

def get_default_sandbox() -> BaseSandbox:
    """우선순위:
      1. OssfDataSandbox — OSSF Package Analysis 결과를 데이터로 흡수. Docker / Linux 의존 0.
      2. (opt-in) DockerSandbox / StraceDockerSandbox — Linux + Docker 환경에서만.
      3. MockSandbox — 위 둘 다 사용 불가시 fallback (no-op).

    DockerSandbox 는 더 이상 default 가 아님 — 실 운영에서 Windows 호스트 또는
    Docker 없는 컨테이너 환경 에서도 dynamic-analysis 데이터를 받기 위함.
    OSSF Package Analysis 가 매일 신규 패키지 분석을 publish 하므로 우리 자체
    sandbox 운영의 한계 (Linux+Docker 필수, 비용, 보안 검토) 가 해소됨.
    """
    # 동적 import — OssfDataSandbox 가 knowledge 패키지에 있어 순환 import 회피
    from ..knowledge.ossf_package_analysis import OssfDataSandbox
    return OssfDataSandbox()


def get_local_docker_sandbox() -> BaseSandbox:
    """명시적으로 Docker / Linux 환경 자체 sandbox 가 필요할 때만 사용.

    제약: Linux + Docker 데몬 필요. 악성 코드가 실행됨 — 보안 검토 후 사용.
    """
    docker_sandbox = DockerSandbox()
    if docker_sandbox._available():
        return docker_sandbox
    return MockSandbox()


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    import sys

    sb = get_default_sandbox()
    print(f"Using sandbox: {type(sb).__name__}")

    pkg = sys.argv[1] if len(sys.argv) > 1 else "flask"
    eco = Ecosystem(sys.argv[2]) if len(sys.argv) > 2 else Ecosystem.PYPI

    obs = sb.run(pkg, eco, "latest")
    print(f"mode       : {obs.mode}")
    print(f"duration   : {obs.duration_s:.2f}s")
    print(f"error      : {obs.error}")
    print(f"processes  : {obs.process_spawns}")
    print(f"network    : {obs.network_requests}")
    print(f"file writes: {obs.file_writes}")
